"""Pure-logic + contract-boundary tests for the audit-PDF text extractor.

The full worker loop (claim → download → extract → store → persist) is
covered end-to-end by ``test_audit_text_extraction_integration.py`` which
runs against real Postgres + real MinIO. What lives here is:

    - ``extract_text_from_pdf`` round-trip through real ``pypdf``
    - ``download_pdf`` HTTP contract boundaries that the integration test
      doesn't exercise because it stubs ``download_pdf`` wholesale
      (size caps, content-type rejection, transport errors)
    - ``audit_text_key`` deterministic key format

Anything that would re-mock the worker / storage / LLM paths belongs in
the integration test, not here.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.audits.text_extraction import (
    _ACCEPTED_CONTENT_TYPES,
    PdfDownloadError,
    PdfParseError,
    PdfTooLargeError,
    _normalize_download_url,
    audit_text_key,
    download_audit_body,
    download_pdf,
    extract_text_from_pdf,
    process_audit_report,
)
from tests.support.pdf import minimal_pdf_with_text

# ---------------------------------------------------------------------------
# extract_text_from_pdf — real pypdf roundtrip, no mocks
# ---------------------------------------------------------------------------


class TestExtractTextFromPdf:
    def test_roundtrips_simple_ascii(self):
        body = minimal_pdf_with_text("Audit scope covers Pool.sol and Vault.sol.")
        text = extract_text_from_pdf(body)
        assert "Pool.sol" in text
        assert "Vault.sol" in text
        # Page markers must be preserved so the scope extractor can recover
        # page boundaries.
        assert "--- page 1 ---" in text

    def test_garbage_body_raises_parse_error(self):
        with pytest.raises(PdfParseError):
            extract_text_from_pdf(b"not a pdf at all")

    def test_empty_body_raises_parse_error(self):
        with pytest.raises(PdfParseError):
            extract_text_from_pdf(b"")

    def test_link_annotation_uris_are_included_in_extracted_text(self):
        """Certora's audit PDFs embed commit SHAs as hyperlinks
        ("Fixed in [commit](https://github.com/x/y/commit/<sha>)") rather
        than inline text. pypdf's ``extract_text()`` drops the URI. Without
        the annotation-scraping path, the scope extractor's hex regex sees
        the body as "Fixed in commit" with no SHA following, and
        ``reviewed_commits`` stays empty — which kills source-equivalence
        and strands the audit in heuristic grace-zone matching.
        """
        import io

        from pypdf import PdfWriter
        from pypdf.annotations import Link
        from pypdf.generic import RectangleObject

        sha = "353765993b40e3c2bddcdcdf7adc6f2f6ec080c9"  # 40 hex chars with letters
        url = f"https://github.com/etherfi-protocol/smart-contracts/commit/{sha}"

        w = PdfWriter()
        w.add_blank_page(width=612, height=792)
        w.add_annotation(
            page_number=0,
            annotation=Link(rect=RectangleObject((100, 700, 300, 720)), url=url),
        )
        buf = io.BytesIO()
        w.write(buf)

        text = extract_text_from_pdf(buf.getvalue())

        # The full URL (or at least the SHA) must appear somewhere in the
        # extracted text so downstream regex can see it. We assert on the
        # SHA rather than the URL so we don't pin the impl to a specific
        # formatting choice (raw URL vs bracketed vs prefixed line).
        assert sha in text, f"commit SHA from link annotation lost in extraction. Extracted text: {text!r}"

    def test_multiple_link_annotations_all_extracted(self):
        """A real PDF has many commit links — we can't drop any of them."""
        import io

        from pypdf import PdfWriter
        from pypdf.annotations import Link
        from pypdf.generic import RectangleObject

        shas = [
            "3e9f54ec" + "0" * 32,
            "abc96405" + "1" * 32,
            "b7a8d04d" + "2" * 32,
        ]
        w = PdfWriter()
        w.add_blank_page(width=612, height=792)
        for i, sha in enumerate(shas):
            w.add_annotation(
                page_number=0,
                annotation=Link(
                    rect=RectangleObject((100, 700 - i * 30, 300, 720 - i * 30)),
                    url=f"https://github.com/etherfi-protocol/smart-contracts/commit/{sha}",
                ),
            )
        buf = io.BytesIO()
        w.write(buf)

        text = extract_text_from_pdf(buf.getvalue())
        for sha in shas:
            assert sha in text, f"SHA {sha} missing from extraction"

    def test_link_annotations_across_multiple_pages(self):
        """URIs on page 2 must show up alongside (or after) page 2's body
        text, not get collapsed into page 1."""
        import io

        from pypdf import PdfWriter
        from pypdf.annotations import Link
        from pypdf.generic import RectangleObject

        sha_p1 = "aaaaaaa" + "0" * 33
        sha_p2 = "bbbbbbb" + "1" * 33
        w = PdfWriter()
        w.add_blank_page(width=612, height=792)
        w.add_blank_page(width=612, height=792)
        w.add_annotation(
            page_number=0,
            annotation=Link(
                rect=RectangleObject((100, 700, 300, 720)),
                url=f"https://github.com/x/y/commit/{sha_p1}",
            ),
        )
        w.add_annotation(
            page_number=1,
            annotation=Link(
                rect=RectangleObject((100, 700, 300, 720)),
                url=f"https://github.com/x/y/commit/{sha_p2}",
            ),
        )
        buf = io.BytesIO()
        w.write(buf)

        text = extract_text_from_pdf(buf.getvalue())
        assert sha_p1 in text
        assert sha_p2 in text
        # Both page markers must still be there.
        assert "--- page 1 ---" in text
        assert "--- page 2 ---" in text

    def test_non_link_annotations_do_not_leak_garbage(self):
        """We only want ``/Subtype == /Link`` with ``/A/URI``. Highlight
        annotations, form fields, comments etc. must not pollute the text.
        """
        import io

        from pypdf import PdfWriter
        from pypdf.annotations import FreeText
        from pypdf.generic import RectangleObject

        w = PdfWriter()
        w.add_blank_page(width=612, height=792)
        w.add_annotation(
            page_number=0,
            annotation=FreeText(
                text="annotator's private note — should not appear",
                rect=RectangleObject((100, 700, 400, 720)),
                font_size="12pt",
            ),
        )
        buf = io.BytesIO()
        w.write(buf)

        text = extract_text_from_pdf(buf.getvalue())
        assert "annotator's private note" not in text

    def test_pdf_without_any_annotations_still_extracts_cleanly(self):
        """Regression guard: the new path must be a pure addition and
        leave annotation-free PDFs byte-identical to the old behaviour."""
        body = minimal_pdf_with_text("No links here, just scope contracts.")
        text = extract_text_from_pdf(body)
        assert "No links here" in text
        # No stray URI placeholders, empty sections, or duplicated markers.
        assert text.count("--- page 1 ---") == 1

    def test_end_to_end_link_sha_reaches_reviewed_commits_extractor(self):
        """The real reason we care about link URIs: downstream,
        ``extract_reviewed_commits`` must pick up the SHA out of the
        extracted text. This test locks the end-to-end behaviour —
        extract_text_from_pdf → extract_reviewed_commits — so a future
        change to either side won't silently re-break the
        Certora-V3.Prelude-1 case (hyperlinked "commit" with no inline
        SHA) that motivated this fix.
        """
        import io

        from pypdf import PdfWriter
        from pypdf.annotations import Link
        from pypdf.generic import RectangleObject

        from services.audits.source_equivalence import extract_reviewed_commits

        sha = "c820841928a25ac270e5b31058e858e6804ed9b1"  # 40 hex, has letters
        url = f"https://github.com/etherfi-protocol/smart-contracts/commit/{sha}"

        w = PdfWriter()
        w.add_blank_page(width=612, height=792)
        w.add_annotation(
            page_number=0,
            annotation=Link(rect=RectangleObject((100, 700, 300, 720)), url=url),
        )
        buf = io.BytesIO()
        w.write(buf)

        text = extract_text_from_pdf(buf.getvalue())
        commits = extract_reviewed_commits(text)
        assert sha in commits, (
            f"End-to-end path broken: link-annotation SHA {sha} didn't reach extract_reviewed_commits. Got: {commits!r}"
        )


# ---------------------------------------------------------------------------
# download_pdf — boundary conditions around HTTP behaviour.
#
# These are *not* covered by the integration test: the integration suite
# stubs ``download_pdf`` wholesale so it can drop fixture PDFs in without
# a real HTTP server. The contract boundaries below (HTTP error, wrong
# content-type, oversize body) are the thing that would actually break in
# prod when a publisher changes their CDN behaviour.
# ---------------------------------------------------------------------------


def _mock_response(
    *,
    status_code: int = 200,
    content_type: str = "application/pdf",
    content_length: str | None = None,
    body: bytes = b"",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": content_type}
    if content_length is not None:
        resp.headers["content-length"] = content_length
    resp.iter_content.return_value = iter([body]) if body else iter([])
    resp.close = MagicMock()
    return resp


class TestDownloadPdfBoundaries:
    def test_happy_path_returns_bytes(self):
        session = MagicMock()
        session.get.return_value = _mock_response(body=b"%PDF-1.4\n...")
        assert download_pdf("https://example.com/a.pdf", session=session) == b"%PDF-1.4\n..."

    def test_non_200_raises_download_error(self):
        session = MagicMock()
        session.get.return_value = _mock_response(status_code=404)
        with pytest.raises(PdfDownloadError, match="HTTP 404"):
            download_pdf("https://example.com/missing.pdf", session=session)

    def test_rejects_html_content_type(self):
        """Etherscan / publisher soft-redirects (login walls, 200 HTML) are
        the main cause of misclassified bodies — guard against them."""
        session = MagicMock()
        session.get.return_value = _mock_response(content_type="text/html")
        with pytest.raises(PdfDownloadError, match="content-type"):
            download_pdf("https://example.com/a.pdf", session=session)

    def test_accepts_octet_stream(self):
        session = MagicMock()
        session.get.return_value = _mock_response(content_type="application/octet-stream", body=b"PDF body")
        assert download_pdf("https://example.com/a.pdf", session=session) == b"PDF body"

    def test_content_length_over_cap_raises(self):
        session = MagicMock()
        session.get.return_value = _mock_response(
            content_length=str(100 * 1024 * 1024),  # 100MB, over the 50MB cap
        )
        with pytest.raises(PdfTooLargeError, match="Content-Length"):
            download_pdf("https://example.com/huge.pdf", session=session)

    def test_streamed_body_over_cap_raises(self):
        """Content-Length header is optional — the size cap must still trip
        when the stream itself exceeds the limit."""
        session = MagicMock()
        resp = _mock_response()
        resp.iter_content.return_value = iter([b"x" * (60 * 1024 * 1024)])
        session.get.return_value = resp
        with pytest.raises(PdfTooLargeError, match="streamed body"):
            download_pdf("https://example.com/huge.pdf", session=session)

    def test_request_exception_raises_download_error(self):
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("connection refused")
        with pytest.raises(PdfDownloadError, match="fetch error"):
            download_pdf("https://example.com/a.pdf", session=session)

    def test_all_accepted_content_types_include_pdf(self):
        assert "application/pdf" in _ACCEPTED_CONTENT_TYPES


# ---------------------------------------------------------------------------
# download_audit_body — retry-with-backoff on transient transport failures.
#
# Production observed bursts of ConnectionResetError(104, 'Connection reset by
# peer') from upstream publishers (Code4rena / Sherlock). Without retry, every
# transient flake permanently fails an audit row — the worker writes
# ``ExtractionOutcome(status="failed")`` and the audit never gets reattempted.
# requests wraps OS-level ConnectionResetError as
# requests.exceptions.ConnectionError, so the tests below mock with the wrapped
# form to mirror what actually flows through ``download_audit_body``.
# ---------------------------------------------------------------------------


class TestDownloadAuditBodyRetry:
    def test_transient_connection_error_is_retried_to_success(self, monkeypatch):
        """First call RSTs the way prod does, second call succeeds — audit
        should end as a successful download, not a terminal failure."""
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        ok = _mock_response(body=b"%PDF-1.4\n...")
        session = MagicMock()
        session.get.side_effect = [
            requests.exceptions.ConnectionError(
                "Connection aborted.",
                ConnectionResetError(104, "Connection reset by peer"),
            ),
            ok,
        ]

        body = download_pdf("https://example.com/audit.pdf", session=session)
        assert body == b"%PDF-1.4\n..."
        assert session.get.call_count == 2

    def test_retries_exhausted_raises_download_error(self, monkeypatch):
        """Caps the retry budget — three transient flakes in a row still
        surface as a download failure, not an infinite loop."""
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        session = MagicMock()
        session.get.side_effect = requests.exceptions.ConnectionError(
            "Connection aborted.",
            ConnectionResetError(104, "Connection reset by peer"),
        )

        with pytest.raises(PdfDownloadError, match="fetch error"):
            download_pdf("https://example.com/audit.pdf", session=session)
        assert session.get.call_count == 3

    def test_read_timeout_is_retried_to_success(self, monkeypatch):
        """Slow CDNs surface as ReadTimeout, not ConnectionError. Both are
        transient transport failures and get the same retry treatment."""
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        ok = _mock_response(body=b"%PDF-1.4\n...")
        session = MagicMock()
        session.get.side_effect = [
            requests.exceptions.ReadTimeout("read timed out"),
            ok,
        ]

        body = download_pdf("https://example.com/audit.pdf", session=session)
        assert body == b"%PDF-1.4\n..."
        assert session.get.call_count == 2

    def test_transient_5xx_is_retried_to_success(self, monkeypatch):
        """A 503 from a CDN is the HTTP-level analogue of a connection reset.
        Bucketed with 4xx as fatal pre-fix; should be retried post-fix."""
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        ok = _mock_response(body=b"%PDF-1.4\n...")
        session = MagicMock()
        session.get.side_effect = [_mock_response(status_code=503), ok]

        body = download_pdf("https://example.com/audit.pdf", session=session)
        assert body == b"%PDF-1.4\n..."
        assert session.get.call_count == 2

    def test_fatal_4xx_does_not_retry(self, monkeypatch):
        """404 means the audit URL is dead — retrying just wastes the budget."""
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        session = MagicMock()
        session.get.return_value = _mock_response(status_code=404)

        with pytest.raises(PdfDownloadError, match="HTTP 404"):
            download_pdf("https://example.com/missing.pdf", session=session)
        assert session.get.call_count == 1

    def test_fatal_content_type_does_not_retry(self, monkeypatch):
        """text/html signals a wrong URL was captured at discovery — refetching
        the same URL will keep returning HTML, so this short-circuits."""
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        session = MagicMock()
        session.get.return_value = _mock_response(content_type="text/html")

        with pytest.raises(PdfDownloadError, match="content-type"):
            download_pdf("https://example.com/login.pdf", session=session)
        assert session.get.call_count == 1

    def test_end_to_end_audit_succeeds_after_transient_flake(self, monkeypatch):
        """Closes the loop on the prod failure mode: a single ConnectionReset
        burst made audit rows permanently 'failed'. Post-fix the same flake
        is absorbed by retry and the audit ends as 'success'."""
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        pdf = minimal_pdf_with_text("Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 20)
        session = MagicMock()
        session.get.side_effect = [
            requests.exceptions.ConnectionError(
                "Connection aborted.",
                ConnectionResetError(104, "Connection reset by peer"),
            ),
            _mock_response(body=pdf),
        ]
        monkeypatch.setattr(
            "services.audits.text_extraction.store_audit_text",
            lambda aid, text: (f"audits/text/{aid}.txt", len(text.encode("utf-8")), "f" * 64),
        )

        outcome = process_audit_report(
            audit_report_id=1,
            url="https://example.com/audit.pdf",
            session=session,
        )
        assert outcome.status == "success", (
            f"expected success after transient retry, got {outcome.status}: {outcome.error}"
        )
        assert session.get.call_count == 2


# ---------------------------------------------------------------------------
# audit_text_key — deterministic key format that downstream routes depend on
# ---------------------------------------------------------------------------


def test_audit_text_key_is_deterministic():
    assert audit_text_key(1) == "audits/text/1.txt"
    assert audit_text_key(999999) == "audits/text/999999.txt"


# ---------------------------------------------------------------------------
# download_audit_body — accepts text/* content-types when kind="text"
# ---------------------------------------------------------------------------


class TestDownloadAuditBodyTextMode:
    def test_accepts_text_markdown_content_type(self):
        session = MagicMock()
        session.get.return_value = _mock_response(
            content_type="text/markdown",
            body=b"# Audit Report\n\nFindings...",
        )
        body = download_audit_body(
            "https://raw.githubusercontent.com/x/y/main/audit.md",
            session=session,
            kind="text",
        )
        assert body == b"# Audit Report\n\nFindings..."

    def test_accepts_text_plain_content_type(self):
        session = MagicMock()
        session.get.return_value = _mock_response(
            content_type="text/plain",
            body=b"plain text audit content",
        )
        body = download_audit_body(
            "https://raw.githubusercontent.com/x/y/main/audit.md",
            session=session,
            kind="text",
        )
        assert body == b"plain text audit content"

    def test_accepts_text_x_markdown_content_type(self):
        session = MagicMock()
        session.get.return_value = _mock_response(
            content_type="text/x-markdown",
            body=b"markdown body",
        )
        body = download_audit_body(
            "https://raw.githubusercontent.com/x/y/main/audit.md",
            session=session,
            kind="text",
        )
        assert body == b"markdown body"

    def test_rejects_html_in_text_mode(self):
        """Even in text mode we reject HTML — a GitHub /blob/ URL serves HTML
        which is the code-view page, not the raw markdown."""
        session = MagicMock()
        session.get.return_value = _mock_response(content_type="text/html")
        with pytest.raises(PdfDownloadError, match="content-type"):
            download_audit_body(
                "https://github.com/x/y/blob/main/audit.md",
                session=session,
                kind="text",
            )

    def test_pdf_mode_still_rejects_text_markdown(self):
        """PDF mode must not silently accept markdown — the caller's URL
        said .pdf, so getting text/markdown signals a wrong file."""
        session = MagicMock()
        session.get.return_value = _mock_response(content_type="text/markdown")
        with pytest.raises(PdfDownloadError, match="content-type"):
            download_audit_body(
                "https://example.com/audit.pdf",
                session=session,
                kind="pdf",
            )


# ---------------------------------------------------------------------------
# process_audit_report — markdown / plain-text routing
# ---------------------------------------------------------------------------


_MD_BODY = "# Hats Finance Audit\n\n" + ("\n## Scope\n\nPool.sol, Vault.sol, Strategy.sol. " * 30)


class TestProcessAuditReportTextFiles:
    def test_normalizes_github_blob_markdown_url_before_download(self, monkeypatch):
        captured: dict[str, str] = {}

        def fake_download_text(url, session=None):
            captured["url"] = url
            return _MD_BODY.encode("utf-8")

        monkeypatch.setattr("services.audits.text_extraction.download_text", fake_download_text)
        monkeypatch.setattr(
            "services.audits.text_extraction.store_audit_text",
            lambda aid, text: (f"audits/text/{aid}.txt", len(text.encode("utf-8")), "e" * 64),
        )

        out = process_audit_report(
            audit_report_id=9,
            url="https://github.com/x/y/blob/main/audits/report.md",
        )

        assert out.status == "success"
        assert captured["url"] == "https://raw.githubusercontent.com/x/y/main/audits/report.md"

    def test_markdown_url_success_stores_text_unchanged(self, monkeypatch):
        """URL ending in .md should succeed, skip pypdf entirely, and store
        the decoded text verbatim (no page markers inserted)."""
        captured: dict = {}

        def fake_download_text(url, session=None):
            captured["url"] = url
            captured["mode"] = "text"
            return _MD_BODY.encode("utf-8")

        def fake_store(aid, text):
            captured["text"] = text
            captured["aid"] = aid
            return (f"audits/text/{aid}.txt", len(text.encode("utf-8")), "b" * 64)

        monkeypatch.setattr("services.audits.text_extraction.download_text", fake_download_text)
        # Ensure the pdf path is not taken — monkeypatch to explode if hit.
        monkeypatch.setattr(
            "services.audits.text_extraction.download_pdf",
            lambda *_a, **_kw: pytest.fail("pdf path must not run for .md URL"),
        )
        monkeypatch.setattr("services.audits.text_extraction.store_audit_text", fake_store)

        out = process_audit_report(
            audit_report_id=7,
            url="https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/master/audits/Hats.md",
        )
        assert out.status == "success"
        assert out.storage_key == "audits/text/7.txt"
        assert out.text_size_bytes == len(_MD_BODY.encode("utf-8"))
        assert captured["mode"] == "text"
        # Text is passed to store verbatim — no pypdf page markers.
        assert captured["text"] == _MD_BODY
        assert "--- page 1 ---" not in captured["text"]

    def test_txt_url_success(self, monkeypatch):
        """``.txt`` suffix is also routed through the text-file path."""
        body = ("plain text audit body. " * 60).encode("utf-8")

        monkeypatch.setattr(
            "services.audits.text_extraction.download_text",
            lambda url, session=None: body,
        )
        monkeypatch.setattr(
            "services.audits.text_extraction.store_audit_text",
            lambda aid, text: (f"audits/text/{aid}.txt", len(text.encode("utf-8")), "c" * 64),
        )
        out = process_audit_report(
            audit_report_id=11,
            url="https://example.com/reports/audit.txt",
        )
        assert out.status == "success"

    def test_markdown_under_min_threshold_skipped(self, monkeypatch):
        """The 500-char min-useful-text gate still applies to markdown."""
        monkeypatch.setattr(
            "services.audits.text_extraction.download_text",
            lambda url, session=None: b"tiny md",
        )
        out = process_audit_report(
            audit_report_id=3,
            url="https://raw.githubusercontent.com/x/y/main/small.md",
        )
        assert out.status == "skipped"

    def test_pdf_url_still_uses_pypdf_path(self, monkeypatch):
        """Regression: a .pdf URL must go through the pypdf extraction path,
        not the text decode path."""
        body = minimal_pdf_with_text("Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 20)

        monkeypatch.setattr(
            "services.audits.text_extraction.download_pdf",
            lambda url, session=None: body,
        )
        monkeypatch.setattr(
            "services.audits.text_extraction.download_text",
            lambda *_a, **_kw: pytest.fail("text path must not run for .pdf URL"),
        )
        captured_text: dict = {}

        def fake_store(aid, text):
            captured_text["text"] = text
            return (f"audits/text/{aid}.txt", len(text.encode("utf-8")), "d" * 64)

        monkeypatch.setattr("services.audits.text_extraction.store_audit_text", fake_store)

        out = process_audit_report(
            audit_report_id=42,
            url="https://example.com/audit.pdf",
        )
        assert out.status == "success"
        # pypdf path preserves the --- page N --- markers.
        assert "--- page 1 ---" in captured_text["text"]

    def test_normalizes_github_blob_pdf_url_before_download(self, monkeypatch):
        captured: dict[str, str] = {}

        monkeypatch.setattr(
            "services.audits.text_extraction.download_pdf",
            lambda url, session=None: (
                captured.setdefault("url", url),
                minimal_pdf_with_text("Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 20),
            )[1],
        )
        monkeypatch.setattr(
            "services.audits.text_extraction.store_audit_text",
            lambda aid, text: (f"audits/text/{aid}.txt", len(text.encode("utf-8")), "f" * 64),
        )

        out = process_audit_report(
            audit_report_id=43,
            url="https://github.com/x/y/blob/main/audits/report.pdf",
        )

        assert out.status == "success"
        assert captured["url"] == "https://raw.githubusercontent.com/x/y/main/audits/report.pdf"


def test_normalize_download_url_rewrites_github_blob_files():
    assert _normalize_download_url("https://github.com/a/b/blob/main/foo.pdf") == (
        "https://raw.githubusercontent.com/a/b/main/foo.pdf"
    )
