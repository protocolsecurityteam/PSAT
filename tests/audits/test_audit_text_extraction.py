"""The worker loop is covered by ``test_audit_text_extraction_integration.py``, which stubs ``download_pdf``
wholesale.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from services.audits.text_extraction import (
    PdfDownloadError,
    PdfParseError,
    PdfTooLargeError,
    audit_text_key,
    download_audit_body,
    download_pdf,
    extract_text_from_pdf,
    process_audit_report,
)
from tests.support.pdf import minimal_pdf_with_text


class TestExtractTextFromPdf:
    def test_roundtrips_simple_ascii(self):
        body = minimal_pdf_with_text("Audit scope covers Pool.sol and Vault.sol.")
        text = extract_text_from_pdf(body)
        assert "Pool.sol" in text
        assert "Vault.sol" in text
        assert "--- page 1 ---" in text

    @pytest.mark.parametrize("body", [b"not a pdf at all", b""], ids=["garbage_body", "empty_body"])
    def test_unparseable_body_raises_parse_error(self, body):
        with pytest.raises(PdfParseError):
            extract_text_from_pdf(body)

    def test_link_annotation_uris_are_included_in_extracted_text(self):
        """Certora embeds commit SHAs as hyperlinks that ``extract_text()`` drops, leaving ``reviewed_commits``
        empty.
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

        assert sha in text, f"commit SHA from link annotation lost in extraction. Extracted text: {text!r}"

    def test_link_annotations_across_multiple_pages(self):
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
        assert "--- page 1 ---" in text
        assert "--- page 2 ---" in text

    def test_non_link_annotations_do_not_leak_garbage(self):
        """Only ``/Link`` annotations with ``/A/URI`` count."""
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

    def test_end_to_end_link_sha_reaches_reviewed_commits_extractor(self):
        """The Certora-V3.Prelude-1 case: a hyperlinked "commit" with no inline SHA."""
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


# The integration suite stubs download_pdf wholesale, so these break unnoticed when a publisher changes CDN behaviour.


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
        """Soft-redirects (login walls, 200 HTML) are the main cause of misclassified bodies."""
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
        """Content-Length is optional."""
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


# Prod saw bursts of ConnectionResetError(104) from Code4rena / Sherlock; requests wraps it as ConnectionError.


class TestDownloadAuditBodyRetry:
    @pytest.mark.parametrize(
        "failure",
        [
            pytest.param(
                requests.exceptions.ConnectionError(
                    "Connection aborted.",
                    ConnectionResetError(104, "Connection reset by peer"),
                ),
                id="connection_error",
            ),
            pytest.param(requests.exceptions.ReadTimeout("read timed out"), id="read_timeout"),
            # 503 used to be bucketed with 4xx as fatal.
            pytest.param(_mock_response(status_code=503), id="transient_5xx"),
        ],
    )
    def test_transient_failure_is_retried_to_success(self, monkeypatch, failure):
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        ok = _mock_response(body=b"%PDF-1.4\n...")
        session = MagicMock()
        session.get.side_effect = [failure, ok]

        body = download_pdf("https://example.com/audit.pdf", session=session)
        assert body == b"%PDF-1.4\n..."
        assert session.get.call_count == 2

    def test_retries_exhausted_raises_download_error(self, monkeypatch):
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        session = MagicMock()
        session.get.side_effect = requests.exceptions.ConnectionError(
            "Connection aborted.",
            ConnectionResetError(104, "Connection reset by peer"),
        )

        with pytest.raises(PdfDownloadError, match="fetch error"):
            download_pdf("https://example.com/audit.pdf", session=session)
        assert session.get.call_count == 3

    @pytest.mark.parametrize(
        ("response_kwargs", "url", "match"),
        [
            pytest.param({"status_code": 404}, "https://example.com/missing.pdf", "HTTP 404", id="fatal_4xx"),
            # HTML means a wrong URL was captured at discovery; refetching keeps returning it.
            pytest.param(
                {"content_type": "text/html"}, "https://example.com/login.pdf", "content-type", id="fatal_content_type"
            ),
        ],
    )
    def test_fatal_failure_does_not_retry(self, monkeypatch, response_kwargs, url, match):
        monkeypatch.setattr("services.audits.text_extraction._retry_sleep", lambda _s: None, raising=False)

        session = MagicMock()
        session.get.return_value = _mock_response(**response_kwargs)

        with pytest.raises(PdfDownloadError, match=match):
            download_pdf(url, session=session)
        assert session.get.call_count == 1


def test_audit_text_key_is_deterministic():
    assert audit_text_key(1) == "audits/text/1.txt"
    assert audit_text_key(999999) == "audits/text/999999.txt"


class TestDownloadAuditBodyTextMode:
    @pytest.mark.parametrize(
        ("content_type", "payload"),
        [
            pytest.param("text/markdown", b"# Audit Report\n\nFindings...", id="text_markdown"),
            pytest.param("text/plain", b"plain text audit content", id="text_plain"),
            pytest.param("text/x-markdown", b"markdown body", id="text_x_markdown"),
        ],
    )
    def test_accepts_text_content_type(self, content_type, payload):
        session = MagicMock()
        session.get.return_value = _mock_response(content_type=content_type, body=payload)
        body = download_audit_body(
            "https://raw.githubusercontent.com/x/y/main/audit.md",
            session=session,
            kind="text",
        )
        assert body == payload

    def test_rejects_html_in_text_mode(self):
        """A GitHub /blob/ URL serves the HTML code view."""
        session = MagicMock()
        session.get.return_value = _mock_response(content_type="text/html")
        with pytest.raises(PdfDownloadError, match="content-type"):
            download_audit_body(
                "https://github.com/x/y/blob/main/audit.md",
                session=session,
                kind="text",
            )

    def test_pdf_mode_still_rejects_text_markdown(self):
        session = MagicMock()
        session.get.return_value = _mock_response(content_type="text/markdown")
        with pytest.raises(PdfDownloadError, match="content-type"):
            download_audit_body(
                "https://example.com/audit.pdf",
                session=session,
                kind="pdf",
            )


_MD_BODY = "# Hats Finance Audit\n\n" + ("\n## Scope\n\nPool.sol, Vault.sol, Strategy.sol. " * 30)


class TestProcessAuditReportTextFiles:
    @pytest.mark.parametrize(
        ("downloader", "payload", "audit_id", "blob_url", "raw_url"),
        [
            pytest.param(
                "download_text",
                _MD_BODY.encode("utf-8"),
                9,
                "https://github.com/x/y/blob/main/audits/report.md",
                "https://raw.githubusercontent.com/x/y/main/audits/report.md",
                id="markdown",
            ),
            pytest.param(
                "download_pdf",
                minimal_pdf_with_text("Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 20),
                43,
                "https://github.com/x/y/blob/main/audits/report.pdf",
                "https://raw.githubusercontent.com/x/y/main/audits/report.pdf",
                id="pdf",
            ),
        ],
    )
    def test_normalizes_github_blob_url_before_download(
        self, monkeypatch, downloader, payload, audit_id, blob_url, raw_url
    ):
        captured: dict[str, str] = {}

        def fake_download(url, session=None):
            captured["url"] = url
            return payload

        monkeypatch.setattr(f"services.audits.text_extraction.{downloader}", fake_download)
        monkeypatch.setattr(
            "services.audits.text_extraction.store_audit_text",
            lambda aid, text: (f"audits/text/{aid}.txt", len(text.encode("utf-8")), "e" * 64),
        )

        out = process_audit_report(audit_report_id=audit_id, url=blob_url)

        assert out.status == "success"
        assert captured["url"] == raw_url

    def test_markdown_url_success_stores_text_unchanged(self, monkeypatch):
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
        assert captured["text"] == _MD_BODY
        assert "--- page 1 ---" not in captured["text"]

    def test_txt_url_success(self, monkeypatch):
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
        assert "--- page 1 ---" in captured_text["text"]
