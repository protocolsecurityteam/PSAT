"""Pure-logic tests for internals the integration suite no longer exercises; no DB, HTTP or object storage."""

from __future__ import annotations

import pytest

from services.audits.text_extraction import (
    PdfDownloadError,
    PdfTooLargeError,
    StorageWriteError,
    process_audit_report,
)
from services.discovery.audit_reports._dedup import _collapse_same_audit_mirrors
from services.discovery.audit_reports._fetch import (
    _MAX_DOWNLOAD_BYTES,
    _fetch_html_page,
)
from services.discovery.audit_reports_llm import (
    _chunked_text,
    extract_report_details,
    generate_followup_query,
)
from tests.support.pdf import minimal_pdf_with_text

_LONG_PDF = minimal_pdf_with_text("Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 20)


def _raising(message):
    def boom(*_a, **_kw):
        raise RuntimeError(message)

    return boom


def _raising_as(exc_type, message):
    def boom(*_a, **_kw):
        raise exc_type(message)

    return boom


def _returning(value):
    return lambda *_a, **_kw: value


# The heuristic fallback when the LLM is unavailable; each pass must not merge distinct audits.


def _report(**overrides) -> dict:
    base = {
        "url": "https://example.com/x.pdf",
        "pdf_url": "https://example.com/x.pdf",
        "auditor": "Unknown",
        "title": "Audit",
        "date": "2024-06-01",
    }
    base.update(overrides)
    return base


class TestCollapseSameAuditMirrors:
    def test_drops_unknown_on_unique_host_when_same_date_named_exists(self):
        """Pass 1: an Unknown-auditor entry on a host no named same-date entry uses looks like a mirror."""
        reports = [
            _report(url="https://real.com/x.pdf", auditor="Halborn"),
            _report(url="https://mirror.xyz/x.pdf", auditor="Unknown"),
        ]
        out = _collapse_same_audit_mirrors(reports)
        assert [r["auditor"] for r in out] == ["Halborn"]

    def test_keeps_same_host_unknown_sibling(self):
        """Pass 1: an Unknown on the same host is a sibling file whose auditor the LLM missed."""
        reports = [
            _report(url="https://github.com/x/y/a.pdf", auditor="Halborn"),
            _report(url="https://github.com/x/y/b.pdf", auditor="Unknown"),
        ]
        out = _collapse_same_audit_mirrors(reports)
        assert len(out) == 2

    def test_cross_host_named_mirror_collapses_to_richest(self):
        sparse = _report(
            url="https://docs.x.com/audit",
            pdf_url=None,
            auditor="Spearbit",
            title="Audit",
            date="2024-06-01",
        )
        rich = _report(
            url="https://github.com/x/y/2024-06-01-spearbit.pdf",
            pdf_url="https://github.com/x/y/2024-06-01-spearbit.pdf",
            auditor="Spearbit",
            title="Spearbit Review",
            date="2024-06-01",
        )
        out = _collapse_same_audit_mirrors([sparse, rich])
        assert len(out) == 1
        assert out[0]["pdf_url"]  # richer entry retained

    def test_no_titles_bypasses_pass3(self):
        """Pass 3: collapsing entries with no title tokens would be too risky."""
        reports = [
            _report(auditor="X", date="2024-01-01", title="", url="https://a/1.pdf"),
            _report(auditor="X", date="2024-01-01", title="", url="https://b/2.pdf"),
        ]
        # Pass 2 still collapses them: named auditor, same date, different hosts.
        out = _collapse_same_audit_mirrors(reports)
        assert len(out) == 1


class TestChunkedText:
    @pytest.mark.parametrize(
        "size",
        [
            pytest.param(45_000, id="long"),
            pytest.param(300_000, id="huge-still-capped"),
        ],
    )
    def test_long_text_splits_into_overlapping_windows(self, size):
        text = "A" * size
        chunks = _chunked_text(text)
        assert len(chunks) == 3  # _MAX_CHUNKS
        assert all(len(c) <= 15_000 for c in chunks)
        # Overlap keeps contracts that straddle a chunk boundary.
        assert chunks[0][-100:] == chunks[1][:100]


class TestExtractReportDetails:
    def test_none_when_every_chunk_fails(self, monkeypatch):
        def raising(*_a, **_kw):
            raise RuntimeError("x")

        monkeypatch.setattr("services.discovery.audit_reports_llm.llm.chat", raising)
        assert extract_report_details("https://x.com", "text", "Acme") is None

    def test_resolves_relative_pdf_url(self, monkeypatch):
        """The LLM returns root-relative paths, which must be joined against the source page."""
        import json

        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: json.dumps(
                {
                    "reports": [
                        {"auditor": "X", "title": "Y", "pdf_url": "/audits/report.pdf"},
                    ],
                    "linked_urls": ["/other", "already-absolute"],
                }
            ),
        )
        out = extract_report_details("https://host.com/page", "text", "Acme")
        assert out is not None
        assert out["reports"][0]["pdf_url"] == "https://host.com/audits/report.pdf"

    def test_drops_reports_missing_auditor_or_title(self, monkeypatch):
        import json

        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: json.dumps(
                {
                    "reports": [
                        {"auditor": "Halborn", "title": "", "pdf_url": "https://x/a.pdf"},
                        {"auditor": "", "title": "Some Audit", "pdf_url": "https://x/b.pdf"},
                        {"auditor": "OZ", "title": "Valid", "pdf_url": "https://x/c.pdf"},
                    ],
                    "linked_urls": [],
                }
            ),
        )
        out = extract_report_details("https://x.com", "text", "Acme")
        assert out is not None
        assert [r["auditor"] for r in out["reports"]] == ["OZ"]


class TestGenerateFollowupQuery:
    def test_empty_initial_returns_canned_fallback(self):
        """The fallback query doesn't burn an LLM call."""
        q = generate_followup_query([], "Morpho")
        assert q is not None
        assert "Morpho" in q

    @pytest.mark.parametrize(
        ("chat", "expected"),
        [
            # None means no follow-up Tavily query.
            pytest.param(_returning(""), None, id="empty-llm-response"),
            pytest.param(_returning('"aave audits 2024"'), "aave audits 2024", id="strips-surrounding-quotes"),
            pytest.param(_returning("x" * 300), None, id="overlong-response-rejected"),
            pytest.param(_raising("llm down"), None, id="llm-raises"),
        ],
    )
    def test_followup_query_from_llm_response(self, monkeypatch, chat, expected):
        monkeypatch.setattr("services.discovery.audit_reports_llm.llm.chat", chat)
        assert generate_followup_query([{"title": "t", "url": "u"}], "Aave") == expected

    def test_mismatched_quotes_are_scrubbed(self, monkeypatch):
        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: '"aave audit',
        )
        q = generate_followup_query([{"title": "t", "url": "u"}], "Aave")
        assert q is not None
        assert '"' not in q


class TestProcessAuditReportErrorPaths:
    @pytest.mark.parametrize(
        ("url", "download", "store", "status", "error_parts"),
        [
            pytest.param("", _raising("unused"), None, "failed", ("no URL",), id="missing-url"),
            pytest.param(
                "https://x/a.pdf",
                _raising_as(PdfDownloadError, "HTTP 503"),
                None,
                "failed",
                ("HTTP 503",),
                id="http-failure",
            ),
            pytest.param(
                "https://x/huge.pdf",
                _raising_as(PdfTooLargeError, "streamed body exceeded cap"),
                None,
                "skipped",
                ("too large",),
                id="oversized-pdf",
            ),
            pytest.param("https://x/a.pdf", _returning(b"not a pdf"), None, "failed", ("parse",), id="parse-error"),
            pytest.param(
                "https://x/a.pdf",
                _returning(minimal_pdf_with_text("tiny")),
                None,
                "skipped",
                ("image-only",),
                id="short-text",
            ),
            # ``failed`` lets the worker retry.
            pytest.param(
                "https://x/a.pdf",
                _returning(_LONG_PDF),
                _raising_as(StorageWriteError, "tigris down"),
                "failed",
                ("store", "tigris"),
                id="storage-failure",
            ),
        ],
    )
    def test_error_paths(self, monkeypatch, url, download, store, status, error_parts):
        monkeypatch.setattr("services.audits.text_extraction.download_pdf", download)
        if store is not None:
            monkeypatch.setattr("services.audits.text_extraction.store_audit_text", store)
        out = process_audit_report(audit_report_id=1, url=url)
        assert out.status == status
        for part in error_parts:
            assert part in (out.error or "")


# Candidate URLs come from attacker-seedable search results and the output is served publicly, so fetches go through
# ``utils.egress.safe_get`` and keep the download cap.


class _FakeResp:
    def __init__(self, *, status_code=200, content_type="text/html", chunks=()):
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        self._chunks = list(chunks)
        self.closed = False

    def iter_content(self, chunk_size=64_000):
        yield from self._chunks

    def close(self):
        self.closed = True


class TestFetchHtmlPage:
    def test_binary_content_type_rejected(self, monkeypatch):
        resp = _FakeResp(content_type="application/pdf", chunks=[b"%PDF-1.7 ..."])
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: resp)

        out = _fetch_html_page("https://example.com/report")
        assert out is None
        assert resp.closed is True

    def test_download_cap_still_truncates(self, monkeypatch):
        oversized = [b"a" * 64_000 for _ in range(100)]  # 6.4 MB offered
        resp = _FakeResp(chunks=oversized)
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: resp)

        out = _fetch_html_page("https://example.com/huge")
        assert out is not None
        # Reading stops at the first chunk crossing the cap.
        assert len(out) == _MAX_DOWNLOAD_BYTES
        assert len(out) < sum(len(c) for c in oversized)
