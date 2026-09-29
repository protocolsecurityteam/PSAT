"""Pure-logic tests for audit-pipeline internals the integration suite no longer exercises: the
``_collapse_same_audit_mirrors`` heuristic fallback (used only when LLM validate+cluster fails), chunking
and extraction helpers, follow-up query cleanup, classifier threshold, and process_audit_report error
paths. No DB, HTTP or object storage; ``llm.chat`` and storage/download functions are monkeypatched.
"""

from __future__ import annotations

import json

import pytest
import requests

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
    _extract_one_chunk,
    classify_search_results,
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


# ---------------------------------------------------------------------------
# _collapse_same_audit_mirrors — heuristic fallback when LLM is unavailable.
# Three passes, each designed not to merge genuinely distinct audits.
# ---------------------------------------------------------------------------


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
        """Pass 1: Unknown-auditor entry on a host that no named same-date
        entry uses looks like a cross-host mirror — drop it."""
        reports = [
            _report(url="https://real.com/x.pdf", auditor="Halborn"),
            _report(url="https://mirror.xyz/x.pdf", auditor="Unknown"),
        ]
        out = _collapse_same_audit_mirrors(reports)
        assert [r["auditor"] for r in out] == ["Halborn"]

    def test_keeps_same_host_unknown_sibling(self):
        """Pass 1: an Unknown on the same host as a named entry is a sibling
        file whose auditor the LLM missed — don't drop it."""
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

    def test_same_auditor_same_day_different_products_survive(self):
        """Pass 3: Certora's same-day v2.49 vs Instant-Withdrawal audits have
        distinct title tokens → don't collapse."""
        a = _report(
            auditor="Certora",
            date="2024-05-01",
            title="EtherFi v2.49",
            url="https://github.com/a/v249.pdf",
            pdf_url="https://github.com/a/v249.pdf",
        )
        b = _report(
            auditor="Certora",
            date="2024-05-01",
            title="EtherFi Instant Withdrawal",
            url="https://github.com/a/instant.pdf",
            pdf_url="https://github.com/a/instant.pdf",
        )
        out = _collapse_same_audit_mirrors([a, b])
        assert len(out) == 2

    def test_pass3_collapses_same_tokens_across_hosts(self):
        a = _report(
            auditor="OpenZeppelin",
            date="2024-06-01",
            title="Morpho Blue",
            url="https://docs.morpho.org/audit.pdf",
            pdf_url=None,
        )
        b = _report(
            auditor="OpenZeppelin",
            date="2024-06-01",
            title="Morpho Blue Audit Report",
            url="https://github.com/morpho/audits/oz.pdf",
            pdf_url="https://github.com/morpho/audits/oz.pdf",
        )
        out = _collapse_same_audit_mirrors([a, b])
        assert len(out) == 1
        assert out[0]["pdf_url"]

    def test_no_titles_bypasses_pass3(self):
        """Pass 3 skips entries with no meaningful title tokens — collapsing
        them would be too risky."""
        reports = [
            _report(auditor="X", date="2024-01-01", title="", url="https://a/1.pdf"),
            _report(auditor="X", date="2024-01-01", title="", url="https://b/2.pdf"),
        ]
        # Cross-host pass 2 still catches these: both have named auditor +
        # same date + different hosts → collapse to one.
        out = _collapse_same_audit_mirrors(reports)
        assert len(out) == 1


# ---------------------------------------------------------------------------
# _chunked_text — page-splitter for long gitbook/SPA bodies
# ---------------------------------------------------------------------------


class TestChunkedText:
    @pytest.mark.parametrize(
        "text",
        [
            pytest.param("small text", id="short"),
            pytest.param("B" * 15_000, id="exactly-at-cap"),
        ],
    )
    def test_text_within_cap_returns_single_chunk(self, text):
        assert _chunked_text(text) == [text]

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
        # Consecutive chunks overlap by ``overlap`` chars so contracts
        # straddling the boundary aren't lost.
        assert chunks[0][-100:] == chunks[1][:100]


# ---------------------------------------------------------------------------
# _extract_one_chunk — LLM call + JSON parsing for one slice
# ---------------------------------------------------------------------------


class TestExtractOneChunk:
    def test_happy_path_returns_parsed_object(self, monkeypatch):
        import json

        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: json.dumps({"reports": [{"auditor": "OZ", "title": "X", "date": "2024-01-01"}]}),
        )
        out = _extract_one_chunk("https://x.com", "some page text", "Acme")
        assert out == {"reports": [{"auditor": "OZ", "title": "X", "date": "2024-01-01"}]}

    @pytest.mark.parametrize(
        "chat", [_raising("LLM exploded"), _returning("not json")], ids=["llm-raises", "unparseable"]
    )
    def test_llm_failure_returns_none(self, monkeypatch, chat):
        monkeypatch.setattr("services.discovery.audit_reports_llm.llm.chat", chat)
        assert _extract_one_chunk("https://x.com", "text", "Acme") is None


# ---------------------------------------------------------------------------
# extract_report_details — multi-chunk dedup + relative-URL resolution
# ---------------------------------------------------------------------------


class TestExtractReportDetails:
    def test_none_when_every_chunk_fails(self, monkeypatch):
        def raising(*_a, **_kw):
            raise RuntimeError("x")

        monkeypatch.setattr("services.discovery.audit_reports_llm.llm.chat", raising)
        assert extract_report_details("https://x.com", "text", "Acme") is None

    def test_resolves_relative_pdf_url(self, monkeypatch):
        """PDFs discovered via a ``<a href="/path">`` link come back as
        absolute paths from the LLM; the orchestrator must ``urljoin`` them
        against the source page."""
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


# ---------------------------------------------------------------------------
# generate_followup_query — quote-handling + length cap + failure modes
# ---------------------------------------------------------------------------


class TestGenerateFollowupQuery:
    def test_empty_initial_returns_canned_fallback(self):
        """Nothing from Tavily → use a deterministic fallback query that
        doesn't burn an LLM call."""
        q = generate_followup_query([], "Morpho")
        assert q is not None
        assert "Morpho" in q

    @pytest.mark.parametrize(
        ("chat", "expected"),
        [
            # LLM strips to empty -> None so the caller skips the second Tavily
            # query (falsy means no follow-up).
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
        """The LLM sometimes produces ``'foo"`` or ``"foo'`` — scrub to avoid
        passing a syntactically-invalid search query downstream."""
        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: '"aave audit',
        )
        q = generate_followup_query([{"title": "t", "url": "u"}], "Aave")
        assert q is not None
        assert '"' not in q


# ---------------------------------------------------------------------------
# classify_search_results — confidence threshold + LLM error paths
# ---------------------------------------------------------------------------


class TestClassifySearchResults:
    @pytest.mark.parametrize(
        "chat",
        [
            pytest.param(
                _returning(json.dumps([{"url": "https://x.com", "is_audit": False, "confidence": 0.95}])),
                id="is-audit-false-filtered",
            ),
            pytest.param(_raising("LLM down"), id="llm-raises"),
        ],
    )
    def test_classify_returns_empty(self, monkeypatch, chat):
        monkeypatch.setattr("services.discovery.audit_reports_llm.llm.chat", chat)
        out = classify_search_results([{"url": "https://x.com", "title": "t", "content": "c"}], "Acme")
        assert out == []


# ---------------------------------------------------------------------------
# text_extraction.process_audit_report — error-path coverage that the
# integration suite's happy path doesn't exercise.
# ---------------------------------------------------------------------------


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
            # Image-only PDFs return near-empty text; worker marks skipped so OCR can be handled later.
            pytest.param(
                "https://x/a.pdf",
                _returning(minimal_pdf_with_text("tiny")),
                None,
                "skipped",
                ("image-only",),
                id="short-text",
            ),
            # Download+parse succeed but object storage rejects the write: must surface as
            # ``failed`` so the worker can retry.
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

    def test_success_returns_all_metadata(self, monkeypatch):
        pdf = minimal_pdf_with_text("Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 20)
        monkeypatch.setattr(
            "services.audits.text_extraction.download_pdf",
            lambda *_a, **_kw: pdf,
        )
        monkeypatch.setattr(
            "services.audits.text_extraction.store_audit_text",
            lambda aid, text: (f"audits/text/{aid}.txt", len(text), "a" * 64),
        )
        out = process_audit_report(audit_report_id=42, url="https://x/a.pdf")
        assert out.status == "success"
        assert out.storage_key == "audits/text/42.txt"
        assert out.text_size_bytes and out.text_size_bytes > 0
        assert out.text_sha256 == "a" * 64


# ---------------------------------------------------------------------------
# _fetch_html_page — SSRF egress guard routing + preserved download protections.
#
# The candidate URLs come from attacker-seedable Exa/Tavily results, and the
# fetched HTML feeds LLM extraction whose output is stored on ``AuditReport``
# and served publicly. So the outbound request must go through the shared
# egress guard (``utils.egress.safe_get``), and the pre-existing download-cap /
# binary-rejection protections must survive that reroute.
# ---------------------------------------------------------------------------


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
    @pytest.mark.parametrize(
        ("safe_get", "expected"),
        [
            pytest.param(
                lambda *a, **kw: _FakeResp(chunks=[b"<html>hello world</html>"]),
                "<html>hello world</html>",
                id="normal-page-parses",
            ),
            pytest.param(lambda *a, **kw: _FakeResp(status_code=404), None, id="non-200"),
            pytest.param(_raising_as(requests.RequestException, "connection reset"), None, id="request-exception"),
        ],
    )
    def test_fetch_outcome(self, monkeypatch, safe_get, expected):
        monkeypatch.setattr("utils.egress.safe_get", safe_get)
        assert _fetch_html_page("https://example.com/report") == expected

    def test_internal_target_refused_without_raising(self, monkeypatch):
        """A URL whose host would resolve to an internal address is refused by
        the guard and treated as a plain fetch failure (None, no exception).

        This also proves the request is routed through ``safe_get``: the raw
        ``requests.get`` is booby-trapped, so reverting to it would fetch the
        internal URL and blow up here instead of returning None."""
        from utils.egress import UnsafeUrlError

        def refuse(*_a, **_kw):
            raise UnsafeUrlError("host resolves to non-public address 169.254.169.254")

        def raw_egress_tripwire(*_a, **_kw):
            raise AssertionError("raw requests.get reached — SSRF guard bypassed")

        monkeypatch.setattr("utils.egress.safe_get", refuse)
        monkeypatch.setattr(
            "services.discovery.audit_reports._fetch._requests.get",
            raw_egress_tripwire,
        )

        out = _fetch_html_page("http://169.254.169.254/latest/meta-data/")
        assert out is None

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
        # Reads whole chunks until downloaded >= cap, then stops: exactly the
        # first ceil(cap / chunk) chunks, nowhere near the 6.4 MB offered.
        assert len(out) == _MAX_DOWNLOAD_BYTES
        assert len(out) < sum(len(c) for c in oversized)
