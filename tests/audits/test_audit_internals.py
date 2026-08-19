"""Targeted pure-logic tests for audit-pipeline internals.

When the mock-heavy orchestrator tests were deleted in favour of the
``test_audit_discovery_integration.py`` integration suite, a handful of
internal-helper branches stopped being exercised:

    - ``_collapse_same_audit_mirrors`` — the heuristic fallback used only
      when the LLM validate+cluster call fails (integration tests always
      hit the LLM path).
    - ``audit_reports_llm._chunked_text`` / ``_extract_one_chunk`` —
      chunking for long gitbook pages, and the per-chunk LLM error path.
    - ``extract_report_details`` — dedup across chunks, malformed entries,
      None-returning LLM.
    - ``generate_followup_query`` — empty/long/mismatched-quote responses.
    - ``classify_search_results`` — LLM exception + confidence threshold.
    - ``text_extraction.process_audit_report`` — download/parse/store error
      paths that the integration suite's happy path doesn't hit.

All tests here are pure Python (monkeypatched ``llm.chat`` for the LLM
helpers; ``monkeypatch`` on ``download_pdf`` / ``store_audit_text`` for
the text-extraction orchestrator). No DB, no HTTP, no object storage.
"""

from __future__ import annotations

from services.audits.text_extraction import (
    ExtractionOutcome,
    PdfDownloadError,
    PdfParseError,
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
            # Unknown on a different host → classic cross-host mirror signature.
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
        """Pass 2: same (auditor, date) on two hosts → keep the richest."""
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

    def test_all_on_one_host_defers_to_pass3(self):
        """Pass 2 skips single-host groups so pass 3's title-token logic can
        handle same-auditor-same-day siblings correctly."""
        a = _report(
            auditor="Halborn",
            date="2024-06-01",
            url="https://github.com/x/y/a.pdf",
            pdf_url="https://github.com/x/y/a.pdf",
            title="Audit A",
        )
        b = _report(
            auditor="Halborn",
            date="2024-06-01",
            url="https://github.com/x/y/b.pdf",
            pdf_url="https://github.com/x/y/b.pdf",
            title="Audit B",
        )
        # Distinct tokens → pass 3 keeps both.
        assert len(_collapse_same_audit_mirrors([a, b])) == 2

    def test_pass3_collapses_same_tokens_across_hosts(self):
        """Pass 3: (auditor, date, title-tokens) match → collapse to richest."""
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

    def test_empty_input_returns_empty(self):
        assert _collapse_same_audit_mirrors([]) == []

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
    def test_short_text_returns_single_chunk(self):
        assert _chunked_text("small text") == ["small text"]

    def test_long_text_splits_into_overlapping_windows(self):
        text = "A" * 45_000
        chunks = _chunked_text(text)
        assert len(chunks) == 3  # _MAX_CHUNKS
        # Each chunk is at most the cap size.
        assert all(len(c) <= 15_000 for c in chunks)
        # Consecutive chunks overlap by ``overlap`` chars so contracts
        # straddling the boundary aren't lost.
        assert chunks[0][-100:] == chunks[1][:100]

    def test_exactly_at_cap_stays_one_chunk(self):
        text = "B" * 15_000
        assert _chunked_text(text) == [text]

    def test_caps_at_max_chunks_even_for_huge_text(self):
        """A 300k-char page should not produce 20 chunks — we cap at 3."""
        text = "C" * 300_000
        assert len(_chunked_text(text)) == 3


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

    def test_llm_raises_returns_none(self, monkeypatch):
        def boom(*_a, **_kw):
            raise RuntimeError("LLM exploded")

        monkeypatch.setattr("services.discovery.audit_reports_llm.llm.chat", boom)
        assert _extract_one_chunk("https://x.com", "text", "Acme") is None

    def test_unparseable_response_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: "not json",
        )
        assert _extract_one_chunk("https://x.com", "text", "Acme") is None


# ---------------------------------------------------------------------------
# extract_report_details — multi-chunk dedup + relative-URL resolution
# ---------------------------------------------------------------------------


class TestExtractReportDetails:
    def test_single_chunk_passes_through(self, monkeypatch):
        import json

        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: json.dumps(
                {
                    "reports": [
                        {
                            "auditor": "Halborn",
                            "title": "Audit",
                            "date": "2024-05-01",
                            "pdf_url": "https://x.com/a.pdf",
                        }
                    ],
                    "linked_urls": [],
                }
            ),
        )
        out = extract_report_details("https://x.com/page", "short text", "Acme")
        assert out is not None
        assert len(out["reports"]) == 1
        assert out["reports"][0]["pdf_url"] == "https://x.com/a.pdf"

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

    def test_empty_llm_response_returns_none(self, monkeypatch):
        """LLM strips to empty → None so the caller skips the second Tavily
        query (falsy means no follow-up)."""
        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: "",
        )
        assert generate_followup_query([{"title": "t", "url": "u"}], "X") is None

    def test_strips_surrounding_quotes(self, monkeypatch):
        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: '"aave audits 2024"',
        )
        q = generate_followup_query([{"title": "t", "url": "u"}], "Aave")
        assert q == "aave audits 2024"

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

    def test_overlong_response_rejected(self, monkeypatch):
        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: "x" * 300,
        )
        assert generate_followup_query([{"title": "t", "url": "u"}], "X") is None

    def test_llm_raises_returns_none(self, monkeypatch):
        def boom(*_a, **_kw):
            raise RuntimeError("llm down")

        monkeypatch.setattr("services.discovery.audit_reports_llm.llm.chat", boom)
        assert generate_followup_query([{"title": "t", "url": "u"}], "X") is None


# ---------------------------------------------------------------------------
# classify_search_results — confidence threshold + LLM error paths
# ---------------------------------------------------------------------------


class TestClassifySearchResults:
    def test_empty_input_short_circuits(self):
        assert classify_search_results([], "X") == []

    def test_below_confidence_threshold_filtered(self, monkeypatch):
        import json

        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: json.dumps(
                [
                    {
                        "url": "https://x.com",
                        "is_audit": True,
                        "auditor": "X",
                        "title": "Y",
                        "date": "2024",
                        "confidence": 0.3,
                    },
                ]
            ),
        )
        out = classify_search_results([{"url": "https://x.com", "title": "t", "content": "c"}], "Acme")
        assert out == []

    def test_is_audit_false_filtered(self, monkeypatch):
        import json

        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: json.dumps(
                [
                    {"url": "https://x.com", "is_audit": False, "confidence": 0.95},
                ]
            ),
        )
        out = classify_search_results([{"url": "https://x.com", "title": "t", "content": "c"}], "Acme")
        assert out == []

    def test_llm_raises_returns_empty(self, monkeypatch):
        def boom(*_a, **_kw):
            raise RuntimeError("LLM down")

        monkeypatch.setattr("services.discovery.audit_reports_llm.llm.chat", boom)
        out = classify_search_results([{"url": "https://x.com", "title": "t", "content": "c"}], "X")
        assert out == []

    def test_unparseable_response_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            "services.discovery.audit_reports_llm.llm.chat",
            lambda *_a, **_kw: "not a json array",
        )
        out = classify_search_results([{"url": "https://x.com", "title": "t", "content": "c"}], "X")
        assert out == []


# ---------------------------------------------------------------------------
# text_extraction.process_audit_report — error-path coverage that the
# integration suite's happy path doesn't exercise.
# ---------------------------------------------------------------------------


class TestProcessAuditReportErrorPaths:
    def test_missing_url_returns_failed(self):
        out = process_audit_report(audit_report_id=1, url="")
        assert out.status == "failed"
        assert "no URL" in (out.error or "")

    def test_http_failure_returns_failed(self, monkeypatch):
        def raising(*_a, **_kw):
            raise PdfDownloadError("HTTP 503")

        monkeypatch.setattr("services.audits.text_extraction.download_pdf", raising)
        out = process_audit_report(audit_report_id=1, url="https://x/a.pdf")
        assert out.status == "failed"
        assert "HTTP 503" in (out.error or "")

    def test_oversized_pdf_returns_skipped(self, monkeypatch):
        def too_big(*_a, **_kw):
            raise PdfTooLargeError("streamed body exceeded cap")

        monkeypatch.setattr("services.audits.text_extraction.download_pdf", too_big)
        out = process_audit_report(audit_report_id=1, url="https://x/huge.pdf")
        assert out.status == "skipped"
        assert "too large" in (out.error or "")

    def test_parse_error_returns_failed(self, monkeypatch):
        monkeypatch.setattr(
            "services.audits.text_extraction.download_pdf",
            lambda *_a, **_kw: b"not a pdf",
        )
        out = process_audit_report(audit_report_id=1, url="https://x/a.pdf")
        assert out.status == "failed"
        assert "parse" in (out.error or "")

    def test_short_text_returns_skipped(self, monkeypatch):
        """Image-only PDFs return near-empty text — worker marks skipped so
        OCR can be handled separately later."""
        monkeypatch.setattr(
            "services.audits.text_extraction.download_pdf",
            lambda *_a, **_kw: minimal_pdf_with_text("tiny"),
        )
        out = process_audit_report(audit_report_id=1, url="https://x/a.pdf")
        assert out.status == "skipped"
        assert "image-only" in (out.error or "")

    def test_storage_failure_returns_failed(self, monkeypatch):
        """When download+parse succeed but object storage rejects the write,
        the outcome must surface as ``failed`` so the worker can retry."""
        pdf = minimal_pdf_with_text("Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 20)
        monkeypatch.setattr(
            "services.audits.text_extraction.download_pdf",
            lambda *_a, **_kw: pdf,
        )

        def broken_store(*_a, **_kw):
            raise StorageWriteError("tigris down")

        monkeypatch.setattr("services.audits.text_extraction.store_audit_text", broken_store)
        out = process_audit_report(audit_report_id=1, url="https://x/a.pdf")
        assert out.status == "failed"
        assert "store" in (out.error or "") and "tigris" in (out.error or "")

    def test_success_returns_all_metadata(self, monkeypatch):
        """Happy path — verify the outcome object carries every field the
        worker persists to the row."""
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
# Sanity — importable public error classes have the expected MRO.
# ---------------------------------------------------------------------------


def test_extraction_errors_share_base():
    from services.audits.text_extraction import TextExtractionError

    for cls in (PdfDownloadError, PdfTooLargeError, PdfParseError, StorageWriteError):
        assert issubclass(cls, TextExtractionError)


def test_extraction_outcome_defaults_are_none():
    """Constructing ``ExtractionOutcome(status=...)`` without other fields
    leaves them explicitly None so callers can tell apart "unset" from "0"."""
    oc = ExtractionOutcome(status="failed", error="x")
    assert oc.storage_key is None
    assert oc.text_size_bytes is None
    assert oc.text_sha256 is None


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
    """Minimal stand-in for the streamed ``requests.Response`` shape that
    ``_fetch_html_page`` consumes."""

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
    def test_normal_page_parses(self, monkeypatch):
        resp = _FakeResp(chunks=[b"<html>hello world</html>"])
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: resp)

        out = _fetch_html_page("https://example.com/report")
        assert out == "<html>hello world</html>"

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

    def test_unsafe_error_does_not_leak_into_return(self, monkeypatch):
        """``UnsafeUrlError`` carries the refused URL/reason; the function must
        swallow it to None and never surface it to the caller (witness
        discipline — the stored/returned output leaks nothing about the probe)."""
        from utils.egress import UnsafeUrlError

        def refuse(*_a, **_kw):
            raise UnsafeUrlError("http://internal.secret/ resolves to 10.0.0.5")

        monkeypatch.setattr("utils.egress.safe_get", refuse)

        assert _fetch_html_page("http://internal.secret/") is None

    def test_binary_content_type_rejected(self, monkeypatch):
        """Content-type binary rejection is preserved: a PDF response is
        skipped (None) and the body is never streamed."""
        resp = _FakeResp(content_type="application/pdf", chunks=[b"%PDF-1.7 ..."])
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: resp)

        out = _fetch_html_page("https://example.com/report")
        assert out is None
        assert resp.closed is True

    def test_non_200_returns_none(self, monkeypatch):
        resp = _FakeResp(status_code=404)
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: resp)

        assert _fetch_html_page("https://example.com/missing") is None

    def test_download_cap_still_truncates(self, monkeypatch):
        """The size cap is preserved: a body far larger than the cap stops at
        ``_MAX_DOWNLOAD_BYTES`` rather than being read whole."""
        oversized = [b"a" * 64_000 for _ in range(100)]  # 6.4 MB offered
        resp = _FakeResp(chunks=oversized)
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: resp)

        out = _fetch_html_page("https://example.com/huge")
        assert out is not None
        # Reads whole chunks until downloaded >= cap, then stops: exactly the
        # first ceil(cap / chunk) chunks, nowhere near the 6.4 MB offered.
        assert len(out) == _MAX_DOWNLOAD_BYTES
        assert len(out) < sum(len(c) for c in oversized)

    def test_request_exception_returns_none(self, monkeypatch):
        import requests

        def boom(*_a, **_kw):
            raise requests.RequestException("connection reset")

        monkeypatch.setattr("utils.egress.safe_get", boom)

        assert _fetch_html_page("https://example.com/report") is None
