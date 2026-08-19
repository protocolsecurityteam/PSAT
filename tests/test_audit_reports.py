"""Pure-logic tests for the audit report discovery module.

The orchestrator — ``search_audit_reports`` and the LLM classify/extract
helpers — is exercised end-to-end in ``test_audit_discovery_integration.py``
against real HTTP fixtures via the ``responses`` library. That test is the
source of truth for the discovery pipeline's behaviour.

What lives here is everything that is *pure* (no HTTP, no LLM, no DB):
    - JSON parsing helpers tolerant of markdown fences / surrounding text
    - ``merge_audit_reports`` append-only dedup + richness selection
    - filename date-extraction regex
    - audit folder-name allowlist
    - single-org auto-hop policy check
    - cross-source filename dedup
    - provenance field plumbing
    - branch → commit SHA cache

Any test that would need mocks for Tavily / LLM / GitHub / Solodit belongs
in the integration test, not here.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery.audit_reports import merge_audit_reports
from services.discovery.audit_reports_llm import _parse_json_array, _parse_json_object

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _report(
    url: str = "https://example.com/audit",
    auditor: str = "OpenZeppelin",
    title: str = "Protocol Audit",
    date: str | None = "2023-06-15",
    pdf_url: str | None = None,
    confidence: float = 0.9,
) -> dict:
    return {
        "url": url,
        "pdf_url": pdf_url,
        "auditor": auditor,
        "title": title,
        "date": date,
        "source_url": url,
        "confidence": confidence,
        "discovered_at": "2026-01-01T00:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# JSON parsing helpers — LLM outputs arrive wrapped in prose + markdown fences
# ---------------------------------------------------------------------------


class TestJsonParsing:
    def test_parse_array_clean(self):
        assert _parse_json_array('[{"a": 1}]') == [{"a": 1}]

    def test_parse_array_with_markdown_fences(self):
        assert _parse_json_array('```json\n[{"a": 1}]\n```') == [{"a": 1}]

    def test_parse_array_with_surrounding_text(self):
        assert _parse_json_array('Here is the result: [{"a": 1}] Done.') == [{"a": 1}]

    def test_parse_array_garbage_returns_none(self):
        assert _parse_json_array("not json at all") is None

    def test_parse_array_empty(self):
        assert _parse_json_array("[]") == []

    def test_parse_object_clean(self):
        assert _parse_json_object('{"a": 1}') == {"a": 1}

    def test_parse_object_with_markdown_fences(self):
        assert _parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}

    def test_parse_object_with_surrounding_text(self):
        assert _parse_json_object('Here is the result: {"a": 1} Done.') == {"a": 1}

    def test_parse_object_garbage_returns_none(self):
        assert _parse_json_object("not json") is None

    def test_parse_object_empty(self):
        assert _parse_json_object("{}") == {}


# ---------------------------------------------------------------------------
# merge_audit_reports — append-only URL-keyed dedup, richness selection
# ---------------------------------------------------------------------------


class TestMergeAuditReports:
    def test_append_only_keeps_prev_only_reports(self):
        prev = {"company": "Aave", "reports": [_report(url="https://a.com/old")]}
        new = {"company": "Aave", "reports": [_report(url="https://b.com/new")]}
        merged = merge_audit_reports(prev, new)
        urls = {r["url"] for r in merged["reports"]}
        assert urls == {"https://a.com/old", "https://b.com/new"}

    def test_richer_entry_wins_on_overlap(self):
        sparse = _report(url="https://a.com/report", pdf_url=None, date=None)
        rich = _report(
            url="https://a.com/report",
            pdf_url="https://a.com/report.pdf",
            date="2023-06-15",
        )
        merged = merge_audit_reports(
            {"company": "X", "reports": [sparse]},
            {"company": "X", "reports": [rich]},
        )
        assert len(merged["reports"]) == 1
        assert merged["reports"][0]["pdf_url"] == "https://a.com/report.pdf"

    def test_prev_richer_beats_new(self):
        rich = _report(
            url="https://a.com/report",
            pdf_url="https://a.com/report.pdf",
            date="2023-01-01",
        )
        sparse = _report(url="https://a.com/report", pdf_url=None, date=None)
        merged = merge_audit_reports(
            {"company": "X", "reports": [rich]},
            {"company": "X", "reports": [sparse]},
        )
        assert merged["reports"][0]["pdf_url"] == "https://a.com/report.pdf"
        assert merged["reports"][0]["date"] == "2023-01-01"

    def test_empty_prev_returns_new(self):
        new = {"company": "X", "reports": [_report()]}
        merged = merge_audit_reports({"company": "X", "reports": []}, new)
        assert len(merged["reports"]) == 1

    def test_empty_new_keeps_prev(self):
        prev = {"company": "X", "reports": [_report()]}
        merged = merge_audit_reports(prev, {"company": "X", "reports": []})
        assert len(merged["reports"]) == 1

    def test_both_empty(self):
        merged = merge_audit_reports(
            {"company": "X", "reports": []},
            {"company": "X", "reports": []},
        )
        assert merged["reports"] == []

    def test_url_normalization_dedup(self):
        """Trailing slashes and case differences treated as the same URL."""
        r1 = _report(url="https://Example.com/Audit/")
        r2 = _report(url="https://example.com/Audit", title="Updated Title")
        merged = merge_audit_reports(
            {"company": "X", "reports": [r1]},
            {"company": "X", "reports": [r2]},
        )
        assert len(merged["reports"]) == 1

    def test_sorted_by_date_descending(self):
        old = _report(url="https://a.com/old", date="2022-01-01")
        new = _report(url="https://b.com/new", date="2024-06-01")
        merged = merge_audit_reports(
            {"company": "X", "reports": []},
            {"company": "X", "reports": [old, new]},
        )
        assert merged["reports"][0]["date"] == "2024-06-01"


# ---------------------------------------------------------------------------
# Filename date extraction — the regex path that augments LLM-null dates
# ---------------------------------------------------------------------------


class TestFilenameDateExtraction:
    @pytest.mark.parametrize(
        "filename, expected",
        [
            ("2024.06.25 - Halborn - EFIP.pdf", "2024-06-25"),
            ("2023-12-20 - Hats Finance.md", "2023-12-20"),
            ("2025_03_15_audit.pdf", "2025-03-15"),
            ("20241109-scroll-native-minting.md", "2024-11-09"),
            ("2024-06_audit.pdf", "2024-06"),
            ("Audit-2023.pdf", "2023"),
            # URL-encoded
            ("2025.10.20%20-%20WeETH%20withdrawal%20adapter.pdf", "2025-10-20"),
            # Invalid month → falls through to year-only
            ("2024-13-01.pdf", "2024"),
            # Random digits don't match (audit report ID-like)
            ("Bundle_11.pdf", None),
            ("Cash Audit Report.pdf", None),
        ],
    )
    def test_date_extraction(self, filename, expected):
        from services.discovery.audit_reports import _extract_date_from_filename

        assert _extract_date_from_filename(filename) == expected

    def test_augment_only_fills_missing_llm_date(self):
        """Filename augmenter never overwrites an LLM-supplied date, and
        never guesses an auditor — that's the LLM's job."""
        from services.discovery.audit_reports import _augment_filename_metadata

        meta = {"auditor": "Cantina", "date": "2024-01-01", "title": "X"}
        out = _augment_filename_metadata("2025.10.20-Halborn.pdf", meta)
        assert out["date"] == "2024-01-01"
        assert out["auditor"] == "Cantina"

        meta = {"auditor": "Halborn", "date": None, "title": "X"}
        out = _augment_filename_metadata("2025.10.20-Halborn.pdf", meta)
        assert out["date"] == "2025-10-20"
        assert out["auditor"] == "Halborn"

        # LLM auditor null + filename has obvious auditor → augmenter still
        # leaves auditor unset.
        meta = {"auditor": None, "date": None, "title": "X"}
        out = _augment_filename_metadata("2025.10.20-Halborn.pdf", meta)
        assert out["date"] == "2025-10-20"
        assert out.get("auditor") is None


# ---------------------------------------------------------------------------
# GitHub blob → raw URL normalization. Blob URLs render HTML (the code-view
# page); raw URLs serve the actual file bytes. The audit text-extraction
# worker needs raw URLs for markdown/text files so the response has a
# text/* content-type instead of text/html.
# ---------------------------------------------------------------------------


class TestGithubBlobToRaw:
    def test_converts_blob_url_to_raw(self):
        from services.discovery.audit_reports import github_blob_to_raw

        assert (
            github_blob_to_raw("https://github.com/a/b/blob/main/foo.md")
            == "https://raw.githubusercontent.com/a/b/main/foo.md"
        )

    def test_preserves_url_encoded_characters(self):
        """Audit filenames often contain spaces encoded as %20 — those must
        survive the conversion verbatim (don't double-encode, don't decode)."""
        from services.discovery.audit_reports import github_blob_to_raw

        src = (
            "https://github.com/etherfi-protocol/smart-contracts/blob/master/audits/2023.12.20%20-%20Hats%20Finance.md"
        )
        expected = "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/master/audits/2023.12.20%20-%20Hats%20Finance.md"
        assert github_blob_to_raw(src) == expected

    def test_non_github_url_passes_through(self):
        from services.discovery.audit_reports import github_blob_to_raw

        assert github_blob_to_raw("https://example.com/foo/bar.md") == "https://example.com/foo/bar.md"

    def test_already_raw_url_passes_through(self):
        """Idempotent — applying twice is a no-op."""
        from services.discovery.audit_reports import github_blob_to_raw

        raw = "https://raw.githubusercontent.com/a/b/main/foo.md"
        assert github_blob_to_raw(raw) == raw

    def test_github_tree_url_passes_through(self):
        """``/tree/`` URLs aren't file blobs — leave them alone."""
        from services.discovery.audit_reports import github_blob_to_raw

        tree = "https://github.com/a/b/tree/main/audits"
        assert github_blob_to_raw(tree) == tree


class TestReportEntryNormalization:
    def test_build_report_entry_normalizes_github_blob_pdf_urls(self):
        from services.discovery.audit_reports import _build_report_entry

        blob = "https://github.com/a/b/blob/main/audits/report.pdf"
        out = _build_report_entry(
            {
                "auditor": "Foo",
                "title": "Report",
                "pdf_url": blob,
            },
            source_url="https://docs.example.com/audits",
            confidence=0.9,
            now_iso="2026-01-01T00:00:00+00:00",
        )

        assert out["pdf_url"] == "https://raw.githubusercontent.com/a/b/main/audits/report.pdf"
        assert out["url"] == out["pdf_url"]

    def test_build_fallback_entry_normalizes_github_blob_pdf_urls(self):
        from services.discovery.audit_reports import _build_fallback_entry

        blob = "https://github.com/a/b/blob/main/audits/report.pdf"
        out = _build_fallback_entry(
            blob,
            {"auditor": "Foo", "title": "Report"},
            "Acme",
            [],
            confidence=0.9,
            now_iso="2026-01-01T00:00:00+00:00",
            pdf_url=blob,
        )

        assert out["pdf_url"] == "https://raw.githubusercontent.com/a/b/main/audits/report.pdf"
        assert out["url"] == out["pdf_url"]


# ---------------------------------------------------------------------------
# Auto-hop policy — pure predicate, no HTTP
# ---------------------------------------------------------------------------


class TestAutoHopPolicy:
    def test_should_auto_hop_includes_org_kind(self):
        from services.discovery.audit_reports import _should_auto_hop_org

        # Bare org URL whose owner matches company name → hop
        assert _should_auto_hop_org("https://github.com/morpho-org", "Morpho", set())
        # Same org already enumerated → don't re-hop
        assert not _should_auto_hop_org("https://github.com/morpho-org", "Morpho", {"morpho-org"})
        # Org name doesn't substring-match company → don't hop
        assert not _should_auto_hop_org("https://github.com/Certora", "Morpho", set())


# ---------------------------------------------------------------------------
# Cross-source filename dedup — the same PDF mirrored across hosts
# ---------------------------------------------------------------------------


class TestFilenameDedup:
    def test_collapses_same_filename_different_urls(self):
        from services.discovery.audit_reports import _collapse_by_filename

        reports = [
            # Same PDF mirrored on two hosts — should collapse
            {
                "url": "https://solodit.cyfrin.io/audit.pdf",
                "pdf_url": "https://s3/audit.pdf",
                "auditor": "Spearbit",
                "title": "Foo",
                "date": "2024-05-01",
            },
            {
                "url": "https://github.com/spearbit/portfolio/blob/main/audit.pdf",
                "pdf_url": "https://raw.github.com/spearbit/portfolio/main/audit.pdf",
                "auditor": "Spearbit",
                "title": "Foo Audit longer title",
                "date": "2024-05-01",
            },
            # Different filename — standalone
            {
                "url": "https://github.com/x/y/other.pdf",
                "pdf_url": "https://github.com/x/y/other.pdf",
                "auditor": "Halborn",
                "title": "Bar",
                "date": "2024-05-01",
            },
        ]
        out = _collapse_by_filename(reports)
        assert len(out) == 2
        # Richer entry (longer title) wins
        foo = next(r for r in out if r["auditor"] == "Spearbit")
        assert "longer title" in foo["title"]

    def test_different_year_month_stays_separate(self):
        """Same filename + different dates = different audits (retest)."""
        from services.discovery.audit_reports import _collapse_by_filename

        reports = [
            {"url": "x/audit.pdf", "pdf_url": "x/audit.pdf", "auditor": "Foo", "title": "A", "date": "2024-05-01"},
            {"url": "y/audit.pdf", "pdf_url": "y/audit.pdf", "auditor": "Foo", "title": "A", "date": "2024-11-01"},
        ]
        assert len(_collapse_by_filename(reports)) == 2

    def test_missing_filename_never_groups(self):
        """Opaque URLs (cantina.xyz/portfolio/<uuid>) shouldn't merge with
        other opaque URLs even if they look similar."""
        from services.discovery.audit_reports import _collapse_by_filename

        reports = [
            {
                "url": "https://cantina.xyz/portfolio/abcd",
                "pdf_url": None,
                "auditor": "Cantina",
                "title": "X",
                "date": "2024-05-01",
            },
            {
                "url": "https://cantina.xyz/portfolio/efgh",
                "pdf_url": None,
                "auditor": "Cantina",
                "title": "Y",
                "date": "2024-05-01",
            },
        ]
        assert len(_collapse_by_filename(reports)) == 2

    def test_prefers_pdf_url_over_no_pdf(self):
        from services.discovery.audit_reports import _collapse_by_filename

        reports = [
            {"url": "x/audit.pdf", "pdf_url": None, "auditor": "Foo", "title": "A", "date": "2024-05-01"},
            {"url": "y/audit.pdf", "pdf_url": "y/audit.pdf", "auditor": "Foo", "title": "A", "date": "2024-05-01"},
        ]
        out = _collapse_by_filename(reports)
        assert len(out) == 1
        assert out[0]["pdf_url"] is not None


# ---------------------------------------------------------------------------
# Provenance fields — GitHub-sourced audits carry commit/repo/path through
# ---------------------------------------------------------------------------


class TestProvenanceFields:
    def test_build_report_entry_passes_source_commit(self):
        from services.discovery.audit_reports import _build_report_entry

        sha = "a" * 40
        out = _build_report_entry(
            {
                "auditor": "Foo",
                "title": "T",
                "date": "2024-01-01",
                "pdf_url": "https://x.pdf",
                "source_commit": sha,
                "source_repo": "owner/repo",
                "source_path": "audits/X.pdf",
            },
            "https://src/",
            0.9,
            "2024-01-01T00:00:00Z",
        )
        assert out["source_commit"] == sha
        assert out["source_repo"] == "owner/repo"
        assert out["source_path"] == "audits/X.pdf"

    def test_build_report_entry_omits_provenance_when_missing(self):
        """Non-GitHub sources don't supply a commit SHA — entry stays clean."""
        from services.discovery.audit_reports import _build_report_entry

        out = _build_report_entry(
            {"auditor": "Foo", "title": "T", "date": "2024-01-01", "pdf_url": "https://x.pdf"},
            "https://src/",
            0.9,
            "2024-01-01T00:00:00Z",
        )
        assert "source_commit" not in out
        assert "source_repo" not in out
        assert "source_path" not in out


# ---------------------------------------------------------------------------
# Branch → commit SHA resolver cache — keeps GitHub rate limit out of the
# hot path when many URLs point at the same branch
# ---------------------------------------------------------------------------


class TestResolveBranchCommit:
    def test_resolves_and_caches(self, monkeypatch):
        from services.discovery import audit_reports as ar

        ar._BRANCH_SHA_CACHE.clear()

        call_count = {"n": 0}
        sha = "b" * 40

        def fake_get(url, **kwargs):
            call_count["n"] += 1

            class R:
                status_code = 200

                def json(self):
                    return {"ref": "refs/heads/main", "object": {"sha": sha}}

            return R()

        monkeypatch.setattr(ar._requests, "get", fake_get)

        assert ar._resolve_branch_commit("owner", "repo", "main") == sha
        assert call_count["n"] == 1
        # Second call: cache hit, no extra HTTP.
        assert ar._resolve_branch_commit("owner", "repo", "main") == sha
        assert call_count["n"] == 1

    def test_returns_none_on_404(self, monkeypatch):
        from services.discovery import audit_reports as ar

        ar._BRANCH_SHA_CACHE.clear()

        def fake_get(url, **kwargs):
            class R:
                status_code = 404

                def json(self):
                    return {"message": "Not Found"}

            return R()

        monkeypatch.setattr(ar._requests, "get", fake_get)
        assert ar._resolve_branch_commit("owner", "ghost-repo", "main") is None

    def test_does_not_cache_negative_result(self, monkeypatch):
        """A transient miss is not cached, so the next call re-probes."""
        from services.discovery.audit_reports import _github

        _github.clear_branch_sha_cache()
        sha = "c" * 40
        state = {"n": 0}

        def fake_get(url, **kwargs):
            state["n"] += 1

            class R:
                # First call 5xx (transient); retry succeeds.
                status_code = 500 if state["n"] == 1 else 200

                def json(self):
                    return {"object": {"sha": sha}}

            return R()

        monkeypatch.setattr(_github._requests, "get", fake_get)

        assert _github._resolve_branch_commit("owner", "repo", "main") is None
        assert ("owner", "repo", "main") not in _github._BRANCH_SHA_CACHE
        # Retry resolves and now caches.
        assert _github._resolve_branch_commit("owner", "repo", "main") == sha
        assert state["n"] == 2

    def test_expired_entry_reprobes(self, monkeypatch):
        """An entry older than the TTL is dropped and the HEAD re-fetched."""
        from services.discovery.audit_reports import _github

        _github.clear_branch_sha_cache()
        fresh = "d" * 40
        state = {"n": 0}

        def fake_get(url, **kwargs):
            state["n"] += 1

            class R:
                status_code = 200

                def json(self):
                    return {"object": {"sha": fresh}}

            return R()

        monkeypatch.setattr(_github._requests, "get", fake_get)

        key = ("owner", "repo", "main")
        stale_ts = time.monotonic() - _github._BRANCH_SHA_CACHE_TTL_S - 10
        _github._BRANCH_SHA_CACHE[key] = ("e" * 40, stale_ts)

        assert _github._resolve_branch_commit("owner", "repo", "main") == fresh
        assert state["n"] == 1
        assert _github._BRANCH_SHA_CACHE[key][0] == fresh

    def test_eviction_bounds_at_max(self, monkeypatch):
        """Distinct repos past the cap evict, keeping the cache size-bounded."""
        from services.discovery.audit_reports import _github

        _github.clear_branch_sha_cache()
        monkeypatch.setattr(_github, "_BRANCH_SHA_CACHE_MAX", 4)

        def fake_get(url, **kwargs):
            class R:
                status_code = 200

                def json(self):
                    return {"object": {"sha": "f" * 40}}

            return R()

        monkeypatch.setattr(_github._requests, "get", fake_get)

        for i in range(20):
            _github._resolve_branch_commit("owner", f"repo{i}", "main")
        assert len(_github._BRANCH_SHA_CACHE) <= _github._BRANCH_SHA_CACHE_MAX

    def test_clear_resets_pressure_state(self, monkeypatch):
        """clear_branch_sha_cache empties the dict and forgets pressure state."""
        from services.discovery.audit_reports import _github
        from utils import memory

        _github.clear_branch_sha_cache()
        monkeypatch.setattr(_github, "_BRANCH_SHA_CACHE_MAX", 4)

        def fake_get(url, **kwargs):
            class R:
                status_code = 200

                def json(self):
                    return {"object": {"sha": "a" * 40}}

            return R()

        monkeypatch.setattr(_github._requests, "get", fake_get)

        for i in range(8):
            _github._resolve_branch_commit("owner", f"repo{i}", "main")
        assert "branch_sha" in memory._CACHE_PRESSURE_STATE

        _github.clear_branch_sha_cache()
        assert _github._BRANCH_SHA_CACHE == {}
        assert "branch_sha" not in memory._CACHE_PRESSURE_STATE
