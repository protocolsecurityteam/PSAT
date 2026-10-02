from __future__ import annotations

import pytest

from services.discovery.audit_reports import merge_audit_reports
from services.discovery.audit_reports_llm import _parse_json_array, _parse_json_object


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


_ARRAY = [{"a": 1}]
_OBJECT = {"a": 1}


class TestJsonParsing:
    @pytest.mark.parametrize(
        "parse, text, expected",
        [
            pytest.param(_parse_json_array, '[{"a": 1}]', _ARRAY, id="array-clean"),
            pytest.param(_parse_json_array, '```json\n[{"a": 1}]\n```', _ARRAY, id="array-markdown-fences"),
            pytest.param(
                _parse_json_array, 'Here is the result: [{"a": 1}] Done.', _ARRAY, id="array-surrounding-text"
            ),
            pytest.param(_parse_json_array, "not json at all", None, id="array-garbage-returns-none"),
            pytest.param(_parse_json_array, "[]", [], id="array-empty"),
            pytest.param(_parse_json_object, '{"a": 1}', _OBJECT, id="object-clean"),
            pytest.param(_parse_json_object, '```json\n{"a": 1}\n```', _OBJECT, id="object-markdown-fences"),
            pytest.param(
                _parse_json_object, 'Here is the result: {"a": 1} Done.', _OBJECT, id="object-surrounding-text"
            ),
            pytest.param(_parse_json_object, "not json", None, id="object-garbage-returns-none"),
            pytest.param(_parse_json_object, "{}", {}, id="object-empty"),
        ],
    )
    def test_parse_json(self, parse, text, expected):
        assert parse(text) == expected


class TestMergeAuditReports:
    def test_append_only_keeps_prev_only_reports(self):
        prev = {"company": "Aave", "reports": [_report(url="https://a.com/old")]}
        new = {"company": "Aave", "reports": [_report(url="https://b.com/new")]}
        merged = merge_audit_reports(prev, new)
        urls = {r["url"] for r in merged["reports"]}
        assert urls == {"https://a.com/old", "https://b.com/new"}

    @pytest.mark.parametrize("prev_is_richer", [True, False], ids=["prev-richer-beats-new", "new-richer-beats-prev"])
    def test_richer_entry_wins_on_overlap(self, prev_is_richer):
        sparse = _report(url="https://a.com/report", pdf_url=None, date=None)
        rich = _report(
            url="https://a.com/report",
            pdf_url="https://a.com/report.pdf",
            date="2023-06-15",
        )
        prev, new = (rich, sparse) if prev_is_richer else (sparse, rich)
        merged = merge_audit_reports(
            {"company": "X", "reports": [prev]},
            {"company": "X", "reports": [new]},
        )
        assert len(merged["reports"]) == 1
        assert merged["reports"][0]["pdf_url"] == "https://a.com/report.pdf"
        assert merged["reports"][0]["date"] == "2023-06-15"

    def test_sorted_by_date_descending(self):
        old = _report(url="https://a.com/old", date="2022-01-01")
        new = _report(url="https://b.com/new", date="2024-06-01")
        merged = merge_audit_reports(
            {"company": "X", "reports": []},
            {"company": "X", "reports": [old, new]},
        )
        assert merged["reports"][0]["date"] == "2024-06-01"


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
            ("2025.10.20%20-%20WeETH%20withdrawal%20adapter.pdf", "2025-10-20"),
            ("2024-13-01.pdf", "2024"),
            ("Bundle_11.pdf", None),
            ("Cash Audit Report.pdf", None),
        ],
    )
    def test_date_extraction(self, filename, expected):
        from services.discovery.audit_reports import _extract_date_from_filename

        assert _extract_date_from_filename(filename) == expected

    def test_augment_only_fills_missing_llm_date(self):
        """The LLM owns auditor attribution; the filename only fills a missing date."""
        from services.discovery.audit_reports import _augment_filename_metadata

        meta = {"auditor": "Cantina", "date": "2024-01-01", "title": "X"}
        out = _augment_filename_metadata("2025.10.20-Halborn.pdf", meta)
        assert out["date"] == "2024-01-01"
        assert out["auditor"] == "Cantina"

        meta = {"auditor": "Halborn", "date": None, "title": "X"}
        out = _augment_filename_metadata("2025.10.20-Halborn.pdf", meta)
        assert out["date"] == "2025-10-20"
        assert out["auditor"] == "Halborn"

        meta = {"auditor": None, "date": None, "title": "X"}
        out = _augment_filename_metadata("2025.10.20-Halborn.pdf", meta)
        assert out["date"] == "2025-10-20"
        assert out.get("auditor") is None


# Blob URLs render the HTML code view; text extraction needs raw bytes with a text/* content-type.


class TestGithubBlobToRaw:
    @pytest.mark.parametrize(
        "src, expected",
        [
            pytest.param(
                "https://github.com/a/b/blob/main/foo.md",
                "https://raw.githubusercontent.com/a/b/main/foo.md",
                id="converts-blob-url-to-raw",
            ),
            pytest.param(
                "https://github.com/etherfi-protocol/smart-contracts/blob/master/audits/2023.12.20%20-%20Hats%20Finance.md",
                "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/master/audits/2023.12.20%20-%20Hats%20Finance.md",
                id="preserves-url-encoded-characters",
            ),
            pytest.param(
                "https://example.com/foo/bar.md", "https://example.com/foo/bar.md", id="non-github-passes-through"
            ),
            pytest.param(
                "https://raw.githubusercontent.com/a/b/main/foo.md",
                "https://raw.githubusercontent.com/a/b/main/foo.md",
                id="already-raw-passes-through",
            ),
            pytest.param(
                "https://github.com/a/b/tree/main/audits",
                "https://github.com/a/b/tree/main/audits",
                id="tree-url-passes-through",
            ),
        ],
    )
    def test_github_blob_to_raw(self, src, expected):
        from services.discovery.audit_reports import github_blob_to_raw

        assert github_blob_to_raw(src) == expected


class TestReportEntryNormalization:
    @pytest.mark.parametrize("builder", ["report_entry", "fallback_entry"])
    def test_builders_normalize_github_blob_pdf_urls(self, builder):
        from services.discovery.audit_reports import _build_fallback_entry, _build_report_entry

        blob = "https://github.com/a/b/blob/main/audits/report.pdf"
        if builder == "report_entry":
            out = _build_report_entry(
                {"auditor": "Foo", "title": "Report", "pdf_url": blob},
                source_url="https://docs.example.com/audits",
                confidence=0.9,
                now_iso="2026-01-01T00:00:00+00:00",
            )
        else:
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


class TestAutoHopPolicy:
    def test_should_auto_hop_includes_org_kind(self):
        from services.discovery.audit_reports import _should_auto_hop_org

        assert _should_auto_hop_org("https://github.com/morpho-org", "Morpho", set())
        assert not _should_auto_hop_org("https://github.com/morpho-org", "Morpho", {"morpho-org"})
        assert not _should_auto_hop_org("https://github.com/Certora", "Morpho", set())


class TestFilenameDedup:
    def test_collapses_same_filename_different_urls(self):
        from services.discovery.audit_reports import _collapse_by_filename

        reports = [
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
        foo = next(r for r in out if r["auditor"] == "Spearbit")
        assert "longer title" in foo["title"]

    def test_different_year_month_stays_separate(self):
        from services.discovery.audit_reports import _collapse_by_filename

        reports = [
            {"url": "x/audit.pdf", "pdf_url": "x/audit.pdf", "auditor": "Foo", "title": "A", "date": "2024-05-01"},
            {"url": "y/audit.pdf", "pdf_url": "y/audit.pdf", "auditor": "Foo", "title": "A", "date": "2024-11-01"},
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


# The cache keeps the GitHub rate limit out of the hot path.


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
        assert ar._resolve_branch_commit("owner", "repo", "main") == sha
        assert call_count["n"] == 1

    def test_eviction_bounds_at_max(self, monkeypatch):
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
