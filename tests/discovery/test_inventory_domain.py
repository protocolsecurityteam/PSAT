from __future__ import annotations

import time
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
import requests

from services.clients.tavily import TavilyError
from services.discovery.inventory_domain import (
    RateLimiter,
    _collect_in_domain_pages,
    _dedupe_results_by_url,
    _discover_contract_inventory_pages,
    _domain_candidates_from_results,
    _extract_addresses,
    _fetch_page,
    _get_domain,
    _infer_chain,
    _is_explorer_domain,
    _is_unresolved_safe_link,
    _link_addresses,
    _llm_select_domain,
    _llm_select_pages,
    _maybe_domain,
    _resolve_chain,
    _tavily_search,
)


class TestRateLimiter:
    def test_back_to_back_calls_enforce_interval(self):
        rl = RateLimiter(20.0)  # 50ms interval
        rl.wait()
        start = time.monotonic()
        rl.wait()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.04  # allow small timing slack


class TestGetDomain:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            pytest.param("https://example.com/path", "example.com", id="simple_url"),
            pytest.param("https://www.example.com", "example.com", id="strips_www"),
            pytest.param("https://docs.example.com", "docs.example.com", id="preserves_subdomain"),
            pytest.param("https://Example.COM/Page", "example.com", id="lowercases"),
            pytest.param("", "", id="invalid_url_returns_empty"),
            pytest.param("https://example.com:8080/path", "example.com", id="host_without_port"),
            pytest.param("https://example.com@other.com/path", "other.com", id="host_without_userinfo"),
        ],
    )
    def test_get_domain(self, url, expected):
        assert _get_domain(url) == expected

    def test_valueerror_returns_empty(self, monkeypatch):
        from urllib import parse as _urlparse_mod

        _ = _urlparse_mod.urlparse  # keep reference before patching

        def bad_urlparse(url, *a, **kw):
            raise ValueError("bad url")

        monkeypatch.setattr("services.discovery.inventory_domain.urlparse", bad_urlparse)
        assert _get_domain("anything") == ""


class TestExtractAddresses:
    @pytest.mark.parametrize(
        ("values", "expected_count"),
        [
            pytest.param((f"contract at 0x{'ab' * 20}",), 1, id="single_value"),
            pytest.param((f"a=0x{'aa' * 20}", f"b=0x{'bb' * 20}"), 2, id="multiple_values"),
            pytest.param(("",), 0, id="empty_string"),
            pytest.param(("", None), 0, id="none_values_skipped"),
            pytest.param((f"0x{'cc' * 20} and 0x{'cc' * 20}",), 1, id="deduplication"),
        ],
    )
    def test_extract(self, values, expected_count):
        assert len(_extract_addresses(*cast(Any, values))) == expected_count


class TestInferChain:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Deployed on Arbitrum network", "arbitrum"),
            ("Optimism chain", "optimism"),
            ("Optimistic rollup", "optimism"),
            ("Polygon deployment", "polygon"),
            ("MATIC network", "polygon"),
            ("Base chain", "base"),
            ("Ethereum mainnet", "ethereum"),
            ("Mainnet contracts", "ethereum"),
        ],
    )
    def test_text_fallback(self, text, expected):
        # One case per literal in the keyword ladder.
        assert _infer_chain("https://example.com", text) == expected

    def test_optimistic_etherscan_url_resolves_to_optimism(self):
        # etherscan.io must not suffix-shadow its own subdomain entry.
        assert _infer_chain("https://optimistic.etherscan.io/address/0x1234", "") == "optimism"

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://app.safe.global/home?safe=eth:0x" + "ab" * 20, "ethereum"),
            ("https://app.safe.global/transactions/history?safe=arb1%3A0x" + "ab" * 20, "arbitrum"),
            ("https://gnosis-safe.io/app/oeth:0x" + "ab" * 20 + "/balances", "optimism"),
            ("https://app.safe.global/home?safe=nochain:0x" + "ab" * 20, "unknown"),
            ("https://app.safe.global/welcome", "unknown"),
        ],
    )
    def test_safe_link_chain_comes_from_its_prefix(self, url, expected):
        assert _infer_chain(url, "") == expected
        assert _is_explorer_domain(_get_domain(url))

    def test_percent_encoded_safe_link_resolves(self):
        url = "https://app.safe.global/home?safe=base%3A0x" + "AB" * 20
        assert _link_addresses(url) == {"0x" + "ab" * 20}
        assert _infer_chain(url, "") == "base"

    def test_unknown_prefix_is_unresolved_not_absent(self):
        assert _is_unresolved_safe_link("https://app.safe.global/home?safe=gno:0x" + "ab" * 20)
        assert not _is_unresolved_safe_link("https://app.safe.global/home?safe=eth:0x" + "ab" * 20)
        assert not _is_unresolved_safe_link("https://app.safe.global/welcome")
        assert _link_addresses("https://app.safe.global/welcome") == set()


class TestResolveChain:
    @pytest.mark.parametrize(
        ("inferred", "requested", "expected"),
        [
            pytest.param("ethereum", None, ("ethereum", False), id="no_requested_returns_inferred"),
            pytest.param("arbitrum", "", ("arbitrum", False), id="empty_requested_returns_inferred"),
            pytest.param("ethereum", "ethereum", ("ethereum", False), id="matching_inferred_and_requested"),
            pytest.param("unknown", "polygon", ("polygon", True), id="inferred_unknown_with_requested"),
            pytest.param("arbitrum", "ethereum", (None, False), id="conflicting_chains_returns_none"),
        ],
    )
    def test_resolve_chain(self, inferred, requested, expected):
        assert _resolve_chain(inferred, requested) == expected


class TestMaybeDomain:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            pytest.param("uniswap.org", "uniswap.org", id="valid_domain"),
            pytest.param("https://uniswap.org", "uniswap.org", id="strips_protocol"),
            pytest.param("http://uniswap.org/path", "uniswap.org", id="strips_http"),
            pytest.param("www.uniswap.org", "uniswap.org", id="strips_www"),
            pytest.param("Uniswap.ORG", "uniswap.org", id="lowercases"),
            pytest.param("  uniswap.org  ", "uniswap.org", id="strips_whitespace"),
            pytest.param("etherscan.io", None, id="rejects_explorer"),
            pytest.param("not a domain", None, id="rejects_space_in_value"),
            pytest.param("localhost", None, id="rejects_single_label"),
            pytest.param("-invalid.com", None, id="rejects_invalid_domain_chars"),
        ],
    )
    def test_maybe_domain(self, value, expected):
        assert _maybe_domain(value) == expected


class TestFetchPage:
    # ``_fetch_page`` goes through ``utils.egress.safe_get``.
    @pytest.mark.parametrize(
        ("stub", "expected"),
        [
            pytest.param(
                MagicMock(return_value=MagicMock(status_code=200, text="<html>hello</html>")),
                "<html>hello</html>",
                id="success",
            ),
            pytest.param(MagicMock(return_value=MagicMock(status_code=404)), None, id="non_200_returns_none"),
            pytest.param(
                MagicMock(side_effect=requests.RequestException("network error")), None, id="exception_returns_none"
            ),
        ],
    )
    def test_fetch_outcome(self, monkeypatch, stub, expected):
        monkeypatch.setattr("utils.egress.safe_get", stub)

        assert _fetch_page("https://example.com") == expected

    def test_debug_logging_on_success(self, monkeypatch, capsys):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "content"
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: mock_resp)

        _fetch_page("https://example.com", debug=True)
        captured = capsys.readouterr()
        assert "Fetched" in captured.err

    def test_debug_logging_on_failure(self, monkeypatch, capsys):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: mock_resp)

        _fetch_page("https://example.com", debug=True)
        captured = capsys.readouterr()
        assert "HTTP 500" in captured.err


class TestTavilySearch:
    def test_budget_exhausted_returns_empty(self):
        queries_used = [5]
        errors: list[dict] = []
        results = _tavily_search("query", 5, queries_used, 5, errors)

        assert results == []
        assert queries_used[0] == 5  # not incremented

    @pytest.mark.parametrize(
        "exc",
        [
            pytest.param(TavilyError({"error": "rate limit"}), id="tavily_error"),
            pytest.param(requests.RequestException("network error"), id="request_exception"),
        ],
    )
    def test_error_appended(self, monkeypatch, exc):
        monkeypatch.setattr("services.discovery.inventory_domain.tavily.search", MagicMock(side_effect=exc))
        monkeypatch.setattr(
            "services.discovery.inventory_domain.tavily.error_from_exception",
            lambda exc: {"error": str(exc)},
        )

        queries_used = [0]
        errors: list[dict] = []
        results = _tavily_search("query", 5, queries_used, 10, errors)

        assert results == []
        assert len(errors) == 1
        assert queries_used[0] == 1


class TestLlmSelectDomain:
    @pytest.mark.parametrize(
        ("results", "chat"),
        [
            pytest.param([], MagicMock(return_value="1"), id="empty_results"),
            pytest.param(
                [{"url": "https://etherscan.io/address/0x123", "title": "Etherscan"}],
                MagicMock(return_value="1"),
                id="all_explorer_results",
            ),
            pytest.param(
                [{"url": "https://coingecko.com/en/coins/test", "title": "CoinGecko"}],
                MagicMock(return_value="1"),
                id="all_low_trust",
            ),
            pytest.param(
                [{"url": "https://example.com", "title": "Example"}],
                MagicMock(side_effect=RuntimeError("LLM unavailable")),
                id="llm_exception",
            ),
            pytest.param(
                [{"url": "https://example.com", "title": "Example"}],
                MagicMock(return_value="I don't know"),
                id="unparseable_llm_response",
            ),
        ],
    )
    def test_returns_none(self, monkeypatch, results, chat):
        monkeypatch.setattr("services.discovery.inventory_domain.llm.chat", chat)

        domain, extras = _llm_select_domain(results, "TestCo")
        assert domain is None
        assert extras == []

    @pytest.mark.parametrize(
        ("results", "reply", "expected_domain", "expected_extras"),
        [
            pytest.param(
                [
                    {"url": "https://docs.uniswap.org/contracts", "title": "Uniswap Docs"},
                    {"url": "https://docs.uniswap.org/guides", "title": "Guides"},
                ],
                "1",
                "docs.uniswap.org",
                [],
                id="single_domain",
            ),
            # Candidates sort by frequency, ties in insertion order:
            # [docs.uniswap.org (2), uniswap.org, gitbook.uniswap.org]; "1, 3" -> indices 0 and 2.
            pytest.param(
                [
                    {"url": "https://uniswap.org/blog", "title": "Uniswap"},
                    {"url": "https://docs.uniswap.org/contracts", "title": "Docs"},
                    {"url": "https://docs.uniswap.org/guides", "title": "More Docs"},
                    {"url": "https://gitbook.uniswap.org/deploy", "title": "Gitbook"},
                ],
                "1, 3",
                "docs.uniswap.org",
                ["gitbook.uniswap.org"],
                id="multiple_domains",
            ),
            pytest.param(
                [
                    {"url": "https://a.example.com/p1", "title": "A1"},
                    {"url": "https://a.example.com/p2", "title": "A2"},
                    {"url": "https://b.example.com/p1", "title": "B1"},
                ],
                "1, 1, 2",
                "a.example.com",
                ["b.example.com"],
                id="multiple_domains_deduplication",
            ),
            pytest.param(
                [
                    {"url": "", "title": "Empty URL"},
                    {"url": "https://example.com/page", "title": "Good"},
                ],
                "1",
                "example.com",
                [],
                id="no_url_in_result_skipped",
            ),
        ],
    )
    def test_selects_domains(self, monkeypatch, results, reply, expected_domain, expected_extras):
        monkeypatch.setattr("services.discovery.inventory_domain.llm.chat", lambda *a, **kw: reply)

        domain, extras = _llm_select_domain(results, "Uniswap")
        assert domain == expected_domain
        assert extras == expected_extras


class TestDomainCandidatesFromResults:
    def test_filters_explorers_and_low_trust(self):
        results = [
            {"url": "https://etherscan.io/address/0x123", "title": "Explorer"},
            {"url": "https://coingecko.com/coins/test", "title": "CoinGecko"},
            {"url": "https://uniswap.org/contracts", "title": "Uniswap"},
        ]
        candidates = _domain_candidates_from_results(results)
        assert "uniswap.org" in candidates
        assert "etherscan.io" not in candidates
        assert "coingecko.com" not in candidates


class TestCollectInDomainPages:
    @pytest.mark.parametrize(
        ("results", "domain"),
        [
            pytest.param(
                [
                    {"url": "https://a.com/page", "title": "A", "content": "x"},
                    {"url": "https://a.com/page", "title": "A2", "content": "y"},
                ],
                "a.com",
                id="deduplicates_urls",
            ),
            pytest.param(
                [{"url": "https://sub.example.com/page", "title": "Sub", "content": "c"}],
                "example.com",
                id="subdomain_match",
            ),
        ],
    )
    def test_collects_exactly_one_page(self, results, domain):
        assert len(_collect_in_domain_pages(results, domain)) == 1


class TestLlmSelectPages:
    def test_empty_page_info_returns_empty(self):
        result = _llm_select_pages([], "TestCo", "example.com", "{page_list}", ["example.com"])
        assert result == []

    def test_llm_exception_returns_empty(self, monkeypatch):
        pages = [{"url": "https://example.com/page", "title": "T", "snippet": "s"}]

        def raise_error(*a, **kw):
            raise RuntimeError("LLM down")

        monkeypatch.setattr("services.discovery.inventory_domain.llm.chat", raise_error)
        result = _llm_select_pages(pages, "TestCo", "example.com", "{page_list}", ["example.com"])
        assert result == []

    @pytest.mark.parametrize(
        "reply",
        [
            pytest.param("https://example.com/a\nhttps://example.com/a", id="deduplicates_urls_in_response"),
            pytest.param("https://example.com/a.", id="strips_trailing_punctuation"),
        ],
    )
    def test_cleans_response_urls(self, monkeypatch, reply):
        pages = [{"url": "https://example.com/a", "title": "A", "snippet": "s"}]
        monkeypatch.setattr("services.discovery.inventory_domain.llm.chat", lambda *a, **kw: reply)
        result = _llm_select_pages(pages, "TestCo", "example.com", "{page_list}", ["example.com"])
        assert result == ["https://example.com/a"]


class TestDedupeResultsByUrl:
    @pytest.mark.parametrize(
        ("results", "expected"),
        [
            pytest.param(
                [{"url": "https://a.com/1", "content": "short"}, {"url": "https://a.com/2", "content": "another"}],
                [("https://a.com/1", "short"), ("https://a.com/2", "another")],
                id="no_duplicates",
            ),
            pytest.param(
                [
                    {"url": "https://a.com/page", "content": "short", "title": "T1"},
                    {"url": "https://a.com/page", "content": "this is a much longer content string", "title": "T2"},
                ],
                [("https://a.com/page", "this is a much longer content string")],
                id="duplicate_keeps_richer_content",
            ),
            pytest.param(
                [
                    {"url": "https://a.com/page", "content": "this is the longer original content"},
                    {"url": "https://a.com/page", "content": "short"},
                ],
                [("https://a.com/page", "this is the longer original content")],
                id="duplicate_shorter_content_keeps_original",
            ),
            pytest.param(
                [{"url": "", "content": "no url"}, {"url": "https://a.com/page", "content": "valid"}],
                [("https://a.com/page", "valid")],
                id="empty_url_skipped",
            ),
        ],
    )
    def test_dedupe(self, results, expected):
        deduped = _dedupe_results_by_url(results)
        assert [(r["url"], r["content"]) for r in deduped] == expected

    def test_merged_result_preserves_extra_fields(self):
        results = [
            {"url": "https://a.com/page", "content": "short", "score": 0.5},
            {"url": "https://a.com/page", "content": "longer content here", "score": 0.9},
        ]
        deduped = _dedupe_results_by_url(results)
        assert len(deduped) == 1
        assert deduped[0]["score"] == 0.9


class TestDiscoverContractInventoryPages:
    def test_with_broad_and_site_results(self, monkeypatch):
        site_results = [
            {"url": "https://docs.example.com/contracts", "title": "Contracts", "content": "addresses"},
        ]
        broad_results = [
            {"url": "https://docs.example.com/overview", "title": "Overview", "content": "intro"},
            {"url": "https://other.com/page", "title": "Other", "content": "x"},
        ]
        monkeypatch.setattr(
            "services.discovery.inventory_domain._tavily_search",
            lambda *a, **kw: site_results,
        )
        monkeypatch.setattr(
            "services.discovery.inventory_domain._llm_select_pages",
            lambda *a, **kw: ["https://docs.example.com/contracts"],
        )

        combined, recommended = _discover_contract_inventory_pages(
            domain="docs.example.com",
            company="TestCo",
            broad_results=broad_results,
            queries_used=[0],
            max_queries=5,
            errors=[],
        )
        assert len(combined) > 0
        assert "https://docs.example.com/contracts" in recommended

    def test_combined_results_but_no_in_domain_pages(self, monkeypatch):
        site_results = [
            {"url": "https://other.com/page", "title": "Other", "content": "off-domain"},
        ]
        monkeypatch.setattr(
            "services.discovery.inventory_domain._tavily_search",
            lambda *a, **kw: site_results,
        )

        combined, recommended = _discover_contract_inventory_pages(
            domain="example.com",
            company="TestCo",
            broad_results=[],
            queries_used=[0],
            max_queries=5,
            errors=[],
        )
        assert len(combined) > 0
        assert recommended == []


class TestExtractInventoryEntriesFromPagesParallel:
    def test_fetches_all_urls_and_preserves_order(self, monkeypatch):
        from services.discovery import inventory_extract

        urls = [f"https://example.com/page{i}" for i in range(6)]
        fetched: list[str] = []

        def fake_fetch(url, debug=False):
            fetched.append(url)
            return f"<html>{url}</html>"

        seen_text_order: list[str] = []

        def fake_extract(url, page_text, requested_chain, debug=False):
            seen_text_order.append(url)
            return [{"address": f"0x{abs(hash(url)) & 0xFFFFFFFF:040x}", "url": url}]

        monkeypatch.setattr(inventory_extract, "_fetch_page", fake_fetch)
        monkeypatch.setattr(inventory_extract, "extract_inventory_entries_from_page_text", fake_extract)

        out = inventory_extract.extract_inventory_entries_from_pages(urls, requested_chain=None)

        assert sorted(fetched) == sorted(urls)
        assert seen_text_order == urls
        assert [entry["url"] for entry in out] == urls

    def test_skips_failed_fetches_without_aborting(self, monkeypatch):
        from services.discovery import inventory_extract

        urls = ["https://good.example.com", "https://bad.example.com", "https://also-good.example.com"]

        def fake_fetch(url, debug=False):
            if "bad" in url:
                raise RuntimeError("connection reset")
            return f"<html>{url}</html>"

        monkeypatch.setattr(inventory_extract, "_fetch_page", fake_fetch)
        monkeypatch.setattr(
            inventory_extract,
            "extract_inventory_entries_from_page_text",
            lambda url, page_text, requested_chain, debug=False: [{"url": url}],
        )

        out = inventory_extract.extract_inventory_entries_from_pages(urls, requested_chain=None)

        assert [e["url"] for e in out] == ["https://good.example.com", "https://also-good.example.com"]
