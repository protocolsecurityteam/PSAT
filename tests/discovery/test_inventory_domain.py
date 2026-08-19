"""Unit tests for services.discovery.inventory_domain.

Covers regex constants, RateLimiter, pure utility helpers, and mocked
external-service functions (Tavily search, LLM domain/page selection).
"""

from __future__ import annotations

import time
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from services.discovery.inventory_domain import (
    ADDRESS_RE,
    CHAIN_IDS,
    DOMAIN_RE,
    URL_RE,
    RateLimiter,
    _collect_in_domain_pages,
    _debug_log,
    _dedupe_results_by_url,
    _discover_contract_inventory_pages,
    _domain_candidates_from_results,
    _domain_matches,
    _extract_addresses,
    _fetch_page,
    _get_domain,
    _infer_chain,
    _is_allowed_domain,
    _is_explorer_domain,
    _is_low_trust_domain,
    _llm_select_domain,
    _llm_select_pages,
    _maybe_domain,
    _resolve_chain,
    _tavily_search,
)

# ---------------------------------------------------------------------------
# Regex constants
# ---------------------------------------------------------------------------


class TestAddressRE:
    def test_matches_mixed_case(self):
        assert ADDRESS_RE.search("0xAaBbCcDdEeFf0011223344556677889900112233") is not None

    def test_no_match_too_short(self):
        assert ADDRESS_RE.search("0x" + "a" * 39) is None

    def test_no_match_too_long_boundary(self):
        # 41 hex chars — the regex should only grab 40, but the \b boundary
        # means it still finds the first 40 if followed by a non-word char.
        # With 41 hex chars the last char is still word, so it shouldn't match.
        result = ADDRESS_RE.search("0x" + "a" * 41)
        # The 41-char string has no word boundary after 40, so full match fails
        assert result is None

    def test_no_match_without_0x(self):
        assert ADDRESS_RE.search("a" * 40) is None


class TestURLRE:
    def test_stops_at_angle_bracket(self):
        match = URL_RE.search('<a href="https://example.com/page">')
        assert match is not None
        # Should stop before the closing quote or angle bracket
        assert ">" not in match.group()


class TestDomainRE:
    def test_subdomain(self):
        assert DOMAIN_RE.match("docs.example.com") is not None

    def test_hyphenated(self):
        assert DOMAIN_RE.match("my-app.example.com") is not None


# ---------------------------------------------------------------------------
# Constants sanity checks
# ---------------------------------------------------------------------------


class TestConstants:
    def test_chain_ids_ethereum_is_1(self):
        # Cross-module agreement: the ``utils.chains`` registry and inventory's
        # ``CHAIN_IDS`` must resolve the same id, which chain_resolver.py feeds to
        # Etherscan v2 as the ``chainid`` query param.
        assert CHAIN_IDS["ethereum"] == 1


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_back_to_back_calls_enforce_interval(self):
        rl = RateLimiter(20.0)  # 50ms interval
        rl.wait()
        start = time.monotonic()
        rl.wait()
        elapsed = time.monotonic() - start
        # Second call should wait roughly 50ms
        assert elapsed >= 0.04  # allow small timing slack

    def test_no_wait_if_enough_time_passed(self):
        rl = RateLimiter(100.0)  # 10ms interval
        rl.wait()
        time.sleep(0.02)  # sleep longer than the interval
        start = time.monotonic()
        rl.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 0.02  # should not need to wait


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


class TestDebugLog:
    def test_enabled_prints_to_stderr(self, capsys):
        _debug_log(True, "hello debug")
        captured = capsys.readouterr()
        assert "hello debug" in captured.err
        assert "[debug]" in captured.err

    def test_disabled_prints_nothing(self, capsys):
        _debug_log(False, "should not appear")
        captured = capsys.readouterr()
        assert captured.err == ""


class TestGetDomain:
    def test_simple_url(self):
        assert _get_domain("https://example.com/path") == "example.com"

    def test_strips_www(self):
        assert _get_domain("https://www.example.com") == "example.com"

    def test_preserves_subdomain(self):
        assert _get_domain("https://docs.example.com") == "docs.example.com"

    def test_lowercases(self):
        assert _get_domain("https://Example.COM/Page") == "example.com"

    def test_invalid_url_returns_empty(self):
        # urlparse is lenient, but completely broken strings may return empty netloc
        assert _get_domain("") == ""

    def test_port_included_in_netloc(self):
        result = _get_domain("https://example.com:8080/path")
        assert result == "example.com:8080"

    def test_valueerror_returns_empty(self, monkeypatch):
        """Trigger the defensive ValueError branch in _get_domain."""
        from urllib import parse as _urlparse_mod

        _ = _urlparse_mod.urlparse  # keep reference before patching

        def bad_urlparse(url, *a, **kw):
            raise ValueError("bad url")

        monkeypatch.setattr("services.discovery.inventory_domain.urlparse", bad_urlparse)
        assert _get_domain("anything") == ""


class TestDomainMatches:
    def test_subdomain_match(self):
        assert _domain_matches("docs.example.com", "example.com") is True

    def test_no_match_partial(self):
        # Suffix-confusion guard: `known in domain` would admit this.
        assert _domain_matches("notexample.com", "example.com") is False


class TestIsExplorerDomain:
    def test_blockscout_subdomain(self):
        assert _is_explorer_domain("eth.blockscout.com") is True

    def test_non_explorer(self):
        assert _is_explorer_domain("example.com") is False


class TestIsLowTrustDomain:
    def test_subdomain_of_low_trust(self):
        assert _is_low_trust_domain("www.reddit.com") is True

    def test_normal_domain(self):
        assert _is_low_trust_domain("uniswap.org") is False


class TestIsAllowedDomain:
    def test_not_in_list(self):
        assert _is_allowed_domain("other.com", ["example.com"]) is False

    def test_empty_list(self):
        # Fail-closed: an empty allowlist admits nothing.
        assert _is_allowed_domain("example.com", []) is False


class TestExtractAddresses:
    def test_single_value(self):
        addr = "0x" + "ab" * 20
        result = _extract_addresses(f"contract at {addr}")
        assert addr.lower().replace("0x", "", 1) in list(result)[0]

    def test_multiple_values(self):
        addr1 = "0x" + "aa" * 20
        addr2 = "0x" + "bb" * 20
        result = _extract_addresses(f"a={addr1}", f"b={addr2}")
        assert len(result) == 2

    def test_empty_string(self):
        assert _extract_addresses("") == set()

    def test_none_values_skipped(self):
        # Falsy values should be skipped
        assert _extract_addresses("", cast(Any, None)) == set()

    def test_deduplication(self):
        addr = "0x" + "cc" * 20
        result = _extract_addresses(f"{addr} and {addr}")
        assert len(result) == 1


class TestInferChain:
    def test_etherscan_url(self):
        assert _infer_chain("https://etherscan.io/address/0x1234", "") == "ethereum"

    def test_arbiscan_url(self):
        assert _infer_chain("https://arbiscan.io/address/0x1234", "") == "arbitrum"

    def test_polygonscan_url(self):
        assert _infer_chain("https://polygonscan.com/address/0x1234", "") == "polygon"

    def test_basescan_url(self):
        assert _infer_chain("https://basescan.org/address/0x1234", "") == "base"

    def test_blockscout_base(self):
        assert _infer_chain("https://base.blockscout.com/address/0x1234", "") == "base"

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
        # One case per distinct literal in _infer_chain's keyword ladder, including
        # the ``optimistic``/``matic`` alias arms.
        assert _infer_chain("https://example.com", text) == expected

    @pytest.mark.xfail(
        strict=True,
        reason="EXPLORER_CHAINS iteration order lets etherscan.io suffix-match "
        "optimistic.etherscan.io before its own entry is reached, so the URL "
        "resolves to ethereum. The map's optimism entry states the intent; this "
        "pin flips to a hard failure when the ordering is fixed.",
    )
    def test_optimistic_etherscan_url_resolves_to_optimism(self):
        assert _infer_chain("https://optimistic.etherscan.io/address/0x1234", "") == "optimism"

    def test_unknown_when_no_clues(self):
        assert _infer_chain("https://example.com", "some random text") == "unknown"

    def test_url_takes_priority_over_text(self):
        # URL says ethereum, text says arbitrum — URL should win
        assert _infer_chain("https://etherscan.io/address/0x1234", "arbitrum stuff") == "ethereum"


class TestResolveChain:
    def test_no_requested_returns_inferred(self):
        chain, forced = _resolve_chain("ethereum", None)
        assert chain == "ethereum"
        assert forced is False

    def test_empty_requested_returns_inferred(self):
        chain, forced = _resolve_chain("arbitrum", "")
        assert chain == "arbitrum"
        assert forced is False

    def test_matching_inferred_and_requested(self):
        chain, forced = _resolve_chain("ethereum", "ethereum")
        assert chain == "ethereum"
        assert forced is False

    def test_inferred_unknown_with_requested(self):
        chain, forced = _resolve_chain("unknown", "polygon")
        assert chain == "polygon"
        assert forced is True

    def test_conflicting_chains_returns_none(self):
        chain, forced = _resolve_chain("arbitrum", "ethereum")
        assert chain is None
        assert forced is False


# ---------------------------------------------------------------------------
# _maybe_domain
# ---------------------------------------------------------------------------


class TestMaybeDomain:
    def test_valid_domain(self):
        assert _maybe_domain("uniswap.org") == "uniswap.org"

    def test_strips_protocol(self):
        assert _maybe_domain("https://uniswap.org") == "uniswap.org"

    def test_strips_http(self):
        assert _maybe_domain("http://uniswap.org/path") == "uniswap.org"

    def test_strips_www(self):
        assert _maybe_domain("www.uniswap.org") == "uniswap.org"

    def test_lowercases(self):
        assert _maybe_domain("Uniswap.ORG") == "uniswap.org"

    def test_strips_whitespace(self):
        assert _maybe_domain("  uniswap.org  ") == "uniswap.org"

    def test_rejects_explorer(self):
        assert _maybe_domain("etherscan.io") is None

    def test_rejects_space_in_value(self):
        assert _maybe_domain("not a domain") is None

    def test_rejects_single_label(self):
        assert _maybe_domain("localhost") is None

    def test_rejects_invalid_domain_chars(self):
        assert _maybe_domain("-invalid.com") is None


# ---------------------------------------------------------------------------
# _fetch_page
# ---------------------------------------------------------------------------


class TestFetchPage:
    # ``_fetch_page`` fetches through the SSRF guard (``utils.egress.safe_get``),
    # so these stub that rather than the raw ``requests`` call.
    def test_success(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>hello</html>"
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: mock_resp)

        result = _fetch_page("https://example.com")
        assert result == "<html>hello</html>"

    def test_non_200_returns_none(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        monkeypatch.setattr("utils.egress.safe_get", lambda *a, **kw: mock_resp)

        assert _fetch_page("https://example.com") is None

    def test_exception_returns_none(self, monkeypatch):
        import requests

        def raise_exc(*a, **kw):
            raise requests.RequestException("network error")

        monkeypatch.setattr("utils.egress.safe_get", raise_exc)

        assert _fetch_page("https://example.com") is None

    def test_unsafe_url_returns_none(self, monkeypatch):
        from utils.egress import UnsafeUrlError

        def raise_unsafe(*a, **kw):
            raise UnsafeUrlError("non-public address")

        monkeypatch.setattr("utils.egress.safe_get", raise_unsafe)

        assert _fetch_page("http://169.254.169.254/") is None

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


# ---------------------------------------------------------------------------
# _tavily_search
# ---------------------------------------------------------------------------


class TestTavilySearch:
    def test_within_budget_calls_tavily(self, monkeypatch):
        fake_results = [{"url": "https://example.com", "title": "test"}]
        monkeypatch.setattr(
            "services.discovery.inventory_domain.tavily.search",
            lambda *a, **kw: fake_results,
        )

        queries_used = [0]
        errors: list[dict] = []
        results = _tavily_search("test query", 5, queries_used, 10, errors)

        assert results == fake_results
        assert queries_used[0] == 1
        assert errors == []

    def test_budget_exhausted_returns_empty(self):
        queries_used = [5]
        errors: list[dict] = []
        results = _tavily_search("query", 5, queries_used, 5, errors)

        assert results == []
        assert queries_used[0] == 5  # not incremented

    def test_tavily_error_appended(self, monkeypatch):
        from utils.tavily import TavilyError

        def raise_tavily(*a, **kw):
            raise TavilyError({"error": "rate limit"})

        monkeypatch.setattr("services.discovery.inventory_domain.tavily.search", raise_tavily)
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

    def test_request_exception_appended(self, monkeypatch):
        import requests

        def raise_req(*a, **kw):
            raise requests.RequestException("network error")

        monkeypatch.setattr("services.discovery.inventory_domain.tavily.search", raise_req)
        monkeypatch.setattr(
            "services.discovery.inventory_domain.tavily.error_from_exception",
            lambda exc: {"error": str(exc)},
        )

        queries_used = [0]
        errors: list[dict] = []
        results = _tavily_search("query", 5, queries_used, 10, errors)

        assert results == []
        assert len(errors) == 1

    def test_budget_counter_increments(self, monkeypatch):
        monkeypatch.setattr(
            "services.discovery.inventory_domain.tavily.search",
            lambda *a, **kw: [],
        )

        queries_used = [3]
        _tavily_search("q1", 5, queries_used, 10, [])
        assert queries_used[0] == 4
        _tavily_search("q2", 5, queries_used, 10, [])
        assert queries_used[0] == 5


# ---------------------------------------------------------------------------
# _llm_select_domain
# ---------------------------------------------------------------------------


class TestLlmSelectDomain:
    def test_empty_results_returns_none(self):
        domain, extras = _llm_select_domain([], "TestCo")
        assert domain is None
        assert extras == []

    def test_all_explorer_results_returns_none(self):
        results = [{"url": "https://etherscan.io/address/0x123", "title": "Etherscan"}]
        domain, extras = _llm_select_domain(results, "TestCo")
        assert domain is None
        assert extras == []

    def test_all_low_trust_returns_none(self):
        results = [{"url": "https://coingecko.com/en/coins/test", "title": "CoinGecko"}]
        domain, extras = _llm_select_domain(results, "TestCo")
        assert domain is None
        assert extras == []

    def test_single_domain_selected(self, monkeypatch):
        results = [
            {"url": "https://docs.uniswap.org/contracts", "title": "Uniswap Docs"},
            {"url": "https://docs.uniswap.org/guides", "title": "Guides"},
        ]
        # LLM returns "1" meaning the first (and only) domain
        monkeypatch.setattr(
            "services.discovery.inventory_domain.llm.chat",
            lambda *a, **kw: "1",
        )

        domain, extras = _llm_select_domain(results, "Uniswap")
        assert domain == "docs.uniswap.org"
        assert extras == []

    def test_multiple_domains_selected(self, monkeypatch):
        results = [
            {"url": "https://uniswap.org/blog", "title": "Uniswap"},
            {"url": "https://docs.uniswap.org/contracts", "title": "Docs"},
            {"url": "https://docs.uniswap.org/guides", "title": "More Docs"},
            {"url": "https://gitbook.uniswap.org/deploy", "title": "Gitbook"},
        ]
        # Sorted by frequency: docs.uniswap.org (2 pages), then uniswap.org (1),
        # then gitbook.uniswap.org (1). Ties preserve insertion order from dict keys.
        # So sorted order is: [docs.uniswap.org, uniswap.org, gitbook.uniswap.org]
        # LLM returns "1, 3" -> 1-indexed -> 0-based indices 0 and 2
        # Index 0 = docs.uniswap.org, index 2 = gitbook.uniswap.org
        monkeypatch.setattr(
            "services.discovery.inventory_domain.llm.chat",
            lambda *a, **kw: "1, 3",
        )

        domain, extras = _llm_select_domain(results, "Uniswap")
        assert domain == "docs.uniswap.org"
        assert len(extras) == 1
        assert extras[0] == "gitbook.uniswap.org"

    def test_multiple_domains_deduplication(self, monkeypatch):
        """LLM returning the same index twice should not produce duplicate extras."""
        results = [
            {"url": "https://a.example.com/p1", "title": "A1"},
            {"url": "https://a.example.com/p2", "title": "A2"},
            {"url": "https://b.example.com/p1", "title": "B1"},
        ]
        # "1, 1, 2" — index 0 twice, index 1 once
        monkeypatch.setattr(
            "services.discovery.inventory_domain.llm.chat",
            lambda *a, **kw: "1, 1, 2",
        )
        domain, extras = _llm_select_domain(results, "TestCo")
        assert domain == "a.example.com"
        assert extras == ["b.example.com"]

    def test_llm_exception_returns_none(self, monkeypatch):
        results = [{"url": "https://example.com", "title": "Example"}]

        def raise_error(*a, **kw):
            raise RuntimeError("LLM unavailable")

        monkeypatch.setattr("services.discovery.inventory_domain.llm.chat", raise_error)

        domain, extras = _llm_select_domain(results, "TestCo")
        assert domain is None
        assert extras == []

    def test_unparseable_llm_response(self, monkeypatch):
        results = [{"url": "https://example.com", "title": "Example"}]
        monkeypatch.setattr(
            "services.discovery.inventory_domain.llm.chat",
            lambda *a, **kw: "I don't know",
        )

        domain, extras = _llm_select_domain(results, "TestCo")
        assert domain is None
        assert extras == []

    def test_no_url_in_result_skipped(self, monkeypatch):
        results = [
            {"url": "", "title": "Empty URL"},
            {"url": "https://example.com/page", "title": "Good"},
        ]
        monkeypatch.setattr(
            "services.discovery.inventory_domain.llm.chat",
            lambda *a, **kw: "1",
        )
        domain, extras = _llm_select_domain(results, "TestCo")
        assert domain == "example.com"


# ---------------------------------------------------------------------------
# _domain_candidates_from_results
# ---------------------------------------------------------------------------


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

    def test_orders_by_frequency(self):
        results = [
            {"url": "https://docs.aave.com/p1", "title": "A"},
            {"url": "https://docs.aave.com/p2", "title": "B"},
            {"url": "https://aave.com/home", "title": "C"},
        ]
        candidates = _domain_candidates_from_results(results)
        assert candidates[0] == "docs.aave.com"

    def test_empty_results(self):
        assert _domain_candidates_from_results([]) == []

    def test_skips_empty_urls(self):
        results = [{"url": "", "title": "No URL"}, {"url": "  ", "title": "Blank"}]
        assert _domain_candidates_from_results(results) == []


# ---------------------------------------------------------------------------
# _collect_in_domain_pages
# ---------------------------------------------------------------------------


class TestCollectInDomainPages:
    def test_collects_matching_domain(self):
        results = [
            {"url": "https://docs.uniswap.org/contracts", "title": "Contracts", "content": "snippet"},
            {"url": "https://other.com/page", "title": "Other", "content": "x"},
        ]
        pages = _collect_in_domain_pages(results, "docs.uniswap.org")
        assert len(pages) == 1
        assert pages[0]["url"] == "https://docs.uniswap.org/contracts"

    def test_deduplicates_urls(self):
        results = [
            {"url": "https://a.com/page", "title": "A", "content": "x"},
            {"url": "https://a.com/page", "title": "A2", "content": "y"},
        ]
        pages = _collect_in_domain_pages(results, "a.com")
        assert len(pages) == 1

    def test_empty_results(self):
        assert _collect_in_domain_pages([], "example.com") == []

    def test_subdomain_match(self):
        results = [
            {"url": "https://sub.example.com/page", "title": "Sub", "content": "c"},
        ]
        pages = _collect_in_domain_pages(results, "example.com")
        assert len(pages) == 1


# ---------------------------------------------------------------------------
# _llm_select_pages
# ---------------------------------------------------------------------------


class TestLlmSelectPages:
    def test_empty_page_info_returns_empty(self):
        result = _llm_select_pages([], "TestCo", "example.com", "{page_list}", ["example.com"])
        assert result == []

    def test_returns_urls_from_llm_response(self, monkeypatch):
        pages = [
            {"url": "https://docs.example.com/contracts", "title": "Contracts", "snippet": "addresses here"},
            {"url": "https://docs.example.com/faq", "title": "FAQ", "snippet": "questions"},
        ]
        monkeypatch.setattr(
            "services.discovery.inventory_domain.llm.chat",
            lambda *a, **kw: "https://docs.example.com/contracts",
        )
        result = _llm_select_pages(
            pages,
            "TestCo",
            "docs.example.com",
            "Select pages for {company} on {domain}:\n{page_list}",
            ["docs.example.com", "example.com"],
        )
        assert "https://docs.example.com/contracts" in result

    def test_filters_out_non_allowed_domain(self, monkeypatch):
        pages = [{"url": "https://docs.example.com/page", "title": "T", "snippet": "s"}]
        monkeypatch.setattr(
            "services.discovery.inventory_domain.llm.chat",
            lambda *a, **kw: "https://docs.example.com/page\nhttps://evil.com/hack",
        )
        result = _llm_select_pages(
            pages,
            "TestCo",
            "example.com",
            "{page_list}",
            ["example.com"],
        )
        assert len(result) == 1
        assert "evil.com" not in result[0]

    def test_llm_exception_returns_empty(self, monkeypatch):
        pages = [{"url": "https://example.com/page", "title": "T", "snippet": "s"}]

        def raise_error(*a, **kw):
            raise RuntimeError("LLM down")

        monkeypatch.setattr("services.discovery.inventory_domain.llm.chat", raise_error)
        result = _llm_select_pages(pages, "TestCo", "example.com", "{page_list}", ["example.com"])
        assert result == []

    def test_deduplicates_urls_in_response(self, monkeypatch):
        pages = [{"url": "https://example.com/a", "title": "A", "snippet": "s"}]
        monkeypatch.setattr(
            "services.discovery.inventory_domain.llm.chat",
            lambda *a, **kw: "https://example.com/a\nhttps://example.com/a",
        )
        result = _llm_select_pages(pages, "TestCo", "example.com", "{page_list}", ["example.com"])
        assert len(result) == 1

    def test_strips_trailing_punctuation(self, monkeypatch):
        pages = [{"url": "https://example.com/a", "title": "A", "snippet": "s"}]
        monkeypatch.setattr(
            "services.discovery.inventory_domain.llm.chat",
            lambda *a, **kw: "https://example.com/a.",
        )
        result = _llm_select_pages(pages, "TestCo", "example.com", "{page_list}", ["example.com"])
        assert len(result) == 1
        assert result[0] == "https://example.com/a"


# ---------------------------------------------------------------------------
# _dedupe_results_by_url
# ---------------------------------------------------------------------------


class TestDedupeResultsByUrl:
    def test_no_duplicates(self):
        results = [
            {"url": "https://a.com/1", "content": "short"},
            {"url": "https://a.com/2", "content": "another"},
        ]
        deduped = _dedupe_results_by_url(results)
        assert len(deduped) == 2

    def test_duplicate_keeps_richer_content(self):
        results = [
            {"url": "https://a.com/page", "content": "short", "title": "T1"},
            {"url": "https://a.com/page", "content": "this is a much longer content string", "title": "T2"},
        ]
        deduped = _dedupe_results_by_url(results)
        assert len(deduped) == 1
        assert deduped[0]["content"] == "this is a much longer content string"

    def test_duplicate_shorter_content_keeps_original(self):
        results = [
            {"url": "https://a.com/page", "content": "this is the longer original content"},
            {"url": "https://a.com/page", "content": "short"},
        ]
        deduped = _dedupe_results_by_url(results)
        assert len(deduped) == 1
        assert deduped[0]["content"] == "this is the longer original content"

    def test_empty_url_skipped(self):
        results = [
            {"url": "", "content": "no url"},
            {"url": "https://a.com/page", "content": "valid"},
        ]
        deduped = _dedupe_results_by_url(results)
        assert len(deduped) == 1
        assert deduped[0]["url"] == "https://a.com/page"

    def test_empty_results(self):
        assert _dedupe_results_by_url([]) == []

    def test_merged_result_preserves_extra_fields(self):
        results = [
            {"url": "https://a.com/page", "content": "short", "score": 0.5},
            {"url": "https://a.com/page", "content": "longer content here", "score": 0.9},
        ]
        deduped = _dedupe_results_by_url(results)
        assert len(deduped) == 1
        assert deduped[0]["score"] == 0.9


# ---------------------------------------------------------------------------
# _discover_contract_inventory_pages (integration with mocks)
# ---------------------------------------------------------------------------


class TestDiscoverContractInventoryPages:
    def test_no_results_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            "services.discovery.inventory_domain._tavily_search",
            lambda *a, **kw: [],
        )
        combined, recommended = _discover_contract_inventory_pages(
            domain="example.com",
            company="TestCo",
            broad_results=[],
            queries_used=[0],
            max_queries=5,
            errors=[],
        )
        assert combined == []
        assert recommended == []

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

    def test_extra_domains_are_searched(self, monkeypatch):
        search_queries = []

        def track_search(query, *a, **kw):
            search_queries.append(query)
            return []

        monkeypatch.setattr(
            "services.discovery.inventory_domain._tavily_search",
            track_search,
        )

        _discover_contract_inventory_pages(
            domain="example.com",
            company="TestCo",
            broad_results=[],
            queries_used=[0],
            max_queries=10,
            errors=[],
            extra_domains=["gitbook.example.com"],
        )
        # Should search both domains
        assert len(search_queries) == 2
        assert any("example.com" in q for q in search_queries)
        assert any("gitbook.example.com" in q for q in search_queries)

    def test_combined_results_but_no_in_domain_pages(self, monkeypatch):
        """When Tavily returns results but none match the target domain."""
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
        # combined should have results (off-domain ones), recommended should be empty
        assert len(combined) > 0
        assert recommended == []


# ---------------------------------------------------------------------------
# Step 4: extract_inventory_entries_from_pages parallel fetch
# ---------------------------------------------------------------------------


class TestExtractInventoryEntriesFromPagesParallel:
    """Page fetches run concurrently; entries are still emitted in URL input order."""

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
        # extract is called in input URL order even though fetches finished out of order.
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
