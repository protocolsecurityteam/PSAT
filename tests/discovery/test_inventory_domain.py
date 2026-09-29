"""Unit tests for services.discovery.inventory_domain.

Covers regex constants, RateLimiter, pure utility helpers, and mocked
external-service functions (Tavily search, LLM domain/page selection).
"""

from __future__ import annotations

import time
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
import requests

from services.clients.tavily import TavilyError
from services.discovery.inventory_domain import (
    ADDRESS_RE,
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
    @pytest.mark.parametrize(
        ("text", "matches"),
        [
            pytest.param("0xAaBbCcDdEeFf0011223344556677889900112233", True, id="mixed_case"),
            pytest.param("0x" + "a" * 39, False, id="too_short"),
            # 41 hex chars: no word boundary after 40, so the full match fails.
            pytest.param("0x" + "a" * 41, False, id="too_long_boundary"),
            pytest.param("a" * 40, False, id="without_0x"),
        ],
    )
    def test_search(self, text, matches):
        assert (ADDRESS_RE.search(text) is not None) is matches


class TestURLRE:
    def test_stops_at_angle_bracket(self):
        match = URL_RE.search('<a href="https://example.com/page">')
        assert match is not None
        # Should stop before the closing quote or angle bracket
        assert ">" not in match.group()


class TestDomainRE:
    @pytest.mark.parametrize("value", ["docs.example.com", "my-app.example.com"], ids=["subdomain", "hyphenated"])
    def test_matches(self, value):
        assert DOMAIN_RE.match(value) is not None


# ---------------------------------------------------------------------------
# Constants sanity checks
# ---------------------------------------------------------------------------


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


class TestGetDomain:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            pytest.param("https://example.com/path", "example.com", id="simple_url"),
            pytest.param("https://www.example.com", "example.com", id="strips_www"),
            pytest.param("https://docs.example.com", "docs.example.com", id="preserves_subdomain"),
            pytest.param("https://Example.COM/Page", "example.com", id="lowercases"),
            # urlparse is lenient, but completely broken strings may return empty netloc
            pytest.param("", "", id="invalid_url_returns_empty"),
            pytest.param("https://example.com:8080/path", "example.com:8080", id="port_included_in_netloc"),
        ],
    )
    def test_get_domain(self, url, expected):
        assert _get_domain(url) == expected

    def test_valueerror_returns_empty(self, monkeypatch):
        """Trigger the defensive ValueError branch in _get_domain."""
        from urllib import parse as _urlparse_mod

        _ = _urlparse_mod.urlparse  # keep reference before patching

        def bad_urlparse(url, *a, **kw):
            raise ValueError("bad url")

        monkeypatch.setattr("services.discovery.inventory_domain.urlparse", bad_urlparse)
        assert _get_domain("anything") == ""


class TestDomainMatches:
    @pytest.mark.parametrize(
        ("domain", "known", "expected"),
        [
            pytest.param("docs.example.com", "example.com", True, id="subdomain_match"),
            # Suffix-confusion guard: `known in domain` would admit this.
            pytest.param("notexample.com", "example.com", False, id="no_match_partial"),
        ],
    )
    def test_domain_matches(self, domain, known, expected):
        assert _domain_matches(domain, known) is expected


class TestDomainClassifiers:
    @pytest.mark.parametrize(
        ("fn", "domain", "expected"),
        [
            pytest.param(_is_explorer_domain, "eth.blockscout.com", True, id="explorer_blockscout_subdomain"),
            pytest.param(_is_explorer_domain, "example.com", False, id="explorer_non_explorer"),
            pytest.param(_is_low_trust_domain, "www.reddit.com", True, id="low_trust_subdomain"),
            pytest.param(_is_low_trust_domain, "uniswap.org", False, id="low_trust_normal_domain"),
        ],
    )
    def test_classifier(self, fn, domain, expected):
        assert fn(domain) is expected


class TestIsAllowedDomain:
    @pytest.mark.parametrize(
        ("allowed", "domain"),
        [
            pytest.param(["example.com"], "other.com", id="not_in_list"),
            # Fail-closed: an empty allowlist admits nothing.
            pytest.param([], "example.com", id="empty_list"),
        ],
    )
    def test_rejected(self, domain, allowed):
        assert _is_allowed_domain(domain, allowed) is False


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

    def test_single_value_is_the_address(self):
        addr = "0x" + "ab" * 20
        result = _extract_addresses(f"contract at {addr}")
        assert addr.lower().replace("0x", "", 1) in list(result)[0]


class TestInferChain:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            pytest.param("https://etherscan.io/address/0x1234", "ethereum", id="etherscan_url"),
            pytest.param("https://arbiscan.io/address/0x1234", "arbitrum", id="arbiscan_url"),
            pytest.param("https://polygonscan.com/address/0x1234", "polygon", id="polygonscan_url"),
            pytest.param("https://basescan.org/address/0x1234", "base", id="basescan_url"),
            pytest.param("https://base.blockscout.com/address/0x1234", "base", id="blockscout_base"),
        ],
    )
    def test_explorer_url(self, url, expected):
        assert _infer_chain(url, "") == expected

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

    def test_optimistic_etherscan_url_resolves_to_optimism(self):
        # Regression: etherscan.io must not suffix-shadow its own subdomain entry.
        assert _infer_chain("https://optimistic.etherscan.io/address/0x1234", "") == "optimism"

    def test_unknown_when_no_clues(self):
        assert _infer_chain("https://example.com", "some random text") == "unknown"

    def test_url_takes_priority_over_text(self):
        # URL says ethereum, text says arbitrum — URL should win
        assert _infer_chain("https://etherscan.io/address/0x1234", "arbitrum stuff") == "ethereum"


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


# ---------------------------------------------------------------------------
# _maybe_domain
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _fetch_page
# ---------------------------------------------------------------------------


class TestFetchPage:
    # ``_fetch_page`` fetches through the SSRF guard (``utils.egress.safe_get``),
    # so these stub that rather than the raw ``requests`` call.
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


# ---------------------------------------------------------------------------
# _dedupe_results_by_url
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _discover_contract_inventory_pages (integration with mocks)
# ---------------------------------------------------------------------------


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
        assert len(search_queries) == 2
        assert any("example.com" in q for q in search_queries)
        assert any("gitbook.example.com" in q for q in search_queries)

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
