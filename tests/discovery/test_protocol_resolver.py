"""Tests for services.discovery.protocol_resolver."""

from __future__ import annotations

import pytest
import requests

from services.discovery.protocol_resolver import (
    _fetch_protocols,
    _find_siblings,
    _make_result,
    _match_protocol,
    _normalize,
    resolve_protocol,
)

# ---------------------------------------------------------------------------
# Sample protocol dicts reused across tests
# ---------------------------------------------------------------------------

AAVE = {
    "slug": "aave-v3",
    "name": "Aave V3",
    "url": "https://app.aave.com",
    "chains": ["Ethereum", "Polygon"],
    "tvl": 10_000,
    "parentProtocol": "parent#aave",
}

AAVE_V2 = {
    "slug": "aave-v2",
    "name": "Aave V2",
    "url": "https://app.aave.com/v2",
    "chains": ["Ethereum"],
    "tvl": 5_000,
    "parentProtocol": "parent#aave",
}

ETHERFI = {
    "slug": "ether.fi-stake",
    "name": "Ether.fi Stake",
    "url": "https://ether.fi",
    "chains": ["Ethereum"],
    "tvl": 8_000,
    "parentProtocol": "parent#etherfi",
}

LIDO = {
    "slug": "lido",
    "name": "Lido",
    "url": "https://lido.fi",
    "chains": ["Ethereum"],
    "tvl": 20_000,
}

PROTOCOLS = [LIDO, AAVE, ETHERFI, AAVE_V2]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch):
    """Reset the module-level protocol cache before every test."""
    monkeypatch.setattr("services.discovery.protocol_resolver._protocols_cache", None)


# ---------------------------------------------------------------------------
# _normalize
# ---------------------------------------------------------------------------


class TestNormalize:
    def test_lowercase_and_strip_punctuation(self):
        assert _normalize("Ether.fi") == "etherfi"

    def test_spaces_removed(self):
        assert _normalize("Aave V3") == "aavev3"

    def test_dashes_and_underscores_removed(self):
        assert _normalize("my-proto_col") == "myprotocol"

    def test_unicode_non_ascii_stripped(self):
        # Non-ASCII characters are removed by the [^a-z0-9] regex
        assert _normalize("café") == "caf"

    def test_empty_string(self):
        assert _normalize("") == ""


# ---------------------------------------------------------------------------
# _make_result
# ---------------------------------------------------------------------------


class TestMakeResult:
    def test_builds_correct_structure(self):
        result = _make_result(AAVE, [AAVE, AAVE_V2])
        assert result == {
            "slug": "aave-v3",
            "url": "https://app.aave.com",
            "name": "Aave V3",
            "chains": ["Ethereum", "Polygon"],
            "all_slugs": ["aave-v3", "aave-v2"],
            "all_names": ["Aave V3", "Aave V2"],
        }

    def test_single_protocol_no_siblings(self):
        result = _make_result(LIDO, [LIDO])
        assert result["all_slugs"] == ["lido"]

    def test_missing_fields_default_to_none(self):
        bare = {"tvl": 1}
        result = _make_result(bare, [bare])
        assert result["slug"] is None
        assert result["url"] is None
        assert result["name"] is None
        assert result["chains"] == []
        assert result["all_slugs"] == []


# ---------------------------------------------------------------------------
# _find_siblings
# ---------------------------------------------------------------------------


class TestFindSiblings:
    def test_with_parent_protocol(self):
        siblings = _find_siblings(AAVE, PROTOCOLS)
        slugs = {s["slug"] for s in siblings}
        assert slugs == {"aave-v3", "aave-v2"}

    def test_without_parent_protocol(self):
        siblings = _find_siblings(LIDO, PROTOCOLS)
        assert siblings == [LIDO]

    def test_single_child_of_parent(self):
        siblings = _find_siblings(ETHERFI, PROTOCOLS)
        assert siblings == [ETHERFI]


# ---------------------------------------------------------------------------
# _match_protocol
# ---------------------------------------------------------------------------


class TestMatchProtocol:
    # Tier 1: exact slug
    def test_exact_slug_match(self):
        result = _match_protocol("aave-v3", PROTOCOLS)
        assert result is AAVE

    def test_exact_slug_case_insensitive(self):
        result = _match_protocol("AAVE-V3", PROTOCOLS)
        assert result is AAVE

    # Tier 2: exact name
    def test_exact_name_match(self):
        result = _match_protocol("Aave V3", PROTOCOLS)
        assert result is AAVE

    def test_exact_name_case_insensitive(self):
        result = _match_protocol("aave v3", PROTOCOLS)
        assert result is AAVE

    # Tier 3: normalized match
    def test_normalized_match_dot(self):
        # "etherfi" normalizes the same as "ether.fi" in slug "ether.fi-stake"
        # but tier 3 checks full normalized equality, so we need exact match.
        # "etherfistake" != "etherfi", so this goes to tier 4 substring.
        # Instead test: "ether.fi-stake" (with punctuation) matches slug exactly
        # after normalization.
        result = _match_protocol("etherfistake", PROTOCOLS)
        assert result is ETHERFI

    def test_normalized_match_ignores_punctuation(self):
        result = _match_protocol("ether.fi stake", PROTOCOLS)
        assert result is ETHERFI

    # Tier 4: substring match (50% length requirement)
    def test_substring_match_sufficient_length(self):
        # "etherfi" (7 chars) is substring of "etherfistake" (12 chars)
        # 7/12 = 0.583 >= 0.5 -> match
        result = _match_protocol("etherfi", PROTOCOLS)
        assert result is ETHERFI

    def test_substring_match_via_name(self):
        # Slug does NOT contain the substring, but name does -> hits line 88
        protos = [
            {"slug": "xyz-unrelated", "name": "SuperSwap", "tvl": 1},
        ]
        # "superswap" (9 chars) is the full normalized name (9 chars)
        # but slug normalized "xyzunrelated" does not contain "supers"
        # "supers" (6 chars) in "superswap" (9 chars) => 6/9 = 0.667 >= 0.5
        result = _match_protocol("supers", protos)
        assert result is protos[0]

    def test_substring_too_short_no_match(self):
        # Very short substring that is less than 50% of target
        # "fi" (2 chars) in "etherfistake" (12 chars) => 2/12 = 0.167 < 0.5
        protos = [{"slug": "abcdefghijklmn", "name": "Big Protocol", "tvl": 1}]
        result = _match_protocol("abc", protos)
        # 3/14 = 0.214 < 0.5, and 3/11 (name normalized "bigprotocol") doesn't contain "abc"
        assert result is None

    # Tier 5: fuzzy similarity
    def test_fuzzy_match_above_threshold(self):
        # "lidoo" is very close to "lido" — similarity ~0.89 with 4/5 matching.
        # Actually SequenceMatcher("lidoo", "lido").ratio() = 0.889 which is < 0.90
        # Use a closer mismatch.
        protos = [{"slug": "compound-v2", "name": "Compound V2", "tvl": 1}]
        # "compoundv2" vs "compoundv2" (exact after normalize) would be tier 3.
        # Let's use a name that is very close but not identical.
        # "compoundv2x" ratio with "compoundv2" = 20/21 ≈ 0.952
        result = _match_protocol("compound-v2x", protos)
        assert result is protos[0]

    # No match
    def test_no_match_returns_none(self):
        result = _match_protocol("nonexistent-protocol-xyz", PROTOCOLS)
        assert result is None

    # Empty / blank input
    def test_empty_input_returns_none(self):
        result = _match_protocol("", PROTOCOLS)
        assert result is None

    def test_blank_input_returns_none(self):
        result = _match_protocol("   ", PROTOCOLS)
        assert result is None

    def test_punctuation_only_returns_none(self):
        result = _match_protocol("...", PROTOCOLS)
        assert result is None


# ---------------------------------------------------------------------------
# resolve_protocol  (mocks _fetch_protocols via requests.get)
# ---------------------------------------------------------------------------


class TestResolveProtocol:
    def test_happy_path_with_siblings(self, monkeypatch):
        mock_resp = type(
            "Resp",
            (),
            {
                "raise_for_status": lambda self: None,
                "json": lambda self: list(PROTOCOLS),
            },
        )()
        monkeypatch.setattr(requests, "get", lambda *a, **kw: mock_resp)

        result = resolve_protocol("Aave V3")
        assert result["slug"] == "aave-v3"
        assert result["name"] == "Aave V3"
        assert "aave-v2" in result["all_slugs"]
        assert "aave-v3" in result["all_slugs"]

    def test_no_match_returns_empty_result(self, monkeypatch):
        mock_resp = type(
            "Resp",
            (),
            {
                "raise_for_status": lambda self: None,
                "json": lambda self: list(PROTOCOLS),
            },
        )()
        monkeypatch.setattr(requests, "get", lambda *a, **kw: mock_resp)

        result = resolve_protocol("totally-unknown-protocol-zzz")
        assert result["slug"] is None
        assert result["all_slugs"] == []

    def test_fetch_failure_returns_empty_result(self, monkeypatch):
        def _boom(*a, **kw):
            raise requests.ConnectionError("network down")

        monkeypatch.setattr(requests, "get", _boom)

        result = resolve_protocol("Aave")
        assert result["slug"] is None
        assert result["all_slugs"] == []


# ---------------------------------------------------------------------------
# _fetch_protocols caching
# ---------------------------------------------------------------------------


class TestFetchProtocols:
    def test_caching_avoids_second_request(self, monkeypatch):
        call_count = 0

        def _mock_get(*a, **kw):
            nonlocal call_count
            call_count += 1
            resp = type(
                "Resp",
                (),
                {
                    "raise_for_status": lambda self: None,
                    "json": lambda self: [{"slug": "x", "tvl": 1}],
                },
            )()
            return resp

        monkeypatch.setattr(requests, "get", _mock_get)

        first = _fetch_protocols()
        second = _fetch_protocols()

        assert call_count == 1
        assert first is second

    def test_sorts_by_tvl_descending(self, monkeypatch):
        data = [
            {"slug": "low", "tvl": 100},
            {"slug": "high", "tvl": 9999},
            {"slug": "mid", "tvl": 500},
        ]
        mock_resp = type(
            "Resp",
            (),
            {
                "raise_for_status": lambda self: None,
                "json": lambda self: list(data),
            },
        )()
        monkeypatch.setattr(requests, "get", lambda *a, **kw: mock_resp)

        result = _fetch_protocols()
        assert [p["slug"] for p in result] == ["high", "mid", "low"]

    def test_raises_on_http_error(self, monkeypatch):
        def _mock_get(*a, **kw):
            resp = type(
                "Resp",
                (),
                {
                    "raise_for_status": lambda self: (_ for _ in ()).throw(requests.HTTPError("500")),
                },
            )()
            return resp

        monkeypatch.setattr(requests, "get", _mock_get)

        with pytest.raises(requests.HTTPError):
            _fetch_protocols()
