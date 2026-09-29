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
    listing_addresses,
    listing_nominations,
    parse_listing_address,
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

ETHERFI_LIQUID = {
    "slug": "ether.fi-liquid",
    "name": "Ether.fi Liquid",
    "url": "https://ether.fi",
    "chains": ["Ethereum"],
    "tvl": 4_000,
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


def _set_cache(monkeypatch, protocols):
    """Seed the module cache so ``resolve_protocol`` never reaches the wire."""
    monkeypatch.setattr("services.discovery.protocol_resolver._protocols_cache", list(protocols))


# ---------------------------------------------------------------------------
# _normalize
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("Ether.fi", "etherfi", id="lowercase_and_strip_punctuation"),
        pytest.param("Aave V3", "aavev3", id="spaces_removed"),
        pytest.param("my-proto_col", "myprotocol", id="dashes_and_underscores_removed"),
        # Non-ASCII characters are removed by the [^a-z0-9] regex
        pytest.param("café", "caf", id="unicode_non_ascii_stripped"),
        pytest.param("", "", id="empty_string"),
    ],
)
def test_normalize(raw, expected):
    assert _normalize(raw) == expected


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
            "listing_addresses": [],
            "all_slugs": ["aave-v3", "aave-v2"],
            "all_names": ["Aave V3", "Aave V2"],
        }

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


SUPERSWAP = {"slug": "xyz-unrelated", "name": "SuperSwap", "tvl": 1}
BIG_PROTOCOL = {"slug": "abcdefghijklmn", "name": "Big Protocol", "tvl": 1}
COMPOUND = {"slug": "compound-v2", "name": "Compound V2", "tvl": 1}


class TestMatchProtocol:
    @pytest.mark.parametrize(
        ("query", "protos", "expected"),
        [
            # Tier 1: exact slug
            pytest.param("aave-v3", PROTOCOLS, AAVE, id="exact_slug"),
            pytest.param("AAVE-V3", PROTOCOLS, AAVE, id="exact_slug_case_insensitive"),
            # Tier 2: exact name
            pytest.param("Aave V3", PROTOCOLS, AAVE, id="exact_name"),
            pytest.param("aave v3", PROTOCOLS, AAVE, id="exact_name_case_insensitive"),
            # Tier 3: normalized match
            pytest.param("etherfistake", PROTOCOLS, ETHERFI, id="normalized_dot"),
            pytest.param("ether.fi stake", PROTOCOLS, ETHERFI, id="normalized_ignores_punctuation"),
            # Tier 4: substring match (50% length requirement); 7/12 = 0.583 >= 0.5
            pytest.param("etherfi", PROTOCOLS, ETHERFI, id="substring_sufficient_length"),
            # Slug does not contain the substring, but the name does: 6/9 = 0.667 >= 0.5
            pytest.param("supers", [SUPERSWAP], SUPERSWAP, id="substring_via_name"),
            # Substring under 50% of the target length: 3/14 and 3/11 (name "bigprotocol") are both < 0.5
            pytest.param("abc", [BIG_PROTOCOL], None, id="substring_too_short_no_match"),
            # Tier 5: fuzzy similarity; "compoundv2x" vs "compoundv2": ratio 20/21 ~ 0.952
            pytest.param("compound-v2x", [COMPOUND], COMPOUND, id="fuzzy_above_threshold"),
            pytest.param("nonexistent-protocol-xyz", PROTOCOLS, None, id="no_match"),
            # Empty / blank input
            pytest.param("", PROTOCOLS, None, id="empty_input"),
            pytest.param("   ", PROTOCOLS, None, id="blank_input"),
            pytest.param("...", PROTOCOLS, None, id="punctuation_only"),
        ],
    )
    def test_match(self, query, protos, expected):
        assert _match_protocol(query, protos) is expected


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


# ---------------------------------------------------------------------------
# Listing `address` seed (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §3.2 W6)
# ---------------------------------------------------------------------------


class TestListingAddress:
    """The listing's own ``address`` field — the governance token DefiLlama
    publishes on the protocol entry, which the adapter-source scan never sees."""

    def test_bare_address_is_ethereum(self):
        assert parse_listing_address("0xFE0C30065B384F05761f15d0CC899D4F9F9Cc0eB") == (
            "0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb",
            None,
        )

    def test_chain_prefixed_address_keeps_its_chain(self):
        assert parse_listing_address("base:0x60359a0D0Bd9F2C6E3a8b1A9B4C5d6E7f8091A2b") == (
            "0x60359a0d0bd9f2c6e3a8b1a9b4c5d6e7f8091a2b",
            "base",
        )

    @pytest.mark.parametrize("raw", [None, "", "-", "   ", "null", 0x1234, ["0x" + "a" * 40]])
    def test_non_address_values_are_skipped(self, raw):
        assert parse_listing_address(raw) is None

    @pytest.mark.parametrize(
        "raw",
        ["0xnothex", "0x" + "a" * 39, "0x" + "a" * 41, "base:", "base:notanaddress", ":0x" + "a" * 40],
    )
    def test_malformed_values_are_skipped(self, raw):
        assert parse_listing_address(raw) is None

    def test_family_addresses_are_deduped_and_ordered(self):
        family = [
            {"slug": "b", "address": "0x" + "b" * 40},
            {"slug": "a", "address": "0x" + "A" * 40},
            {"slug": "c", "address": "0x" + "a" * 40},
            {"slug": "d", "address": "-"},
            {"slug": "e", "address": None},
        ]
        assert listing_addresses(family) == [
            {"address": "0x" + "a" * 40, "chain": None, "slug": "a"},
            {"address": "0x" + "b" * 40, "chain": None, "slug": "b"},
        ]

    def test_resolve_protocol_publishes_the_family_listing_addresses(self, monkeypatch):
        stake = dict(ETHERFI, address="0xFE0C30065B384F05761f15d0CC899D4F9F9Cc0eB")
        liquid = dict(ETHERFI_LIQUID, address="0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb")
        _set_cache(monkeypatch, [stake, liquid])
        resolved = resolve_protocol("etherfi")
        assert resolved["listing_addresses"] == [
            {"address": "0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb", "chain": None, "slug": stake["slug"]}
        ]
        assert listing_nominations(resolved) == [
            {"address": "0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb", "chain": "ethereum"}
        ]

    def test_no_match_publishes_no_listing_addresses(self, monkeypatch):
        _set_cache(monkeypatch, [AAVE])
        assert resolve_protocol("zzzz-nothing-like-this")["listing_addresses"] == []

    def test_prefixed_chain_is_canonicalized_for_nomination(self):
        resolved = {"listing_addresses": [{"address": "0x" + "c" * 40, "chain": "arbitrum one", "slug": "x"}]}
        assert listing_nominations(resolved) == [{"address": "0x" + "c" * 40, "chain": "arbitrum"}]

    def test_unrecognized_prefix_is_preserved_never_coerced(self):
        """A chain nobody named must not become ethereum — the row stays a
        candidate whose chain never resolves."""
        resolved = {"listing_addresses": [{"address": "0x" + "d" * 40, "chain": "someL3", "slug": "x"}]}
        assert listing_nominations(resolved) == [{"address": "0x" + "d" * 40, "chain": "somel3"}]
