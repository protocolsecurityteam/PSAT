"""Registry behavior tests (inv. 5): id/name lookup, alias resolution,
raise-on-unknown, supported_chain_ids parsing, and per-chain registry
invariants (hypersync url, native asset, predeploy constants)."""

from __future__ import annotations

import pytest

from utils.chains import (
    UnknownChainError,
    all_chains,
    chain_by_id,
    chain_by_name,
    supported_chain_ids,
)


def test_chain_by_id_known():
    info = chain_by_id(1)
    assert info.name == "ethereum"
    assert info.chain_id == 1
    assert info.explorer_base_url == "https://etherscan.io"


def test_chain_by_id_unknown_raises():
    with pytest.raises(UnknownChainError):
        chain_by_id(999999)


def test_chain_by_name_canonical():
    assert chain_by_name("ethereum").chain_id == 1
    assert chain_by_name("arbitrum").chain_id == 42161


def test_chain_by_name_registry_alias():
    # Aliases declared directly on ChainInfo.
    assert chain_by_name("mainnet").name == "ethereum"
    assert chain_by_name("bera").name == "berachain"


def test_chain_by_name_loose_label_alias():
    # Falls back through canonical_chain for loose human labels.
    assert chain_by_name("Arbitrum One").chain_id == 42161
    assert chain_by_name("AVAX").name == "avalanche"
    assert chain_by_name("matic").name == "polygon"


@pytest.mark.parametrize(
    "bad",
    [
        # The discovery "unknown" sentinel is intentionally not resolvable.
        pytest.param("unknown", id="unknown_sentinel"),
        pytest.param("fantom", id="unregistered_name"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="blank"),
    ],
)
def test_chain_by_name_unknown_and_empty_raise(bad):
    with pytest.raises(UnknownChainError):
        chain_by_name(bad)


def test_all_chain_ids_positive_and_unique():
    ids = [c.chain_id for c in all_chains()]
    assert all(cid > 0 for cid in ids)
    assert len(ids) == len(set(ids))


def test_every_chain_has_a_native_asset():
    # inv. 5: the native gas-token symbol is an explicit registry fact for every
    # chain — TVL native-asset pricing dispatches on it (services/monitoring/tvl.py).
    for info in all_chains():
        assert info.native_asset, f"{info.name} is missing a native_asset symbol"
        assert info.native_asset == info.native_asset.strip()


@pytest.mark.parametrize(
    ("name", "symbol"),
    [
        # ETH-native chains are the only ones TVL can price at the ETH/USD quote.
        *[
            pytest.param(n, "ETH", id=n)
            for n in ("ethereum", "base", "arbitrum", "optimism", "linea", "scroll", "zksync", "blast", "mode")
        ],
        # These chains carry their own native gas token (never ETH), so TVL must
        # refuse to quote their native balance at the ETH price. POL is the
        # current canonical symbol for polygon (renamed from MATIC).
        pytest.param("polygon", "POL", id="polygon"),
        pytest.param("bsc", "BNB", id="bsc"),
        pytest.param("avalanche", "AVAX", id="avalanche"),
        pytest.param("berachain", "BERA", id="berachain"),
    ],
)
def test_native_asset(name, symbol):
    assert {c.name: c for c in all_chains()}[name].native_asset == symbol


def test_supported_chain_ids_default_is_mainnet(monkeypatch):
    monkeypatch.delenv("PSAT_SUPPORTED_CHAIN_IDS", raising=False)
    assert supported_chain_ids() == frozenset({1})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("1, 8453 ,, bogus,10", frozenset({1, 8453, 10}), id="parses_env"),
        pytest.param("   ", frozenset({1}), id="blank_falls_back_to_default"),
    ],
)
def test_supported_chain_ids_parses_env(monkeypatch, raw, expected):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", raw)
    assert supported_chain_ids() == expected


def test_supported_property_tracks_env(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    assert chain_by_id(1).supported is True
    assert chain_by_id(8453).supported is False
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    assert chain_by_id(8453).supported is True
