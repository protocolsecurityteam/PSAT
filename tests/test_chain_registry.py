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


def test_chain_by_name_unknown_sentinel_raises():
    # The discovery "unknown" sentinel is intentionally not resolvable.
    with pytest.raises(UnknownChainError):
        chain_by_name("unknown")


def test_chain_by_name_unknown_and_empty_raise():
    for bad in ("fantom", "", "   "):
        with pytest.raises(UnknownChainError):
            chain_by_name(bad)


def test_all_chain_ids_positive_and_unique():
    ids = [c.chain_id for c in all_chains()]
    assert all(cid > 0 for cid in ids)
    assert len(ids) == len(set(ids))


def test_indexer_enabled_chains_have_hypersync_url():
    # Conservative default (inv. 10): indexer enabled only where coverage is
    # proven. Mainnet is demonstrated in-codebase; Base is preview-validated
    # (inv. 14, Phase 2). Every other chain stays None until it earns its slot.
    by_name = {c.name: c for c in all_chains()}
    assert by_name["ethereum"].hypersync_url == "https://eth.hypersync.xyz"
    assert all(c.hypersync_url is None for c in all_chains() if c.name not in ("ethereum", "base"))


def test_base_registry_values():
    # Phase 2 enablement facts for Base (chain 8453). Bridge constants are the
    # OP-stack L2 predeploys (inv. 15); confirmation depth tracks mainnet's
    # wall-clock finality window on Base's ~2s blocks.
    base = chain_by_id(8453)
    assert base.name == "base"
    assert base.hypersync_url == "https://base.hypersync.xyz"
    assert base.explorer_base_url == "https://basescan.org"
    assert base.confirmation_depth == 75
    assert base.max_getlogs_range == 2000
    assert base.cross_domain_messengers == ("0x4200000000000000000000000000000000000007",)
    assert base.bridge_executors == ("0x4200000000000000000000000000000000000010",)


def test_every_chain_has_a_native_asset():
    # inv. 5: the native gas-token symbol is an explicit registry fact for every
    # chain — TVL native-asset pricing dispatches on it (services/monitoring/tvl.py).
    for info in all_chains():
        assert info.native_asset, f"{info.name} is missing a native_asset symbol"
        assert info.native_asset == info.native_asset.strip()


def test_native_asset_eth_native_chains():
    # ETH-native chains are the only ones TVL can price at the ETH/USD quote.
    by_name = {c.name: c for c in all_chains()}
    for name in ("ethereum", "base", "arbitrum", "optimism", "linea", "scroll", "zksync", "blast", "mode"):
        assert by_name[name].native_asset == "ETH", name


def test_native_asset_non_eth_chains():
    # These chains carry their own native gas token — never ETH — so TVL must
    # refuse to quote their native balance at the ETH price.
    by_name = {c.name: c for c in all_chains()}
    # POL is the current canonical symbol (renamed from MATIC).
    assert by_name["polygon"].native_asset == "POL"
    assert by_name["bsc"].native_asset == "BNB"
    assert by_name["avalanche"].native_asset == "AVAX"
    assert by_name["berachain"].native_asset == "BERA"
    for name in ("polygon", "bsc", "avalanche", "berachain"):
        assert by_name[name].native_asset != "ETH", name


def test_supported_chain_ids_default_is_mainnet(monkeypatch):
    monkeypatch.delenv("PSAT_SUPPORTED_CHAIN_IDS", raising=False)
    assert supported_chain_ids() == frozenset({1})


def test_supported_chain_ids_parses_env(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1, 8453 ,, bogus,10")
    assert supported_chain_ids() == frozenset({1, 8453, 10})


def test_supported_chain_ids_blank_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "   ")
    assert supported_chain_ids() == frozenset({1})


def test_supported_property_tracks_env(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    assert chain_by_id(1).supported is True
    assert chain_by_id(8453).supported is False
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    assert chain_by_id(8453).supported is True
