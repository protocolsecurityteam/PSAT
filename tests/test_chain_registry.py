"""Registry behavior tests (inv. 5): id/name lookup, alias resolution,
raise-on-unknown, supported_chain_ids parsing, and consistency of the derived
maps that replaced the four former hand-maintained chain maps."""

from __future__ import annotations

import pytest

from services.discovery.inventory_domain import CHAIN_IDS as INVENTORY_CHAIN_IDS
from utils.chains import (
    UnknownChainError,
    all_chains,
    chain_by_id,
    chain_by_name,
    chain_name_to_id_map,
    supported_chain_ids,
)
from utils.rpc import COMMON_CHAIN_IDS


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


def test_common_chain_ids_preserves_legacy_entries():
    # The registry-derived map must still carry exactly the entries the old
    # hand-maintained utils.rpc.COMMON_CHAIN_IDS did.
    expected = {
        "ethereum": 1,
        "mainnet": 1,
        "arbitrum": 42161,
        "optimism": 10,
        "polygon": 137,
        "base": 8453,
        "avalanche": 43114,
        "bsc": 56,
        "linea": 59144,
        "scroll": 534352,
        "zksync": 324,
        "blast": 81457,
        "mode": 34443,
        "bera": 80094,
        "berachain": 80094,
    }
    assert COMMON_CHAIN_IDS == expected
    assert chain_name_to_id_map() == expected


def test_inventory_chain_ids_preserved():
    # The inventory discoverable set stays the exact 11 chains, id values now
    # sourced from the registry.
    assert INVENTORY_CHAIN_IDS == {
        "ethereum": 1,
        "arbitrum": 42161,
        "optimism": 10,
        "polygon": 137,
        "base": 8453,
        "avalanche": 43114,
        "bsc": 56,
        "linea": 59144,
        "scroll": 534352,
        "zksync": 324,
        "blast": 81457,
    }
