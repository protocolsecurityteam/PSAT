"""Unit coverage for the multichain chain-identity primitives.

DB-level (chain, address) dedupe is covered by ``test_chain_aware_cache.py``;
these exercise the pure helpers that thread chain identity everywhere else:
the ``normalize_chain_fields`` chokepoint, the chain<->chain_id mapping, the
``AnalyzeRequest`` boundary validator, and the Etherscan ambient-chain routing.
"""

from __future__ import annotations

import copy

import pytest


@pytest.mark.parametrize(
    "request_in, expected_chain, expected_chain_id",
    [
        ({}, "ethereum", 1),
        ({"chain": "mainnet"}, "ethereum", 1),
        ({"chain": "Base"}, "base", 8453),
        ({"chain": "  Arbitrum One "}, "arbitrum", 42161),
        ({"chain": "base", "chain_id": 8453}, "base", 8453),
        ({"chain_id": 42161}, "arbitrum", 42161),  # back-fill chain from id
        ({"chain": None, "chain_id": None}, "ethereum", 1),
        ({"chain": "someexoticchain"}, "someexoticchain", None),  # unknown -> no id, not mainnet
    ],
)
def test_normalize_chain_fields(request_in, expected_chain, expected_chain_id):
    from utils.chains import normalize_chain_fields

    out = normalize_chain_fields(copy.deepcopy(request_in))
    assert out["chain"] == expected_chain
    assert out["chain_id"] == expected_chain_id


def test_normalize_chain_fields_mutates_in_place():
    from utils.chains import normalize_chain_fields

    d = {"address": "0x" + "ab" * 20}
    returned = normalize_chain_fields(d)
    assert returned is d
    assert d["chain"] == "ethereum" and d["chain_id"] == 1


def test_chain_id_name_round_trip():
    from utils.rpc import chain_id_for_chain_name, chain_name_for_chain_id

    for name in ("ethereum", "base", "arbitrum", "optimism", "polygon"):
        cid = chain_id_for_chain_name(name)
        assert cid is not None
        assert chain_name_for_chain_id(cid) == name


def test_chain_name_for_unknown_id_is_none():
    from utils.rpc import chain_name_for_chain_id

    assert chain_name_for_chain_id(999999) is None
    assert chain_name_for_chain_id(None) is None


def test_analyze_request_canonicalizes_chain():
    from schemas.api_requests import AnalyzeRequest

    addr = "0x" + "11" * 20
    assert (AnalyzeRequest(address=addr, chain="Base").chain) == "base"
    assert AnalyzeRequest(address=addr, chain="Base").chain_id == 8453
    # Omitted chain defaults to ethereum so existing single-chain clients are unchanged.
    default = AnalyzeRequest(address=addr)
    assert default.chain == "ethereum" and default.chain_id == 1
    # chain_id only -> chain back-filled.
    id_only = AnalyzeRequest(address=addr, chain_id=10)
    assert id_only.chain == "optimism"


def test_etherscan_ambient_chain_id_follows_contextvar():
    import utils.etherscan as etherscan
    from utils.logging import chain_var

    assert etherscan._ambient_chain_id() == 1  # no job context -> mainnet
    token = chain_var.set("base")
    try:
        assert etherscan._ambient_chain_id() == 8453
    finally:
        chain_var.reset(token)
    token = chain_var.set("someexoticchain")
    try:
        # Unknown chain falls back to mainnet rather than erroring.
        assert etherscan._ambient_chain_id() == 1
    finally:
        chain_var.reset(token)
