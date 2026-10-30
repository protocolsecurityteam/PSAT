"""Storage completeness/state-root checks against independently executed local chain state."""

import pytest
from eth_abi import encode
from eth_utils import keccak

from services.clients.logic_reads import ChainReads
from services.logic.model import BudgetExceeded, ReadError
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import rpc


@pytest.fixture(scope="module")
def snapshot(anvil):
    url, root = anvil
    d = Deployment(
        url,
        root,
        "pragma solidity 0.8.27; contract C {uint public a=1; uint public b=2; "
        "function set(uint x,uint y) external {a=x;b=y;}}",
    )
    at = d.deploy("C")
    d.send("C", "0x" + (keccak(text="set(uint256,uint256)")[:4] + encode(["uint", "uint"], [7, 9])).hex())
    block = int(rpc(url, "eth_blockNumber", []), 16)
    return url, at, block


def pages(words):
    return {
        "storage": {
            "0x" + keccak(k.to_bytes(32, "big")).hex(): {"key": hex(k), "value": hex(v)} for k, v in words.items()
        },
        "nextKey": None,
    }


def provider(snapshot, words):
    url, at, block = snapshot

    def call(method, params):
        if method == "debug_storageRangeAt":
            return pages(words)
        return rpc(url, method, params)

    return ChainReads(call, block)


def test_dump_matches_real_post_transaction_account_root(snapshot):
    _, at, _ = snapshot
    assert provider(snapshot, {0: 7, 1: 9}).storage_dump(at) == {0: 7, 1: 9}


@pytest.mark.parametrize("words", [{0: 7}, {0: 1, 1: 2}, {0: 7, 1: 9, 2: 1}, {}])
def test_missing_extra_and_pre_transaction_storage_are_refused(snapshot, words):
    _, at, _ = snapshot
    with pytest.raises(ReadError, match="state root"):
        provider(snapshot, words).storage_dump(at)


def test_unknown_slot_preimage_is_refused(snapshot):
    url, at, block = snapshot

    def call(method, params):
        if method == "debug_storageRangeAt":
            return {"storage": {"0x" + "00" * 32: {"key": None, "value": "0x7"}}}
        return rpc(url, method, params)

    with pytest.raises(ReadError, match="preimages"):
        ChainReads(call, block).storage_dump(at)


def test_dump_size_budget_never_claims_empty(snapshot):
    _, at, _ = snapshot
    r = provider(snapshot, {0: 7, 1: 9})
    r.word_limit = 1
    with pytest.raises(BudgetExceeded):
        r.storage_dump(at)


def test_separate_debug_chain_identity_is_not_hidden_by_primary_memo():
    r = ChainReads(lambda m, p: "0x1", 123, debug=lambda m, p: "0x2")
    assert r._read("eth_chainId", []) == "0x1"
    with pytest.raises(ReadError, match="different chain"):
        r._read("debug_storageRangeAt", [], debug=True)
    assert r.sent == 2


def test_configured_quicknode_only_routes_debug(monkeypatch):
    from services.logic.deployment import _deployment_inputs

    monkeypatch.setenv("QUICK_NODE_ETH", "https://quicknode.invalid/key")
    monkeypatch.delenv("PSAT_DEBUG_RPC_URL_1", raising=False)
    calls = []

    def call(url, method, params, **kw):
        calls.append((url, method))
        return "0x1"

    monkeypatch.setattr("services.clients.rpc.rpc_request", call)
    with _deployment_inputs(None, 1, "https://erpc.invalid", 123) as (reads, _):
        reads.storage(1, 0)
        reads._read("debug_traceTransaction", ["hash"], debug=True)
    assert ("https://erpc.invalid", "eth_getStorageAt") in calls
    assert ("https://quicknode.invalid/key", "debug_traceTransaction") in calls
    assert ("https://quicknode.invalid/key", "eth_chainId") in calls


def test_noncanonical_zero_padding_cannot_bypass_word_budget(snapshot):
    _, at, _ = snapshot
    with pytest.raises(ReadError, match="zero"):
        provider(snapshot, {0: 7, 1: 9, 2: 0}).storage_dump(at)


@pytest.mark.parametrize("cursor", ["0xnothex", "0x7", {}, ""])
def test_malformed_cursor_is_rejected(snapshot, cursor):
    url, at, block = snapshot

    def call(method, params):
        if method == "debug_storageRangeAt":
            return {**pages({0: 7, 1: 9}), "nextKey": cursor}
        return rpc(url, method, params)

    with pytest.raises(ReadError, match="cursor"):
        ChainReads(call, block).storage_dump(at)


def test_pagination_cycle_is_rejected(snapshot):
    url, at, block = snapshot

    def call(method, params):
        if method == "debug_storageRangeAt":
            return {"storage": {}, "nextKey": "0x" + "07" * 32}
        return rpc(url, method, params)

    with pytest.raises(ReadError, match="cursor"):
        ChainReads(call, block).storage_dump(at)


@pytest.mark.parametrize(
    "damage",
    [
        lambda p: p.update(accountProof=[]),
        lambda p: p.update(storageHash="0x" + "00" * 32),
        lambda p: p.update(accountProof=["0x00"]),
    ],
)
def test_invalid_proof_fails_before_dump_requests(snapshot, damage):
    url, at, block = snapshot
    dump = []

    def call(method, params):
        if method == "debug_storageRangeAt":
            dump.append(params)
            return pages({0: 7, 1: 9})
        result = rpc(url, method, params)
        if method == "eth_getProof":
            damage(result)
        return result

    with pytest.raises(ReadError, match="account proof"):
        ChainReads(call, block).storage_dump(at)
    assert not dump
