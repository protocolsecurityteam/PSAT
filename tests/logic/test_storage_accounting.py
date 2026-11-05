"""Accounting optimizations checked against independently constructed, chain-read slots."""

import pytest
from eth_abi import encode
from eth_utils import keccak

from services.logic.model import Limits
from services.logic.storage import Storage
from services.logic.terms import const
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity ^0.8.10;
contract C {
 mapping(address=>mapping(bytes4=>bool)) allowed;
 struct Pair { uint128 a; uint128 b; }
 mapping(int8=>Pair) pairs;
 constructor() { allowed[msg.sender][0xdeadbeef]=true; pairs[-1]=Pair(17,29); }
 function member(bytes4 key) external view returns(bool) { return allowed[msg.sender][key]; }
 function pair(int8 key) external view returns(uint128,uint128) { return (pairs[key].a,pairs[key].b); }
}
"""
KEY = 0xDEADBEEF


@pytest.fixture
def setup(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C")
    # Independently derive locations from Solidity's layout and ABI encoding.
    outer = encode(["address", "uint256"], [O.hex20(O.OWNER), 0])
    inner = encode(["bytes4", "uint256"], [KEY.to_bytes(4, "big"), int.from_bytes(keccak(outer), "big")])
    signed = encode(["int8", "uint256"], [-1, 1])
    preimages = {int.from_bytes(keccak(x), "big"): x for x in (outer, inner, signed)}
    slots = {int.from_bytes(keccak(x), "big") for x in (inner, signed)}
    reads = d.chain()
    dump = {s: reads.storage(d.at["C"], s) for s in slots}
    assert sorted(dump.values()) == [1, 17 + (29 << 128)]
    return d, dump, preimages


class Hints:
    def __init__(self, dump, words, preimages):
        self.dump, self.words, self.hints = dump, words, preimages
        self.trace_calls = 0

    def storage_dump(self, address):
        return self.dump

    def key_words(self, address):
        return self.words

    def preimages(self, address, slots):
        self.trace_calls += 1
        return self.hints


def account(setup, words, hints=None, limit=100000):
    d, dump, preimages = setup
    reads = Hints(dump, words, preimages if hints is None else hints)
    storage = Storage(reads, d.contracts("C"), Limits(storage_steps=limit), const(0))
    return storage, storage.snapshot(d.at["C"]), reads


def assert_values(snap):
    assert snap.complete
    assert ((("k", O.OWNER), ("k", KEY)), True) in snap.entries["allowed"]
    assert ((("k", -1), ("f", "a")), 17) in snap.entries["pairs"]
    assert ((("k", -1), ("f", "b")), 29) in snap.entries["pairs"]


def test_left_aligned_event_keys_and_signed_aliases_are_normalized_once(setup):
    noise = {int.from_bytes(keccak(str(i).encode()), "big") for i in range(300)}
    storage, snap, reads = account(setup, noise | {O.OWNER, KEY << 224, 255, 2**256 - 1}, hints={})
    assert_values(snap)
    assert reads.trace_calls == 0
    work = next(iter(storage.work.values()))
    # One domain per type, independent of the number of outer mapping keys.
    assert work["by_kind"]["key_normalizations"] == 3 * work["candidate_words"]
    assert work["steps"] < 20000
    assert work["unattributed_slots"] == 0


def test_verified_preimages_recover_hidden_nested_keys_and_both_packed_fields(setup):
    storage, snap, reads = account(setup, set())
    assert_values(snap)
    assert reads.trace_calls == 1
    work = next(iter(storage.work.values()))
    assert work["passes"] == 2 and work["verified_preimages"] == 3
    assert work["snapshot_slots"] == 2 and work["complete"]


def test_forged_preimages_never_account_for_an_unseen_holder(setup):
    _, dump, _ = setup
    fake = {s: b"\0" * 64 for s in dump}
    storage, snap, _ = account(setup, set(), hints=fake)
    assert not snap.complete and snap.unexplained == set(dump)
    assert next(iter(storage.work.values()))["verified_preimages"] == 0


@pytest.mark.parametrize("limit", [0, 1, 10, 100])
def test_cutoff_never_claims_completeness_or_zero_unattributed_slots(setup, limit):
    storage, snap, _ = account(setup, set(), limit=limit)
    assert not snap.complete and any(i.kind == "budget" for i in snap.issues)
    work = next(iter(storage.work.values()))
    assert work["steps"] <= limit
    if limit == 0:
        assert snap.slot_count is None and work["unattributed_slots"] is None
    else:
        assert snap.unexplained == set(setup[1]) - snap.accounted
        assert work["unattributed_slots"] == len(snap.unexplained) > 0


def test_projection_collects_constants_from_the_predicate_before_caller_translation(setup):
    from services.logic.solver import Translation, project
    from services.logic.terms import CALLER, mk

    d, dump, _ = setup
    # No selector in events or traces: its only source is the saved predicate.
    reads = Hints(dump, {O.OWNER, 2**256 - 1}, {})
    predicate = mk("load", const(d.at["C"], "address"), "allowed", (("k", CALLER), ("k", const(KEY, "bytes4"))))
    translation = Translation(reads, d.contracts("C"), d.at["C"], 0, Limits())
    result = project(predicate, translation)
    assert result.complete and result.members == (O.OWNER,)
    assert reads.trace_calls == 0
    assert KEY in translation.storage.constants
