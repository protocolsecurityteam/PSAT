"""Fields of structs another contract returns, checked against the EVM: each is the item of the call's ABI-decoded
return data it is (``("abi", call, returns, path, type)``), so the lowered formula evaluated at concrete arguments says
exactly what ``eth_call`` says, where the earlier word-indexed reading was wrong or refused: a nested struct's field, a
field beside a dynamic one (the struct then sits behind an offset word, which that reading took for its first field),
a struct among several return values (which shifts the words of the values after it). A dynamic field itself
(``bytes``) is refused by its name alone, the fields beside it read. A struct in memory wrapping a dynamic array
(``KeyValueList.List``) stays read through the memory model. The verdict lists an identity a nested or offset struct
field holds like any other address a call returns (``_oracle.check``)."""

from __future__ import annotations

import pytest

from services.logic.decide import UNK
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract Oracle {
    struct Report { uint104 totalValue; int104 inOutDelta; uint48 timestamp; }
    struct Record { Report report; uint96 liabilityShares; address keeper; }
    struct Tagged { uint256 nonce; bytes data; address who; }
    struct Flat { uint64 a; uint256 value; address who; }
    Flat flat; Record record; Tagged tagged;
    constructor(address who) {
        flat = Flat(9, 500, who);
        record = Record(Report(1000, -3, 1700), 77, who);
        tagged = Tagged(7, hex"aabbcc", who);
    }
    function getFlat() external view returns (Flat memory) { return flat; }
    function getRecord() external view returns (Record memory) { return record; }
    function getTagged() external view returns (Tagged memory) { return tagged; }
    function getMixed() external view returns (Report memory, uint256 n, bool ok) { return (record.report, 42, true); }
}

contract C {
    struct List { uint256[] _inner; }
    Oracle oracle;
    constructor(Oracle o) { oracle = o; }
    function flatValue(uint256 min) external view { require(oracle.getFlat().value >= min); }
    function nestedSlot(uint48 want) external view { require(oracle.getRecord().report.timestamp == want); }
    function nestedDelta(int104 want) external view { require(oracle.getRecord().report.inOutDelta == want); }
    function nestedKeeper() external view { require(oracle.getRecord().keeper == msg.sender); }
    function mixed(uint256 n, bool ok, uint48 ts) external view {
        (Oracle.Report memory r, uint256 m, bool b) = oracle.getMixed();
        require(m == n && b == ok && r.timestamp == ts);
    }
    function taggedNonce(uint256 want) external view { require(oracle.getTagged().nonce == want); }
    function taggedWho() external view { require(oracle.getTagged().who == msg.sender); }
    function taggedData(uint256 len) external view { require(oracle.getTagged().data.length == len); }
    function memoryInner(uint256 n, uint256 want) external pure {
        List memory l = List(new uint256[](n));
        require(l._inner.length == want);
    }
    function memoryInnerItem(uint256 n, uint256 v) external pure {
        List memory l = List(new uint256[](n));
        l._inner[0] = v;
        require(l._inner[0] == v);
    }
}
"""

WHO = O.ACCOUNTS[1]

# (function, arguments, what the chain says)
CASES = [
    ("flatValue", (5,), True), ("flatValue", (1000,), False),
    ("nestedSlot", (1700,), True), ("nestedSlot", (32,), False),
    ("nestedDelta", (-3,), True), ("nestedDelta", (3,), False),
    ("mixed", (42, True, 1700), True), ("mixed", (42, False, 1700), False), ("mixed", (1700, True, 1700), False),
    # The struct sits behind an offset word (32): read as its first field, the offset passed for the nonce.
    ("taggedNonce", (7,), True), ("taggedNonce", (32,), False),
    ("memoryInner", (3, 3), True), ("memoryInner", (3, 4), False), ("memoryInnerItem", (2, 9), True),
]  # fmt: skip


def _setup(d):
    d.deploy("Oracle", ("address",), (WHO,))
    d.deploy("C", ("address",), (d.at["Oracle"],))


PROBES = [O.Probe(SOURCE, _setup, (("C", "nestedKeeper", ("Oracle",)), ("C", "taggedWho", ("Oracle",))))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


@pytest.mark.parametrize(("name", "values", "chain"), CASES, ids=[f"{c[0]}{c[1]}"[:50] for c in CASES])
def test_a_field_of_a_returned_struct_reads_as_the_chain_decodes_it(d, name, values, chain):
    fn = O.function(d, "C", name)
    assert O.chain_says(d, fn, values) == chain
    formula, engine = O.engine_says(d, fn, values, contracts=d.contracts("C", "Oracle"))
    assert engine == chain, (name, values, formula)


@pytest.mark.parametrize("name", ["nestedKeeper", "taggedWho"])
def test_an_identity_a_returned_struct_holds_reads_for_its_holder_alone(d, name):
    fn = O.function(d, "C", name)
    for who in (WHO, O.OWNER, *O.STRANGERS[:2]):
        assert O.chain_says(d, fn, (), sender=who) == (who == WHO)
        formula, engine = O.engine_says(d, fn, (), sender=who, contracts=d.contracts("C", "Oracle"))
        assert engine == (who == WHO), (name, hex(who), formula)


def test_a_dynamic_field_is_refused_by_its_name_alone(d):
    fn = O.function(d, "C", "taggedData")
    assert O.chain_says(d, fn, (3,))
    formula, engine = O.engine_says(d, fn, (3,), contracts=d.contracts("C", "Oracle"))
    assert engine is UNK and O.labels(formula) == {"unsupported:member:data"}, formula


@pytest.mark.parametrize("name", ["nestedKeeper", "taggedWho"])
def test_the_verdict_lists_the_identity_a_returned_struct_names(d, name):
    v = O.verdict(d, "C", name, "Oracle")
    O.check(d, "C", name, v, open_at=False)
    assert v.openness == "restricted" and v.complete and set(v.principals) == {WHO}, v
