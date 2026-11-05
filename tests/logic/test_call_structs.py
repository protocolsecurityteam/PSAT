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

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.logic._oracle import analyze_function

UNK = None

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


def test_a_dynamic_field_is_evaluated_or_explicitly_qualified(d):
    fn = O.function(d, "C", "taggedData")
    assert O.chain_says(d, fn, (3,))
    formula, engine = O.engine_says(d, fn, (3,), contracts=d.contracts("C", "Oracle"))
    assert engine is UNK or engine is O.chain_says(d, fn, (3,), sender=O.OWNER), formula
    if engine is UNK:
        assert any("member:data" in label or "storage_value:bytes" in label for label in O.labels(formula)), formula


@pytest.mark.parametrize("name", ["nestedKeeper", "taggedWho"])
def test_the_verdict_lists_the_identity_a_returned_struct_names(d, name):
    v = result(d, name)
    assert v.representation == "finite" and v.complete and set(v.members) == {WHO}, v


def result(d, name, followed=True):
    contracts = d.contracts("C", "Oracle") if followed else d.contracts("C")
    return analyze_function(d.slither["C"], O.function(d, "C", name), d.at["C"], d.chain(), contracts).callers


# Widths and alignment: every field type a struct can hold in place, in an all-static struct (one word each, where a
# word-indexed reading took the raw word: a ``bytes4`` sits left-aligned in it, a signed field sign-extended) and in
# one beside a dynamic field; nested structs, fixed arrays of structs and of words (indexed by a constant and by an
# argument), a struct at the second of several return positions, beside a ``bytes`` return, and one the callee builds
# from its argument. Each reading is compared with ``eth_call``, the callee followed and not.
WIDTHS = """
pragma solidity 0.8.27;

contract Oracle {
    enum Kind { A, B, C }
    struct Inner { uint64 a; bytes4 sel; }
    struct Deep { Inner inner; int8 delta; bool ok; Kind kind; }
    struct Outer { Deep deep; uint256 k; }
    struct Flat4 { bytes4 sel; uint256 n; int8 d; bool ok; }
    struct Arr { Inner[2] pair; uint256 n; }
    struct FixedArr { uint256[2] xs; address who; }
    struct DynFirst { bytes data; uint256 nonce; address who; }
    struct TwoDyn { uint256 a; bytes d1; uint256 b; string s; address who; }
    struct Wide {
        bytes1 b1; bytes4 b4; bytes32 b32; bool ok; int8 i8; int128 i128; uint8 u8; Kind kind; address who;
    }
    struct WideDyn {
        bytes data; bytes1 b1; bytes4 b4; bytes32 b32; bool ok; int8 i8; int128 i128; uint8 u8; Kind kind; address who;
    }
    Inner inner; Deep deep; Outer outer; Flat4 flat4; Arr arr; FixedArr fixedArr; DynFirst dynFirst; TwoDyn twoDyn;
    Wide wide; WideDyn wideDyn;
    constructor(address who) {
        inner = Inner(11, 0xdeadbeef);
        deep = Deep(inner, -5, true, Kind.B);
        outer = Outer(deep, 8);
        flat4 = Flat4(0x12345678, 99, -7, true);
        arr.pair[0] = Inner(1, 0x11111111); arr.pair[1] = Inner(2, 0x22222222); arr.n = 5;
        fixedArr = FixedArr([uint256(3), 4], who);
        dynFirst = DynFirst(hex"aa", 7, who);
        twoDyn = TwoDyn(1, hex"bb", 2, "s", who);
        wide = Wide(0xab, 0x12345678, bytes32(uint256(2**255 + 5)), true, -7, -(2**100), 200, Kind.C, who);
        wideDyn = WideDyn(
            hex"cc", 0xab, 0x12345678, bytes32(uint256(2**255 + 5)), true, -7, -(2**100), 200, Kind.C, who
        );
    }
    function getDeep() external view returns (Deep memory) { return deep; }
    function getOuter() external view returns (Outer memory) { return outer; }
    function getFlat4() external view returns (Flat4 memory) { return flat4; }
    function getArr() external view returns (Arr memory) { return arr; }
    function getFixedArr() external view returns (FixedArr memory) { return fixedArr; }
    function getDynFirst() external view returns (DynFirst memory) { return dynFirst; }
    function getTwoDyn() external view returns (TwoDyn memory) { return twoDyn; }
    function getWide() external view returns (Wide memory) { return wide; }
    function getWideDyn() external view returns (WideDyn memory) { return wideDyn; }
    function getSecond() external view returns (uint256 x, Inner memory i, bool ok) { return (10, inner, true); }
    function getWithBytes() external view returns (Inner memory i, bytes memory d) { return (inner, hex"cc"); }
    function getBuilt(uint64 a) external pure returns (Deep memory d) {
        d.inner.a = a; d.inner.sel = 0xcafebabe; d.delta = -1; d.ok = a > 5; d.kind = Kind.C;
    }
}

contract C {
    Oracle oracle; uint256 public n;
    constructor(Oracle o) { oracle = o; }
    function deepSel(bytes4 want) external view { require(oracle.getDeep().inner.sel == want); }
    function deepA(uint64 want) external view { require(oracle.getDeep().inner.a == want); }
    function deepDelta(int8 want) external view { require(oracle.getDeep().delta == want); }
    function deepDeltaNeg() external view { require(oracle.getDeep().delta < 0); }
    function deepOk(bool want) external view { require(oracle.getDeep().ok == want); }
    function deepKind(uint8 want) external view { require(uint8(oracle.getDeep().kind) == want); }
    function deepKindIsB() external view { require(oracle.getDeep().kind == Oracle.Kind.B); }
    function outerDelta(int8 want) external view { require(oracle.getOuter().deep.delta == want); }
    function outerSel(bytes4 want) external view { require(oracle.getOuter().deep.inner.sel == want); }
    function outerK(uint256 want) external view { require(oracle.getOuter().k == want); }
    function flatSel(bytes4 want) external view { require(oracle.getFlat4().sel == want); }
    function flatN(uint256 want) external view { require(oracle.getFlat4().n == want); }
    function flatD(int8 want) external view { require(oracle.getFlat4().d == want); }
    function flatOk(bool want) external view { require(oracle.getFlat4().ok == want); }
    function arrSel(bytes4 want) external view { require(oracle.getArr().pair[1].sel == want); }
    function arrA(uint64 want) external view { require(oracle.getArr().pair[1].a == want); }
    function arrN(uint256 want) external view { require(oracle.getArr().n == want); }
    function fixedXs(uint256 want) external view { require(oracle.getFixedArr().xs[1] == want); }
    function fixedXsAt(uint256 i, uint256 want) external view { require(oracle.getFixedArr().xs[i] == want); }
    function fixedXsLen(uint256 want) external view { require(oracle.getFixedArr().xs.length == want); }
    function fixedWho() external view { require(oracle.getFixedArr().who == msg.sender); }
    function dynFirstNonce(uint256 want) external view { require(oracle.getDynFirst().nonce == want); }
    function dynFirstWho() external view { require(oracle.getDynFirst().who == msg.sender); }
    function twoDynB(uint256 want) external view { require(oracle.getTwoDyn().b == want); }
    function twoDynWho() external view { require(oracle.getTwoDyn().who == msg.sender); }
    function wB1(bytes1 want) external view { require(oracle.getWide().b1 == want); }
    function wB4(bytes4 want) external view { require(oracle.getWide().b4 == want); }
    function wB32(bytes32 want) external view { require(oracle.getWide().b32 == want); }
    function wOk(bool want) external view { require(oracle.getWide().ok == want); }
    function wI8(int8 want) external view { require(oracle.getWide().i8 == want); }
    function wI8Neg() external view { require(oracle.getWide().i8 < 0); }
    function wI128(int128 want) external view { require(oracle.getWide().i128 == want); }
    function wI128Neg() external view { require(oracle.getWide().i128 < 0); }
    function wU8(uint8 want) external view { require(oracle.getWide().u8 == want); }
    function wKind(uint8 want) external view { require(uint8(oracle.getWide().kind) == want); }
    function wWho() external view { require(oracle.getWide().who == msg.sender); }
    function dB1(bytes1 want) external view { require(oracle.getWideDyn().b1 == want); }
    function dB4(bytes4 want) external view { require(oracle.getWideDyn().b4 == want); }
    function dB32(bytes32 want) external view { require(oracle.getWideDyn().b32 == want); }
    function dOk(bool want) external view { require(oracle.getWideDyn().ok == want); }
    function dI8(int8 want) external view { require(oracle.getWideDyn().i8 == want); }
    function dI128(int128 want) external view { require(oracle.getWideDyn().i128 == want); }
    function dU8(uint8 want) external view { require(oracle.getWideDyn().u8 == want); }
    function dKind(uint8 want) external view { require(uint8(oracle.getWideDyn().kind) == want); }
    function dWho() external view { require(oracle.getWideDyn().who == msg.sender); }
    function secondA(uint64 want) external view {
        (, Oracle.Inner memory i, ) = oracle.getSecond(); require(i.a == want);
    }
    function secondSel(bytes4 want) external view {
        (, Oracle.Inner memory i, ) = oracle.getSecond(); require(i.sel == want);
    }
    function secondOk(bool want) external view { (, , bool ok) = oracle.getSecond(); require(ok == want); }
    function secondX(uint256 want) external view { (uint256 x, , ) = oracle.getSecond(); require(x == want); }
    function withBytesA(uint64 want) external view {
        (Oracle.Inner memory i, ) = oracle.getWithBytes(); require(i.a == want);
    }
    function builtA(uint64 a, uint64 want) external view { require(oracle.getBuilt(a).inner.a == want); }
    function builtOk(uint64 a) external view { require(oracle.getBuilt(a).ok); }
    function builtSel(uint64 a, bytes4 want) external view { require(oracle.getBuilt(a).inner.sel == want); }
    function builtDelta(uint64 a) external view { require(oracle.getBuilt(a).delta == -1); }
    // Verdicts: a ``bytes4`` field read as its raw word would make ``notSel`` look open and ``isSel`` closed.
    function notSel() external { require(oracle.getFlat4().sel != 0x12345678, "is"); n += 1; }   // truth: nobody
    function isSel() external { require(oracle.getFlat4().sel == 0x12345678, "isnt"); n += 1; }  // truth: everyone
    function xsGate() external { require(oracle.getFixedArr().xs[1] == 4); n += 1; }             // truth: everyone
}
"""

B32 = (2**255 + 5).to_bytes(32, "big")
WIDTH_CASES = [
    ("deepSel", (bytes.fromhex("deadbeef"),), True), ("deepSel", (bytes.fromhex("00000001"),), False),
    ("deepA", (11,), True), ("deepA", (12,), False),
    ("deepDelta", (-5,), True), ("deepDelta", (5,), False), ("deepDeltaNeg", (), True),
    ("deepOk", (True,), True), ("deepOk", (False,), False),
    ("deepKind", (1,), True), ("deepKind", (2,), False), ("deepKindIsB", (), True),
    ("outerDelta", (-5,), True), ("outerDelta", (-4,), False),
    ("outerSel", (bytes.fromhex("deadbeef"),), True), ("outerSel", (bytes.fromhex("deadbeee"),), False),
    ("outerK", (8,), True), ("outerK", (9,), False),
    ("flatSel", (bytes.fromhex("12345678"),), True), ("flatSel", (bytes.fromhex("12345679"),), False),
    ("flatN", (99,), True), ("flatN", (98,), False),
    ("flatD", (-7,), True), ("flatD", (7,), False),
    ("flatOk", (True,), True), ("flatOk", (False,), False),
    ("arrSel", (bytes.fromhex("22222222"),), True), ("arrSel", (bytes.fromhex("11111111"),), False),
    ("arrA", (2,), True), ("arrA", (1,), False),
    ("arrN", (5,), True), ("arrN", (4,), False),
    ("fixedXs", (4,), True), ("fixedXs", (3,), False),
    ("fixedXsAt", (1, 4), True), ("fixedXsAt", (0, 4), False), ("fixedXsAt", (0, 3), True),
    ("fixedXsAt", (2, 0), False),  # out of range: the bound on the path, as the chain's Panic 0x32
    ("fixedXsLen", (2,), True), ("fixedXsLen", (3,), False),
    ("dynFirstNonce", (7,), True), ("dynFirstNonce", (32,), False), ("dynFirstNonce", (64,), False),
    ("twoDynB", (2,), True), ("twoDynB", (1,), False),
    ("wB1", (b"\xab",), True), ("wB1", (b"\x00",), False), ("wB1", (b"\xac",), False),
    ("wB4", (bytes.fromhex("12345678"),), True), ("wB4", (bytes.fromhex("12345600"),), False),
    ("wB32", (B32,), True), ("wB32", (b"\x00" * 32,), False),
    ("wOk", (True,), True), ("wOk", (False,), False),
    ("wI8", (-7,), True), ("wI8", (7,), False), ("wI8Neg", (), True),
    ("wI128", (-(2**100),), True), ("wI128", (2**100,), False), ("wI128Neg", (), True),
    ("wU8", (200,), True), ("wU8", (201,), False),
    ("wKind", (2,), True), ("wKind", (1,), False),
    ("dB1", (b"\xab",), True), ("dB1", (b"\x00",), False),
    ("dB4", (bytes.fromhex("12345678"),), True), ("dB4", (bytes.fromhex("12345600"),), False),
    ("dB32", (B32,), True), ("dB32", (b"\x00" * 32,), False),
    ("dOk", (True,), True), ("dOk", (False,), False),
    ("dI8", (-7,), True), ("dI8", (7,), False),
    ("dI128", (-(2**100),), True), ("dI128", (2**100,), False),
    ("dU8", (200,), True), ("dU8", (201,), False),
    ("dKind", (2,), True), ("dKind", (1,), False),
    ("secondA", (11,), True), ("secondA", (10,), False),
    ("secondSel", (bytes.fromhex("deadbeef"),), True), ("secondSel", (bytes.fromhex("0000000b"),), False),
    ("secondOk", (True,), True), ("secondOk", (False,), False),
    ("secondX", (10,), True), ("secondX", (11,), False),
    ("withBytesA", (11,), True), ("withBytesA", (12,), False),
    ("builtA", (3, 3), True), ("builtA", (3, 4), False),
    ("builtOk", (9,), True), ("builtOk", (2,), False),
    ("builtSel", (1, bytes.fromhex("cafebabe")), True), ("builtSel", (1, bytes.fromhex("cafebab0")), False),
    ("builtDelta", (1,), True),
]  # fmt: skip
IDENTITY_FIELDS = ["fixedWho", "dynFirstWho", "twoDynWho", "wWho", "dWho"]


def _widths(d):
    d.deploy("Oracle", ("address",), (WHO,))
    d.deploy("C", ("address",), (d.at["Oracle"],))


@pytest.fixture(scope="module")
def w(anvil):  # noqa: F811
    d = O.deployment(*anvil, WIDTHS)
    _widths(d)
    return d


@pytest.mark.parametrize(("name", "values", "chain"), WIDTH_CASES, ids=[f"{c[0]}{c[1]}"[:60] for c in WIDTH_CASES])
@pytest.mark.parametrize("followed", [True, False], ids=["followed", "unfollowed"])
def test_every_width_of_a_returned_struct_field_reads_as_the_chain_decodes_it(w, name, values, chain, followed):
    fn = O.function(w, "C", name)
    assert O.chain_says(w, fn, values) == chain
    contracts = w.contracts("C", "Oracle") if followed else None
    formula, engine = O.engine_says(w, fn, values, contracts=contracts)
    if not followed:
        O.agrees(formula, engine, chain, (name, values))
        assert engine is not True
        if engine is UNK:
            assert any("unverified:" in label for label in O.labels(formula))
        return
    assert engine is not UNK, (name, values, followed, O.labels(formula), formula)
    assert engine == chain, (name, values, followed, formula)


@pytest.mark.parametrize("name", IDENTITY_FIELDS)
@pytest.mark.parametrize("followed", [True, False], ids=["followed", "unfollowed"])
def test_an_identity_at_any_place_in_a_returned_struct_reads_for_its_holder_alone(w, name, followed):
    fn = O.function(w, "C", name)
    contracts = w.contracts("C", "Oracle") if followed else None
    for who in (WHO, O.OWNER, *O.STRANGERS[:2]):
        assert O.chain_says(w, fn, (), sender=who) == (who == WHO)
        formula, engine = O.engine_says(w, fn, (), sender=who, contracts=contracts)
        if not followed:
            assert engine is UNK and any("unverified:" in label for label in O.labels(formula))
            continue
        assert engine == (who == WHO), (name, hex(who), followed, formula)


@pytest.mark.parametrize("name", IDENTITY_FIELDS)
def test_the_verdict_lists_the_identity_at_any_place_in_a_returned_struct(w, name):
    v = result(w, name)
    assert v.representation == "finite" and v.complete and set(v.members) == {WHO}, v


@pytest.mark.parametrize("followed", [True, False], ids=["followed", "unfollowed"])
def test_a_bytes4_gate_nobody_meets_is_never_open(w, followed):
    fn = O.function(w, "C", "notSel")
    assert not any(O.passes(w, "C", fn, {}, sender=who) for who in (O.OWNER, *O.STRANGERS))
    v = result(w, "notSel", followed)
    assert (v.representation == "finite" and not v.members) if followed else not v.complete


@pytest.mark.parametrize("name", ["isSel", "xsGate"])
@pytest.mark.parametrize("followed", [True, False], ids=["followed", "unfollowed"])
def test_a_gate_on_a_decoded_field_everyone_meets_is_open(w, name, followed):
    v = result(w, name, followed)
    assert (v.representation == "cofinite" and v.excluded == (0,)) if followed else not v.complete
