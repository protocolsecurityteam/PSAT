"""``abi.encode`` lays each item out by its declared type: a ``bytesN`` at the left of its word, a signed integer
sign-extended, an address, a bool and an unsigned integer at the right. A value read from storage, computed, or handed
into an inlined function no longer says its type, so the lowering gives each item the argument's declared type, as it
does for ``abi.encodePacked``; an item whose type isn't known, or is dynamic, is refused, never guessed. Each probe
hands the encoding to a callee keyed on its hash and checks the verdict against ``eth_call`` on anvil, the callee
followed and not (unfollowed, the encoded bytes go to the chain as the call's ``bytes`` argument)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from eth_utils import keccak

from services.logic.terms import reset_terms
from services.logic.verdict import function_verdict
from tests.logic import _oracle as O
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """
pragma solidity 0.8.27;

contract G {
    mapping(bytes32 => bool) public good;
    constructor() {
        good[keccak256(abi.encode(bytes4(0x11223344)))] = true;
        good[keccak256(abi.encode(uint256(0x55667788)))] = true;
        good[keccak256(abi.encode(bytes2(0x1122)))] = true;
        good[keccak256(abi.encode(bytes3(0x445566)))] = true;
        good[keccak256(abi.encode(int8(-1)))] = true;
        good[keccak256(abi.encode(uint256(0xfffe)))] = true;
        good[keccak256(abi.encode(address(0xBEEF)))] = true;
        good[keccak256(abi.encode(true))] = true;
        good[keccak256(abi.encode(uint8(9)))] = true;
        good[keccak256(abi.encode(uint64(1 << 40)))] = true;
        good[keccak256(abi.encode(uint256(1 << 200)))] = true;
        good[keccak256(abi.encode(uint256(7), bytes4(0x11223344)))] = true;
        good[keccak256(abi.encodePacked(bytes4(0x11223344)))] = true;
        good[keccak256(abi.encodeWithSelector(bytes4(0xaabbccdd), bytes4(0x11223344)))] = true;
        good[keccak256(abi.encode("hi"))] = true;
    }
    function ok(bytes memory d) external view returns (bool) { return good[keccak256(d)]; }
}
contract C {
    G public g;
    uint256 public x;
    bytes4 public tag = 0x11223344;
    bytes4 public other = 0x55667788;
    bytes2 public b2 = 0x1122;
    int8 public neg = -1;
    int16 public neg16 = -2;
    address public who = address(0xBEEF);
    bool public flag = true;
    uint8 public small = 9;
    uint64 public mid = uint64(1 << 40);
    uint256 public big = 1 << 200;
    string public s = "hi";
    constructor(G z) { g = z; }
    function _k(bytes4 t) internal view returns (bool) { return g.ok(abi.encode(t)); }
    function storedBytes() external { require(g.ok(abi.encode(tag))); x = 1; }
    // Its word as an integer would be in G; as a bytes4 it isn't: nobody passes.
    function storedBytesNot() external { require(g.ok(abi.encode(other))); x = 1; }
    function exprBytes() external { require(g.ok(abi.encode(b2 ^ bytes2(0)))); x = 1; }
    function literalBytes() external { require(g.ok(abi.encode(bytes3(0x445566)))); x = 1; }
    function argBytes() external { require(_k(tag)); x = 1; }
    function signedSmall() external { require(g.ok(abi.encode(neg))); x = 1; }
    // Sign-extended, -2 is not 0xfffe: nobody passes.
    function signedSmallNot() external { require(g.ok(abi.encode(neg16))); x = 1; }
    function addr() external { require(g.ok(abi.encode(who))); x = 1; }
    function boolean() external { require(g.ok(abi.encode(flag))); x = 1; }
    function uint8w() external { require(g.ok(abi.encode(small))); x = 1; }
    function uint64w() external { require(g.ok(abi.encode(mid))); x = 1; }
    function uint256w() external { require(g.ok(abi.encode(big))); x = 1; }
    function pair() external { require(g.ok(abi.encode(uint256(7), tag))); x = 1; }
    function packed() external { require(g.ok(abi.encodePacked(tag))); x = 1; }
    function selector() external { require(g.ok(abi.encodeWithSelector(bytes4(0xaabbccdd), tag))); x = 1; }
    function dynamic() external { require(g.ok(abi.encode(s))); x = 1; }
}
"""

STRANGER = "0x" + "00" * 19 + "aa"
ONE_WORD = [
    "storedBytes",
    "storedBytesNot",
    "exprBytes",
    "literalBytes",
    "argBytes",
    "signedSmall",
    "signedSmallNot",
    "addr",
    "boolean",
    "uint8w",
    "uint64w",
    "uint256w",
    "pair",
    "packed",
    "selector",
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("G")
    d.deploy("C", ("address",), (d.at["G"],))
    return d


def _verdict(d, name, *others):
    reset_terms()
    c = d.slither["C"]
    fn = next(f for f in c.functions_entry_points if f.name == name)
    return function_verdict(c, fn, d.at["C"], d.chain(), d.contracts("C", *others))[0]


def _passes(d, name) -> bool:
    data = "0x" + keccak(text=f"{name}()")[:4].hex()
    try:
        rpc(d.url, "eth_call", [{"from": STRANGER, "to": "0x%040x" % d.at["C"], "data": data}, "latest"])
        return True
    except RuntimeError:
        return False


def test_the_probe_s_chain_truth(d):
    assert {n for n in ONE_WORD if not _passes(d, n)} == {"storedBytesNot", "signedSmallNot"}
    assert _passes(d, "dynamic")


@pytest.mark.parametrize("others", [("G",), ()], ids=["followed", "unfollowed"])
@pytest.mark.parametrize("name", ONE_WORD)
def test_a_one_word_item_is_encoded_as_its_declared_type(d, name, others):
    verdict = _verdict(d, name, *others)
    if _passes(d, name):
        assert verdict.openness == "open" and verdict.allowed == "now", verdict
    else:
        # G's answer is a condition the engine reads as adjustable ("open once it allows"): never "open now".
        assert not (verdict.openness == "open" and verdict.allowed == "now"), verdict


@pytest.mark.parametrize("others", [("G",), ()], ids=["followed", "unfollowed"])
def test_a_dynamic_item_is_refused_never_guessed(d, others):
    # A string read from storage: its encoding isn't laid out by the lowering. Every stranger's own call goes
    # through on the chain, which may settle it "open"; otherwise it is undetermined, the refusal named.
    v = O.check(d, "C", "dynamic", _verdict(d, "dynamic", *others), open_at={})
    if v.openness != "open":
        assert "unknown:unsupported:abi_item:string" in v.gaps, v


ITEMS = """
pragma solidity 0.8.27;

interface I { function k(bytes4) external; }
type Sel is bytes4;

contract Good {
    mapping(bytes32 => bool) public good;
    function set(bytes32 h) external { good[h] = true; }
    function ok(bytes memory d) external view returns (bool) { return good[keccak256(d)]; }
}

// Review 5's encodings (``q3``/``q3b``): items of every kind, each handed to ``Good`` keyed on its hash.
contract Items {
    struct S { uint128 a; uint128 b; }
    Good public g; uint256 public x;
    S public s;
    uint256[2] public arr;
    bytes public bs = hex"11223344";
    bytes4 public b4 = 0x11223344;
    enum E { A, B, C2 }
    E public e = E.C2;
    function() external fp;
    int8 public n8 = -1; int128 public n128 = -2; int256 public n256 = -3;
    uint public u = 7;
    string public sigStr = "f(uint256)";
    address payable public pay = payable(address(0xBEEF));
    Sel public sel = Sel.wrap(0x11223344);
    function target() external {}
    constructor(Good z, bool seed) {
        g = z; s = S(1, 2); arr = [uint256(3), 4]; fp = this.target;
        uint256 rs; uint256 rb; uint256 rf;
        assembly { rs := sload(s.slot) rb := sload(bs.slot) rf := sload(fp.slot) }
        if (seed) {  // the true encodings: functions named f* pass
            z.set(keccak256(abi.encode(s)));
            z.set(keccak256(abi.encode(arr)));
            z.set(keccak256(abi.encode(bs)));
            z.set(keccak256(abi.encode(e)));
            z.set(keccak256(abi.encode(z)));
            z.set(keccak256(abi.encode(fp)));
            z.set(keccak256(abi.encode(n8)));
            z.set(keccak256(abi.encode(n128)));
            z.set(keccak256(abi.encode(n256)));
            z.set(keccak256(abi.encode(u)));
            z.set(keccak256(abi.encodeWithSignature(sigStr, uint256(1))));
            z.set(keccak256(abi.encode(bytes4(keccak256("fMsgSig()")))));
            z.set(keccak256(abi.encodePacked(bytes4(keccak256("fPackedSig()")), uint8(1))));
            z.set(keccak256(abi.encode(pay)));
            z.set(keccak256(abi.encode(sel)));
            z.set(keccak256(abi.encodeCall(I.k, (b4))));
        }
        // Encodings a lowering laying an item out wrongly would produce: w* never pass now.
        z.set(keccak256(abi.encode(rs)));
        z.set(keccak256(abi.encode(uint256(1))));
        z.set(keccak256(abi.encode(uint256(3))));
        z.set(keccak256(abi.encode(rb)));
        z.set(keccak256(abi.encode(uint256(0x11223344))));
        z.set(keccak256(abi.encode(rf)));
        z.set(keccak256(abi.encode(uint256(uint8(int8(-1))))));
        z.set(keccak256(abi.encode(uint256(uint128(int128(-2))))));
        z.set(keccak256(abi.encode(uint256(uint32(bytes4(keccak256("wMsgSig()")))))));
        z.set(keccak256(abi.encodePacked(uint256(uint32(bytes4(keccak256("wPackedSig()")))), uint8(1))));
        z.set(keccak256(abi.encode(uint256(uint32(bytes4(keccak256("wSlice()")))))));
        z.set(keccak256(abi.encode(bytes4(keccak256("wSlice()")))));
    }
    function fStruct() external { require(g.ok(abi.encode(s))); x = 1; }
    function fArr() external { require(g.ok(abi.encode(arr))); x = 1; }
    function fBytes() external { require(g.ok(abi.encode(bs))); x = 1; }
    function fEnum() external { require(g.ok(abi.encode(e))); x = 1; }
    function fContract() external { require(g.ok(abi.encode(g))); x = 1; }
    function fFn() external { require(g.ok(abi.encode(fp))); x = 1; }
    function fN8() external { require(g.ok(abi.encode(n8))); x = 1; }
    function fN128() external { require(g.ok(abi.encode(n128))); x = 1; }
    function fN256() external { require(g.ok(abi.encode(n256))); x = 1; }
    function fUint() external { require(g.ok(abi.encode(u))); x = 1; }
    function fSigStr() external { require(g.ok(abi.encodeWithSignature(sigStr, uint256(1)))); x = 1; }
    function fMsgSig() external { require(g.ok(abi.encode(msg.sig))); x = 1; }
    function fPackedSig() external { require(g.ok(abi.encodePacked(msg.sig, uint8(1)))); x = 1; }
    function fPay() external { require(g.ok(abi.encode(pay))); x = 1; }
    function fUdvt() external { require(g.ok(abi.encode(sel))); x = 1; }
    function fCall() external { require(g.ok(abi.encodeCall(I.k, (b4)))); x = 1; }
    function wMsgSig() external { require(g.ok(abi.encode(msg.sig))); x = 1; }
    function wPackedSig() external { require(g.ok(abi.encodePacked(uint256(uint32(msg.sig)), uint8(2)))); x = 1; }
    function wSlice() external { require(g.ok(abi.encode(msg.data[0:4]))); x = 1; }
    function wSliceB4() external { require(g.ok(abi.encode(bytes4(msg.data[0:4])))); x = 1; }
    function wN8neg(int8 v) external { require(v < 0); require(g.ok(abi.encode(v))); x = 1; }
}

contract Seeded is Items { constructor(Good z) Items(z, true) {} }
contract Unseeded is Items { constructor(Good z) Items(z, false) {} }
"""
FS = ["fStruct", "fArr", "fBytes", "fEnum", "fContract", "fFn", "fN8", "fN128", "fN256", "fUint", "fSigStr",
      "fMsgSig", "fPackedSig", "fPay", "fUdvt", "fCall"]  # fmt: skip
WS = ["wMsgSig", "wPackedSig", "wSlice", "wSliceB4", "wN8neg"]
# Items the lowering refuses, by the type it names.
REFUSED = {"fStruct": "Items.S", "fArr": "uint256[2]", "fBytes": "bytes", "fFn": "function()", "fSigStr": "string",
           "fUdvt": "Sel", "fCall": "encodeCall", "wSlice": "bytes"}  # fmt: skip


def _setup_items(d):
    d.deploy("Good")
    for name in ("Seeded", "Unseeded"):
        d.deploy(name, ("address",), (d.at["Good"],))


PROBES = [
    O.Probe(SOURCE, lambda d: (d.deploy("G"), d.deploy("C", ("address",), (d.at["G"],))),
            tuple(("C", n, f) for n in [*ONE_WORD, "dynamic"] for f in (("G",), ()))),
    O.Probe(ITEMS, _setup_items, tuple((c, n, f) for c in ("Seeded", "Unseeded") for n in FS + WS
                                       for f in (("Good",), ()))),
]  # fmt: skip


@pytest.fixture(scope="module")
def items(anvil):  # noqa: F811
    d = O.deployment(*anvil, ITEMS)
    _setup_items(d)
    return d


def _args(fn):
    return {p.name: -1 for p in fn.parameters}  # ``wN8neg``'s ``v < 0``


@pytest.mark.parametrize("others", [("Good",), ()], ids=["followed", "unfollowed"])
@pytest.mark.parametrize("contract", ["Seeded", "Unseeded"])
@pytest.mark.parametrize("name", FS + WS)
def test_every_kind_of_item_is_laid_out_as_the_chain_does_or_refused_by_name(items, contract, name, others):
    fn = O.function(items, contract, name)
    passing = O.strangers_passing(items, contract, fn, _args(fn))
    assert len(passing) == 1  # the same for every stranger
    v = O.verdict(items, contract, name, *others)
    O.check(items, contract, name, v, samples=(_args(fn),), open_at=_args(fn) if passing == {True} else False)
    if v.openness == "not_determined" and name in REFUSED:
        assert f"unknown:unsupported:abi_item:{REFUSED[name]}" in v.gaps, v
    if v.openness == "not_determined":
        assert "read_failed:condition" not in v.gaps, v


def test_an_item_of_unknown_type_is_refused():
    from services.logic.decide import UNK, Evaluator
    from services.logic.terms import mk

    # A word whose type nothing says (a storage read, here held at 3) is never laid out as a guess; given its declared
    # type, it is.
    word = mk("load", 1, "x")
    ev = Evaluator(SimpleNamespace(arranged={}, work=0), {}, {word: 3}, when=frozenset({word}))
    assert ev._encoded(mk("enc", "abi.encode", (word,))) is None
    assert ev._encoded(mk("enc", "abi.encode", (mk("conv", "bytes4", word),))) == (3).to_bytes(4, "big").ljust(
        32, b"\0"
    )
    assert ev._encoded(mk("enc", "abi.encode", (mk("conv", "int8", word),))) == (3).to_bytes(32, "big")
    assert ev._encoded_length(mk("enc", "abi.encode", (word,))) is UNK
