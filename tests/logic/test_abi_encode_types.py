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
    verdict = _verdict(d, "dynamic", *others)
    assert verdict.openness == "not_determined" and not verdict.complete and verdict.gaps, verdict


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
