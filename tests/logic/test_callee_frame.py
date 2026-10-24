"""A followed callee runs in its own call frame: its ``msg.value`` is what the call carries (nothing, for a view call),
its ``msg.data`` and ``msg.sig`` are its own, and its ``msg.sender`` is whoever makes the call, a callee one level up
included. Its code may rank and skip the guesses a search makes, never prove one passes on its own: a pass resting on
it is asked again of the chain. A guess failing a conjunct rules out the guesses agreeing on what its evaluation read,
and ``msg.data`` reads every argument."""

from __future__ import annotations

import os

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

os.environ["PSAT_LOGIC_STRICT_GAPS"] = "1"
from services.logic.terms import reset_terms  # noqa: E402
from services.logic.verdict import function_verdict  # noqa: E402
from tests.logic._anvil import Deployment, anvil  # noqa: E402,F401
from tests.support.anvil import ACCOUNT0  # noqa: E402

SOURCE = """
pragma solidity 0.8.27;

contract B {
    address public a;
    function setA(address x) external { a = x; }
    // Only A may ask: inside B, msg.sender is A, the contract calling it.
    function check(uint256 v) external view returns (bool) { require(msg.sender == a); return v == 7; }
}
contract A {
    B public b;
    constructor(B x) { b = x; }
    function ok(uint256 v) external view returns (bool) { return b.check(v); }
}
contract V {
    function ok(uint256 v) external view returns (bool) { return _value() == v && v > 0; }
    function _value() internal view returns (uint256) { return msg.value; }
}
contract S {
    // Its own selector, whatever function of the caller's asks.
    function own(uint256 v) external pure returns (bool) { return msg.sig == this.own.selector && v == 5; }
}
contract Checker {
    // The second argument's low byte, in the call data it is handed, must be 10.
    function allowed(bytes calldata data) external pure returns (bool) {
        return data.length >= 68 && uint8(data[67]) == 10;
    }
}
contract D { function val(uint256 v) external pure returns (uint256) { return v * 2; } }
contract E {
    D public d;
    constructor(D x) { d = x; }
    function ok(uint256 v) external view returns (bool) { return d.val(7) == v; }
}
contract Strict { function ok(uint256 v) external pure returns (bool) { return v == 3 && false; } }
contract Lax { function ok(uint256 v) external pure returns (bool) { return v == 3; } }
contract C {
    A public a;
    V public vv;
    S public s;
    Checker public checker;
    Strict public strict;
    E public e;
    address public owner;
    uint256 public x;
    constructor(A y, V z, S w, Checker k, Strict t, E u) {
        (a, vv, s, checker, strict, e, owner) = (y, z, w, k, t, u, msg.sender);
    }
    // E asks D, whose answer is the same whoever asks: asked of the chain as this contract.
    function asked(uint256 v) external { require(e.ok(v)); x = v; }
    // Anyone passing v = 7 gets through: A asks B, which lets A ask.
    function nested(uint256 v) external { require(a.ok(v)); x = v; }
    // V.ok is false under every staticcall (msg.value is 0 there): only the owner passes.
    function paid(uint256 v) external payable {
        require(msg.value == v);
        require(vv.ok(v) || msg.sender == owner);
        x = v;
    }
    // S checks its own selector, never this function's: anyone passing v = 5.
    function selector(uint256 v) external { require(s.own(v)); x = v; }
    function forwarded(uint256 a1, uint256 b) external {
        require(b == 9 || b == 10);
        require(checker.allowed(msg.data));
        x = a1;
    }
    // Strict.ok never returns true: only the owner passes, whatever code is believed to sit at ``strict``.
    function confirmed(uint256 v) external { require(strict.ok(v) || msg.sender == owner); x = v; }
    // The word read is the first argument when it is even, the second when odd: never 9 with b = 8.
    function words(uint256 a1, uint256 b) external {
        uint256 w;
        assembly { w := calldataload(add(4, mul(mod(a1, 2), 32))) }
        require(w == 9 && b == 8);
        x = a1;
    }
}
"""


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("B")
    d.deploy("A", ("address",), (d.at["B"],))
    for name in ("V", "S", "Checker", "Strict", "Lax", "D"):
        d.deploy(name)
    d.deploy("E", ("address",), (d.at["D"],))
    d.deploy(
        "C",
        ("address",) * 6,
        tuple(d.at[n] for n in ("A", "V", "S", "Checker", "Strict", "E")),
    )
    d.send("B", "0x" + (keccak(text="setA(address)")[:4] + encode(["address"], ["0x%040x" % d.at["A"]])).hex())
    return d


def _verdict(d, name, contracts=None, chain=None):
    reset_terms()
    c = d.slither["C"]
    fn = next(f for f in c.functions_entry_points if f.name == name)
    known = contracts if contracts is not None else d.contracts("C", "A", "B", "V", "S", "Checker", "Strict", "E", "D")
    return function_verdict(c, fn, d.at["C"], chain or d.chain(), known)[0]


def test_a_callee_of_a_callee_sees_the_callee_asking_as_its_sender(d):
    verdict = _verdict(d, "nested")
    assert verdict.openness == "open", verdict
    assert list(verdict.witnesses.values())[0].get("v") == 7


def test_a_view_callee_reads_no_value_whatever_the_outer_call_carries(d):
    # Read with the outer call's value, ``vv.ok(v)`` would let a stranger paying v through. That it never does over
    # any v only V's code shows, which never refutes on its own (``test_callee_refutation``): the owner, not complete.
    verdict = _verdict(d, "paid")
    assert verdict.openness != "open", verdict
    assert int(ACCOUNT0, 16) in verdict.principals
    assert not verdict.complete and "callee_code_refutation" in verdict.gaps


def test_a_callee_reads_its_own_selector(d):
    verdict = _verdict(d, "selector")
    assert verdict.openness == "open", verdict
    assert list(verdict.witnesses.values())[0].get("v") == 5


def test_a_failed_guess_rules_out_only_the_guesses_agreeing_on_what_it_read(d):
    # b = 9 fails the forwarded check, which reads the whole call data: b = 10 must still be tried.
    verdict = _verdict(d, "forwarded")
    assert verdict.openness == "open", verdict
    assert list(verdict.witnesses.values())[0].get("b") == 10


def test_a_pass_resting_on_callee_code_is_asked_of_the_chain(d):
    # The code believed to be at ``strict`` (Lax) lets v = 3 through; what is deployed there never does.
    known = d.contracts("C")
    known[d.at["Strict"]] = d.slither["Lax"]
    verdict = _verdict(d, "confirmed", known)
    assert verdict.openness != "open", verdict


def test_a_word_of_the_call_data_inside_the_arguments_is_what_they_encode(d):
    verdict = _verdict(d, "words")
    assert verdict.openness != "open", verdict


def test_a_callee_answering_alike_for_every_asker_is_asked_as_this_contract(d):
    # D's code never reads who asks: E's call to it goes to the chain from this contract, an answer already shared.
    chain = d.chain()
    verdict = _verdict(d, "asked", chain=chain)
    assert verdict.openness == "open" and list(verdict.witnesses.values())[0].get("v") == 14
    senders = {key[3] for key in chain._memo if isinstance(key, tuple) and key[:1] == ("c",)}
    assert senders == {d.at["C"]}
