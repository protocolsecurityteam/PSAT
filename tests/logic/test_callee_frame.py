"""A followed callee runs in its own call frame: its ``msg.value`` is what the call carries (nothing, for a view call),
its ``msg.data`` and ``msg.sig`` are its own, and its ``msg.sender`` is whoever makes the call, a callee one level up
included. Its code may rank and skip the guesses a search makes, never prove one passes on its own: a pass resting on
it is asked again of the chain. A guess failing a conjunct rules out the guesses agreeing on what its evaluation read,
and ``msg.data`` reads every argument. Each verdict is checked against ``eth_call`` on anvil (``_oracle.check``): an
open one passes for every stranger, a listed holder from its own address, a refusal for no stranger."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

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
contract W { function who() external view returns (address) { return msg.sender; } }
contract F {
    W public w;
    constructor(W x) { w = x; }
    // W answers each asker with itself: only F asking gets F back.
    function ok(uint256 v) external view returns (bool) { return w.who() == address(this) && v == 4; }
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
    F public f;
    function setF(F z) external { f = z; }
    // E asks D, whose answer is the same whoever asks: asked of the chain as this contract.
    function asked(uint256 v) external { require(e.ok(v)); x = v; }
    // F asks W, whose answer is who asks: asked of the chain as F. Anyone passing v = 4.
    function askedBy(uint256 v) external { require(f.ok(v)); x = v; }
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


EVERY = ("A", "B", "V", "S", "Checker", "Strict", "E", "D", "W", "F")


def _setup(d):
    d.deploy("B")
    d.deploy("A", ("address",), (d.at["B"],))
    for name in ("V", "S", "Checker", "Strict", "Lax", "D"):
        d.deploy(name)
    d.deploy("E", ("address",), (d.at["D"],))
    d.deploy("W")
    d.deploy("F", ("address",), (d.at["W"],))
    d.deploy("C", ("address",) * 6, tuple(d.at[n] for n in ("A", "V", "S", "Checker", "Strict", "E")))
    assert O.transact(d, "B", "setA(address)", ("address",), (d.at["A"],))
    assert O.transact(d, "C", "setF(address)", ("address",), (d.at["F"],))


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        tuple(
            ("C", f, EVERY)
            for f in ("asked", "askedBy", "nested", "paid", "selector", "forwarded", "confirmed", "words")
        ),  # fmt: skip
    )
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _verdict(d, name):
    return O.verdict(d, "C", name, *EVERY)


def test_a_callee_of_a_callee_sees_the_callee_asking_as_its_sender(d):
    v = O.check(d, "C", "nested", _verdict(d, "nested"), open_at={"v": 7})
    assert list(v.witnesses.values())[0].get("v") == 7


def test_a_view_callee_reads_no_value_whatever_the_outer_call_carries(d):
    # Read with the outer call's value, ``vv.ok(v)`` would let a stranger paying v through. That it never does over
    # any v only V's code shows, which never refutes on its own (``test_callee_refutation``): the owner, not complete.
    paying = [{"v": n, "msg.value": n} for n in (1, 5)]
    v = O.check(d, "C", "paid", _verdict(d, "paid"), samples=[{"v": 0}, *paying], open_at=False)
    assert v.openness != "open" and O.OWNER in v.principals
    assert not v.complete and "callee_code_refutation" in v.gaps


def test_a_callee_reads_its_own_selector(d):
    v = O.check(d, "C", "selector", _verdict(d, "selector"), open_at={"v": 5})
    assert list(v.witnesses.values())[0].get("v") == 5


def test_a_failed_guess_rules_out_only_the_guesses_agreeing_on_what_it_read(d):
    # b = 9 fails the forwarded check, which reads the whole call data: b = 10 must still be tried.
    v = O.check(d, "C", "forwarded", _verdict(d, "forwarded"), open_at={"a1": 0, "b": 10})
    assert list(v.witnesses.values())[0].get("b") == 10
    assert O.strangers_passing(d, "C", O.function(d, "C", "forwarded"), {"a1": 0, "b": 9}) == {False}


def test_a_word_of_the_call_data_inside_the_arguments_is_what_they_encode(d):
    samples = [{"a1": a, "b": 8} for a in (8, 9, 0, 1)]
    v = O.check(d, "C", "words", _verdict(d, "words"), samples=samples, open_at=False)
    assert v.openness != "open"


@pytest.mark.parametrize(("name", "v"), [("asked", 14), ("askedBy", 4)])
def test_a_callee_answering_alike_for_every_asker_is_asked_as_this_contract(d, name, v):
    # D's code never reads who asks: E's call to it is asked as this contract. W's answer is who asks: F's call to it
    # is asked as F. Either way the chain's answer: v = 14, v = 4 pass.
    verdict = O.check(d, "C", name, _verdict(d, name), open_at={"v": v})
    assert list(verdict.witnesses.values())[0].get("v") == v


def test_a_pass_resting_on_callee_code_is_asked_of_the_chain(d):
    # The code believed to sit at ``strict`` is ``Lax``'s, which lets v = 3 through; what is deployed there
    # (``Strict``) never does. A pass resting on the believed code is asked of the chain: only the owner passes.
    from services.logic.terms import reset_terms
    from services.logic.verdict import function_verdict

    reset_terms()
    known = {d.at[n]: d.slither[n] for n in ("C", *EVERY)}
    known[d.at["Strict"]] = d.slither["Lax"]
    c = d.slither["C"]
    v = function_verdict(c, O.function(d, "C", "confirmed"), d.at["C"], d.chain(), known)[0]
    O.check(d, "C", "confirmed", v, samples=[{"v": 3}, {"v": 0}], open_at=False)
    assert v.openness != "open", v
    assert O.strangers_passing(d, "C", O.function(d, "C", "confirmed"), {"v": 3}) == {False}


def test_a_callee_that_never_returns_true_lets_only_the_owner_through(d):
    v = O.check(d, "C", "confirmed", _verdict(d, "confirmed"), samples=[{"v": 3}, {"v": 0}], open_at=False)
    O.sound(v, {O.OWNER})
