""" "Open" from the chain's own runs of the call needs every stranger to pass, as ``_strangers_pass`` does on the
engine's side: one stranger's call going through proves little where the caller's address, or the origin a callee
reads, feeds arithmetic. A callee checking the origin's low bit lets half the strangers through: never "open", not
determined and named ``strangers_differ``; one every stranger passes is open. Each probe is checked against
``eth_call`` on anvil from strangers with different low bits."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

from services.logic.decide import _STRANGERS
from services.logic.terms import reset_terms
from services.logic.verdict import function_verdict
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """
pragma solidity 0.8.27;

contract G {
    function lowbits() external view returns (bool) { return uint160(tx.origin) % 2 == 1; }
    function lowcaller(address who) external pure returns (bool) { return uint160(who) % 2 == 1; }
    function anyOrigin() external view returns (bool) { return tx.origin != address(0); }
    function anyCaller(address who) external pure returns (bool) { return who != address(0); }
}
contract H {
    function check(address who, uint256 junk) external pure returns (bool) { junk; return uint160(who) % 2 == 1; }
    function checkAll(address who, uint256 junk) external pure returns (bool) { junk; return who != address(0); }
}
// Review 5 (``q1b``): the callee is also handed what no evaluation knows (the gas left, a block hash), so the
// engine's own search leaves it, and only the strangers' own runs can settle it.
contract K {
    H public h; uint256 public x;
    constructor(H z) { h = z; }
    function bitGas(uint256 v) external { require(h.check(msg.sender, gasleft())); x = v; }
    function allGas(uint256 v) external { require(h.checkAll(msg.sender, gasleft())); x = v; }
    function bitHash(uint256 v) external { require(h.check(msg.sender, _hash())); x = v; }
    function allHash(uint256 v) external { require(h.checkAll(msg.sender, _hash())); x = v; }
    function _hash() internal view returns (uint256) { return uint256(blockhash(block.number - 1)); }
}
contract C {
    G public g;
    uint256 public x;
    constructor(G z) { g = z; }
    function originBit(uint256 v) external { require(g.lowbits()); x = v; }
    function callerBit(uint256 v) external { require(g.lowcaller(msg.sender)); x = v; }
    function originAll(uint256 v) external { require(g.anyOrigin()); x = v; }
    function callerAll(uint256 v) external { require(g.anyCaller(msg.sender)); x = v; }
}
"""


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _setup(d):
    d.deploy("G")
    d.deploy("C", ("address",), (d.at["G"],))
    d.deploy("H")
    d.deploy("K", ("address",), (d.at["H"],))


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        tuple(("C", n, f) for n in ("originBit", "callerBit", "originAll", "callerAll") for f in (("G",), ()))
        + tuple(("K", n, f) for n in ("bitGas", "allGas", "bitHash", "allHash") for f in (("H",), ())),
    )
]


def _verdict(d, name, *others):
    reset_terms()
    c = d.slither["C"]
    fn = next(f for f in c.functions_entry_points if f.name == name)
    return function_verdict(c, fn, d.at["C"], d.chain(), d.contracts("C", *others))[0]


def _passing(d, name) -> set[bool]:
    data = "0x" + (keccak(text=f"{name}(uint256)")[:4] + encode(["uint256"], [1])).hex()
    outcomes = set()
    for who in _STRANGERS:
        try:
            rpc(d.url, "eth_call", [{"from": "0x%040x" % who, "to": "0x%040x" % d.at["C"], "data": data}, "latest"])
            outcomes.add(True)
        except RuntimeError:
            outcomes.add(False)
    return outcomes


@pytest.mark.parametrize("others", [("G",), ()], ids=["followed", "unfollowed"])
@pytest.mark.parametrize("name", ["originBit", "callerBit"])
def test_strangers_the_chain_treats_differently_never_make_it_open(d, name, others):
    assert _passing(d, name) == {True, False}
    verdict = _verdict(d, name, *others)
    assert verdict.openness != "open" and not verdict.complete, verdict
    if verdict.openness == "not_determined":
        assert verdict.gaps, verdict


@pytest.mark.parametrize("others", [("G",), ()], ids=["followed", "unfollowed"])
@pytest.mark.parametrize("name", ["originBit", "callerBit"])
def test_a_pass_only_some_strangers_get_is_named(d, name, others):
    verdict = _verdict(d, name, *others)
    if (name, others) != ("callerBit", ("G",)):  # there the engine's own search already leaves it unsolved
        assert "strangers_differ" in verdict.gaps, verdict


@pytest.mark.parametrize("others", [("G",), ()], ids=["followed", "unfollowed"])
@pytest.mark.parametrize("name", ["originAll", "callerAll"])
def test_a_pass_every_stranger_gets_is_open(d, name, others):
    assert _passing(d, name) == {True}
    verdict = _verdict(d, name, *others)
    assert verdict.openness == "open" and verdict.allowed == "now", verdict


def test_an_inlined_callee_s_open_proposal_needs_every_stranger_on_the_chain(d, monkeypatch):
    # The inlined origin check proposes "open" (forced here, as a mis-lowered callee would): the chain runs the call
    # from each stranger, and half of them revert, so it is never taken.
    import services.logic.verdict as verdict_module
    from services.logic.decide import FRESH, Verdict
    from services.logic.terms import contains

    real = verdict_module.decide
    proposed = []

    def proposing(formula, world, coverage):
        result = real(formula, world, coverage)
        if contains(formula, frozenset({"origin"})) and result.openness != "open":
            proposed.append(formula)
            return Verdict("open", frozenset(), True, witnesses={FRESH: {"v": 1}})
        return result

    monkeypatch.setattr(verdict_module, "decide", proposing)
    verdict = _verdict(d, "originBit", "G")
    assert verdict.openness != "open", verdict
    assert proposed, "the inlined formula was never decided"
    assert any(g.startswith("inlined_callee:") for g in verdict.gaps), verdict


@pytest.mark.parametrize("others", [("H",), ()], ids=["followed", "unfollowed"])
@pytest.mark.parametrize("name", ["bitGas", "allGas", "bitHash", "allHash"])
def test_strangers_runs_settle_open_only_when_every_one_passes(d, name, others):
    fn = O.function(d, "K", name)
    every = O.strangers_passing(d, "K", fn, {"v": 1}) == {True}
    assert every == name.startswith("all")
    v = O.check(d, "K", name, O.verdict(d, "K", name, *others), open_at={"v": 1} if every else False)
    if not every:
        assert v.openness != "open" and "strangers_differ" in v.gaps, v
