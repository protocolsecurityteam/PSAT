"""A followed callee's code never refutes on its own (``Evaluator.truth``, ``solve``): a failure or an unsatisfiable
question resting on a callee's code standing in for a call is asked again without it, each view call a value tied to
what the chain answers at the inputs the models reach. What still fails was refuted by the chain; a model the chain's
answers agree with is a pass; anything else is unknown, named ``callee_code_refutation``, never complete. So however a
callee is mis-lowered, the verdict is never a confident list missing a stranger the chain lets through. Each probe
lowers the callee wrongly on purpose (its code read as "nobody") and checks the verdict against ``eth_call`` on
anvil."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

from services.logic.lower import Lowerer
from services.logic.terms import FALSE, TRUE, reset_terms
from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import ACCOUNT0, rpc

SOURCE = """
pragma solidity 0.8.27;

contract L {
    function ok(uint256 v) external pure returns (bool) { return v == 3; }
    function pick(uint256 w) external pure returns (bool) { return w == 1; }
    function never(uint256 w) external pure returns (bool) { w; return false; }
}
contract C {
    L public l;
    address public owner;
    uint256 public x;
    constructor(L z) { l = z; owner = msg.sender; }
    // A stranger passing v = 3 gets through.
    function any(uint256 v) external { require(l.ok(v) || msg.sender == owner); x = v; }
    // A stranger passing v > 5 gets through: the call's input is 1 or 2, whatever v is.
    function picked(uint256 v) external { require(l.pick(v > 5 ? 1 : 2) || msg.sender == owner); x = v; }
    // Only the owner: the call fails at both inputs it can be handed.
    function none(uint256 v) external { require(l.never(v > 5 ? 1 : 2) || msg.sender == owner); x = v; }
}
"""

STRANGER = "0x" + "00" * 19 + "aa"


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("L")
    d.deploy("C", ("address",), (d.at["L"],))
    return d


@pytest.fixture
def wrong(monkeypatch):
    """L's code lowered as "nobody": returns false, whatever it is handed."""
    called = Lowerer.called

    def misread(self, function, args, view):
        if getattr(getattr(function, "contract", None), "name", None) == "L":
            return TRUE, (FALSE,)
        return called(self, function, args, view)

    monkeypatch.setattr(Lowerer, "called", misread)


def _verdict(d, name):
    reset_terms()
    c = d.slither["C"]
    fn = next(f for f in c.functions_entry_points if f.name == name)
    return function_verdict(c, fn, d.at["C"], d.chain(), d.contracts("C", "L"))[0]


def _passes(d, name, v, sender=STRANGER) -> bool:
    data = "0x" + (keccak(text=f"{name}(uint256)")[:4] + encode(["uint256"], [v])).hex()
    try:
        rpc(d.url, "eth_call", [{"from": sender, "to": "0x%040x" % d.at["C"], "data": data}, "latest"])
        return True
    except RuntimeError:
        return False


def test_a_mis_lowered_callee_never_makes_a_confident_list_missing_a_stranger(d, wrong):
    assert _passes(d, "any", 3)
    verdict = _verdict(d, "any")
    assert not (verdict.openness == "restricted" and verdict.complete), verdict
    if verdict.openness != "open":
        assert "callee_code_refutation" in verdict.gaps
        assert int(ACCOUNT0, 16) in verdict.principals


def test_a_mis_lowered_callee_s_refusal_the_chain_contradicts_is_a_pass(d, wrong):
    # The call's input is 1 or 2 whatever v is: the chain answers both, and v > 5 passes.
    assert _passes(d, "picked", 6)
    verdict = _verdict(d, "picked")
    assert verdict.openness == "open", verdict
    assert list(verdict.witnesses.values())[0]["v"] > 5


@pytest.mark.parametrize("misread", [False, True])
def test_a_refusal_the_chain_answers_at_every_input_is_complete(d, monkeypatch, misread):
    if misread:
        called = Lowerer.called
        monkeypatch.setattr(
            Lowerer,
            "called",
            lambda self, function, args, view: (
                (TRUE, (FALSE,)) if function.contract.name == "L" else called(self, function, args, view)
            ),
        )
    assert not any(_passes(d, "none", v) for v in (0, 6))
    verdict = _verdict(d, "none")
    assert verdict.openness == "restricted" and verdict.complete, verdict
    assert verdict.principals == {int(ACCOUNT0, 16)}
