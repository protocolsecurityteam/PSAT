""" "Nobody, ever" (restricted, complete, nobody listed) only where what refutes everyone reads nothing a transaction
may change: a business condition mixing the arguments with state (``amount >= lo && amount <= hi``, ``lo > hi``
now, both owner-settable) blocks everyone only as things stand. With such conditions set aside, whoever the identity
core lets through is named, holding only on them (``conditions``, ``allowed`` conditional); with no core, not
determined. Each variable is named, ``state_blocks_everyone:<variable>``. A condition on constants or a variable no
entry point writes still refutes everyone. Against anvil."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

from services.logic.terms import reset_terms
from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import ACCOUNT0, rpc

SOURCE = """
pragma solidity 0.8.27;

contract C {
    uint256 public lo = 10;
    uint256 public hi = 5;
    uint256 public fixedLo = 10;  // set at deployment, written by no entry point
    uint256 public constant HI = 5;
    address public owner;
    uint256 public x;
    bool public paused = true;
    constructor() { owner = msg.sender; }
    function setRange(uint256 l, uint256 h) external { require(msg.sender == owner); lo = l; hi = h; }
    function setPaused(bool p) external { require(msg.sender == owner); paused = p; }
    function act(uint256 amount) external { require(amount >= lo && amount <= hi); x = amount; }
    function actOwner(uint256 amount) external { require(amount >= lo && amount <= hi && msg.sender == owner); x = 1; }
    function actConstant(uint256 amount) external { require(amount >= 10 && amount <= HI); x = amount; }
    function actFixed(uint256 amount) external { require(amount >= fixedLo && amount <= HI); x = amount; }
    function paus(uint256 amount) external { require(!paused); x = amount; }
}
"""

OWNER = int(ACCOUNT0, 16)


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("C")
    return d


def _verdict(d, name):
    reset_terms()
    c = d.slither["C"]
    fn = next(f for f in c.functions_entry_points if f.name == name)
    return function_verdict(c, fn, d.at["C"], d.chain(), d.contracts("C"))[0]


def _passes(d, name, amount, sender="0x" + "00" * 19 + "aa") -> bool:
    data = "0x" + (keccak(text=f"{name}(uint256)")[:4] + encode(["uint256"], [amount])).hex()
    try:
        rpc(d.url, "eth_call", [{"from": sender, "to": "0x%040x" % d.at["C"], "data": data}, "latest"])
        return True
    except RuntimeError:
        return False


def test_a_business_condition_on_settable_state_blocks_everyone_only_as_things_stand(d):
    assert not any(_passes(d, "act", a) for a in (0, 5, 7, 10))
    verdict = _verdict(d, "act")
    assert verdict.openness == "not_determined" and not verdict.complete
    assert {"state_blocks_everyone:lo", "state_blocks_everyone:hi"} <= set(verdict.gaps)


def test_an_identity_core_behind_such_a_condition_names_its_holders_on_it(d):
    assert not any(_passes(d, "actOwner", a, sender=ACCOUNT0) for a in (0, 5, 7, 10))
    verdict = _verdict(d, "actOwner")
    assert verdict.openness == "restricted" and not verdict.complete
    assert verdict.conditions == {OWNER: "business"} and verdict.allowed == "conditional"
    assert {"state_blocks_everyone:lo", "state_blocks_everyone:hi"} <= set(verdict.gaps)


@pytest.mark.parametrize("name", ["actConstant", "actFixed"])
def test_a_condition_on_what_never_changes_still_refutes_everyone(d, name):
    verdict = _verdict(d, name)
    assert verdict.openness == "restricted" and verdict.complete and not verdict.principals, verdict
    assert not any(g.startswith("state_blocks_everyone") for g in verdict.gaps)


def test_a_pause_is_open_once_it_allows(d):
    verdict = _verdict(d, "paus")
    assert verdict.openness == "open" and verdict.allowed == "later"
