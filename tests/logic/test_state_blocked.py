""" "Nobody, ever" (restricted, complete, nobody listed) only where what refutes everyone reads nothing a transaction
may change: a business condition mixing the arguments with state (``amount >= lo && amount <= hi``, ``lo > hi``
now, both owner-settable) blocks everyone only as things stand. With such conditions set aside, whoever the identity
core lets through is named, holding only on them (``conditions``, ``allowed`` conditional); with no core, not
determined. Each variable is named, ``state_blocks_everyone:<variable>``. A condition on constants or a variable no
entry point writes still refutes everyone. Against anvil."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

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

OWNER = O.OWNER
AMOUNTS = [{"amount": a} for a in (0, 5, 7, 10, 50)]


def _setup(d):
    d.deploy("C")


PROBES = [O.Probe(SOURCE, _setup, tuple(("C", f, ()) for f in ("act", "actOwner", "actConstant", "actFixed", "paus")))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _set_range(d):
    assert O.transact(d, "C", "setRange(uint256,uint256)", ("uint256", "uint256"), (0, 100))


def test_a_business_condition_on_settable_state_blocks_everyone_only_as_things_stand(d):
    v = O.check(d, "C", "act", O.verdict(d, "C", "act"), samples=AMOUNTS, open_at=False)
    assert not O.nobody(v), v
    with O.snapshot(d):  # the owner widens the range: every stranger passes
        _set_range(d)
        assert O.strangers_passing(d, "C", O.function(d, "C", "act"), {"amount": 50}) == {True}
    if v.openness == "not_determined":
        assert {"state_blocks_everyone:lo", "state_blocks_everyone:hi"} <= set(v.gaps)


def test_an_identity_core_behind_such_a_condition_names_its_holders_on_it(d):
    v = O.check(d, "C", "actOwner", O.verdict(d, "C", "actOwner"), samples=AMOUNTS, open_at=False)
    O.sound(v, {OWNER})
    assert not O.nobody(v), v
    act_owner = O.function(d, "C", "actOwner")
    with O.snapshot(d):  # the owner widens the range: the owner passes, no stranger does
        _set_range(d)
        assert O.passes(d, "C", act_owner, {"amount": 50}, sender=OWNER)
        assert O.strangers_passing(d, "C", act_owner, {"amount": 50}) == {False}
    if v.conditions:
        assert v.conditions == {OWNER: "business"} and v.allowed == "conditional"


@pytest.mark.parametrize("name", ["actConstant", "actFixed"])
def test_a_condition_on_what_never_changes_still_refutes_everyone(d, name):
    v = O.check(d, "C", name, O.verdict(d, "C", name), samples=AMOUNTS)
    assert O.nobody(v), v
    assert not any(g.startswith("state_blocks_everyone") for g in v.gaps)
    with O.snapshot(d):  # what the owner may set changes nothing here
        _set_range(d)
        for amount in AMOUNTS:
            assert O.strangers_passing(d, "C", O.function(d, "C", name), amount) == {False}


def test_a_pause_is_open_once_it_allows(d):
    v = O.check(d, "C", "paus", O.verdict(d, "C", "paus"), open_at=False, samples=AMOUNTS)
    assert v.openness == "open" and v.allowed == "later"
    with O.snapshot(d):
        assert O.transact(d, "C", "setPaused(bool)", ("bool",), (False,))
        assert O.strangers_passing(d, "C", O.function(d, "C", "paus"), {"amount": 1}) == {True}
