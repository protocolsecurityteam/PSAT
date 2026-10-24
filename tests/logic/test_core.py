"""Who may call is decided on the core: conjuncts no caller's identity reaches, left unknown only for what the
lowering couldn't express, are conditions on the call, reported as such (``allowed`` ``conditional``, a
``conditional:`` gap, never complete). Not when they read false now, a read failed, or the callee isn't followed: its
code may read ``tx.origin``, which is the caller's. Deployed on anvil (the hub never followed) and each verdict checked
against ``eth_call``."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

interface IHub {
    function math(uint256 x) external view returns (uint256);
    function check(address who) external view returns (bool);
    function pair(uint256 x, address who) external view returns (bool);
}

contract Hub {
    address admin;
    constructor(address a) { admin = a; }
    function math(uint256 x) external pure returns (uint256) { return x; }
    function check(address who) external view returns (bool) { return who == admin; }
    function pair(uint256 x, address who) external pure returns (bool) { return x == 7 && who != address(0); }
}

contract C {
    IHub hub;
    mapping(address => bool) roles;
    mapping(address => bool) blocked;
    address admin;
    bool paused;
    address[] admins;
    uint256 total;
    event Granted(address indexed who);

    constructor(IHub h, address[] memory list) { hub = h; admin = msg.sender; admins = list; }

    function grant(address who) external { require(msg.sender == admin); roles[who] = true; emit Granted(who); }
    function pause(bool p) external { require(msg.sender == admin); paused = p; }

    function gated(uint256 x) external { require(hub.math(x) > 0); require(roles[msg.sender]); }
    function screened(uint256 x) external { require(hub.math(x) > 0); require(!blocked[msg.sender]); total += x; }
    function free(uint256 x) external { require(hub.math(x) > 0); total += x; }
    function pausable(uint256 x) external { require(!paused); require(hub.math(x) > 0); total += x; }
    function handed() external { require(hub.check(msg.sender)); total += 1; }
    function paired(uint256 x) external { require(hub.pair(x, msg.sender)); total += x; }
    function screenedGas(uint256 x) external { require(gasleft() > x); require(!blocked[msg.sender]); total += x; }
    function pausableGas(uint256 x) external { require(!paused); require(gasleft() > x); total += x; }
    function listedFixed() external {
        bool ok;
        for (uint256 i; i < admins.length; i++) { if (admins[i] == msg.sender) ok = true; }
        require(ok);
        require(hub.math(5) > 0);
    }
    function listed(uint256 x) external {
        bool ok;
        for (uint256 i; i < admins.length; i++) { if (admins[i] == msg.sender) ok = true; }
        require(ok);
        require(hub.math(x) > 0);
    }
}
"""
HOLDERS = set(O.ACCOUNTS[1:3])
# More entries than a loop over the list is followed exactly.
ADMINS = [O.ACCOUNTS[3], 0xAD1 << 148, 0xAD2 << 148, 0xAD3 << 148, 0xAD4 << 148]


def _setup(d):
    d.deploy("Hub", ("address",), (O.OWNER,))
    d.deploy("C", ("address", "address[]"), (d.at["Hub"], [O.hex20(a) for a in ADMINS]))
    for h in sorted(HOLDERS):
        assert O.transact(d, "C", "grant(address)", ("address",), (h,))


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        tuple(
            ("C", f, ())
            for f in (
                "gated",
                "screened",
                "free",
                "handed",
                "paired",
                "screenedGas",
                "pausableGas",
                "listedFixed",
                "listed",
            )
        ),  # fmt: skip
    )
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def test_a_role_beside_an_unfollowed_call_lists_its_holders_on_that_condition(d):
    v = O.check(d, "C", "gated", O.verdict(d, "C", "gated"), samples=({"x": 1}, {"x": 0}))
    assert v.openness == "restricted" and v.complete
    assert set(v.principals) | set(v.conditions) == HOLDERS
    gated = O.function(d, "C", "gated")
    assert all(O.passes(d, "C", gated, {"x": 1}, sender=h) for h in HOLDERS)


@pytest.mark.parametrize("name", ["free", "screened"])
def test_an_unfollowed_callee_is_never_set_aside(d, name):
    # Its code may read tx.origin, the caller's: the conjunct may single someone out.
    v = O.check(d, "C", name, O.verdict(d, "C", name))
    assert O.strangers_passing(d, "C", O.function(d, "C", name), {"x": 1}) == {True}
    O.sound(v, anyone=True)
    if v.openness != "open":
        assert v.openness == "not_determined" and "unfollowed:math(uint256)" in v.gaps


def test_a_screen_beside_an_unknown_is_open_only_on_it(d):
    # ``gasleft() > x`` is unknown to the lowering; every stranger's own call with a small ``x`` goes through.
    v = O.check(d, "C", "screenedGas", O.verdict(d, "C", "screenedGas"), open_at={"x": 1})
    if v.allowed != "now":
        assert v.allowed == "conditional" and not v.complete
        assert "conditional:unknown:gasleft()" in v.gaps


def test_a_pause_still_holds_everyone_back_now(d):
    with O.snapshot(d):
        assert O.transact(d, "C", "pause(bool)", ("bool",), (True,))
        v = O.check(d, "C", "pausableGas", O.verdict(d, "C", "pausableGas"), open_at=False, samples=({"x": 1},))
        assert v.openness == "open" and v.allowed in ("later", "later_conditional")
        assert O.transact(d, "C", "pause(bool)", ("bool",), (False,))
        assert O.strangers_passing(d, "C", O.function(d, "C", "pausableGas"), {"x": 1}) == {True}


def test_a_call_handed_the_caller_stays_undecided(d):
    clean = O.check(d, "C", "handed", O.verdict(d, "C", "handed"))
    v = O.verdict(d, "C", "handed", chain=O.Faulty(d, calls={d.at["Hub"]}))
    assert v.openness == "not_determined"
    assert f"call:check(address):arg0@0x{d.at['Hub']:040x}" in v.gaps
    O.never_bolder(clean, v)


def test_the_gap_names_the_argument_the_caller_reaches(d):
    v = O.check(d, "C", "paired", O.verdict(d, "C", "paired"))
    O.sound(v, anyone=True)  # x = 7 lets anyone through
    if v.openness != "open":
        assert v.openness == "not_determined"
        assert f"call:pair(uint256,address):arg1@0x{d.at['Hub']:040x}" in v.gaps


def test_an_unknown_that_may_hide_the_caller_still_blocks(d):
    v = O.check(d, "C", "listed", O.verdict(d, "C", "listed"), samples=({"x": 1},), open_at=False)
    O.sound(v, set(ADMINS))
    assert v.openness == "not_determined"
    assert any(g.startswith("unknown:loop:") for g in v.gaps)
    listed = O.function(d, "C", "listed")
    assert all(O.passes(d, "C", listed, {"x": 1}, sender=a) for a in ADMINS)


def test_a_failed_read_in_a_condition_stays_a_gap(d):
    clean = O.verdict(d, "C", "listedFixed")
    v = O.verdict(d, "C", "listedFixed", chain=O.Faulty(d, calls={d.at["Hub"]}))
    assert v.openness == "not_determined"
    assert "read_failed:call:math(uint256)" in v.gaps
    O.never_bolder(clean, v)
