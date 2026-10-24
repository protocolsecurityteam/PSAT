"""Where the core still holds what the lowering couldn't express, one call run as a fresh address settles it when it
goes through (a success proves the function open); one that fails proves nothing and changes nothing. Checked on
anvil: every stranger passes ``spin``; ``admin`` passes for exactly the five admins."""

from __future__ import annotations

import pytest

from services.logic.decide import FRESH
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract Loopy {
    address[] admins;
    uint256 rounds;
    uint256 total;

    constructor(address[] memory initial) {
        admins = initial;
        rounds = 5;
    }

    // Widened past two iterations, and the caller's address feeds every one: open, though the engine can't say.
    function spin() external {
        uint256 s;
        for (uint256 i; i < rounds; i++) { s += uint256(uint160(msg.sender)) % 2 + 1; }
        require(s > 0);
        total += s;
    }

    // The same loop, an admin list in it: a stranger's call reverts.
    function admin() external {
        bool ok;
        for (uint256 i; i < admins.length; i++) { if (admins[i] == msg.sender) ok = true; }
        require(ok);
        total += 1;
    }
}
"""

ADMINS = [0xC3 << 140, 0xD4 << 140, 0xE5 << 140, 0xF6 << 140, 0xA7 << 140]  # more than a loop is followed exactly


def _setup(d):
    d.deploy("Loopy", ("address[]",), ([O.hex20(a) for a in ADMINS],))


PROBES = [O.Probe(SOURCE, _setup, (("Loopy", "spin", ()), ("Loopy", "admin", ())))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def test_a_stranger_whose_call_goes_through_makes_it_open(d):
    v = O.check(d, "Loopy", "spin", O.verdict(d, "Loopy", "spin"), open_at={})
    assert v.witnesses == {FRESH: {}}


def test_a_stranger_whose_call_reverts_proves_nothing(d):
    v = O.check(d, "Loopy", "admin", O.verdict(d, "Loopy", "admin"), open_at=False)
    O.sound(v, set(ADMINS))
    admin = O.function(d, "Loopy", "admin")
    assert all(O.passes(d, "Loopy", admin, sender=a) for a in ADMINS)


def test_the_call_is_one_of_the_functions_reads(d, monkeypatch):
    import services.logic.verdict as verdict_module

    clean = O.verdict(d, "Loopy", "spin")
    monkeypatch.setattr(verdict_module, "READS_PER_FUNCTION", 0)
    v = O.verdict(d, "Loopy", "spin")
    assert v.openness == "not_determined"
    O.never_bolder(clean, v)
