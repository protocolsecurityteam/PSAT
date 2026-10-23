"""Where the core still holds what the lowering couldn't express, one call run as a fresh address settles it when it
goes through (a success proves the function open); one that fails proves nothing and changes nothing."""

from __future__ import annotations

from services.logic.decide import FRESH
from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401

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


def _verdict(anvil, name):  # noqa: F811
    from services.logic.terms import reset_terms

    url, root = anvil
    d = Deployment(url, root, SOURCE)
    at = d.deploy("Loopy", ("address[]",), (["0x" + format(a, "040x") for a in ADMINS],))
    reset_terms()
    contract = d.slither["Loopy"]
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    return function_verdict(contract, fn, at, d.chain(), {at: contract})[0]


def test_a_stranger_whose_call_goes_through_makes_it_open(anvil):  # noqa: F811
    verdict = _verdict(anvil, "spin")
    assert verdict.openness == "open"
    assert verdict.witnesses == {FRESH: {}}


def test_a_stranger_whose_call_reverts_proves_nothing(anvil):  # noqa: F811
    verdict = _verdict(anvil, "admin")
    assert verdict.openness == "not_determined"
    assert any(g.startswith("unknown:loop:") for g in verdict.gaps)


def test_the_call_is_one_of_the_functions_reads(anvil, monkeypatch):  # noqa: F811
    import services.logic.verdict as verdict_module

    monkeypatch.setattr(verdict_module, "READS_PER_FUNCTION", 0)
    assert _verdict(anvil, "spin").openness == "not_determined"
