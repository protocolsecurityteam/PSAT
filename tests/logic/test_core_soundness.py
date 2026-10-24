"""What the second pass on the core may never do: open a function on a failed read or a spent budget, set aside a
callee that reads ``tx.origin`` (the caller's in every callee), pass off "open on conditions" as open, or read a
memory word it lost track of as the same for everyone. Each against what the chain does on anvil."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract Guard {
    address public admin;
    constructor(address a) { admin = a; }
    function ok(uint256 x) external view returns (bool) { x; return tx.origin == admin; }
    function okOr(uint256 x) external view returns (bool) { return tx.origin == admin || gasleft() == x; }
}

// Apart from Guard: code with an ``ORIGIN`` opcode anywhere is never read as the same for every caller.
contract Flags {
    bool public flag;
    function paused(uint256 x) external view returns (bool) { x; return true; }
    function flagged(uint256 x) external view returns (bool) { return flag && gasleft() > x; }
}

contract C {
    address admin;
    Guard guard;
    Flags flags;
    mapping(address => bool) isAdmin;
    uint256 total;
    constructor(address a, address g, address f) { admin = a; guard = Guard(g); flags = Flags(f); isAdmin[a] = true; }
    function viaOrigin(uint256 x) external { require(guard.ok(x)); total += x; }
    function viaOriginOr(uint256 x) external { require(guard.okOr(x)); total += x; }
    function viaPause(uint256 x) external { require(!flags.paused(x)); total += x; }
    function viaFlag(uint256 x) external { require(flags.flagged(x)); total += x; }
    function viaMem(uint256 x) external {
        address who;
        assembly { let p := mload(0x40) mstore(add(p, mul(x, 0)), caller()) who := mload(add(p, mul(x, 0))) }
        require(isAdmin[who]);
        total += 1;
    }
}
"""

ADMIN = 0xAB << 152 | int("ab" * 19, 16)


def _setup(d):
    d.deploy("Guard", ("address",), (ADMIN,))
    d.deploy("Flags")
    d.deploy("C", ("address",) * 3, (ADMIN, d.at["Guard"], d.at["Flags"]))


PROBES = [O.Probe(SOURCE, _setup, tuple(("C", f, ("Guard", "Flags")) for f in ("viaOrigin", "viaOriginOr", "viaPause",
                                                                        "viaFlag", "viaMem")))]  # fmt: skip
X = ({"x": 0}, {"x": 1}, {"x": 10**9})


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def test_a_failed_read_in_a_followed_callee_never_opens_it(d):
    whole = O.check(d, "C", "viaFlag", O.verdict(d, "C", "viaFlag", "Flags"), samples=X, open_at=False)
    v = O.verdict(d, "C", "viaFlag", "Flags", chain=O.Faulty(d, storage={d.at["Flags"]}))
    assert v.openness == "not_determined"
    assert "read_failed:storage:flag" in v.gaps
    O.never_bolder(whole, v)
    # Read whole: nobody passes, the flag being unset, but over every ``x`` only Flags' code shows it, which never
    # refutes on its own: unknown, never open.
    assert whole.openness == "not_determined" and "callee_code_refutation" in whole.gaps


def test_a_spent_read_budget_never_opens_it(d, monkeypatch):
    import services.logic.verdict as verdict_module

    clean = O.verdict(d, "C", "viaFlag", "Flags")
    monkeypatch.setattr(verdict_module, "READS_PER_FUNCTION", 1)
    v = O.verdict(d, "C", "viaFlag", "Flags")
    assert v.openness == "not_determined"
    O.never_bolder(clean, v)


def test_a_followed_callee_reading_the_origin_singles_out_its_admin(d):
    v = O.check(d, "C", "viaOrigin", O.verdict(d, "C", "viaOrigin", "Guard"), samples=X, open_at=False)
    # Inlined, the guard's code only proposes: the admin's own call goes through on the chain; over every ``x`` no
    # run settles the list, so it is not complete.
    assert not v.complete and set(v.principals) == {ADMIN}
    assert "inlined_callee:ok(uint256)" in v.gaps
    O.check(d, "C", "viaOriginOr", O.verdict(d, "C", "viaOriginOr", "Guard"), samples=X, open_at=False)


@pytest.mark.parametrize(("name", "signature"), [("viaOrigin", "ok(uint256)"), ("viaOriginOr", "okOr(uint256)")])
def test_an_unfollowed_callee_is_never_taken_free_of_the_origin(d, name, signature):
    v = O.check(d, "C", name, O.verdict(d, "C", name), samples=X, open_at=False)
    O.sound(v, {ADMIN})
    assert v.openness == "not_determined"
    assert f"origin:{signature}" in v.gaps  # its runtime code has an ORIGIN opcode


def test_open_on_an_unsettled_condition_is_never_plain_open(d):
    # paused() is always true: everyone reverts on the chain
    O.check(d, "C", "viaPause", O.verdict(d, "C", "viaPause"), samples=X, open_at=False)


def test_a_memory_word_lost_track_of_may_be_the_caller(d):
    v = O.check(d, "C", "viaMem", O.verdict(d, "C", "viaMem"), samples=X, open_at=False)
    O.sound(v, {ADMIN})
    assert O.passes(d, "C", O.function(d, "C", "viaMem"), sender=ADMIN)
