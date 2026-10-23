"""Who may call is decided on the core: conjuncts no caller's identity reaches, left unknown only for what the
lowering couldn't express, are conditions on the call, reported as such (``allowed`` ``conditional``, a
``conditional:`` gap, never complete). Not when they read false now, a read failed, or the callee isn't followed: its
code may read ``tx.origin``, which is the caller's."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

interface IHub {
    function math(uint256 x) external view returns (uint256);
    function check(address who) external view returns (bool);
    function pair(uint256 x, address who) external view returns (bool);
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

AT, HUB, ADMIN = 0xA1 << 140, 0xB7 << 140, 0xB2 << 140
HOLDERS = (0xC3 << 140, 0xD4 << 140)
GRANTED = int.from_bytes(keccak(b"Granted(address)"), "big")
CALL = ("business", "0 lt hub.math(uint256)(x)")


def _role(who: int) -> int:
    return int.from_bytes(keccak(who.to_bytes(32, "big") + (1).to_bytes(32, "big")), "big")


class _Deployed(Chain):
    """The hub's calls revert (``call_error`` a node's error instead); the admin list holds five entries, more than a loop over it is followed exactly."""

    def __init__(self, paused: bool = False, call_error: str = "execution reverted"):
        self.words = {0: HUB, 3: ADMIN | int(paused) << 160, 4: 5, **{_role(h): 1 for h in HOLDERS}}
        self.call_error = call_error
        super().__init__(self._answer, 100, lambda calls: [self._safe(m, p) for m, p in calls])

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(self.words.get(int(params[1], 16), 0))
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError(self.call_error)

    def code(self, address):
        return b"\\x60" if address in (AT, HUB) else b""

    def logs(self, address, topics):
        return [([GRANTED, h], []) for h in HOLDERS] if address == AT else []


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("core") / "C.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "C")


def _verdict(contract, name, chain=None):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    return function_verdict(contract, fn, AT, chain or _Deployed(), {AT: contract})[0]


def test_a_role_beside_an_unfollowed_call_lists_its_holders_on_that_condition(contract):
    verdict = _verdict(contract, "gated")
    assert verdict.openness == "restricted"
    assert verdict.complete
    assert verdict.conditions == {h: "business" for h in HOLDERS}
    assert verdict.core == ("roles[caller]",)
    assert CALL in verdict.condition_terms


def test_an_unfollowed_callee_is_never_set_aside(contract):
    # Its code may read tx.origin, the caller's: the conjunct may single someone out.
    for name in ("free", "screened"):
        verdict = _verdict(contract, name)
        assert verdict.openness == "not_determined"
        assert "unfollowed:math(uint256)" in verdict.gaps
        assert CALL in verdict.condition_terms


def test_a_screen_beside_an_unknown_is_open_only_on_it(contract):
    verdict = _verdict(contract, "screenedGas")
    assert verdict.openness == "open"
    assert verdict.allowed == "conditional"
    assert not verdict.complete
    assert "conditional:unknown:gasleft()" in verdict.gaps
    assert verdict.witnesses == {}  # the stranger's own call reverts on this chain: no witness


def test_a_pause_still_holds_everyone_back_now(contract):
    verdict = _verdict(contract, "pausableGas", _Deployed(paused=True))
    assert verdict.openness == "open"
    assert verdict.allowed == "later_conditional"
    assert not verdict.complete


def test_a_call_handed_the_caller_stays_undecided(contract):
    verdict = _verdict(contract, "handed", _Deployed(call_error="upstream timeout"))
    assert verdict.openness == "not_determined"
    assert f"call:check(address):arg0@0x{HUB:040x}" in verdict.gaps


def test_the_gap_names_the_argument_the_caller_reaches(contract):
    verdict = _verdict(contract, "paired")
    assert verdict.openness == "not_determined"
    assert f"call:pair(uint256,address):arg1@0x{HUB:040x}" in verdict.gaps


def test_an_unknown_that_may_hide_the_caller_still_blocks(contract):
    verdict = _verdict(contract, "listed")
    assert verdict.openness == "not_determined"
    assert any(g.startswith("unknown:loop:") for g in verdict.gaps)
    assert "unfollowed:math(uint256)" in verdict.gaps
    assert CALL in verdict.condition_terms


def test_a_failed_read_in_a_condition_stays_a_gap(contract):
    verdict = _verdict(contract, "listedFixed", _Deployed(call_error="upstream timeout"))
    assert verdict.openness == "not_determined"
    assert "read_failed:call:math(uint256)" in verdict.gaps
