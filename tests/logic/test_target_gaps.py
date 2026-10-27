"""A call whose target address the decision can't read is named for why: ``read_failed:target:<sig>`` (and
``read_failed:call_target:<sig>`` for a view call the verdict keeps from being read alike) only where a read the
target comes from went unanswered by the node; otherwise ``unknown:target:<why>:<sig>`` /
``unknown:call_target:<why>:<sig>``, the target being an argument the caller picks or another call's result (here, a
call to an address with no code, which reverts). The verdicts themselves are what the chain says (``_oracle.check``),
the same whatever the label; a failing chain (``_oracle.Faulty``) is what brings ``read_failed`` back, never bolder."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

interface IToken {
    function transferFrom(address a, address b, uint256 v) external returns (bool);
    function ok(address who) external view returns (bool);
}
interface IReg { function token() external view returns (address); }

contract Reg {
    address public token;
    function set(address t) external { token = t; }
}

contract Tok {
    mapping(address => bool) public allowed;
    function ok(address who) external view returns (bool) { return allowed[who]; }
    function transferFrom(address, address, uint256) external returns (bool) { return true; }
}

contract C {
    IReg reg;
    uint256 x;
    constructor(address r) { reg = IReg(r); }
    function byArg(address token, uint256 v) external {
        require(IToken(token).transferFrom(msg.sender, address(this), v));
        x = v;
    }
    function byResult(uint256 v) external {
        require(IToken(reg.token()).transferFrom(msg.sender, address(this), v));
        x = v;
    }
    function viewByArg(address token) external { require(IToken(token).ok(address(0))); x = 1; }
    function viewByResult() external { require(IToken(reg.token()).ok(address(0))); x = 1; }
}
"""

TRANSFER = "transferFrom(address,address,uint256)"


def _setup(d):
    d.deploy("Reg")
    d.deploy("Tok")
    d.deploy("C", ("address",), (d.at["Reg"],))


PICKY = """
pragma solidity 0.8.27;

interface IToken { function ok(address who) external view returns (bool); }

// Lets the deployer's transactions through and nobody else's, whoever hands it what.
contract OriginTok {
    address admin;
    constructor() { admin = msg.sender; }
    function ok(address) external view returns (bool) { return tx.origin == admin; }
}

contract Picky {
    mapping(address => bool) approved;
    uint256 x;
    constructor(address t) { approved[t] = true; }
    // Truth: only the admin's transactions pass, with the one approved token.
    function approvedOnly(address t) external { require(approved[t]); require(IToken(t).ok(address(0))); x = 1; }
}
"""


def _setup_picky(d):
    d.deploy("OriginTok")
    d.deploy("Picky", ("address",), (d.at["OriginTok"],))


PROBES = [
    O.Probe(SOURCE, _setup, (("C", "byArg", ()), ("C", "viewByArg", ()))),
    O.Probe(PICKY, _setup_picky, (("Picky", "approvedOnly", ()),)),
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


@pytest.fixture(scope="module")
def nocode(d):
    """``C`` whose registry is an address with no code: ``reg.token()`` reverts, so no read gives the target."""
    return d.deploy("C", ("address",), (O.ACCOUNTS[1],))


def _no_failed_read(v):
    assert not any(g.startswith("read_failed") for g in v.gaps), v.gaps


def test_a_target_the_caller_picks_is_no_failed_read(d):
    v = O.check(d, "C", "byArg", O.verdict(d, "C", "byArg"), samples=({"token": d.at["Tok"], "v": 1},))
    assert v.openness == "not_determined"
    assert f"unknown:target:argument:{TRANSFER}" in v.gaps
    _no_failed_read(v)


def test_a_view_target_the_caller_picks_is_no_failed_read(d):
    # Not determined, as before the relabelling: whoever is at the address the caller names may read ``tx.origin``,
    # so the call is never a condition every caller faces alike (``decide._rests_on_code_not_followed``).
    v = O.check(d, "C", "viewByArg", O.verdict(d, "C", "viewByArg"))
    assert v.openness == "not_determined" and "unknown:target:argument:ok(address)" in v.gaps, v
    assert not any(g.startswith("conditional:") for g in v.gaps), v.gaps
    _no_failed_read(v)


def test_a_target_another_call_fails_to_give_is_a_call_result(d, nocode):
    for name, gap in (("byResult", f"unknown:target:call_result:{TRANSFER}"),
                      ("viewByResult", "unknown:call_target:call_result:ok(address)")):  # fmt: skip
        v = O.check(d, "C", name, O.verdict(d, "C", name, at=nocode), at=nocode, samples=({"v": 1},))
        assert v.openness == "not_determined" and gap in v.gaps, v.gaps
        _no_failed_read(v)
        fn = O.function(d, "C", name)
        assert not any(O.passes(d, nocode, fn, {"v": 1}, sender=who) for who in (*O.ACCOUNTS, *O.STRANGERS))


def test_a_target_whose_storage_read_fails_is_a_failed_read(d):
    failing = {
        "byResult": ("read_failed:call_target:token()", f"read_failed:target:{TRANSFER}"),
        "viewByResult": ("read_failed:call_target:ok(address)", "read_failed:call_target:token()"),
    }
    for name, gaps in failing.items():
        clean = O.verdict(d, "C", name)
        v = O.verdict(d, "C", name, chain=O.Faulty(d, storage=True))
        assert set(gaps) <= set(v.gaps), v.gaps
        assert not any(g.startswith(("unknown:target:", "unknown:call_target:")) for g in v.gaps), v.gaps
        O.never_bolder(clean, v)


@pytest.fixture(scope="module")
def picky(anvil):  # noqa: F811
    d = O.deployment(*anvil, PICKY)
    _setup_picky(d)
    return d


def test_only_the_admin_passes_the_approved_origin_reading_token(picky):
    d = picky
    fn = O.function(d, "Picky", "approvedOnly")
    args = {"t": d.at["OriginTok"]}
    assert O.passes(d, "Picky", fn, args, sender=O.OWNER)
    assert not any(O.passes(d, "Picky", fn, args, sender=w) for w in (*O.STRANGERS, *O.UNSEEN[:4], *O.ACCOUNTS[1:]))


def test_an_unfollowed_callee_the_caller_picks_is_never_an_opaque_condition(picky):
    """Round ten-c, probe q5: with its gap relabelled ``unknown:target:argument:<sig>``, a call to an address the
    caller names passed ``_opaque_conditions``' prefix test and a function only the admin ever passes read "open,
    conditional". The rule is on the terms: code not followed may read ``tx.origin``, whatever the label."""
    d = picky
    v = O.verdict(d, "Picky", "approvedOnly")
    O.check(d, "Picky", "approvedOnly", v, open_at=False, samples=({"t": d.at["OriginTok"]},))
    assert v.openness == "not_determined", v
    assert "unknown:target:argument:ok(address)" in v.gaps and not any(g.startswith("conditional:") for g in v.gaps), v
