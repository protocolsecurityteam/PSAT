"""The KNOWN GAPS of ``COVERAGE.md`` as the reviewers' probes found them, each against the chain on anvil. A test that
asserts what the chain shows and the engine doesn't yet do is a strict xfail naming its gap: a fix flips it loudly.
The probes come from ``scratchpad/probe_audit4`` (``b1``, ``c2``, ``c3``, ``f2``) and ``probe_audit5`` (``q7``,
``q1g3``)."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

OWNER = O.OWNER
STRANGER = O.STRANGERS[0]

SOURCE = """
pragma solidity 0.8.27;

// G1: a settable condition refuting everyone, inside a disjunction or behind an early exit (c3).
contract Ranged {
    uint256 public lo = 10; uint256 public hi = 5; address public owner; address public pending; uint256 public x;
    constructor() { owner = msg.sender; }
    function setRange(uint256 l, uint256 h) external { require(msg.sender == owner); lo = l; hi = h; }
    function orPending(uint256 a) external { require((a >= lo && a <= hi) || msg.sender == pending); x = a; }
    function branchy(uint256 a) external {
        if (msg.sender == pending) { x = 1; return; }
        require(a >= lo && a <= hi);
        x = a;
    }
}

// G4: identity state nobody holds now, which the owner can set to anyone (c2).
contract Pending {
    address public owner; address public pending; uint256 public cap; uint256 public x;
    mapping(address => bool) public role;
    constructor() { owner = msg.sender; }
    function setPending(address p) external { require(msg.sender == owner); pending = p; }
    function setCap(uint256 c) external { require(msg.sender == owner); cap = c; }
    function grant(address a) external { require(msg.sender == owner); role[a] = true; }
    function accept(uint256 v) external { require(msg.sender == pending); x = v; }
    function acceptCapped(uint256 v) external { require(msg.sender == pending && v <= cap && v > 0); x = v; }
    function roleCapped(uint256 v) external { require(role[msg.sender] && v <= cap && v > 0); x = v; }
}

// G1 extended: an identity check or a callee's answer another contract's owner can change (f2).
contract Blocklist {
    mapping(bytes32 => bool) public bad;
    address public owner;
    constructor() { owner = msg.sender; bad[keccak256(abi.encode(bytes4(0x11223344)))] = true; }
    function setBad(bytes32 h, bool b) external { require(msg.sender == owner); bad[h] = b; }
    function blocked(bytes memory d) external view returns (bool) { return bad[keccak256(d)]; }
}
contract Tagged {
    Blocklist public g; uint256 public x; address public owner;
    bytes4 public tag = 0x11223344;
    constructor(Blocklist z) { g = z; owner = msg.sender; }
    function e9(uint256 v) external { require(!g.blocked(abi.encode(tag))); x = v; }
    function e10(uint256 v) external { require(msg.sender == owner || !g.blocked(abi.encode(tag))); x = v; }
}

// G3: "open" is "the call does not revert", not "the privileged effect happens" (b1, q1g3).
contract Origin {
    address public owner;
    constructor(address o) { owner = o; }
    function ok() external view returns (bool) { return tx.origin == owner; }
}
contract Early {
    Origin public g; uint256 public x;
    constructor(Origin z) { g = z; }
    function f1(uint256 v) external { if (v == 0) return; require(g.ok()); x = v; }
}
contract Exempt { function exempt(address who) external pure returns (bool) { who; return true; } }
contract Exempted {
    Exempt public g; address public owner; uint256 public x;
    constructor(Exempt z) { g = z; owner = msg.sender; }
    // Everyone returns early; only the owner reaches the write.
    function e11(uint256 v) external { if (g.exempt(msg.sender)) return; require(msg.sender == owner); x = v; }
}

// G6: "open later" on a callee no transaction can make pass (q7).
contract Never {
    bool public f;  // no writer anywhere: false for ever
    function ok() external view returns (bool) { return f; }
    function never() external pure returns (bool) { return false; }
}
contract ViaNever {
    Never public g; uint256 public x;
    constructor(Never z) { g = z; }
    function viaState(uint256 v) external { require(g.ok()); x = v; }
    function viaPure(uint256 v) external { require(g.never()); x = v; }
}
"""
TAG_HASH = keccak(encode(["bytes4"], [bytes.fromhex("11223344")]))


def _setup(d):
    d.deploy("Ranged")
    d.deploy("Pending")
    d.deploy("Blocklist")
    d.deploy("Tagged", ("address",), (d.at["Blocklist"],))
    d.deploy("Origin", ("address",), (OWNER,))
    d.deploy("Early", ("address",), (d.at["Origin"],))
    d.deploy("Exempt")
    d.deploy("Exempted", ("address",), (d.at["Exempt"],))
    d.deploy("Never")
    d.deploy("ViaNever", ("address",), (d.at["Never"],))


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        (
            ("Ranged", "orPending", ()), ("Ranged", "branchy", ()), ("Pending", "accept", ()),
            ("Pending", "acceptCapped", ()), ("Pending", "roleCapped", ()), ("Tagged", "e9", ("Blocklist",)),
            ("Tagged", "e10", ("Blocklist",)), ("Early", "f1", ("Origin",)), ("Exempted", "e11", ("Exempt",)),
            ("ViaNever", "viaState", ("Never",)), ("ViaNever", "viaPure", ("Never",)),
        ),
    )
]  # fmt: skip
FOLLOWED = pytest.mark.parametrize("followed", [True, False], ids=["followed", "unfollowed"])


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


@pytest.mark.xfail(
    strict=True,
    reason="G1: a settable condition inside a disjunction or behind an early exit is never "
    "set aside: 'restricted, complete, nobody' though the owner's setRange lets every stranger through",
)
@pytest.mark.parametrize("name", ["orPending", "branchy"])
def test_g1_a_settable_condition_beside_an_identity_check_is_never_nobody_ever(d, name):
    with O.snapshot(d):
        assert O.transact(d, "Ranged", "setRange(uint256,uint256)", ("uint256", "uint256"), (0, 100))
        assert O.strangers_passing(d, "Ranged", O.function(d, "Ranged", name), {"a": 5}) == {True}
    assert not O.nobody(O.verdict(d, "Ranged", name))


@pytest.mark.xfail(
    strict=True,
    reason="G4: identity state nobody holds now (pending == 0), which the owner can set "
    "to anyone, is reported 'restricted, complete, nobody'",
)
@pytest.mark.parametrize("name", ["accept", "acceptCapped"])
def test_g4_identity_state_nobody_holds_now_is_never_nobody_ever(d, name):
    with O.snapshot(d):
        assert O.transact(d, "Pending", "setPending(address)", ("address",), (STRANGER,))
        assert O.transact(d, "Pending", "setCap(uint256)", ("uint256",), (10,))
        assert O.passes(d, "Pending", O.function(d, "Pending", name), {"v": 1}, sender=STRANGER)
    assert not O.nobody(O.verdict(d, "Pending", name))


def test_g4_a_role_nobody_holds_now_beside_a_cap_is_not_complete(d):
    v = O.check(d, "Pending", "roleCapped", O.verdict(d, "Pending", "roleCapped"), samples=({"v": 1},))
    assert not O.nobody(v)


@FOLLOWED
def test_g1_extended_a_callee_answer_its_owner_can_change_opens_later(d, followed):
    v = O.verdict(d, "Tagged", "e9", *(("Blocklist",) if followed else ()))
    O.check(d, "Tagged", "e9", v, samples=({"v": 7},), open_at=False)
    assert v.openness == "open" and v.allowed == "later"
    with O.snapshot(d):  # the blocklist's owner unblocks the tag: every stranger passes
        assert O.transact(d, "Blocklist", "setBad(bytes32,bool)", ("bytes32", "bool"), (TAG_HASH, False))
        assert O.strangers_passing(d, "Tagged", O.function(d, "Tagged", "e9"), {"v": 7}) == {True}


@pytest.mark.xfail(
    strict=True,
    reason="G1 extended: 'restricted, complete, {owner}' though the blocklist's owner can "
    "unblock the tag and let every stranger through the other side of the disjunction",
)
@FOLLOWED
def test_g1_extended_an_owner_or_a_changeable_callee_answer_is_never_a_complete_list(d, followed):
    v = O.verdict(d, "Tagged", "e10", *(("Blocklist",) if followed else ()))
    O.check(d, "Tagged", "e10", v, samples=({"v": 7},), open_at=False)
    with O.snapshot(d):
        assert O.transact(d, "Blocklist", "setBad(bytes32,bool)", ("bytes32", "bool"), (TAG_HASH, False))
        assert O.strangers_passing(d, "Tagged", O.function(d, "Tagged", "e10"), {"v": 7}) == {True}
    assert not (v.openness == "restricted" and v.complete), v


def test_g3_an_early_return_before_the_gate_is_open_as_the_call_does_not_revert(d):
    # What "open" means today (D3): every stranger's call with v = 0 goes through, writing nothing.
    v = O.check(d, "Early", "f1", O.verdict(d, "Early", "f1", "Origin"), open_at={"v": 0})
    assert v.allowed == "now"


@pytest.mark.xfail(
    strict=True,
    reason="G3: 'open' is claimed on not reverting; f1 returns early for v == 0 and only "
    "the origin Origin names can set x",
)
def test_g3_open_is_claimed_on_the_privileged_effect(d):
    assert O.verdict(d, "Early", "f1", "Origin").openness != "open"


@FOLLOWED
@pytest.mark.parametrize("failing", [False, True], ids=["clean", "callee_calls_fail"])
def test_g3_extension_strangers_run_first_settle_open_where_reads_fail(d, followed, failing):
    # Review 5: every stranger returns early through ``exempt``; the chain runs each one's call first, so the row is
    # "open" (the call does not revert) even where the callee's own reads fail: G3's meaning reaches rows that failed
    # reads once left undecided.
    chain = O.Faulty(d, calls={d.at["Exempt"]}) if failing else None
    v = O.verdict(d, "Exempted", "e11", *(("Exempt",) if followed else ()), chain=chain)
    O.check(d, "Exempted", "e11", v, open_at={"v": 1})
    assert v.allowed == "now"


@pytest.mark.xfail(
    strict=True,
    reason="G6: 'open later' on a callee no transaction can make pass (a flag nothing "
    "writes, a pure false): nobody ever passes",
)
@FOLLOWED
@pytest.mark.parametrize("name", ["viaState", "viaPure"])
def test_g6_a_callee_nothing_can_make_pass_is_never_open_later(d, name, followed):
    assert O.strangers_passing(d, "ViaNever", O.function(d, "ViaNever", name), {"v": 1}) == {False}
    v = O.verdict(d, "ViaNever", name, *(("Never",) if followed else ()))
    assert v.openness != "open", v
