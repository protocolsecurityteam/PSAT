"""What the resolver publishes for gates read through a bool helper under a negated call, and for a revert reached only
under a branch.

Real compile, real tracking plan, real snapshot and real resolver; only the JSON-RPC HTTP wire is stubbed (the harness
in ``test_unset_authority_undetermined_beside_owner``).
"""

from __future__ import annotations

import pytest

from tests.conftest import requires_postgres
from tests.resolution.test_unset_authority_undetermined_beside_owner import (  # noqa: F401
    OWNER,
    ZERO,
    _run,
    compile_contract,
)

pytestmark = [requires_postgres, pytest.mark.compile]

_HEADER = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
"""

_GETTER_BLACKLIST = (
    _HEADER
    + """
contract GetterBlacklist {
    address public owner;
    mapping(address => bool) public blacklisted;
    uint256 public hook;
    function isBlacklisted(address account) public view returns (bool) { return blacklisted[account]; }
    function setBlacklisted(address account, bool value) external {
        require(msg.sender == owner, "UNAUTHORIZED");
        blacklisted[account] = value;
    }
    function setHook(uint256 v) external {
        require(!isBlacklisted(msg.sender), "BLACKLISTED");
        hook = v;
    }
}
"""
)

_OZ_V5_PAUSABLE = (
    _HEADER
    + """
contract OzV5Pausable {
    error EnforcedPause();
    address public owner;
    bool private _paused;
    uint256 public hook;
    modifier whenNotPaused() { _requireNotPaused(); _; }
    function paused() public view returns (bool) { return _paused; }
    function _requireNotPaused() internal view { if (paused()) revert EnforcedPause(); }
    function pause() external { require(msg.sender == owner, "UNAUTHORIZED"); _paused = true; }
    function unpause() external { require(msg.sender == owner, "UNAUTHORIZED"); _paused = false; }
    function setHook(uint256 v) external whenNotPaused { hook = v; }
}
"""
)

_CONDITIONAL_OWNER = (
    _HEADER
    + """
contract ConditionalOwner {
    event E(uint256 v);
    address public owner;
    bool public openMode;
    uint256 public hook;
    modifier gatedUnlessOpen() { if (!openMode) { require(msg.sender == owner, "UNAUTHORIZED"); } _; }
    function announce(uint256 v) external {
        if (!openMode) { require(msg.sender == owner, "UNAUTHORIZED"); }
        emit E(v);
    }
    function setHook(uint256 v) external gatedUnlessOpen { hook = v; }
    function setInside(uint256 v) external {
        if (!openMode) { require(msg.sender == owner, "UNAUTHORIZED"); hook = v; }
    }
}
"""
)

_FALSE = "0x0"
_TRUE = "0x1"


def test_a_getter_negated_blacklist_reads_as_a_denylist_not_an_allowlist(db_session, monkeypatch, compile_contract):
    _job, out = _run(
        db_session,
        monkeypatch,
        compile_contract("GetterBlacklist", _GETTER_BLACKLIST),
        authority=ZERO,
    )
    cap = out["setHook(uint256)"]
    # Anyone not blacklisted may call: open minus a denylist, never an allowlist with no adapter.
    assert cap["kind"] == "cofinite_blacklist", cap
    assert [condition["kind"] for condition in cap["conditions"]] == ["denylist"], cap


def test_an_openzeppelin_v5_pause_gate_allows_only_while_unpaused(db_session, monkeypatch, compile_contract):
    compiled = compile_contract("OzV5Pausable", _OZ_V5_PAUSABLE)
    _job, out = _run(db_session, monkeypatch, compiled, authority=ZERO, extra_getters={"paused()": _FALSE})
    leaf = compiled[1]["trees"]["setHook(uint256)"]["leaf"]
    assert (leaf["operator"], leaf["authority_role"]) == ("falsy", "pause"), leaf
    cap = out["setHook(uint256)"]
    assert cap["kind"] == "conditional_universal", cap
    assert [condition["kind"] for condition in cap["conditions"]] == ["pause"], cap


@pytest.mark.parametrize("signature", ["announce(uint256)", "setHook(uint256)"])
def test_an_owner_check_under_a_branch_is_open_on_the_other_branch(
    db_session, monkeypatch, compile_contract, signature
):
    _job, out = _run(
        db_session,
        monkeypatch,
        compile_contract("ConditionalOwner", _CONDITIONAL_OWNER),
        authority=ZERO,
        extra_getters={"openMode()": _TRUE},
    )
    cap = out[signature]
    assert cap["kind"] == "OR", cap
    assert sorted(child["kind"] for child in cap["children"]) == ["conditional_universal", "finite_set"], cap
    owner = next(child for child in cap["children"] if child["kind"] == "finite_set")
    assert owner["members"] == [OWNER], cap


def test_an_effect_reached_only_past_the_owner_check_stays_owner_only(db_session, monkeypatch, compile_contract):
    _job, out = _run(
        db_session,
        monkeypatch,
        compile_contract("ConditionalOwner", _CONDITIONAL_OWNER),
        authority=ZERO,
        extra_getters={"openMode()": _TRUE},
    )
    cap = out["setInside(uint256)"]
    assert cap["kind"] == "finite_set" and cap["members"] == [OWNER], cap
