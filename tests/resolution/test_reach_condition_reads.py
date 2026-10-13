"""A condition under which a gate isn't reached opens a path only when read true at the analysis block, with the read
as its witness; read false the gate stands alone, and unread the function is not determined, never public and never
an exact set.

Real compile, real tracking plan, real snapshot, real resolver and real projection; only the JSON-RPC HTTP wire is
stubbed (the harness in ``test_unset_authority_undetermined_beside_owner``), and the role events are real index rows.
"""

from __future__ import annotations

from typing import Any

import pytest
from eth_utils.crypto import keccak

from tests.conftest import requires_postgres
from tests.resolution.test_unset_authority_undetermined_beside_owner import (  # noqa: F401
    BLOCK,
    OWNER,
    SUBJECT,
    ZERO,
    _run,
    _selector,
    compile_contract,
)

pytestmark = [requires_postgres, pytest.mark.compile]

_HEADER = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
"""

# OpenZeppelin v4.9 AccessControl and TimelockController's ``onlyRoleOrOpenRole``, as they compile into a timelock.
_TIMELOCK = (
    _HEADER
    + """
contract OpenRoleTimelock {
    struct RoleData { mapping(address => bool) members; bytes32 adminRole; }
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    mapping(bytes32 => RoleData) private _roles;
    uint256 public hook;
    constructor(address executor) { _grantRole(EXECUTOR_ROLE, executor); }
    modifier onlyRole(bytes32 role) { _checkRole(role); _; }
    modifier onlyRoleOrOpenRole(bytes32 role) {
        if (!hasRole(role, address(0))) { _checkRole(role, _msgSender()); }
        _;
    }
    function _msgSender() internal view returns (address) { return msg.sender; }
    function hasRole(bytes32 role, address account) public view returns (bool) { return _roles[role].members[account]; }
    function getRoleAdmin(bytes32 role) public view returns (bytes32) { return _roles[role].adminRole; }
    function _checkRole(bytes32 role) internal view { _checkRole(role, _msgSender()); }
    function _checkRole(bytes32 role, address account) internal view {
        if (!hasRole(role, account)) { revert("AccessControl: account is missing role"); }
    }
    function grantRole(bytes32 role, address account) external onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }
    function revokeRole(bytes32 role, address account) external onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }
    function _grantRole(bytes32 role, address account) internal {
        if (!hasRole(role, account)) {
            _roles[role].members[account] = true;
            emit RoleGranted(role, account, _msgSender());
        }
    }
    function _revokeRole(bytes32 role, address account) internal {
        if (hasRole(role, account)) {
            _roles[role].members[account] = false;
            emit RoleRevoked(role, account, _msgSender());
        }
    }
    function execute(uint256 v) external onlyRoleOrOpenRole(EXECUTOR_ROLE) { hook = v; }
}
"""
)

# LayerZero OneSig's executor gate: a bool helper that admits anyone while the flag is off.
_FLAG_GATED = (
    _HEADER
    + """
contract FlagGatedExecutor {
    address public executor;
    bool public executorRequired;
    uint256 public hook;
    function canExecuteTransaction(address sender) public view returns (bool) {
        return !executorRequired || sender == executor;
    }
    function executeTransaction(uint256 v) external {
        if (!canExecuteTransaction(msg.sender)) revert("NOT_EXECUTOR");
        hook = v;
    }
}
"""
)

# The gate under the branch is reached when the narrowed value is zero, whatever the full word says.
_POLARITY = (
    _HEADER
    + """
contract ReachPolarity {
    address public owner;
    bool public closed;
    uint256 public mode;
    uint256 public hook;
    function whenClosed(uint256 v) external {
        if (closed) { require(msg.sender == owner, "UNAUTHORIZED"); }
        hook = v;
    }
    function narrowed(uint256 v) external {
        if (uint8(mode) == 0) { require(msg.sender == owner, "UNAUTHORIZED"); }
        hook = v;
    }
}
"""
)

EXECUTOR = "0x" + "e7" * 20
EXECUTOR_ROLE = "0x" + keccak(text="EXECUTOR_ROLE").hex()
GRANTED = "0x" + keccak(text="RoleGranted(bytes32,address,address)").hex()
REVOKED = "0x" + keccak(text="RoleRevoked(bytes32,address,address)").hex()
_TRUE = "0x1"
_FALSE = "0x0"


def _topic(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def _seed_executor_grant(db_session) -> None:
    from db.models import IndexedEventCursor, IndexedEventLog

    db_session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=SUBJECT,
            topic0=GRANTED,
            tx_hash=b"\xaa" * 32,
            log_index=0,
            block_number=100,
            block_hash=b"\xbb" * 32,
            transaction_index=0,
            topics=[GRANTED, EXECUTOR_ROLE, _topic(EXECUTOR), _topic(OWNER)],
            data_words=[],
        )
    )
    for topic0 in (GRANTED, REVOKED):
        db_session.add(
            IndexedEventCursor(
                chain_id=1,
                event_address=SUBJECT,
                topic0=topic0,
                last_indexed_block=BLOCK + 10,
                last_indexed_block_hash=b"\xcc" * 32,
                backfill_complete=True,
                first_indexed_block=0,
                first_indexed_block_basis="creation_block_minus_one",
            )
        )
    db_session.commit()


def _surface(cap: dict[str, Any]) -> tuple[str, Any]:
    from services.policy.capability_surface import capability_surface_openness, project_capability_surface

    surface = project_capability_surface(cap)
    return capability_surface_openness(cap, surface), surface


def _reach_reads(cap: Any) -> list[dict[str, Any]]:
    """Every reach read in a serialized capability, whatever node it rides on."""
    out: list[dict[str, Any]] = []
    if isinstance(cap, dict):
        out.extend(step for step in cap.get("trace") or [] if step.get("step") == "reach_condition_read")
        for child in cap.get("children") or []:
            out.extend(_reach_reads(child))
    return out


def _timelock(db_session, monkeypatch, compile_contract, open_role: str | None):
    _seed_executor_grant(db_session)
    _job, out = _run(
        db_session,
        monkeypatch,
        compile_contract("OpenRoleTimelock", _TIMELOCK),
        authority=None,
        owner=None,
        extra_getters={"EXECUTOR_ROLE()": EXECUTOR_ROLE, "hasRole(bytes32,address)": open_role},
    )
    return out["execute(uint256)"]


def test_a_timelock_whose_executor_role_is_not_open_is_restricted_to_its_executors(
    db_session, monkeypatch, compile_contract
):
    cap = _timelock(db_session, monkeypatch, compile_contract, _FALSE)
    openness, surface = _surface(cap)
    assert openness == "restricted", cap
    assert [row["address"] for row in surface.principal_rows] == [EXECUTOR], cap
    # The read that refuted the open role is kept with the answer.
    [read] = _reach_reads(cap)
    assert read["holds"] is False
    [call] = read["reads"]
    assert call["method"] == "eth_call" and call["block"] == BLOCK
    assert call["params"][0]["data"] == _selector("hasRole(bytes32,address)") + EXECUTOR_ROLE[2:] + "0" * 64


def test_a_timelock_whose_executor_role_is_open_is_public_on_the_read(db_session, monkeypatch, compile_contract):
    cap = _timelock(db_session, monkeypatch, compile_contract, _TRUE)
    openness, surface = _surface(cap)
    assert openness == "open", cap
    assert surface.authority_public
    assert any(read["holds"] is True for read in _reach_reads(cap)), cap


def test_a_timelock_whose_open_role_read_fails_is_not_determined(db_session, monkeypatch, compile_contract):
    cap = _timelock(db_session, monkeypatch, compile_contract, None)
    openness, surface = _surface(cap)
    assert openness == "not_determined", cap
    assert not surface.authority_public
    assert surface.open_not_determined


def _flag_gated(db_session, monkeypatch, compile_contract, required: str | None):
    _job, out = _run(
        db_session,
        monkeypatch,
        compile_contract("FlagGatedExecutor", _FLAG_GATED),
        authority=None,
        owner=None,
        extra_getters={"executor()": EXECUTOR, "executorRequired()": required},
    )
    return out["executeTransaction(uint256)"]


def test_a_flag_gated_executor_with_the_flag_on_is_restricted_to_the_executor(
    db_session, monkeypatch, compile_contract
):
    cap = _flag_gated(db_session, monkeypatch, compile_contract, _TRUE)
    openness, surface = _surface(cap)
    assert openness == "restricted", cap
    assert [row["address"] for row in surface.principal_rows] == [EXECUTOR], cap


def test_a_flag_gated_executor_with_the_flag_off_is_public_on_the_read(db_session, monkeypatch, compile_contract):
    cap = _flag_gated(db_session, monkeypatch, compile_contract, _FALSE)
    openness, _surface_ = _surface(cap)
    assert openness == "open", cap
    [read] = [read for read in _reach_reads(cap) if read["holds"] is True]
    assert read["reads"][0]["params"][0]["data"] == _selector("executorRequired()")


def test_a_flag_gated_executor_whose_flag_read_fails_is_not_determined(db_session, monkeypatch, compile_contract):
    cap = _flag_gated(db_session, monkeypatch, compile_contract, None)
    openness, surface = _surface(cap)
    assert openness == "not_determined", cap
    assert not surface.authority_public


@pytest.mark.parametrize(("closed", "expected"), [(_TRUE, "restricted"), (_FALSE, "open"), (None, "not_determined")])
def test_a_gate_under_a_state_branch_follows_the_branch_read(
    db_session, monkeypatch, compile_contract, closed, expected
):
    _job, out = _run(
        db_session,
        monkeypatch,
        compile_contract("ReachPolarity", _POLARITY),
        authority=None,
        extra_getters={"closed()": closed, "mode()": _FALSE},
    )
    openness, surface = _surface(out["whenClosed(uint256)"])
    assert openness == expected, out["whenClosed(uint256)"]
    if expected == "restricted":
        assert [row["address"] for row in surface.principal_rows] == [OWNER]


def test_a_branch_on_a_narrowed_value_reads_the_narrowed_value(db_session, monkeypatch, compile_contract):
    # 256 is nonzero, but ``uint8(256)`` is zero: the owner check is reached.
    _job, out = _run(
        db_session,
        monkeypatch,
        compile_contract("ReachPolarity", _POLARITY),
        authority=None,
        extra_getters={"closed()": _FALSE, "mode()": hex(256)},
    )
    openness, surface = _surface(out["narrowed(uint256)"])
    assert openness == "restricted", out["narrowed(uint256)"]
    assert [row["address"] for row in surface.principal_rows] == [OWNER]


def test_an_owner_check_under_a_negated_branch_stands_when_the_flag_is_off(db_session, monkeypatch, compile_contract):
    from tests.resolution.test_gate_control_flow import _CONDITIONAL_OWNER

    _job, out = _run(
        db_session,
        monkeypatch,
        compile_contract("ConditionalOwner", _CONDITIONAL_OWNER),
        authority=ZERO,
        extra_getters={"openMode()": _FALSE},
    )
    for signature in ("announce(uint256)", "setHook(uint256)"):
        openness, surface = _surface(out[signature])
        assert openness == "restricted", out[signature]
        assert [row["address"] for row in surface.principal_rows] == [OWNER]
