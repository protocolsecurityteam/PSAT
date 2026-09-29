"""``_detect_timelock`` -- the STATIC half.

It was a stub returning ``has_timelock: False``, so the column was false on 92/92 local rows
including ``EtherFiTimelock`` (``getMinDelay()`` 864000, sole holder of ``UPGRADE_TIMELOCK_ROLE``),
a credit-bearing scoring input. The proven property is structural and chain-free: a state
variable is written with a clock-derived value (queue half) and another entry point reverts
unless it has matured (execute half). ``pattern`` is ``oz_timelock`` when the claims plane also
recognises the ``TimelockController`` ABI.

**The delay VALUE is not read here** (no chain / RPC handle): ``delay`` is ``None`` with
``delay_source: "not_read"`` and ``delay_variables`` names where it lives. A defaulted delay
would fabricate a protective credit.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any, cast

import pytest

pytest.importorskip("slither")
from slither import Slither

from schemas.contract_analysis import (
    RoleDefinition,
    SemanticControlAnalysis,
    TimelockAnalysis,
)
from services.static.claims import attach_claims_to_effects, build_claims, project_effect_labels
from services.static.contract_analysis_pipeline.effects import build_effects
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    build_predicate_artifacts_with_pause_info,
)
from services.static.contract_analysis_pipeline.summaries import (
    _detect_timelock,
    _determine_control_model,
)

CUSTOM_TIMELOCK = """
    pragma solidity ^0.8.19;
    contract C {
        address public admin;
        uint256 public delay;
        mapping(bytes32 => uint256) public eta;
        error NotAdmin();
        error NotQueued();
        error TooEarly();
        error CallFailed();
        modifier onlyAdmin() { if (msg.sender != admin) revert NotAdmin(); _; }
        function queue(bytes32 id) external onlyAdmin {
            eta[id] = block.timestamp + delay;
        }
        function run(address target, bytes calldata data, bytes32 id) external onlyAdmin {
            uint256 ready = eta[id];
            if (ready == 0) revert NotQueued();
            if (block.timestamp < ready) revert TooEarly();
            eta[id] = 0;
            (bool ok, ) = target.call(data);
            if (!ok) revert CallFailed();
        }
        function setDelay(uint256 d) external onlyAdmin { delay = d; }
    }
"""

# THE discriminating negative, and the reason the arbitrary-execution
# requirement exists: a Teller's per-user share lock. Structurally identical to
# a timelock -- a clock-derived write and a revert-until-matured gate -- and it
# is a cooldown on one hard-coded operation, not a queued arbitrary action.
# Six corpus contracts (TellerWithMultiAssetSupport / LayerZeroTeller) have this
# exact shape and the bare structural pair credited every one of them with a
# governance timelock.
SHARE_LOCK_COOLDOWN = """
    pragma solidity ^0.8.19;
    contract C {
        address public admin;
        uint256 public shareLockPeriod;
        mapping(address => uint256) public shareUnlockTime;
        mapping(address => uint256) public balanceOf;
        error NotAdmin();
        error SharesLocked();
        modifier onlyAdmin() { if (msg.sender != admin) revert NotAdmin(); _; }
        function deposit(uint256 amount) external {
            balanceOf[msg.sender] += amount;
            shareUnlockTime[msg.sender] = block.timestamp + shareLockPeriod;
        }
        function transfer(address to, uint256 amount) external {
            if (block.timestamp < shareUnlockTime[msg.sender]) revert SharesLocked();
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
        function setShareLockPeriod(uint256 p) external onlyAdmin { shareLockPeriod = p; }
    }
"""

# An admin-gated executor with NO maturity gate. Structurally it queues nothing
# and waits for nothing; it just executes.
IMMEDIATE_EXECUTOR = """
    pragma solidity ^0.8.19;
    contract C {
        address public admin;
        mapping(bytes32 => bool) public queued;
        error NotAdmin();
        error NotQueued();
        modifier onlyAdmin() { if (msg.sender != admin) revert NotAdmin(); _; }
        function queue(bytes32 id) external onlyAdmin { queued[id] = true; }
        function run(bytes32 id) external onlyAdmin {
            if (!queued[id]) revert NotQueued();
            queued[id] = false;
        }
    }
"""

# A contract that merely records a timestamp and never gates on maturity: the
# clock-write half alone must not be enough.
TIMESTAMP_LOG_ONLY = """
    pragma solidity ^0.8.19;
    contract C {
        address public admin;
        uint256 public lastUpdate;
        uint256 public value;
        error NotAdmin();
        modifier onlyAdmin() { if (msg.sender != admin) revert NotAdmin(); _; }
        function poke(uint256 v) external onlyAdmin {
            value = v;
            lastUpdate = block.timestamp;
        }
        function read() external view returns (uint256) { return value; }
    }
"""


# A non-empty role list on every call, so the ``authorized_roles`` gate is
# discriminating: an ungated field would echo these back on a negative.
_ROLES = cast("list[RoleDefinition]", [{"role": "ADMIN_ROLE", "declared_in": "C", "evidence": []}])


def _timelock(tmp_path: Path, source: str, name: str = "C"):
    path = tmp_path / "C.sol"
    path.write_text(textwrap.dedent(source).strip() + "\n")
    contract = next(c for c in Slither(str(path)).contracts if c.name == name)
    trees, _pause = build_predicate_artifacts_with_pause_info(contract)
    effects = build_effects(contract)
    attach_claims_to_effects(effects, build_claims(contract, effects, trees))
    project_effect_labels(effects)
    return _detect_timelock(contract, tmp_path, _ROLES, effects)


def test_custom_queue_execute_timelock_is_detected(tmp_path):
    """POSITIVE CONTROL for the structural half: no OZ ABI anywhere, only the invariant."""
    result = _timelock(tmp_path, CUSTOM_TIMELOCK)
    assert result["has_timelock"] is True, result
    assert result["pattern"] == "custom"
    assert "queue(bytes32)" in result["queue_execute_functions"]
    assert "run(address,bytes,bytes32)" in result["queue_execute_functions"]
    assert "delay" in result["delay_variables"], result["delay_variables"]
    # R4 positive arm for the three verdict-gated evidence fields, so the
    # negative's ``== []`` cannot be satisfied by a field that is always empty.
    assert result["authorized_roles"] == ["ADMIN_ROLE"]
    assert result["evidence"]


def test_share_lock_cooldown_is_not_a_timelock(tmp_path):
    """THE discriminating negative: the bare structural pair (clock-derived write + revert-until-matured
    gate) is a per-user cooldown on one hard-coded operation. Without the arbitrary-execution
    requirement it fired on 16 of 19 local hits (6 Tellers, an EigenLayer withdrawal delay, a
    blacklist expiry), each published as ``control_model: governance``."""
    result = _timelock(tmp_path, SHARE_LOCK_COOLDOWN)
    assert result["has_timelock"] is False, result
    assert result["pattern"] == "none"
    assert result["delay_variables"] == []
    # EVERY output field, not only the verdict: the bare pair DOES fire on this shape, so an
    # ungated evidence list would republish the excluded claim next to ``has_timelock: false``
    # (measured: Teller ``deposit(...)`` / DelegationManager ``getQueuedWithdrawal`` views).
    assert result["queue_execute_functions"] == [], result["queue_execute_functions"]
    assert result["authorized_roles"] == []
    assert result["evidence"] == []


def test_immediate_executor_is_not_a_timelock(tmp_path):
    """NEGATIVE CONTROL. Queue + execute + admin gate, no clock: the maturity check is what makes
    a timelock, else every two-step admin flow would be credited with a delay."""
    result = _timelock(tmp_path, IMMEDIATE_EXECUTOR)
    assert result["has_timelock"] is False, result
    assert result["pattern"] == "none"
    assert result["queue_execute_functions"] == []
    assert result["delay_variables"] == []


def test_timestamp_write_without_a_maturity_gate_is_not_a_timelock(tmp_path):
    """NEGATIVE CONTROL. Writing ``block.timestamp`` is a log, not a latch."""
    result = _timelock(tmp_path, TIMESTAMP_LOG_ONLY)
    assert result["has_timelock"] is False, result
    assert result["pattern"] == "none"


@pytest.mark.parametrize("source", [CUSTOM_TIMELOCK, SHARE_LOCK_COOLDOWN, IMMEDIATE_EXECUTOR, TIMESTAMP_LOG_ONLY])
def test_delay_value_is_never_published_from_source(tmp_path, source):
    """The static half proves "this is a timelock", not HOW LONG; a defaulted delay would be a fabricated credit."""
    result = _timelock(tmp_path, source)
    assert result["delay"] is None
    assert result["delay_source"] == "not_read"


def test_has_timelock_is_not_determined_without_ir(tmp_path):
    """R1/R2 sentinel: with no functions to walk neither half could run, and ``False`` would assert an
    unlooked-for absence."""

    class _NoIR:
        name = "C"
        functions = []

    result = _detect_timelock(_NoIR(), tmp_path, [], {"functions": {}})
    assert result["has_timelock"] is None
    assert result["pattern"] == "unknown"
    assert result["delay_source"] == "not_read"


@pytest.mark.parametrize("degradation", ["claims_stage_raised", "effects_stage_raised", "no_effects_artifact"])
def test_has_timelock_is_not_determined_without_the_claims_plane(tmp_path, degradation):
    """R1 on the POSITIVE control (a contract that IS a timelock).

    BOTH verdict determinants live on the claims plane (``structural`` needs ``exec.arbitrary``,
    ``standard`` needs ``timelock.schedule`` + ``timelock.execute``), so any claims-plane
    degradation makes ``False`` a proven absence of a timelock that exists.

    ``claims_stage_raised`` is unreachable by a no-IR test: ``core`` runs ``build_effects`` and
    the claims block under separate ``try``/``except`` (``core.py:225-253``), so effects can be
    complete and claim-free; ``_determine_control_model`` reads that ``False`` as "not governance"."""
    path = tmp_path / "C.sol"
    path.write_text(textwrap.dedent(CUSTOM_TIMELOCK).strip() + "\n")
    contract = next(c for c in Slither(str(path)).contracts if c.name == "C")

    if degradation == "claims_stage_raised":
        effects: Any = build_effects(contract)
        assert effects["functions"], "guard: the effects plane succeeded"
        assert all("claims" not in record for record in effects["functions"].values())
    elif degradation == "effects_stage_raised":
        effects = {"schema_version": "semantic", "error": "boom"}
    else:
        effects = None

    result = _detect_timelock(contract, tmp_path, _ROLES, effects)
    assert result["has_timelock"] is None, result
    assert result["pattern"] == "unknown"
    assert result["delay"] is None
    assert result["delay_source"] == "not_read"
    assert result["queue_execute_functions"] == []
    assert result["delay_variables"] == []
    assert result["authorized_roles"] == []
    assert result["evidence"] == []


def test_control_model_does_not_read_not_determined_as_governance(tmp_path):
    """``has_timelock is True``, not truthiness: not-determined must neither promote to ``governance``
    nor demote; it falls through to the semantic pattern."""
    semantic = cast("SemanticControlAnalysis", {"pattern": "role_control"})

    def timelock(has: bool | None) -> TimelockAnalysis:
        return cast("TimelockAnalysis", {"has_timelock": has})

    assert _determine_control_model(None, semantic, timelock(True)) == "governance"
    assert _determine_control_model(None, semantic, timelock(None)) == "role_control"
    assert _determine_control_model(None, semantic, timelock(False)) == "role_control"
