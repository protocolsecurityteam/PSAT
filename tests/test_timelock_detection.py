"""``_detect_timelock`` -- the STATIC half.

It was a stub: it ``del``ed all three arguments and returned
``has_timelock: False``, so the column was false on 92/92 local rows including
``EtherFiTimelock`` itself, whose ``getMinDelay()`` is 864000 (10 days) and
which is the sole holder of ``UPGRADE_TIMELOCK_ROLE``. inv 9 names that delay a
credit-bearing protective fact.

The proven property is structural and chain-free: some state variable is
written with a value the clock flows into (the queue half), and some other
entry point reverts unless that variable has matured against the clock (the
execute half). ``pattern`` is ``oz_timelock`` when the claims plane also
recognises the published ``TimelockController`` ABI.

**The delay VALUE is not read here.** It needs ``getMinDelay()`` on chain and
this module has no chain, no ``chain_id`` and no RPC handle. ``delay`` is
``None`` with ``delay_source: "not_read"``; ``delay_variables`` names where the
value lives. A defaulted delay would fabricate a protective credit.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.claims import attach_claims_to_effects, build_claims, project_effect_labels  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts_with_pause_info,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
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
        modifier onlyAdmin() { if (msg.sender != admin) revert NotAdmin(); _; }
        function queue(bytes32 id) external onlyAdmin {
            eta[id] = block.timestamp + delay;
        }
        function run(bytes32 id) external onlyAdmin {
            uint256 ready = eta[id];
            if (ready == 0) revert NotQueued();
            if (block.timestamp < ready) revert TooEarly();
            eta[id] = 0;
        }
        function setDelay(uint256 d) external onlyAdmin { delay = d; }
    }
"""

# The discriminating negative: an admin-gated executor with NO maturity gate.
# Structurally it queues nothing and waits for nothing; it just executes.
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


def _timelock(tmp_path: Path, source: str, name: str = "C"):
    path = tmp_path / "C.sol"
    path.write_text(textwrap.dedent(source).strip() + "\n")
    contract = next(c for c in Slither(str(path)).contracts if c.name == name)
    trees, _pause = build_predicate_artifacts_with_pause_info(contract)
    effects = build_effects(contract)
    attach_claims_to_effects(effects, build_claims(contract, effects, trees))
    project_effect_labels(effects)
    return _detect_timelock(contract, tmp_path, [], effects)


def test_custom_queue_execute_timelock_is_detected(tmp_path):
    """POSITIVE CONTROL for the structural half: no OZ ABI anywhere, only the
    invariant."""
    result = _timelock(tmp_path, CUSTOM_TIMELOCK)
    assert result["has_timelock"] is True, result
    assert result["pattern"] == "custom"
    assert "queue(bytes32)" in result["queue_execute_functions"]
    assert "run(bytes32)" in result["queue_execute_functions"]
    assert "delay" in result["delay_variables"], result["delay_variables"]


def test_immediate_executor_is_not_a_timelock(tmp_path):
    """NEGATIVE CONTROL. Queue + execute + an admin gate, and no clock: the
    thing that makes a timelock a timelock is the maturity check, and asserting
    otherwise would credit every two-step admin flow with a delay."""
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


@pytest.mark.parametrize("source", [CUSTOM_TIMELOCK, IMMEDIATE_EXECUTOR, TIMESTAMP_LOG_ONLY])
def test_delay_value_is_never_published_from_source(tmp_path, source):
    """The whole point of splitting the deliverable: the static half proves
    "this is a timelock" and says nothing about HOW LONG. A defaulted delay
    would be a fabricated protective credit."""
    result = _timelock(tmp_path, source)
    assert result["delay"] is None
    assert result["delay_source"] == "not_read"


def test_has_timelock_is_not_determined_without_ir(tmp_path):
    """R1/R2 sentinel: no functions to walk means neither half could be
    evaluated, and ``False`` would assert an absence nothing looked for."""

    class _NoIR:
        name = "C"
        functions = []

    result = _detect_timelock(_NoIR(), tmp_path, [], {"functions": {}})
    assert result["has_timelock"] is None
    assert result["pattern"] == "unknown"
    assert result["delay_source"] == "not_read"


def test_control_model_does_not_read_not_determined_as_governance(tmp_path):
    """``has_timelock is True``, not truthiness: a not-determined timelock must
    not silently promote the contract to ``governance``, and must not silently
    demote it either -- it falls through to the semantic pattern."""
    semantic = {"pattern": "role_control"}
    assert _determine_control_model(None, semantic, {"has_timelock": True}) == "governance"
    assert _determine_control_model(None, semantic, {"has_timelock": None}) == "role_control"
    assert _determine_control_model(None, semantic, {"has_timelock": False}) == "role_control"
