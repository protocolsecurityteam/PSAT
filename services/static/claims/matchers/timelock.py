"""OZ TimelockController per-selector claims (resurrects ``timelock_operation``).

The dead legacy label had 0 producers while 4 consumer branches waited on it.
Each entry rides the oz_timelock gate (getMinDelay + schedule + execute +
hashOperation) and matches its canonical entry name. ``execute``/``executeBatch``
additionally carry ``exec.arbitrary`` (forwarded target + calldata) from that
matcher.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from ._gates import function_name, is_oz_timelock_gate

_SCHEDULE_FUNCTIONS = frozenset({"schedule", "scheduleBatch"})
_EXECUTE_FUNCTIONS = frozenset({"execute", "executeBatch"})


def _timelock_evidence(function: str) -> ClaimEvidence:
    return ClaimEvidence(
        tier="standard_exact",
        witness={"kind": "selector+gate", "standard": "oz_timelock", "function": function_name(function)},
    )


@claim_matcher(
    claim_id="timelock.schedule",
    sentence="schedules a timelocked operation",
    legacy_projection="timelock_operation",
    consumer_family="control_plane",
    gate=is_oz_timelock_gate,
)
def timelock_schedule(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function_name(function) not in _SCHEDULE_FUNCTIONS:
        return None
    return _timelock_evidence(function)


@claim_matcher(
    claim_id="timelock.execute",
    sentence="executes a matured timelocked operation",
    legacy_projection="timelock_operation",
    consumer_family="control_plane",
    gate=is_oz_timelock_gate,
)
def timelock_execute(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function_name(function) not in _EXECUTE_FUNCTIONS:
        return None
    return _timelock_evidence(function)


@claim_matcher(
    claim_id="timelock.cancel",
    sentence="cancels a scheduled timelocked operation",
    legacy_projection="timelock_operation",
    consumer_family="control_plane",
    gate=is_oz_timelock_gate,
)
def timelock_cancel(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function_name(function) != "cancel":
        return None
    return _timelock_evidence(function)


@claim_matcher(
    claim_id="timelock.set_delay",
    sentence="changes the timelock minimum delay",
    legacy_projection="timelock_operation",
    consumer_family="control_plane",
    gate=is_oz_timelock_gate,
)
def timelock_set_delay(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function_name(function) != "updateDelay":
        return None
    return _timelock_evidence(function)
