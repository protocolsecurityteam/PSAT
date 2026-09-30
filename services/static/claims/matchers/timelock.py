"""OZ TimelockController per-selector claims, on the timelock gate.

``execute``/``executeBatch`` also carry ``exec.arbitrary``.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from ._gates import (
    TIMELOCK_CANCEL,
    TIMELOCK_EXECUTE_SELECTORS,
    TIMELOCK_SCHEDULE_SELECTORS,
    TIMELOCK_UPDATE_DELAY,
    is_oz_timelock_gate,
)


def _timelock_evidence(selector: str) -> ClaimEvidence:
    return ClaimEvidence(
        tier="standard_exact",
        witness={"kind": "selector+gate", "standard": "oz_timelock", "selector": selector},
    )


@claim_matcher(
    claim_id="timelock.schedule",
    sentence="schedules a timelocked operation",
    legacy_projection="timelock_operation",
    consumer_family="control_plane",
    gate=is_oz_timelock_gate,
)
def timelock_schedule(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    selector = ctx.canonical_selector(function)
    if selector is None or selector not in TIMELOCK_SCHEDULE_SELECTORS:
        return None
    return _timelock_evidence(selector)


@claim_matcher(
    claim_id="timelock.execute",
    sentence="executes a matured timelocked operation",
    legacy_projection="timelock_operation",
    consumer_family="control_plane",
    gate=is_oz_timelock_gate,
)
def timelock_execute(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    selector = ctx.canonical_selector(function)
    if selector is None or selector not in TIMELOCK_EXECUTE_SELECTORS:
        return None
    return _timelock_evidence(selector)


@claim_matcher(
    claim_id="timelock.cancel",
    sentence="cancels a scheduled timelocked operation",
    legacy_projection="timelock_operation",
    consumer_family="control_plane",
    gate=is_oz_timelock_gate,
)
def timelock_cancel(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if ctx.canonical_selector(function) != TIMELOCK_CANCEL:
        return None
    return _timelock_evidence(TIMELOCK_CANCEL)


@claim_matcher(
    claim_id="timelock.set_delay",
    sentence="changes the timelock minimum delay",
    legacy_projection="timelock_operation",
    consumer_family="control_plane",
    gate=is_oz_timelock_gate,
)
def timelock_set_delay(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if ctx.canonical_selector(function) != TIMELOCK_UPDATE_DELAY:
        return None
    return _timelock_evidence(TIMELOCK_UPDATE_DELAY)
