"""Per-controller markers for scan-pass verification reads that did not answer.

A hint read has three outcomes: the value moved (a ``value_changed`` event), it did not (published as nothing), or the
read never answered (not determined, which must stay visible). Markers live in ``last_poll_status`` under the
controller's field, and the poller overwrites that map on every answered pass, so they are an ops signal, not history.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import MonitoredContract

# The node answered this call with an error (e.g. a revert): a negative about the call, never the value.
VERIFY_ERROR = "verify_error"
# The batch was never answered.
VERIFY_UNANSWERED = "verify_unanswered"
# Answered, but nothing parses as the entry's declared type.
VERIFY_NO_VALUE = "verify_no_value"
# Dirty but out of read budget; a skipped read is not a negative.
VERIFY_OVER_BUDGET = "verify_over_budget"
# Hint with no polling entry proven to read its controller: nothing could be attempted.
VERIFY_NO_READ_BINDING = "verify_no_read_binding"

VERIFY_FAILURE_STATUSES = frozenset({VERIFY_ERROR, VERIFY_UNANSWERED, VERIFY_NO_VALUE})
VERIFY_SKIP_STATUSES = frozenset({VERIFY_OVER_BUDGET, VERIFY_NO_READ_BINDING})
VERIFY_STATUSES = VERIFY_FAILURE_STATUSES | VERIFY_SKIP_STATUSES

# Prefix so controller keys can't collide with the poller's field keys.
CONTROLLER_STATUS_PREFIX = "controller:"


def record_verify_status(mc: MonitoredContract, field: str | None, status: str) -> bool:
    """Stamp *status* for *field*; returns whether a marker was written (nothing without a field name)."""
    if not isinstance(field, str) or not field or status not in VERIFY_STATUSES:
        return False
    current = dict(mc.last_poll_status or {})
    current[field] = status
    mc.last_poll_status = current
    return True


def record_unresolvable_read(mc: MonitoredContract, controller_id: str | None) -> bool:
    """Record, keyed by controller, that a hint has no bound read; returns False if already recorded.

    The no-op matters: unbound controllers emit often, and re-stamping would UPDATE ``monitored_contracts`` every window
    inside the scanner's cursor transaction, the documented deadlock with the poller.
    """
    if not isinstance(controller_id, str) or not controller_id:
        return False
    key = f"{CONTROLLER_STATUS_PREFIX}{controller_id}"
    current = dict(mc.last_poll_status or {})
    if current.get(key) == VERIFY_NO_READ_BINDING:
        return False
    current[key] = VERIFY_NO_READ_BINDING
    mc.last_poll_status = current
    return True


# The counts are of markers present at read time; a 0 is not proof no read failed since the last poll.
CENSUS_BASIS = "current_markers"


def count_verification_read_gaps(session: Session) -> dict[str, Any]:
    """Fleet census of verification-read markers, by bucket, plus ``contracts_affected``.

    Buckets stay separate because they are different facts: over-budget is capacity, a failed read is the chain or plan,
    a missing binding is the analysis. A zero is not an earned negative; the scanner heartbeat's per-pass counters are
    the complement.
    """
    rows = session.execute(
        select(MonitoredContract.last_poll_status).where(MonitoredContract.is_active == True)  # noqa: E712
    ).scalars()

    read_failed = 0
    over_budget = 0
    no_read_binding = 0
    contracts_affected = 0
    for status_map in rows:
        if not isinstance(status_map, dict):
            continue
        failed = sum(1 for v in status_map.values() if v in VERIFY_FAILURE_STATUSES)
        skipped = sum(1 for v in status_map.values() if v == VERIFY_OVER_BUDGET)
        unbound = sum(1 for v in status_map.values() if v == VERIFY_NO_READ_BINDING)
        if failed or skipped or unbound:
            contracts_affected += 1
        read_failed += failed
        over_budget += skipped
        no_read_binding += unbound
    return {
        "read_failed": read_failed,
        "over_budget": over_budget,
        "no_read_binding": no_read_binding,
        "contracts_affected": contracts_affected,
        "basis": CENSUS_BASIS,
    }
