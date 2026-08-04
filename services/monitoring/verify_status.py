"""Per-controller outcome markers for scan-pass verification reads (F2/F9b).

A hint occurrence resolves through one read per dirty controller. Three
outcomes are publishable facts and one is not:

  * the value moved            → a witnessed ``value_changed`` event;
  * the value did not move     → an earned negative, published as nothing;
  * the read did not happen or did not answer → **not determined**, and that
    third state has to be visible to an operator rather than dropped.

The last case is what this module carries. Markers are written into the
existing ``monitored_contracts.last_poll_status`` JSONB under the controller's
polling field, the same ``{field: outcome}`` shape the poller writes, so
nothing downstream needs a new column to see them.

Lifetime is deliberately that of the poll-status map: the poller overwrites it
wholesale on every answered pass, so a marker states "the most recent
observation of this field was a verification read that did not answer", not a
durable history. It is an ops signal, not evidence.

``count_verification_read_gaps`` is the F9b counter. It is self-contained on
purpose — the fleet/ops surfaces it feeds are owned by another lane and are
wired to it separately.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import MonitoredContract

# The node answered this specific call with an error (a revert on a getter the
# address does not expose). An earned per-call negative about the CALL — never
# about the value.
VERIFY_ERROR = "verify_error"
# The batch itself was never answered. Nothing was observed, including whether
# the call would have errored.
VERIFY_UNANSWERED = "verify_unanswered"
# Answered without error, but the body carried nothing that parses as the
# entry's declared type.
VERIFY_NO_VALUE = "verify_no_value"
# The controller was marked dirty but the pass ran out of read budget before
# reaching it. Recorded rather than dropped: a skipped read is not a negative.
VERIFY_OVER_BUDGET = "verify_over_budget"

VERIFY_FAILURE_STATUSES = frozenset({VERIFY_ERROR, VERIFY_UNANSWERED, VERIFY_NO_VALUE})
VERIFY_STATUSES = VERIFY_FAILURE_STATUSES | {VERIFY_OVER_BUDGET}


def record_verify_status(mc: MonitoredContract, field: str | None, status: str) -> bool:
    """Stamp *status* for *field* on the contract's poll-status map.

    Returns True when a marker was written. A missing field name means there is
    nowhere honest to record the outcome, so nothing is written.
    """
    if not isinstance(field, str) or not field or status not in VERIFY_STATUSES:
        return False
    current = dict(mc.last_poll_status or {})
    current[field] = status
    mc.last_poll_status = current
    return True


def count_verification_read_gaps(session: Session) -> dict[str, int]:
    """Fleet counts of verification reads that produced no observation (F9b).

    ``read_failed`` and ``over_budget`` count FIELDS, ``contracts_affected``
    counts distinct contracts carrying at least one of either. The two failure
    modes stay apart: an over-budget skip is a capacity fact about this
    deployment, a failed read is a fact about the chain or the plan.
    """
    rows = session.execute(
        select(MonitoredContract.last_poll_status).where(MonitoredContract.is_active == True)  # noqa: E712
    ).scalars()

    read_failed = 0
    over_budget = 0
    contracts_affected = 0
    for status_map in rows:
        if not isinstance(status_map, dict):
            continue
        failed = sum(1 for v in status_map.values() if v in VERIFY_FAILURE_STATUSES)
        skipped = sum(1 for v in status_map.values() if v == VERIFY_OVER_BUDGET)
        if failed or skipped:
            contracts_affected += 1
        read_failed += failed
        over_budget += skipped
    return {
        "read_failed": read_failed,
        "over_budget": over_budget,
        "contracts_affected": contracts_affected,
    }
