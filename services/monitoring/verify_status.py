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

``count_verification_read_gaps`` is the F9b counter, published on the F9a
surface as ``watchers.verification_gaps`` (``services/aggregations/fleet.py``)
and collected by ``ops_alerts.collect_verification_gaps``. Because of that
lifetime it is a **census of the markers present when it runs**, not a tally of
what happened — see the function's own contract, and the scanner heartbeat's
pass-scoped counters (``verification_reads_failed`` /
``verification_reads_over_budget``) for the complement that does not depend on a
marker surviving.
"""

from __future__ import annotations

from typing import Any

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
# The spec classified as hint but no polling entry is PROVEN to read its
# controller, so the hint resolves to nothing at all. Distinct from a failed
# read: nothing was attempted, and nothing could have been.
VERIFY_NO_READ_BINDING = "verify_no_read_binding"

VERIFY_FAILURE_STATUSES = frozenset({VERIFY_ERROR, VERIFY_UNANSWERED, VERIFY_NO_VALUE})
VERIFY_SKIP_STATUSES = frozenset({VERIFY_OVER_BUDGET, VERIFY_NO_READ_BINDING})
VERIFY_STATUSES = VERIFY_FAILURE_STATUSES | VERIFY_SKIP_STATUSES

# Controller-keyed entries live under this prefix so they cannot collide with
# a polling entry's ``field`` key, which is what the poller owns.
CONTROLLER_STATUS_PREFIX = "controller:"


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


def record_unresolvable_read(mc: MonitoredContract, controller_id: str | None) -> bool:
    """Record that a hint could not be resolved because no read is bound to
    *controller_id*.

    Keyed on the controller rather than a polling field, because the absence of
    a bound entry is exactly why there is no field name to key on. One key per
    controller, so repeat occurrences do not grow the map.

    Returns False — writing nothing — when the marker is already recorded. This
    is called once per unbound hint OCCURRENCE, and an unbound controller is
    usually one whose events are frequent (that is why it was hinted at all),
    so re-stamping an identical value would emit a ``monitored_contracts``
    UPDATE on every window forever, inside the same transaction that carries
    the scanner's cursor UPDATE — the documented deadlock counterpart to the
    poller. The state is idempotent, so the second write says nothing the first
    did not.
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


#: What the counts below are counts OF, carried in the payload rather than only
#: in this docstring: the markers a read of ``last_poll_status`` finds AT THAT
#: INSTANT. The poller rewrites that map wholesale on every answered pass, so a
#: bucket at 0 means "no marker is present now" — it is not proof that no
#: verification read failed or was skipped since the last poll.
CENSUS_BASIS = "current_markers"


def count_verification_read_gaps(session: Session) -> dict[str, Any]:
    """Fleet census of verification reads that produced no observation (F9b).

    Three buckets, all counting KEYS, plus ``contracts_affected`` counting
    distinct contracts carrying at least one. They stay apart because they are
    different facts about different things: an over-budget skip is a capacity
    fact about this deployment, a failed read is a fact about the chain or the
    plan, and a missing read binding is a fact about the analysis — the
    controller was classified readable at enrollment but no polling entry is
    proven to read it.

    **A zero here is not an earned negative.** The numbers are a point-in-time
    marker census (``basis``), and markers live only until the poller's next
    answered pass over the contract, so an intermittent failure is routinely
    erased before anyone reads this. The per-pass counters on the scanner
    heartbeat are what state how many reads failed or were skipped in a given
    pass; the two are complements and neither substitutes for the other.
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
