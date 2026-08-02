"""The score's invalidation mark — one upsert, and it never fails its host.

The grade is a whole-protocol fold (strategy §0): value is MAX per entity,
principal units are cross-contract and re-key under new evidence, and
subsumption needs every row present. None of that can be accumulated one
contract at a time, so the pipeline's half of the contract is not "add your
contribution" but "say the protocol changed" — this module.

**A mark is a hint, never a fact the score rests on.** Every mark site is
wrapped so a queue write cannot fail the operation that triggered it: the
staleness sweep in ``services.scoring.loop`` re-folds a protocol whose mark was
lost, so the cost of a dropped mark is latency, and the cost of a raise would be
a failed effects job or a lost coverage verdict. That asymmetry is why
:func:`mark_protocol_score_dirty` swallows and logs.

Follows ``services.monitoring.enrollment.mark_enrollment_dirty``: does not
commit, so the mark lands atomically with (or right after) the write that
triggered it, and the caller decides which.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# The write site that enqueued the protocol. Documentation, not enforcement —
# same posture as ``ENROLLMENT_DIRTY_REASONS``.
SCORE_DIRTY_EFFECTS = "effects_distillation"
SCORE_DIRTY_COVERAGE = "coverage_refresh"
SCORE_DIRTY_COVERAGE_VERIFY = "coverage_equivalence_flip"
SCORE_DIRTY_REANALYSIS = "reanalysis_queued"
SCORE_DIRTY_MANUAL = "manual"
# Not a mark site: the loop writes this itself when a protocol selected by the
# staleness sweep FAILS to fold, because a failure needs a queue row to hold its
# backoff and that row's reason must come from the same vocabulary as every
# other. Listed here so the column has one vocabulary rather than two.
SCORE_DIRTY_STALENESS_SWEEP = "staleness_sweep"
SCORE_DIRTY_REASONS = frozenset(
    {
        SCORE_DIRTY_EFFECTS,
        SCORE_DIRTY_COVERAGE,
        SCORE_DIRTY_COVERAGE_VERIFY,
        SCORE_DIRTY_REANALYSIS,
        SCORE_DIRTY_MANUAL,
        SCORE_DIRTY_STALENESS_SWEEP,
    }
)


def mark_protocol_score_dirty(session: Session, protocol_id: Any, reason: str) -> bool:
    """Enqueue *protocol_id* for a re-fold. Returns whether the mark was written.

    One upsert that bumps ``dirty_at`` to now(), so a protocol marked twenty
    times between two passes is folded once. Does not commit.

    Returns ``False`` rather than raising when the write fails: the caller is a
    producer whose own work is already done and correct, and the sweep is the
    backstop. The boolean is there so a caller that wants to log the difference
    can, not so it can treat a missing mark as evidence of anything.
    """
    from db.models import ProtocolScoreQueue

    if not isinstance(protocol_id, int):
        return False
    # Flushed BEFORE the guard, not inside it. ``begin_nested`` flushes
    # unconditionally, and a flush failure is the caller's own pending work
    # failing — it would raise at commit regardless, so letting it through here
    # keeps it from being logged as a dirty-mark failure it is not.
    session.flush()
    try:
        # SAVEPOINT, not a bare try: a failed statement aborts the whole
        # Postgres transaction, so swallowing the Python exception without one
        # would leave the caller holding a transaction that can no longer
        # commit — the mark would then fail its host by a different route.
        with session.begin_nested():
            session.execute(
                pg_insert(ProtocolScoreQueue)
                .values(protocol_id=protocol_id, reason=reason)
                .on_conflict_do_update(
                    index_elements=["protocol_id"],
                    set_={"dirty_at": func.now(), "reason": reason},
                )
            )
    except Exception:
        # Never the caller's problem: the staleness sweep re-folds this
        # protocol regardless, so a lost mark costs latency and nothing else.
        logger.warning(
            "protocol score dirty-mark failed",
            exc_info=True,
            extra={"protocol_id": protocol_id, "reason": reason},
        )
        return False
    return True


__all__ = [
    "SCORE_DIRTY_COVERAGE",
    "SCORE_DIRTY_COVERAGE_VERIFY",
    "SCORE_DIRTY_EFFECTS",
    "SCORE_DIRTY_MANUAL",
    "SCORE_DIRTY_REANALYSIS",
    "SCORE_DIRTY_REASONS",
    "SCORE_DIRTY_STALENESS_SWEEP",
    "mark_protocol_score_dirty",
]
