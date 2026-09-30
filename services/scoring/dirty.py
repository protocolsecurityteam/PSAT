"""The score's invalidation mark: one upsert that never fails its host.

The grade is a whole-protocol fold, so producers only say "the protocol changed". A mark is a hint: the staleness sweep
in ``services.scoring.loop`` re-folds protocols whose mark was lost, so a dropped mark costs latency while a raise would
fail an effects job. Hence :func:`mark_protocol_score_dirty` swallows and logs.

Like ``services.monitoring.enrollment.mark_enrollment_dirty``, it doesn't commit.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# The enqueuing write site. Documentation, not enforcement (like ``ENROLLMENT_DIRTY_REASONS``).
SCORE_DIRTY_EFFECTS = "effects_distillation"
SCORE_DIRTY_COVERAGE = "coverage_refresh"
SCORE_DIRTY_COVERAGE_VERIFY = "coverage_equivalence_flip"
SCORE_DIRTY_REANALYSIS = "reanalysis_queued"
SCORE_DIRTY_MANUAL = "manual"
SCORE_DIRTY_MEMBERSHIP = "membership_change"
# Written by the loop itself when a sweep-selected protocol fails to fold and needs a queue row for backoff; listed so
# the column has one vocabulary.
SCORE_DIRTY_STALENESS_SWEEP = "staleness_sweep"
SCORE_DIRTY_REASONS = frozenset(
    {
        SCORE_DIRTY_EFFECTS,
        SCORE_DIRTY_COVERAGE,
        SCORE_DIRTY_COVERAGE_VERIFY,
        SCORE_DIRTY_REANALYSIS,
        SCORE_DIRTY_MANUAL,
        SCORE_DIRTY_MEMBERSHIP,
        SCORE_DIRTY_STALENESS_SWEEP,
    }
)


def mark_protocol_score_dirty(session: Session, protocol_id: Any, reason: str) -> bool:
    """Enqueue *protocol_id* for a re-fold. Returns whether the mark was written.

    Bumps ``dirty_at`` so repeated marks fold once. Doesn't commit. Returns ``False`` on failure rather than raising;
    the sweep is the backstop.
    """
    from db.models import ProtocolScoreQueue

    if not isinstance(protocol_id, int):
        return False
    # Flush before the guard: ``begin_nested`` flushes anyway, and a flush failure is the caller's own work failing, not
    # a dirty-mark failure.
    session.flush()
    try:
        # A savepoint is required: a failed statement aborts the whole Postgres transaction, leaving the caller unable
        # to commit.
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
