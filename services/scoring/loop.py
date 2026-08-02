"""The protocol-score loop: the sixth supervised thread in ``protocol_monitor``.

The grade is a whole-protocol fold and cannot live in the effects worker
(strategy §2): effects runs single-flight behind a process-global anvil, the
perimeter is not settled at any per-job instant, and audit coverage settles
*after* effects. So the fold runs here, off the critical path, on a dirty-mark
with a staleness sweep behind it.

**Perimeter — compute and stamp, never defer (ruled).** A protocol with queued
or processing jobs is scored anyway and the document carries
``perimeter_state = unsettled``; a mid-run score is a real fact about a partial
perimeter, and witness discipline says publish it labelled rather than suppress
it. Deferring would leave the endpoint empty for hours on a long run. The state
is decided inside the fold (``services.scoring.planes.perimeter_state``) because
it must be read in the same transaction as the population it describes — this
module persists it verbatim and never re-derives it.

**Clearing a mark is time-scoped, not protocol-scoped.** The loop deletes only
queue rows whose ``dirty_at`` predates the instant it read the population. A
mark that lands while the fold is running describes a change the fold did not
see, so clearing it would lose an invalidation with no trace — the one failure
mode a dirty-flag design has.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Event
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.queue import HEARTBEAT_PROTOCOL_SCORE, record_heartbeat
from services.monitoring import emit_monitor_cycle
from services.scoring.fold import compute_protocol_score
from services.scoring.persist import persist_score_document
from utils.scoring_status import SCORE_TRIGGER_DIRTY_LOOP, SCORE_TRIGGER_STALENESS_SWEEP

logger = logging.getLogger(__name__)

DEFAULT_SCORE_INTERVAL = int(os.getenv("PSAT_SCORE_INTERVAL", "300"))
# Protocols folded per pass. The fold is seconds at this corpus, but it is N
# queries against planes other loops are also reading, so the pass is bounded
# rather than draining the whole queue at once.
DEFAULT_PROTOCOLS_PER_PASS = int(os.getenv("PSAT_SCORE_PROTOCOLS_PER_PASS", "10"))
# How long a score may stand before the sweep re-folds it regardless of marks.
# The backstop for the write sites §4 enumerates that carry no mark (hourly
# balance rows, TVL snapshots, upgrade indexing) — every one of them moves a
# scored number without touching a marking path.
DEFAULT_MAX_SCORE_AGE_S = int(os.getenv("PSAT_SCORE_MAX_AGE_S", "21600"))


@dataclass(frozen=True)
class DueProtocol:
    """One protocol selected for a fold, and why."""

    protocol_id: int
    trigger: str
    reason: str | None = None


@dataclass
class PassCounters:
    considered: int = 0
    dirty: int = 0
    stale: int = 0
    scored: int = 0
    failures: int = 0
    marks_cleared: int = 0
    notes: list[str] = field(default_factory=list)


def select_due_protocols(
    session: Session,
    *,
    limit: int = DEFAULT_PROTOCOLS_PER_PASS,
    now: datetime | None = None,
    max_age_s: int = DEFAULT_MAX_SCORE_AGE_S,
) -> list[DueProtocol]:
    """Dirty protocols first, then the stalest scores, ``NULLS FIRST``.

    Two orderings on purpose, in this order: a dirty mark is a *witnessed*
    change to a scored input, while staleness is only the possibility of one.
    Serving the witnessed work first is what keeps a busy protocol's score
    fresh when the pass budget binds. Both queries carry a total ORDER BY so a
    pass is reproducible.

    A protocol already selected as dirty is excluded from the staleness arm —
    without that it would take two of the pass's slots and fold twice.
    """
    from db.models import Protocol, ProtocolScoreLatest, ProtocolScoreQueue

    if limit <= 0:
        return []
    now = now or datetime.now(timezone.utc)

    dirty_rows = session.execute(
        select(ProtocolScoreQueue.protocol_id, ProtocolScoreQueue.reason)
        .order_by(ProtocolScoreQueue.dirty_at.asc(), ProtocolScoreQueue.protocol_id.asc())
        .limit(limit)
    ).all()
    due = [DueProtocol(int(pid), SCORE_TRIGGER_DIRTY_LOOP, reason) for pid, reason in dirty_rows]
    if len(due) >= limit:
        return due

    seen = {d.protocol_id for d in due}
    cutoff = now - timedelta(seconds=max_age_s)
    stale = session.execute(
        select(Protocol.id)
        .outerjoin(ProtocolScoreLatest, ProtocolScoreLatest.protocol_id == Protocol.id)
        .where(
            # NULLS FIRST as an ordering is not enough on its own: a protocol
            # that has never been scored must also PASS the age filter, and
            # ``computed_at < cutoff`` is false for NULL.
            (ProtocolScoreLatest.computed_at.is_(None)) | (ProtocolScoreLatest.computed_at < cutoff)
        )
        .order_by(ProtocolScoreLatest.computed_at.asc().nullsfirst(), Protocol.id.asc())
        .limit(limit + len(seen))
    ).scalars()
    for pid in stale:
        if len(due) >= limit:
            break
        if int(pid) in seen:
            continue
        due.append(DueProtocol(int(pid), SCORE_TRIGGER_STALENESS_SWEEP))
    return due


def _clear_marks(session: Session, protocol_id: int, read_at: datetime) -> int:
    """Delete this protocol's mark iff it predates the population read.

    ``read_at`` is captured from the DATABASE clock before the fold reads
    anything, so the comparison is against the same clock the mark was stamped
    by. A mark that arrived after it survives and re-fires next pass.
    """
    from db.models import ProtocolScoreQueue

    return int(
        session.query(ProtocolScoreQueue)
        .filter(
            ProtocolScoreQueue.protocol_id == protocol_id,
            ProtocolScoreQueue.dirty_at <= read_at,
        )
        .delete(synchronize_session=False)
    )


def score_protocol(session: Session, due: DueProtocol) -> Any:
    """Fold, persist, and clear the marks this fold accounted for. Commits.

    ``computed_at`` is passed in from the call site: the fold bans wall-clock
    reads internally so the same DB state yields a byte-identical document, and
    the one timestamp it cannot derive has to come from outside.
    """
    read_at = session.execute(select(func.now())).scalar_one()
    computed_at = datetime.now(timezone.utc)
    document = compute_protocol_score(
        session,
        due.protocol_id,
        trigger=due.trigger,
        computed_at=computed_at,
    )
    row = persist_score_document(session, document)
    cleared = _clear_marks(session, due.protocol_id, read_at)
    session.commit()
    logger.info(
        "protocol score written",
        extra={
            "protocol_id": due.protocol_id,
            "trigger": due.trigger,
            "grade_state": document.grade_state,
            "perimeter_state": document.perimeter_state,
            "findings": len(document.findings),
            "marks_cleared": cleared,
            "spilled": row.storage_key is not None,
        },
    )
    return row


def score_due_protocols(
    session: Session,
    *,
    limit: int = DEFAULT_PROTOCOLS_PER_PASS,
    max_age_s: int = DEFAULT_MAX_SCORE_AGE_S,
) -> PassCounters:
    """One pass: select, fold each, emit exactly one cycle summary."""
    started = time.monotonic()
    counters = PassCounters()
    due = select_due_protocols(session, limit=limit, max_age_s=max_age_s)
    counters.considered = len(due)
    counters.dirty = sum(1 for d in due if d.trigger == SCORE_TRIGGER_DIRTY_LOOP)
    counters.stale = counters.considered - counters.dirty

    for item in due:
        try:
            score_protocol(session, item)
            counters.scored += 1
        except Exception as exc:
            # One protocol's fold failing is not evidence about any other, and
            # its mark deliberately stays: an unscored protocol must re-select
            # next pass rather than be silently dropped from the queue.
            session.rollback()
            counters.failures += 1
            counters.notes.append("fold_error")
            logger.warning(
                "protocol score fold failed",
                exc_info=True,
                extra={"protocol_id": item.protocol_id, "trigger": item.trigger, "exc_type": type(exc).__name__},
            )

    emit_monitor_cycle(
        HEARTBEAT_PROTOCOL_SCORE,
        started=started,
        contracts_scanned=counters.considered,
        # A fold reads planes, not a block range; 0 under-claims rather than
        # inventing a span.
        blocks_scanned=0,
        events_found=counters.scored,
        partial=counters.failures > 0,
        note=";".join(sorted(set(counters.notes))) or None,
        extra_detail={
            "protocols_due": counters.considered,
            "protocols_dirty": counters.dirty,
            "protocols_stale": counters.stale,
            "protocols_scored": counters.scored,
            "protocols_failed": counters.failures,
        },
    )
    return counters


def run_score_loop(interval: float = DEFAULT_SCORE_INTERVAL, stop_event: Event | None = None) -> None:
    """Run the protocol-score fold until *stop_event* is set."""
    from db.models import SessionLocal

    stop_event = stop_event or Event()
    logger.info("Starting protocol score loop (interval=%ss)", interval)
    while not stop_event.is_set():
        try:
            with SessionLocal() as session:
                score_due_protocols(session)
        except Exception as exc:
            logger.warning("protocol score cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
            # The pass raised before it could emit its own summary — still beat,
            # so a wedged loop is visible on /api/fleet rather than silent.
            record_heartbeat(
                HEARTBEAT_PROTOCOL_SCORE,
                status="degraded",
                detail={"partial": True, "note": "cycle_error", "exc_type": type(exc).__name__},
            )
        stop_event.wait(interval)


__all__ = [
    "DEFAULT_MAX_SCORE_AGE_S",
    "DEFAULT_PROTOCOLS_PER_PASS",
    "DEFAULT_SCORE_INTERVAL",
    "DueProtocol",
    "PassCounters",
    "run_score_loop",
    "score_due_protocols",
    "score_protocol",
    "select_due_protocols",
]
