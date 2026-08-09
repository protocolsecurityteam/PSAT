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

**Clearing a mark is token-scoped, not time-scoped.** The loop deletes the queue
row only while its ``dirty_at`` still EQUALS the value read at selection, so a
mark that arrives during the fold survives and re-fires. An instant comparison
would not do: ``now()`` is ``transaction_timestamp()`` and the effects stage is
ONE long transaction, so its mark is stamped minutes before the data it
describes becomes visible — a ``dirty_at <= read_at`` clear would delete marks
for writes the fold never saw. Losing an invalidation with no trace is the one
failure mode a dirty-flag design has, and equality is immune to clock semantics
rather than merely careful about them.

**A failing protocol backs off.** Marks survive a failed fold on purpose and
dirty rows sort first, so without ``attempts``/``last_failed_at`` a pass-budget
of poison protocols would hold the loop forever and the staleness sweep — the
only cover for the §4 invalidation events that carry no mark — would never run.
The accepted cost is stated rather than hidden: a TRANSIENT fold failure delays
a real invalidation by that protocol's current backoff, up to
``DEFAULT_RETRY_BACKOFF_CAP_S`` — deliberately set to the staleness ceiling, so
the worst case is no worse than a protocol nobody marked at all.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Event
from typing import Any

from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.queue import HEARTBEAT_PROTOCOL_SCORE, record_heartbeat
from services.monitoring import emit_monitor_cycle
from services.scoring.dirty import SCORE_DIRTY_STALENESS_SWEEP
from services.scoring.distill import load_protocol_universe
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
# Poison backoff: a failed protocol waits ``base * 2**attempts``, capped. Marks
# survive a failed fold on purpose, and dirty rows sort ahead of stale ones, so
# without this a full pass-budget of permanently-failing protocols would hold
# the loop forever and the sweep would never reach anything.
DEFAULT_RETRY_BACKOFF_S = int(os.getenv("PSAT_SCORE_RETRY_BACKOFF_S", "300"))
DEFAULT_RETRY_BACKOFF_CAP_S = int(os.getenv("PSAT_SCORE_RETRY_BACKOFF_CAP_S", "21600"))
# Consecutive failures after which the protocol is called out by name. Backing
# off silently forever would turn a broken fold into an invisible one.
DEFAULT_POISON_WARN_AFTER = int(os.getenv("PSAT_SCORE_POISON_WARN_AFTER", "5"))


@dataclass(frozen=True)
class DueProtocol:
    """One protocol selected for a fold, and why.

    ``dirty_at`` is the queue row's value AT SELECTION and is the token the
    clear compares against — carried on the selection rather than re-read at
    clear time, because re-reading would pick up a mark that landed during the
    fold and delete it as though this fold had covered it. ``None`` on the
    staleness arm: no mark was consumed, so there is nothing to clear.
    """

    protocol_id: int
    trigger: str
    reason: str | None = None
    dirty_at: datetime | None = None


@dataclass
class PassCounters:
    considered: int = 0
    dirty: int = 0
    stale: int = 0
    scored: int = 0
    failures: int = 0
    marks_cleared: int = 0
    notes: list[str] = field(default_factory=list)


def _retry_ready(backoff_base_s: int, backoff_cap_s: int) -> Any:
    """SQL predicate: this queue row's backoff has elapsed (or it never failed).

    ``base * 2**attempts``, capped. Exponential rather than fixed so a protocol
    that is broken rather than merely unlucky stops competing for pass slots
    quickly, and capped so it never stops being retried altogether — a fold that
    starts working again must be able to prove it.
    """
    from db.models import ProtocolScoreQueue

    backoff_s = func.least(
        func.power(2.0, ProtocolScoreQueue.attempts) * float(backoff_base_s),
        float(backoff_cap_s),
    )
    return or_(
        ProtocolScoreQueue.last_failed_at.is_(None),
        ProtocolScoreQueue.last_failed_at + backoff_s * text("interval '1 second'") <= func.now(),
    )


def select_due_protocols(
    session: Session,
    *,
    limit: int = DEFAULT_PROTOCOLS_PER_PASS,
    now: datetime | None = None,
    max_age_s: int = DEFAULT_MAX_SCORE_AGE_S,
    backoff_base_s: int = DEFAULT_RETRY_BACKOFF_S,
    backoff_cap_s: int = DEFAULT_RETRY_BACKOFF_CAP_S,
) -> list[DueProtocol]:
    """Dirty protocols first, then the stalest scores, ``NULLS FIRST``.

    Two orderings on purpose, in this order: a dirty mark is a *witnessed*
    change to a scored input, while staleness is only the possibility of one.
    Serving the witnessed work first is what keeps a busy protocol's score
    fresh when the pass budget binds. Both queries carry a total ORDER BY so a
    pass is reproducible.

    A protocol already selected as dirty is excluded from the staleness arm —
    without that it would take two of the pass's slots and fold twice.

    A protocol still inside its failure backoff is not selected by EITHER arm.
    The dirty filter is in SQL rather than in Python because the point is to
    free the pass SLOT, not merely to skip the fold — filtering after the
    ``LIMIT`` would let poison rows keep consuming the budget they were backed
    off from. The staleness arm honours the same predicate because a protocol
    whose fold raises has no score row, so it is permanently stale: without it a
    poison protocol would simply re-enter through the other door.
    """
    from db.models import Protocol, ProtocolScoreLatest, ProtocolScoreQueue

    if limit <= 0:
        return []
    now = now or datetime.now(timezone.utc)

    retry_ready = _retry_ready(backoff_base_s, backoff_cap_s)
    dirty_rows = session.execute(
        select(ProtocolScoreQueue.protocol_id, ProtocolScoreQueue.reason, ProtocolScoreQueue.dirty_at)
        .where(retry_ready)
        .order_by(ProtocolScoreQueue.dirty_at.asc(), ProtocolScoreQueue.protocol_id.asc())
        .limit(limit)
    ).all()
    due = [DueProtocol(int(pid), SCORE_TRIGGER_DIRTY_LOOP, reason, dirty_at) for pid, reason, dirty_at in dirty_rows]
    if len(due) >= limit:
        return due

    seen = {d.protocol_id for d in due}
    cutoff = now - timedelta(seconds=max_age_s)
    stale = session.execute(
        select(Protocol.id)
        .outerjoin(ProtocolScoreLatest, ProtocolScoreLatest.protocol_id == Protocol.id)
        .outerjoin(ProtocolScoreQueue, ProtocolScoreQueue.protocol_id == Protocol.id)
        .where(
            # NULLS FIRST as an ordering is not enough on its own: a protocol
            # that has never been scored must also PASS the age filter, and
            # ``computed_at < cutoff`` is false for NULL.
            (ProtocolScoreLatest.computed_at.is_(None)) | (ProtocolScoreLatest.computed_at < cutoff)
        )
        .where(or_(ProtocolScoreQueue.protocol_id.is_(None), retry_ready))
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


def _clear_mark(session: Session, due: DueProtocol) -> int:
    """Delete the exact queue row this fold consumed. Nothing else.

    Matched on ``(protocol_id, dirty_at)`` by EQUALITY, against the value read
    at selection. Any mark that landed since — including one whose data this
    fold could not have seen — has a different ``dirty_at`` and is left alone.

    An instant-based ``dirty_at <= read_at`` cannot do this: ``now()`` is
    ``transaction_timestamp()``, and the end-of-effects mark is stamped at its
    job transaction's START, minutes before that transaction commits and makes
    the data visible. A loop that captured its own ``now()`` in between would
    delete a mark strictly newer than everything it read.

    Returns 0 on the staleness arm, which consumed no mark to begin with.
    """
    from db.models import ProtocolScoreQueue

    if due.dirty_at is None:
        return 0
    return int(
        session.query(ProtocolScoreQueue)
        .filter(
            ProtocolScoreQueue.protocol_id == due.protocol_id,
            ProtocolScoreQueue.dirty_at == due.dirty_at,
        )
        .delete(synchronize_session=False)
    )


def _reset_backoff(session: Session, protocol_id: int) -> None:
    """Clear the failure state of a queue row that outlived a SUCCESSFUL fold.

    A no-op unless the row was actually carrying failures. Without it a protocol
    that failed, then started folding again, would keep serving its old backoff
    — and a fold that has begun working must be able to prove it.
    """
    from db.models import ProtocolScoreQueue

    session.query(ProtocolScoreQueue).filter(
        ProtocolScoreQueue.protocol_id == protocol_id,
        ProtocolScoreQueue.attempts > 0,
    ).update({"attempts": 0, "last_failed_at": None}, synchronize_session=False)


def _record_failure(session: Session, due: DueProtocol, *, warn_after: int) -> None:
    """Arm the backoff for a protocol whose fold raised. Commits its own write.

    UPSERTS rather than updating: a protocol selected by the staleness arm has
    no queue row, and a failed fold leaves it with no score row either — so it
    is permanently stale and would be re-selected on every pass forever. The row
    minted here is the only place that failure can be remembered. It is an
    honest mark besides: the protocol does still need a fold.

    Runs after the caller rolled the failed fold back, so it needs its own
    commit — and it must not raise into the pass, because the whole point is
    that the pass continues.
    """
    from db.models import ProtocolScoreQueue

    try:
        session.execute(
            pg_insert(ProtocolScoreQueue)
            .values(
                protocol_id=due.protocol_id,
                # One vocabulary for the column: a row minted by a staleness
                # failure names itself from the same register the mark sites use.
                reason=due.reason or SCORE_DIRTY_STALENESS_SWEEP,
                attempts=1,
                last_failed_at=func.clock_timestamp(),
            )
            .on_conflict_do_update(
                index_elements=["protocol_id"],
                # ``dirty_at`` is deliberately untouched: it is the clearing
                # token and the sweep's cursor, and bumping it on a FAILURE
                # would move a protocol that achieved nothing to the back of a
                # queue ordered by when its work arrived.
                set_={
                    "attempts": ProtocolScoreQueue.attempts + 1,
                    "last_failed_at": func.clock_timestamp(),
                },
            )
        )
        session.commit()
        attempts = int(
            session.execute(
                select(ProtocolScoreQueue.attempts).where(ProtocolScoreQueue.protocol_id == due.protocol_id)
            ).scalar()
            or 0
        )
        if attempts >= warn_after:
            logger.warning(
                "protocol score fold has failed %d consecutive times; it is now in backoff",
                attempts,
                extra={"protocol_id": due.protocol_id, "attempts": attempts, "reason": due.reason},
            )
    except Exception:
        session.rollback()
        logger.warning(
            "protocol score backoff bookkeeping failed", exc_info=True, extra={"protocol_id": due.protocol_id}
        )


def score_protocol(session: Session, due: DueProtocol) -> Any:
    """Fold, persist, and clear the mark this fold consumed. Commits.

    ``computed_at`` comes from the DATABASE clock, not the process clock: it is
    what ``protocol_scores_latest`` orders on, and two writers on skewed hosts
    would otherwise be able to order a stale fold ahead of a fresh one. The fold
    bans wall-clock reads internally, so the one timestamp it cannot derive is
    supplied here.
    """
    computed_at = session.execute(select(func.clock_timestamp())).scalar_one()
    # Assembled before the fold because it reads object storage and the fold's
    # planes may not. ``None`` is the fail-closed answer to an unreadable source
    # artifact and disposes nothing.
    universe = load_protocol_universe(session, due.protocol_id)
    document = compute_protocol_score(
        session,
        due.protocol_id,
        trigger=due.trigger,
        computed_at=computed_at,
        universe=universe,
    )
    row = persist_score_document(session, document)
    cleared = _clear_mark(session, due)
    if not cleared:
        # A mark still standing after a SUCCESSFUL fold — either one that
        # arrived mid-fold, or one this protocol was carrying from the staleness
        # arm. Either way it must not inherit the attempt count of the failures
        # that preceded this success.
        _reset_backoff(session, due.protocol_id)
    try:
        session.commit()
    except Exception:
        # The other half of the orphan accounting in ``persist``: a spilled body
        # whose row never commits is an object nothing names.
        if row.storage_key:
            logger.warning(
                "protocol score document orphaned in object storage: commit failed",
                extra={"protocol_id": due.protocol_id, "storage_key": row.storage_key},
            )
        raise
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
    warn_after: int = DEFAULT_POISON_WARN_AFTER,
    backoff_base_s: int = DEFAULT_RETRY_BACKOFF_S,
    backoff_cap_s: int = DEFAULT_RETRY_BACKOFF_CAP_S,
) -> PassCounters:
    """One pass: select, fold each, emit exactly one cycle summary."""
    started = time.monotonic()
    counters = PassCounters()
    due = select_due_protocols(
        session,
        limit=limit,
        max_age_s=max_age_s,
        backoff_base_s=backoff_base_s,
        backoff_cap_s=backoff_cap_s,
    )
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
            # next pass rather than be silently dropped from the queue. What it
            # does NOT keep is its place at the front — the backoff is what
            # stops a poison row from holding a pass slot forever.
            session.rollback()
            _record_failure(session, item, warn_after=warn_after)
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
    "DEFAULT_POISON_WARN_AFTER",
    "DEFAULT_PROTOCOLS_PER_PASS",
    "DEFAULT_RETRY_BACKOFF_CAP_S",
    "DEFAULT_RETRY_BACKOFF_S",
    "DEFAULT_SCORE_INTERVAL",
    "DueProtocol",
    "PassCounters",
    "run_score_loop",
    "score_due_protocols",
    "score_protocol",
    "select_due_protocols",
]
