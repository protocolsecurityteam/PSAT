"""The protocol-score loop: the sixth supervised thread in ``protocol_monitor``.

The fold can't live in the effects worker (single-flight anvil, unsettled perimeter, audit coverage settles later), so
it runs here on dirty marks with a staleness sweep.

Perimeter: protocols with in-flight jobs are scored anyway and stamped ``perimeter_state = unsettled`` rather than
deferred. The state is decided in the fold (``services.scoring.planes.perimeter_state``) in the same transaction as the
population.

Marks are cleared by token equality on ``dirty_at``, not by time: ``now()`` is transaction start and the effects stage
is one long transaction, so a ``<=`` clear would delete marks for data the fold never saw.

Failing protocols back off exponentially, otherwise poison rows would hold the pass and starve the sweep. The cap equals
the staleness ceiling, so a transient failure delays at worst like an unmarked protocol.
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
from services.scoring.fold import compute_protocol_score
from services.scoring.persist import persist_score_document
from services.scoring.schema import ScoreDocument
from utils.logging import log_timed_phase
from utils.scoring_status import SCORE_TRIGGER_DIRTY_LOOP, SCORE_TRIGGER_STALENESS_SWEEP

logger = logging.getLogger(__name__)

DEFAULT_SCORE_INTERVAL = int(os.getenv("PSAT_SCORE_INTERVAL", "300"))
# Bounded per pass since the fold queries planes other loops also read.
DEFAULT_PROTOCOLS_PER_PASS = int(os.getenv("PSAT_SCORE_PROTOCOLS_PER_PASS", "10"))
# Backstop for write sites that carry no mark (hourly balances, TVL snapshots, upgrade indexing).
DEFAULT_MAX_SCORE_AGE_S = int(os.getenv("PSAT_SCORE_MAX_AGE_S", "21600"))
# ``base * 2**attempts``, capped; see the module docstring for why.
DEFAULT_RETRY_BACKOFF_S = int(os.getenv("PSAT_SCORE_RETRY_BACKOFF_S", "300"))
DEFAULT_RETRY_BACKOFF_CAP_S = int(os.getenv("PSAT_SCORE_RETRY_BACKOFF_CAP_S", "21600"))
# Consecutive failures before the protocol is named in logs, so a broken fold doesn't back off invisibly.
DEFAULT_POISON_WARN_AFTER = int(os.getenv("PSAT_SCORE_POISON_WARN_AFTER", "5"))


@dataclass(frozen=True)
class DueProtocol:
    """One protocol selected for a fold, and why.

    ``dirty_at`` is captured at selection as the clearing token; re-reading at clear time would delete a mark that
    landed mid-fold. ``None`` on the staleness arm.
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

    Capped so a recovered fold is eventually retried.
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

    Dirty marks are witnessed changes, so they're served first; both queries are totally ordered. Protocols already
    selected as dirty are excluded from the staleness arm. Protocols in backoff are excluded from both, in SQL so they
    don't consume ``LIMIT`` slots; a failing protocol has no score row and would otherwise re-enter via staleness.
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
            # Never-scored protocols must also pass the age filter; ``< cutoff`` is false for NULL.
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
    """Delete the exact queue row this fold consumed, matched on ``(protocol_id, dirty_at)`` by equality.

    A ``<=`` comparison would delete marks stamped at a long transaction's start but committed after the fold's read.
    Returns 0 on the staleness arm.
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
    """Clear the failure state of a queue row that outlived a successful fold, so a recovered protocol doesn't keep
    its old backoff.
    """
    from db.models import ProtocolScoreQueue

    session.query(ProtocolScoreQueue).filter(
        ProtocolScoreQueue.protocol_id == protocol_id,
        ProtocolScoreQueue.attempts > 0,
    ).update({"attempts": 0, "last_failed_at": None}, synchronize_session=False)


def _record_failure(session: Session, due: DueProtocol, *, warn_after: int) -> None:
    """Arm the backoff for a protocol whose fold raised. Commits its own write.

    Upserts because a staleness-selected protocol has no queue row and, having failed, no score row; this row is the
    only place to remember the failure. Runs after the caller's rollback and must not raise.
    """
    from db.models import ProtocolScoreQueue

    try:
        session.execute(
            pg_insert(ProtocolScoreQueue)
            .values(
                protocol_id=due.protocol_id,
                reason=due.reason or SCORE_DIRTY_STALENESS_SWEEP,
                attempts=1,
                last_failed_at=func.clock_timestamp(),
            )
            .on_conflict_do_update(
                index_elements=["protocol_id"],
                # ``dirty_at`` is untouched: it's the clearing token and queue order.
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


def _confidence_detail(document: ScoreDocument) -> dict[str, Any]:
    detail = document.model_parameters.get("confidence_detail")
    return detail if isinstance(detail, dict) else {}


def _int(value: Any) -> int | None:
    """*value* as an int, or ``None``. Never raises, and never coerces a non-number to zero."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _flow_pricing(confidence: dict[str, Any]) -> tuple[int | None, int | None]:
    """The ``[decidable, seen]`` pairs, summed, or ``None``.

    An absent census is ``None``, not zero. Present and empty is a real zero. Any unreadable pair also gives ``None`` so
    a partial sum isn't mistaken for a regression.
    """
    pricing = confidence.get("flow_pricing_decidable")
    if not isinstance(pricing, dict):
        return None, None
    decidable = seen = 0
    for pair in pricing.values():
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            return None, None
        left, right = _int(pair[0]), _int(pair[1])
        if left is None or right is None:
            return None, None
        decidable += left
        seen += right
    return decidable, seen


def document_summary(document: ScoreDocument) -> dict[str, Any]:
    """The fields the one summary INFO carries, read off the finished document.

    Nothing is recomputed. Total over every document shape, since a raise would arm backoff for a successful fold (loop)
    or fail a computed score (CLI); unreadable fields publish ``None``.
    """
    population = document.provenance.get("population")
    population = population if isinstance(population, dict) else {}
    coverage = document.provenance.get("exposure_coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    confidence = _confidence_detail(document)

    warnings_by_kind: dict[str, int] = {}
    for warning in document.warnings:
        # ``str(None)`` would publish "None" as a vocabulary member.
        raw_kind = warning.get("kind") if isinstance(warning, dict) else None
        kind = str(raw_kind) if isinstance(raw_kind, str) and raw_kind else "unknown"
        warnings_by_kind[kind] = warnings_by_kind.get(kind, 0) + 1

    undetermined = sum(
        len(finding.get("undetermined_instances") or [])
        for finding in document.findings
        if isinstance(finding, dict) and isinstance(finding.get("undetermined_instances") or [], (list, tuple))
    )

    # Per-entity ``[decidable, seen]``, so a pricing regression shows as a step change between folds.
    priced_decidable, priced_seen = _flow_pricing(confidence)

    faults = document.execution_evidence_faults
    return {
        "protocol_id": document.protocol_id,
        "model_version": document.model_version,
        "trigger": document.trigger,
        "grade_state": document.grade_state,
        "perimeter_state": document.perimeter_state,
        "grade_lambda": document.grade_lambda,
        "grade_exposure": document.grade_exposure,
        "confidence_pct": document.confidence_pct,
        "confidence_reachability_pct": confidence.get("reachability_answered_pct"),
        "confidence_capability_pct": confidence.get("capability_scored_pct"),
        "confidence_value_priced_pct": confidence.get("value_priced_pct"),
        "confidence_reach_magnitude_pct": confidence.get("reach_magnitude_witnessed_pct"),
        "population_disposition": population.get("disposition"),
        "signals": population.get("signals"),
        "signals_entering_grade": population.get("signals_entering_grade"),
        "findings": len(document.findings),
        "subsumed_rows": population.get("subsumed_rows"),
        "rows_withheld_malformed": population.get("rows_withheld_malformed"),
        "warnings": len(document.warnings),
        "warnings_by_kind": warnings_by_kind,
        "undetermined_instances": undetermined,
        "flow_pricing_decidable": priced_decidable,
        "flow_pricing_seen": priced_seen,
        "tracked_total_usd": coverage.get("tracked_total_usd"),
        # Absent is the earned zero for this model version (see ``ScoreDocument.execution_evidence_faults``); present
        # but unreadable is ``None``.
        "execution_records_faulted": _int(faults.get("records_faulted")) if isinstance(faults, dict) else 0,
    }


def score_protocol(session: Session, due: DueProtocol) -> Any:
    """Fold, persist, and clear the mark this fold consumed. Commits.

    ``computed_at`` uses the database clock because ``protocol_scores_latest`` orders on it and hosts may skew; the fold
    itself bans wall-clock reads.
    """
    computed_at = session.execute(select(func.clock_timestamp())).scalar_one()
    durations: dict[str, int] = {}
    with log_timed_phase(logger, "fold", durations_ms=durations, protocol_id=due.protocol_id):
        document = compute_protocol_score(
            session,
            due.protocol_id,
            trigger=due.trigger,
            computed_at=computed_at,
        )
    faults = document.execution_evidence_faults
    if faults is not None:
        # The census moves the grade and lives only in the document, and a failing store looks like a code regression.
        logger.warning(
            "protocol score execution evidence faulted for %s of %s records",
            faults.get("records_faulted"),
            faults.get("execution_records_examined"),
            extra={
                "protocol_id": due.protocol_id,
                "trigger": due.trigger,
                "records_faulted": faults.get("records_faulted"),
                "execution_records_examined": faults.get("execution_records_examined"),
                "faulted_by_reason": faults.get("faulted_by_reason"),
                "faulted_by_population": faults.get("faulted_by_population"),
                "grade_qualifier": faults.get("grade_qualifier"),
            },
        )
    with log_timed_phase(logger, "persist", durations_ms=durations, protocol_id=due.protocol_id):
        row = persist_score_document(session, document)
    cleared = _clear_mark(session, due)
    if not cleared:
        # A mark remaining after success must not inherit the failure count.
        _reset_backoff(session, due.protocol_id)
    try:
        session.commit()
    except Exception:
        # The other half of ``persist``'s orphan accounting.
        if row.storage_key:
            logger.warning(
                "protocol score document orphaned in object storage: commit failed",
                extra={"protocol_id": due.protocol_id, "storage_key": row.storage_key},
            )
        raise
    # After the commit: a raising summary would arm backoff for a protocol that succeeded.
    try:
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
                "durations_ms": dict(durations),
                "duration_ms_total": sum(durations.values()),
            },
        )
        logger.info("score document summary", extra=document_summary(document))
    except Exception:
        logger.warning("score summary emit failed", exc_info=True, extra={"protocol_id": due.protocol_id})
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
            # The mark stays so the protocol re-selects next pass; backoff keeps it from holding the slot.
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
        # A fold reads planes, not blocks; 0 under-claims.
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
    from db.models import SessionLocal

    stop_event = stop_event or Event()
    logger.info("Starting protocol score loop (interval=%ss)", interval)
    while not stop_event.is_set():
        try:
            with SessionLocal() as session:
                score_due_protocols(session)
        except Exception as exc:
            logger.warning(
                "protocol score cycle failed",
                exc_info=True,
                extra={"exc_type": type(exc).__name__},
            )
            # Still beat so a wedged loop shows on /api/fleet.
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
    "document_summary",
    "PassCounters",
    "run_score_loop",
    "score_due_protocols",
    "score_protocol",
    "select_due_protocols",
]
