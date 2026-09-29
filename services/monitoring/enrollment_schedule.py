"""Lightweight daily repair scheduling: no governance, RPC or analysis imports."""

from __future__ import annotations

import os
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import MonitoringEnrollmentQueue, Protocol

DEFAULT_RECONCILE_SWEEP_K = 2
DEFAULT_RECONCILE_SWEEP_MIN_AGE_S = 86400
DEFAULT_RECONCILE_INTERVAL_S = int(os.getenv("PSAT_ENROLLMENT_RECONCILE_INTERVAL", "600"))


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def sweep_enqueue_stale(session: Session, k: int | None = None, *, min_age_s: int | None = None) -> list[int]:
    """Enqueue up to *k* protocols overdue for repair (NULLS FIRST).

    The convergence backstop for drift from write sites that don't mark dirty
    (psql fix-ups, unknown paths). A successful reconcile must be at least
    ``PSAT_RECONCILE_SWEEP_MIN_AGE_S`` old (default 24 hours), unless the
    protocol has never been reconciled. Inserts with reason ``'sweep'`` and
    commits. Returns only the protocol ids actually inserted.

    Candidates already sitting in the queue are excluded: re-marking them would
    reset ``dirty_at`` to now() and so pull a poisoned row out of its
    ``_finish_failure`` backoff every tick, re-triggering a full governance
    build forever. Skipping queued rows keeps the exponential backoff intact and
    frees the sweep slot for a genuinely un-enqueued stale protocol.
    """
    k = k if k is not None else _env_int("PSAT_RECONCILE_SWEEP_K", DEFAULT_RECONCILE_SWEEP_K)
    if k <= 0:
        return []
    min_age_s = (
        min_age_s
        if min_age_s is not None
        else _env_int("PSAT_RECONCILE_SWEEP_MIN_AGE_S", DEFAULT_RECONCILE_SWEEP_MIN_AGE_S)
    )
    pids = list(
        session.execute(
            select(Protocol.id)
            .outerjoin(MonitoringEnrollmentQueue, MonitoringEnrollmentQueue.protocol_id == Protocol.id)
            .where(MonitoringEnrollmentQueue.protocol_id.is_(None))
            .where(
                Protocol.last_enrollment_reconcile_at.is_(None)
                | (Protocol.last_enrollment_reconcile_at <= func.now() - timedelta(seconds=max(0, min_age_s)))
            )
            .order_by(Protocol.last_enrollment_reconcile_at.asc().nullsfirst(), Protocol.id)
            .limit(k)
        ).scalars()
    )
    inserted = []
    if pids:
        # A producer or another sweeper may enqueue after the SELECT. Never
        # replace its reason, dirty timestamp, backoff, or in-flight lease.
        inserted = list(
            session.execute(
                pg_insert(MonitoringEnrollmentQueue)
                .values([{"protocol_id": pid, "reason": "sweep"} for pid in pids])
                .on_conflict_do_nothing(index_elements=["protocol_id"])
                .returning(MonitoringEnrollmentQueue.protocol_id)
            ).scalars()
        )
    session.commit()
    return inserted
