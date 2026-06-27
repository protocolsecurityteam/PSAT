"""Fleet / process-status aggregation.

Builds the monitor page's view of *every* background process the system
runs, so an operator can see what's alive and what each thing is doing
without querying the DB or scraping logs:

  - ``jobs``     — the jobs-queue pipeline, summarised from the jobs table.
  - ``daemons``  — row-draining daemons that report liveness via the
                   ``worker_heartbeats`` table (coverage-verify, audit
                   text/scope extraction, event-log indexer, enrollment
                   reconciler). Heartbeats are what distinguish 'idle' from
                   'dead'; the work-state breakdown is queried straight from
                   each daemon's own table so it's always fresh.
  - ``watchers`` — runtime monitors (proxy/event scan, state poll, TVL)
                   whose liveness is *derived* from the freshness of the
                   rows they write, since they always have work and so never
                   look falsely idle.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import (
    AuditContractCoverage,
    AuditReport,
    IndexedEventCursor,
    Job,
    JobStatus,
    MonitoredContract,
    TvlSnapshot,
    WorkerHeartbeat,
)
from db.queue import (
    HEARTBEAT_AUDIT_SCOPE,
    HEARTBEAT_AUDIT_TEXT,
    HEARTBEAT_COVERAGE_VERIFY,
    HEARTBEAT_ENROLLMENT_RECONCILER,
    HEARTBEAT_EVENT_INDEXER,
)

from .audits_pipeline import build_audits_pipeline

logger = logging.getLogger(__name__)

# Per-process display metadata + staleness window. ``interval_s`` is the
# loop cadence; a process is flagged ``stale`` when its last beat is older
# than ``3 × interval`` (with a 120s floor) — long enough to absorb one slow
# pass, short enough to surface a crash. ``kind`` groups processes for the UI.
PROCESS_META: dict[str, dict[str, Any]] = {
    HEARTBEAT_COVERAGE_VERIFY: {"kind": "drainer", "interval_s": 30, "label": "Coverage / source-equivalence"},
    HEARTBEAT_AUDIT_TEXT: {"kind": "drainer", "interval_s": 30, "label": "Audit text extraction"},
    HEARTBEAT_AUDIT_SCOPE: {"kind": "drainer", "interval_s": 30, "label": "Audit scope extraction"},
    HEARTBEAT_EVENT_INDEXER: {"kind": "indexer", "interval_s": 90, "label": "Event-log indexer"},
    HEARTBEAT_ENROLLMENT_RECONCILER: {"kind": "daemon", "interval_s": 660, "label": "Enrollment reconciler"},
}

# A cursor more than this many blocks behind the leading cursor is "lagging" —
# the signature of one still backfilling from its contract's creation block
# while the rest track head. ~2 weeks of mainnet blocks; far below any genuine
# backfill gap.
_CURSOR_LAG_BLOCKS = 100_000


def _age_seconds(ts: datetime | None, now: datetime) -> float | None:
    """Seconds between *ts* and *now*, or None. Guards naive timestamps so a
    column read without tzinfo can't raise on the subtraction."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return max(0.0, (now - ts).total_seconds())


def _bucket_counts(bucket: Any) -> dict[str, Any]:
    """Collapse an audit-pipeline bucket ({status: [rows]}) to {status: count}."""
    if not isinstance(bucket, dict):
        return {}
    return {k: (len(v) if isinstance(v, list) else v) for k, v in bucket.items()}


def _warn_stale_daemon(process: str, beat_age_s: float | None) -> None:
    """WARNING that a heartbeat-backed daemon has gone stale (likely crashed or
    wedged), so the death is captured server-side even when nobody is watching
    ``/api/fleet``. Facts in ``extra`` so an alert can key on ``process``."""
    # Keyed ``daemon`` not ``process``: ``process`` is a reserved LogRecord
    # attribute (the PID) and stdlib logging raises on the extra-key collision.
    logger.warning(
        "fleet: daemon %s is stale",
        process,
        extra={"daemon": process, "beat_age_s": beat_age_s},
    )


def _warn_lagging_cursors(lagging_cursors: int, block_spread: int | None) -> None:
    """WARNING that one or more event-indexer cursors lag the leader by more
    than ``_CURSOR_LAG_BLOCKS`` — the backfill-stall signature."""
    logger.warning(
        "fleet: %d event-indexer cursor(s) lagging the leader",
        lagging_cursors,
        extra={"lagging_cursors": lagging_cursors, "block_spread": block_spread},
    )


def build_fleet_status(session: Session, *, now: datetime | None = None) -> dict[str, Any]:
    """Liveness + work breakdown for every background process, for the
    monitor page's "all processes" view. ``now`` is injectable for tests."""
    now = now or datetime.now(timezone.utc)

    # --- Jobs queue pipeline -----------------------------------------------
    jobs: dict[str, Any] = {s.value: 0 for s in JobStatus}
    for status, count in session.execute(select(Job.status, func.count()).group_by(Job.status)).all():
        jobs[status.value] = count
    by_stage: dict[str, dict[str, int]] = {}
    for stage, status, count in session.execute(
        select(Job.stage, Job.status, func.count())
        .where(Job.status.in_([JobStatus.processing, JobStatus.queued]))
        .group_by(Job.stage, Job.status)
    ).all():
        by_stage.setdefault(stage.value, {})[status.value] = count
    jobs["by_stage"] = by_stage

    # --- Heartbeat-backed daemons ------------------------------------------
    beats = {hb.process: hb for hb in session.execute(select(WorkerHeartbeat)).scalars().all()}

    cov_work: dict[str, int] = {}
    for eq_status, count in session.execute(
        select(AuditContractCoverage.equivalence_status, func.count()).group_by(
            AuditContractCoverage.equivalence_status
        )
    ).all():
        cov_work[eq_status or "unknown"] = count

    audit_pipeline = build_audits_pipeline(session)

    # Backlog + oldest-pending age for the two audit row workers. Cheap
    # index-backed aggregates (the partial ``ix_audit_reports_*_status``
    # indexes cover the predicates). Computed here rather than reused from the
    # build_audits_pipeline buckets because those cap each bucket at 50, which
    # understates a real backlog; ``min(...)`` over the pending slice dates the
    # oldest waiting row so the frontend can flag a stuck worker (old age with
    # zero throughput).
    text_backlog, text_oldest = session.execute(
        select(func.count(), func.min(AuditReport.discovered_at)).where(AuditReport.text_extraction_status.is_(None))
    ).one()
    scope_backlog, scope_oldest = session.execute(
        select(func.count(), func.min(AuditReport.text_extracted_at)).where(
            AuditReport.text_extraction_status == "success",
            AuditReport.scope_extraction_status.is_(None),
        )
    ).one()

    idx_cursors, idx_oldest_run, idx_max_block, idx_min_block = session.execute(
        select(
            func.count(),
            func.min(IndexedEventCursor.last_run_at),
            func.max(IndexedEventCursor.last_indexed_block),
            func.min(IndexedEventCursor.last_indexed_block),
        )
    ).one()
    # Cursors far behind the leader. A cursor still backfilling from its
    # contract's creation block is invisible in max_indexed_block alone once a
    # healthy cursor reaches head; this surfaces it.
    idx_lagging = 0
    if idx_max_block:
        idx_lagging = (
            session.execute(
                select(func.count())
                .select_from(IndexedEventCursor)
                .where(IndexedEventCursor.last_indexed_block < idx_max_block - _CURSOR_LAG_BLOCKS)
            ).scalar()
            or 0
        )
    if idx_lagging:
        _warn_lagging_cursors(
            idx_lagging,
            idx_max_block - idx_min_block if idx_max_block is not None and idx_min_block is not None else None,
        )

    def _work_for(process: str) -> dict[str, Any] | None:
        if process == HEARTBEAT_COVERAGE_VERIFY:
            return {
                "by_equivalence_status": cov_work,
                "total": sum(cov_work.values()),
                # Drainable queue depth. Derived from the breakdown above (no
                # extra query). No clean enqueue timestamp exists —
                # equivalence_checked_at is stamped at *claim*, not enqueue —
                # so we lead with backlog and omit oldest-age rather than date
                # it from the wrong column.
                "backlog": cov_work.get("pending", 0),
            }
        if process == HEARTBEAT_AUDIT_TEXT:
            return {
                **_bucket_counts(audit_pipeline.get("text_extraction")),
                "backlog": text_backlog or 0,
                "oldest_pending_age_s": _age_seconds(text_oldest, now),
            }
        if process == HEARTBEAT_AUDIT_SCOPE:
            return {
                **_bucket_counts(audit_pipeline.get("scope_extraction")),
                "backlog": scope_backlog or 0,
                "oldest_pending_age_s": _age_seconds(scope_oldest, now),
            }
        if process == HEARTBEAT_EVENT_INDEXER:
            spread = idx_max_block - idx_min_block if idx_max_block is not None and idx_min_block is not None else None
            return {
                "cursors": idx_cursors or 0,
                "stalest_run_age_s": _age_seconds(idx_oldest_run, now),
                "max_indexed_block": idx_max_block,
                "min_indexed_block": idx_min_block,
                "block_spread": spread,
                "lagging_cursors": idx_lagging,
            }
        return None

    daemons: list[dict[str, Any]] = []
    for process, meta in PROCESS_META.items():
        hb = beats.get(process)
        beat_at = hb.beat_at if hb else None
        age = _age_seconds(beat_at, now)
        stale_after = max(3 * meta["interval_s"], 120)
        if age is None or age >= stale_after:
            _warn_stale_daemon(process, age)
        daemons.append(
            {
                "process": process,
                "kind": meta["kind"],
                "label": meta["label"],
                "status": hb.status if hb else "unknown",
                "last_beat_at": beat_at.isoformat() if beat_at else None,
                "beat_age_s": age,
                "alive": age is not None and age < stale_after,
                "stale": age is None or age >= stale_after,
                "detail": hb.detail if hb else None,
                "work": _work_for(process),
            }
        )

    # --- Runtime watchers (derived liveness, no heartbeat) -----------------
    mon_total = session.execute(select(func.count()).select_from(MonitoredContract)).scalar() or 0
    mon_active = (
        session.execute(
            select(func.count()).select_from(MonitoredContract).where(MonitoredContract.is_active.is_(True))
        ).scalar()
        or 0
    )
    mon_latest = session.execute(select(func.max(MonitoredContract.updated_at))).scalar()
    mon_min_block, mon_max_block = session.execute(
        select(func.min(MonitoredContract.last_scanned_block), func.max(MonitoredContract.last_scanned_block))
    ).one()
    tvl_latest = session.execute(select(func.max(TvlSnapshot.timestamp))).scalar()
    watchers = {
        "monitored_contracts": mon_total,
        "active": mon_active,
        "last_update_at": mon_latest.isoformat() if mon_latest else None,
        "last_update_age_s": _age_seconds(mon_latest, now),
        "min_scanned_block": mon_min_block,
        "max_scanned_block": mon_max_block,
        "scan_block_spread": (
            mon_max_block - mon_min_block if mon_max_block is not None and mon_min_block is not None else None
        ),
        "tvl_last_snapshot_at": tvl_latest.isoformat() if tvl_latest else None,
        "tvl_last_snapshot_age_s": _age_seconds(tvl_latest, now),
    }

    return {"now": now.isoformat(), "jobs": jobs, "daemons": daemons, "watchers": watchers}
