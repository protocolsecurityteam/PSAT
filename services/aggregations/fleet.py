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
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from db.models import (
    AuditContractCoverage,
    AuditReport,
    DaemonLease,
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
    HEARTBEAT_EVENT_INDEXER,
    HEARTBEAT_PROTOCOL_SCANNER,
)
from schemas.api_responses import FleetStatusResponse
from services.monitoring.materialization_reconciler import materialization_backlog
from services.monitoring.observation_plan_state import plan_coverage_counts
from services.monitoring.process_meta import PROCESS_META, stale_after_seconds
from services.monitoring.verify_status import count_verification_read_gaps
from utils.chains import UnknownChainError, chain_by_id, chain_cache_token

from .audits_pipeline import build_audits_pipeline

logger = logging.getLogger(__name__)

# Daemon-lease name prefixes for the two chain-scoped monitoring loops. The
# lease name embeds the chain (``protocol_scanner:ethereum``), so parsing it is
# the source of per-chain monitoring visibility — no extra schema needed.
_SCANNER_LEASE_PREFIX = "protocol_scanner:"
_POLLER_LEASE_PREFIX = "protocol_poller:"

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


# This function runs once per ``/api/fleet`` read — every ~7s while the monitor
# page is open — and both conditions below persist for as long as the fault
# does, so an unconditional WARNING logs one incident thousands of times (739x
# for a single 9.6h outage, measured). State-transition logging instead: the
# entry into a condition and the recovery out of it each log once, with a
# re-warn cadence so a standing fault does not fall out of a log window
# entirely. Process-local, so a restart re-announces once.
_CONDITION_RESTATE_S = 900.0
_condition_state: dict[str, float] = {}


def _condition_should_log(key: str, active: bool) -> bool:
    """Whether this observation of *key* is a transition worth a line.

    True on entering the condition, on leaving it, and once per
    ``_CONDITION_RESTATE_S`` while it holds. False for every repeat in between.

    ``build_fleet_status`` is a sync endpoint, so anyio runs concurrent reads in
    a threadpool: the recovery arm pops rather than checking-then-deleting,
    because two racing recoveries would both pass the check and the second
    ``del`` would raise into a 500.
    """
    now = time.monotonic()
    last = _condition_state.get(key)
    if not active:
        return _condition_state.pop(key, None) is not None
    if last is not None and now - last < _CONDITION_RESTATE_S:
        return False
    _condition_state[key] = now
    return True


def reset_fleet_log_dedupe() -> None:
    """Drop the transition state, so the next observation announces again."""
    _condition_state.clear()


def _warn_stale_daemon(process: str, beat_age_s: float | None) -> None:
    """WARNING that a heartbeat-backed daemon has gone stale (likely crashed or
    wedged), so the death is captured server-side even when nobody is watching
    ``/api/fleet``. Facts in ``extra`` so an alert can key on ``process``."""
    if not _condition_should_log(f"stale:{process}", True):
        return
    # Keyed ``daemon`` not ``process``: ``process`` is a reserved LogRecord
    # attribute (the PID) and stdlib logging raises on the extra-key collision.
    logger.warning(
        "fleet: daemon %s is stale",
        process,
        extra={"daemon": process, "beat_age_s": beat_age_s},
    )


def _note_daemon_fresh(process: str) -> None:
    """The other half of the transition: one INFO when a stale daemon returns."""
    if not _condition_should_log(f"stale:{process}", False):
        return
    logger.info("fleet: daemon %s is beating again", process, extra={"daemon": process})


def _warn_lagging_cursors(lagging_cursors: int, block_spread: int | None) -> None:
    """WARNING that one or more event-indexer cursors lag the leader by more
    than ``_CURSOR_LAG_BLOCKS`` — the backfill-stall signature."""
    if not _condition_should_log("cursor_lag", bool(lagging_cursors)):
        return
    if not lagging_cursors:
        logger.info("fleet: event-indexer cursors have caught up to the leader")
        return
    logger.warning(
        "fleet: %d event-indexer cursor(s) lagging the leader",
        lagging_cursors,
        extra={"lagging_cursors": lagging_cursors, "block_spread": block_spread},
    )


def _chain_name_for_id(chain_id: int) -> str:
    """Registry canonical name for *chain_id*, or the decimal id as a string for
    a legacy/unregistered id — an observability read must never raise on a chain
    the registry doesn't know."""
    try:
        return chain_by_id(chain_id).name
    except UnknownChainError:
        return str(chain_id)


def _indexer_by_chain(session: Session, now: datetime) -> list[dict[str, Any]]:
    """Per-chain event-indexer cursor rollup. The cursor row already carries
    ``chain_id`` (invariant 4) — a stalled Base indexer shows as its own row
    with an old ``stalest_run_age_s`` while mainnet stays fresh."""
    rows = session.execute(
        select(
            IndexedEventCursor.chain_id,
            func.count(),
            func.min(IndexedEventCursor.last_run_at),
            func.max(IndexedEventCursor.last_indexed_block),
            func.min(IndexedEventCursor.last_indexed_block),
        ).group_by(IndexedEventCursor.chain_id)
    ).all()
    # Laggards are measured against each chain's *own* leader, so a chain still
    # backfilling can't hide behind another chain's head.
    max_sub = (
        select(
            IndexedEventCursor.chain_id,
            func.max(IndexedEventCursor.last_indexed_block).label("mx"),
        )
        .group_by(IndexedEventCursor.chain_id)
        .subquery()
    )
    lagging_by_chain = {
        chain_id: count
        for chain_id, count in session.execute(
            select(IndexedEventCursor.chain_id, func.count())
            .join(max_sub, max_sub.c.chain_id == IndexedEventCursor.chain_id)
            .where(IndexedEventCursor.last_indexed_block < max_sub.c.mx - _CURSOR_LAG_BLOCKS)
            .group_by(IndexedEventCursor.chain_id)
        ).all()
    }
    out: list[dict[str, Any]] = []
    for chain_id, cursors, oldest_run, max_block, min_block in rows:
        spread = max_block - min_block if max_block is not None and min_block is not None else None
        out.append(
            {
                "chain_id": chain_id,
                "chain": _chain_name_for_id(chain_id),
                "cursors": cursors or 0,
                "stalest_run_age_s": _age_seconds(oldest_run, now),
                "max_indexed_block": max_block,
                "min_indexed_block": min_block,
                "block_spread": spread,
                "lagging_cursors": lagging_by_chain.get(chain_id, 0),
            }
        )
    return sorted(out, key=lambda d: d["chain_id"])


def _held_lease_chains(session: Session, now: datetime) -> tuple[set[str], set[str]]:
    """Chain-cache tokens of chains currently holding a live scanner / poller
    daemon lease. The ``protocol_scanner:{chain}`` naming is the reuse of the
    existing per-chain lease dimension (invariant 4) — no heartbeat schema
    change needed to see which chains a monitoring pass is serving."""
    scanner: set[str] = set()
    poller: set[str] = set()
    for name, expires_at in session.execute(select(DaemonLease.name, DaemonLease.expires_at)).all():
        if expires_at is None:
            continue
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:  # lease expired → not currently serving this chain
            continue
        if name.startswith(_SCANNER_LEASE_PREFIX):
            scanner.add(chain_cache_token(name[len(_SCANNER_LEASE_PREFIX) :]))
        elif name.startswith(_POLLER_LEASE_PREFIX):
            poller.add(chain_cache_token(name[len(_POLLER_LEASE_PREFIX) :]))
    return scanner, poller


def _monitoring_by_chain(session: Session, now: datetime) -> list[dict[str, Any]]:
    """Per-chain monitored-contract rollup + live-lease flags. Combines the
    ``monitored_contracts.chain`` dimension with the per-chain daemon leases so
    a chain whose scanner has stalled is visible against the ones still fresh."""
    rows = session.execute(
        select(
            MonitoredContract.chain,
            func.count(),
            func.sum(case((MonitoredContract.is_active.is_(True), 1), else_=0)),
            func.max(MonitoredContract.updated_at),
            func.min(MonitoredContract.last_scanned_block),
            func.max(MonitoredContract.last_scanned_block),
        ).group_by(MonitoredContract.chain)
    ).all()
    scanner_held, poller_held = _held_lease_chains(session, now)
    out: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()
    for chain, total, active, latest, min_block, max_block in rows:
        token = chain_cache_token(chain)
        seen_tokens.add(token)
        spread = max_block - min_block if max_block is not None and min_block is not None else None
        out.append(
            {
                "chain": chain,
                "chain_id": int(token) if token.isdigit() else None,
                "monitored_contracts": total or 0,
                "active": int(active or 0),
                "last_update_at": latest.isoformat() if latest else None,
                "last_update_age_s": _age_seconds(latest, now),
                "min_scanned_block": min_block,
                "max_scanned_block": max_block,
                "scan_block_spread": spread,
                "scanner_lease_held": token in scanner_held,
                "poller_lease_held": token in poller_held,
            }
        )
    # A chain can hold a lease before its first contract is enrolled — surface it
    # so an early-enablement pass isn't invisible.
    for token in (scanner_held | poller_held) - seen_tokens:
        out.append(
            {
                "chain": token,
                "chain_id": int(token) if token.isdigit() else None,
                "monitored_contracts": 0,
                "active": 0,
                "last_update_at": None,
                "last_update_age_s": None,
                "min_scanned_block": None,
                "max_scanned_block": None,
                "scan_block_spread": None,
                "scanner_lease_held": token in scanner_held,
                "poller_lease_held": token in poller_held,
            }
        )
    return sorted(out, key=lambda d: (d["chain_id"] is None, d["chain_id"] or 0, d["chain"]))


def build_fleet_status(session: Session, *, now: datetime | None = None) -> FleetStatusResponse:
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
    # healthy cursor reaches head; this surfaces it. Lag and spread are
    # within-chain figures rolled up from the per-chain breakdown — a faster
    # chain's naturally higher block numbers are not a backfill signal for
    # another chain's cursors.
    idx_by_chain = _indexer_by_chain(session, now)
    idx_lagging = sum(d["lagging_cursors"] for d in idx_by_chain)
    idx_spread = max((d["block_spread"] or 0 for d in idx_by_chain), default=None)
    # Called on every read, lagging or not: the recovery is the other half of
    # the transition and it is what closes the incident in the log.
    _warn_lagging_cursors(idx_lagging, idx_spread)

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
            return {
                "cursors": idx_cursors or 0,
                "stalest_run_age_s": _age_seconds(idx_oldest_run, now),
                "max_indexed_block": idx_max_block,
                "min_indexed_block": idx_min_block,
                "block_spread": idx_spread,
                "lagging_cursors": idx_lagging,
                "by_chain": idx_by_chain,
            }
        if process == HEARTBEAT_PROTOCOL_SCANNER:
            # The scanner writes its head-lag into its own heartbeat detail
            # (design §2.1). Surface it here so "behind" is a first-class number
            # in the fleet view; tolerate absence (stage-1 scanner deploys
            # separately and older beats predate the field).
            hb = beats.get(process)
            detail = hb.detail if hb and isinstance(hb.detail, dict) else {}
            return {"max_lag_blocks": detail.get("max_lag_blocks")}
        return None

    daemons: list[dict[str, Any]] = []
    for process, meta in PROCESS_META.items():
        hb = beats.get(process)
        beat_at = hb.beat_at if hb else None
        age = _age_seconds(beat_at, now)
        stale_after = stale_after_seconds(meta["interval_s"])
        if age is None or age >= stale_after:
            _warn_stale_daemon(process, age)
        else:
            _note_daemon_fresh(process)
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
    mon_by_chain = _monitoring_by_chain(session, now)
    # Scan spread is a within-chain figure (rolled up as the worst per-chain
    # gap) — chains run at different heights, so a cross-chain max−min is noise.
    mon_spreads = [d["scan_block_spread"] for d in mon_by_chain if d["scan_block_spread"] is not None]
    watchers = {
        "monitored_contracts": mon_total,
        "active": mon_active,
        "last_update_at": mon_latest.isoformat() if mon_latest else None,
        "last_update_age_s": _age_seconds(mon_latest, now),
        "min_scanned_block": mon_min_block,
        "max_scanned_block": mon_max_block,
        "scan_block_spread": max(mon_spreads) if mon_spreads else None,
        "tvl_last_snapshot_at": tvl_latest.isoformat() if tvl_latest else None,
        "tvl_last_snapshot_age_s": _age_seconds(tvl_latest, now),
        "by_chain": mon_by_chain,
        # Liveness says the scanner is running; this says what it is running
        # WITH. A contract watching on the baseline registry alone is quiet for
        # the same reason a healthy one is, and without this census the two are
        # indistinguishable on the page.
        "plan_coverage": plan_coverage_counts(session),
        # The other half of "what is it running with": a plan can be current and
        # its hint controllers still unverified, because the read failed, was
        # skipped over budget, or is bound to nothing. Point-in-time by
        # construction (``basis``) — the per-pass counts that do not depend on a
        # marker surviving ride the scanner's own heartbeat, published above as
        # ``daemons[protocol_scanner].detail.verification_reads_*``.
        "verification_gaps": count_verification_read_gaps(session),
        # And the supply side of the same question: ``plan_coverage`` counts
        # contracts watching without a current plan, this counts the rebuild
        # work that would fix them and how much of it the budget allows today.
        # A schema bump moves the whole fleet into here at once, which is the
        # moment this needs to be visible rather than inferred.
        "materialization_backlog": materialization_backlog(session, now=now),
    }

    return {"now": now.isoformat(), "jobs": jobs, "daemons": daemons, "watchers": watchers}
