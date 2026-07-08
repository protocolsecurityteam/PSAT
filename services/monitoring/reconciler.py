"""Periodic enrollment reconciler — convergence backstop for monitored_contracts.

Background
----------
``MonitoredContract`` is derived state computed from ``Contract`` +
``Job`` + analysis output (``ControlGraphNode`` / ``FunctionPrincipal`` /
``ContractSummary`` / ``ControllerValue``). The historical write path
fires once per completed job from ``PolicyWorker.process()`` via
``maybe_enroll_protocol``. That edge-triggered pattern lets monitoring
drift from ground truth in two ways:

1. The in-flight gate in ``maybe_enroll_protocol`` skips when any
   sibling job for the protocol is ``queued``/``processing``. When the
   sibling fails terminally and no later trigger fires, the missed
   enrollment is never retried.

2. ``Contract.protocol_id`` is set from several write sites that don't
   re-trigger enrollment: the deployer-cascade in
   ``workers/discovery.py:538-545``, the orphan-adoption migrations
   ``3a8f4d1c9b07`` + ``4d72e9b1f035``, admin DB fix-ups, ``routers/
   audits.py:282``. A contract adopted by one of these paths after
   PolicyWorker already ran for its job has no MonitoredContract row
   until someone hits ``POST /api/protocols/{id}/re-enroll`` by hand.

The general fix is to stop relying on a single trigger moment and
converge enrollment on a cadence. ``enroll_protocol_contracts`` is
already idempotent (upsert by ``(address, chain)``, stale-row
deactivation by enrollment_source). The reconciler walks every
``Protocol`` row and calls it.

``maybe_enroll_protocol`` stays as a low-latency hint so fresh analyses
land in ``monitored_contracts`` within milliseconds in the common case.
This reconciler bounds staleness to ``interval`` for everything else.

Concurrency
-----------
The reconciler and a concurrent ``PolicyWorker``-triggered enrollment
for the same protocol both upsert ``(address, chain)`` so the second
writer's UPDATE is a no-op. ``_enroll_controller_addresses`` runs its
Pass 1 / Pass 2 (promote / demote) inside one ``enroll_protocol_
contracts`` call, so a single pass converges; a brief inter-pass
window during overlapping calls self-corrects on the next tick.
"""

from __future__ import annotations

import logging
import os
import signal
import uuid
from threading import Event
from typing import NamedTuple

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.orm import Session

from db.models import MonitoringEnrollmentQueue, Protocol, SessionLocal
from db.queue import HEARTBEAT_ENROLLMENT_RECONCILER, record_heartbeat
from services.monitoring.enrollment import enroll_protocol_contracts, mark_enrollment_dirty
from utils.logging import configure_logging

logger = logging.getLogger(__name__)


# Default convergence interval. Configurable via env so an operator can
# trade staleness for query load without a redeploy. 600s matches the
# unified watcher's scan cadence — same order of magnitude as
# "MonitoredContract may be stale for up to ten minutes."
DEFAULT_RECONCILE_INTERVAL_S = int(os.getenv("PSAT_ENROLLMENT_RECONCILE_INTERVAL", "600"))

# Lease TTL for a claimed queue row — must exceed the worst single-protocol
# ``enroll_protocol_contracts`` build (a full ``build_governance_view``) so a
# slow build doesn't hand its row to a competing drainer mid-flight.
DEFAULT_ENROLLMENT_LEASE_TTL_S = 900

# Slow-sweep width: how many least-recently-reconciled protocols to enqueue per
# tick as the convergence backstop for drift from unknown write sites.
DEFAULT_RECONCILE_SWEEP_K = 2

# Per-drain claim ceiling. Bounds how many heavy builds one tick serializes so a
# lease can't expire while its protocol waits behind a long backlog.
DEFAULT_ENROLLMENT_DRAIN_BATCH = 8

# Backoff ceiling for a repeatedly-failing (poisoned) protocol: 6 hours.
_BACKOFF_CEILING_S = 6 * 3600


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class EnrollmentClaim(NamedTuple):
    protocol_id: int
    dirty_at: object  # server timestamp captured at claim; opaque guard value
    attempts: int
    lease_id: uuid.UUID


def claim_due_enrollments(
    session: Session,
    *,
    lease_ttl_s: int,
    limit: int,
) -> list[EnrollmentClaim]:
    """Lease-claim up to *limit* due queue rows, exactly like ``db.queue.claim_job``.

    A row is *due* when ``dirty_at <= now()`` and its lease is absent or
    expired. We ``SELECT ... FOR UPDATE SKIP LOCKED`` the oldest-dirty rows,
    stamp ``lease_id`` + ``lease_expires_at = now() + ttl`` (server clock), and
    **commit** — the lock is released immediately so the minutes-long
    governance build never holds a row lock (idle-in-transaction hazard on
    Neon/pgbouncer, design §2.3). ``dirty_at`` is deliberately left untouched so
    the success delete can guard on the exact value seen at claim time.
    """
    stmt = (
        select(MonitoringEnrollmentQueue)
        .where(
            MonitoringEnrollmentQueue.dirty_at <= func.now(),
            (
                MonitoringEnrollmentQueue.lease_expires_at.is_(None)
                | (MonitoringEnrollmentQueue.lease_expires_at < func.now())
            ),
        )
        .order_by(MonitoringEnrollmentQueue.dirty_at.asc())
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    rows = list(session.execute(stmt).scalars())
    claims: list[EnrollmentClaim] = []
    for row in rows:
        lease_id = uuid.uuid4()
        claims.append(EnrollmentClaim(row.protocol_id, row.dirty_at, row.attempts, lease_id))
        session.execute(
            update(MonitoringEnrollmentQueue)
            .where(MonitoringEnrollmentQueue.protocol_id == row.protocol_id)
            .values(
                lease_id=lease_id,
                lease_expires_at=text(f"NOW() + INTERVAL '{int(lease_ttl_s)} seconds'"),
            )
        )
    session.commit()
    return claims


def _finish_success(session: Session, claim: EnrollmentClaim) -> None:
    """Delete the claimed row and stamp the protocol's reconcile time.

    The ``dirty_at=:claimed AND lease_id=:mine`` guard keeps a row that was
    re-dirtied during the build (its ``dirty_at`` advanced): the delete no-ops,
    so we instead release our lease so the next tick re-drains it against the
    newer ``dirty_at``.
    """
    res = session.execute(
        delete(MonitoringEnrollmentQueue).where(
            MonitoringEnrollmentQueue.protocol_id == claim.protocol_id,
            MonitoringEnrollmentQueue.dirty_at == claim.dirty_at,
            MonitoringEnrollmentQueue.lease_id == claim.lease_id,
        )
    )
    if int(getattr(res, "rowcount", 0) or 0) == 0:
        session.execute(
            update(MonitoringEnrollmentQueue)
            .where(
                MonitoringEnrollmentQueue.protocol_id == claim.protocol_id,
                MonitoringEnrollmentQueue.lease_id == claim.lease_id,
            )
            .values(lease_id=None, lease_expires_at=None)
        )
    session.execute(
        update(Protocol).where(Protocol.id == claim.protocol_id).values(last_enrollment_reconcile_at=func.now())
    )
    session.commit()


def _finish_failure(session: Session, claim: EnrollmentClaim) -> None:
    """Bump attempts, clear the lease, and push ``dirty_at`` forward with
    exponential backoff so a poisoned protocol can't wedge the queue."""
    delay_s = min(2 ** (claim.attempts + 1) * 60, _BACKOFF_CEILING_S)
    session.execute(
        update(MonitoringEnrollmentQueue)
        .where(
            MonitoringEnrollmentQueue.protocol_id == claim.protocol_id,
            MonitoringEnrollmentQueue.lease_id == claim.lease_id,
        )
        .values(
            attempts=MonitoringEnrollmentQueue.attempts + 1,
            lease_id=None,
            lease_expires_at=None,
            dirty_at=text(f"NOW() + INTERVAL '{int(delay_s)} seconds'"),
        )
    )
    session.commit()


def drain_enrollment_queue(
    rpc_url: str,
    chain: str = "ethereum",
    *,
    lease_ttl_s: int | None = None,
    max_claims: int | None = None,
) -> dict[str, int]:
    """Claim and process due enrollment-queue rows.

    Claims a bounded batch with :func:`claim_due_enrollments`, then processes
    each claimed protocol in its **own fresh session** running the full
    ``enroll_protocol_contracts(..., enroll_controllers=True)`` build. Success
    deletes the claimed row (``dirty_at``-guarded) and stamps
    ``last_enrollment_reconcile_at``; failure backs the row off. Per-protocol
    exceptions are logged and swallowed so one poisoned protocol never aborts
    the drain. Returns ``{"drained", "failed"}`` counts.
    """
    lease_ttl_s = (
        lease_ttl_s
        if lease_ttl_s is not None
        else _env_int("PSAT_ENROLLMENT_LEASE_TTL_S", DEFAULT_ENROLLMENT_LEASE_TTL_S)
    )
    max_claims = (
        max_claims
        if max_claims is not None
        else _env_int("PSAT_ENROLLMENT_DRAIN_BATCH", DEFAULT_ENROLLMENT_DRAIN_BATCH)
    )

    with SessionLocal() as claim_session:
        claims = claim_due_enrollments(claim_session, lease_ttl_s=lease_ttl_s, limit=max_claims)

    drained = 0
    failed = 0
    for claim in claims:
        try:
            with SessionLocal() as work_session:
                enroll_protocol_contracts(work_session, claim.protocol_id, rpc_url, chain, enroll_controllers=True)
                _finish_success(work_session, claim)
            drained += 1
        except Exception:
            logger.exception("enrollment drain failed for protocol %s", claim.protocol_id)
            failed += 1
            try:
                with SessionLocal() as fail_session:
                    _finish_failure(fail_session, claim)
            except Exception:
                logger.exception("enrollment failure-bookkeeping failed for protocol %s", claim.protocol_id)

    if drained or failed:
        logger.info("enrollment drain: %d reconciled, %d failed", drained, failed)
    return {"drained": drained, "failed": failed}


def sweep_enqueue_stale(session: Session, k: int | None = None) -> list[int]:
    """Enqueue the *k* least-recently-reconciled protocols (NULLS FIRST).

    The convergence backstop for drift from write sites that don't mark dirty
    (psql fix-ups, unknown paths). Marks each with reason ``'sweep'`` and
    commits. Returns the enqueued protocol ids.

    Candidates already sitting in the queue are excluded: re-marking them would
    reset ``dirty_at`` to now() and so pull a poisoned row out of its
    ``_finish_failure`` backoff every tick, re-triggering a full governance
    build forever. Skipping queued rows keeps the exponential backoff intact and
    frees the sweep slot for a genuinely un-enqueued stale protocol.
    """
    k = k if k is not None else _env_int("PSAT_RECONCILE_SWEEP_K", DEFAULT_RECONCILE_SWEEP_K)
    if k <= 0:
        return []
    pids = list(
        session.execute(
            select(Protocol.id)
            .outerjoin(MonitoringEnrollmentQueue, MonitoringEnrollmentQueue.protocol_id == Protocol.id)
            .where(MonitoringEnrollmentQueue.protocol_id.is_(None))
            .order_by(Protocol.last_enrollment_reconcile_at.asc().nullsfirst())
            .limit(k)
        ).scalars()
    )
    for pid in pids:
        mark_enrollment_dirty(session, pid, "sweep")
    session.commit()
    return pids


def _queue_depth(session: Session) -> int:
    return int(session.execute(select(func.count()).select_from(MonitoringEnrollmentQueue)).scalar() or 0)


def reconcile_enrollments(
    session: Session,
    rpc_url: str,
    chain: str = "ethereum",
) -> int:
    """DEPRECATED — walk-all reconciliation pass; superseded by the dirty-queue
    drain (:func:`drain_enrollment_queue` + :func:`sweep_enqueue_stale`).

    Walks every ``Protocol`` row and re-enrolls it. Retained and exported only
    because ``unified_watcher._boot_reconcile`` still imports it until stage 1
    lands; new code must use the drain. A per-protocol exception is logged and
    swallowed so one broken protocol does not abort the sweep. Returns the count
    of protocols successfully reconciled.
    """
    protocol_ids = list(session.execute(select(Protocol.id)).scalars())
    if not protocol_ids:
        return 0

    reconciled = 0
    for pid in protocol_ids:
        try:
            enroll_protocol_contracts(session, pid, rpc_url, chain)
            reconciled += 1
        except Exception:
            logger.exception("reconciler enrollment failed for protocol %s", pid)
            # ``enroll_protocol_contracts`` commits internally; a
            # partial write may have landed before the exception.
            # Rollback so the next protocol's queries don't see the
            # failed transaction's autobegun state.
            session.rollback()

    if reconciled:
        logger.info(
            "reconciler pass reconciled %d/%d protocols",
            reconciled,
            len(protocol_ids),
        )
    return reconciled


def run_enrollment_reconciler_loop(
    rpc_url: str,
    interval: float = DEFAULT_RECONCILE_INTERVAL_S,
    stop_event: Event | None = None,
    chain: str = "ethereum",
) -> None:
    """Long-running reconciler. Each tick = slow-sweep enqueue + queue drain.

    Designed to be hosted by ``workers/protocol_monitor.py --reconcile``. Each
    pass opens its own ``SessionLocal()`` for the sweep enqueue (the drain opens
    its own per-protocol sessions) so a connection blip on one tick does not
    poison the next.
    """
    stop_event = stop_event or Event()
    logger.info("starting enrollment reconciler interval=%ss", interval)
    while not stop_event.is_set():
        result = {"drained": 0, "failed": 0}
        depth = 0
        status = "running"
        try:
            with SessionLocal() as session:
                sweep_enqueue_stale(session)
            result = drain_enrollment_queue(rpc_url, chain)
            with SessionLocal() as session:
                depth = _queue_depth(session)
        except Exception:
            logger.exception("reconciler outer loop failed")
            status = "error"
        record_heartbeat(
            HEARTBEAT_ENROLLMENT_RECONCILER,
            status=status,
            detail={
                "drained": result["drained"],
                "failures": result["failed"],
                "queue_depth": depth,
            },
        )
        stop_event.wait(interval)


def main() -> None:
    """CLI entry point — used by ``workers/protocol_monitor.py --reconcile``."""
    configure_logging()
    stop_event = Event()

    def handle_signal(signum, _frame):
        logger.info("received signal %s, shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    from utils.rpc import require_rpc_url

    rpc_url = require_rpc_url(chain="ethereum")
    run_enrollment_reconciler_loop(rpc_url, stop_event=stop_event)


if __name__ == "__main__":
    main()
