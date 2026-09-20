"""Drain changed protocols into monitoring, with an infrequent repair sweep.

Enrollment derives ``MonitoredContract`` rows from analysis and governance
data. Although the writes are idempotent, deriving the controller set builds
the full governance view and is expensive even when nothing has changed.

Normal work comes from the dirty queue: job completion, policy output,
membership changes, governance rotations, audit additions, and manual requests.
The queue is checked every ten minutes by default. An unchanged protocol is
eligible for the bounded repair sweep only after 24 hours; never-reconciled
protocols are eligible immediately. The sweep recovers missed notifications
(including manual DB changes), with additional delay possible under backlog.

Queue leases and dirty_at-guarded completion preserve concurrent changes and
retry backoff. The repair sweep only inserts missing queue rows, so it cannot
overwrite an event notification or pull a retry forward.
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Sequence
from datetime import timedelta
from threading import Event
from typing import NamedTuple

from sqlalchemy import case, delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import Contract, MonitoredContract, MonitoringEnrollmentQueue, Protocol, SessionLocal
from db.queue import HEARTBEAT_ENROLLMENT_RECONCILER, record_heartbeat
from services.monitoring.chain_rpc import rpc_for_chain
from services.monitoring.enrollment import enroll_protocol_contracts
from services.monitoring.tracking_plan_state import NOT_DETERMINED_KEY, TRANSIENT_PLAN_FAILURES

logger = logging.getLogger(__name__)


# Default convergence interval. Configurable via env so an operator can
# trade staleness for query load without a redeploy. 600s matches the
# unified watcher's scan cadence — same order of magnitude as
# "MonitoredContract may be stale for up to ten minutes."
DEFAULT_RECONCILE_INTERVAL_S = int(os.getenv("PSAT_ENROLLMENT_RECONCILE_INTERVAL", "600"))

# Daemon-edge fallback chain for the reconciler loop (inv. 6): the base RPC chain
# and the ambiguous-protocol default handed to ``_protocol_chain``. Explicit and
# overridable via env rather than a buried ``chain="ethereum"`` signature default.
RECONCILER_FALLBACK_CHAIN = os.getenv("PSAT_RECONCILER_FALLBACK_CHAIN", "ethereum")

# Lease TTL for a claimed queue row — must exceed the worst single-protocol
# ``enroll_protocol_contracts`` build (a full ``build_governance_view``) so a
# slow build doesn't hand its row to a competing drainer mid-flight.
DEFAULT_ENROLLMENT_LEASE_TTL_S = 900

# Repair-sweep width and minimum age. The queue drain cadence stays independent
# so real changes and retries do not wait a day. K=0 disables only the backstop.
DEFAULT_RECONCILE_SWEEP_K = 2
DEFAULT_RECONCILE_SWEEP_MIN_AGE_S = 24 * 3600

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


def _protocol_chain(session: Session, protocol_id: int, default: str) -> str:
    """The chain a protocol's contracts live on (v1 chain-as-island, inv. 15).

    Reads the distinct non-null ``Contract.chain`` values for the protocol and
    returns the sole chain when unambiguous, else *default*. Used to thread each
    protocol's own chain (and its eRPC route) into ``enroll_protocol_contracts``
    instead of the reconciler's mainnet default; ``enroll_protocol_contracts``
    still resolves each contract's chain independently, so this pins the fallback
    for NULL-chain rows and the seed RPC.
    """
    chains = {
        c
        for c in session.execute(
            select(Contract.chain).where(Contract.protocol_id == protocol_id, Contract.chain.isnot(None)).distinct()
        ).scalars()
        if c
    }
    return chains.pop() if len(chains) == 1 else default


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
    exponential backoff so a poisoned protocol can't wedge the queue.

    If a producer re-dirtied the protocol during this attempt, release only our
    lease. Its notification (including a deliberate delay) supersedes this
    attempt and must not be postponed by an older failure.
    """
    delay_s = min(2 ** (claim.attempts + 1) * 60, _BACKOFF_CEILING_S)
    unchanged = MonitoringEnrollmentQueue.dirty_at == claim.dirty_at
    session.execute(
        update(MonitoringEnrollmentQueue)
        .where(
            MonitoringEnrollmentQueue.protocol_id == claim.protocol_id,
            MonitoringEnrollmentQueue.lease_id == claim.lease_id,
        )
        .values(
            attempts=case(
                (unchanged, MonitoringEnrollmentQueue.attempts + 1), else_=MonitoringEnrollmentQueue.attempts
            ),
            lease_id=None,
            lease_expires_at=None,
            dirty_at=case(
                (unchanged, text(f"NOW() + INTERVAL '{int(delay_s)} seconds'")),
                else_=MonitoringEnrollmentQueue.dirty_at,
            ),
        )
    )
    session.commit()


def _has_transient_plan_failures(session: Session, enrolled: Sequence[MonitoredContract]) -> bool:
    """Check persisted enrollment results without reloading their ORM graphs.

    Enrollment commits baseline/last-known-good monitoring even when artifact
    storage cannot answer. That is useful partial work, but not a completed
    reconcile: storage recovery emits no dirty notification of its own. Only
    inspect rows this pass enrolled, not unrelated manual or disabled-chain
    records that it cannot repair.
    """
    if not enrolled:
        return False
    return (
        session.execute(
            select(MonitoredContract.id)
            .where(
                MonitoredContract.id.in_([row.id for row in enrolled]),
                MonitoredContract.is_active.is_(True),
                MonitoredContract.monitoring_config[NOT_DETERMINED_KEY].as_string().in_(TRANSIENT_PLAN_FAILURES),
            )
            .limit(1)
        ).first()
        is not None
    )


def drain_enrollment_queue(
    rpc_url: str,
    chain: str,
    *,
    lease_ttl_s: int | None = None,
    max_claims: int | None = None,
) -> dict[str, int]:
    """Claim and process due enrollment-queue rows.

    Claims a bounded batch with :func:`claim_due_enrollments`, then processes
    each claimed protocol in its **own fresh session** running the full
    ``enroll_protocol_contracts(..., enroll_controllers=True)`` build. Success
    deletes the claimed row (``dirty_at``-guarded) and stamps
    ``last_enrollment_reconcile_at``; failure (including a partially enrolled
    protocol with transiently unreadable tracking plans) backs the row off. Per-protocol
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
                protocol_chain = _protocol_chain(work_session, claim.protocol_id, chain)
                enrolled = enroll_protocol_contracts(
                    work_session,
                    claim.protocol_id,
                    rpc_for_chain(protocol_chain, rpc_url),
                    protocol_chain,
                    enroll_controllers=True,
                )
                if _has_transient_plan_failures(work_session, enrolled):
                    raise RuntimeError("Enrollment incomplete: tracking plans temporarily unreadable")
                _finish_success(work_session, claim)
            drained += 1
        except Exception as exc:
            # Degraded, not failing: the claim is re-queued with backoff and the
            # drain continues with the next protocol.
            logger.warning(
                "enrollment drain failed for a protocol; the claim is re-queued",
                extra={"protocol_id": claim.protocol_id, "exc_type": type(exc).__name__, "error": str(exc)},
            )
            failed += 1
            try:
                with SessionLocal() as fail_session:
                    _finish_failure(fail_session, claim)
            except Exception as book_exc:
                logger.warning(
                    "enrollment failure-bookkeeping failed for a protocol; its backoff is not advanced",
                    extra={
                        "protocol_id": claim.protocol_id,
                        "exc_type": type(book_exc).__name__,
                        "error": str(book_exc),
                    },
                )

    if drained or failed:
        logger.info("enrollment drain: %d reconciled, %d failed", drained, failed)
    return {"drained": drained, "failed": failed}


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


def _queue_depth(session: Session) -> int:
    return int(session.execute(select(func.count()).select_from(MonitoringEnrollmentQueue)).scalar() or 0)


def run_enrollment_reconciler_loop(
    rpc_url: str,
    chain: str,
    interval: float = DEFAULT_RECONCILE_INTERVAL_S,
    stop_event: Event | None = None,
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
        swept = []
        depth = 0
        status = "running"
        try:
            with SessionLocal() as session:
                swept = sweep_enqueue_stale(session)
            result = drain_enrollment_queue(rpc_url, chain)
            with SessionLocal() as session:
                depth = _queue_depth(session)
        except Exception as exc:
            # The tick is lost, not the loop: the heartbeat below records the
            # degraded pass and the next interval retries.
            logger.warning(
                "reconciler tick failed",
                extra={"exc_type": type(exc).__name__, "error": str(exc)},
            )
            status = "error"
        record_heartbeat(
            HEARTBEAT_ENROLLMENT_RECONCILER,
            status=status,
            detail={
                "drained": result["drained"],
                "failures": result["failed"],
                "queue_depth": depth,
                "repair_enqueued": len(swept),
            },
        )
        stop_event.wait(interval)
