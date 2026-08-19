"""Daemon heartbeats and singleton daemon leases."""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any

from sqlalchemy import func, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import SessionLocal, WorkerHeartbeat

logger = logging.getLogger("db.queue")

# How long a job can sit in ``status='processing'`` before we assume the
# worker holding it crashed and return the row to the queue. ``updated_at``
# is the legacy implicit heartbeat (every status/detail write stamped
# NOW()); the lease-based path replaces it with an explicit
# ``lease_expires_at`` column that the heartbeat extends.
DEFAULT_JOB_STALE_TIMEOUT = int(os.getenv("PSAT_JOB_STALE_TIMEOUT", "900"))

# Per-claim lease lifetime. A claimed job's ``lease_expires_at`` is set to
# NOW() + this on the initial claim and bumped past NOW()+this on every
# heartbeat. The reclaim sweep wakes any row whose lease has expired —
# either a crashed worker or a worker that's gone too long without a
# heartbeat (e.g. a single nested forge build over the heartbeat cadence).
DEFAULT_JOB_LEASE_TTL_S = int(os.getenv("PSAT_JOB_LEASE_TTL_S", str(DEFAULT_JOB_STALE_TIMEOUT)))

# Canonical process names for the background daemons that drain their own
# tables (not the jobs queue). Shared by the daemons (writers) and the
# ``/api/fleet`` endpoint (reader) so the two can't drift.
HEARTBEAT_COVERAGE_VERIFY = "coverage_verify"
HEARTBEAT_EVENT_INDEXER = "event_log_indexer"
HEARTBEAT_ENROLLMENT_RECONCILER = "enrollment_reconciler"
HEARTBEAT_AUDIT_TEXT = "audit_text_extraction"
HEARTBEAT_AUDIT_SCOPE = "audit_scope_extraction"
# The three monitoring-daemon loops (scan/poll/TVL) run outside BaseWorker,
# so each emits its own per-cycle ``record_heartbeat(detail={...})`` rather
# than job-scoped metrics. Names are shared by the writers (the loops) and
# the ``/api/fleet`` reader so the two can't drift.
HEARTBEAT_PROTOCOL_SCANNER = "protocol_scanner"
HEARTBEAT_PROTOCOL_POLLER = "protocol_poller"
HEARTBEAT_PROTOCOL_TVL = "protocol_tvl"
HEARTBEAT_PROTOCOL_RESTAKING = "protocol_restaking"
HEARTBEAT_ROLE_HOLDER_PLANE = "role_holder_plane"
HEARTBEAT_PROTOCOL_SCORE = "protocol_score"
# The ops watchdog runs in the web app lifespan; its heartbeat row doubles as
# the CAS-guarded store for alert dedupe/cooldown state (services/monitoring/
# ops_alerts.py).
HEARTBEAT_OPS_ALERTER = "ops_alerter"


# Seconds between two WARNINGs about the same process's failing heartbeat
# write. The first failure warns immediately; a persistent outage then re-warns
# on this cadence so the condition stays visible without repeating per pass.
_HEARTBEAT_WARN_INTERVAL_S = 300.0
_heartbeat_last_warned: dict[str, float] = {}


def _heartbeat_failure_is_due(process: str) -> bool:
    now = time.monotonic()
    last = _heartbeat_last_warned.get(process)
    if last is not None and now - last < _HEARTBEAT_WARN_INTERVAL_S:
        return False
    _heartbeat_last_warned[process] = now
    return True


def record_heartbeat(process: str, *, status: str = "running", detail: dict[str, Any] | None = None) -> None:
    """Upsert a background daemon's liveness row (best-effort).

    Opens its own short-lived session and never raises into the caller's
    loop — a heartbeat-write failure must not take down a worker. ``detail``
    carries a small JSON summary the daemon already computes (rows claimed,
    protocols reconciled, …) for the fleet view; the heavier work-state
    breakdowns are queried straight from each daemon's table by the endpoint.
    """
    try:
        with SessionLocal() as session:
            stmt = (
                pg_insert(WorkerHeartbeat)
                .values(process=process, status=status, detail=detail, beat_at=func.now())
                .on_conflict_do_update(
                    index_elements=["process"],
                    set_={"status": status, "detail": detail, "beat_at": func.now()},
                )
            )
            session.execute(stmt)
            session.commit()
    except Exception as exc:
        # Rate-limited rather than silent: a heartbeat that never lands makes
        # the fleet view show every daemon dead while the processes run happily,
        # and the ops watchdog pages on exactly that. Rate-limited rather than
        # unconditional because this is called once per pass by every daemon in
        # the process, so a DB outage would otherwise turn one fault into a
        # WARNING storm on top of it.
        if _heartbeat_failure_is_due(process):
            logger.warning(
                "heartbeat write failed; the fleet view will read this daemon as dead",
                extra={"daemon": process, "exc_type": type(exc).__name__, "error": str(exc)},
            )
        else:
            logger.debug("heartbeat write failed for process=%s", process, exc_info=True)


# Default lifetime of a daemon-pass lease. Chosen to exceed
# ~3× the worst scan window and the RPC client timeout, so a stalled getLogs
# rarely outlives the lease and lets a competitor steal it mid-pass.
DEFAULT_DAEMON_LEASE_TTL_S = int(os.getenv("PSAT_DAEMON_LEASE_TTL_S", "120"))


def try_acquire_daemon_lease(
    session: Session,
    name: str,
    holder: uuid.UUID,
    ttl_seconds: int = DEFAULT_DAEMON_LEASE_TTL_S,
) -> bool:
    """Try to take (or extend) the named singleton daemon lease. Returns True on win.

    One statement, no read-modify-write race: an ``INSERT ... ON CONFLICT (name)
    DO UPDATE`` whose ``WHERE`` is the exclusivity guarantee — the update fires
    (and ``RETURNING`` yields the row ⇒ win) only when the existing lease has
    expired *or* is already held by this caller. A live lease held by someone
    else fails the ``WHERE``, updates nothing, returns no row ⇒ lose.

    Semantics:
      * fresh name → inserted → win;
      * expired lease → stolen by the new holder → win;
      * live lease, different holder → lose;
      * current holder re-acquiring → always wins and pushes ``expires_at``
        forward. Renewal *is* re-acquisition (see ``renew_daemon_lease``).

    Expiry is ``NOW() + ttl`` evaluated server-side (Postgres clock), exactly
    like ``claim_job`` — so daemons on different hosts agree on the instant
    regardless of local clock skew.

    Commits internally, matching this module's convention (``claim_job`` /
    ``heartbeat_job`` / ``record_heartbeat`` all commit). Callers are per-pass
    daemon loops that also commit per window; a renewal here therefore flushes
    the caller's in-flight window writes along with the lease bump — intended,
    since the cursor advance and the lease renewal want to land together.
    """
    result = session.execute(
        text(
            """
            INSERT INTO daemon_leases (name, holder, expires_at)
            VALUES (:name, :holder, NOW() + (:ttl * INTERVAL '1 second'))
            ON CONFLICT (name) DO UPDATE
                SET holder = EXCLUDED.holder,
                    expires_at = EXCLUDED.expires_at
                WHERE daemon_leases.expires_at < NOW()
                   OR daemon_leases.holder = EXCLUDED.holder
            RETURNING name
            """
        ),
        {"name": name, "holder": holder, "ttl": int(ttl_seconds)},
    )
    won = result.first() is not None
    session.commit()
    return won


def renew_daemon_lease(
    session: Session,
    name: str,
    holder: uuid.UUID,
    ttl_seconds: int = DEFAULT_DAEMON_LEASE_TTL_S,
) -> bool:
    """Extend the caller's own lease past ``NOW() + ttl``. Returns True if held.

    A thin alias for ``try_acquire_daemon_lease`` for readability at the
    per-window/per-chunk renewal call sites — renewal is re-acquisition, and
    the ``holder = EXCLUDED.holder`` branch of the upsert makes the current
    holder's re-acquire always win. Returns False only if the lease was lost to
    a competitor (expired and stolen) since the last renewal.
    """
    return try_acquire_daemon_lease(session, name, holder, ttl_seconds)


class LeaseLost(RuntimeError):
    """Raised when a mutating queue write detects the caller no longer
    holds the row's lease.

    A worker should treat this as fatal for the current attempt: another
    worker has been handed the job, and any further writes from this
    thread would corrupt that worker's view. The handler in
    ``BaseWorker._execute_job`` logs it and bails without further
    advance/requeue/fail_terminal calls.
    """
