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

# How long a ``processing`` job may sit before its worker is presumed dead (legacy ``updated_at`` path; the lease path
# uses ``lease_expires_at``).
DEFAULT_JOB_STALE_TIMEOUT = int(os.getenv("PSAT_JOB_STALE_TIMEOUT", "900"))

# Per-claim lease lifetime; set on claim and extended by heartbeats. Expired leases are reclaimed.
DEFAULT_JOB_LEASE_TTL_S = int(os.getenv("PSAT_JOB_LEASE_TTL_S", str(DEFAULT_JOB_STALE_TIMEOUT)))

# Process names for daemons draining their own tables, shared with the ``/api/fleet`` reader.
HEARTBEAT_COVERAGE_VERIFY = "coverage_verify"
HEARTBEAT_EVENT_INDEXER = "event_log_indexer"
HEARTBEAT_ENROLLMENT_RECONCILER = "enrollment_reconciler"
HEARTBEAT_AUDIT_TEXT = "audit_text_extraction"
HEARTBEAT_AUDIT_SCOPE = "audit_scope_extraction"
# The monitoring loops run outside BaseWorker, so each records its own per-cycle heartbeat.
HEARTBEAT_PROTOCOL_SCANNER = "protocol_scanner"
HEARTBEAT_PROTOCOL_POLLER = "protocol_poller"
HEARTBEAT_PROTOCOL_TVL = "protocol_tvl"
HEARTBEAT_PROTOCOL_RESTAKING = "protocol_restaking"
HEARTBEAT_ROLE_HOLDER_PLANE = "role_holder_plane"
HEARTBEAT_PROTOCOL_SCORE = "protocol_score"
# Runs in the web app; its row also stores alert dedupe/cooldown state (services/monitoring/ops_alerts.py).
HEARTBEAT_OPS_ALERTER = "ops_alerter"


# Re-warn interval for a persistently failing heartbeat write.
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
    """Upsert a daemon's liveness row (best-effort).

    Uses its own session and never raises into the caller. ``detail`` is a small summary for the fleet view.
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
        # Rate-limited, not silent: a missing heartbeat makes daemons look dead and pages; rate-limited because every
        # daemon calls this each pass.
        if _heartbeat_failure_is_due(process):
            logger.warning(
                "heartbeat write failed; the fleet view will read this daemon as dead",
                extra={"daemon": process, "exc_type": type(exc).__name__, "error": str(exc)},
            )
        else:
            logger.debug("heartbeat write failed for process=%s", process, exc_info=True)


# Exceeds ~3x the worst scan window and the RPC timeout, so a stalled call rarely loses the lease mid-pass.
DEFAULT_DAEMON_LEASE_TTL_S = int(os.getenv("PSAT_DAEMON_LEASE_TTL_S", "120"))


def try_acquire_daemon_lease(
    session: Session,
    name: str,
    holder: uuid.UUID,
    ttl_seconds: int = DEFAULT_DAEMON_LEASE_TTL_S,
) -> bool:
    """Take or extend the named singleton lease; True on win.

    One ``INSERT ... ON CONFLICT (name) DO UPDATE`` whose ``WHERE`` allows the update only if the lease expired or is
    ours, so there's no race. Fresh or expired names win; a live lease held by someone else loses; the holder always
    wins and extends (renewal is re-acquisition). Expiry uses the DB clock.

    Commits internally like the rest of this module, which also flushes the caller's in-flight window writes (intended:
    cursor and lease land together).
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
    """Alias for ``try_acquire_daemon_lease`` at renewal sites. False only if the lease was lost."""
    return try_acquire_daemon_lease(session, name, holder, ttl_seconds)


class LeaseLost(RuntimeError):
    """A mutating queue write found the caller no longer holds the lease.

    Fatal for this attempt: another worker owns the job. ``BaseWorker._execute_job`` logs and stops.
    """
