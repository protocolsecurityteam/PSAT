"""Coordination shared by the controller, launcher and queue claimers.

The one-row gate serializes *claims*, not analysis. A boot holds a separate
session advisory lock for its lifetime. Draining closes the gate atomically;
existing claims finish normally. Producers never need a Fly credential or ping.
"""

from __future__ import annotations

import os
import uuid

import psycopg2
from sqlalchemy import text
from sqlalchemy.orm import Session


def lifecycle_mode() -> str:
    mode = os.getenv("PSAT_WORKER_LIFECYCLE_MODE", "off")
    if mode not in {"off", "observe", "enforce"}:
        raise ValueError("PSAT_WORKER_LIFECYCLE_MODE must be off, observe, or enforce")
    return mode


def claim_allowed(session: Session) -> bool:
    """Hold the gate until the claim commits, including custom claim paths.

    Only managed worker children receive a boot ID. Browser/admin/legacy processes
    retain their existing behavior. A missing row or stale boot fails closed.
    FOR UPDATE avoids shared-lock upgrades deadlocking simultaneous claims.
    """
    boot = os.getenv("PSAT_WORKER_BOOT_ID")
    if not boot:
        return True
    return (
        session.execute(
            text("SELECT phase = 'running' AND boot_id = :boot FROM worker_lifecycle WHERE id = 1 FOR UPDATE"),
            {"boot": uuid.UUID(boot)},
        ).scalar_one()
        is True
    )


def note_claim(session: Session) -> None:
    """Record even a short job entirely between controller samples."""
    boot = os.getenv("PSAT_WORKER_BOOT_ID")
    if boot:
        session.execute(
            text("UPDATE worker_lifecycle SET last_work_at = clock_timestamp() WHERE id = 1 AND boot_id = :boot"),
            {"boot": uuid.UUID(boot)},
        )


def register_boot(session: Session, boot: uuid.UUID, machine_id: str) -> None:
    # Caller MUST hold the workers singleton lock. No TTL takeover of a live VM.
    session.execute(
        text("""
            UPDATE worker_lifecycle SET boot_id=:boot, machine_id=:machine,
                phase='running', started_at=clock_timestamp(), heartbeat_at=clock_timestamp(),
                last_work_at=clock_timestamp(), idle_since=NULL
            WHERE id=1
        """),
        {"boot": boot, "machine": machine_id},
    )
    session.commit()


class BootSuperseded(RuntimeError):
    """The lifecycle row names another boot, so this launcher no longer owns the workers."""


def boot_phase(session: Session, boot: uuid.UUID) -> str:
    """The boot's phase, refreshing its heartbeat unless a claim holds the gate row.

    Claims hold the row for their whole transaction; on a CPU-starved machine a heartbeat queued behind them timed
    out and took the group down. A skipped beat only delays a drain, which the controller refuses without a fresh one.
    """
    session.execute(text("SET LOCAL statement_timeout = '5s'"))
    phase = session.execute(
        text("""
            UPDATE worker_lifecycle SET heartbeat_at=clock_timestamp()
            WHERE id = (SELECT id FROM worker_lifecycle WHERE id=1 AND boot_id=:boot FOR UPDATE SKIP LOCKED)
            RETURNING phase
        """),
        {"boot": boot},
    ).scalar_one_or_none()
    if phase is None:
        phase = session.execute(
            text("SELECT phase FROM worker_lifecycle WHERE id=1 AND boot_id=:boot"), {"boot": boot}
        ).scalar_one_or_none()
    session.commit()
    if phase is None:
        raise BootSuperseded("worker boot superseded")
    return phase


def db_error_detail(exc: BaseException) -> dict[str, str | None]:
    """Log fields for a failed lifecycle query: the Postgres code and primary message, never the statement.

    Data and constraint errors (SQLSTATE classes 22, 23) can echo bound values, so they keep the code only.
    """
    orig = getattr(exc, "orig", exc)
    if not isinstance(orig, psycopg2.Error):
        return {"exc_type": type(exc).__name__}
    detail: dict[str, str | None] = {"exc_type": type(exc).__name__, "pgcode": orig.pgcode}
    if not (orig.pgcode or "").startswith(("22", "23")):
        detail["db_error"] = orig.diag.message_primary or (str(orig).splitlines() or [""])[0]
    return detail


def finish_boot(session: Session, boot: uuid.UUID) -> None:
    session.execute(
        text(
            "UPDATE worker_lifecycle SET phase='stopped', heartbeat_at=clock_timestamp() WHERE id=1 AND boot_id=:boot"
        ),
        {"boot": boot},
    )
    session.commit()
