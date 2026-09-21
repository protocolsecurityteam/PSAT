"""Coordination shared by the controller, launcher and queue claimers.

The one-row gate serializes *claims*, not analysis. A boot holds a separate
session advisory lock for its lifetime. Draining closes the gate atomically;
existing claims finish normally. Producers never need a Fly credential or ping.
"""

from __future__ import annotations

import os
import uuid

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


def boot_phase(session: Session, boot: uuid.UUID) -> str:
    session.execute(text("SET LOCAL statement_timeout = '5s'"))
    phase = session.execute(
        text("""
            UPDATE worker_lifecycle SET heartbeat_at=clock_timestamp()
            WHERE id=1 AND boot_id=:boot RETURNING phase
        """),
        {"boot": boot},
    ).scalar_one()
    session.commit()
    return phase


def finish_boot(session: Session, boot: uuid.UUID) -> None:
    session.execute(
        text(
            "UPDATE worker_lifecycle SET phase='stopped', heartbeat_at=clock_timestamp() WHERE id=1 AND boot_id=:boot"
        ),
        {"boot": boot},
    )
    session.commit()
