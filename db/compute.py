"""Compute routing and transaction-scoped group recovery serialization."""

from __future__ import annotations

import hashlib
import os
import uuid

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from db.attempts import LeaseLost, assert_current_job_attempt, session_attempt
from db.models import Job, JobStage, JobStatus

ROUTED_COMPUTE_STAGES = frozenset({JobStage.static, JobStage.resolution, JobStage.policy, JobStage.effects})


def routing_enabled() -> bool:
    return os.getenv("PSAT_LOCAL_COMPUTE_ROUTING_ENABLED", "0") == "1"


def worker_compute_target() -> str:
    target = os.getenv("PSAT_COMPUTE_TARGET", "cloud")
    if target not in {"cloud", "local"}:
        raise ValueError("PSAT_COMPUTE_TARGET must be cloud or local")
    if target == "local" and not routing_enabled():
        raise ValueError("Local compute routing is disabled")
    return target


def lock_compute_groups(session: Session, *groups: uuid.UUID) -> None:
    for group in sorted(set(groups), key=str):
        key = int.from_bytes(
            hashlib.sha256(b"psat-compute-group:" + str(group).encode()).digest()[:8], byteorder="big", signed=True
        )
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def parent_route(session: Session, parent: Job) -> tuple[str, uuid.UUID]:
    with session.no_autoflush:
        group = session.execute(select(Job.compute_group_id).where(Job.id == parent.id)).scalar_one()
        lock_compute_groups(session, group)
        row = session.execute(
            select(Job.compute_target, Job.compute_group_id).where(Job.id == parent.id).with_for_update()
        ).one()
    if row.compute_group_id != group:
        raise LeaseLost("Parent group changed while acquiring routing authority")
    attempt = session_attempt(session)
    if attempt is None or attempt.job_id != parent.id:
        raise LeaseLost("Child creation requires the parent's claim-time attempt")
    assert_current_job_attempt(session, attempt.job_id, attempt.lease_id)
    return row.compute_target, row.compute_group_id


class ComputeGroupBusy(RuntimeError):
    pass


def move_group_to_cloud(session: Session, job_id: uuid.UUID) -> int:
    """Move a settled group; caller owns the transaction and audit log."""
    group = session.execute(select(Job.compute_group_id).where(Job.id == job_id)).scalar_one()
    lock_compute_groups(session, group)
    rows = (
        session.execute(
            select(Job)
            .where(Job.compute_group_id == group)
            .order_by(Job.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )
    if not any(row.id == job_id for row in rows):
        raise ComputeGroupBusy("Job changed groups; refresh and retry")
    if any(row.status == JobStatus.processing or row.lease_id is not None for row in rows):
        raise ComputeGroupBusy("A group attempt can still publish; stop workers and wait for lease recovery")
    for row in rows:
        row.compute_target = "cloud"
    session.flush()
    return len(rows)


def reactivate_terminal_job(
    session: Session,
    job_id: uuid.UUID,
    *,
    expected_stage: JobStage,
    next_stage: JobStage,
    detail: str,
    request: dict | None = None,
    routing_from: Job | None = None,
) -> bool:
    """Row-locked system/proxy reactivation; never changes active work."""
    with session.no_autoflush:
        group = session.execute(select(Job.compute_group_id).where(Job.id == job_id)).scalar_one()
        parent_group = (
            session.execute(select(Job.compute_group_id).where(Job.id == routing_from.id)).scalar_one()
            if routing_from is not None
            else group
        )
        lock_compute_groups(session, group, parent_group)
        job = session.execute(
            select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True)
        ).scalar_one()
        if job.compute_group_id != group or job.status != JobStatus.completed or job.stage != expected_stage:
            return False
        if routing_from is not None:
            actual_parent_group = session.execute(
                select(Job.compute_group_id).where(Job.id == routing_from.id)
            ).scalar_one()
            if actual_parent_group != parent_group:
                return False
        target, adopted_group = parent_route(session, routing_from) if routing_from is not None else ("cloud", group)
    job.stage = next_stage
    job.status = JobStatus.queued
    job.compute_target = target
    job.compute_group_id = adopted_group
    if request is not None:
        job.request = request
    job.detail = detail
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    job.next_attempt_at = None
    job.retry_count = 0
    job.last_failure_kind = None
    job.error = None
    session.flush()
    return True
