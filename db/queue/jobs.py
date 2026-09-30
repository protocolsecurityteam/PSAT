"""Job lifecycle: create/claim/advance/complete/requeue/fail + lease checks."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

from db.models import Job, JobDependency, JobStage, JobStatus, derive_job_chain_id

from .heartbeats import DEFAULT_JOB_LEASE_TTL_S, DEFAULT_JOB_STALE_TIMEOUT, LeaseLost

logger = logging.getLogger("db.queue")


def reclaim_stuck_jobs(session: Session, stale_timeout_seconds: int = DEFAULT_JOB_STALE_TIMEOUT) -> list[str]:
    """Return jobs with expired leases to ``queued``.

    Heartbeating workers keep their lease; crashed or stuck ones don't. Rows without a lease (pre-migration) fall back
    to ``updated_at < NOW() - timeout``; both predicates are indexed. The reset clears the lease so ``claim_job`` mints
    a fresh one. ``failed_terminal`` rows are never touched (operators retry via ``POST /api/jobs/{id}/retry``).
    """
    result = session.execute(
        text(
            """
            UPDATE jobs
            SET status = 'queued', worker_id = NULL,
                lease_id = NULL, lease_expires_at = NULL
            WHERE id IN (
                SELECT id FROM jobs
                WHERE status = 'processing'
                  AND (
                    lease_expires_at < NOW()
                    OR (lease_expires_at IS NULL
                        AND updated_at < NOW() - (:timeout * INTERVAL '1 second'))
                  )
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id
            """
        ),
        {"timeout": stale_timeout_seconds},
    )
    rescued = [str(row_id) for (row_id,) in result]
    if rescued:
        session.commit()
        for job_id in rescued:
            logger.warning(
                "reclaim_stuck_jobs: reset job %s (lease expired or stuck > %ss)",
                job_id,
                stale_timeout_seconds,
            )
    else:
        session.rollback()
    return rescued


def create_job(
    session: Session,
    request_dict: dict[str, Any],
    initial_stage: JobStage = JobStage.discovery,
) -> Job:
    """Insert a queued job at the given stage. ``trace_id`` comes from the ambient contextvar, else a fresh one."""
    from utils.logging import trace_id_var

    trace_id = trace_id_var.get() or uuid.uuid4().hex[:16]
    address = request_dict.get("address")
    job = Job(
        address=address,
        # Enqueue-path dual-write (invariant 1), sharing the model default's derivation.
        chain_id=derive_job_chain_id(request_dict.get("chain"), address),
        company=request_dict.get("company"),
        name=request_dict.get("name"),
        status=JobStatus.queued,
        stage=initial_stage,
        detail="Queued for analysis",
        request=request_dict,
        protocol_id=request_dict.get("protocol_id"),
        trace_id=trace_id,
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    return job


def claim_job(
    session: Session,
    target_stage: JobStage,
    worker_id: str,
    *,
    lease_ttl_seconds: int = DEFAULT_JOB_LEASE_TTL_S,
) -> Job | None:
    """Claim the next job for a stage with SKIP LOCKED.

    Sets ``processing`` and a fresh ``lease_id`` + ``lease_expires_at``; the lease token is passed back to the mutating
    writes, which reject mismatches. Skips rows whose ``next_attempt_at`` (DB clock) hasn't arrived and rows with
    pending ``job_dependencies`` (see :class:`~db.models.JobDependency`; ``ix_job_dep_pending`` keeps it fast).
    """
    from services.worker_lifecycle import claim_allowed, note_claim

    if not claim_allowed(session):
        return None
    pending_dep_exists = (
        select(JobDependency.id)
        .where(
            JobDependency.depender_job_id == Job.id,
            JobDependency.status == "pending",
        )
        .exists()
    )
    stmt = (
        select(Job)
        .where(
            Job.stage == target_stage,
            Job.status == JobStatus.queued,
            (Job.next_attempt_at.is_(None) | (Job.next_attempt_at <= func.now())),
            ~pending_dep_exists,
        )
        .order_by(Job.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    job = session.execute(stmt).scalar_one_or_none()
    if job is None:
        return None
    note_claim(session)
    job.status = JobStatus.processing
    job.worker_id = worker_id
    job.lease_id = uuid.uuid4()
    # Server-side NOW() so hosts agree.
    session.execute(
        sa_update(Job)
        .where(Job.id == job.id)
        .values(lease_expires_at=text(f"NOW() + INTERVAL '{int(lease_ttl_seconds)} seconds'"))
    )
    session.commit()
    session.refresh(job)
    return job


def _check_lease_or_raise(job: Job, lease_id: uuid.UUID | None) -> None:
    """Raise ``LeaseLost`` unless the caller holds the lease.

    ``lease_id=None`` skips the check (legacy/admin); a supplied token must match even if the current lease is NULL.
    """
    if lease_id is None:
        return
    if job.lease_id != lease_id:
        raise LeaseLost(
            f"Job {job.id}: lease {lease_id} no longer holds the row "
            f"(current holder: {job.lease_id}, worker_id={job.worker_id})"
        )


def _locked_job(session: Session, job_id: Any, lease_id: uuid.UUID | None) -> Job | None:
    if lease_id is not None:
        # Check the database, not the ORM cache, without autoflushing pending fields.
        with session.no_autoflush:
            row = session.execute(select(Job.lease_id).where(Job.id == job_id).with_for_update()).first()
            if row is None:
                return None
            if row[0] != lease_id:
                raise LeaseLost(f"Job {job_id}: lease no longer owns the row")
    return session.get(Job, job_id)


def heartbeat_job(
    session: Session,
    job_id: Any,
    *,
    lease_id: uuid.UUID,
    lease_ttl_seconds: int = DEFAULT_JOB_LEASE_TTL_S,
) -> None:
    """Extend the lease; raises ``LeaseLost`` if it moved. One conditional UPDATE with ``RETURNING``."""
    result = session.execute(
        text(
            """
            UPDATE jobs
            SET lease_expires_at = NOW() + (:ttl * INTERVAL '1 second'),
                updated_at = NOW()
            WHERE id = :job_id
              AND lease_id = :lease_id
            RETURNING id
            """
        ),
        {"ttl": int(lease_ttl_seconds), "job_id": job_id, "lease_id": lease_id},
    )
    rows = result.fetchall()
    session.commit()
    if not rows:
        raise LeaseLost(f"Job {job_id}: heartbeat rejected — lease {lease_id} no longer holds the row")


def update_job_detail(session: Session, job_id: Any, detail: str) -> None:
    job = session.get(Job, job_id)
    if job:
        job.detail = detail
        session.commit()


def advance_job(
    session: Session,
    job_id: Any,
    next_stage: JobStage,
    detail: str = "",
    *,
    lease_id: uuid.UUID | None = None,
) -> None:
    """Advance to the next stage, reset to queued. A given *lease_id* must still hold the lease (``LeaseLost``)."""
    job = _locked_job(session, job_id, lease_id)
    if job is None:
        return
    _check_lease_or_raise(job, lease_id)
    job.stage = next_stage
    job.status = JobStatus.queued
    job.detail = detail or f"Advanced to {next_stage.value}"
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    session.commit()


def complete_job(
    session: Session,
    job_id: Any,
    detail: str = "Analysis complete",
    *,
    lease_id: uuid.UUID | None = None,
) -> None:
    """Mark completed with stage=done. See :func:`advance_job` for *lease_id*."""
    job = _locked_job(session, job_id, lease_id)
    if job is None:
        return
    _check_lease_or_raise(job, lease_id)
    newly_completed = job.status != JobStatus.completed
    job.stage = JobStage.done
    job.status = JobStatus.completed
    job.detail = detail
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    if newly_completed and job.protocol_id is not None and job.address:
        # Enrollment reads completed jobs, and an earlier notification may drain before completion, so notify again
        # atomically here.
        from services.monitoring.enrollment import mark_enrollment_dirty

        mark_enrollment_dirty(session, job.protocol_id, "analysis_complete")
    session.commit()


def _convert_impl_job_to_proxy_context(
    session: Session,
    job: Job,
    *,
    proxy_addr: str,
    proxy_type: str | None = None,
    discovery_relationship: str = "implementation",
) -> None:
    """Convert a standalone impl job to proxy context, re-enqueuing it if it already ran.

    An impl found before its proxy resolves against its own empty storage. Converting the same job (not a duplicate) and
    re-running from static lets split-proxy linkage fire and re-reads against the proxy; the deployment-scoped writes
    replace the stale rows.
    """
    req = dict(job.request) if isinstance(job.request, dict) else {}
    req["proxy_address"] = proxy_addr
    if proxy_type:
        req["proxy_type"] = proxy_type
    req.setdefault("discovery_relationship", discovery_relationship)
    job.request = req  # reassign so SQLAlchemy flushes the JSONB change

    already_ran_resolution = job.status == JobStatus.completed or job.stage in (
        JobStage.resolution,
        JobStage.policy,
        JobStage.effects,
        JobStage.coverage,
        JobStage.done,
    )
    if already_ran_resolution:
        job.stage = JobStage.static
        job.status = JobStatus.queued
        job.worker_id = None
        job.lease_id = None
        job.lease_expires_at = None
        job.next_attempt_at = None
        job.detail = f"Re-resolving in proxy context ({proxy_addr})"
    session.commit()


def reconcile_impl_job_for_proxy(
    session: Session,
    *,
    impl_addr: str,
    proxy_addr: str,
    proxy_type: str | None = None,
    chain: str | None = None,
    root_job_id: str | None = None,
    discovery_relationship: str = "implementation",
) -> str:
    """How to spawn or dedupe an impl job now known to sit behind ``proxy_addr``:

    * ``"skip"``: a proxy-context job for this ``(impl, proxy)`` exists.
    * ``"backpatched"``: a standalone job was converted to proxy context (the discovery-order race).
    * ``"spawn"``: create a proxy-context child (no job, or only another proxy's; a shared impl gets one per
    deployment).

    ``root_job_id`` scopes lookups to the current cascade for ``--force`` re-runs.
    """
    impl_lc = impl_addr.lower()
    proxy_lc = proxy_addr.lower()

    def _scoped(stmt):
        # An effects-only retry isn't an implementation analysis.
        stmt = stmt.where(Job.request["effects_resume_work_id"].astext.is_(None))
        # Filter chain in both branches; it used to apply only with a root, letting another chain's job look like a
        # duplicate (invariant 1).
        if chain is not None:
            stmt = stmt.where(Job.chain_id == derive_job_chain_id(chain, impl_lc))
        if root_job_id is not None:
            stmt = stmt.where(Job.request["root_job_id"].as_string() == root_job_id)
        return stmt

    same_proxy = session.execute(
        _scoped(
            select(Job).where(
                Job.address == impl_lc,
                func.lower(Job.request["proxy_address"].as_string()) == proxy_lc,
            )
        ).limit(1)
    ).scalar_one_or_none()
    if same_proxy is not None:
        return "skip"

    standalone = session.execute(
        _scoped(
            select(Job).where(
                Job.address == impl_lc,
                Job.request["proxy_address"].as_string().is_(None),
            )
        ).limit(1)
    ).scalar_one_or_none()
    if standalone is not None:
        _convert_impl_job_to_proxy_context(
            session,
            standalone,
            proxy_addr=proxy_lc,
            proxy_type=proxy_type,
            discovery_relationship=discovery_relationship,
        )
        return "backpatched"

    other_proxy = session.execute(_scoped(select(Job.id).where(Job.address == impl_lc)).limit(1)).scalar_one_or_none()
    if other_proxy is not None:
        logger.warning(
            "Shared implementation %s is behind multiple proxies; spawning a separate "
            "per-deployment job for proxy %s (resolution keyed by deployment_address)",
            impl_lc,
            proxy_lc,
        )
    return "spawn"


def fail_job(session: Session, job_id: Any, error: str) -> None:
    """Mark failed with a traceback.

    For callers outside ``BaseWorker``, which uses :func:`requeue_job` / :func:`fail_job_terminal`.
    """
    job = session.get(Job, job_id)
    if job is None:
        return
    job.status = JobStatus.failed
    job.error = error
    job.detail = "Failed"
    job.worker_id = None
    session.commit()


def requeue_job(
    session: Session,
    job_id: Any,
    error: str,
    *,
    retry_count: int,
    next_attempt_at: datetime,
    lease_id: uuid.UUID | None = None,
) -> None:
    """Requeue after a transient failure with a backoff timestamp; clears ``worker_id``.

    Doesn't touch ``stage_errors`` (the caller appends the attempt first).
    """
    job = _locked_job(session, job_id, lease_id)
    if job is None:
        return
    _check_lease_or_raise(job, lease_id)
    job.status = JobStatus.queued
    job.error = error
    job.retry_count = retry_count
    job.next_attempt_at = next_attempt_at
    job.last_failure_kind = "transient"
    job.detail = f"Retry scheduled for {next_attempt_at.isoformat()}"
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    session.commit()


def fail_job_terminal(
    session: Session,
    job_id: Any,
    error: str,
    *,
    kind: str,
    retry_count: int | None = None,
    lease_id: uuid.UUID | None = None,
) -> None:
    """Mark terminally failed (no more automatic retries; the sweep ignores it).

    *kind* is ``"transient"`` (retries exhausted) or ``"terminal"`` (deterministic), stored in ``last_failure_kind``.
    *retry_count* None leaves the column unchanged (deterministic failures never retried); the exhausted path passes the
    total.
    """
    job = _locked_job(session, job_id, lease_id)
    if job is None:
        return
    _check_lease_or_raise(job, lease_id)
    job.status = JobStatus.failed_terminal
    job.error = error
    job.detail = "Failed (terminal)"
    job.last_failure_kind = kind
    job.next_attempt_at = None
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    if retry_count is not None:
        job.retry_count = retry_count
    session.commit()
