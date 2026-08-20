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
    """Sweep jobs whose lease has expired back to ``queued``.

    Lease-based: a row is eligible when ``lease_expires_at < NOW()``.
    ``_heartbeat`` extends ``lease_expires_at`` past now+ttl, so a worker
    that's actively heartbeating from inside its long task keeps its lease
    alive and is never reclaimed. A crashed worker — or one stuck so long
    that even the heartbeat callback never fired — has an expired lease
    and the row goes back to the queue.

    Pre-migration rows (``lease_expires_at IS NULL``) fall through to the
    legacy ``updated_at < NOW() - timeout`` predicate so an in-progress
    deploy doesn't strand jobs. The OR is index-friendly: the partial
    ``ix_jobs_lease_expires_at`` covers the new path, and ``ix_jobs_stage_status``
    covers the legacy path.

    The reset clears ``lease_id`` and ``lease_expires_at`` alongside
    ``status`` and ``worker_id`` so the next ``claim_job`` mints a fresh
    lease.

    ``failed_terminal`` rows are intentionally excluded by the
    ``status = 'processing'`` predicate — operators promote them back to
    ``queued`` via ``POST /api/jobs/{id}/retry``, never via the sweep.
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
    """Insert a new job at the given stage with status=queued.

    ``trace_id`` is read from the ambient contextvar (set by the API
    ingress middleware on HTTP-triggered creates, or by the parent
    worker on child-job spawns). When neither is bound, a fresh id is
    minted so every job in the system is correlatable end-to-end.
    """
    from utils.logging import trace_id_var

    trace_id = trace_id_var.get() or uuid.uuid4().hex[:16]
    address = request_dict.get("address")
    job = Job(
        address=address,
        # Explicit enqueue-path dual-write (invariant 1). Shares the model's
        # derivation, which also runs as a column default for any non-create_job
        # construction, so the two layers can never disagree.
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
    """Claim the next available job for the given stage using SKIP LOCKED.

    Atomically flips ``status`` to ``processing`` and stamps a fresh
    ``lease_id`` (uuid4) + ``lease_expires_at = NOW() + lease_ttl_seconds``
    so the caller's mutating writes can prove they still hold the lease.
    Returning the row's ``lease_id`` is what gives ``BaseWorker._execute_job``
    the token it needs to pass back to ``advance_job`` / ``complete_job``
    / ``requeue_job`` / ``fail_job_terminal`` — those reject writes whose
    ``lease_id`` doesn't match.

    Honours ``Job.next_attempt_at``: a queued job set by ``requeue_job`` to
    retry in the future is skipped until the DB clock catches up. We compare
    against ``NOW()`` (Postgres-side) rather than Python's clock so workers
    spread across processes/timezones agree on eligibility.

    Honours ``job_dependencies``: a job with at least one row whose status
    is ``'pending'`` is skipped. Dependent rows are flipped to
    ``'satisfied'`` by ``BaseWorker._satisfy_dependencies`` when the
    provider job completes the required stage, and to ``'degraded'`` if
    the provider terminally fails (so dependents fall back to
    ``external_check_only`` rather than block forever). The partial
    index ``ix_job_dep_pending`` keeps the ``NOT EXISTS`` clause sub-ms
    even at fleet scale.
    """
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
    job.status = JobStatus.processing
    job.worker_id = worker_id
    job.lease_id = uuid.uuid4()
    # Server-side NOW() so workers spread across hosts agree on the
    # expiry instant. ``func.now() + INTERVAL`` would require a literal
    # interval; we synthesize it via ``text``.
    session.execute(
        sa_update(Job)
        .where(Job.id == job.id)
        .values(lease_expires_at=text(f"NOW() + INTERVAL '{int(lease_ttl_seconds)} seconds'"))
    )
    session.commit()
    session.refresh(job)
    return job


def _check_lease_or_raise(job: Job, lease_id: uuid.UUID | None) -> None:
    """Verify the caller still holds the row's lease; raise ``LeaseLost`` if not.

    ``lease_id=None`` means the caller doesn't care (legacy/admin path);
    skip the check. The pre-claim ``lease_id`` column may itself be NULL
    on rows that pre-date the lease columns — in that case treat the
    write as authoritative (no live competing claimant).
    """
    if lease_id is None:
        return
    if job.lease_id is None:
        return
    if job.lease_id != lease_id:
        raise LeaseLost(
            f"Job {job.id}: lease {lease_id} no longer holds the row "
            f"(current holder: {job.lease_id}, worker_id={job.worker_id})"
        )


def heartbeat_job(
    session: Session,
    job_id: Any,
    *,
    lease_id: uuid.UUID,
    lease_ttl_seconds: int = DEFAULT_JOB_LEASE_TTL_S,
) -> None:
    """Extend the row's lease past now+ttl. Raises ``LeaseLost`` if the
    caller's lease has rolled to a sibling.

    Conditional UPDATE in one round trip — no SELECT-then-UPDATE race
    window. ``RETURNING id`` lets us tell "row matched and updated" from
    "row exists but lease_id differs" without a second query.
    """
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
    """Update the human-readable progress message on a job."""
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
    """Move a job to the next stage and reset status to queued.

    *lease_id*: when provided, refuses to write if the caller no longer
    holds the row's lease (raises ``LeaseLost``). ``BaseWorker``
    threads its claim-time lease through here so a worker that's been
    silently reclaimed can't advance a job a sibling is now processing.
    """
    job = session.get(Job, job_id)
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
    """Mark a job as completed with stage=done. See :func:`advance_job` for *lease_id*."""
    job = session.get(Job, job_id)
    if job is None:
        return
    _check_lease_or_raise(job, lease_id)
    job.stage = JobStage.done
    job.status = JobStatus.completed
    job.detail = detail
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    session.commit()


def _convert_impl_job_to_proxy_context(
    session: Session,
    job: Job,
    *,
    proxy_addr: str,
    proxy_type: str | None = None,
    discovery_relationship: str = "implementation",
) -> None:
    """Back-patch a standalone impl job to proxy context, re-enqueuing it if it ran.

    An impl discovered standalone (e.g. via deployer expansion) before its proxy is
    classified gets a job with no ``proxy_address`` and resolves against its own
    empty storage. When the proxy later links it, convert that same job to proxy
    context — one job, no duplicate — and re-run from static so split-proxy
    secondary-impl linkage fires and resolution re-reads against the proxy. The
    re-resolution's deployment-scoped writes sweep the stale standalone rows.
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
    """Decide how to spawn/dedupe an implementation job now known to sit behind
    ``proxy_addr``. Returns one of:

    * ``"skip"`` — a proxy-context job for this exact ``(impl, proxy)`` already
      exists (true duplicate).
    * ``"backpatched"`` — an existing standalone (no ``proxy_address``) job for the
      impl was converted to proxy context (and re-enqueued if it had already run).
      Fixes the discovery-ordering race where the impl was analyzed before its proxy.
    * ``"spawn"`` — caller should create a fresh proxy-context child: either no job
      exists, or only a *different* proxy's job exists (a genuine shared impl behind
      N proxies — each proxy is its own deployment, keyed by ``deployment_address``).

    ``root_job_id`` scopes the lookup to the current cascade for ``--force`` re-runs
    (mirrors the existing per-cascade dedupe).
    """
    impl_lc = impl_addr.lower()
    proxy_lc = proxy_addr.lower()

    def _scoped(stmt):
        # Chain is filtered in BOTH branches. Previously the chain predicate was
        # nested under ``root_job_id is not None``, so when root_job_id was None a
        # same-address impl job on a *different* chain could masquerade as a
        # duplicate (invariant 1). Impl jobs are address-scoped, so ``jobs.chain_id``
        # is populated and the filter is total (``derive_job_chain_id`` maps the
        # chain string to the stored id; unknown/missing → 1).
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
    """Mark a job as failed with the error traceback.

    Retained for callers outside ``BaseWorker`` that have not been migrated
    to the transient/terminal split. Inside the worker the failure path
    routes through :func:`requeue_job` (transient) or
    :func:`fail_job_terminal` (terminal) so retries and DLQ semantics apply.
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
    """Re-queue a job after a transient failure with a backoff timestamp.

    Mirrors :func:`fail_job`'s transactional discipline: one commit, no
    silent swallows. The row goes back to ``status='queued'`` so any
    eligible worker can claim it once ``NOW() >= next_attempt_at``;
    ``worker_id`` is cleared so the previous claimer's id doesn't linger
    on what's now an unclaimed row.

    The accumulated ``stage_errors`` artifact is the per-job audit log of
    every attempt — this function does not touch it. The caller (typically
    ``BaseWorker``) appends the just-failed attempt before calling here.
    """
    job = session.get(Job, job_id)
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


def release_job_lease(
    session: Session,
    job_id: Any,
    *,
    lease_id: uuid.UUID,
    reason: str = "graceful shutdown",
) -> bool:
    """Release the lease on a ``processing`` job so a sibling worker can
    claim it immediately, without bumping ``retry_count`` or marking the
    row as failed.

    Use case: a worker receives SIGTERM mid-job (Fly machine drain,
    auto-stop, OOM) and exits before the in-flight stage can complete.
    The work didn't fail — the worker just had to stop. Without this
    helper the row sits in ``processing`` until ``lease_expires_at``
    fires (default 15min via ``DEFAULT_JOB_LEASE_TTL_S``), wedging any
    downstream pipeline waiting on its output. Calling this on shutdown
    collapses that 15min wait to ~0.

    Race-safe: the SQL filter on ``lease_id`` makes the UPDATE a no-op
    if the row is no longer leased to this caller. Two relevant races:
      1. The main thread completed the job between SIGTERM landing and
         the daemon-thread release: ``complete_job`` already cleared
         ``lease_id``, so this UPDATE matches 0 rows and we report
         "already handled" rather than overwriting completed status.
      2. ``reclaim_stuck_jobs`` swept the row first: same outcome.

    The conditional UPDATE replaces the in-memory ``_check_lease_or_raise``
    pattern used elsewhere because we explicitly want a no-throw,
    "best-effort idempotent release" semantic, not a raise-on-mismatch.

    Returns ``True`` if this call performed the release, ``False`` if
    the row was already released or no longer matched our lease.
    """
    result = session.execute(
        text(
            """
            UPDATE jobs
            SET status = 'queued',
                worker_id = NULL,
                lease_id = NULL,
                lease_expires_at = NULL,
                detail = :detail
            WHERE id = :job_id
              AND status = 'processing'
              AND lease_id = :lease_id
            """
        ),
        {"job_id": job_id, "lease_id": lease_id, "detail": f"Released lease: {reason}"},
    )
    session.commit()
    # ``CursorResult.rowcount`` is the standard accessor for affected-row
    # count; the typeshed stubs route through generic ``Result[Any]`` so
    # pyright doesn't see the attribute. Guard with ``getattr`` to keep
    # the strict-typecheck CI green without a noqa.
    return int(getattr(result, "rowcount", 0)) > 0


def fail_job_terminal(
    session: Session,
    job_id: Any,
    error: str,
    *,
    kind: str,
    retry_count: int | None = None,
    lease_id: uuid.UUID | None = None,
) -> None:
    """Mark a job as terminally failed (no further automatic retries).

    Distinct from :func:`fail_job` so observers can tell "retries exhausted
    or deterministically broken" apart from "just hit the legacy code
    path". The stale-job sweep does not resurrect ``failed_terminal`` rows.

    *kind* is the classifier verdict (``"transient"`` if retries were
    exhausted; ``"terminal"`` if classified as deterministic from the
    start). Persisted to ``last_failure_kind`` so an operator can answer
    "was this a flaky upstream or a bug?" without resolving the artifact.

    *retry_count* defaults to None — leaves the column unchanged, which is
    the right behaviour for deterministic terminal failures (we never
    retried, so the count shouldn't move). The retries-exhausted path
    passes ``new_retry_count`` so the row records the total attempt count.
    """
    job = session.get(Job, job_id)
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
