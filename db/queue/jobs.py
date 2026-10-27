"""Job lifecycle: create/claim/advance/complete/requeue/fail + lease checks."""

from __future__ import annotations

import functools
import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import bindparam, func, literal, or_, select, text
from sqlalchemy import update as sa_update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from db.models import Contract, Job, JobDependency, JobStage, JobStatus, derive_job_chain_id
from utils.chains import UnknownChainError, canonical_chain, chain_by_id, chain_by_name

from ._chains import _mainnet_coalesced_chain
from .heartbeats import DEFAULT_JOB_LEASE_TTL_S, DEFAULT_JOB_STALE_TIMEOUT, LeaseLost
from .static_cache import _not_stamped_with_other_era, _stands_without_walk_first, job_stands_for_current_analyzer

logger = logging.getLogger("db.queue")

# Set when a job is converted to proxy context while a stage that reads the context runs on its claim-time copy. That
# stage's exit, whichever it is, sends the job back to static; the running worker keeps its lease, so no second worker
# writes the job's artifacts alongside it.
RESTART_STATIC_REQUEST_KEY = "restart_static_for_proxy_context"
_CONTEXT_READING_STAGES = frozenset(
    {JobStage.static, JobStage.resolution, JobStage.policy, JobStage.effects, JobStage.coverage}
)
_POINTER_WRITING_STAGES = (JobStage.discovery, JobStage.static)
_RAN_PAST_STATIC_STAGES = frozenset(
    {JobStage.resolution, JobStage.policy, JobStage.effects, JobStage.coverage, JobStage.done}
)


class ProxyContextUnsettled(Exception):
    """A proxy pointing at the address has an analysis queued or running, so its pointer may still change."""

    def __init__(self, proxies: list[str]) -> None:
        super().__init__(", ".join(proxies))
        self.proxies = proxies


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


def _stamped_chain(raw: Any, chain_id: int | None) -> str | None:
    """The canonical name to store in an address job's request, so request readers can't disagree with ``chain_id``.

    A missing chain or an alias of a known chain becomes the canonical name; an unrecognized name is kept as given (it
    is not evidence of the chain ``chain_id`` defaulted to).
    """
    if chain_id is None:
        return None
    if not canonical_chain(raw):
        return chain_by_id(chain_id).name
    try:
        named = chain_by_name(raw)
    except UnknownChainError:
        return None
    return named.name if named.chain_id == chain_id else None


def create_job(
    session: Session,
    request_dict: dict[str, Any],
    initial_stage: JobStage = JobStage.discovery,
) -> Job:
    """Insert a queued job at the given stage. ``trace_id`` comes from the ambient contextvar, else a fresh one."""
    from utils.logging import trace_id_var

    trace_id = trace_id_var.get() or uuid.uuid4().hex[:16]
    address = request_dict.get("address")
    # Enqueue-path dual-write, sharing the model default's derivation.
    chain_id = derive_job_chain_id(request_dict.get("chain"), address)
    stamped = _stamped_chain(request_dict.get("chain"), chain_id)
    if stamped is not None and stamped != request_dict.get("chain"):
        request_dict = {**request_dict, "chain": stamped}
    job = Job(
        address=address,
        chain_id=chain_id,
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
    if _restart_static_if_flagged(session, job):
        session.commit()
        return
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
    if _restart_static_if_flagged(session, job):
        session.commit()
        return
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


def static_restart_pending(session: Session, job_id: Any, *, lease_id: uuid.UUID | None = None) -> bool:
    """Lock the job row and say whether its stage's exit will send it back to static (``RESTART_STATIC_REQUEST_KEY``).

    The lock is held until the caller's exit commits, so no conversion lands between this answer and the exit. Raises
    ``LeaseLost`` if a given *lease_id* no longer holds the row.
    """
    with session.no_autoflush:
        row = session.execute(
            select(Job.lease_id, Job.request[RESTART_STATIC_REQUEST_KEY].astext)
            .where(Job.id == job_id)
            .with_for_update()
        ).first()
    if row is None:
        return False
    if lease_id is not None and row[0] != lease_id:
        raise LeaseLost(f"Job {job_id}: lease no longer owns the row")
    return row[1] == "true"


def _restart_static_if_flagged(session: Session, job: Job) -> bool:
    """Consume :data:`RESTART_STATIC_REQUEST_KEY`: the job goes back to a queued static stage, the flag cleared.

    Read from the row, which the caller's lease lock holds, never from the session's claim-time copy.
    """
    flagged = session.execute(
        select(Job.request[RESTART_STATIC_REQUEST_KEY].astext).where(Job.id == job.id)
    ).scalar_one_or_none()
    if flagged != "true":
        return False
    stored = session.execute(
        sa_update(Job)
        .where(Job.id == job.id)
        .values(request=Job.request.op("-", return_type=JSONB)(literal(RESTART_STATIC_REQUEST_KEY)))
        .returning(Job.request)
        .execution_options(synchronize_session=False)
    ).first()
    set_committed_value(job, "request", stored[0] if stored is not None else None)
    job.stage = JobStage.static
    job.status = JobStatus.queued
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    job.next_attempt_at = None
    job.detail = "Re-running static in proxy context"
    return True


def defer_job(
    session: Session,
    job_id: Any,
    *,
    detail: str,
    delay_seconds: int,
    lease_id: uuid.UUID | None = None,
) -> None:
    """Put a claimed job back in its queue until ``delay_seconds`` from now (DB clock) without spending a retry: the
    stage is waiting on another job, not failing.
    """
    job = _locked_job(session, job_id, lease_id)
    if job is None:
        return
    _check_lease_or_raise(job, lease_id)
    job.status = JobStatus.queued
    job.detail = detail
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    session.execute(
        sa_update(Job)
        .where(Job.id == job_id)
        .values(next_attempt_at=text(f"NOW() + INTERVAL '{int(delay_seconds)} seconds'"))
        .execution_options(synchronize_session=False)
    )
    session.commit()


def merge_job_request(
    session: Session,
    job: Job,
    patch: dict[str, Any],
    *,
    defaults: dict[str, Any] | None = None,
    unless_present: str | None = None,
) -> bool:
    """Merge *patch* into the stored ``job.request`` in one UPDATE, never from the session's copy.

    Sessions keep the claim-time ``request``, so writing ``{**job.request, ...}`` back erases keys another worker wrote
    since (a proxy converting this job to its context). The merge reads the row's own value, and under a concurrent
    committed update Postgres re-evaluates it against the newest version. *defaults* fill only absent keys. With
    *unless_present*, nothing is written while that key holds a value, and False is returned. Either way the session's
    copy is set to the stored value. Doesn't commit.
    """
    merged = (
        literal(defaults or {}, JSONB)
        .op("||", return_type=JSONB)(func.coalesce(Job.request, literal({}, JSONB)))
        .op("||", return_type=JSONB)(literal(patch, JSONB))
    )
    stmt = sa_update(Job).where(Job.id == job.id)
    if unless_present is not None:
        stmt = stmt.where(Job.request[unless_present].astext.is_(None))
    stored = session.execute(
        stmt.values(request=merged).returning(Job.request).execution_options(synchronize_session=False)
    ).first()
    applied = stored is not None
    if stored is None:
        stored = session.execute(select(Job.request).where(Job.id == job.id)).first()
    set_committed_value(job, "request", stored[0] if stored is not None else None)
    return applied


def _convert_impl_job_to_proxy_context(
    session: Session,
    job: Job,
    *,
    proxy_addr: str,
    proxy_type: str | None = None,
    discovery_relationship: str = "implementation",
    parent_job_id: str | None = None,
) -> bool:
    """Convert a standalone impl job to proxy context so every stage from static runs in it. False when the job
    already carries a proxy context (another proxy, or intake, got there first); the job is then left as it is.

    An impl found before its proxy resolves against its own empty storage. Converting the same job (not a duplicate) and
    re-running from static lets split-proxy linkage fire and re-reads against the proxy; the deployment-scoped writes
    replace the stale rows. A job past static is re-enqueued there; one whose context-reading stage is running is
    flagged instead, and that stage's exit re-enqueues it.
    """
    patch: dict[str, Any] = {"proxy_address": proxy_addr}
    if proxy_type:
        patch["proxy_type"] = proxy_type
    defaults: dict[str, Any] = {"discovery_relationship": discovery_relationship}
    if parent_job_id:
        defaults["parent_job_id"] = parent_job_id
    converted = merge_job_request(session, job, patch, defaults=defaults, unless_present="proxy_address")
    if not converted:
        session.commit()
        return False

    # The UPDATE holds the row lock, so this reads the stage no other writer can move before the commit.
    session.refresh(job, attribute_names=["status", "stage"])
    if job.status == JobStatus.processing and job.stage in _CONTEXT_READING_STAGES:
        merge_job_request(session, job, {RESTART_STATIC_REQUEST_KEY: True})
    elif job.status == JobStatus.completed or job.stage in _RAN_PAST_STATIC_STAGES:
        job.stage = JobStage.static
        job.status = JobStatus.queued
        job.worker_id = None
        job.lease_id = None
        job.lease_expires_at = None
        job.next_attempt_at = None
        job.detail = f"Re-resolving in proxy context ({proxy_addr})"
    session.commit()
    return True


@functools.cache
def _impl_job_stmt(kind: str, chain_scoped: bool, root_scoped: bool, version: int, *, first_only: bool):
    """Built once per shape: the reconcile runs for every implementation, facet and secondary impl of a proxy job.

    ``kind`` is ``same_proxy`` or ``standalone`` (jobs that could stand, those standing on their own columns first) or
    ``other_proxy`` (any job behind a different proxy).
    """
    proxy = func.lower(Job.request["proxy_address"].as_string())
    # The lower() form lets ``ix_jobs_lower_address_chain_id`` serve the lookup.
    where = [
        Job.address == bindparam("impl"),
        func.lower(Job.address) == bindparam("impl"),
        # An effects-only retry isn't an implementation analysis.
        Job.request["effects_resume_work_id"].astext.is_(None),
    ]
    # Filter chain in every branch, so another chain's job never looks like a duplicate.
    if chain_scoped:
        where.append(Job.chain_id == bindparam("chain_id"))
    if root_scoped:
        where.append(Job.request["root_job_id"].as_string() == bindparam("root"))
    if kind == "other_proxy":
        stmt = select(Job.id).where(*where, proxy != bindparam("proxy"))
    else:
        match = proxy == bindparam("proxy") if kind == "same_proxy" else proxy.is_(None)
        stmt = (
            select(Job)
            .where(*where, match, _not_stamped_with_other_era(version))
            .order_by(_stands_without_walk_first(version), Job.updated_at.desc())
        )
    return stmt.limit(1) if first_only else stmt


def _impl_job_lookup(
    impl_lc: str, proxy_lc: str, chain: str | None, root_job_id: str | None
) -> tuple[tuple[bool, bool, int], dict[str, Any]]:
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

    params: dict[str, Any] = {"impl": impl_lc, "proxy": proxy_lc}
    if chain is not None:
        params["chain_id"] = derive_job_chain_id(chain, impl_lc)
    if root_job_id is not None:
        params["root"] = root_job_id
    return (chain is not None, root_job_id is not None, ANALYSIS_SCHEMA_VERSION), params


def _first_standing_impl_job(
    session: Session,
    kind: str,
    shape: tuple[bool, bool, int],
    params: dict[str, Any],
    eras: dict[str, int | None],
) -> Job | None:
    first = session.execute(_impl_job_stmt(kind, *shape, first_only=True), params).scalar_one_or_none()
    if first is None or job_stands_for_current_analyzer(session, first, eras):
        return first
    for candidate in session.execute(_impl_job_stmt(kind, *shape, first_only=False), params).scalars():
        if job_stands_for_current_analyzer(session, candidate, eras):
            return candidate
    return None


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

    ``root_job_id`` scopes lookups to the current cascade for ``--force`` re-runs. Only jobs that stand for the current
    analyzer (``job_stands_for_current_analyzer``) skip or get backpatched; a stale one leads to a fresh spawn.
    """
    impl_lc = impl_addr.lower()
    proxy_lc = proxy_addr.lower()
    shape, params = _impl_job_lookup(impl_lc, proxy_lc, chain, root_job_id)
    eras: dict[str, int | None] = {}

    while True:
        if _first_standing_impl_job(session, "same_proxy", shape, params, eras) is not None:
            return "skip"
        standalone = _first_standing_impl_job(session, "standalone", shape, params, eras)
        if standalone is None:
            break
        if _convert_impl_job_to_proxy_context(
            session,
            standalone,
            proxy_addr=proxy_lc,
            proxy_type=proxy_type,
            discovery_relationship=discovery_relationship,
        ):
            return "backpatched"
        # It took a proxy context concurrently; the lookups now see it as that proxy's job.

    other_proxy = session.execute(_impl_job_stmt("other_proxy", *shape, first_only=True), params).scalar_one_or_none()
    if other_proxy is not None:
        logger.warning(
            "Shared implementation %s is behind multiple proxies; spawning a separate "
            "per-deployment job for proxy %s (resolution keyed by deployment_address)",
            impl_lc,
            proxy_lc,
        )
    return "spawn"


def adopt_current_proxy_context(session: Session, job: Job, *, chain: str) -> str | None:
    """Give an address job without a proxy context the context of a proxy on *chain* whose current implementation
    (``Contract.implementation``) is the job's address, as that proxy's reconcile would. Returns the proxy address the
    job carries afterwards, or None when it is not the current implementation of any known proxy.

    Linking otherwise happens only when the proxy's static stage runs, so an implementation submitted after its proxy
    would resolve against its own storage and take the contract row from the proxy's implementation job. A pointer is
    settled once no job for its proxy is queued or running in discovery or static, the stages that rewrite it; until
    every pointer at this address is settled this raises :class:`ProxyContextUnsettled` and decides nothing. A proxy job
    held by pending dependencies doesn't count: it may be waiting on this very job, and deferral is invisible to the
    dependency cycle check, so only claimable jobs, which run static to its end, are waited on. Among several proxies,
    the first (by row id) without a standing implementation job of its own is chosen, else the first. The proxy's job,
    which holds the row, becomes the parent unless the request names one.
    """
    request = job.request if isinstance(job.request, dict) else {}
    carried = request.get("proxy_address")
    if isinstance(carried, str) and carried:
        return carried
    if not job.address or request.get("effects_resume_work_id") is not None:
        return None
    impl_lc = job.address.lower()
    stmt = (
        select(Contract.address, Contract.proxy_type, Contract.job_id)
        .where(
            func.lower(Contract.implementation) == impl_lc,
            func.lower(Contract.address) != impl_lc,
            or_(Contract.is_proxy.is_(True), Contract.proxy_type == "beacon"),
            func.lower(func.coalesce(Contract.chain, "ethereum")) == _mainnet_coalesced_chain(chain),
        )
        .order_by(Contract.id)
    )
    proxies = [(proxy_addr.lower(), proxy_type, holder) for proxy_addr, proxy_type, holder in session.execute(stmt)]
    if not proxies:
        return None

    blocked = (
        select(JobDependency.id)
        .where(JobDependency.depender_job_id == Job.id, JobDependency.status == "pending")
        .exists()
    )
    in_flight_stmt = select(Job.address).where(
        func.lower(Job.address).in_([proxy for proxy, _type, _holder in proxies]),
        Job.chain_id == chain_by_name(chain).chain_id,
        Job.stage.in_(_POINTER_WRITING_STAGES),
        Job.status.in_((JobStatus.queued, JobStatus.processing)),
        Job.request["effects_resume_work_id"].astext.is_(None),
        ~blocked,
    )
    in_flight = sorted({address.lower() for (address,) in session.execute(in_flight_stmt) if address})
    if in_flight:
        raise ProxyContextUnsettled(in_flight)

    eras: dict[str, int | None] = {}
    chosen = proxies[0]
    for candidate in proxies:
        shape, params = _impl_job_lookup(impl_lc, candidate[0], chain, None)
        if _first_standing_impl_job(session, "same_proxy", shape, params, eras) is None:
            chosen = candidate
            break
    proxy_lc, proxy_type, holder = chosen
    if _convert_impl_job_to_proxy_context(
        session,
        job,
        proxy_addr=proxy_lc,
        proxy_type=proxy_type,
        parent_job_id=str(holder) if holder is not None else None,
    ):
        logger.info(
            "address job adopted the proxy context of the proxy whose current implementation it is",
            extra={"job_id": str(job.id), "impl": impl_lc, "proxy": proxy_lc, "proxies_known": len(proxies)},
        )
    stored = job.request if isinstance(job.request, dict) else {}
    adopted = stored.get("proxy_address")
    return adopted if isinstance(adopted, str) and adopted else None


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
    if _restart_static_if_flagged(session, job):
        # The failed attempt ran on a request the job no longer has; the re-run is a fresh one, not a retry of it.
        session.commit()
        return
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
    _restart_static_if_flagged(session, job)
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
