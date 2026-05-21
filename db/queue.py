"""Postgres-based job queue operations using SELECT ... FOR UPDATE SKIP LOCKED."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy import update as sa_update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from services.discovery.source_confidence import asserts_ownership
from utils.chains import canonical_chain, canonical_chain_list

from .models import (
    Artifact,
    Base,
    Contract,
    ContractSummary,
    Job,
    JobDependency,
    JobStage,
    JobStatus,
    Protocol,
    SourceFile,
)
from .storage import (
    StorageError,
    StorageKeyMissing,
    artifact_key,
    deserialize_artifact,
    get_storage_client,
    serialize_artifact,
    source_file_key,
)

logger = logging.getLogger(__name__)

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


class LeaseLost(RuntimeError):
    """Raised when a mutating queue write detects the caller no longer
    holds the row's lease.

    A worker should treat this as fatal for the current attempt: another
    worker has been handed the job, and any further writes from this
    thread would corrupt that worker's view. The handler in
    ``BaseWorker._execute_job`` logs it and bails without further
    advance/requeue/fail_terminal calls.
    """


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
    job = Job(
        address=request_dict.get("address"),
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


def bulk_upsert_discovered_contracts(
    session: Session,
    *,
    protocol_id: int | None,
    entries: list[dict[str, Any]],
) -> list[Contract]:
    """Bulk variant of :func:`upsert_discovered_contract` with identical first-writer-wins semantics.

    Each *entries* item is a dict with keys: ``address`` (required),
    ``chain``, ``new_sources`` (list[str]), ``contract_name``, ``confidence``,
    ``chains``, ``discovery_url``. The single-row helper does one SELECT per
    address, which dominates wall time when discovery surfaces 100-300
    contracts at once. This collapses every SELECT into one ``IN (...)`` and
    keeps the merge logic identical so semantics don't drift.

    Commit is the caller's responsibility — typical use is one bulk call
    per discovery source followed by a single commit.
    """
    if not entries:
        return []

    # Normalize once so the lookup map and the merge loop see identical keys.
    norm_entries: list[tuple[str, str | None, dict[str, Any]]] = []
    for entry in entries:
        address = str(entry["address"]).lower()
        chain = canonical_chain(entry.get("chain"))
        clean_entry = dict(entry)
        clean_entry["chain"] = chain
        clean_entry["chains"] = canonical_chain_list(entry.get("chains"))
        norm_entries.append((address, chain, clean_entry))

    # One round-trip for every existing row across the requested (address, chain) tuples.
    # We can't use a single tuple-IN against a composite key efficiently in SQLAlchemy
    # core without raw SQL, so query by address set and filter chain in Python — the
    # set is small (typically 100-300 addresses) and the chain comparison is O(1).
    addresses = list({a for a, _c, _e in norm_entries})
    existing_rows = session.execute(select(Contract).where(Contract.address.in_(addresses))).scalars().all()
    existing_by_key: dict[tuple[str, str | None], Contract] = {(row.address, row.chain): row for row in existing_rows}

    out: list[Contract] = []
    for address, chain, entry in norm_entries:
        clean_sources = [s for s in (entry.get("new_sources") or []) if s]
        # Only high-confidence sources may assert protocol ownership.
        # Low-confidence sources (dapp_crawl scraping, upgrade_history
        # traversal of unconfirmed proxies) populate discovery_sources
        # but leave protocol_id NULL until a high-confidence source
        # corroborates. See services/discovery/source_confidence.py.
        owning_protocol_id = protocol_id if asserts_ownership(clean_sources) else None
        existing = existing_by_key.get((address, chain))
        if existing is None:
            row = Contract(
                address=address,
                chain=chain,
                protocol_id=owning_protocol_id,
                contract_name=entry.get("contract_name"),
                confidence=entry.get("confidence"),
                discovery_sources=list(clean_sources) or None,
                chains=entry.get("chains"),
                discovery_url=entry.get("discovery_url"),
            )
            session.add(row)
            existing_by_key[(address, chain)] = row
            out.append(row)
            continue

        merged = list(existing.discovery_sources or [])
        for src in clean_sources:
            if src not in merged:
                merged.append(src)
        if merged:
            existing.discovery_sources = merged
        if existing.protocol_id is None and owning_protocol_id is not None:
            existing.protocol_id = owning_protocol_id
        if not existing.contract_name and entry.get("contract_name"):
            existing.contract_name = entry["contract_name"]
        if existing.confidence is None and entry.get("confidence") is not None:
            existing.confidence = entry["confidence"]
        if not existing.chains and entry.get("chains"):
            existing.chains = entry["chains"]
        if not existing.discovery_url and entry.get("discovery_url"):
            existing.discovery_url = entry["discovery_url"]
        out.append(existing)

    return out


def upsert_discovered_contract(
    session: Session,
    *,
    address: str,
    chain: str | None,
    protocol_id: int | None,
    new_sources: list[str],
    contract_name: str | None = None,
    confidence: float | None = None,
    chains: list[str] | None = None,
    discovery_url: str | None = None,
) -> Contract:
    """Insert or update a discovered contract, unioning ``discovery_sources``.

    Every discovery worker — inventory, DApp crawl, DefiLlama scan,
    upgrade-history backfill — funnels through here so "three sources
    agree" shows up in the data as a three-element array, not as
    whichever writer landed first. The ranking module reads the union
    and applies a corroboration boost.

    When the row exists already:
        - ``discovery_sources`` is unioned (new entries appended, dedup
          preserves order so the first discoverer stays first).
        - ``protocol_id`` is backfilled if null (orphan adoption).
        - ``contract_name`` / ``confidence`` / ``chains`` /
          ``discovery_url`` are first-writer-wins: later writers only
          fill them if the stored value is missing, so a later
          lower-quality source doesn't stomp a better one.

    Commit is the caller's responsibility — callers usually batch many
    upserts into one transaction.
    """
    normalized = address.lower()
    chain = canonical_chain(chain)
    chains = canonical_chain_list(chains)
    existing = session.execute(
        select(Contract).where(
            Contract.address == normalized,
            Contract.chain == chain,
        )
    ).scalar_one_or_none()

    clean_sources = [s for s in new_sources if s]
    # See bulk_upsert_discovered_contracts — only high-confidence sources
    # may assert protocol ownership.
    owning_protocol_id = protocol_id if asserts_ownership(clean_sources) else None

    if existing is None:
        row = Contract(
            address=normalized,
            chain=chain,
            protocol_id=owning_protocol_id,
            contract_name=contract_name,
            confidence=confidence,
            discovery_sources=list(clean_sources) or None,
            chains=chains,
            discovery_url=discovery_url,
        )
        session.add(row)
        return row

    merged = list(existing.discovery_sources or [])
    for src in clean_sources:
        if src not in merged:
            merged.append(src)
    if merged:
        existing.discovery_sources = merged

    if existing.protocol_id is None and owning_protocol_id is not None:
        existing.protocol_id = owning_protocol_id
    if not existing.contract_name and contract_name:
        existing.contract_name = contract_name
    if existing.confidence is None and confidence is not None:
        existing.confidence = confidence
    if not existing.chains and chains:
        existing.chains = chains
    if not existing.discovery_url and discovery_url:
        existing.discovery_url = discovery_url

    return existing


_PROTOCOL_FK_TABLES = (
    # (table, column) for every FK referencing protocols.id. Listed
    # explicitly so the merge step touches every dependent table without
    # depending on a model registry walk. Includes both CASCADE and SET NULL
    # FKs — the orphan row is being deleted, not nulled, so the destination
    # protocol takes ownership of all children.
    ("jobs", "protocol_id"),
    ("audit_reports", "protocol_id"),
    ("audit_contract_coverage", "protocol_id"),
    ("contracts", "protocol_id"),
    ("monitored_contracts", "protocol_id"),
    ("protocol_subscriptions", "protocol_id"),
    ("dapp_interactions", "protocol_id"),
    ("tvl_snapshots", "protocol_id"),
)


def _merge_protocol_into(session: Session, src: Protocol, dst: Protocol) -> None:
    """Reassign every protocols.id FK from ``src`` to ``dst``, then delete src.

    Used when ``get_or_create_protocol`` discovers that a pre-resolver row
    (NULL canonical_slug) is a duplicate of a freshly-resolved family. None
    of the dependent tables have a UNIQUE(protocol_id, …) constraint, so the
    bulk UPDATE never conflicts.
    """
    if src.id == dst.id:
        return
    for table, col in _PROTOCOL_FK_TABLES:
        session.execute(
            text(f"UPDATE {table} SET {col} = :dst WHERE {col} = :src"),
            {"src": src.id, "dst": dst.id},
        )
    session.delete(src)
    session.flush()


def get_or_create_protocol(
    session: Session,
    name: str,
    official_domain: str | None = None,
    canonical_slug: str | None = None,
    aliases: list[str] | None = None,
) -> Protocol:
    """Look up Protocol by canonical slug (preferred) or name, create if missing.

    The slug-keyed branch is the durable fix for duplicate rows: ``"ether fi"``
    and ``"etherfi"`` both resolve to the same DefiLlama family slug, so
    keying on slug collapses them. The name-keyed branch is the fallback
    for protocols without a DefiLlama match (slug is None).

    ``aliases`` is the list of every display-name spelling the resolver
    knows for this family (typically ``resolved["all_names"]``). It is used
    to find pre-resolver duplicate rows whose ``canonical_slug`` is still
    NULL and merge them into the slug-keyed row. Without this, the prod
    incident's two rows (``"ether fi"`` + ``"etherfi"``) would not collapse
    on first post-migration touch — one would adopt the slug and the other
    would orphan.

    Concurrent slug inserts are serialized via ``uq_protocol_canonical_slug``;
    the IntegrityError is caught inside a savepoint and we re-fetch the
    winning row instead of bubbling the failure up to the worker.
    """
    if canonical_slug:
        row = session.execute(select(Protocol).where(Protocol.canonical_slug == canonical_slug)).scalar_one_or_none()
        if row is None:
            # Look at every alias plus the requested name. Match is
            # name + NULL slug — never poach a row that's already owned
            # by a different family.
            candidate_names = [name, *(aliases or [])]
            orphans = list(
                session.execute(
                    select(Protocol).where(
                        Protocol.canonical_slug.is_(None),
                        Protocol.name.in_(candidate_names),
                    )
                ).scalars()
            )
            if orphans:
                # Adopt the first orphan; merge any siblings into it so
                # FK children consolidate onto one row.
                row = orphans[0]
                row.canonical_slug = canonical_slug
                for extra in orphans[1:]:
                    _merge_protocol_into(session, src=extra, dst=row)
            else:
                # Savepoint so a concurrent winner's IntegrityError on
                # uq_protocol_canonical_slug doesn't poison the outer
                # transaction. ``add`` goes inside the savepoint so the
                # session expunges the rejected pending object on rollback —
                # otherwise the next autoflush retries the doomed INSERT.
                try:
                    with session.begin_nested():
                        row = Protocol(name=name, official_domain=official_domain, canonical_slug=canonical_slug)
                        session.add(row)
                        session.flush()
                except IntegrityError:
                    row = session.execute(
                        select(Protocol).where(Protocol.canonical_slug == canonical_slug)
                    ).scalar_one()
                if official_domain and not row.official_domain:
                    row.official_domain = official_domain
                    session.flush()
                return row
        if official_domain and not row.official_domain:
            row.official_domain = official_domain
        session.flush()
        return row

    row = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if row is None:
        row = Protocol(name=name, official_domain=official_domain)
        session.add(row)
        session.flush()
        return row
    if official_domain and not row.official_domain:
        row.official_domain = official_domain
        session.flush()
    return row


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


def count_analysis_children(session: Session, root_job_id: str) -> int:
    """Count analysis jobs (jobs with an address) linked to a root job."""
    from sqlalchemy import func

    count = (
        session.execute(
            select(func.count(Job.id)).where(
                Job.address.isnot(None),
                Job.request["root_job_id"].as_string() == root_job_id,
            )
        ).scalar()
        or 0
    )
    return count


def _artifact_row_to_value(artifact: Artifact) -> dict | list | str | None:
    """Resolve an Artifact row to its decoded payload (handles inline + storage)."""
    if artifact.storage_key:
        client = get_storage_client()
        if client is None:
            raise RuntimeError(
                f"Artifact {artifact.name} on job {artifact.job_id} has storage_key but storage is not configured"
            )
        body = client.get(artifact.storage_key)
        return deserialize_artifact(body, artifact.content_type)
    if artifact.data is not None:
        return artifact.data
    return artifact.text_data


def _mirror_contract_flags_to_job(session: Session, job_id: Any, name: str, data: Any) -> None:
    """Mirror ``contract_flags.is_proxy`` onto ``Job.is_proxy`` so /api/jobs
    can answer the proxy-flag question without resolving the artifact body."""
    if name != "contract_flags" or not isinstance(data, dict):
        return
    is_proxy = data.get("is_proxy") is True
    session.execute(sa_update(Job).where(Job.id == job_id).values(is_proxy=is_proxy))


def store_artifact(session: Session, job_id: Any, name: str, data: Any = None, text_data: str | None = None) -> None:
    """Upsert an artifact for a job (unique on job_id + name).

    When ``ARTIFACT_STORAGE_*`` env vars are set, the body is written to object
    storage and only metadata (storage_key, size_bytes, content_type) is stored
    in Postgres. Otherwise, the body lives inline in ``data`` / ``text_data``.

    If the storage put succeeds but the DB write fails, the storage object is
    deleted — but only if the row did not pre-exist. Overwriting a previously-
    committed artifact with the same deterministic key and then rolling back
    leaves the object in place (deleting it would break the previous row).
    """
    client = get_storage_client()
    if client is not None:
        body, content_type = serialize_artifact(data, text_data)
        key = artifact_key(job_id, name)
        preexisting = session.execute(
            select(Artifact.id).where(Artifact.job_id == job_id, Artifact.name == name).limit(1)
        ).scalar_one_or_none()

        client.put(key, body, content_type, metadata={"artifact_name": name, "job_id": str(job_id)})
        stmt = pg_insert(Artifact).values(
            job_id=job_id,
            name=name,
            data=None,
            text_data=None,
            storage_key=key,
            size_bytes=len(body),
            content_type=content_type,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_artifact_job_name",
            set_={
                "data": None,
                "text_data": None,
                "storage_key": stmt.excluded.storage_key,
                "size_bytes": stmt.excluded.size_bytes,
                "content_type": stmt.excluded.content_type,
            },
        )
        try:
            session.execute(stmt)
            _mirror_contract_flags_to_job(session, job_id, name, data)
            session.commit()
        except Exception:
            session.rollback()
            if preexisting is None:
                try:
                    client.delete(key)
                except StorageError:
                    logger.warning("Failed to clean up orphan storage object %s", key)
            raise
        return

    stmt = pg_insert(Artifact).values(
        job_id=job_id,
        name=name,
        data=data,
        text_data=text_data,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_artifact_job_name",
        set_={
            "data": stmt.excluded.data,
            "text_data": stmt.excluded.text_data,
            "storage_key": None,
            "size_bytes": None,
            "content_type": None,
        },
    )
    session.execute(stmt)
    _mirror_contract_flags_to_job(session, job_id, name, data)
    session.commit()


def get_artifact(session: Session, job_id: Any, name: str) -> dict | list | str | None:
    """Read an artifact by job_id and name."""
    stmt = select(Artifact).where(Artifact.job_id == job_id, Artifact.name == name)
    artifact = session.execute(stmt).scalar_one_or_none()
    if artifact is None:
        return None
    return _artifact_row_to_value(artifact)


def backfill_job_is_proxy_from_storage(session: Session) -> int:
    """Flip ``Job.is_proxy`` for legacy storage-backed ``contract_flags`` rows the inline SQL backfill can't reach."""
    if get_storage_client() is None:
        return 0
    rows = session.execute(
        select(Artifact)
        .join(Job, Artifact.job_id == Job.id)
        .where(
            Artifact.name == "contract_flags",
            Artifact.storage_key.is_not(None),
            Job.is_proxy.is_(False),
        )
    ).scalars()
    updated = 0
    for art in rows:
        try:
            value = _artifact_row_to_value(art)
        except StorageError:
            logger.warning("backfill: contract_flags storage read failed for job %s", art.job_id)
            continue
        if not isinstance(value, dict) or value.get("is_proxy") is not True:
            continue
        session.execute(sa_update(Job).where(Job.id == art.job_id, Job.is_proxy.is_(False)).values(is_proxy=True))
        updated += 1
    session.commit()
    return updated


def get_all_artifacts(session: Session, job_id: Any) -> dict[str, Any]:
    """Read all artifacts for a job. Returns {name: data_or_text}.

    Storage-backed bodies are fetched in parallel via ``StorageClient.get_many``
    so a job with N storage artifacts pays one HTTP round-trip's worth of
    latency instead of N. Missing keys are skipped (mirrors the prior
    ``StorageKeyMissing`` behavior).
    """
    stmt = select(Artifact).where(Artifact.job_id == job_id)
    artifacts = session.execute(stmt).scalars().all()
    result: dict[str, Any] = {}
    storage_lookups: dict[str, tuple[str, str | None]] = {}
    for artifact in artifacts:
        if artifact.storage_key:
            storage_lookups[artifact.name] = (artifact.storage_key, artifact.content_type)
        elif artifact.data is not None:
            result[artifact.name] = artifact.data
        elif artifact.text_data is not None:
            result[artifact.name] = artifact.text_data

    if storage_lookups:
        client = get_storage_client()
        if client is None:
            raise RuntimeError(f"job {job_id} has artifacts with storage_key but storage is not configured")
        bodies = client.get_many([key for key, _ in storage_lookups.values()])
        for name, (key, content_type) in storage_lookups.items():
            body = bodies.get(key)
            if body is None:
                continue
            value = deserialize_artifact(body, content_type)
            if value is not None:
                result[name] = value

    return result


def store_source_files(session: Session, job_id: Any, files: dict[str, str]) -> None:
    """Bulk insert source files for a job (replaces existing).

    When object storage is configured, every body is uploaded first with the
    path carried in user-metadata (so the path is recoverable from storage
    alone). Only after all uploads succeed do we swap the DB rows. If any
    upload fails, already-uploaded objects are deleted so the bucket does not
    accumulate orphans pointing at nothing.
    """
    client = get_storage_client()
    if client is None:
        session.query(SourceFile).filter(SourceFile.job_id == job_id).delete()
        for path, content in files.items():
            session.add(SourceFile(job_id=job_id, path=path, content=content))
        session.commit()
        return

    # Fan out the per-file uploads — Etherscan-verified contracts often have
    # 30-100 source files and the prior sequential loop was paying one S3/MinIO
    # RTT per file on the static-stage critical path. Threading-only: each
    # ``client.put`` is an independent HTTP request to object storage with no
    # shared session state.
    from utils.concurrency import parallel_map

    items = list(files.items())

    def _upload(item: tuple[str, str]) -> tuple[str, str]:
        path, content = item
        key = source_file_key(job_id, path)
        client.put(
            key,
            content.encode("utf-8"),
            "text/plain; charset=utf-8",
            metadata={"path": path, "job_id": str(job_id)},
        )
        return path, key

    upload_results = parallel_map(_upload, items)
    entries: list[tuple[str, str]] = []
    uploaded_keys: list[str] = []
    failure: BaseException | None = None
    for _item, outcome in upload_results:
        if isinstance(outcome, BaseException):
            if failure is None:
                failure = outcome
            continue
        path, key = outcome  # type: ignore[misc]
        entries.append((path, key))
        uploaded_keys.append(key)

    if failure is not None:
        for key in uploaded_keys:
            try:
                client.delete(key)
            except StorageError:
                logger.warning("Failed to clean up orphan source file object %s", key)
        raise failure

    try:
        # All uploads succeeded — swap DB rows atomically.
        session.query(SourceFile).filter(SourceFile.job_id == job_id).delete()
        for path, key in entries:
            session.add(SourceFile(job_id=job_id, path=path, content=None, storage_key=key))
        session.commit()
    except Exception:
        session.rollback()
        for key in uploaded_keys:
            try:
                client.delete(key)
            except StorageError:
                logger.warning("Failed to clean up orphan source file object %s", key)
        raise


def get_source_files(session: Session, job_id: Any) -> dict[str, str]:
    """Returns {relative_path: file_content} for all source files of a job."""
    stmt = select(SourceFile).where(SourceFile.job_id == job_id)
    rows = session.execute(stmt).scalars().all()
    out: dict[str, str] = {}
    client = get_storage_client()

    storage_rows: list[tuple[str, str]] = []
    for row in rows:
        if row.storage_key:
            if client is None:
                raise RuntimeError(
                    f"SourceFile {row.path} on job {row.job_id} has storage_key but storage is not configured"
                )
            storage_rows.append((row.path, row.storage_key))
        elif row.content is not None:
            out[row.path] = row.content

    if not storage_rows:
        return out

    # Fan out the storage GETs the same way ``store_source_files`` fans out
    # the PUTs — these blocked the static + resolution + policy stages on
    # 30-100 sequential MinIO/S3 RTTs each.
    from utils.concurrency import parallel_map

    # Capture into a non-None local so the closure's type narrows past pyright
    # (the loop above already raised when client was None for any storage_row).
    storage_client = client
    assert storage_client is not None

    def _fetch(item: tuple[str, str]) -> tuple[str, str | None]:
        path, key = item
        try:
            return path, storage_client.get(key).decode("utf-8")
        except StorageKeyMissing:
            return path, None

    fetch_results = parallel_map(_fetch, storage_rows)
    for _item, outcome in fetch_results:
        if isinstance(outcome, BaseException):
            raise outcome
        path, content = outcome  # type: ignore[misc]
        if content is not None:
            out[path] = content
    return out


# ---------------------------------------------------------------------------
# Static data caching
# ---------------------------------------------------------------------------

# Artifact names that constitute cached static data (immutable, never change).
# slither_results / analysis_report were removed when vulnerability-detector
# triage was split out of PSAT's pipeline; downstream stages don't depend on
# them, and the only writer (StaticWorker._run_slither_phase) is gone.
# predicate_trees / effects are emitted by semantic static analysis and are
# required by resolution and policy, so cache hits must carry them forward.
_STATIC_ARTIFACT_NAMES = frozenset(
    {
        "contract_analysis",
        "control_tracking_plan",
        "predicate_trees",
        "effects",
        "static_dependencies",
        "enrichment_cache",
    }
)

# Artifacts copied as a starting baseline but appended to on subsequent runs.
_SEED_ARTIFACT_NAMES = frozenset(
    {
        "dynamic_dependencies",
        "classifications",
        "upgrade_history",
    }
)

# Contract columns that are mutable (resolved live by _resolve_proxy) and
# must NOT be carried over from a cached job.
_MUTABLE_CONTRACT_FIELDS = frozenset({"is_proxy", "proxy_type", "implementation", "beacon", "admin"})


def copy_row(session: Session, source: Base, *, exclude: frozenset[str] = frozenset(), **overrides: Any) -> Base:
    """Copy a SQLAlchemy row, returning a new detached instance.

    - Primary keys are always skipped (auto-generated).
    - Columns with a ``server_default`` (e.g. ``created_at``) are skipped
      so the DB assigns fresh values, unless explicitly passed in *overrides*.
    - *exclude* names additional columns to drop.
    - *overrides* supply values that differ from the source (e.g. remapped
      foreign keys, zeroed-out mutable fields).

    Lists are shallow-copied so the new row doesn't share references with
    the source.
    """
    from sqlalchemy import inspect as sa_inspect

    mapper = sa_inspect(type(source))
    kwargs: dict[str, Any] = {}
    for attr in mapper.column_attrs:
        key = attr.key
        if key in exclude:
            continue
        col = attr.columns[0]
        if col.primary_key:
            continue
        if key in overrides:
            kwargs[key] = overrides[key]
            continue
        if col.server_default is not None:
            continue
        value = getattr(source, key)
        if isinstance(value, list):
            value = list(value)
        kwargs[key] = value

    new_row = type(source)(**kwargs)
    session.add(new_row)
    return new_row


def find_completed_static_cache(session: Session, address: str, chain: str | None = None) -> Job | None:
    """Find a previously completed job for *address* (and *chain*) that has all required static data.

    Returns the cached :class:`Job` if one exists with:
    - status = completed, stage = done
    - at least one ``source_files`` row
    - the ``contract_analysis`` artifact (key indicator that the static stage finished)
    - a ``contracts`` row for this address/chain with a ``contract_summaries`` row

    The contract lookup uses (address, chain) rather than ``job_id`` so that
    the cache remains valid even after ``copy_static_cache`` reassigned the
    Contract row to a later target job.

    Returns ``None`` when no suitable cache exists.
    """
    stmt = (
        select(Job)
        .where(
            func.lower(Job.address) == address.lower(),
            Job.status == JobStatus.completed,
            Job.stage == JobStage.done,
        )
        .order_by(Job.updated_at.desc())
    )
    candidates = session.execute(stmt).scalars().all()

    for candidate in candidates:
        # Filter by chain stored in the job's request dict
        if chain is not None:
            req = candidate.request if isinstance(candidate.request, dict) else {}
            if req.get("chain") != chain:
                continue

        src_count = session.execute(
            select(SourceFile).where(SourceFile.job_id == candidate.id).limit(1)
        ).scalar_one_or_none()
        if not src_count:
            continue

        # Look up by (address, chain), not job_id — copy_static_cache may have reassigned.
        # Join ContractSummary so .limit(1) skips stub rows that lack the cached summary.
        contract_stmt = (
            select(Contract)
            .join(ContractSummary, ContractSummary.contract_id == Contract.id)
            .where(func.lower(Contract.address) == address.lower())
        )
        if chain is not None:
            contract_stmt = contract_stmt.where(Contract.chain == chain)
        contract_row = session.execute(contract_stmt.limit(1)).scalar_one_or_none()
        if not contract_row:
            continue

        # Static-stage-finished check. For non-proxy contracts the canonical
        # indicator is ``contract_analysis`` (slither output + summary).
        # Proxies never produce ``contract_analysis`` on their own job —
        # it lives on the impl child — so require ``contract_flags`` instead,
        # which proxies do write (is_proxy + proxy_type). Without this
        # branch, re-discovered proxies would miss the cache and do a full
        # fresh Etherscan fetch + slither run every time.
        required_artifact = "contract_flags" if contract_row.is_proxy else "contract_analysis"
        has_required = session.execute(
            select(Artifact).where(Artifact.job_id == candidate.id, Artifact.name == required_artifact).limit(1)
        ).scalar_one_or_none()
        if not has_required:
            continue

        summary = session.execute(
            select(ContractSummary).where(ContractSummary.contract_id == contract_row.id).limit(1)
        ).scalar_one_or_none()
        if not summary:
            continue

        return candidate

    return None


def find_previous_company_inventory(
    session: Session,
    company: str,
    exclude_job_id: Any = None,
    chain: str | None = None,
) -> Job | None:
    """Find the most recent completed company job with a contract_inventory artifact.

    When *chain* is given, only jobs whose ``request["chain"]`` matches are
    considered, preventing cross-chain inventory contamination.
    """
    stmt = (
        select(Job)
        .where(
            func.lower(Job.company) == company.lower(),
            Job.status == JobStatus.completed,
            Job.stage == JobStage.done,
        )
        .order_by(Job.updated_at.desc())
    )
    candidates = session.execute(stmt).scalars().all()
    for candidate in candidates:
        if exclude_job_id and candidate.id == exclude_job_id:
            continue
        if chain is not None:
            req = candidate.request if isinstance(candidate.request, dict) else {}
            if req.get("chain") != chain:
                continue
        art = session.execute(
            select(Artifact).where(Artifact.job_id == candidate.id, Artifact.name == "contract_inventory").limit(1)
        ).scalar_one_or_none()
        if art:
            return candidate
    return None


def find_existing_job_for_address(session: Session, address: str, chain: str | None = None) -> Job | None:
    """Find a non-failed job for *address* (and *chain*), case-insensitive.

    When *chain* is given, only jobs whose ``request["chain"]`` matches are
    returned, so an Ethereum job won't suppress a Base job at the same address.
    """
    candidates = (
        session.execute(
            select(Job).where(
                func.lower(Job.address) == address.lower(),
                Job.status != JobStatus.failed,
            )
        )
        .scalars()
        .all()
    )
    for c in candidates:
        if chain is not None:
            req = c.request if isinstance(c.request, dict) else {}
            if req.get("chain") != chain:
                continue
        return c
    return None


def is_known_proxy(session: Session, address: str, chain: str | None = None) -> bool:
    """Return True if *address* (on *chain*) has been classified as a proxy in any prior analysis."""
    stmt = select(Contract).where(
        func.lower(Contract.address) == address.lower(),
        Contract.is_proxy.is_(True),
    )
    if chain is not None:
        stmt = stmt.where(Contract.chain == chain)
    return session.execute(stmt.limit(1)).scalar_one_or_none() is not None


def copy_static_cache(session: Session, source_job_id: Any, target_job_id: Any) -> int | None:
    """Copy all cached static data from *source_job_id* to *target_job_id*.

    Copies:
    - ``contracts`` row (immutable fields only; proxy fields left as defaults)
    - ``source_files`` rows
    - ``contract_summaries`` and ``role_definitions``
      rows (linked to the new contract row)
    - Static artifacts (``contract_analysis``, ``control_tracking_plan``,
      ``predicate_trees``, ``effects``, ``static_dependencies``,
      ``enrichment_cache``)

    The source contract is looked up by (address, chain) rather than by
    ``job_id`` so that subsequent cache copies still work after a prior copy
    reassigned the Contract row.

    Returns the new ``Contract.id`` on success, or ``None`` on failure.
    """
    # Guard: if the target already has a contract row, return early.
    existing = session.execute(select(Contract).where(Contract.job_id == target_job_id).limit(1)).scalar_one_or_none()
    if existing:
        return existing.id

    # Resolve the source job's address and chain so we can find the Contract
    # by its natural key (address, chain) rather than by job_id.  A prior
    # copy_static_cache may have reassigned the Contract row's job_id to a
    # different target, so job_id lookup is unreliable after the first copy.
    src_job = session.get(Job, source_job_id)
    if not src_job or not src_job.address:
        return None

    src_req = src_job.request if isinstance(src_job.request, dict) else {}
    src_chain = src_req.get("chain")

    # Join ContractSummary so we copy a summaried row, not a stub (mirrors find_completed_static_cache).
    src_contract_stmt = (
        select(Contract)
        .join(ContractSummary, ContractSummary.contract_id == Contract.id)
        .where(func.lower(Contract.address) == src_job.address.lower())
    )
    if src_chain is not None:
        src_contract_stmt = src_contract_stmt.where(Contract.chain == src_chain)
    src_contract = session.execute(src_contract_stmt.limit(1)).scalar_one_or_none()
    if not src_contract:
        return None

    # The unique constraint on (address, chain) means src_contract IS the
    # only Contract for this address/chain.  Reassign it to the target job.
    src_contract.job_id = target_job_id

    # Save the current proxy state so _check_proxy_cache can compare it
    # against the live on-chain implementation to decide whether
    # re-classification is needed.  The Contract row keeps its proxy
    # fields intact — zeroing them would corrupt data for the old
    # completed job that also references this row via address lookup.
    _cached_proxy_state = {
        "is_proxy": src_contract.is_proxy,
        "proxy_type": src_contract.proxy_type,
        "implementation": src_contract.implementation,
        "beacon": src_contract.beacon,
        "admin": src_contract.admin,
    }
    store_artifact(session, target_job_id, "cached_proxy_state", data=_cached_proxy_state)

    session.flush()
    new_contract = src_contract

    storage = get_storage_client()

    # --- source files ---
    src_files = session.execute(select(SourceFile).where(SourceFile.job_id == source_job_id)).scalars().all()
    for sf in src_files:
        if sf.storage_key and storage is not None:
            new_key = source_file_key(target_job_id, sf.path)
            storage.copy(sf.storage_key, new_key)
            session.add(SourceFile(job_id=target_job_id, path=sf.path, content=None, storage_key=new_key))
        else:
            copy_row(session, sf, job_id=target_job_id)

    # --- artifacts (static + seed) ---
    src_artifacts = (
        session.execute(
            select(Artifact).where(
                Artifact.job_id == source_job_id,
                Artifact.name.in_(_STATIC_ARTIFACT_NAMES | _SEED_ARTIFACT_NAMES),
            )
        )
        .scalars()
        .all()
    )
    for art in src_artifacts:
        if art.storage_key and storage is not None:
            new_key = artifact_key(target_job_id, art.name)
            storage.copy(art.storage_key, new_key)
            stmt = pg_insert(Artifact).values(
                job_id=target_job_id,
                name=art.name,
                data=None,
                text_data=None,
                storage_key=new_key,
                size_bytes=art.size_bytes,
                content_type=art.content_type,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_artifact_job_name",
                set_={
                    "data": None,
                    "text_data": None,
                    "storage_key": stmt.excluded.storage_key,
                    "size_bytes": stmt.excluded.size_bytes,
                    "content_type": stmt.excluded.content_type,
                },
            )
            session.execute(stmt)
        else:
            store_artifact(session, target_job_id, art.name, data=art.data, text_data=art.text_data)

    session.commit()
    return new_contract.id  # type: ignore[attr-defined]
