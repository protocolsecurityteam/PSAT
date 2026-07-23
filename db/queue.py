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
from utils.chains import UnknownChainError, canonical_chain, canonical_chain_list, chain_by_id

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
    SessionLocal,
    SourceFile,
    WorkerHeartbeat,
    derive_job_chain_id,
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
# The ops watchdog runs in the web app lifespan; its heartbeat row doubles as
# the CAS-guarded store for alert dedupe/cooldown state (services/monitoring/
# ops_alerts.py).
HEARTBEAT_OPS_ALERTER = "ops_alerter"


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
    except Exception:
        logger.debug("heartbeat write failed for process=%s", process, exc_info=True)


# Default lifetime of a daemon-pass lease. Chosen (per design §2.4) to exceed
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


def release_daemon_lease(session: Session, name: str, holder: uuid.UUID) -> None:
    """Release the lease iff the caller still holds it. Wrong holder no-ops.

    The ``holder`` guard means a daemon that already lost its lease to a
    competitor can't delete the competitor's row on the way out. Commits
    internally, like the acquire path.
    """
    session.execute(
        text("DELETE FROM daemon_leases WHERE name = :name AND holder = :holder"),
        {"name": name, "holder": holder},
    )
    session.commit()


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


def _job_chain_name(job: Job) -> str:
    """Canonical chain name of *job*, from the first-class ``chain_id`` column
    (falling back to the request chain; mainnet when underivable). Used to
    chain-qualify Contract lookups tied to a specific job so a same-address
    deployment on another chain can never stand in (inv. 12)."""
    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        try:
            return chain_by_id(chain_id).name
        except UnknownChainError:
            return "ethereum"
    request = job.request if isinstance(job.request, dict) else {}
    return canonical_chain(request.get("chain")) or "ethereum"


def _mainnet_coalesced_chain(chain: str | None) -> str:
    """Mainnet-coalesced dedup key (invariants 1/6/12).

    Legacy rows persisted ``chain=NULL`` for mainnet, so coalescing
    ``NULL``→``'ethereum'`` lets a mainnet write dedup against them while a
    non-mainnet write (its own name ≠ ``'ethereum'``) stays isolated, and the
    ``'unknown'`` resolve-later bucket keeps its own identity. Mirrors the
    ``coalesce(chain,'ethereum')`` predicate in ``workers/discovery.py``'s
    single-row path so both writers match each other's rows regardless of
    historical NULLs.
    """
    return (chain or "ethereum").lower()


def bulk_upsert_discovered_contracts(
    session: Session,
    *,
    protocol_id: int | None,
    entries: list[dict[str, Any]],
    default_chain: str | None = None,
) -> list[Contract]:
    """Bulk variant of :func:`upsert_discovered_contract` with identical first-writer-wins semantics.

    Each *entries* item is a dict with keys: ``address`` (required),
    ``chain``, ``new_sources`` (list[str]), ``contract_name``, ``confidence``,
    ``chains``, ``discovery_url``. The single-row helper does one SELECT per
    address, which dominates wall time when discovery surfaces 100-300
    contracts at once. This collapses every SELECT into one ``IN (...)`` and
    keeps the merge logic identical so semantics don't drift.

    *default_chain* is the job's chain (derived from ``Job.chain_id`` via the
    registry): an entry that carries no evidence chain of its own inherits it
    so no writer persists ``chain=NULL`` and mints a duplicate against a sibling
    writer's ``'ethereum'`` stub (NULL ≠ NULL defeats ``uq_contract_address_chain``
    — invariants 1/6/12). The ``'unknown'`` resolve-later sentinel is a real
    chain bucket, not absent evidence, so it is preserved, never coerced.

    Commit is the caller's responsibility — typical use is one bulk call
    per discovery source followed by a single commit.
    """
    if not entries:
        return []

    resolved_default = canonical_chain(default_chain)

    # Normalize once so the lookup map and the merge loop see identical keys.
    norm_entries: list[tuple[str, str | None, dict[str, Any]]] = []
    for entry in entries:
        address = str(entry["address"]).lower()
        chain = canonical_chain(entry.get("chain")) or resolved_default
        clean_entry = dict(entry)
        clean_entry["chain"] = chain
        clean_entry["chains"] = canonical_chain_list(entry.get("chains"))
        norm_entries.append((address, chain, clean_entry))

    # One round-trip for every existing row across the requested (address, chain) tuples.
    # We can't use a single tuple-IN against a composite key efficiently in SQLAlchemy
    # core without raw SQL, so query by address set and filter chain in Python — the
    # set is small (typically 100-300 addresses) and the chain comparison is O(1).
    # The chain half of the key is mainnet-coalesced so a mainnet writer dedups
    # against legacy NULL-chain rows instead of minting a duplicate.
    addresses = list({a for a, _c, _e in norm_entries})
    existing_rows = session.execute(select(Contract).where(Contract.address.in_(addresses))).scalars().all()
    existing_by_key: dict[tuple[str, str], Contract] = {
        (row.address, _mainnet_coalesced_chain(row.chain)): row for row in existing_rows
    }

    out: list[Contract] = []
    for address, chain, entry in norm_entries:
        key = (address, _mainnet_coalesced_chain(chain))
        clean_sources = [s for s in (entry.get("new_sources") or []) if s]
        # Only high-confidence sources may assert protocol ownership.
        # Low-confidence sources (dapp_crawl scraping, upgrade_history
        # traversal of unconfirmed proxies) populate discovery_sources
        # but leave protocol_id NULL until a high-confidence source
        # corroborates. See services/discovery/source_confidence.py.
        owning_protocol_id = protocol_id if asserts_ownership(clean_sources) else None
        existing = existing_by_key.get(key)
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
            existing_by_key[key] = row
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
    default_chain: str | None = None,
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

    *default_chain* is the job's chain (derived from ``Job.chain_id`` via the
    registry); an entry carrying no evidence chain inherits it so no writer
    persists ``chain=NULL`` and mints a duplicate against a sibling writer's
    ``'ethereum'`` stub. Shares the mainnet-coalesced dedup key with
    :func:`bulk_upsert_discovered_contracts` (invariants 1/6/12).

    Commit is the caller's responsibility — callers usually batch many
    upserts into one transaction.
    """
    normalized = address.lower()
    chain = canonical_chain(chain) or canonical_chain(default_chain)
    chains = canonical_chain_list(chains)
    # Mainnet-coalesced dedup so a mainnet write finds legacy NULL-chain rows
    # while a non-mainnet write stays isolated. ``first()`` (not
    # ``scalar_one_or_none``) tolerates pre-existing legacy duplicates without
    # raising, mirroring the bulk helper's dict-collapse.
    existing = (
        session.execute(
            select(Contract)
            .where(
                Contract.address == normalized,
                func.lower(func.coalesce(Contract.chain, "ethereum")) == _mainnet_coalesced_chain(chain),
            )
            .order_by(Contract.id)
            .limit(1)
        )
        .scalars()
        .first()
    )

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


def find_completed_static_cache(
    session: Session,
    address: str,
    chain: str | None = None,
    source_content_hash: str | None = None,
) -> Job | None:
    """Find a previously completed job for *address* (and *chain*) that has all required static data.

    Returns the cached :class:`Job` if one exists with:
    - status = completed, stage = done
    - at least one ``source_files`` row
    - the ``contract_analysis`` artifact (key indicator that the static stage finished)
    - a ``contracts`` row for this address/chain with a ``contract_summaries`` row

    The contract lookup uses (address, chain) rather than ``job_id`` so that
    the cache remains valid even after ``copy_static_cache`` reassigned the
    Contract row to a later target job.

    **Cross-chain fallback (invariant 1):** when the exact ``(address, chain)``
    lookup misses and *source_content_hash* is supplied, a second lookup finds a
    completed job that analyzed the *same verified source* under the current
    analyzer schema version — regardless of its chain or address. That donor's
    code plane is reusable for this deployment (its state is re-resolved per
    chain by the copy path). The primary ``(address, chain)`` behaviour is
    unchanged, so mainnet re-runs are byte-identical; the fallback only fires on
    a primary miss. Returns ``None`` when no suitable cache exists.
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
    # SQL-side chain filtering on the first-class ``jobs.chain_id`` column
    # (invariant 1). The M0.2 backfill populated chain_id for every
    # address-scoped row, so ``chain_id = :id`` is a total, collision-free
    # filter; ``derive_job_chain_id`` maps the caller's chain string to the same
    # id the dual-write stored (unknown/missing → 1) so mainnet is unchanged.
    if chain is not None:
        stmt = stmt.where(Job.chain_id == derive_job_chain_id(chain, address))
    candidates = session.execute(stmt).scalars().all()

    for candidate in candidates:
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
            # Mainnet-coalesced so a mainnet lookup matches legacy NULL-chain
            # rows; a non-mainnet lookup stays isolated (invariants 1/6/12).
            contract_stmt = contract_stmt.where(
                func.lower(func.coalesce(Contract.chain, "ethereum"))
                == _mainnet_coalesced_chain(canonical_chain(chain))
            )
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

    # Cross-chain fallback: the exact (address, chain) lookup missed; if we know
    # this deployment's source hash, reuse a completed job that analyzed the same
    # source on any chain (invariant 1).
    if source_content_hash:
        return _find_static_cache_by_source_hash(session, source_content_hash)

    return None


def _find_static_cache_by_source_hash(session: Session, source_content_hash: str) -> Job | None:
    """Most-recent completed job whose verified source hashes to *source_content_hash*
    under the current analyzer schema version, with a real analyzed root (a
    ``contract_analysis`` artifact + a summaried contract).

    Version-gated so a bumped analyzer misses stale donors (``jobs`` rows carry
    the schema version they were analyzed under). Proxies are never donors — they
    carry ``contract_flags`` rather than ``contract_analysis`` and are analyzed
    per chain.
    """
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

    candidates = (
        session.execute(
            select(Job)
            .where(
                Job.status == JobStatus.completed,
                Job.stage == JobStage.done,
                Job.source_content_hash == source_content_hash,
                Job.analysis_schema_version == ANALYSIS_SCHEMA_VERSION,
            )
            .order_by(Job.updated_at.desc())
        )
        .scalars()
        .all()
    )
    for candidate in candidates:
        if candidate.address is None:
            continue
        has_src = session.execute(
            select(SourceFile).where(SourceFile.job_id == candidate.id).limit(1)
        ).scalar_one_or_none()
        if not has_src:
            continue
        # A summaried contract at the donor's own (address, chain) proves the
        # static tables landed; contract_analysis proves the analysis (not a
        # proxy stub). Chain-qualified: a CREATE2 same-address deployment on
        # another chain can carry different source, so the donor job must pair
        # with its own chain's row (inv. 12).
        donor_contract = session.execute(
            select(Contract)
            .join(ContractSummary, ContractSummary.contract_id == Contract.id)
            .where(
                func.lower(Contract.address) == candidate.address.lower(),
                func.lower(func.coalesce(Contract.chain, "ethereum"))
                == _mainnet_coalesced_chain(_job_chain_name(candidate)),
            )
            .limit(1)
        ).scalar_one_or_none()
        if not donor_contract:
            continue
        has_analysis = session.execute(
            select(Artifact).where(Artifact.job_id == candidate.id, Artifact.name == "contract_analysis").limit(1)
        ).scalar_one_or_none()
        if not has_analysis:
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
    # Company/root jobs are address-less, so ``jobs.chain_id`` is NULL for them
    # (M0.2's CHECK requires chain_id only for address-scoped rows). Their chain
    # identity lives solely in ``request->>'chain'``, so the SQL-side chain
    # predicate keys on the JSONB value — an exact-string match that preserves
    # the prior Python-side ``req.get("chain") != chain`` semantics, including
    # excluding candidates whose request omits ``chain`` (NULL != value).
    if chain is not None:
        stmt = stmt.where(Job.request["chain"].as_string() == chain)
    candidates = session.execute(stmt).scalars().all()
    for candidate in candidates:
        if exclude_job_id and candidate.id == exclude_job_id:
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
    stmt = select(Job).where(
        func.lower(Job.address) == address.lower(),
        Job.status != JobStatus.failed,
    )
    # SQL-side chain filtering on ``jobs.chain_id`` (invariant 1). The M0.2
    # backfill populated every address-scoped row, so this is total;
    # ``derive_job_chain_id`` resolves the caller's chain string to the stored
    # id (unknown/missing → 1), matching the dual-write.
    if chain is not None:
        stmt = stmt.where(Job.chain_id == derive_job_chain_id(chain, address))
    return session.execute(stmt.limit(1)).scalar_one_or_none()


def is_known_proxy(session: Session, address: str, chain: str | None = None) -> bool:
    """Return True if *address* (on *chain*) has been classified as a proxy in any prior analysis."""
    stmt = select(Contract).where(
        func.lower(Contract.address) == address.lower(),
        Contract.is_proxy.is_(True),
    )
    if chain is not None:
        # Mainnet-coalesced so a mainnet lookup matches legacy NULL-chain rows;
        # a non-mainnet lookup stays isolated (invariants 1/6/12).
        stmt = stmt.where(
            func.lower(func.coalesce(Contract.chain, "ethereum")) == _mainnet_coalesced_chain(canonical_chain(chain))
        )
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
        # Mainnet-coalesced so a mainnet lookup matches legacy NULL-chain rows;
        # a non-mainnet lookup stays isolated (invariants 1/6/12).
        src_contract_stmt = src_contract_stmt.where(
            func.lower(func.coalesce(Contract.chain, "ethereum"))
            == _mainnet_coalesced_chain(canonical_chain(src_chain))
        )
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


# Code-plane artifacts safe to reuse across a same-source deployment. Unlike the
# same-chain ``copy_static_cache`` set, this EXCLUDES ``static_dependencies`` and
# ``enrichment_cache`` (dependency addresses / Etherscan enrichment differ per
# chain and are re-derived by the static/discovery stage) and every
# ``_SEED_ARTIFACT_NAMES`` member (dynamic_dependencies / classifications /
# upgrade_history are on-chain-derived and MERGED on re-run — cross-chain merge
# would be wrong). ``contract_analysis`` / ``control_tracking_plan`` carry the one
# deployment-specific field (the contract address), which is re-stamped on copy.
_CROSS_CHAIN_STATIC_ARTIFACTS = frozenset({"contract_analysis", "control_tracking_plan", "predicate_trees", "effects"})


def copy_static_cache_cross_chain(
    session: Session,
    source_job_id: Any,
    target_job_id: Any,
    *,
    target_address: str,
) -> int | None:
    """Reuse a donor job's CODE plane for a same-source deployment on another chain.

    Unlike :func:`copy_static_cache` (which reassigns the donor's Contract row —
    correct only same-chain), this leaves the donor untouched and copies onto the
    target's OWN Contract row (already created per-chain by discovery, with the
    right address/chain/deployer/proxy state). It copies only source-derived
    artifacts, re-stamping the contract address in ``contract_analysis`` /
    ``control_tracking_plan`` so resolution reads the target deployment's state,
    and it copies the summary + role definitions (the static worker skips
    ``_write_analysis_tables`` on a cache hit). The STATE plane (proxy impl,
    controllers, balances, events, monitoring) is untouched and resolved per
    ``(chain, address)`` downstream.

    Returns the target ``Contract.id`` on success, or ``None`` if the target has
    no contract row or the donor lacks the expected artifacts.
    """
    from db.models import RoleDefinition

    target_contract = session.execute(
        select(Contract).where(Contract.job_id == target_job_id).limit(1)
    ).scalar_one_or_none()
    if target_contract is None:
        return None

    src_job = session.get(Job, source_job_id)
    if src_job is None or not src_job.address:
        return None

    # Chain-qualified on the donor job's own chain: a CREATE2 same-address
    # deployment on another chain can carry different source, and its
    # summary/roles must never be the ones copied (inv. 12).
    donor_contract = session.execute(
        select(Contract)
        .join(ContractSummary, ContractSummary.contract_id == Contract.id)
        .where(
            func.lower(Contract.address) == src_job.address.lower(),
            func.lower(func.coalesce(Contract.chain, "ethereum")) == _mainnet_coalesced_chain(_job_chain_name(src_job)),
        )
        .limit(1)
    ).scalar_one_or_none()
    if donor_contract is None:
        return None

    target_addr_norm = target_address.lower()

    # --- summary + role definitions (source-level; re-linked to target) ---
    donor_summary = session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == donor_contract.id).limit(1)
    ).scalar_one_or_none()
    if (
        donor_summary is not None
        and not session.execute(
            select(ContractSummary).where(ContractSummary.contract_id == target_contract.id).limit(1)
        ).scalar_one_or_none()
    ):
        copy_row(session, donor_summary, contract_id=target_contract.id)

    existing_roles = session.execute(
        select(RoleDefinition).where(RoleDefinition.contract_id == target_contract.id).limit(1)
    ).scalar_one_or_none()
    if not existing_roles:
        donor_roles = (
            session.execute(select(RoleDefinition).where(RoleDefinition.contract_id == donor_contract.id))
            .scalars()
            .all()
        )
        for rd in donor_roles:
            copy_row(session, rd, contract_id=target_contract.id)

    # --- code-plane artifacts (re-stamp the deployment address) ---
    for name in _CROSS_CHAIN_STATIC_ARTIFACTS:
        payload = get_artifact(session, source_job_id, name)
        if payload is None:
            continue
        if name == "contract_analysis" and isinstance(payload, dict) and isinstance(payload.get("subject"), dict):
            payload = {**payload, "subject": {**payload["subject"], "address": target_addr_norm}}
        elif name == "control_tracking_plan" and isinstance(payload, dict):
            payload = {**payload, "contract_address": target_addr_norm}
        store_artifact(session, target_job_id, name, data=payload)

    session.commit()
    return target_contract.id
