"""SQLAlchemy models for PSAT job queue and artifact storage."""

from __future__ import annotations

import enum
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from utils.chains import UnknownChainError, chain_by_name

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class JobStatus(str, enum.Enum):
    queued = "queued"
    processing = "processing"
    completed = "completed"
    # Transient/retryable failure. ``BaseWorker`` requeues the row with a
    # backoff-set ``next_attempt_at`` after the first transient exception;
    # only after retries are exhausted does the row move to ``failed_terminal``.
    failed = "failed"
    # Terminal failure: deterministic-from-the-start (e.g. ValueError on bad
    # input, missing Etherscan source) or transient retries exhausted. The
    # stale-job sweep never resurrects ``failed_terminal`` rows.
    failed_terminal = "failed_terminal"


class JobStage(str, enum.Enum):
    discovery = "discovery"
    dapp_crawl = "dapp_crawl"
    defillama_scan = "defillama_scan"
    selection = "selection"
    static = "static"
    resolution = "resolution"
    policy = "policy"
    # Effect simulation (EFFECTS_RESOLUTION_SPEC §3a). Inserted between policy
    # and coverage; source order IS the progression, so this position makes
    # ``_satisfy_dependencies`` (relative enum order) route it correctly. The
    # policy->effects transition is feature-flagged (PSAT_EFFECTS_STAGE); with
    # the flag off, policy advances straight to coverage and this stage is inert.
    effects = "effects"
    coverage = "coverage"
    done = "done"


def derive_job_chain_id(chain_value: Any, address: str | None) -> int | None:
    """Resolve a job's first-class ``chain_id`` from its ``request["chain"]``.

    Single source of derivation truth for the ``jobs.chain_id`` dual-write
    (invariant 1). Address-less company/root jobs carry no chain identity
    (a deployment concept) and return None; the CHECK constraint permits that.
    For address-scoped jobs the chain string resolves through the canonical
    registry; missing/empty is the mainnet edge default, and an unrecognized
    value (typo, the ``"unknown"`` sentinel, or a non-string) falls back to
    mainnet with a warning so a misconfiguration is visible without changing
    mainnet behaviour. Mirrors the M0.2 migration backfill so dual-written and
    legacy rows agree.
    """
    if address is None:
        return None
    if chain_value is None or (isinstance(chain_value, str) and not chain_value.strip()):
        return 1
    try:
        return chain_by_name(chain_value).chain_id
    except UnknownChainError:
        logger.warning(
            "derive_job_chain_id: unrecognized chain %r for address %s; defaulting chain_id=1",
            chain_value,
            address,
        )
        return 1


def _job_chain_id_insert_default(context: Any) -> int | None:
    """Column ``default`` for ``jobs.chain_id`` — fires only when a row is
    inserted without an explicit chain_id.

    ``db.queue.create_job`` sets chain_id explicitly (the enqueue-path
    dual-write), so this never runs on the production path. It is a
    defense-in-depth net: any direct ``Job(...)`` construction (only tests
    today) still gets a derived chain_id from its own ``request["chain"]`` and
    can't violate the CHECK constraint. Never a constant default — always the
    same registry-backed derivation."""
    params = context.get_current_parameters()
    request = params.get("request")
    chain = request.get("chain") if isinstance(request, dict) else None
    return derive_job_chain_id(chain, params.get("address"))


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # First-class chain identity for the deployment (invariant 1). Derived at
    # create time from ``request["chain"]`` via the canonical registry and
    # dual-written alongside the string chain in ``request``. Nullable, but a
    # CHECK constraint (see ``__table_args__``) requires it for address-scoped
    # jobs; company/root jobs with ``address IS NULL`` keep it NULL. Reads still
    # come from ``request["chain"]`` until the M0.2 Item-2 dedup flip. ``default``
    # derives from this row's own ``request["chain"]`` when a caller omits
    # chain_id, so no construction path can silently violate the CHECK.
    chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True, default=_job_chain_id_insert_default)
    company: Mapped[str | None] = mapped_column(String, nullable=True)
    name: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), nullable=False, default=JobStatus.queued)
    stage: Mapped[JobStage] = mapped_column(Enum(JobStage), nullable=False, default=JobStage.discovery)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    request: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # Correlation id shared with the originating HTTP request and any
    # spawned child jobs. 16-char hex (uuid4().hex[:16]); nullable so
    # pre-migration rows remain valid. Persisted so a fly-log scrape can
    # join HTTP logs to worker logs without timestamp guesswork.
    trace_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    # Mirrored from contract_flags by store_artifact; lets /api/jobs skip the artifact resolve.
    is_proxy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    # Number of attempts completed for this job. 0 means "first attempt has
    # not yet failed"; bumped by ``requeue_job`` on every transient failure
    # before ``BaseWorker`` re-queues. Persisted across crashes so the
    # worker pool agrees on attempt count.
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # When NOT NULL, ``claim_job`` skips this row until wall-clock ≥ this
    # value. Set by ``requeue_job`` after a transient failure to the result
    # of ``compute_next_attempt`` so workers honour exponential backoff.
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # ``"transient"`` / ``"terminal"`` for the most recent failure; NULL for
    # never-failed rows. Cheap operational index for "which jobs flap" /
    # "which jobs were terminally bad" without resolving the artifact.
    last_failure_kind: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Per-claim lease. ``claim_job`` mints a fresh ``lease_id`` (uuid4) and
    # stamps ``lease_expires_at`` to NOW() + ttl. ``_heartbeat`` extends
    # ``lease_expires_at``; the stale sweep keys on it instead of
    # ``updated_at``. Every mutating queue write (advance/complete/requeue/
    # fail_terminal) filters on ``lease_id`` so a worker whose lease has
    # rolled to a sibling can't silently corrupt the row.
    lease_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Content hash of this job's verified-source set (services/discovery/fetch.py
    # source_content_hash) plus the analyzer schema version it was analyzed under.
    # Together they let the job-level static cache (find_completed_static_cache)
    # reuse a completed job's code-plane analysis for a NEW (chain, address)
    # deployment of the same source — the cross-chain analog of the (address,
    # chain) primary lookup. Both nullable: written only when a job fetches its
    # own source (a cache-hit job never fetches), and legacy rows stay NULL and so
    # never act as a reuse donor. State is still resolved per (chain, address).
    source_content_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    analysis_schema_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    artifacts: Mapped[list["Artifact"]] = relationship("Artifact", back_populates="job", cascade="all, delete-orphan")
    source_files: Mapped[list["SourceFile"]] = relationship(
        "SourceFile", back_populates="job", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_jobs_stage_status", "stage", "status"),
        Index("ix_jobs_trace_id", "trace_id"),
        # Partial index — powers the lease-expiry sweep. Most rows aren't
        # ``processing`` so a partial keeps the index small and the sweep
        # query a single index scan.
        Index(
            "ix_jobs_lease_expires_at",
            "lease_expires_at",
            postgresql_where=text("status = 'processing'"),
        ),
        # Serves the M0.2 Item-2 SQL-side dedup lookups keyed on
        # ``(lower(address), chain_id)``. Mirrors the ``lower(address)``
        # functional-index style used elsewhere (ix_function_principals_lower_address)
        # since the dedup helpers compare ``func.lower(Job.address)``.
        Index("ix_jobs_lower_address_chain_id", text("lower(address)"), "chain_id"),
        # Serves the cross-chain source-hash fallback in find_completed_static_cache.
        Index("ix_jobs_source_content_hash", "source_content_hash"),
        # Address-scoped jobs must carry a chain_id; company/root jobs
        # (address IS NULL) legitimately leave it NULL (invariant 1).
        CheckConstraint(
            "address IS NULL OR chain_id IS NOT NULL",
            name="ck_jobs_chain_id_required_for_address",
        ),
    )

    def to_dict(self) -> dict:
        from utils.secrets import sanitize_obj, sanitize_string

        return {
            "job_id": str(self.id),
            "address": self.address,
            "company": self.company,
            "name": self.name,
            "status": self.status.value,
            "stage": self.stage.value,
            "detail": self.detail,
            "request": sanitize_obj(self.request) if self.request is not None else None,
            "error": sanitize_string(self.error) if isinstance(self.error, str) else self.error,
            "worker_id": self.worker_id,
            "trace_id": self.trace_id,
            "is_proxy": self.is_proxy,
            "retry_count": self.retry_count,
            "next_attempt_at": self.next_attempt_at.isoformat() if self.next_attempt_at else None,
            "last_failure_kind": self.last_failure_kind,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class JobDependency(Base):
    """Durable edge ``A depends on B`` so A's stage claim can be gated on
    B reaching ``required_stage``.

    Inserted by the resolution worker when A's predicate trees reference
    a state-variable-resolved external contract address. The ``claim_job``
    queue gate skips A while at least one row with status='pending'
    exists for ``A.id``. ``BaseWorker._satisfy_dependencies`` flips rows
    to ``satisfied`` when B reaches the required stage and to
    ``degraded`` when B terminally fails (so dependents fall back to
    ``external_check_only`` rather than block forever).
    """

    __tablename__ = "job_dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    depender_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    # ``provider_chain`` mirrors ``Job.request['chain']`` for the provider
    # contract; nullable for legacy / mainnet-default rows.
    provider_chain: Mapped[str | None] = mapped_column(String(50), nullable=True)
    provider_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # Stage of the provider that A needs reached before unblocking. Stage
    # ordering follows the ``JobStage`` enum's natural order (discovery <
    # static < resolution < policy < coverage < done).
    required_stage: Mapped[JobStage] = mapped_column(Enum(JobStage), nullable=False)
    # ``pending`` — provider hasn't reached required_stage yet (claim gate
    # blocks A).
    # ``satisfied`` — provider reached or passed required_stage.
    # ``degraded`` — provider terminally failed; dependent should
    # short-circuit to ``external_check_only``.
    # ``cycle_degraded`` — adding this edge would close a cycle in the
    # dep graph; treat as a non-blocking degradation to preserve liveness.
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", server_default="pending")
    # When status='cycle_degraded', the dep-chain that closed back to the
    # depender is recorded here for ops debugging.
    cycle_path: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    satisfied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # An edge is uniquely identified by (depender, provider_chain,
        # provider_address, required_stage). Duplicate inserts on
        # re-runs of the resolution stage are no-ops via
        # ON CONFLICT DO NOTHING.
        UniqueConstraint(
            "depender_job_id",
            "provider_chain",
            "provider_address",
            "required_stage",
            name="uq_job_dep_edge",
        ),
        # Powers the satisfy-on-advance scan: one provider job's
        # advance walks every pending row for (chain, address) +
        # required_stage<=completed.
        Index(
            "ix_job_dep_provider",
            "provider_chain",
            "provider_address",
            "required_stage",
            "status",
        ),
        # Powers the claim gate's NOT EXISTS — most edges become
        # satisfied quickly so a partial index keeps the gate
        # sub-millisecond.
        Index(
            "ix_job_dep_pending",
            "depender_job_id",
            postgresql_where=text("status = 'pending'"),
        ),
    )


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    # Legacy inline storage. Kept nullable so pre-Tigris rows still read; new writes leave NULL.
    data: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    text_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Size of the object in the bucket, not of anything stored in this row.
    # It is nonzero on all 5,770 rows while ``data``/``text_data`` are null on
    # all of them; the old name ``size_bytes`` read as "this row holds N bytes".
    stored_object_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    job: Mapped[Job] = relationship("Job", back_populates="artifacts")

    __table_args__ = (UniqueConstraint("job_id", "name", name="uq_artifact_job_name"),)


class SourceFile(Base):
    __tablename__ = "source_files"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    path: Mapped[str] = mapped_column(String, nullable=False)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)

    job: Mapped[Job] = relationship("Job", back_populates="source_files")


class WatchedProxy(Base):
    __tablename__ = "watched_proxies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    proxy_address: Mapped[str] = mapped_column(String(42), nullable=False)
    chain: Mapped[str] = mapped_column(String, nullable=False, default="ethereum")
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    proxy_type: Mapped[str | None] = mapped_column(String, nullable=True)
    last_known_implementation: Mapped[str | None] = mapped_column(String(42), nullable=True)
    last_scanned_block: Mapped[int] = mapped_column(default=0)
    needs_polling: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    events: Mapped[list["ProxyUpgradeEvent"]] = relationship(
        "ProxyUpgradeEvent", back_populates="watched_proxy", cascade="all, delete-orphan"
    )
    subscriptions: Mapped[list["ProxySubscription"]] = relationship(
        "ProxySubscription", back_populates="watched_proxy", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("proxy_address", "chain", name="uq_watched_proxy_address_chain"),)


class ProxySubscription(Base):
    __tablename__ = "proxy_subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    watched_proxy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("watched_proxies.id", ondelete="CASCADE"), nullable=False
    )
    discord_webhook_url: Mapped[str | None] = mapped_column(String, nullable=True)
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    watched_proxy: Mapped[WatchedProxy] = relationship("WatchedProxy", back_populates="subscriptions")


class ProxyUpgradeEvent(Base):
    __tablename__ = "proxy_upgrade_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    watched_proxy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("watched_proxies.id", ondelete="CASCADE"), nullable=False
    )
    block_number: Mapped[int] = mapped_column(nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    old_implementation: Mapped[str | None] = mapped_column(String(42), nullable=True)
    new_implementation: Mapped[str] = mapped_column(String(42), nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False, default="upgraded")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    watched_proxy: Mapped[WatchedProxy] = relationship("WatchedProxy", back_populates="events")


# ---------------------------------------------------------------------------
# Protocol / company entity
# ---------------------------------------------------------------------------


class Protocol(Base):
    __tablename__ = "protocols"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    chains: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)), server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    contracts: Mapped[list["Contract"]] = relationship("Contract", back_populates="protocol")
    monitored_contracts: Mapped[list["MonitoredContract"]] = relationship(
        "MonitoredContract", backref="protocol", foreign_keys="MonitoredContract.protocol_id"
    )
    protocol_subscriptions: Mapped[list["ProtocolSubscription"]] = relationship(
        "ProtocolSubscription", backref="protocol"
    )
    official_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Canonical external ID — DefiLlama family slug. NULL when the protocol
    # has no DefiLlama match (long-tail / private). Worker code resolves
    # free-text input to a slug, then keys ``get_or_create_protocol`` on it
    # so different spellings ("ether fi" vs "etherfi") collapse to one row.
    canonical_slug: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Set to NOW() each time the enrollment reconciler successfully drains this
    # protocol. The K-per-tick slow sweep enqueues the least-recently-reconciled
    # protocols (NULLS FIRST) so drift from unknown write sites still converges.
    last_enrollment_reconcile_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    audit_reports: Mapped[list["AuditReport"]] = relationship(
        "AuditReport", backref="protocol", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("name", name="uq_protocol_name"),
        UniqueConstraint("canonical_slug", name="uq_protocol_canonical_slug"),
    )


class AuditReport(Base):
    __tablename__ = "audit_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    pdf_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    auditor: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    date: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Numeric(5, 4), nullable=True)

    # Text-extraction pipeline state. Populated by workers.audit_text_extraction.
    # status values: NULL (not yet attempted), "processing", "success",
    # "failed", "skipped" (e.g. image-only PDFs that need OCR).
    text_extraction_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    text_extraction_worker: Mapped[str | None] = mapped_column(String(128), nullable=True)
    text_extraction_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    text_extracted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    text_extraction_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    text_storage_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    text_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    text_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Scope-extraction pipeline state. Populated by workers.audit_scope_extraction
    # once text_extraction_status='success'. Mirrors the text_* state machine:
    # NULL (eligible) -> "processing" -> "success"/"failed"/"skipped".
    # "skipped" means no scope-section header was found in the PDF text.
    scope_extraction_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    scope_extraction_worker: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scope_extraction_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope_extracted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope_extraction_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_storage_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_contracts: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Commit SHAs mentioned in the PDF as the reviewed revision.
    reviewed_commits: Mapped[list[str] | None] = mapped_column(ARRAY(String(40)), nullable=True)
    # Lower-cased fallback GitHub repos mentioned anywhere in the PDF body.
    referenced_repos: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    # Phase C: LLM-labeled commit metadata from the audit text.
    classified_commits: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)

    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # GitHub repo the PDF was discovered in.
    source_repo: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Findings extracted from the audit; stored as JSONB so the shape can evolve.
    findings: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)
    # Structured scope-table rows, kept alongside the flat ``scope_contracts`` list.
    scope_entries: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("protocol_id", "url", name="uq_audit_report_protocol_url"),
        Index("ix_audit_reports_protocol_id", "protocol_id"),
        Index(
            "ix_audit_reports_text_extraction_status",
            "text_extraction_status",
        ),
        Index(
            "ix_audit_reports_scope_extraction_status",
            "scope_extraction_status",
        ),
        Index(
            "ix_audit_reports_scope_contracts",
            "scope_contracts",
            postgresql_using="gin",
        ),
        # Partial index — powers the content-hash cache lookup in the
        # scope-extraction worker.
        Index(
            "ix_audit_reports_text_sha256_scoped",
            "text_sha256",
            postgresql_where=text("scope_extraction_status = 'success'"),
        ),
    )


class AuditContractCoverage(Base):
    """Link between an ``AuditReport`` and a ``Contract`` that was in scope.

    Persisted so "which audits cover this impl?" is a plain join, not a
    query-time scan of ``scope_contracts[]``. Proxy-aware: the row links
    the implementation-era ``Contract`` the audit actually reviewed, not
    the proxy. See ``services.audits.coverage`` for the matcher.
    """

    __tablename__ = "audit_contract_coverage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    audit_report_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("audit_reports.id", ondelete="CASCADE"), nullable=False
    )
    # Denormalized FK so per-protocol queries stay single-hop.
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    # Matching scope entry, kept for debugging and auditability.
    matched_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Match taxonomy lives in ``services.audits.coverage``.
    match_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # String enum to avoid implying false numeric precision downstream.
    match_confidence: Mapped[str] = mapped_column(String(10), nullable=False)
    # Impl active window the audit applies to. NULL for direct matches.
    covered_from_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    covered_to_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Runtime bytecode anchor captured when the coverage row was written.
    bytecode_keccak_at_match: Mapped[str | None] = mapped_column(String(66), nullable=True)
    # Timestamp for the bytecode anchor sample.
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Source-equivalence verdict for this (audit, contract) pair.
    equivalence_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Short human-readable detail for the equivalence verdict.
    equivalence_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Last verification attempt time, distinct from the bytecode anchor sample.
    equivalence_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Phase C proof strength for ``equivalence_status='proven'`` rows.
    proof_kind: Mapped[str | None] = mapped_column(String(30), nullable=True)
    # Specific commit SHA from ``AuditReport.classified_commits`` that matched
    # this contract's bytecode during verification. Populated alongside
    # ``proof_kind``/``equivalence_status``. NULL for heuristic-only matches
    # (direct / impl_era) and for rows verified before this field existed.
    # Stored as the full 40-char hex so downstream can build GitHub tree URLs
    # without having to look up the audit's commit list again.
    matched_commit_sha: Mapped[str | None] = mapped_column(String(66), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("contract_id", "audit_report_id", name="uq_audit_contract_coverage_pair"),
        Index("ix_audit_contract_coverage_contract_id", "contract_id"),
        Index("ix_audit_contract_coverage_audit_report_id", "audit_report_id"),
        Index("ix_audit_contract_coverage_protocol_id", "protocol_id"),
        # Partial queue index for ``CoverageVerifyWorker``: only ``pending``
        # rows are scanned, so the index size tracks the queue depth not
        # the table size. Built in ``a3b4c5d6e7f8_add_coverage_pending_index``.
        Index(
            "ix_acc_equivalence_pending",
            "id",
            postgresql_where=text("equivalence_status = 'pending'"),
        ),
    )


# ---------------------------------------------------------------------------
# Pipeline artifact tables (replace JSONB blobs)
# ---------------------------------------------------------------------------


class Contract(Base):
    __tablename__ = "contracts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    source_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    chain: Mapped[str | None] = mapped_column(String(100), nullable=True)
    contract_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    compiler_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    language: Mapped[str | None] = mapped_column(String(20), nullable=True)
    evm_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    optimization: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    optimization_runs: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_format: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source_file_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    license: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_proxy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    proxy_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    implementation: Mapped[str | None] = mapped_column(String(42), nullable=True)
    beacon: Mapped[str | None] = mapped_column(String(42), nullable=True)
    admin: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # Additional logic contracts this proxy delegates to beyond the EIP-1967
    # slot ``implementation`` — the split-proxy / admin-impl pattern where the
    # primary impl's ``fallback`` delegatecalls an address held in an ordinary
    # state variable (e.g. ether.fi LRTSquared's ``adminImpl``). Resolved
    # against the PROXY's storage and analyzed as proxy-child jobs so their
    # authority resolves to the proxy's controller. See
    # services/discovery/secondary_impl.py.
    secondary_implementations: Mapped[list[str] | None] = mapped_column(ARRAY(String(42)), nullable=True)
    deployer: Mapped[str | None] = mapped_column(String(42), nullable=True)
    remappings: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    rank_score: Mapped[float | None] = mapped_column(Numeric(10, 4), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Numeric(10, 4), nullable=True)
    # Every source that has independently confirmed this contract for the
    # protocol. Writers union their tag in instead of overwriting, so
    # ranking can boost contracts corroborated by multiple discovery
    # pipelines (e.g. shown on the docs page AND called by the DApp).
    discovery_sources: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)), nullable=True)
    discovery_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    chains: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    job: Mapped[Job] = relationship("Job")
    protocol: Mapped[Protocol | None] = relationship("Protocol", back_populates="contracts")
    summary: Mapped["ContractSummary | None"] = relationship(
        "ContractSummary", back_populates="contract", uselist=False, cascade="all, delete-orphan"
    )
    role_definitions: Mapped[list["RoleDefinition"]] = relationship(
        "RoleDefinition", back_populates="contract", cascade="all, delete-orphan"
    )
    controller_values: Mapped[list["ControllerValue"]] = relationship(
        "ControllerValue", back_populates="contract", cascade="all, delete-orphan"
    )
    control_graph_nodes: Mapped[list["ControlGraphNode"]] = relationship(
        "ControlGraphNode", back_populates="contract", cascade="all, delete-orphan"
    )
    control_graph_edges: Mapped[list["ControlGraphEdge"]] = relationship(
        "ControlGraphEdge", back_populates="contract", cascade="all, delete-orphan"
    )
    upgrade_events: Mapped[list["UpgradeEvent"]] = relationship(
        "UpgradeEvent", back_populates="contract", cascade="all, delete-orphan"
    )
    effective_functions: Mapped[list["EffectiveFunction"]] = relationship(
        "EffectiveFunction", back_populates="contract", cascade="all, delete-orphan"
    )
    principal_labels: Mapped[list["PrincipalLabel"]] = relationship(
        "PrincipalLabel", back_populates="contract", cascade="all, delete-orphan"
    )
    dependencies: Mapped[list["ContractDependency"]] = relationship(
        "ContractDependency", back_populates="contract", cascade="all, delete-orphan"
    )
    balances: Mapped[list["ContractBalance"]] = relationship(
        "ContractBalance", back_populates="contract", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_contracts_job_id", "job_id"),
        Index("ix_contracts_protocol_id", "protocol_id"),
        UniqueConstraint("address", "chain", name="uq_contract_address_chain"),
    )


class ContractSummary(Base):
    __tablename__ = "contract_summaries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    control_model: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_upgradeable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_pausable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_timelock: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    is_factory: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_nft: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    standards: Mapped[list[str] | None] = mapped_column(ARRAY(String(50)), nullable=True)
    source_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="summary")


class RoleDefinition(Base):
    __tablename__ = "role_definitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    role_name: Mapped[str] = mapped_column(String(255), nullable=False)
    declared_in: Mapped[str | None] = mapped_column(String(255), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="role_definitions")

    __table_args__ = (Index("ix_role_definitions_contract_id", "contract_id"),)


class ControllerValue(Base):
    __tablename__ = "controller_values"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    # Proxy/deployment this row was resolved against (NULL = own/sole deployment).
    # Lets one impl-bytecode contract row hold N per-proxy sets; see migration d4e8f1a9c2b7.
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    controller_id: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str | None] = mapped_column(String(66), nullable=True)
    resolved_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # ``none_as_null=True``: a Python ``None`` here means "not determined" and
    # must reach the database as SQL NULL. SQLAlchemy's default renders it as
    # the jsonb scalar ``null``, which is a DIFFERENT state that no ``IS NULL``
    # test can see (db/jsonb.py, W0-5). The watcher clears this field on a
    # controller rotation, so the distinction is load-bearing.
    details: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # How the current value was observed: 'eth_call' / 'eth_call_impl_fallback'
    # / 'eth_call_error' / 'beacon_owner' from the resolution snapshot, or
    # 'event_log' / 'storage_poll' when the watcher rotated it.
    observed_via: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # 'caller_gate' | 'call_target' | NULL. NULL is a third state — the static
    # stage did not determine why this address is attached — and is NOT a
    # synonym for either value. Before this column the analyzer unioned "the
    # caller is checked against this address" with "this address gets called",
    # so a callee (eETH, lido, liquidityPool) was indistinguishable from an
    # authority registry on the persisted row. See ``ControllerProvenance``.
    authority_provenance: Mapped[str | None] = mapped_column(String(32), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="controller_values")

    __table_args__ = (Index("ix_controller_values_contract_id", "contract_id"),)


class ControlGraphNode(Base):
    __tablename__ = "control_graph_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    node_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resolved_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    contract_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    depth: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Kept for compatibility; ``False`` on it is four different populations at
    # once. ``analysis_state`` is what a consumer must read.
    analyzed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # 'analyzed' | 'not_analyzable' | 'attempt_failed' | 'beyond_depth_horizon'
    # | NULL (not determined). No row has ever held a non-NULL value: the column
    # is newer than the last analysis run. ``beyond_depth_horizon`` is a fact about OUR
    # walk, not about the address, and is the one the bool could never express:
    # without ``graph_max_depth`` below it was not even derivable from the row.
    # See ``schemas.resolved_control_graph.ResolvedAnalysisState``.
    analysis_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The ``max_depth`` of the walk that produced this row. NULL = not
    # determined. Without it ``depth`` alone cannot say whether an unanalysed
    # contract was skipped by the horizon or by something else.
    graph_max_depth: Mapped[int | None] = mapped_column(Integer, nullable=True)
    details: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="control_graph_nodes")

    __table_args__ = (Index("ix_control_graph_nodes_contract_id", "contract_id"),)


class ControlGraphEdge(Base):
    __tablename__ = "control_graph_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    from_node_id: Mapped[str] = mapped_column(String(255), nullable=False)
    to_node_id: Mapped[str] = mapped_column(String(255), nullable=False)
    relation: Mapped[str | None] = mapped_column(String(100), nullable=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_controller_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="control_graph_edges")

    __table_args__ = (Index("ix_control_graph_edges_contract_id", "contract_id"),)


# ``ControlGraphEdge.relation`` vocabulary.
#
# ``controller_value`` and the owner/principal relations are *control* claims:
# reversed, they say the to-node has authority over the from-node.
# ``external_call_target`` is not — it says the from-node calls the to-node,
# which is a proven fact about the code but carries no authority: being called
# by X confers nothing over X. Until this split both were written as
# ``controller_value``, and 66 directed edge pairs asserted "A controls B" and
# "B controls A" at once.
EDGE_RELATION_CONTROLLER_VALUE = "controller_value"
EDGE_RELATION_EXTERNAL_CALL_TARGET = "external_call_target"
# The third state. ``controller_value`` asserts "the to-node has authority over
# the from-node"; ``external_call_target`` asserts the opposite positive fact
# ("merely called, confers nothing"). A tracked controller whose
# ``authority_provenance`` is ABSENT supports NEITHER: the static stage answered
# neither question, so the address appeared in a lowered predicate tree without
# ever being shown to gate a caller or to be a call destination. Writing it
# ``controller_value`` makes an authority claim nothing proved (Leg A's tree
# widening minted 37 such targets at once, incl. pure constants like
# HUNDRED_PERCENT_IN_BPS and non-authority mappings like _balances); writing it
# ``external_call_target`` asserts the other unproven fact. This relation keeps
# the edge VISIBLE and out of ``CONTROL_EDGE_RELATIONS``, so it moves no
# authority and no value through the closure.
EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED = "controller_value_unattributed"

# Allowlist, not a denylist: a relation this set does not name contributes no
# authority. A new relation therefore has to be classified deliberately before
# it can move value through the authority closure, instead of being folded in
# by default the way ``external_call_target`` would have been.
CONTROL_EDGE_RELATIONS = frozenset(
    {
        EDGE_RELATION_CONTROLLER_VALUE,
        "safe_owner",
        "timelock_owner",
        "proxy_admin_owner",
        "role_principal",
        "mapping_member",
    }
)


# ``ControllerValue.observed_via`` values written by the monitoring watcher.
# The resolution snapshot's own vocabulary ('eth_call', 'eth_call_error',
# 'eth_call_impl_fallback', 'beacon_owner') lives in services/resolution.
CONTROLLER_OBSERVED_VIA_EVENT_LOG = "event_log"
CONTROLLER_OBSERVED_VIA_STORAGE_POLL = "storage_poll"


# ``UpgradeEvent.source`` vocabulary. Three writers, three values; NULL is the
# fourth state ("writer unknown") and belongs to rows written before the column.
UPGRADE_SOURCE_BACKFILL = "backfill"
UPGRADE_SOURCE_EVENT_SCAN = "event_scan"
UPGRADE_SOURCE_POLL = "poll"


class UpgradeEvent(Base):
    __tablename__ = "upgrade_events"
    __table_args__ = (Index("ix_upgrade_events_contract_id", "contract_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    proxy_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # NULL means "this writer does not record the predecessor", not "there was
    # no predecessor". ``source`` is what tells the two apart: the backfiller
    # projects an artifact that never carried old_impl, the watcher reads the
    # slot's previous value. Without the discriminator both are NULL.
    old_impl: Mapped[str | None] = mapped_column(String(42), nullable=True)
    new_impl: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # NULL = the block was not determined by the writer. Never 0: every
    # consumer orders by this column with ``nullslast()``, and 0 sorts ahead
    # of the genuine genesis deployment, which shifts every impl-era window.
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # For ``source='backfill'`` / ``'event_scan'`` this is the on-chain block
    # timestamp. For ``source='poll'`` no block is known, so it carries the
    # detection time — an upper bound within one poll interval of the change.
    # ``source`` is the only thing that distinguishes the two readings.
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    # Which writer produced this row: 'backfill' (upgrade-history artifact
    # projection), 'event_scan' (log-derived), 'poll' (storage-slot poll).
    # NULL = written before this column existed; the writer is unknown, which
    # is a third state and not a synonym for either value.
    source: Mapped[str | None] = mapped_column(String(20), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="upgrade_events")


class EffectiveFunction(Base):
    __tablename__ = "effective_functions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    function_name: Mapped[str] = mapped_column(String(255), nullable=False)
    selector: Mapped[str | None] = mapped_column(String(10), nullable=True)
    abi_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    effect_labels: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)), nullable=True)
    effect_targets: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    action_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    authority_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Three-state counterpart to ``authority_public`` (whose ``False`` merges a
    # witnessed caller restriction with "we could not determine the authority"):
    # 'open' | 'restricted' | 'not_determined'. NULL = the writer that produced
    # this row predates the column and cannot be read as any of the three.
    authority_openness: Mapped[str | None] = mapped_column(String(20), nullable=True)
    authority_roles: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    capability_expr: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    conditions: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Plane-1 claims: list of {claim_id, tier, witness}, dual-written alongside
    # the legacy effect_labels. NULL/[] on rows written before the claims plane.
    claims: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    # State-mutability witness, carried from the effects stage's ``EffectInfo``.
    # Before these columns the only way to ask "does this function write state"
    # was ``effect_targets``, which concatenates state-write variable names with
    # dotted external-call heads: 501 of its 1642 populated rows carry only call
    # heads, so a populated value asserted a write that was never proven.
    #
    # All four are nullable BECAUSE SQL NULL is a distinct fact here — "not
    # determined", i.e. no effects record covered this signature, or the record
    # contradicted itself (see ``_mutability_fields``). ``[]`` / ``false`` mean
    # the effects stage looked and proved none. A consumer that cannot tell those
    # apart re-creates the defect these columns exist to remove.
    #
    # ``none_as_null=True`` on the JSONB pair is load-bearing: SQLAlchemy's
    # default renders a Python ``None`` as the jsonb scalar ``null``, which is a
    # DIFFERENT state from SQL NULL and is why ``conditions`` above is unusable
    # in a null test on 780 of its 1773 rows (see ``db/jsonb.py``).
    state_changing: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    state_writes: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    sinks: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    writer_selectors: Mapped[list[str] | None] = mapped_column(ARRAY(String(10)), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="effective_functions")
    principals: Mapped[list["FunctionPrincipal"]] = relationship(
        "FunctionPrincipal", back_populates="function", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_effective_functions_contract_id", "contract_id"),)


class FunctionPrincipal(Base):
    __tablename__ = "function_principals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    function_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("effective_functions.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    resolved_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    origin: Mapped[str | None] = mapped_column(String(255), nullable=True)
    principal_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    details: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    function: Mapped[EffectiveFunction] = relationship("EffectiveFunction", back_populates="principals")

    __table_args__ = (
        Index("ix_function_principals_function_id", "function_id"),
        Index("ix_function_principals_lower_address", text("lower(address)")),
        Index(
            "ix_function_principals_safe_owners",
            text("(details->'owners')"),
            postgresql_using="gin",
            postgresql_where=text("resolved_type = 'safe'"),
        ),
    )


class PrincipalLabel(Base):
    __tablename__ = "principal_labels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resolved_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    labels: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    details: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    graph_context: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="principal_labels")

    __table_args__ = (Index("ix_principal_labels_contract_id", "contract_id"),)


class AddressLabel(Base):
    """Admin-curated human-readable name for an arbitrary address.

    Exists to give Safe signers and EOA principals — which are just raw
    addresses with no on-chain metadata — a legible name in the UI. Distinct
    from ``PrincipalLabel`` which is worker-populated and scoped per-contract.

    Global-plus-override model (invariant 12): ``chain`` is a nullable
    chain-NAME string (``'ethereum'``, ``'base'`` — entity tables key on chain
    names, not ids, per invariant 11).

      * ``chain IS NULL`` is a **global** label that applies on every chain.
        This is the right semantics for EOA/Safe-signer labels — the same key
        controls the same off-chain account everywhere — and is this table's
        entire legacy population, so those rows stay untouched and behave
        exactly as before (no backfill).
      * A row with a concrete ``chain`` **overrides** the global label on that
        chain only. This is what makes *contract* labels safe cross-chain: the
        same address is a different contract on each chain and can carry a
        different name per network.

    Identity is a surrogate ``id`` (the bare-address PK collided for contracts
    at the same address on two chains). Uniqueness is enforced by two PARTIAL
    unique indexes rather than a plain ``UNIQUE(address, chain)`` — Postgres
    treats NULL ≠ NULL, so a plain composite unique would admit duplicate
    global rows (this codebase was already bitten by exactly that on
    ``uq_contract_address_chain``). A sentinel chain value was also rejected
    because the sentinel would leak into API semantics.
    """

    __tablename__ = "address_labels"

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    chain: Mapped[str | None] = mapped_column(String(64), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index(
            "uq_address_labels_address_chain",
            "address",
            "chain",
            unique=True,
            postgresql_where=text("chain IS NOT NULL"),
        ),
        Index(
            "uq_address_labels_address_global",
            "address",
            unique=True,
            postgresql_where=text("chain IS NULL"),
        ),
    )


class ContractDependency(Base):
    __tablename__ = "contract_dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    dependency_address: Mapped[str] = mapped_column(String(42), nullable=False)
    dependency_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    relationship_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source: Mapped[list[str] | None] = mapped_column(ARRAY(String(50)), nullable=True)
    proxy_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    implementation: Mapped[str | None] = mapped_column(String(42), nullable=True)
    admin: Mapped[str | None] = mapped_column(String(42), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="dependencies")

    __table_args__ = (Index("ix_contract_dependencies_contract_id", "contract_id"),)


# ---------------------------------------------------------------------------
# Unified monitoring tables
# ---------------------------------------------------------------------------


class MonitoredContract(Base):
    __tablename__ = "monitored_contracts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    chain: Mapped[str] = mapped_column(String(100), nullable=False, default="ethereum")
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="SET NULL"), nullable=True
    )
    watched_proxy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("watched_proxies.id", ondelete="SET NULL"), nullable=True
    )
    contract_type: Mapped[str] = mapped_column(String(50), nullable=False, default="regular")
    monitoring_config: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    last_known_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    last_scanned_block: Mapped[int] = mapped_column(BigInteger, default=0)
    # Stable block at which monitoring began for this contract — seeded once at
    # enrollment and never advanced (unlike last_scanned_block, which tracks the
    # scan frontier). The scanner treats an event below this floor as
    # pre-enrollment history: recorded, but never notified or reanalyzed. NULL
    # (legacy rows the backfill couldn't stamp) disables the floor — notify.
    enrollment_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Poller rotation cursor: NULLS FIRST selection stamps this at chunk-commit
    # time so never-polled and least-recently-polled contracts rotate first.
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    needs_polling: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    enrollment_source: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    events: Mapped[list["MonitoredEvent"]] = relationship(
        "MonitoredEvent", back_populates="monitored_contract", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("address", "chain", name="uq_monitored_contract_address_chain"),
        Index("ix_monitored_contracts_protocol_id", "protocol_id"),
    )


class MonitoredEvent(Base):
    __tablename__ = "monitored_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    monitored_contract_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("monitored_contracts.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    block_number: Mapped[int] = mapped_column(Integer, nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    # On-chain log index — the scan path populates it so identity is
    # (contract, tx_hash, log_index, event_type). NULL for poll-path
    # ``state_changed_poll`` rows (tx_hash='' / block 0), which are outside the
    # partial identity index below by design (design §2.4 Layer 2).
    log_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data: Mapped[dict[str, Any] | None] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    monitored_contract: Mapped[MonitoredContract] = relationship("MonitoredContract", back_populates="events")

    __table_args__ = (
        Index("ix_monitored_events_contract_id", "monitored_contract_id"),
        Index("ix_monitored_events_event_type", "event_type"),
        Index("ix_monitored_events_detected_at", "detected_at"),
        Index(
            "uq_monitored_events_identity",
            "monitored_contract_id",
            "tx_hash",
            "log_index",
            "event_type",
            unique=True,
            postgresql_where=text("log_index IS NOT NULL"),
        ),
    )


class ProtocolSubscription(Base):
    __tablename__ = "protocol_subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    discord_webhook_url: Mapped[str | None] = mapped_column(String, nullable=True)
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    event_filter: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_protocol_subscriptions_protocol_id", "protocol_id"),)


class ContractBalance(Base):
    __tablename__ = "contract_balances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    token_address: Mapped[str | None] = mapped_column(String(42), nullable=True)  # NULL = native ETH
    token_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    token_symbol: Mapped[str | None] = mapped_column(String(50), nullable=True)
    decimals: Mapped[int] = mapped_column(Integer, nullable=False, default=18)
    raw_balance: Mapped[str] = mapped_column(String, nullable=False)  # stored as string to avoid overflow
    usd_value: Mapped[float | None] = mapped_column(Numeric(20, 2), nullable=True)
    price_usd: Mapped[float | None] = mapped_column(Numeric(20, 8), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    contract: Mapped[Contract] = relationship("Contract", back_populates="balances")

    __table_args__ = (Index("ix_contract_balances_contract_id", "contract_id"),)


class DAppInteraction(Base):
    __tablename__ = "dapp_interactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    page_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    to_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    value: Mapped[str | None] = mapped_column(String(80), nullable=True)
    data: Mapped[str | None] = mapped_column(Text, nullable=True)
    method_selector: Mapped[str | None] = mapped_column(String(10), nullable=True)
    typed_data: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    is_permit: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    captured_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_dapp_interactions_job_id", "job_id"),
        Index("ix_dapp_interactions_to_address", "to_address"),
        Index("ix_dapp_interactions_protocol_id", "protocol_id"),
    )


class TvlSnapshot(Base):
    __tablename__ = "tvl_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    total_usd: Mapped[float | None] = mapped_column(Numeric(20, 2), nullable=True)
    defillama_tvl: Mapped[float | None] = mapped_column(Numeric(20, 2), nullable=True)
    chain_breakdown: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    contract_breakdown: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="on_chain")

    __table_args__ = (Index("ix_tvl_snapshots_protocol_timestamp", "protocol_id", "timestamp"),)


class IndexedEventLog(Base):
    """Generic append-only log store for resolver enumeration hints.

    Rows are keyed only by chain, emitting address, event topic, and
    log identity. Descriptor-specific meaning (which topic maps to
    which semantic key) stays in ``enumeration_hint``.
    """

    __tablename__ = "indexed_event_logs"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    topic0: Mapped[str] = mapped_column(String(66), primary_key=True)
    tx_hash: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    log_index: Mapped[int] = mapped_column(Integer, primary_key=True)
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    block_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    transaction_index: Mapped[int] = mapped_column(Integer, nullable=False)
    topics: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    data_words: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index(
            "ix_indexed_event_logs_lookup",
            "chain_id",
            "event_address",
            "topic0",
            "block_number",
            "transaction_index",
            "log_index",
        ),
        Index(
            "ix_indexed_event_logs_block",
            "chain_id",
            "event_address",
            "block_number",
            "log_index",
        ),
    )


class IndexedEventCursor(Base):
    """One scan cursor per ``(chain_id, event_address, topic0)``."""

    __tablename__ = "indexed_event_cursors"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    topic0: Mapped[str] = mapped_column(String(66), primary_key=True)
    last_indexed_block: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    last_indexed_block_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    last_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    # True once the historical backfill has reached the confirmed head at least
    # once. Cursors are seeded at the event address's *creation block* (not 0),
    # so ``last_indexed_block > 0`` no longer implies "indexed" — a freshly
    # enrolled cursor sits at a positive block having scanned nothing. Resolvers
    # consult this flag (not the block number) before trusting the durable index;
    # until it flips True they fall back to an inline fetch.
    backfill_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")


class WorkerHeartbeat(Base):
    """Liveness + last-known work summary for a background daemon that drains
    its own table instead of the ``jobs`` queue (coverage-verify, audit
    text/scope extraction, event-log indexer, enrollment reconciler).

    One row per logical process; the daemon upserts it each loop tick via
    ``db.queue.record_heartbeat`` so the fleet view (``/api/fleet``) can tell
    'idle' from 'dead'. A work-row timestamp can't make that distinction —
    an idle drainer has no recent rows to point at, so it would read as dead.
    """

    __tablename__ = "worker_heartbeats"

    process: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="running")
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    beat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class DaemonLease(Base):
    """A named, TTL'd singleton lease for a background daemon pass.

    One row per logical lease name (e.g. ``'protocol_scanner:ethereum'``).
    The holder writes its ``holder`` uuid and an ``expires_at`` in the
    future; a competitor can only take the row over once ``expires_at`` has
    passed. Unlike a pg advisory lock this survives per-window commits and
    is safe under Neon/pgbouncer transaction pooling (which breaks
    session-scoped advisory locks). See ``db.queue.try_acquire_daemon_lease``.
    """

    __tablename__ = "daemon_leases"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    holder: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class MonitoringEnrollmentQueue(Base):
    """Dirty-flag queue driving the enrollment reconciler (design §2.3).

    One row per protocol that needs its ``monitored_contracts`` (and
    controllers) reconciled. Write sites call
    ``services.monitoring.enrollment.mark_enrollment_dirty`` after a
    protocol-changing action commits; the drainer in
    ``services.monitoring.reconciler`` claims due rows with a lease
    (``lease_id`` + ``lease_expires_at``, same pattern as ``db.queue.claim_job``),
    runs the full ``enroll_protocol_contracts`` build in a fresh session,
    then deletes the row it claimed. ``dirty_at`` doubles as the due-time
    cursor: a failed drain pushes it forward exponentially so a poisoned
    protocol cannot wedge the queue.
    """

    __tablename__ = "monitoring_enrollment_queue"

    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), primary_key=True)
    dirty_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    lease_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EtherscanCache(Base):
    """Persistent Etherscan response cache. Read/written by ``utils/etherscan.py``
    via raw SQL; the model exists so the schema participates in
    ``Base.metadata`` and ``alembic check`` doesn't flag the table as drift.
    """

    __tablename__ = "etherscan_cache"

    module: Mapped[str] = mapped_column(Text, primary_key=True)
    action: Mapped[str] = mapped_column(Text, primary_key=True)
    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    params_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    response: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    cached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    ttl_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_etherscan_cache_cached_at", "cached_at"),)


class ContractMaterialization(Base):
    """Cross-job, cross-process materialization cache.

    A row per ``(chain, bytecode_keccak)`` recording the static analysis
    + tracking_plan bundle so two impl jobs in the same protocol — or a
    same-protocol re-run on the next day — skip the expensive forge build
    + Slither pass. Read/written via ``db.contract_materializations`` with
    request-coalescing through ``pg_advisory_xact_lock``.

    ``status='building'`` marks a row whose builder is currently running
    (``builder_started_at`` records when); concurrent callers poll the
    row instead of duplicating the build. ``'ready'`` means the bundle
    is usable; ``'failed'`` is kept for ops triage but never returned to
    readers. ``'pending'`` is the legacy default kept for compatibility
    with pre-migration rows.
    """

    __tablename__ = "contract_materializations"

    chain: Mapped[str] = mapped_column(String(100), primary_key=True)
    bytecode_keccak: Mapped[str] = mapped_column(String(66), primary_key=True)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    contract_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    analysis: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    tracking_plan: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    predicate_trees: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    analysis_blob_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    tracking_plan_blob_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    predicate_trees_blob_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Content hash of the normalized verified-source file set (+ the compiler
    # inputs that determine the analysis). The ``(chain, bytecode_keccak)`` key
    # reuses a bundle only across byte-identical deployments; per-chain immutables
    # make the same source compile to different bytecode, so keccak misses for a
    # real cross-chain deployment. This hash is chain- and address-independent, so
    # the same source analyzed on chain A can be reused for the deployment on
    # chain B (code plane only — state is still resolved per ``(chain, address)``).
    # Nullable: rows written before this column existed simply never match a hash
    # lookup and fall through to a normal build.
    source_content_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    # Analyzer/pipeline schema version this bundle was built under. Read paths in
    # ``db.contract_materializations`` only serve rows matching the current
    # ``ANALYSIS_SCHEMA_VERSION``; bumping that constant makes older rows miss and
    # rebuild. ``server_default`` backfills pre-existing rows to the launch version.
    analysis_schema_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", server_default="pending")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    builder_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    materialized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("NOW()"), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)

    __table_args__ = (
        UniqueConstraint("chain", "address", name="uq_contract_materializations_chain_address"),
        Index("ix_contract_materializations_status", "status"),
        Index("ix_contract_materializations_source_content_hash", "source_content_hash"),
    )


class MappingEnumerationCache(Base):
    """Cross-process cache for mapping_enumerator hypersync scans.

    A row per ``(chain, address, specs_hash)`` holding the EnumerationResult
    from ``services.resolution.mapping_enumerator``. The single-job pipeline
    walks the recursive resolution graph in *both* the resolution and policy
    stages (``services/resolution/recursive.py``); without a cross-process
    cache each stage re-runs the same hypersync pagination — for a 2017
    contract that's two consecutive 60s timeouts per address. The
    pre-existing in-process module dict only covered same-process repeats,
    which collapsed when 9ce6fa3 split workers into separate OS processes.

    ``specs_hash`` participates in the key so a writer-event-spec change
    produces a fresh row instead of silently returning a stale enumeration.
    Truncated and errored results are cached too — re-running them within
    the TTL would just hit the same bound — and the caller sees the
    ``status`` field to decide whether to act on partial data.
    """

    __tablename__ = "mapping_enumeration_cache"

    chain: Mapped[str] = mapped_column(String(100), primary_key=True)
    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    specs_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    principals: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    pages_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_block_scanned: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    materialized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("NOW()"), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)

    __table_args__ = (Index("ix_mapping_enumeration_cache_materialized_at", "materialized_at"),)


class BytecodeCache(Base):
    """Persistent eth_getCode bytecode cache. Read/written by ``utils/rpc.py`` via
    raw SQL; this model exists so ``alembic check`` doesn't flag the table as
    drift. Bytecode at a deployed address is effectively immutable per
    ``(chain_id, address)`` for the lifetime of the contract — no TTL.
    ``selfdestructed_at`` is reserved for future GC of pre-Cancun SELFDESTRUCT
    survivors; today's writers leave it NULL.
    """

    __tablename__ = "bytecode_cache"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    bytecode: Mapped[str] = mapped_column(Text, nullable=False)
    code_keccak: Mapped[str] = mapped_column(String(66), nullable=False)
    cached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    selfdestructed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_bytecode_cache_cached_at", "cached_at"),)


class EffectBehaviorCache(Base):
    """Persistent, cross-job behavioral-verdict cache (EFFECTS_RESOLUTION_SPEC
    §7 / inv. 11-12). Shared across jobs AND cross-chain twins — the 11
    ``PausableUntil`` sharers are separate jobs, so a sibling (or a twin on
    another chain, or a prior run) that already witnessed a behavior yields a
    free, *trusted* hit.

    Two verdict scopes (inv. 3):

    - ``scope='kernel'`` — function-local (latch-flip, gate-mutation, code-
      change, supply-delta sign, destination *shape*). Key = (``behavior_hash``,
      ``effect_class``); ``contract_surface_hash`` is the empty sentinel.
    - ``scope='projection'`` — contract-scoped (pause blast radius, authorization
      delta). Keyed additionally on ``contract_surface_hash`` (the metadata-
      stripped whole-contract bytecode hash) because the same mixin kernel
      yields different blast radii on different surfaces.

    The row is **code-plane only** (inv. 11): no concrete values ever enter the
    key. Verdicts are **gate-relative** (inv. 12): ``gate_ref`` names the gate
    *structure*, never a concrete address; principal binding happens at read
    time by joining ``function_principals``. The concrete state-plane residue
    (destination address, exact impl, current-check result) lives in
    ``effect_verdicts``, never here.

    ``transcript_ptr`` is an artifact-store key (§8.5), never an inline JSONB
    blob. ``analysis_schema_version`` invalidates the row on a pipeline bump,
    mirroring ``ContractMaterialization``.

    Self-audit (§7): the first time two functions share a behavioral hash, both
    are simulated once and the *kernel* verdicts asserted equal before the cache
    is trusted; ``audit_status`` / ``audit_peer_hash`` / ``audited_at`` record
    that, and ``hit_count`` supports the optional every-Nth re-audit.

    **This table is written on READ, and five of its columns are therefore NOT part of
    its replay identity**: ``hit_count``, ``audit_status``, ``audit_peer_hash``,
    ``audited_at``, ``updated_at`` (the authoritative list is
    ``db.effect_cache.REPLAY_IDENTITY_EXCLUDED_COLUMNS``, which explains why each is
    excluded). ``bump_hit`` / ``mark_audited`` run from the hit path, so two identical
    pipeline runs over an unchanged chain leave DIFFERENT values in them — inv. 11's
    "byte-identical recomputation" and inv. 12's "re-analysis without on-chain change is
    a no-op" hold for this table only modulo those five. ``hit_count`` counts times the
    row was SERVED (``0`` = never served); a lookup that MISSED matches no row at all and
    is counted per job as the ``cache_misses`` stage metric instead.
    """

    __tablename__ = "effect_behavior_cache"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    behavior_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    effect_class: Mapped[str] = mapped_column(String(40), nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False, server_default="kernel")
    # Empty sentinel for kernel rows (projections carry the whole-contract hash).
    # A sentinel rather than NULL keeps the identity UniqueConstraint portable
    # (no NULLS-NOT-DISTINCT dependency).
    contract_surface_hash: Mapped[str] = mapped_column(String(80), nullable=False, server_default="")
    # Gate *structure* descriptor (inv. 12) — never an address.
    gate_ref: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    tier: Mapped[str] = mapped_column(String(20), nullable=False)
    # Artifact-store key (§8.5) — never inline JSONB.
    transcript_ptr: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Small, code-plane structural witness (e.g. supply-delta sign, source-read
    # duration bound). NO concrete/state-plane values.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    analysis_schema_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    # Self-audit bookkeeping (§7).
    audit_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    audit_peer_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    audited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "behavior_hash",
            "effect_class",
            "scope",
            "contract_surface_hash",
            "gate_ref",
            name="uq_effect_behavior_cache_identity",
        ),
        Index("ix_effect_behavior_cache_behavior_class", "behavior_hash", "effect_class"),
    )


class EffectVerdict(Base):
    """Per contract-function **state-plane** residue (EFFECTS_RESOLUTION_SPEC §3a
    / inv. 3). This is where the per-deployment concrete values live — the exact
    destination address, the exact target impl, the Tier-0 current-state check
    result — never the ``effect_behavior_cache``.

    Keyed on the deployment coordinates ``(chain_id, contract_address,
    selector, effect_class)`` and linked back to the behavioral hash + function
    row. The empty-string ``selector`` sentinel keeps the identity constraint
    portable for fallback/receive functions with no selector.
    """

    __tablename__ = "effect_verdicts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    function_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("effective_functions.id", ondelete="SET NULL"), nullable=True
    )
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    contract_address: Mapped[str] = mapped_column(String(42), nullable=False)
    selector: Mapped[str] = mapped_column(String(10), nullable=False, server_default="")
    effect_class: Mapped[str] = mapped_column(String(40), nullable=False)
    behavior_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    tier: Mapped[str] = mapped_column(String(20), nullable=False)
    # State-plane concrete values — the reason this row is not the cache.
    concrete_destination: Mapped[str | None] = mapped_column(String(42), nullable=True)
    current_check_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # The state-plane residue with no column of its own: §5b downstream value
    # reach (holder ADDRESSES + their USD) and the bookkeeping that bounds the
    # hit-path residue re-probe. Deliberately NOT ``witness`` — witness carries
    # the code-plane structural details a cache hit re-publishes verbatim, so
    # anything per-deployment placed there travels to other deployments.
    observed_residue: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    witness: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    transcript_ptr: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "chain_id",
            "contract_address",
            "selector",
            "effect_class",
            name="uq_effect_verdicts_identity",
        ),
        Index("ix_effect_verdicts_function_id", "function_id"),
    )


class EffectsPlanMarker(Base):
    """ "This contract's effect candidates were planned and yielded NO plans."

    A contract whose candidates all synthesize away leaves no trace of having
    been looked at: no ``effect_verdicts`` row, and — when it has no job of its
    own — no ``stage_timing_effects`` artifact either. Effects selection would
    then class it *unowned* forever and re-sweep it from every subsequent job in
    the protocol. This row is the missing trace.

    Only the empty outcome is recorded. A contract that DID yield plans is
    already marked by the verdicts those plans wrote, and recording it here would
    risk claiming coverage for a job that later died before writing them.

    ``planned_at`` is load-bearing, not bookkeeping: the marker is honored only
    while it is at least as new as the reading job (``JobScope.planned_since``),
    so it suppresses the re-sweep *within* a run and expires for the next one.
    Planning inputs are not immutable — an ``upgrade_events`` row lands
    asynchronously, a re-analysis rewrites ``effective_functions`` — so a
    permanent marker could strand a contract that has since become plannable.
    That is silent recall loss, the one failure direction this must not have.
    """

    __tablename__ = "effects_plan_markers"

    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), primary_key=True)
    # The job whose planning pass observed the empty outcome. SET NULL rather
    # than CASCADE: losing the job must not resurrect the re-sweep.
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    # How many candidate functions were planned to reach the empty outcome —
    # ops-facing, so a marker can be audited against the cascade that produced it.
    candidates_planned: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    planned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)


load_dotenv(Path(__file__).resolve().parents[1] / ".env")

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://psat:psat@localhost:5433/psat")

# Env-tunable per process group; start_workers.sh tightens to 2+3 per worker so 10 procs × 5 conns stays under Neon's
# pool ceiling. pool_recycle=300s protects against Neon's ~5-min idle-disconnect.
_POOL_SIZE = int(os.environ.get("PSAT_DB_POOL_SIZE", "5"))
_MAX_OVERFLOW = int(os.environ.get("PSAT_DB_MAX_OVERFLOW", "10"))
_POOL_RECYCLE = int(os.environ.get("PSAT_DB_POOL_RECYCLE", "300"))

engine = create_engine(
    DATABASE_URL,
    pool_size=_POOL_SIZE,
    max_overflow=_MAX_OVERFLOW,
    pool_recycle=_POOL_RECYCLE,
    pool_pre_ping=True,
    # psycopg2 defaults connect_timeout to infinity — would block every
    # session acquisition during a Neon cold-start.
    connect_args={"connect_timeout": 10},
)
SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
