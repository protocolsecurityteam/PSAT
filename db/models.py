"""SQLAlchemy models for PSAT job queue and artifact storage."""

from __future__ import annotations

import enum
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
    DateTime,
    Enum,
    ForeignKey,
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
    coverage = "coverage"
    done = "done"


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    address: Mapped[str | None] = mapped_column(String(42), nullable=True)
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
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
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
    details: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    observed_via: Mapped[str | None] = mapped_column(String(100), nullable=True)

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
    analyzed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
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


class UpgradeEvent(Base):
    __tablename__ = "upgrade_events"
    __table_args__ = (Index("ix_upgrade_events_contract_id", "contract_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    proxy_address: Mapped[str] = mapped_column(String(42), nullable=False)
    old_impl: Mapped[str | None] = mapped_column(String(42), nullable=True)
    new_impl: Mapped[str | None] = mapped_column(String(42), nullable=True)
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)

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
    authority_roles: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    capability_expr: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    conditions: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Plane-1 claims: list of {claim_id, tier, witness}, dual-written alongside
    # the legacy effect_labels. NULL/[] on rows written before the claims plane.
    claims: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

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
    addresses with no on-chain metadata — a legible name in the UI. Keyed
    by the lowercased address so it applies everywhere the address appears
    (signer list, EOA card, function guard, etc.), independent of any
    specific contract context. Distinct from ``PrincipalLabel`` which is
    worker-populated and scoped per-contract.
    """

    __tablename__ = "address_labels"

    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
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
    last_scanned_block: Mapped[int] = mapped_column(Integer, default=0)
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
    data: Mapped[dict[str, Any] | None] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    monitored_contract: Mapped[MonitoredContract] = relationship("MonitoredContract", back_populates="events")

    __table_args__ = (
        Index("ix_monitored_events_contract_id", "monitored_contract_id"),
        Index("ix_monitored_events_event_type", "event_type"),
        Index("ix_monitored_events_detected_at", "detected_at"),
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
