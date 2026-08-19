"""SQLAlchemy models for PSAT job queue and artifact storage."""

from __future__ import annotations

import enum
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dotenv import load_dotenv
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
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
    or_,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    DELIVERY_SHAPE_NOT_DETERMINED,
    NATIVE_STATUS_PROVEN_ZERO,
    SWEEP_STATUS_COMPLETED,
    TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
    TOKEN_REFERENCE_NOT_DETERMINED,
    TOKEN_REFERENCE_SHAPES,
)
from utils.chains import UnknownChainError, chain_by_name

if TYPE_CHECKING:
    from schemas.api_responses import JobDict
from utils.restaking_status import (
    CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED,
    CROSS_READ_AGREE,
    CROSS_READ_AGREEMENTS,
    EIGENPOD_BASES,
    EIGENPOD_BASIS_NO_EIGENPOD_PROVEN,
    EIGENPOD_BASIS_PROVEN_CROSS_READ,
    NODE_SET_COMPLETENESS_NOT_DETERMINED,
    NON_OBSERVING_SHARES_BASES,
    SHARES_BASES,
    SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
    SHARES_BASIS_NO_EIGENPOD_PROVEN,
    SHARES_COLUMN_COMMENT,
)
from utils.scoring_status import (
    DESTINATION_BEARING_CLAIMS,
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_NOT_DETERMINED,
    DESTINATION_STATES,
    GRADE_STATE_COMPUTED,
    GRADE_STATES,
    NO_SELECTOR,
    OPENNESS_STATES,
    PERIMETER_STATES,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATES,
    REACH_GATE_STATES,
    SCORE_TRIGGERS,
    SEVERITY_STATE_PROVEN,
    SEVERITY_STATES,
    VALUE_BOUND_NOT_DETERMINED,
    VALUE_BOUNDS,
    VALUE_STATE_PROVEN_REACH,
    VALUE_STATES,
    WITNESS_TIERS,
)


def _sql_tuple(values: tuple[str, ...]) -> str:
    """A SQL ``IN`` list built from the vocabulary module.

    The constraint text and the producer must name the same strings; spelling
    them twice is how a domain check drifts into permitting a value the writer
    can no longer produce (or refusing one it can).
    """
    return "(" + ", ".join(f"'{value}'" for value in values) + ")"


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
    # Behavioral effect simulation. Inserted between policy
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

    def to_dict(self) -> "JobDict":
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
    stored_object_size_bytes: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
        comment=(
            "Byte length of the object at storage_key in the bucket. Says nothing "
            "about data/text_data, which are null whenever this is set."
        ),
    )
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
    # test can see (db/jsonb.py). The watcher clears this field on a
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
    # | NULL (not determined). ``beyond_depth_horizon`` is a fact about OUR
    # walk, not about the address, and is the one the bool could never express:
    # without ``graph_max_depth`` below it was not even derivable from the row.
    # Two writers: the resolution walk's stamp, and
    # ``services.governance.control_graph_types.reconcile_control_graph_types``,
    # which fills NULL (only NULL) with the walk's own derivation after a type
    # fold determines analyzability the walk could not.
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
# ``controller_value`` makes an authority claim nothing proved (widening the
# lowered tree minted 37 such targets at once, incl. pure constants like
# HUNDRED_PERCENT_IN_BPS and non-authority mappings like _balances); writing it
# ``external_call_target`` asserts the other unproven fact. This relation keeps
# the edge VISIBLE and out of ``CONTROL_EDGE_RELATIONS``, so it moves no
# authority and no value through the closure.
EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED = "controller_value_unattributed"

# A ``function_principals`` row, materialized into the graph plane by
# ``services.governance.control_graph_types.materialize_fp_principal_nodes``.
#
# Deliberately NOT ``role_principal``. That relation asserts a WITNESSED ROLE
# ("this address holds role R"), and the largest population reaching this pass
# is precisely the one for which ``capability_role_grants`` REFUSED to assert a
# role: a ``_ROLE_DISSOLVING_TRACE_STEPS`` trace leaves
# ``effective_functions.authority_roles`` JSON null, and 127 further rows carry
# ``authority_roles == []`` (authority proven, not role-keyed). Writing those as
# ``role_principal`` would mint the exact claim the upstream declined to make.
#
# What it DOES assert is the FP row itself: this address is a resolved principal
# of a gated function on the from-node contract. That is an authority claim, so
# it belongs in ``CONTROL_EDGE_RELATIONS`` below. It moves NO NEW VALUE through
# the effects closure: ``services.effects.selection.build_authority_graph``
# already folds ``function_principals`` straight into the closure as
# "principal -> the contract the function lives on", so this edge duplicates an
# authority link the closure carries anyway — it makes it reachable in the TABLE
# plane (Surface, chat, enrollment) that reads edges instead of FP rows.
EDGE_RELATION_CAPABILITY_PRINCIPAL = "capability_principal"

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
        EDGE_RELATION_CAPABILITY_PRINCIPAL,
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


# ``UpgradeTransaction.executor_kind`` vocabulary. The enum is deliberately
# three-valued: the two positives are each a *proven* routing fact (a
# keccak-matched marker log whose emitter an independent classifier typed), and
# ``not_determined`` is the single state every failure, revert, absence and
# unclassified-emitter path reaches. There is no ``eoa_one_hop`` member: a
# receipt proves ``tx.from`` was msg.sender in the TOP-LEVEL frame, which is not
# proof it was msg.sender at the upgrade site, and never proof of who authorised.
EXECUTOR_KIND_TIMELOCK_ROUTED = "timelock_routed"
EXECUTOR_KIND_SAFE_DIRECT = "safe_direct"
EXECUTOR_KIND_NOT_DETERMINED = "not_determined"
EXECUTOR_KINDS = (
    EXECUTOR_KIND_TIMELOCK_ROUTED,
    EXECUTOR_KIND_SAFE_DIRECT,
    EXECUTOR_KIND_NOT_DETERMINED,
)


class UpgradeTransaction(Base):
    """Receipt-derived facts about ONE upgrade transaction.

    Keyed on the transaction, not the event, because the facts are properties of
    the transaction: one tx emits up to 19 ``Upgraded`` logs across 19 proxies in
    this corpus, and storing the executor fact per event would store 19 mutable
    copies of one fact and let a consumer count one governance action 19 times.
    ``(chain_id, tx_hash)`` IS the governance action id.

    **Row existence is the coverage discriminator.** A row means a receipt was
    read and decoded; its absence means never read or read failed. That is the
    distinction nullable columns on ``upgrade_events`` could not express —
    ``executor_kind IS NULL`` would conflate "not fetched" with "fetched and
    undetermined", which is a defaulted witness by construction.
    """

    __tablename__ = "upgrade_transactions"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Lowercased 0x-prefixed 32-byte hash. Also the ``governance_action_id``:
    # aggregate on this, never on ``upgrade_events.id``.
    tx_hash: Mapped[str] = mapped_column(String(66), primary_key=True)
    # Observation coordinates. ``eth_getTransactionReceipt`` takes no block
    # parameter, so this read cannot be pinned by parameter the way every other
    # chain read in the codebase is; ``block_hash`` is what lets a later reader
    # DETECT a reorg instead of having to trust the original observation.
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    block_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    # 1 = success, 0 = reverted. A reverted transaction cannot have upgraded
    # anything, so every positive below is withheld unless this is 1.
    tx_status: Mapped[int] = mapped_column(Integer, nullable=False)
    receipt_from: Mapped[str] = mapped_column(String(42), nullable=False)
    # NULL is a FACT (the transaction is a contract creation), distinguished
    # from "unknown" by the row existing at all.
    receipt_to: Mapped[str | None] = mapped_column(String(42), nullable=True)
    created_contract_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    is_contract_creation: Mapped[bool] = mapped_column(Boolean, nullable=False)
    executor_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    executor_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # Which persisted plane typed the emitter, and as what. Recorded so the
    # verdict is auditable; the plane order is fixed and is NOT a strength
    # ranking — planes that disagree yield ``not_determined``.
    executor_classification_source: Mapped[str | None] = mapped_column(String(40), nullable=True)
    executor_classified_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Height at which the emitter was classified, from the classifier's own
    # ``safe_protection.probe_block``. NULL = not determined. The classification
    # plane carries no block on rows written before that probe existed, so this
    # is the field that keeps ``executor_kind`` from implying "…and the emitter
    # was a Safe AT the upgrade's block", which the receipt cannot prove.
    executor_classification_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The ``target`` word decoded from each ``CallExecuted`` log, gated on
    # ``executor_kind='timelock_routed'`` (NULL otherwise — the strength gate is
    # not detachable from the payload). Lets a reader tell which proxies the
    # timelock call actually targeted instead of attributing every log in the
    # transaction to it.
    # ``none_as_null`` so an absent target list is SQL NULL (not determined),
    # never the JSON literal ``null`` — the CHECK below distinguishes them and
    # so would any consumer.
    executor_call_targets: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # COMPUTED, never asserted. True only when (i) every stored ``Upgraded``
    # event for this tx is present in the receipt's own log array, emitted by
    # its proxy, (ii) the ``logsBloom`` is present, well-formed and passes a
    # positive control — it must confirm an ``Upgraded`` log the array actually
    # carries, which is what rules out the all-zero bloom that answers "absent"
    # to everything — and (iii) that usable bloom agrees with the log array
    # about ``CallExecuted`` (a bloom has no false negatives, so bloom-absent is
    # then independent proof of absence; bloom-present with no such log means
    # the array may be pruned). False withdraws every marker-ABSENCE inference —
    # which is the whole basis of ``safe_direct``.
    receipt_log_set_complete_for_tx: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # The receipt's own ``Upgraded``-log count per emitting proxy. Kept because
    # the projected rows cannot witness their own under-projection: if only one
    # of two logs was stored, the stored pair count says "one event" and the
    # deployment guard would exclude a transaction that also carried a real
    # implementation change.
    receipt_upgraded_counts: Mapped[Any] = mapped_column(JSONB, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "executor_kind IN ('timelock_routed', 'safe_direct', 'not_determined')",
            name="ck_upgrade_transactions_executor_kind",
        ),
        # The strength gate may never be published apart from its payload: a
        # positive kind must carry its emitter AND the plane that typed it, and
        # ``not_determined`` may carry neither.
        CheckConstraint(
            "(executor_kind = 'not_determined') = (executor_address IS NULL) "
            "AND (executor_kind = 'not_determined') = (executor_classification_source IS NULL) "
            "AND (executor_kind = 'not_determined') = (executor_classified_type IS NULL)",
            name="ck_upgrade_transactions_executor_gate_attached",
        ),
        # ``jsonb_typeof`` rather than a SQL null test: a null test also passes
        # the jsonb scalar ``null``, and a written-null here would be a target
        # list a writer claimed to have recorded. Only the never-written state
        # is admissible outside ``timelock_routed``.
        CheckConstraint(
            "executor_kind = 'timelock_routed' OR coalesce(jsonb_typeof(executor_call_targets), 'unset') = 'unset'",
            name="ck_upgrade_transactions_call_targets_gated",
        ),
        Index("ix_upgrade_transactions_tx_hash", "tx_hash"),
    )


class ContractCreationWitness(Base):
    """Two independent witnesses that an address was created in a given tx.

    The receipt rule (``to IS NULL AND contractAddress == proxy``) catches only
    the proxies deployed by an EOA-sent creation transaction. A proxy deployed
    BY A FACTORY has a populated ``receipt.to`` and is indistinguishable from an
    upgrade on the receipt alone, so its deployment-time ``Upgraded`` log gets
    counted as an upgrade. This table carries the second arm.

    **Both witnesses are required and they must agree.** ``creation_tx_hash``
    alone is a claim by an indexer; ``code_absent_at_probe`` alone proves only
    that the address was empty at some height. Together — the indexer names this
    exact tx AND the address provably had no code in the block before the event
    — they prove the event is a deployment. Disagreement, or either witness
    missing, yields ``not_determined``, and a ``not_determined`` event stays
    COUNTED (an upgrade count that may over-count is honest; one that silently
    drops real upgrades is not).
    """

    __tablename__ = "contract_creation_witnesses"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    # From Etherscan ``getcontractcreation``. NULL = the indexer did not answer,
    # never "the address has no creation tx".
    creation_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    creation_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The height at which ``eth_getCode`` was read, and what it said. NULL/NULL
    # = not probed; the pair is written together so "probed and code was there"
    # is distinguishable from "never probed".
    code_probe_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    code_absent_at_probe: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "(code_probe_block IS NULL) = (code_absent_at_probe IS NULL)",
            name="ck_contract_creation_witnesses_code_probe_paired",
        ),
    )


class UpgradeEvent(Base):
    __tablename__ = "upgrade_events"
    __table_args__ = (
        Index("ix_upgrade_events_contract_id", "contract_id"),
        # MATCH SIMPLE: a NULL in EITHER column disables the constraint, which
        # is what lets an event exist before (or without) its receipt fact and
        # what carries the poll writer's tx_hash-less rows.
        ForeignKeyConstraint(
            ["chain_id", "tx_hash"],
            ["upgrade_transactions.chain_id", "upgrade_transactions.tx_hash"],
            name="fk_upgrade_events_upgrade_transaction",
        ),
    )

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
    # Link half of the composite FK to ``upgrade_transactions``. Set ONLY once
    # the receipt-fact row for this ``tx_hash`` exists, so NULL means "no linked
    # receipt fact" — it is NOT a claim that the chain is unknown (the chain is
    # always derivable from ``contracts.chain``). Nothing reads it as a chain
    # discriminator; it exists so the join to the per-transaction facts is a
    # real foreign key rather than a convention.
    chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

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
    authority_public: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment=(
            "TWO states over a three-state fact: true = a public path was earned; "
            "false merges 'a caller restriction was witnessed' with 'the authority "
            "could not be determined at all'. Read authority_openness for the split "
            "-- this column alone cannot tell a gated function from an unread one."
        ),
    )
    # Three-state counterpart to ``authority_public`` (whose ``False`` merges a
    # witnessed caller restriction with "we could not determine the authority"):
    # 'open' | 'restricted' | 'not_determined'. NULL = the writer that produced
    # this row predates the column and cannot be read as any of the three.
    authority_openness: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
        comment=(
            "Three-state authority verdict: 'open' (a public path was earned), "
            "'restricted' (a caller restriction was witnessed), 'not_determined' "
            "(no public path and no witnessed caller set). NULL = written before "
            "this column existed; never read it as any of the three."
        ),
    )
    authority_roles: Mapped[Any | None] = mapped_column(
        JSONB,
        nullable=True,
        comment=(
            "Three states, and [] is the NEGATION of null, not a coarsening of it: a "
            "non-empty list is a witnessed (role, principals) requirement; null is "
            "role-gated with the role NOT determined; [] is proven not role-gated. "
            "The null is the JSONB SCALAR null, not SQL NULL -- 'WHERE authority_roles "
            "IS NULL' matches 0 of the 379 undetermined rows; test "
            "jsonb_typeof(authority_roles) = 'null' (see db/jsonb.py)."
        ),
    )
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
    state_changing: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment=(
            "ABI mutability of a selector-bearing external/public entry point: true when "
            "non-view and non-pure. SQL NULL = not determined and is NOT the same fact as "
            "false; fallback/receive are always NULL here because they have no selector, "
            "which is a different reason from being proven non-mutating."
        ),
    )
    state_writes: Mapped[Any | None] = mapped_column(
        JSONB(none_as_null=True),
        nullable=True,
        comment=(
            "Proven state writes, richer than the state_write sinks (member path, "
            "granularity, hygiene class). SQL NULL = not determined; [] = the effects "
            "stage looked and proved none."
        ),
    )
    sinks: Mapped[Any | None] = mapped_column(
        JSONB(none_as_null=True),
        nullable=True,
        comment=(
            "Kind-tagged sinks (state_write | external_call | delegatecall | "
            "contract_creation | selfdestruct) with body/guard origin. Kept alongside "
            "state_writes because a function can be a proven actor with zero state "
            "writes -- EtherFiRedemptionManager.sweepDust moves tokens under a role gate "
            "with state_writes=[]. SQL NULL = not determined; [] = proven none."
        ),
    )
    writer_selectors: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(10)),
        nullable=True,
        comment=(
            "Selectors to replay when attributing the state writes of this function; empty "
            "when it writes no state. SQL NULL = not determined."
        ),
    )

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
    # Vocabulary: ``schemas.control_tracking.MonitoredContractType`` (column
    # stays untyped varchar; rows may carry values minted by older enrollments).
    contract_type: Mapped[str] = mapped_column(String(50), nullable=False, default="regular")
    monitoring_config: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    last_known_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    # Per polling-plan ``field``: how that entry's most recent ANSWERED
    # poll call ended — "ok" (result parsed as the entry's declared type,
    # including the type's conventional empty such as the zero address;
    # only non-empty values reach last_known_state), "error" (the node
    # answered this call with a per-call JSON-RPC error, e.g. a revert),
    # or "no_value" (answered without error but returned nothing that
    # parses as the declared type — empty 0x from a codeless address /
    # permissive fallback, short body). Absent field =
    # not polled; NULL = no completed poll pass since the column landed.
    # Written only from batches the node actually answered: a wholesale
    # transport failure publishes nothing and leaves last_polled_at
    # unstamped, so this map never reports liveness the poller did not
    # observe. Overwritten wholesale each answered poll pass.
    last_poll_status: Mapped[dict[str, Any] | None] = mapped_column(
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
    # 100, not 50: the witness taxonomy mints ``value_changed:<controller_id>``
    # / ``member_changed:<mapping_var>`` and a real controller id overflows 50.
    # ``event_topics.MAX_EVENT_TYPE_LENGTH`` mirrors this width and demotes any
    # spec whose type would not fit — a truncated controller id names a
    # different slot, so overflow is a demotion, never a trim.
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    block_number: Mapped[int] = mapped_column(Integer, nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    # On-chain log index — the scan path populates it so identity is
    # (contract, tx_hash, log_index, event_type). NULL for poll-path
    # ``state_changed_poll`` rows (tx_hash='' / block 0), which are outside the
    # partial identity index below by design.
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


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Alembic autogenerate filter: keep mapped VIEWs out.

    ``ContractBalanceLatest`` maps the ``contract_balances_latest`` view so ORM
    readers can swap entity without hand-written SQL. Alembic cannot tell a
    mapped view from a mapped table, so without this it would report the view as
    a missing TABLE and a later autogenerate would emit a ``CREATE TABLE`` that
    shadows it. Keyed on the ``info={"is_view": True}`` marker the model carries,
    not on a name list, so a future view is covered by declaring the marker.

    Lives here rather than in ``alembic/env.py`` because that module runs
    migrations at import time and cannot be imported by the drift test that
    proves this filter works.
    """
    if type_ == "table" and (obj.info or {}).get("is_view"):
        return False
    return True


class ContractBalanceFetch(Base):
    """One balance-read attempt against one address. **NOT a holdings witness.**

    This is the fetch-provenance plane. A row here records that a read was
    ATTEMPTED and how it went; it never asserts that anything is held. That
    separation is the whole point: the three-state discriminator cannot live on
    ``contract_balances`` because ``services.effects.selection`` consumes a
    ``contract_balances`` row's mere EXISTENCE as "this deployment holds this
    asset", so a ``fetch_failed`` or ``proven_zero`` row written there would
    publish holdings that do not exist.

    ``native_status`` must be read as the PAIR ``(native_status, block_number)``
    and never alone — ``proven_nonzero`` with a NULL block is "nonzero at an
    unrecorded height", not an as-of-block fact. Route consumers through
    :func:`services.monitoring.balance_reads.native_balance_fact`.
    """

    __tablename__ = "contract_balance_fetches"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # NULL = this read is about an ENTITY with no ``contracts`` row, and
    # ``(entity_chain, entity_address)`` below is its identity. Exactly one of
    # the two arms is populated (``ck_cbf_exactly_one_subject_key``), so every
    # predicate written against ``contract_id`` still selects exactly the
    # contract-keyed rows it selected when the column was NOT NULL.
    contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=True
    )
    # The other identity arm: a discovery-only principal (a Safe owner, a
    # capability principal) is named by chain and address and by nothing else.
    # NULL on every contract-keyed row.
    entity_chain: Mapped[str | None] = mapped_column(String(100), nullable=True)
    entity_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    # The address the read was actually ISSUED against, captured verbatim from
    # the write-point local. Not necessarily ``contracts.address``: the
    # resolution worker reads ``request['proxy_address'] or address``.
    observed_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # The height the NATIVE quantity was read at. NULL = not_determined. Never
    # projected onto ERC-20 rows (Q1 keeps those unpinned).
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    native_status: Mapped[str] = mapped_column(String(32), nullable=False)
    asset_set_status: Mapped[str] = mapped_column(String(32), nullable=False)
    # The RAW endpoint entry count, BEFORE the ``raw_balance > 0`` filter drops
    # entries. NULL = not_determined. This is the only thing that can witness
    # the at-cap case; a stored-row count cannot (the filter destroys it).
    asset_page_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # WHOSE answer the asset set is. ``asset_set_status`` says what the answer
    # was; only the pair is a claim. An empty set from
    # ``etherscan_pages`` is one index's negative and proves nothing about the
    # chain; an empty set from ``chain_log_sweep`` is an earned negative scoped
    # by ``asset_set_basis`` and ``swept_through_block``.
    asset_set_source: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=ASSET_SET_SOURCE_ETHERSCAN_PAGES
    )
    # What the asset set is a set OF, in the terms it was obtained by — the
    # sentence a published claim derives its scope from, never re-invented
    # downstream.
    asset_set_basis: Mapped[str | None] = mapped_column(Text, nullable=True)
    # NULL = no sweep was attempted (a third state, not a failure).
    sweep_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The ERC-721/1155 receipts the scan found, as
    # ``[{address, kind, quantity_readable}]``. Durable BECAUSE it is durable: a
    # typed receipt whose current holding has no readable ``balanceOf(address)``
    # answer is why an asset set's completeness is withheld, and the evidence for
    # that refusal has to outlive the window it was seen in. An incremental
    # window names only what arrived inside it, so a later cycle that could not
    # read this column would see no typed receipt, believe the set complete, and
    # publish the earned negative the earlier scan refused. NULL = no sweep has
    # answered for this contract; ``[]`` = a scan answered and found none.
    # ``none_as_null`` is load-bearing, not style: without it SQLAlchemy stores a
    # Python ``None`` as the JSON scalar ``null``, which is a THIRD shape beside
    # SQL NULL and ``[]`` — and every reader here keys on "NULL means no scan has
    # answered". The CHECK below refuses that shape outright, so the distinction
    # the code leans on is enforced rather than hoped for.
    typed_assets: Mapped[list | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # The FIRST block of the union of every scan that produced the current asset
    # set — not this cycle's window start. The basis string publishes the extent
    # of the claim, and an incremental cycle whose window is 63 blocks wide still
    # rests on the full-history scan that preceded it.
    swept_from_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The block the log scan ran through. Present ONLY on a completed sweep
    # (CHECK below), because it is the extent of the claim and a failed scan has
    # no extent. It is also the cursor: the next cycle scans from here, which is
    # what keeps a full-history sweep a once-per-contract cost.
    swept_through_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    writer: Mapped[str] = mapped_column(String(32), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_cbf_contract_fetched", "contract_id", "fetched_at", "id"),
        # The entity arm's twin of the index above. The view picks a subject's
        # current fetch with ORDER BY fetched_at DESC, id DESC LIMIT 1 under an
        # equality on the subject, and an arm without that index turns the
        # per-row correlated subquery into a sequential scan of this table.
        Index("ix_cbf_entity_fetched", "entity_chain", "entity_address", "fetched_at", "id"),
        # One subject per row. A row carrying both keys would be two subjects at
        # once — the view would match it on either arm and a consumer could not
        # say whose holdings it is — and a row carrying neither would be a
        # reading of nobody.
        CheckConstraint(
            "(contract_id IS NOT NULL AND entity_chain IS NULL AND entity_address IS NULL) "
            "OR (contract_id IS NULL AND entity_chain IS NOT NULL AND entity_address IS NOT NULL)",
            name="ck_cbf_exactly_one_subject_key",
        ),
        CheckConstraint(
            f"native_status <> '{NATIVE_STATUS_PROVEN_ZERO}' OR block_number IS NOT NULL",
            name="ck_cbf_proven_zero_requires_block",
        ),
        # A sweep-sourced asset set without a through-block would be an unbounded
        # claim: "the chain says this is everything" with no statement of how far
        # the chain was read.
        CheckConstraint(
            f"asset_set_source <> '{ASSET_SET_SOURCE_CHAIN_LOG_SWEEP}' OR swept_through_block IS NOT NULL",
            name="ck_cbf_sweep_source_requires_block",
        ),
        # A cursor written by a scan that could not be shown whole would let the
        # next cycle skip the blocks the failed one never proved it read.
        CheckConstraint(
            f"swept_through_block IS NULL OR sweep_status = '{SWEEP_STATUS_COMPLETED}'",
            name="ck_cbf_swept_block_requires_completed_sweep",
        ),
        # NULL means "no scan has answered"; ``[]`` means "a scan answered and
        # found none". A scalar or an object would be neither, and every reader
        # of this column depends on that distinction being real.
        CheckConstraint(
            "typed_assets IS NULL OR jsonb_typeof(typed_assets) = 'array'",
            name="ck_cbf_typed_assets_is_array",
        ),
    )


class ContractBalance(Base):
    __tablename__ = "contract_balances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # See ``ContractBalanceFetch``: NULL means the holding belongs to an entity
    # with no ``contracts`` row, identified by ``(entity_chain, entity_address)``.
    contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=True
    )
    entity_chain: Mapped[str | None] = mapped_column(String(100), nullable=True)
    entity_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    token_address: Mapped[str | None] = mapped_column(String(42), nullable=True)  # NULL = native ETH
    token_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    token_symbol: Mapped[str | None] = mapped_column(String(50), nullable=True)
    decimals: Mapped[int] = mapped_column(Integer, nullable=False, default=18)
    raw_balance: Mapped[str] = mapped_column(String, nullable=False)  # stored as string to avoid overflow
    # 18 fractional digits because that is the resolution the QUANTITY is quoted
    # at: a cent-scaled column silently republished every sub-cent holding as
    # 0.00, which no reader can tell from a holding of nothing. The column stores
    # what the producer computed and rounds nothing.
    usd_value: Mapped[float | None] = mapped_column(Numeric(38, 18), nullable=True)
    # Same 18 digits, and for a sharper reason than symmetry with the column
    # above: 0 is the literal the writers use for "no price known", so a quote
    # finer than the column can hold would be stored as that same 0 and read as
    # a price that never answered. The column holds the quote it was given.
    price_usd: Mapped[float | None] = mapped_column(Numeric(38, 18), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # The address this quantity was read at, verbatim from the write-point
    # local. NULL = not_determined (every row written before this column
    # existed; the address was never recorded and cannot be recovered).
    observed_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # The height THIS quantity was read at. Populated only on the pinned
    # Multicall3 native path; NULL = not_determined, permanently, for every
    # Etherscan-sourced row. An ERC-20 row can never carry one (CHECK below):
    # its quantity comes from an unpinned ``tag=latest`` answer, and letting it
    # inherit the fetch's native height would mint a height it never had.
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Structurally always NULL, and that is the field's job. No price source in
    # this system carries a height (Etherscan's stats endpoint and
    # ``TokenPriceUSD`` are both heightless), and the same asset diverges up to
    # 20.97% within one recorded instant. A consumer MUST NOT substitute
    # ``block_number``: ``usd_value``/``price_usd`` are never as-of-block facts.
    # DB-enforced by ``ck_contract_balances_price_block_null``.
    price_block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The fetch that observed this row. NULL = legacy row, provenance
    # not_determined. The ``contract_balances_latest`` view keys off it, which
    # also makes it the row set's completeness handle: a row's OWN fetch carries
    # the asset-set status/source/basis that the row set was assembled under, so
    # a consumer asks the winning fetch rather than the latest one (see
    # ``balance_reads.winning_asset_fetches``).
    fetch_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("contract_balance_fetches.id", ondelete="CASCADE"), nullable=True
    )
    # Which mechanism read this quantity. NULL = legacy row, not_determined.
    # Stated per row because one fetch's row set can mix them: a page-derived
    # PRICED row and a sweep-derived unpriced one are both current holdings and
    # neither is the other's basis.
    source: Mapped[str | None] = mapped_column(String(32), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="balances")

    __table_args__ = (
        Index("ix_contract_balances_contract_id", "contract_id"),
        Index("ix_contract_balances_fetch_id", "fetch_id"),
        Index("ix_contract_balances_entity", "entity_chain", "entity_address"),
        CheckConstraint(
            "(contract_id IS NOT NULL AND entity_chain IS NULL AND entity_address IS NULL) "
            "OR (contract_id IS NULL AND entity_chain IS NOT NULL AND entity_address IS NOT NULL)",
            name="ck_contract_balances_exactly_one_subject_key",
        ),
        CheckConstraint(
            "token_address IS NULL OR block_number IS NULL",
            name="ck_contract_balances_token_block_null",
        ),
        CheckConstraint(
            "price_block_number IS NULL",
            name="ck_contract_balances_price_block_null",
        ),
    )


class ContractBalanceLatest(Base):
    """READ-ONLY mapping of the ``contract_balances_latest`` VIEW.

    The view is what every consumer must read now that the writers are
    insert-only. It is a pure projection of ``contract_balances`` — same columns,
    a subset of the rows, never a join that can multiply or manufacture one — and
    it answers one question per (contract, row class): which fetch's row set is
    current?

    The question is asked per SUBJECT, and a subject is a ``contracts`` row or
    an entity that has none — ``(entity_chain, entity_address)``. The two arms
    are mutually exclusive at the schema (``ck_*_exactly_one_subject_key``), so
    the coalesced rule the view carries is the contract rule, term for term, for
    every row that has a contract. Matching on ``contract_id`` alone would have
    been NULL for every entity-keyed row: written, stored, and silently absent
    from the view every consumer reads.

    * Per ROW CLASS (native vs ERC-20), independently: the latest fetch that did
      NOT fail for that class wins WHOLESALE. A fetch's rows ARE the set it
      observed, so an asset the holder has since sold correctly disappears, and
      a transient token-fetch failure does not withdraw the native holding (or
      vice versa).
    * A failed fetch never wins. Letting one win would republish "holds nothing"
      out of a failure — the exact fail-open this unit exists to close.
    * Legacy rows (``fetch_id IS NULL``) remain visible until a NON-FAILED fetch
      exists for that contract and class. A first fetch that fails must not
      delete history from the view.

    Not autogenerate-visible: :func:`include_object` (in this module, wired into
    ``alembic/env.py``) filters it out on the ``info={"is_view": True}`` marker
    below — not by name — because Alembic cannot tell a mapped view from a mapped
    table and would otherwise emit a ``CREATE TABLE`` shadowing it.
    ``tests/test_alembic_chain.py`` asserts the filtered diff is empty.
    """

    __tablename__ = "contract_balances_latest"
    __table_args__ = {"info": {"is_view": True}}

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    contract_id: Mapped[int | None] = mapped_column(Integer)
    entity_chain: Mapped[str | None] = mapped_column(String(100))
    entity_address: Mapped[str | None] = mapped_column(String(42))
    token_address: Mapped[str | None] = mapped_column(String(42))
    token_name: Mapped[str | None] = mapped_column(String(255))
    token_symbol: Mapped[str | None] = mapped_column(String(50))
    decimals: Mapped[int] = mapped_column(Integer)
    raw_balance: Mapped[str] = mapped_column(String)
    usd_value: Mapped[float | None] = mapped_column(Numeric(38, 18))
    price_usd: Mapped[float | None] = mapped_column(Numeric(38, 18))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observed_address: Mapped[str | None] = mapped_column(String(42))
    block_number: Mapped[int | None] = mapped_column(BigInteger)
    price_block_number: Mapped[int | None] = mapped_column(BigInteger)
    fetch_id: Mapped[int | None] = mapped_column(BigInteger)
    source: Mapped[str | None] = mapped_column(String(32))


class RestakingPosition(Base):
    """One node's EigenLayer beaconChainETH position at ONE pinned height.

    A separate plane from ``contract_balances`` on purpose, and the separation is
    structural rather than a filter. Every spot-balance reader joins
    ``contract_balances(_latest).contract_id`` to ``contracts.id``; the live
    EtherFiNode instances are BeaconProxy deployments with NO ``contracts`` row
    (measured: zero), and ``contract_balances.contract_id`` is ``NOT NULL``. So a
    restaking row cannot be written into that table at all without first minting
    a ``contracts`` row per node — which would make
    ``services.effects.selection`` read the share quantity as a HOLDING of a
    deployment and sum it into the authority graph. That is the shape the
    balance-provenance unit exists to close, in a new place.

    There is deliberately **no USD column anywhere on this plane**, so a share
    quantity cannot be added to a dollar figure even by accident.

    ``eigenlayer_beacon_shares_wei`` is named for its scope because a bare
    "position" would be read as the node's money. Measured at block 25643300
    over the 26 enumerated nodes: every one reads 0 shares, while their pods hold
    374.148164612 ETH between them — one of them exactly 320 ETH. Summing this
    column over the enumerated set yields 0 wei against that. The node's and the
    pod's execution-layer native balances are ``not_determined`` here, and the
    consensus-layer residual is ``not_determined`` and unbounded above.
    """

    __tablename__ = "restaking_positions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    node_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # PROVENANCE ONLY: the ``contracts`` row whose ADDRESS EQUALS the address the
    # enumerating log was emitted at — the proxy, not the implementation row that
    # shares the manager's name. Never "this contract holds the position".
    manager_contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="SET NULL"), nullable=True
    )
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    # Every read of a row is ISSUED at this height. There is no unpinned path on
    # this plane: without a height nothing is written at all.
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # The reorg witness (inv.11/12). Without it a replay "at block N" cannot tell
    # it is on the same chain history; the event indexer stamps
    # ``last_indexed_block_hash`` for the same reason.
    block_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    eigenpod: Mapped[str | None] = mapped_column(String(42), nullable=True)
    eigenpod_basis: Mapped[str] = mapped_column(String(32), nullable=False)
    eigenlayer_beacon_shares_wei: Mapped[Any | None] = mapped_column(
        Numeric(80, 0), nullable=True, comment=SHARES_COLUMN_COMMENT
    )
    shares_basis: Mapped[str] = mapped_column(String(40), nullable=False)
    # Read from ``EigenPodManager.beaconChainETHStrategy()`` at the SAME block.
    # A literal would be indefensible: the near-miss
    # ``0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee`` answers 0 with success, as
    # does a nonexistent staker, byte-identical to the real 26/26 answer.
    shares_strategy: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # ``int256`` on EigenPodManager and genuinely able to go negative. Stored
    # signed and unclamped.
    deposit_shares_wei: Mapped[Any | None] = mapped_column(Numeric(80, 0), nullable=True)
    cross_read_agreement: Mapped[str] = mapped_column(String(30), nullable=False)
    active_validator_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_checkpoint_timestamp: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    consensus_layer_residual: Mapped[str] = mapped_column(String(20), nullable=False)
    node_set_completeness: Mapped[str] = mapped_column(String(20), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # The basis columns are NOT NULL for a load-bearing reason, not tidiness: the
    # OR-joined arms below are only fail-closed while they are. A NULL basis
    # makes every arm NULL, an OR of NULLs is NULL, and a CHECK that evaluates to
    # NULL PASSES in Postgres — so a nullable basis would readmit every shape
    # these constraints exist to reject.
    __table_args__ = (
        Index("ix_rp_node_block", "chain_id", "node_address", "block_number", "id"),
        CheckConstraint(
            "shares_basis IN " + _sql_tuple(SHARES_BASES),
            name="ck_rp_basis_domain",
        ),
        CheckConstraint(
            "eigenpod_basis IN " + _sql_tuple(EIGENPOD_BASES),
            name="ck_rp_pod_basis_domain",
        ),
        CheckConstraint(
            "cross_read_agreement IN " + _sql_tuple(CROSS_READ_AGREEMENTS),
            name="ck_rp_agreement_domain",
        ),
        # ONE ARM PER BASIS, OR-joined, each arm pinning the basis AND the value
        # together. An arm naming only the basis, or only the value, is vacuous.
        # An unrecognised basis satisfies no arm, so the expression is FALSE.
        CheckConstraint(
            "("
            f"  shares_basis = '{SHARES_BASIS_EIGENLAYER_BEACON_SHARES}'"
            "   AND eigenlayer_beacon_shares_wei IS NOT NULL"
            f"  AND eigenpod_basis = '{EIGENPOD_BASIS_PROVEN_CROSS_READ}'"
            "   AND shares_strategy IS NOT NULL"
            f"  AND (eigenlayer_beacon_shares_wei <> 0 OR cross_read_agreement = '{CROSS_READ_AGREE}')"
            ") OR ("
            f"  shares_basis = '{SHARES_BASIS_NO_EIGENPOD_PROVEN}'"
            "   AND eigenlayer_beacon_shares_wei IS NOT DISTINCT FROM 0"
            f"  AND eigenpod_basis = '{EIGENPOD_BASIS_NO_EIGENPOD_PROVEN}'"
            "   AND shares_strategy IS NULL"
            ") OR ("
            "   shares_basis IN " + _sql_tuple(NON_OBSERVING_SHARES_BASES) + ""
            "   AND eigenlayer_beacon_shares_wei IS NULL"
            "   AND shares_strategy IS NULL"
            ")",
            name="ck_rp_basis_matches_value",
        ),
        # A share quantity is unsigned by construction (the withdrawable leg is
        # a ``uint256``); only the DEPOSIT leg is signed. Without this the DB
        # would accept a negative the producer cannot emit.
        CheckConstraint(
            "eigenlayer_beacon_shares_wei IS NULL OR eigenlayer_beacon_shares_wei >= 0",
            name="ck_rp_shares_non_negative",
        ),
        CheckConstraint(
            f"eigenpod_basis <> '{EIGENPOD_BASIS_NO_EIGENPOD_PROVEN}' OR eigenpod IS NULL",
            name="ck_rp_no_pod_has_no_address",
        ),
        CheckConstraint(
            f"eigenpod_basis <> '{EIGENPOD_BASIS_PROVEN_CROSS_READ}' OR eigenpod IS NOT NULL",
            name="ck_rp_pod_cross_read_has_address",
        ),
        # Pod-derived facts require the proven pod. Without this a
        # ``last_checkpoint_timestamp`` of 0 — a real "never checkpointed"
        # witness — could be minted against an address never proven to have one.
        CheckConstraint(
            f"eigenpod_basis = '{EIGENPOD_BASIS_PROVEN_CROSS_READ}'"
            " OR (active_validator_count IS NULL AND last_checkpoint_timestamp IS NULL)",
            name="ck_rp_pod_facts_require_pod",
        ),
        CheckConstraint(
            f"consensus_layer_residual = '{CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED}'",
            name="ck_rp_cl_residual_not_determined",
        ),
        CheckConstraint(
            f"node_set_completeness = '{NODE_SET_COMPLETENESS_NOT_DETERMINED}'",
            name="ck_rp_node_set_completeness",
        ),
    )


class RestakingPositionLatest(Base):
    """READ-ONLY mapping of the ``restaking_positions_latest`` VIEW.

    Per ``(chain_id, node_address)`` — the chain is part of the key because the
    same address on two chains is two different entities — the most recent
    OBSERVING row wins, ordered ``block_number DESC, id DESC`` so the order is
    total and two rows at one height resolve deterministically.

    Both non-observing bases are excluded from winning. ``read_failed`` is a
    transport or decode failure; ``not_determined`` is a transport success whose
    evidence does not license a value. Letting either win would withdraw a proven
    position on the strength of a non-observation.

    **Absence from this view is ``not_determined``, never "no position".** A node
    whose every row is non-observing does not appear at all, so a consumer that
    read a missing row as zero would reintroduce, at the projection layer, the
    absent-row-as-``$0`` shape the balance-provenance unit exists to close.

    Not autogenerate-visible: :func:`include_object` filters it on the
    ``info={"is_view": True}`` marker, as it does the balance view.
    """

    __tablename__ = "restaking_positions_latest"
    __table_args__ = {"info": {"is_view": True}}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    chain_id: Mapped[int] = mapped_column(Integer)
    node_address: Mapped[str] = mapped_column(String(42))
    manager_contract_id: Mapped[int | None] = mapped_column(Integer)
    protocol_id: Mapped[int | None] = mapped_column(Integer)
    block_number: Mapped[int] = mapped_column(BigInteger)
    block_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    eigenpod: Mapped[str | None] = mapped_column(String(42))
    eigenpod_basis: Mapped[str] = mapped_column(String(32))
    eigenlayer_beacon_shares_wei: Mapped[Any | None] = mapped_column(Numeric(80, 0))
    shares_basis: Mapped[str] = mapped_column(String(40))
    shares_strategy: Mapped[str | None] = mapped_column(String(42))
    deposit_shares_wei: Mapped[Any | None] = mapped_column(Numeric(80, 0))
    cross_read_agreement: Mapped[str] = mapped_column(String(30))
    active_validator_count: Mapped[int | None] = mapped_column(Integer)
    last_checkpoint_timestamp: Mapped[int | None] = mapped_column(BigInteger)
    consensus_layer_residual: Mapped[str] = mapped_column(String(20))
    node_set_completeness: Mapped[str] = mapped_column(String(20))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


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


# ``indexed_event_cursors`` provenance vocabulary. It lives here, with the
# columns, because the writer (the indexer worker) and the reader (the resolution
# repo) must agree on the exact tokens and neither may import the other.
#
# ``first_indexed_block_basis`` — only CREATION licenses citing the lower bound.
FIRST_INDEXED_BASIS_CREATION = "creation_block_minus_one"
FIRST_INDEXED_BASIS_EXPLICIT = "explicit_seed"
CURSOR_BASIS_NOT_DETERMINED = "not_determined"
# ``enrollment_basis`` — whether the row carries a variable attribution.
ENROLLMENT_BASIS_PREDICATE_HINT = "predicate_tree_hint"
ENROLLMENT_BASIS_TRACKED_TOPICS = "tracked_topics_asserted"
# ALLOW-LIST, deliberately, and it is the whole point of the column. Exactness —
# a zero-row fold published as "this event never fired" — is permitted only for a
# basis that is known to carry a variable attribution. A deny-list on the one
# token we happened to invent would fail OPEN on every other value, and there is
# already such a value in the schema: ``enroll_event_cursor`` stores the literal
# ``not_determined`` whenever a caller omits the argument, which is precisely the
# case that must not license anything. NULL is included because it means "row
# predates this column", and those 80 rows were folding before the column existed;
# demoting them is a separate change with its own blast radius.
EXACTNESS_ELIGIBLE_ENROLLMENT_BASES = frozenset({None, ENROLLMENT_BASIS_PREDICATE_HINT})


def enrollment_basis_permits_exactness(basis: str | None) -> bool:
    """Whether a cursor with this ``enrollment_basis`` may support an exact empty.

    Anything unrecognised — a future token, a hand-written value, the
    ``not_determined`` default — answers False. New enrolment sources are
    therefore inert until someone deliberately adds them here.
    """
    return basis in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES


# ``window_stats_basis`` — neither token ever means "measured and incomplete";
# that is expressed by a count at or above the cap that gated it.
WINDOW_STATS_CONTINUOUS = "continuous_from_first_indexed_block"
WINDOW_STATS_UNMEASURED_LEGACY = "unmeasured_legacy"
WINDOW_STATS_NOT_DETERMINED = CURSOR_BASIS_NOT_DETERMINED


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
    # Lower bound of the range this cursor's logs cover, and what proves it.
    # ``backfill_complete`` is an UPPER-bound flag only; nothing here bounds the
    # range from below, so absence of a log below ``first_indexed_block`` is
    # proven only when the basis is ``creation_block_minus_one`` — which requires
    # all three pinned reads of ``_witness_seed_block`` to agree. NULL/NULL means
    # the row predates these columns (lower bound unknown); a populated block with
    # basis ``explicit_seed`` is a seed a caller supplied, NOT a witness; basis
    # ``not_determined`` means the witness was attempted and failed, and the block
    # is NULL because a number no consumer may cite is a number no consumer should
    # see.
    first_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    first_indexed_block_basis: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # How this cursor came to exist, and — through the ALLOW-LIST
    # ``enrollment_basis_permits_exactness`` — whether it may ever support an
    # exact empty. ``predicate_tree_hint`` = a static ``enumeration_hint`` named
    # this (chain, address, topic0) as a writer of a specific storage variable;
    # eligible. NULL = predates the column; eligible, because those rows folded
    # before it existed. Everything else is INELIGIBLE, including
    # ``tracked_topics_asserted`` (minted from a tracking plan, which names topics
    # an emitter CAN emit and attributes them to no variable), the literal
    # ``not_determined`` that ``enroll_event_cursor`` stores when a caller omits
    # the argument, and any token added later. Read at the ``_cursor_state`` choke
    # point in ``services/resolution/repos/event_logs_pg.py`` and by the two
    # out-of-band cursor readers (``_authority_has_role_store_cursor``,
    # ``_authority_backfilled``).
    enrollment_basis: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Largest ``eth_getLogs`` page this cursor has ever accepted, the result cap
    # in force when those pages were fetched, and whether the record is continuous
    # from ``first_indexed_block``. A page returned at the cap may have been
    # truncated by the upstream, so "no such log exists" is proven only when every
    # window came back strictly under a cap that was actually enforced. All three
    # are NULL on rows whose windows predate the columns.
    max_window_log_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    window_stats_cap: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    window_stats_basis: Mapped[str | None] = mapped_column(String(48), nullable=True)


def exactness_eligible_cursor_clause():
    """SQL form of :func:`enrollment_basis_permits_exactness`, for the readers
    that ask "does a usable cursor exist" without loading the row.

    Derived from the same frozenset the Python predicate reads, so the two
    cannot drift into disagreeing about which rows may support an exact empty.
    """
    non_null = sorted(b for b in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES if b is not None)
    clauses = []
    if None in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES:
        clauses.append(IndexedEventCursor.enrollment_basis.is_(None))
    if non_null:
        clauses.append(IndexedEventCursor.enrollment_basis.in_(non_null))
    return or_(*clauses)


# ``role_holder_planes`` vocabulary. Each token names the evidence that put the
# row in that state; there is no token meaning "we looked and there is nobody".
HOLDERS_BASIS_PINNED_HAS_ROLE = "pinned_has_role_confirmed"
HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED = "not_determined"
ROLE_COVERAGE_LOWER_BOUND = "lower_bound"
ROLE_COVERAGE_PARTIAL = "partial"
ROLE_NAME_BASIS_KECCAK = "keccak_preimage"
ROLE_NAME_BASIS_AC_DEFAULT_ADMIN = "accesscontrol_default_admin_literal"
ROLE_NAME_BASIS_NOT_DETERMINED = "not_determined"

# ``role_holder_plane_refreshes`` outcomes. Both mean a pass RAN against a
# registry whose gate was open; they differ only in whether the fold proposed
# anything. A registry whose gate was closed gets no row at all — see the model.
ROLE_REFRESH_OUTCOME_NO_ROWS = "no_rows"
ROLE_REFRESH_OUTCOME_ROWS_WRITTEN = "rows_written"

# "No holder set was published", as SQL. A bare ``holders IS NULL`` is NOT this:
# a JSONB column also accepts the jsonb scalar ``null``, which is what a write of
# a Python None stores unless the column says otherwise, and which every SQL null
# test reads as a present payload. Both spellings must count as withheld or the
# constraints below stop discriminating exactly where it matters. Enforced from
# the other side too, by ``holders_is_array_or_absent``, so the two can't drift.
HOLDERS_WITHHELD_SQL = "(holders IS NULL OR jsonb_typeof(holders) = 'null')"
# The same two spellings for the disagreement log. It travels with ``holders``:
# on a withheld row nothing was read, or what was read is not published, so
# "no disagreement was observed" is not_determined rather than an empty list.
DISAGREEMENTS_WITHHELD_SQL = "(fold_chain_disagreements IS NULL OR jsonb_typeof(fold_chain_disagreements) = 'null')"


class RoleHolderPlane(Base):
    """Who a ``(chain_id, registry_address, role_hash)`` is PROVEN to include.

    ``holders`` is a **lower bound**, never a membership set. Every member was
    independently confirmed by a pinned ``hasRole(bytes32,address)`` read at
    ``as_of_block`` — the event fold only proposed the candidates, and a fold
    that is arbitrarily wrong still yields a true lower bound because no member
    rests on it. What the fold's incompleteness costs is completeness, and that
    is published separately and permanently as ``holder_set_exhaustive``.

    The gate travels in the same ROW as the payload. A child holders table was
    rejected for exactly this reason: it would expose addresses to a reader that
    never joined back to the qualifier, and it would make the empty-set check
    below inexpressible.

    Four states a naive schema conflates, kept apart here:

    * a proven lower bound — ``holders`` non-empty, ``holders_basis`` the pinned
      arm, ``as_of_block`` set;
    * every candidate's read completed and confirmed nobody;
    * every candidate's read reverted or failed in transport;
    * the recording surface was cold, so no candidate was even enumerable.

    The last three all publish ``holders = NULL`` and are **deliberately
    indistinguishable at row level**. Telling them apart would reconstruct the
    banned empty set: "N probed, every read completed, none confirmed" is ``[]``
    written in three columns. So the residual counters, which qualify a
    published lower bound, are NULL whenever there is no lower bound to qualify.
    """

    __tablename__ = "role_holder_planes"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    registry_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    # The 32-byte role identity, and the ONLY identity. A name is decoration
    # attached downstream and never keys anything. Rows are minted solely from
    # the OZ AccessControl ``RoleGranted``/``RoleRevoked`` topic pair, so every
    # hash in this column lives in one identity space; Solady's ``RoleSet``
    # carries a ``uint256`` role in a different space and mints no row here.
    role_hash: Mapped[str] = mapped_column(String(66), primary_key=True)
    # NULL means not_determined. It never means "nobody holds this role", and
    # an empty array — which a reader could mistake for that — cannot be stored.
    # ``none_as_null`` is load-bearing: JSONB's default is to store Python None
    # as the JSON literal ``'null'``, which is NOT SQL NULL. Every biconditional
    # below would then read the withheld row as if it carried a holder set, and
    # the checks that make the empty set unrepresentable would not fire.
    holders: Mapped[list[str] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    holders_basis: Mapped[str] = mapped_column(String(48), nullable=False)
    # Pinned to ``not_determined`` by CHECK. 0 of the 4 role registries in the
    # corpus implement the AccessControlEnumerable getter, so under B14 an
    # exhaustiveness arm has population 0 and may not be built. This is a
    # DEFERRAL WITH CAUSE, not a permanent impossibility: a registry that
    # implements ``getRoleMemberCount``/``getRoleMember``, or a proven inverse
    # index over the recording surface, would each license a real value here.
    # A future unit must revisit the constraint deliberately rather than assume
    # it was derived from something weaker.
    holder_set_exhaustive: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED
    )
    # The block every read in ``holders`` was pinned at, plus that block's hash.
    # A membership fact is mutable, so it is meaningless without its height; the
    # hash is what makes the height replayable across a reorg.
    as_of_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    as_of_block_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    # The cursor bounds, copied from ``indexed_event_cursors`` so the candidate
    # source's coverage is legible without a join. The LOWER bound is citable
    # only where U10A witnessed it (basis ``creation_block_minus_one``); an
    # ``explicit_seed`` is a caller's number, not evidence, and lands here as
    # NULL + not_determined.
    cursor_first_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cursor_first_indexed_block_basis: Mapped[str] = mapped_column(String(32), nullable=False)
    cursor_last_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cursor_enrollment_bases: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    cursor_page_completeness: Mapped[str] = mapped_column(String(16), nullable=False)
    coverage: Mapped[str] = mapped_column(String(16), nullable=False)
    # NULL means the key is absent — no preimage was proven. It never means the
    # role is unnamed. ``keccak_preimage`` is a total mathematical fact about
    # the hash, independent of which contract offered the candidate string.
    role_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role_name_basis: Mapped[str] = mapped_column(String(48), nullable=False)
    # How many addresses the fold proposed, and how many of those could not be
    # read at all. Both NULL exactly when ``holders`` is NULL (see class doc).
    candidate_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    unconfirmed_candidate_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Where the fold and the chain read disagreed, recorded and NEVER diagnosed.
    # ``as_of_block`` sits above the cursor head, so a disagreement cannot be
    # attributed between "the fold missed a log" and "the state changed after
    # the cursor stopped". Permitted keys are fixed by the writer; no key
    # naming a cause may be added.
    #
    # NULL exactly when ``holders`` is, and for the same reason the counters are:
    # an empty list asserts "we looked and found none", which on a withheld row
    # is either untrue (an all-reverting registry read nothing to compare) or
    # suppression (an all-false registry DID observe disagreements). Publishing
    # ``[]`` there would be an unearned negative one column over from the empty
    # set the constraints below make unrepresentable. On a PUBLISHED row ``[]``
    # is earned, and its scope is the candidates whose reads completed —
    # ``unconfirmed_candidate_count`` carries the rest.
    fold_chain_disagreements: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        # The two hard bans, enforced where code cannot route around them.
        # NOT NULL on every discriminator is load-bearing for these: a CHECK
        # that evaluates to NULL PASSES in Postgres, so a nullable column would
        # make each of them satisfiable by omission.
        # ``holders`` is a withheld marker or an array — never a jsonb string,
        # number or object, which would satisfy a naive "is it set?" read while
        # naming no addresses at all.
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} OR jsonb_typeof(holders) = 'array'",
            name="ck_role_holder_planes_holders_is_array_or_absent",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} OR jsonb_array_length(holders) > 0",
            name="ck_role_holder_planes_no_empty_set",
        ),
        CheckConstraint(
            "holder_set_exhaustive = 'not_determined'",
            name="ck_role_holder_planes_never_exhaustive",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (holders_basis = 'not_determined')",
            name="ck_role_holder_planes_basis_matches_holders",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (as_of_block IS NULL)",
            name="ck_role_holder_planes_block_matches_holders",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (candidate_count IS NULL)",
            name="ck_role_holder_planes_candidates_match_holders",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (unconfirmed_candidate_count IS NULL)",
            name="ck_role_holder_planes_unconfirmed_match_holders",
        ),
        CheckConstraint(
            f"NOT {HOLDERS_WITHHELD_SQL} OR coverage = 'partial'",
            name="ck_role_holder_planes_null_holders_are_partial",
        ),
        # The disagreement log travels with the holder set: withheld together,
        # published together. Without this a withheld row could carry ``[]`` —
        # "we looked and found none" over reads that either never happened or
        # are not being published.
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = {DISAGREEMENTS_WITHHELD_SQL}",
            name="ck_role_holder_planes_disagreements_match_holders",
        ),
        CheckConstraint(
            f"{DISAGREEMENTS_WITHHELD_SQL} OR jsonb_typeof(fold_chain_disagreements) = 'array'",
            name="ck_role_holder_planes_disagreements_are_array_or_absent",
        ),
        # A witnessed lower bound and its basis are one fact. Split, the row can
        # claim a height it cannot cite, or discard a height it proved.
        CheckConstraint(
            "(cursor_first_indexed_block IS NULL) = (cursor_first_indexed_block_basis = 'not_determined')",
            name="ck_role_holder_planes_lower_bound_matches_basis",
        ),
        # ``explicit_seed`` is deliberately NOT in the stored domain: the writer
        # normalises a seed to NULL + not_determined, because a number a caller
        # supplied is not a witness and must not be storable as one.
        CheckConstraint(
            "cursor_first_indexed_block_basis IN ('creation_block_minus_one', 'not_determined')",
            name="ck_role_holder_planes_lower_bound_basis_domain",
        ),
        CheckConstraint(
            "cursor_page_completeness IN ('complete', 'incomplete', 'not_determined')",
            name="ck_role_holder_planes_page_completeness_domain",
        ),
        CheckConstraint(
            "(role_name IS NULL) = (role_name_basis = 'not_determined')",
            name="ck_role_holder_planes_name_matches_basis",
        ),
        CheckConstraint(
            "holders_basis IN ('pinned_has_role_confirmed', 'not_determined')",
            name="ck_role_holder_planes_holders_basis_domain",
        ),
        CheckConstraint(
            "coverage IN ('lower_bound', 'partial')",
            name="ck_role_holder_planes_coverage_domain",
        ),
        CheckConstraint(
            "role_name_basis IN ('keccak_preimage', 'accesscontrol_default_admin_literal', 'not_determined')",
            name="ck_role_holder_planes_name_basis_domain",
        ),
    )


class RoleHolderPlaneRefresh(Base):
    """When ``(chain_id, registry_address)`` was last folded, and what came of it.

    The plane above is keyed by ROLE, so it cannot answer a question about the
    REGISTRY: a registry whose fold proposed no candidate writes no row there,
    and row-absence in a per-role table is indistinguishable from a registry
    nothing ever ran against. That ambiguity is what this table removes, in
    exactly three states:

    * **never refreshed** — no row here. The registry is due.
    * **refreshed, confirmed nothing** — a row with ``outcome = 'no_rows'``.
      The pass ran; the fold proposed nothing at ``trigger_log_block``. It is
      NOT due again until one of the recorded observations below changes.
    * **refreshed, wrote N** — a row with ``outcome = 'rows_written'`` and
      ``rows_written = N``.

    A row is written only where the AccessControl cursor pair EXISTS. A closed
    gate leaves the registry rowless — "never refreshed" — so it re-selects by
    itself the moment the indexer finishes enrolling it, with no timer to expire
    and no flag to clear.

    The three stored observations are what make the not-due state safe rather
    than a freeze. ``trigger_log_block`` is the highest AccessControl log block
    the registry had indexed at the pass (NULL = none had been), so a later
    grant or revoke re-selects it. ``cursors_warm`` is the pair's
    ``backfill_complete`` conjunction, so a registry folded against a cold
    surface re-selects when the surface goes warm even if no new log lands.
    ``refreshed_at`` bounds the age of the floors themselves, which are
    time-varying facts about deployed state and go stale on their own.

    Nothing here records WHY a floor was withheld, and that is deliberate: the
    plane makes an all-reverting registry and an all-false one indistinguishable
    on purpose, so a refresh trigger that told them apart would reconstruct the
    distinction the plane refuses to publish.
    """

    __tablename__ = "role_holder_plane_refreshes"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    registry_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # NULL means no AccessControl log was indexed for this registry at the pass.
    # An observation of the index, never a claim that none were emitted.
    trigger_log_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cursors_warm: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rows_written: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "outcome IN ('no_rows', 'rows_written')",
            name="ck_role_holder_plane_refreshes_outcome_domain",
        ),
        # The count and the token are one fact. Split, a pass could record
        # "confirmed nothing" over rows it wrote, which would stop the registry
        # re-selecting on the evidence that it does have roles to track.
        CheckConstraint(
            "(outcome = 'rows_written') = (rows_written > 0)",
            name="ck_role_holder_plane_refreshes_outcome_matches_count",
        ),
        CheckConstraint(
            "rows_written >= 0",
            name="ck_role_holder_plane_refreshes_count_non_negative",
        ),
    )


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
    """Dirty-flag queue driving the enrollment reconciler.

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
    # Who established this row and from what: ``{produced_by, source_job_id,
    # materialized_at}`` (see ``db.contract_materializations.build_provenance``).
    # NULL is a row written before the column existed — no provenance was
    # recorded, which is not the same as a producer we happen to assume.
    provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
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
    ``status`` field to decide whether to act on partial data. That
    promise is only kept while every status the enumerator can emit fits
    ``status``: an oversized one turns the upsert into a no-op that
    leaves whatever row was already there, so a stale ``complete`` would
    keep being served in place of the honest truncated verdict. The
    column is sized well past the longest current member and
    ``tests/test_mapping_enumeration_status_vocabulary.py`` round-trips
    the whole vocabulary to keep it that way.
    """

    __tablename__ = "mapping_enumeration_cache"

    chain: Mapped[str] = mapped_column(String(100), primary_key=True)
    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    specs_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    principals: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
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
    """Persistent, cross-job behavioral-verdict cache. Shared across jobs AND
    cross-chain twins — the 11 ``PausableUntil`` sharers are separate jobs, so a
    sibling (or a twin on another chain, or a prior run) that already witnessed
    a behavior yields a free, *trusted* hit.

    Two verdict scopes:

    - ``scope='kernel'`` — function-local (latch-flip, gate-mutation, code-
      change, supply-delta sign, destination *shape*). Key = (``behavior_hash``,
      ``effect_class``); ``contract_surface_hash`` is the empty sentinel.
    - ``scope='projection'`` — contract-scoped (pause blast radius, authorization
      delta). Keyed additionally on ``contract_surface_hash`` (the metadata-
      stripped whole-contract bytecode hash) because the same mixin kernel
      yields different blast radii on different surfaces.

    The row is **code-plane only**: no concrete values ever enter the key.
    Verdicts are **gate-relative**: ``gate_ref`` names the gate *structure*,
    never a concrete address; principal binding happens at read
    time by joining ``function_principals``. The concrete state-plane residue
    (destination address, exact impl, current-check result) lives in
    ``effect_verdicts``, never here.

    ``transcript_ptr`` is an artifact-store key, never an inline JSONB blob.
    ``analysis_schema_version`` invalidates the row on a pipeline bump,
    mirroring ``ContractMaterialization``.

    Self-audit: the first time two functions share a behavioral hash, both
    are simulated once and the *kernel* verdicts asserted equal before the cache
    is trusted; ``audit_status`` / ``audit_peer_hash`` / ``audited_at`` record
    that, and ``hit_count`` supports the optional every-Nth re-audit.

    **This table is written on READ, and five of its columns are therefore NOT part of
    its replay identity**: ``hit_count``, ``audit_status``, ``audit_peer_hash``,
    ``audited_at``, ``updated_at`` (the authoritative list is
    ``db.effect_cache.REPLAY_IDENTITY_EXCLUDED_COLUMNS``, which explains why each is
    excluded). ``bump_hit`` / ``mark_audited`` run from the hit path, so two identical
    pipeline runs over an unchanged chain leave DIFFERENT values in them — the guarantees
    that recomputation is byte-identical and that re-analysis without an on-chain change
    is a no-op hold for this table only modulo those five. ``hit_count`` counts times the
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
    # Gate *structure* descriptor — never an address.
    gate_ref: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    tier: Mapped[str] = mapped_column(String(20), nullable=False)
    # Artifact-store key — never inline JSONB.
    transcript_ptr: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Small, code-plane structural witness (e.g. supply-delta sign, source-read
    # duration bound). NO concrete/state-plane values.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    analysis_schema_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    # Self-audit bookkeeping.
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
    """Per contract-function **state-plane** residue from effect simulation.
    This is where the per-deployment concrete values live — the exact
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
    # The state-plane residue with no column of its own: downstream value
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


class FunctionScoreSignal(Base):
    """One (function, capability) signal — the Layer-1 surface the grade folds over.

    Distilled at the end of the effects stage from one job's planes, and it
    **references rather than resolves**: principal ids and value entity keys, no
    resolved principal types, no dollar amounts, no weakness. Cross-contract
    resolution (principal units, MAX per (entity, asset), subsumption) belongs to
    the fold because only the fold sees the whole protocol — a signal that
    pre-resolved any of them would double-count the moment a second contract
    reached the same entity.

    A CURRENT-STATE plane with contract-scoped wholesale replace — NOT an
    insert-only per-job one. Re-analysis mints a NEW job
    (``maybe_queue_reanalysis`` → ``create_job``) and completed jobs are never
    deleted, so a job-scoped delete could never remove the previous job's rows:
    every re-analysis would add a second full signal set for the same contract
    and the fold would double-count it — the precise bug Layer 2 exists to
    prevent. The distiller therefore delete+reinserts all of a contract's
    signals in one transaction, the same currency pattern
    ``effective_functions`` uses, and the fold reads current rows with no
    job-currency filtering.

    Identity is ``(chain, deployment_address, contract_id, selector,
    claim_id)``. ``contract_id`` is IN the key because split-proxy secondary
    implementations share one ``deployment_address`` — live on this corpus —
    so without it two legitimately distinct contracts collide on the same
    selector. ``job_id`` is provenance only and never identity.

    ``contract_id`` is CASCADE: a contract dropped from the perimeter must stop
    charging exposure, and a signal outliving its contract would keep a finding
    alive against something no longer analysed.

    Every three-state fact is a PAIR — a NOT NULL ``*_state`` discriminator from
    a closed vocabulary containing ``not_determined``, plus a nullable payload
    that is non-NULL only in a proven state, tied by a named CHECK. No
    discriminator carries a server default: an INSERT that omits one must raise
    rather than silently record ``not_determined``, because a default is exactly
    how an unread witness becomes a published fact.

    ``function_id`` is SET NULL, not CASCADE, for the same reason
    ``effect_verdicts.function_id`` is: ``effective_functions`` is
    delete+reinserted per contract, so a concurrent policy pass would otherwise
    destroy signals it never disagreed with. The identity above is what survives
    that, which is why uniqueness keys on the selector and not the function id.
    """

    __tablename__ = "function_score_signals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Provenance only — which job's distillation last wrote this row. SET NULL,
    # because a pruned job must not delete signals that are still current, and
    # never part of the identity: keying on it is what would let a re-analysis
    # accumulate a second signal set instead of replacing the first.
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    # Denormalised rather than joined through ``jobs``: ``jobs.protocol_id`` is
    # nullable and SET NULL, and signals silently orphaned by that NULL would be
    # dropped from the fold's population without a trace. NOT NULL here means a
    # signal that cannot be attributed to a protocol is never written at all.
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    # Chain NAME, matching ``contracts.chain`` and the ``<chain>::<address>``
    # entity-key token the value references use. Per-(chain, address) units, no
    # cross-chain collapse: the same address on two chains is two units.
    chain: Mapped[str] = mapped_column(String(100), nullable=False)
    deployment_address: Mapped[str] = mapped_column(String(42), nullable=False)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    function_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("effective_functions.id", ondelete="SET NULL"), nullable=True
    )
    selector: Mapped[str] = mapped_column(String(10), nullable=False, server_default=NO_SELECTOR)
    function_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # The capability this signal is about: an ``effective_functions.claims[]``
    # ``claim_id``. Not an enum column — the claims registry is the vocabulary
    # owner, and pinning a copy here would silently drop a claim the registry
    # gains before this schema does.
    claim_id: Mapped[str] = mapped_column(String(64), nullable=False)
    witness_tier: Mapped[str] = mapped_column(String(32), nullable=False)

    severity_state: Mapped[str] = mapped_column(String(24), nullable=False)
    severity_proven: Mapped[float | None] = mapped_column(Numeric(6, 4), nullable=True)
    # The sorted ``sev_reason`` list. An enum + payload vocabulary, not a closed
    # enum (``keyset_independent:6>=4``, ``constrained:hash_commitment+pins``),
    # so it is stored as text and never constrained to a member list.
    severity_basis: Mapped[list[str]] = mapped_column(ARRAY(String(128)), nullable=False)

    authority_openness: Mapped[str] = mapped_column(String(24), nullable=False)
    principal_state: Mapped[str] = mapped_column(String(24), nullable=False)
    # ``[{"function_principal_id": int, "chain": str, "address": str}, ...]``.
    # Both the id and the natural key are carried: the id is the pinned
    # reference, the (chain, address) pair is what still identifies the
    # principal after ``effective_functions`` is delete+reinserted and the id is
    # gone. Nothing resolved travels here — no type, no owner set, no threshold.
    principal_refs: Mapped[Any] = mapped_column(JSONB(none_as_null=True), nullable=False)

    value_state: Mapped[str] = mapped_column(String(24), nullable=False)
    value_bound: Mapped[str] = mapped_column(String(24), nullable=False)
    # ``<chain>::<address>`` tokens, the same shape as
    # ``services.aggregations.company_overview._entity_key``. Chain-scoped so the
    # #158 twin-aliasing class cannot re-enter through the scorer.
    value_entity_keys: Mapped[list[str]] = mapped_column(ARRAY(String(160)), nullable=False)
    # Names WHY the value state is what it is, including for the undetermined
    # arms (``observed_reach_floor_absent(not_determined)``). Required in every
    # state so a not_determined always carries its reason.
    value_basis: Mapped[str] = mapped_column(String(160), nullable=False)

    destination_state: Mapped[str] = mapped_column(String(24), nullable=False)
    destination_shape: Mapped[str | None] = mapped_column(String(48), nullable=True)
    reach_gate_state: Mapped[str] = mapped_column(String(24), nullable=False)

    # Per-capability gate inputs that have no column of their own (freeze ladder
    # inputs, amount/asset lattice, timelock delay, latch witness). Structured,
    # and every three-state fact inside repeats the column convention as
    # ``{"<field>": {"state": ..., "value": ...}}`` so a JSONB key's absence is
    # never the thing that carries a state.
    gate_inputs: Mapped[Any] = mapped_column(JSONB(none_as_null=True), nullable=False)
    citations: Mapped[Any] = mapped_column(JSONB(none_as_null=True), nullable=False)
    witness_notes: Mapped[list[str]] = mapped_column(ARRAY(String(255)), nullable=False)
    effect_verdict_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("effect_verdicts.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "chain",
            "deployment_address",
            "contract_id",
            "selector",
            "claim_id",
            name="uq_function_score_signals_identity",
        ),
        Index("ix_fss_protocol_id", "protocol_id"),
        Index("ix_fss_contract_id", "contract_id"),
        Index("ix_fss_job_id", "job_id"),
        Index("ix_fss_function_id", "function_id"),
        Index("ix_fss_entity", "chain", "deployment_address"),
        CheckConstraint(
            f"severity_state IN {_sql_tuple(SEVERITY_STATES)}",
            name="ck_fss_severity_state",
        ),
        # The pairing invariant, in both directions. Without the reverse arm a
        # not_determined row could still carry a severity, which is the defect
        # class the discriminator exists to close.
        CheckConstraint(
            f"(severity_state = '{SEVERITY_STATE_PROVEN}') = (severity_proven IS NOT NULL)",
            name="ck_fss_severity_pairing",
        ),
        CheckConstraint(
            f"witness_tier IN {_sql_tuple(WITNESS_TIERS)}",
            name="ck_fss_witness_tier",
        ),
        CheckConstraint(
            f"authority_openness IN {_sql_tuple(OPENNESS_STATES)}",
            name="ck_fss_authority_openness",
        ),
        CheckConstraint(
            f"principal_state IN {_sql_tuple(PRINCIPAL_STATES)}",
            name="ck_fss_principal_state",
        ),
        # Unconditional: without it a non-enumerated row could carry references
        # as a JSON object, which the pairing check below would not see (it
        # tests array length) and a reader unpacking the blob would still find.
        CheckConstraint(
            "jsonb_typeof(principal_refs) = 'array'",
            name="ck_fss_principal_refs_array",
        ),
        # Only the enumerated arm may carry references, and it must carry some:
        # an empty ``enumerated`` list would be the banned empty caller set
        # published as a proven one.
        # The ``jsonb_typeof`` guard is not redundant with the check above:
        # ``jsonb_array_length`` ERRORS on a non-array, and CHECK evaluation
        # order is not guaranteed, so without it a smuggled object surfaces as a
        # DataError from this constraint instead of a clean violation of the one
        # that actually describes the problem.
        CheckConstraint(
            f"(principal_state = '{PRINCIPAL_STATE_ENUMERATED}') = "
            "(jsonb_typeof(principal_refs) = 'array' AND jsonb_array_length(principal_refs) > 0)",
            name="ck_fss_principal_pairing",
        ),
        CheckConstraint(
            f"value_state IN {_sql_tuple(VALUE_STATES)}",
            name="ck_fss_value_state",
        ),
        CheckConstraint(
            f"value_bound IN {_sql_tuple(VALUE_BOUNDS)}",
            name="ck_fss_value_bound",
        ),
        # Entity keys exist exactly on the proven-reach arm. ``proven_no_reach``
        # is an earned negative and must be empty; ``not_determined`` must not
        # smuggle a partial set that a reader could total.
        CheckConstraint(
            f"(value_state = '{VALUE_STATE_PROVEN_REACH}') = (array_length(value_entity_keys, 1) IS NOT NULL)",
            name="ck_fss_value_pairing",
        ),
        # A NULL element is an entity the fold cannot key, so MAX-per-entity
        # would silently drop or merge it. The ``<chain>::<address>`` FORMAT is
        # validated in ``services.scoring.schema`` — a CHECK cannot quantify over
        # array elements without a subquery.
        CheckConstraint(
            "array_position(value_entity_keys, NULL) IS NULL",
            name="ck_fss_value_entity_keys_no_nulls",
        ),
        # A bound is a property of a proven reach; there is nothing to bound
        # otherwise, and an ``exact`` on an unproven reach would read as a set.
        CheckConstraint(
            f"value_state = '{VALUE_STATE_PROVEN_REACH}' OR value_bound = '{VALUE_BOUND_NOT_DETERMINED}'",
            name="ck_fss_value_bound_pairing",
        ),
        CheckConstraint(
            f"destination_state IN {_sql_tuple(DESTINATION_STATES)}",
            name="ck_fss_destination_state",
        ),
        # Biconditional: exactly one state (``not_determined``) means "unread",
        # and it is the only one without a shape. ``not_applicable`` carries the
        # shape ``not_applicable`` rather than a NULL, so "no destination exists"
        # and "the destination was not read" can never present alike.
        CheckConstraint(
            f"(destination_state <> '{DESTINATION_STATE_NOT_DETERMINED}') = (destination_shape IS NOT NULL)",
            name="ck_fss_destination_pairing",
        ),
        # A capability whose behaviour HAS a destination can never claim there is
        # none. Without this, an unread delegatecall destination could be written
        # as ``not_applicable`` and skip the escalation entirely — the prototype's
        # −30λ false positive arriving through the schema instead of the fold.
        CheckConstraint(
            f"destination_state <> '{DESTINATION_STATE_NOT_APPLICABLE}' "
            f"OR claim_id NOT IN {_sql_tuple(DESTINATION_BEARING_CLAIMS)}",
            name="ck_fss_destination_not_applicable_claims",
        ),
        CheckConstraint(
            f"reach_gate_state IN {_sql_tuple(REACH_GATE_STATES)}",
            name="ck_fss_reach_gate_state",
        ),
        # A proven severity has to name what proved it. An empty basis with a
        # number is a severity with no witness behind it.
        CheckConstraint(
            f"severity_state <> '{SEVERITY_STATE_PROVEN}' OR array_length(severity_basis, 1) IS NOT NULL",
            name="ck_fss_severity_basis_present",
        ),
    )


class ProtocolScore(Base):
    """One computed grade for one protocol at one instant. Insert-only.

    History is the point: insert-only gives the Activity timeline the score's
    movement for free, and a re-fold never destroys the row a consumer already
    read. ``protocol_scores_latest`` is the read surface.

    The document is inline JSONB, spilling to a MinIO ``storage_key`` only above
    ~1 MB. Exactly one of the two is ever set, enforced below, so a reader can
    never be handed a row with both a stale inline copy and a spill.
    """

    __tablename__ = "protocol_scores"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    trigger: Mapped[str] = mapped_column(String(32), nullable=False)
    # The job whose completion triggered this fold, when one did. SET NULL: a
    # pruned job must not delete the score it caused.
    trigger_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )

    grade_state: Mapped[str] = mapped_column(String(24), nullable=False)
    grade_lambda: Mapped[float | None] = mapped_column(Numeric(12, 4), nullable=True)
    grade_exposure: Mapped[float | None] = mapped_column(Numeric(24, 2), nullable=True)
    confidence_pct: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    perimeter_state: Mapped[str] = mapped_column(String(24), nullable=False)

    findings: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Per-plane row counts + max ``updated_at``, plus the ``selection_summary`` /
    # ``perimeter_spawn_summary`` ledger references, so a score is
    # replayable-in-principle and its coverage is auditable after the fact.
    provenance: Mapped[Any] = mapped_column(JSONB(none_as_null=True), nullable=False)
    # The constant block the grade was computed under, stored per row rather than
    # read from code: a score compared against a later one must be comparable
    # against the constants it actually used, and recalibration is then a data
    # change. Carries the uncalibrated-arm flags (strategy §7.2).
    model_parameters: Mapped[Any] = mapped_column(JSONB(none_as_null=True), nullable=False)

    __table_args__ = (
        Index("ix_protocol_scores_protocol_computed", "protocol_id", "computed_at", "id"),
        CheckConstraint(
            f"grade_state IN {_sql_tuple(GRADE_STATES)}",
            name="ck_protocol_scores_grade_state",
        ),
        CheckConstraint(
            f"(grade_state = '{GRADE_STATE_COMPUTED}') = "
            "(grade_lambda IS NOT NULL AND grade_exposure IS NOT NULL AND confidence_pct IS NOT NULL)",
            name="ck_protocol_scores_grade_pairing",
        ),
        CheckConstraint(
            f"perimeter_state IN {_sql_tuple(PERIMETER_STATES)}",
            name="ck_protocol_scores_perimeter_state",
        ),
        CheckConstraint(
            f"trigger IN {_sql_tuple(SCORE_TRIGGERS)}",
            name="ck_protocol_scores_trigger",
        ),
        # ``jsonb_typeof(findings) IS NOT NULL`` rather than
        # ``findings IS NOT NULL``: identical truth value (``jsonb_typeof``
        # returns SQL NULL only for a SQL-NULL column, and the string
        # ``'null'`` — which is NOT NULL — for the jsonb scalar null), but the
        # raw shape is banned repo-wide because everywhere ELSE it silently
        # counts written-nulls as payload. Spelling the discriminator keeps this
        # column out of the exception the reader would otherwise have to know.
        CheckConstraint(
            "(jsonb_typeof(findings) IS NOT NULL) <> (storage_key IS NOT NULL)",
            name="ck_protocol_scores_document_exactly_one",
        ),
    )


class ProtocolScoreLatest(Base):
    """READ-ONLY mapping of the ``protocol_scores_latest`` VIEW.

    The newest row per protocol, and nothing else — a pure projection of
    ``protocol_scores``, same columns, a subset of the rows, never a join that
    can multiply. Needed because the writer is insert-only, so a naive reader
    would see every historical score.

    **This DIVERGES from ``contract_balances_latest``, deliberately.** There, a
    failed fetch never wins, because a failure is the absence of an observation
    and letting it win would republish "holds nothing" out of a read that
    observed nothing. Here there is no equivalent of a failed fetch: a
    ``not_determined`` grade is a COMPUTED VERDICT — the fold ran, over a real
    population, and concluded the grade could not be determined. Suppressing it
    in favour of the last computed grade would republish a stale number as the
    protocol's current standing, which is the more dangerous direction. So the
    newest row wins unconditionally, ``grade_state`` is not filtered, and the
    consumer is expected to read ``grade_state`` rather than assume a grade.

    The fold owes the provenance block the distinction this view cannot make:
    "no population" (nothing to score) versus "population scored to nothing".
    Both arrive here as ``not_determined``.

    Not autogenerate-visible: :func:`include_object` filters it on the
    ``info={"is_view": True}`` marker below.
    """

    __tablename__ = "protocol_scores_latest"
    __table_args__ = {"info": {"is_view": True}}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    protocol_id: Mapped[int] = mapped_column(Integer)
    model_version: Mapped[str] = mapped_column(String(32))
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    trigger: Mapped[str] = mapped_column(String(32))
    trigger_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    grade_state: Mapped[str] = mapped_column(String(24))
    grade_lambda: Mapped[float | None] = mapped_column(Numeric(12, 4))
    grade_exposure: Mapped[float | None] = mapped_column(Numeric(24, 2))
    confidence_pct: Mapped[float | None] = mapped_column(Numeric(5, 2))
    perimeter_state: Mapped[str] = mapped_column(String(24))
    findings: Mapped[Any | None] = mapped_column(JSONB)
    storage_key: Mapped[str | None] = mapped_column(String(512))
    provenance: Mapped[Any] = mapped_column(JSONB)
    model_parameters: Mapped[Any] = mapped_column(JSONB)


class ProtocolScoreQueue(Base):
    """Dirty-flag queue driving the protocol-score fold, one row per protocol.

    Same shape as ``monitoring_enrollment_queue`` and for the same reason: the
    grade is a whole-protocol fold that cannot be accumulated per contract, so
    every write site that changes a scored input enqueues the protocol and the
    score loop re-folds it once. Marking is an upsert that bumps ``dirty_at``,
    so N marks between two passes cost one fold, not N.

    No lease columns, unlike the enrollment queue: that queue's drainer runs a
    minutes-long governance build worth protecting from a competing drainer,
    while a fold is seconds and insert-only — two concurrent folds of the same
    protocol write two history rows and the newest wins, which is a duplicate
    row rather than a corruption.

    ``dirty_at`` is the ordering cursor AND the clearing token: the loop deletes
    the row only when ``dirty_at`` still EQUALS the value it selected, so a mark
    that arrives mid-fold — which bumps ``dirty_at`` — survives instead of being
    cleared by a fold that never saw the change it describes. Equality rather
    than a ``<=`` against a read instant because ``now()`` is
    ``transaction_timestamp()``: the effects stage runs as one long transaction,
    so its mark is stamped minutes before its data is visible and any
    instant-based comparison would clear a mark for data the fold never read.

    ``attempts`` / ``last_failed_at`` are the poison guard. Marks are retained
    on failure (an unscored protocol must re-select), and dirty rows sort first,
    so without a backoff a handful of permanently-failing protocols would
    consume every pass forever and the staleness sweep — the only cover for the
    invalidation events that carry no mark — would never run again.
    """

    __tablename__ = "protocol_score_queue"

    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), primary_key=True)
    dirty_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TokenDeliveryEvidence(Base):
    """How one (chain, token, holder) balance ARRIVED, from the chain's receipts.

    A delivery-shape plane, deliberately separate from every balance table. Two
    reasons, both measured rather than assumed:

    * ``contract_balances`` rows are EVICTED — retention depth 10 plus
      ``ON DELETE CASCADE`` on the fetch — so an annotation carried there is
      gone within ~10 producer cycles and the evidence would have to be
      re-measured every time. A delivering transaction is block-stamped and
      immutable; it outlives every fetch that ever observed the holding.
    * a (holder, token) pair is a fact about two ADDRESSES. It is not owned by
      the protocol whose producer happened to measure it, and nothing here is
      protocol-scoped.

    **The EVIDENCE accretes.** ``delivery_count`` and ``unreadable_deliveries``
    only rise, ``min_fan_out`` only falls, ``measured_through_block`` only
    advances, and ``scanned_from_block`` is written once at insert and never
    again. So the set the all-quantifier ranges over only ever grows: a later
    cycle can withdraw a positive, and can never manufacture one.
    ``has_direct_delivery`` never turns back into ``fan_out_all`` — that verdict
    is an earned negative and it is settled.

    **``basis`` is the exception, and it is re-derived on every pass** — never
    carried, never appended to. It is composed from ``scanned_from_block`` and
    ``measured_through_block`` as they stand on this row
    (``delivery_evidence.compose_basis``), so the extent it names is the union of
    every pass rather than the window of the last one. A pass that finds nothing
    new still rewrites it; that costs no chain request and is how a row authored
    under an older rule is repaired.

    **``deliveries`` is a bounded SAMPLE, not the record.** The scalars above are
    the record and they count every delivery ever seen; the JSONB retains
    ``delivery_evidence.DELIVERY_ENTRIES_RETAINED`` entries, chosen so whichever
    delivery decides the verdict is in it. A pair too heavy to meter stores a
    compact marker — the sample plus the count of the rest, all declared
    unmetered — rather than one entry per delivery.

    ``measured_through_block`` is BOTH the extent of the claim and the cursor
    that keeps this a once-per-pair cost: the all-quantifier is over deliveries
    from ``scanned_from_block`` through it, and a consumer must read the pair to
    know what the verdict covers. Without the cursor the one-shot repeats hourly.
    It is also what makes the bounded sample safe: a later pass resumes strictly
    above it, so a delivery at or below it is already counted and needs no stored
    entry to be recognised as a repeat.

    **The extent MAY LAG the chain head, and the row is the claim's extent.** A
    range-capped chain is scanned a slice per cycle, so a row can be written from
    a window that stopped short of the tip; ``caught_up`` is what says so, and a
    consumer reads the verdict over ``scanned_from_block..measured_through_block``
    and never over "up to now". A pair that was only sliced must never read as a
    pair that was scanned to the head and found nothing.

    The published claim is delivery SHAPE and nothing else — see
    ``utils.balance_status.DELIVERY_SHAPES``. It never says a token is worthless.
    Every fan-out on this row is a count of same-token transfer LOGS, an upper
    bound on distinct recipients.
    """

    __tablename__ = "token_delivery_evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    # Lowercased at the write point. The holder is the address the recipient
    # topic filter was built from — the account the read was issued against,
    # never a canonical/folded entity key: two accounts of one plane entity are
    # two holders here, and folding them would publish one account's evidence
    # over the other's.
    holder_address: Mapped[str] = mapped_column(String(42), nullable=False)
    token_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # The block range the delivery set is an all-quantifier OVER. ``from`` is the
    # holder's creation block where it was obtainable and 0 otherwise; anything
    # else would claim completeness over blocks nobody scanned.
    scanned_from_block: Mapped[int] = mapped_column(BigInteger, nullable=False)
    measured_through_block: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # ``[{tx, block, log_index, fan_out, fan_out_basis}]`` — a BOUNDED sample of
    # the delivering transactions, each carrying the count of same-token transfer
    # LOGS measured from that transaction's own receipt. ``fan_out`` is null
    # exactly where ``fan_out_basis`` is ``receipt_unreadable``, which forces the
    # verdict to ``not_determined``: an unread receipt is not a small fan-out.
    # The counts below, not this list, are the record.
    deliveries: Mapped[list] = mapped_column(JSONB(none_as_null=True), nullable=False)
    # Every delivery ever seen for the pair, sample or not.
    delivery_count: Mapped[int] = mapped_column(Integer, nullable=False)
    unreadable_deliveries: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # The weakest delivery on record, which is what the all-quantifier turns on.
    # NULL where any delivery is unreadable or none is on record.
    min_fan_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The threshold this verdict was decided under, stored per row rather than
    # read from today's constant: K is a published model parameter and a row
    # measured under one K must not be re-read under another.
    fan_out_threshold_k: Mapped[int] = mapped_column(Integer, nullable=False)
    delivery_shape: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=DELIVERY_SHAPE_NOT_DETERMINED
    )
    # The holder's raw balance of this token as the cycle that last SCANNED the
    # pair read it. It is a SKIP key and never evidence: an unmoved balance is
    # what lets the next cycle leave the extent where it is, because a new
    # delivery necessarily moves it. NULL is not "unchanged" — it is a pair
    # nobody stamped, and it is scanned.
    observed_balance_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    # False when the pass that wrote the row stopped at a slice boundary below
    # the chain head. Such a row is scanned forward every cycle whatever its
    # balance does, because the balance argument for skipping only holds over
    # blocks that were already read — and its ``fan_out_all`` is NOT dispositive
    # while it stands (``delivery_evidence.DeliveryFact.is_airdrop_only``): the
    # verdict is true of the slice, and the blocks above it are where a
    # settlement would refute it. A settled ``has_direct_delivery`` written at a
    # partial extent keeps this false forever — catch-up short-circuits on the
    # earned negative — which is why only the POSITIVE is gated on it.
    caught_up: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    # The sentence the published claim derives its scope from — the filter, the
    # block range, the request counts — never re-authored downstream.
    basis: Mapped[str] = mapped_column(Text, nullable=False)
    first_measured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("chain_id", "holder_address", "token_address", name="uq_tde_chain_holder_token"),
        Index("ix_tde_chain_token", "chain_id", "token_address"),
        Index("ix_tde_chain_holder", "chain_id", "holder_address"),
        # The positive verdict is an all-quantifier, so it cannot stand beside a
        # delivery nobody could read, and it cannot stand over an empty set: a
        # holding whose arrival is not on record is not_determined, never
        # airdrop-delivered.
        CheckConstraint(
            f"delivery_shape <> '{DELIVERY_SHAPE_FAN_OUT_ALL}' OR "
            "(unreadable_deliveries = 0 AND delivery_count > 0 AND min_fan_out >= fan_out_threshold_k)",
            name="ck_tde_fan_out_all_is_earned",
        ),
        # The earned negative needs a delivery that actually read BELOW K; a
        # missing measurement must not be laundered into a negative either.
        CheckConstraint(
            f"delivery_shape <> '{DELIVERY_SHAPE_HAS_DIRECT_DELIVERY}' OR "
            "(delivery_count > 0 AND min_fan_out IS NOT NULL AND min_fan_out < fan_out_threshold_k)",
            name="ck_tde_direct_delivery_is_measured",
        ),
        CheckConstraint(
            "delivery_shape IN ('"
            + "', '".join(
                (DELIVERY_SHAPE_FAN_OUT_ALL, DELIVERY_SHAPE_HAS_DIRECT_DELIVERY, DELIVERY_SHAPE_NOT_DETERMINED)
            )
            + "')",
            name="ck_tde_delivery_shape_vocabulary",
        ),
        CheckConstraint("jsonb_typeof(deliveries) = 'array'", name="ck_tde_deliveries_is_array"),
        CheckConstraint("measured_through_block >= scanned_from_block", name="ck_tde_range_is_ordered"),
    )


class TokenProtocolReference(Base):
    """Whether a token address is one THIS protocol's own discovery names.

    Written by the producers' disposition phase against
    ``services.scoring.distill.load_protocol_universe``, and read by the
    presentation layer, which cannot build the universe itself: that assembly is
    a measured 26.5-second object-storage read, unusable on an API path. The
    verdict is stored here so a surface can consult it in one indexed lookup.

    **THIS TABLE IS REFRESHED EVERY CYCLE. IT IS NOT IMMUTABLE, AND THAT IS THE
    POINT** — the exact opposite discipline from ``TokenDeliveryEvidence``, whose
    evidence accretes and is never taken back. The predicate behind
    ``absent_from_universe`` is ANTI-MONOTONE: discovery growing can only turn an
    absence into a presence, so a verdict taken against a smaller universe must be
    able to WITHDRAW. A row here is the answer as of ``measured_at`` against a
    universe of ``universe_addresses`` addresses, and a later cycle overwrites it.
    Read the two tables with that contrast in mind; assuming this one accretes
    would pin a condemnation that discovery has already dissolved.

    **Absence of a row reads as ``not_determined`` at every consumer**, which is
    to say the holding is presented. Nothing may be pulled from a sheet because
    no verdict was stored for it.
    """

    __tablename__ = "token_protocol_reference"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Protocol-scoped, unlike delivery evidence: "the protocol refers to this
    # address" is a claim about one protocol's discovery and about nothing else.
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    # Lowercased at the write point, as everywhere else in the balance planes.
    token_address: Mapped[str] = mapped_column(String(42), nullable=False)
    reference_shape: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=TOKEN_REFERENCE_NOT_DETERMINED
    )
    # The size of the universe the verdict was taken against. A withdrawal is
    # readable as a number here growing, so a reader can tell "discovery found
    # it" from "the predicate changed" without re-running either.
    universe_addresses: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    basis: Mapped[str] = mapped_column(Text, nullable=False)
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("protocol_id", "chain_id", "token_address", name="uq_tpr_protocol_chain_token"),
        Index("ix_tpr_protocol_chain", "protocol_id", "chain_id"),
        CheckConstraint(
            "reference_shape IN ('" + "', '".join(TOKEN_REFERENCE_SHAPES) + "')",
            name="ck_tpr_reference_shape_vocabulary",
        ),
        # A universe of no addresses cannot witness an absence — it would condemn
        # everything. The fail-closed answer under an unbuildable universe is
        # ``not_determined``, and the constraint keeps that from being edited away.
        CheckConstraint(
            f"reference_shape <> '{TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE}' OR universe_addresses > 0",
            name="ck_tpr_absence_needs_a_universe",
        ),
    )


load_dotenv(Path(__file__).resolve().parents[1] / ".env")

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://psat:psat@localhost:5433/psat")

# Env-tunable per process group; deploy/start_workers.sh tightens to 2+3 per worker so 10 procs
# × 5 conns stays under Neon's pool ceiling. pool_recycle=300s protects against Neon's ~5-min
# idle-disconnect.
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
