"""Job queue, job dependencies, artifacts, and source files."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from schemas.api_responses import JobDict

from .base import Base, JobStage, JobStatus, _job_chain_id_insert_default


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    compute_target: Mapped[str] = mapped_column(String, nullable=False, default="cloud", server_default="cloud")
    compute_group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
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
        CheckConstraint("compute_target IN ('cloud', 'local')", name="ck_jobs_compute_target"),
        Index("ix_jobs_compute_claim", "compute_target", "stage", "status", "created_at"),
        Index("ix_jobs_compute_group_id", "compute_group_id"),
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
            "compute_target": self.compute_target,
            "compute_group_id": str(self.compute_group_id),
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
