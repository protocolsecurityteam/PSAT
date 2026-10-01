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
    address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # Chain identity, derived from ``request["chain"]`` and dual-written. Required for address-scoped jobs
    # by CHECK; reads still use ``request["chain"]`` until the M0.2 Item-2 flip.
    chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True, default=_job_chain_id_insert_default)
    company: Mapped[str | None] = mapped_column(String, nullable=True)
    name: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), nullable=False, default=JobStatus.queued)
    stage: Mapped[JobStage] = mapped_column(Enum(JobStage), nullable=False, default=JobStage.discovery)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    request: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # Correlation id shared with the originating request and child jobs, to join HTTP and worker logs.
    trace_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    is_proxy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    # Completed attempts, bumped by ``requeue_job`` on each transient failure; persisted so workers agree.
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # ``claim_job`` skips the row until then (exponential backoff via ``compute_next_attempt``).
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failure_kind: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Per-claim lease minted by ``claim_job``, extended by ``_heartbeat``; the stale sweep keys on it. Every mutating
    # queue write filters on ``lease_id`` so a worker whose lease moved can't corrupt the row.
    lease_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Hash of the verified source set plus analyzer version, letting ``find_completed_static_cache`` reuse a job's
    # code-plane analysis for the same source at a new (chain, address). Written only when a job fetches its own source;
    # NULL rows are never donors.
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
        # Partial index for the lease-expiry sweep.
        Index(
            "ix_jobs_lease_expires_at",
            "lease_expires_at",
            postgresql_where=text("status = 'processing'"),
        ),
        # For the M0.2 Item-2 dedup lookups on ``(lower(address), chain_id)``.
        Index("ix_jobs_lower_address_chain_id", text("lower(address)"), "chain_id"),
        Index("ix_jobs_source_content_hash", "source_content_hash"),
        # Address-scoped jobs need a chain_id.
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
    """Durable edge ``A depends on B``, gating A's claim until B reaches ``required_stage``.

    Inserted by the resolution worker when A's trees reference a state-variable-resolved external address. ``claim_job``
    skips A while any pending row exists; ``_satisfy_dependencies`` marks rows ``satisfied`` or, if B terminally fails,
    ``degraded`` (dependents fall back to ``external_check_only``).
    """

    __tablename__ = "job_dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    depender_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    # Mirrors ``Job.request['chain']``; NULL for legacy/mainnet rows.
    provider_chain: Mapped[str | None] = mapped_column(String(50), nullable=True)
    provider_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # Uses ``JobStage`` enum order.
    required_stage: Mapped[JobStage] = mapped_column(Enum(JobStage), nullable=False)
    # ``pending`` (gate blocks A), ``satisfied``, ``degraded`` (provider failed terminally), ``cycle_degraded`` (the
    # edge would close a cycle; non-blocking for liveness).
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", server_default="pending")
    # For ``cycle_degraded``, the closing dependency chain (for debugging).
    cycle_path: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    satisfied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # Re-runs insert duplicates as no-ops via ON CONFLICT DO NOTHING.
        UniqueConstraint(
            "depender_job_id",
            "provider_chain",
            "provider_address",
            "required_stage",
            name="uq_job_dep_edge",
        ),
        # For the satisfy-on-advance scan.
        Index(
            "ix_job_dep_provider",
            "provider_chain",
            "provider_address",
            "required_stage",
            "status",
        ),
        # Partial index for the claim gate's NOT EXISTS.
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
    # Legacy inline storage; new writes leave NULL.
    data: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    text_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Size of the object in the bucket, not of anything in this row.
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
