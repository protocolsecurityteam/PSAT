"""Ops tables: heartbeats, leases, enrollment queue, caches, effect verdicts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
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
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class WorkerHeartbeat(Base):
    """Liveness and last-work summary for daemons that drain their own tables.

    Upserted each tick via ``db.queue.record_heartbeat`` so ``/api/fleet`` can tell idle from dead.
    """

    __tablename__ = "worker_heartbeats"

    process: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="running")
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    beat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class DaemonLease(Base):
    """A named, TTL'd singleton lease for a daemon pass (e.g.

    ``'protocol_scanner:ethereum'``). Unlike advisory locks it survives per-window commits and works under transaction
    pooling. See ``db.queue.try_acquire_daemon_lease``.
    """

    __tablename__ = "daemon_leases"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    holder: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class MonitoringEnrollmentQueue(Base):
    """Dirty-flag queue for the enrollment reconciler.

    Write sites call ``services.monitoring.enrollment.mark_enrollment_dirty``; ``services.monitoring.reconciler`` claims
    due rows with a lease, runs ``enroll_protocol_contracts``, and deletes the row. ``dirty_at`` is also the due time,
    pushed forward exponentially on failure.
    """

    __tablename__ = "monitoring_enrollment_queue"

    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), primary_key=True)
    dirty_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    lease_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EtherscanCache(Base):
    """Persistent Etherscan response cache, used via raw SQL by ``services/clients/etherscan.py``; modeled so
    ``alembic check`` sees it.
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
    """Cross-job materialization cache, one row per ``(chain, bytecode_keccak)``; see
    ``db.contract_materializations``.

    ``building`` means a builder is running (``builder_started_at``); ``ready`` is usable; ``failed`` is kept for triage
    but never served; ``pending`` is the legacy default.
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
    # Hash of the verified source set, chain- and address-independent, so a bundle can be reused cross-chain even when
    # immutables change the bytecode. NULL rows never match.
    source_content_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    # Read paths serve only rows matching ``ANALYSIS_SCHEMA_VERSION``.
    analysis_schema_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", server_default="pending")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    builder_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # ``{produced_by, source_job_id, materialized_at}`` (see ``build_provenance``). NULL = pre-column, not an assumed
    # producer.
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
    """Cross-process cache for mapping_enumerator HyperSync scans, one row per ``(chain, address, specs_hash)``.

    Resolution and policy stages run in separate processes and both walk the graph, so without this each re-runs the
    same slow scans. ``specs_hash`` keys spec changes to fresh rows. Truncated and errored results are cached too.

    Every status must fit ``status``, or the upsert no-ops and a stale ``complete`` keeps being served;
    ``tests/test_mapping_enumeration_status_vocabulary.py`` checks the vocabulary.
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
    """Persistent eth_getCode cache, used via raw SQL by ``services/clients/rpc.py``; no TTL.

    ``selfdestructed_at`` is reserved (writers leave NULL).
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
    """Persistent, cross-job behavioural-verdict cache, shared across jobs and cross-chain twins.

    See ``db.effect_cache``.

    ``scope='kernel'`` keys on (``behavior_hash``, ``effect_class``) with an empty surface sentinel;
    ``scope='projection'`` also keys on ``contract_surface_hash``. Code-plane only; ``gate_ref`` is structure, never an
    address; per-deployment residue lives in ``effect_verdicts``. ``transcript_ptr`` is an artifact key.

    ``hit_count``, ``audit_status``, ``audit_peer_hash``, ``audited_at`` and ``updated_at`` change on read and aren't
    part of replay identity (``db.effect_cache.REPLAY_IDENTITY_EXCLUDED_COLUMNS``).
    """

    __tablename__ = "effect_behavior_cache"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    behavior_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    effect_class: Mapped[str] = mapped_column(String(40), nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False, server_default="kernel")
    # Empty for kernel rows; a sentinel keeps the UniqueConstraint portable.
    contract_surface_hash: Mapped[str] = mapped_column(String(80), nullable=False, server_default="")
    gate_ref: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    tier: Mapped[str] = mapped_column(String(20), nullable=False)
    transcript_ptr: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Code-plane structural witness only.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    analysis_schema_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
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
    """Per contract-function state-plane residue from effect simulation: concrete destination, target impl, Tier-0
    current check. Keyed ``(chain_id, contract_address, selector, effect_class)``; empty selector for
    fallback/receive.
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
    concrete_destination: Mapped[str | None] = mapped_column(String(42), nullable=True)
    current_check_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Residue without its own column (value reach, re-probe bookkeeping). Not ``witness``, which cache hits re-publish
    # to other deployments.
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
    """ "This contract's effect candidates were planned and yielded no plans."

    Otherwise such a contract leaves no trace and selection re-sweeps it from every job. Only empty outcomes are
    recorded (plans leave verdicts). ``planned_at`` limits the marker to the current run (``JobScope.planned_since``),
    since planning inputs change.
    """

    __tablename__ = "effects_plan_markers"

    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), primary_key=True)
    # SET NULL so losing the job doesn't resurrect the re-sweep.
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    # For auditing the marker against the cascade.
    candidates_planned: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    planned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)


class OpsKv(Base):
    """Minimal key/value row for operational markers (e.g. the membership gate's ``enabled_chains_seen``, spec §3.4)."""

    __tablename__ = "ops_kv"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
