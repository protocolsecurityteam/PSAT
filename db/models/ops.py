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
    """Persistent Etherscan response cache. Read/written by ``services/clients/etherscan.py``
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
    """Persistent eth_getCode bytecode cache. Read/written by ``services/clients/rpc.py`` via
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


class OpsKv(Base):
    """Minimal persistent key/value row for operational markers.

    Added for the membership gate's ``enabled_chains_seen`` marker (spec §3.4
    event 4): workers on boot compare the enabled-chain allowlist against the
    persisted value to detect a chain being enabled. Generic on purpose —
    the next boot-time marker gets a key, not a table.
    """

    __tablename__ = "ops_kv"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
