"""Scoring planes: function score signals and protocol scores."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

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

from .base import Base, _sql_tuple


class FunctionScoreSignal(Base):
    """One (function, capability) signal, the Layer-1 surface the grade folds over.

    References rather than resolves (principal ids and entity keys; no types, dollars or weakness), since cross-contract
    resolution belongs to the fold.

    A current-state plane replaced wholesale per contract, not per job: re-analysis mints new jobs and old jobs aren't
    deleted, so a job-scoped delete would double-count. The fold reads current rows with no job filter.

    Identity is ``(chain, deployment_address, contract_id, selector, claim_id)``; ``contract_id`` is included because
    split-proxy implementations share a deployment address. ``job_id`` is provenance. ``contract_id`` cascades (dropped
    contracts stop charging). ``function_id`` is SET NULL like ``effect_verdicts.function_id``, since
    ``effective_functions`` is delete+reinserted.

    Every three-state fact is a NOT NULL ``*_state`` plus a nullable payload tied by a CHECK. No server defaults, so an
    omitted state raises.
    """

    __tablename__ = "function_score_signals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Provenance only; SET NULL so pruning a job keeps current signals.
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    # Denormalized because ``jobs.protocol_id`` is nullable and SET NULL; unattributable signals are never written.
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    # Chain name, matching ``contracts.chain`` and the entity-key token; no cross-chain collapse.
    chain: Mapped[str] = mapped_column(String(100), nullable=False)
    deployment_address: Mapped[str] = mapped_column(String(42), nullable=False)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    function_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("effective_functions.id", ondelete="SET NULL"), nullable=True
    )
    selector: Mapped[str] = mapped_column(String(10), nullable=False, server_default=NO_SELECTOR)
    function_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # A ``claims[]`` ``claim_id``; not an enum, since the registry owns the vocabulary.
    claim_id: Mapped[str] = mapped_column(String(64), nullable=False)
    witness_tier: Mapped[str] = mapped_column(String(32), nullable=False)

    severity_state: Mapped[str] = mapped_column(String(24), nullable=False)
    severity_proven: Mapped[float | None] = mapped_column(Numeric(6, 4), nullable=True)
    # Sorted ``sev_reason`` list with payloads, so free text.
    severity_basis: Mapped[list[str]] = mapped_column(ARRAY(String(128)), nullable=False)

    authority_openness: Mapped[str] = mapped_column(String(24), nullable=False)
    principal_state: Mapped[str] = mapped_column(String(24), nullable=False)
    # ``[{"function_principal_id": int, "chain": str, "address": str}, ...]``: the id plus the natural key that survives
    # delete+reinsert. Nothing resolved.
    principal_refs: Mapped[Any] = mapped_column(JSONB(none_as_null=True), nullable=False)

    value_state: Mapped[str] = mapped_column(String(24), nullable=False)
    value_bound: Mapped[str] = mapped_column(String(24), nullable=False)
    # ``<chain>::<address>`` tokens (as ``services.aggregations.company_overview._entity_key``), chain-scoped against
    # #158 aliasing.
    value_entity_keys: Mapped[list[str]] = mapped_column(ARRAY(String(160)), nullable=False)
    # Why the value state is what it is, required in every state.
    value_basis: Mapped[str] = mapped_column(String(160), nullable=False)

    destination_state: Mapped[str] = mapped_column(String(24), nullable=False)
    destination_shape: Mapped[str | None] = mapped_column(String(48), nullable=True)
    reach_gate_state: Mapped[str] = mapped_column(String(24), nullable=False)

    # Per-capability inputs without their own column. Three-state facts use ``{"<field>": {"state": ..., "value":
    # ...}}`` so key absence never carries state.
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
        # Pairing in both directions, so a not_determined row can't carry a severity.
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
        # Unconditional, so a non-enumerated row can't smuggle references as an object.
        CheckConstraint(
            "jsonb_typeof(principal_refs) = 'array'",
            name="ck_fss_principal_refs_array",
        ),
        # Only enumerated carries references, and it must carry some (an empty enumerated list is the banned empty
        # caller set). The ``jsonb_typeof`` guard avoids a DataError from ``jsonb_array_length`` on non-arrays.
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
        # Entity keys only on proven reach; ``proven_no_reach`` must be empty and ``not_determined`` can't carry a
        # partial set.
        CheckConstraint(
            f"(value_state = '{VALUE_STATE_PROVEN_REACH}') = (array_length(value_entity_keys, 1) IS NOT NULL)",
            name="ck_fss_value_pairing",
        ),
        # A NULL element can't be keyed. Format is validated in ``services.scoring.schema``.
        CheckConstraint(
            "array_position(value_entity_keys, NULL) IS NULL",
            name="ck_fss_value_entity_keys_no_nulls",
        ),
        # A bound only exists for a proven reach.
        CheckConstraint(
            f"value_state = '{VALUE_STATE_PROVEN_REACH}' OR value_bound = '{VALUE_BOUND_NOT_DETERMINED}'",
            name="ck_fss_value_bound_pairing",
        ),
        CheckConstraint(
            f"destination_state IN {_sql_tuple(DESTINATION_STATES)}",
            name="ck_fss_destination_state",
        ),
        # Only ``not_determined`` lacks a shape; ``not_applicable`` has one, so "no destination" and "unread" never look
        # alike.
        CheckConstraint(
            f"(destination_state <> '{DESTINATION_STATE_NOT_DETERMINED}') = (destination_shape IS NOT NULL)",
            name="ck_fss_destination_pairing",
        ),
        # A destination-bearing capability can't claim no destination, or an unread delegatecall destination would skip
        # escalation.
        CheckConstraint(
            f"destination_state <> '{DESTINATION_STATE_NOT_APPLICABLE}' "
            f"OR claim_id NOT IN {_sql_tuple(DESTINATION_BEARING_CLAIMS)}",
            name="ck_fss_destination_not_applicable_claims",
        ),
        CheckConstraint(
            f"reach_gate_state IN {_sql_tuple(REACH_GATE_STATES)}",
            name="ck_fss_reach_gate_state",
        ),
        # A proven severity must name what proved it.
        CheckConstraint(
            f"severity_state <> '{SEVERITY_STATE_PROVEN}' OR array_length(severity_basis, 1) IS NOT NULL",
            name="ck_fss_severity_basis_present",
        ),
    )


class ProtocolScore(Base):
    """One computed grade for one protocol at one instant.

    Insert-only, giving history for free; ``protocol_scores_latest`` is the read surface. The document is inline JSONB,
    spilling to ``storage_key`` above ~1 MB; exactly one is set.
    """

    __tablename__ = "protocol_scores"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    trigger: Mapped[str] = mapped_column(String(32), nullable=False)
    # SET NULL: pruning a job keeps the score it caused.
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
    # Per-plane row counts, max ``updated_at``, and ledger references, for replay and coverage audits.
    provenance: Mapped[Any] = mapped_column(JSONB(none_as_null=True), nullable=False)
    # The constants the grade used, stored per row so scores stay comparable across recalibration; includes
    # uncalibrated-arm flags (strategy §7.2).
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
        # Same truth value as ``IS NOT NULL`` here, but that spelling is banned repo-wide because elsewhere it counts
        # jsonb ``null`` as payload.
        CheckConstraint(
            "(jsonb_typeof(findings) IS NOT NULL) <> (storage_key IS NOT NULL)",
            name="ck_protocol_scores_document_exactly_one",
        ),
    )


class ProtocolScoreLatest(Base):
    """Read-only mapping of the ``protocol_scores_latest`` view: the newest row per protocol.

    Unlike ``contract_balances_latest``, where failed fetches never win, the newest row wins unconditionally: a
    ``not_determined`` grade is a computed verdict, and hiding it would republish a stale grade. Consumers must read
    ``grade_state``. The fold's provenance distinguishes "no population" from "scored to nothing". Hidden from
    autogenerate via ``info={"is_view": True}``.
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
    """Dirty-flag queue for the protocol-score fold, one row per protocol.

    Like ``monitoring_enrollment_queue``: writers upsert and bump ``dirty_at``, so many marks cost one fold. No lease
    columns: folds are seconds long and insert-only, so a concurrent duplicate just adds a row.

    ``dirty_at`` is the order and the clearing token: the loop deletes only on equality with the selected value, since
    ``now()`` is transaction start and the effects stage is one long transaction.

    ``attempts`` / ``last_failed_at`` are the poison guard; without backoff failing protocols would starve the staleness
    sweep.
    """

    __tablename__ = "protocol_score_queue"

    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), primary_key=True)
    dirty_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
