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
