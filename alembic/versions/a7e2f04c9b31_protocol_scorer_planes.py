"""Protocol scorer planes: per-function signals, insert-only scores, latest view.

Two planes and a read surface, written before the fold so everything keys off a
fixed shape.

``function_score_signals`` is the Layer-1 surface between per-function
distillation (end of the effects stage) and the whole-protocol grade fold. Its
defining property is that it REFERENCES and does not RESOLVE: principal ids and
``<chain>::<address>`` entity keys, never resolved principal types, weakness, or
dollar amounts. The fold owns cross-contract resolution — principal units, MAX
per (entity, asset), subsumption — because only the fold sees every finding that
touches an entity, and a signal that pre-resolved any of them would double-count
the moment a second contract reached the same place.

It is a CURRENT-STATE plane, contract-scoped, replaced wholesale by the
distiller in one transaction — the ``effective_functions`` currency pattern, not
an insert-only per-job one. Re-analysis mints a NEW job and completed jobs are
never deleted, so a job-scoped delete could never remove the prior job's rows:
every re-analysis would leave a second full signal set behind and the fold would
double-count it. Identity is ``(chain, deployment_address, contract_id,
selector, claim_id)``; ``contract_id`` is in the key because split-proxy
secondary implementations share one ``deployment_address`` on the live corpus.
``job_id`` is provenance only.

``protocol_scores`` is insert-only, so a re-fold never destroys a row a consumer
already read and score history comes for free. ``protocol_scores_latest`` is the
read surface, needed for exactly the reason ``contract_balances_latest`` is:
with an insert-only writer, a naive reader sees every historical row. It
deliberately DIVERGES from that view on which row wins — see the model
docstring; a not-determined grade is a computed verdict, not a failed fetch.

Every three-state fact in both tables is stored as a PAIR — a NOT NULL
``*_state`` discriminator from a closed vocabulary that always contains
``not_determined``, plus a nullable payload non-NULL only in a proven state,
tied by a named CHECK. No discriminator carries a server default. That is the
load-bearing part: a DEFAULT would let an INSERT that never determined the fact
record ``not_determined`` silently, and a NOT NULL with no default makes the
same INSERT raise instead. SQL NULL alone never encodes a state anywhere here.

The vocabularies are imported from ``utils.scoring_status`` rather than spelled
again, so the constraint text and the writer cannot drift apart.

Revision ID: a7e2f04c9b31
Revises: f4d18a7c0b93
Create Date: 2026-08-01
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
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

revision: str = "a7e2f04c9b31"
down_revision: Union[str, Sequence[str], None] = "f4d18a7c0b93"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _in(values: tuple[str, ...]) -> str:
    return "(" + ", ".join(f"'{value}'" for value in values) + ")"


# Newest row per protocol, and a ``not_determined`` grade wins if it is newest.
# Filtering to the newest COMPUTED row instead would republish a stale grade as
# the current one — the absence-reads-as-a-fact defect at the read surface. The
# honest answer to "what is the grade now" is the latest fold's verdict,
# including when that verdict is that it could not be determined.
#
# Tie-break on ``id`` after ``computed_at``: two folds inside one clock tick are
# reachable on the dirty-mark path, and without it the view would be
# nondeterministic between them.
_LATEST_VIEW = """
CREATE VIEW protocol_scores_latest AS
SELECT ps.id, ps.protocol_id, ps.model_version, ps.computed_at, ps.trigger,
       ps.trigger_job_id, ps.grade_state, ps.grade_lambda, ps.grade_exposure,
       ps.confidence_pct, ps.perimeter_state, ps.findings, ps.storage_key,
       ps.provenance, ps.model_parameters
FROM protocol_scores ps
WHERE ps.id = (
        SELECT p2.id FROM protocol_scores p2
        WHERE p2.protocol_id = ps.protocol_id
        ORDER BY p2.computed_at DESC, p2.id DESC
        LIMIT 1)
"""


def upgrade() -> None:
    op.create_table(
        "function_score_signals",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        # Provenance only, never identity: keying on it is what would let a
        # re-analysis (which mints a NEW job) accumulate a second signal set
        # instead of replacing the first.
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=True),
        # Denormalised rather than joined through ``jobs``: ``jobs.protocol_id``
        # is nullable and SET NULL, and a signal silently orphaned by that NULL
        # would drop out of the fold's population without a trace.
        sa.Column("protocol_id", sa.Integer(), nullable=False),
        # Chain NAME, matching ``contracts.chain`` and the ``<chain>::<address>``
        # entity-key token the value references use.
        sa.Column("chain", sa.String(length=100), nullable=False),
        sa.Column("deployment_address", sa.String(length=42), nullable=False),
        sa.Column("contract_id", sa.Integer(), nullable=False),
        sa.Column("function_id", sa.Integer(), nullable=True),
        sa.Column("selector", sa.String(length=10), nullable=False, server_default=NO_SELECTOR),
        sa.Column("function_name", sa.String(length=255), nullable=False),
        sa.Column("claim_id", sa.String(length=64), nullable=False),
        sa.Column("witness_tier", sa.String(length=32), nullable=False),
        sa.Column("severity_state", sa.String(length=24), nullable=False),
        sa.Column("severity_proven", sa.Numeric(6, 4), nullable=True),
        sa.Column("severity_basis", postgresql.ARRAY(sa.String(length=128)), nullable=False),
        sa.Column("authority_openness", sa.String(length=24), nullable=False),
        sa.Column("principal_state", sa.String(length=24), nullable=False),
        sa.Column("principal_refs", postgresql.JSONB(none_as_null=True), nullable=False),
        sa.Column("value_state", sa.String(length=24), nullable=False),
        sa.Column("value_bound", sa.String(length=24), nullable=False),
        sa.Column("value_entity_keys", postgresql.ARRAY(sa.String(length=160)), nullable=False),
        sa.Column("value_basis", sa.String(length=160), nullable=False),
        sa.Column("destination_state", sa.String(length=24), nullable=False),
        sa.Column("destination_shape", sa.String(length=48), nullable=True),
        sa.Column("reach_gate_state", sa.String(length=24), nullable=False),
        sa.Column("gate_inputs", postgresql.JSONB(none_as_null=True), nullable=False),
        sa.Column("citations", postgresql.JSONB(none_as_null=True), nullable=False),
        sa.Column("witness_notes", postgresql.ARRAY(sa.String(length=255)), nullable=False),
        sa.Column("effect_verdict_id", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["protocol_id"], ["protocols.id"], ondelete="CASCADE"),
        # CASCADE: a contract dropped from the perimeter must stop charging
        # exposure, not outlive its own analysis as a live finding.
        sa.ForeignKeyConstraint(["contract_id"], ["contracts.id"], ondelete="CASCADE"),
        # SET NULL for the same reason ``effect_verdicts.function_id`` is:
        # ``effective_functions`` is delete+reinserted per contract, so CASCADE
        # would let a concurrent policy pass destroy signals it never disagreed
        # with. ``(chain, deployment_address, selector)`` is the identity that
        # survives it, which is why uniqueness keys on the selector.
        sa.ForeignKeyConstraint(["function_id"], ["effective_functions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["effect_verdict_id"], ["effect_verdicts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        # ``contract_id`` is IN the key because split-proxy secondary
        # implementations share one ``deployment_address`` on the live corpus,
        # so without it two distinct contracts collide on the same selector.
        sa.UniqueConstraint(
            "chain",
            "deployment_address",
            "contract_id",
            "selector",
            "claim_id",
            name="uq_function_score_signals_identity",
        ),
        sa.CheckConstraint(f"severity_state IN {_in(SEVERITY_STATES)}", name="ck_fss_severity_state"),
        # Both directions. Without the reverse arm a not_determined row could
        # still carry a severity, which is the conflation the discriminator
        # exists to close.
        sa.CheckConstraint(
            f"(severity_state = '{SEVERITY_STATE_PROVEN}') = (severity_proven IS NOT NULL)",
            name="ck_fss_severity_pairing",
        ),
        sa.CheckConstraint(f"witness_tier IN {_in(WITNESS_TIERS)}", name="ck_fss_witness_tier"),
        sa.CheckConstraint(f"authority_openness IN {_in(OPENNESS_STATES)}", name="ck_fss_authority_openness"),
        sa.CheckConstraint(f"principal_state IN {_in(PRINCIPAL_STATES)}", name="ck_fss_principal_state"),
        # An empty ``enumerated`` list would be the banned empty caller set
        # published as a proven one.
        # Unconditional: without it a non-enumerated row could carry references
        # as a JSON object, invisible to a length test but not to a reader.
        sa.CheckConstraint("jsonb_typeof(principal_refs) = 'array'", name="ck_fss_principal_refs_array"),
        # The ``jsonb_typeof`` guard is not redundant with the check above:
        # ``jsonb_array_length`` ERRORS on a non-array and CHECK evaluation order
        # is not guaranteed, so without it a smuggled object surfaces as a
        # DataError here instead of violating the constraint that names the problem.
        sa.CheckConstraint(
            f"(principal_state = '{PRINCIPAL_STATE_ENUMERATED}') = "
            "(jsonb_typeof(principal_refs) = 'array' AND jsonb_array_length(principal_refs) > 0)",
            name="ck_fss_principal_pairing",
        ),
        sa.CheckConstraint(f"value_state IN {_in(VALUE_STATES)}", name="ck_fss_value_state"),
        sa.CheckConstraint(f"value_bound IN {_in(VALUE_BOUNDS)}", name="ck_fss_value_bound"),
        # ``proven_no_reach`` is an earned negative and must be empty;
        # ``not_determined`` must not smuggle a partial set a reader could total.
        sa.CheckConstraint(
            f"(value_state = '{VALUE_STATE_PROVEN_REACH}') = (array_length(value_entity_keys, 1) IS NOT NULL)",
            name="ck_fss_value_pairing",
        ),
        sa.CheckConstraint(
            f"value_state = '{VALUE_STATE_PROVEN_REACH}' OR value_bound = '{VALUE_BOUND_NOT_DETERMINED}'",
            name="ck_fss_value_bound_pairing",
        ),
        # A NULL element is an entity the fold cannot key. The
        # ``<chain>::<address>`` FORMAT is validated in services.scoring.schema —
        # a CHECK cannot quantify over array elements without a subquery.
        sa.CheckConstraint(
            "array_position(value_entity_keys, NULL) IS NULL",
            name="ck_fss_value_entity_keys_no_nulls",
        ),
        sa.CheckConstraint(f"destination_state IN {_in(DESTINATION_STATES)}", name="ck_fss_destination_state"),
        # Biconditional: ``not_determined`` is the only state without a shape,
        # so "no destination exists" (``not_applicable``, which carries its own
        # shape token) can never present like "the destination was not read".
        sa.CheckConstraint(
            f"(destination_state <> '{DESTINATION_STATE_NOT_DETERMINED}') = (destination_shape IS NOT NULL)",
            name="ck_fss_destination_pairing",
        ),
        # A capability whose behaviour HAS a destination can never claim there is
        # none — otherwise an unread delegatecall destination could be written as
        # ``not_applicable`` and skip the escalation entirely.
        sa.CheckConstraint(
            f"destination_state <> '{DESTINATION_STATE_NOT_APPLICABLE}' "
            f"OR claim_id NOT IN {_in(DESTINATION_BEARING_CLAIMS)}",
            name="ck_fss_destination_not_applicable_claims",
        ),
        sa.CheckConstraint(f"reach_gate_state IN {_in(REACH_GATE_STATES)}", name="ck_fss_reach_gate_state"),
        # A severity with an empty basis is a number with no witness behind it.
        sa.CheckConstraint(
            f"severity_state <> '{SEVERITY_STATE_PROVEN}' OR array_length(severity_basis, 1) IS NOT NULL",
            name="ck_fss_severity_basis_present",
        ),
    )
    op.create_index("ix_fss_protocol_id", "function_score_signals", ["protocol_id"])
    op.create_index("ix_fss_contract_id", "function_score_signals", ["contract_id"])
    op.create_index("ix_fss_job_id", "function_score_signals", ["job_id"])
    op.create_index("ix_fss_function_id", "function_score_signals", ["function_id"])
    op.create_index("ix_fss_entity", "function_score_signals", ["chain", "deployment_address"])

    op.create_table(
        "protocol_scores",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("protocol_id", sa.Integer(), nullable=False),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=False),
        sa.Column("trigger_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("grade_state", sa.String(length=24), nullable=False),
        sa.Column("grade_lambda", sa.Numeric(12, 4), nullable=True),
        sa.Column("grade_exposure", sa.Numeric(24, 2), nullable=True),
        sa.Column("confidence_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("perimeter_state", sa.String(length=24), nullable=False),
        sa.Column("findings", postgresql.JSONB(none_as_null=True), nullable=True),
        sa.Column("storage_key", sa.String(length=512), nullable=True),
        sa.Column("provenance", postgresql.JSONB(none_as_null=True), nullable=False),
        # Stored per row, not read from code: comparing two scores is only
        # meaningful against the constants each actually used, and recalibration
        # then becomes a data change.
        sa.Column("model_parameters", postgresql.JSONB(none_as_null=True), nullable=False),
        sa.ForeignKeyConstraint(["protocol_id"], ["protocols.id"], ondelete="CASCADE"),
        # A pruned job must not delete the score it caused.
        sa.ForeignKeyConstraint(["trigger_job_id"], ["jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(f"grade_state IN {_in(GRADE_STATES)}", name="ck_protocol_scores_grade_state"),
        sa.CheckConstraint(
            f"(grade_state = '{GRADE_STATE_COMPUTED}') = "
            "(grade_lambda IS NOT NULL AND grade_exposure IS NOT NULL AND confidence_pct IS NOT NULL)",
            name="ck_protocol_scores_grade_pairing",
        ),
        sa.CheckConstraint(f"perimeter_state IN {_in(PERIMETER_STATES)}", name="ck_protocol_scores_perimeter_state"),
        sa.CheckConstraint(f"trigger IN {_in(SCORE_TRIGGERS)}", name="ck_protocol_scores_trigger"),
        # Never both: a reader must not be handed a stale inline copy alongside
        # a spill, and never neither. ``jsonb_typeof(findings) IS NOT NULL`` is
        # the same truth value as ``findings IS NOT NULL`` — ``jsonb_typeof``
        # yields SQL NULL only for a SQL-NULL column — spelled the way the
        # repo-wide jsonb discipline requires, so no reader has to hold this
        # column as the one place the banned shape was still fine.
        sa.CheckConstraint(
            "(jsonb_typeof(findings) IS NOT NULL) <> (storage_key IS NOT NULL)",
            name="ck_protocol_scores_document_exactly_one",
        ),
    )
    op.create_index("ix_protocol_scores_protocol_computed", "protocol_scores", ["protocol_id", "computed_at", "id"])

    op.execute(_LATEST_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS protocol_scores_latest")
    op.drop_index("ix_protocol_scores_protocol_computed", table_name="protocol_scores")
    op.drop_table("protocol_scores")
    op.drop_index("ix_fss_entity", table_name="function_score_signals")
    op.drop_index("ix_fss_function_id", table_name="function_score_signals")
    op.drop_index("ix_fss_job_id", table_name="function_score_signals")
    op.drop_index("ix_fss_contract_id", table_name="function_score_signals")
    op.drop_index("ix_fss_protocol_id", table_name="function_score_signals")
    op.drop_table("function_score_signals")
