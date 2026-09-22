"""Create the immutable, table-first temporal Assessment store."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "f6a1c2d3e4b5"
down_revision = "e27a490bc381"
branch_labels = None
depends_on = None


def enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name)


SUBJECT = enum("assessment_subject_kind", "address", "code", "function", "controller", "role", "proposal", "operation")
SUBJECT_ROLE = enum(
    "assessment_subject_role", "contract", "function", "controller", "entity", "role", "proposal", "operation"
)
EVIDENCE = enum("assessment_evidence_kind", "chain_read", "chain_event", "artifact", "execution", "external")
SCOPE = enum("assessment_scope_kind", "code", "point", "interval", "scenario", "reported")
CLAIM = enum(
    "assessment_claim_kind",
    "function_effect",
    "function_authority",
    "authority_capability",
    "authority_relationship",
    "entity_classification",
    "deployment_code",
    "implementation",
    "role_membership",
    "configuration",
    "proposal_contents",
    "proposal_state",
    "proposal_timing",
    "proposal_quorum",
    "operation_state",
    "operation_timing",
    "applied_configuration",
    "dependency",
)
PRODUCER = enum(
    "assessment_analysis_producer",
    "static",
    "observation",
    "resolution",
    "policy",
    "principal",
    "execution",
    "governance",
    "scenario",
    "correction",
    "migration",
)
OUTCOME = enum("assessment_outcome", "completed", "partial", "failed")
CONTEXT = enum("assessment_context_kind", "observed", "scenario")
REFERENCE = enum("assessment_reference_kind", "evidence", "claim")
COVERAGE = enum(
    "assessment_coverage_kind",
    "code",
    "state_reads",
    "events",
    "authority",
    "effects",
    "configuration",
    "proposal_lifecycle",
    "operation_lifecycle",
    "scenario_actions",
)
COMPLETENESS = enum("assessment_coverage_completeness", "complete", "partial", "unknown")
SEVERITY = enum("assessment_diagnostic_severity", "info", "degraded", "error")
DIAGNOSTIC = enum(
    "assessment_diagnostic_code",
    "invalid_input",
    "missing_evidence",
    "unsupported_code",
    "unsupported_parameter",
    "unsupported_clock",
    "unresolved_identity",
    "unresolved_authority",
    "unresolved_target",
    "incomplete_coverage",
    "conflicting_evidence",
    "rpc_failure",
    "source_unavailable",
    "execution_failure",
    "analysis_failure",
    "scope_mismatch",
    "stale_baseline",
    "orphaned_block",
    "pipeline_diagnostic",
)
CORRECTION = enum(
    "assessment_correction_reason",
    "reorg",
    "invalid_observation",
    "wrong_subject",
    "rule_error",
    "incomplete_basis",
)
RULE = enum(
    "assessment_derivation_rule",
    "function_effect",
    "function_authority",
    "authority_capability",
    "authority_relationship",
    "entity_classification",
    "deployment_code",
    "implementation_binding",
    "role_membership",
    "configuration",
    "proposal_contents",
    "proposal_state",
    "proposal_timing",
    "proposal_quorum",
    "operation_state",
    "operation_timing",
    "applied_configuration",
    "dependency",
    "historical_interval",
    "scenario_transition",
    "imported",
)


def upgrade() -> None:
    op.create_table(
        "assessment_subjects",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("kind", SUBJECT, nullable=False),
        sa.Column("identity", postgresql.JSONB(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("kind", "identity", name="uq_assessment_subject_identity"),
    )
    op.create_table(
        "assessment_payloads",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("media_type", sa.String(120), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("byte_length", sa.BigInteger(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("byte_length >= 0", name="ck_assessment_payload_length"),
    )
    op.create_table(
        "assessment_contexts",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("kind", CONTEXT, nullable=False),
        sa.Column("context", postgresql.JSONB(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("kind", "context", name="uq_assessment_context"),
    )
    op.create_table(
        "assessment_implementations",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("producer", PRODUCER, nullable=False),
        sa.Column("manifest", postgresql.JSONB(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "assessment_evidence",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column(
            "subject_id", sa.String(80), sa.ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("kind", EVIDENCE, nullable=False),
        sa.Column(
            "payload_id", sa.String(80), sa.ForeignKey("assessment_payloads.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("source", postgresql.JSONB(), nullable=False),
        sa.Column("obtained_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=True),
        sa.Column("block_number", sa.Numeric(78, 0), nullable=True),
        sa.Column("block_hash", sa.String(66), nullable=True),
        sa.Column("transaction_hash", sa.String(66), nullable=True),
        sa.Column("transaction_index", sa.Integer(), nullable=True),
        sa.Column("log_index", sa.Integer(), nullable=True),
        sa.UniqueConstraint(
            "chain_id", "block_hash", "transaction_hash", "log_index", name="uq_assessment_chain_event_occurrence"
        ),
    )
    op.create_index(
        "ix_assessment_evidence_subject_time", "assessment_evidence", ["subject_id", "chain_id", "block_number"]
    )
    op.create_table(
        "assessment_claims",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column(
            "subject_id", sa.String(80), sa.ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("kind", CLAIM, nullable=False),
        sa.Column("proposition", postgresql.JSONB(), nullable=False),
        sa.Column("scope_kind", SCOPE, nullable=False),
        sa.Column("scope", postgresql.JSONB(), nullable=False),
        sa.Column("rule", RULE, nullable=False),
        sa.Column(
            "implementation_id",
            sa.String(80),
            sa.ForeignKey("assessment_implementations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_assessment_claim_subject_scope", "assessment_claims", ["subject_id", "scope_kind"])
    op.create_table(
        "assessment_analyses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("producer", PRODUCER, nullable=False),
        sa.Column(
            "implementation_id",
            sa.String(80),
            sa.ForeignKey("assessment_implementations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "context_id", sa.String(80), sa.ForeignKey("assessment_contexts.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("outcome", OUTCOME, nullable=False),
        sa.Column("receipt", postgresql.JSONB(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_assessment_analysis_job_time", "assessment_analyses", ["job_id", "recorded_at"])
    op.create_table(
        "assessment_analysis_outputs",
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_analyses.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "claim_id", sa.String(80), sa.ForeignKey("assessment_claims.id", ondelete="RESTRICT"), primary_key=True
        ),
    )
    op.create_table(
        "assessment_claim_evidence",
        sa.Column(
            "claim_id", sa.String(80), sa.ForeignKey("assessment_claims.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column(
            "evidence_id", sa.String(80), sa.ForeignKey("assessment_evidence.id", ondelete="RESTRICT"), primary_key=True
        ),
    )
    op.create_table(
        "assessment_claim_dependencies",
        sa.Column(
            "claim_id", sa.String(80), sa.ForeignKey("assessment_claims.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column(
            "prerequisite_claim_id",
            sa.String(80),
            sa.ForeignKey("assessment_claims.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.CheckConstraint("claim_id <> prerequisite_claim_id", name="ck_assessment_claim_not_self_dependent"),
    )
    op.create_table(
        "assessment_analysis_inputs",
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_analyses.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("input_kind", REFERENCE, primary_key=True),
        sa.Column("input_id", sa.String(80), primary_key=True),
    )
    op.create_table(
        "assessment_coverage",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "subject_id", sa.String(80), sa.ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), nullable=True
        ),
        sa.Column("kind", COVERAGE, nullable=False),
        sa.Column("scope_kind", SCOPE, nullable=False),
        sa.Column("scope", postgresql.JSONB(), nullable=False),
        sa.Column("completeness", COMPLETENESS, nullable=False),
        sa.Column("detail", postgresql.JSONB(), nullable=False),
    )
    op.create_table(
        "assessment_diagnostics",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("severity", SEVERITY, nullable=False),
        sa.Column("code", DIAGNOSTIC, nullable=False),
        sa.Column("original_code", sa.Text(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column(
            "subject_id", sa.String(80), sa.ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), nullable=True
        ),
        sa.Column("scope", postgresql.JSONB(), nullable=True),
        sa.Column(
            "detail_payload_id",
            sa.String(80),
            sa.ForeignKey("assessment_payloads.id", ondelete="RESTRICT"),
            nullable=True,
        ),
    )
    op.create_table(
        "assessment_corrections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_kind", REFERENCE, nullable=False),
        sa.Column("target_id", sa.String(80), nullable=False),
        sa.Column("reason", CORRECTION, nullable=False),
        sa.Column("detail", postgresql.JSONB(), nullable=False),
    )
    op.create_table(
        "assessment_publications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sequence", sa.BigInteger(), sa.Identity(), nullable=False, unique=True),
        sa.Column(
            "job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "root_subject_id",
            sa.String(80),
            sa.ForeignKey("assessment_subjects.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "context_id", sa.String(80), sa.ForeignKey("assessment_contexts.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("block_number", sa.Numeric(78, 0), nullable=True),
        sa.Column("block_hash", sa.String(66), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_assessment_publication_job_sequence", "assessment_publications", ["job_id", "sequence"])
    op.create_table(
        "assessment_publication_subjects",
        sa.Column(
            "publication_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_publications.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "subject_id", sa.String(80), sa.ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), primary_key=True
        ),
        sa.Column("role", SUBJECT_ROLE, primary_key=True),
        sa.Column("natural_key", sa.Text(), primary_key=True),
    )
    op.create_table(
        "assessment_publication_evidence",
        sa.Column(
            "publication_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_publications.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "evidence_id", sa.String(80), sa.ForeignKey("assessment_evidence.id", ondelete="RESTRICT"), primary_key=True
        ),
        sa.Column("natural_key", sa.Text(), nullable=False),
        sa.UniqueConstraint("publication_id", "natural_key", name="uq_assessment_publication_evidence_key"),
    )
    op.create_table(
        "assessment_publication_claims",
        sa.Column(
            "publication_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_publications.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "claim_id", sa.String(80), sa.ForeignKey("assessment_claims.id", ondelete="RESTRICT"), primary_key=True
        ),
        sa.Column("natural_key", sa.Text(), nullable=False),
        sa.UniqueConstraint("publication_id", "natural_key", name="uq_assessment_publication_claim_key"),
    )
    op.create_table(
        "assessment_publication_analyses",
        sa.Column(
            "publication_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_publications.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_analyses.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.UniqueConstraint("publication_id", "position", name="uq_assessment_publication_analysis_position"),
    )
    op.create_table(
        "assessment_import_manifests",
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("artifact_name", sa.String(), nullable=False),
        sa.Column("source_digest", sa.String(64), nullable=False),
        sa.Column(
            "source_payload_id",
            sa.String(80),
            sa.ForeignKey("assessment_payloads.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "publication_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_publications.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source", postgresql.JSONB(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_assessment_import_manifest_job", "assessment_import_manifests", ["job_id", "artifact_name"])


def downgrade() -> None:
    for table in (
        "assessment_import_manifests",
        "assessment_publication_analyses",
        "assessment_publication_claims",
        "assessment_publication_evidence",
        "assessment_publication_subjects",
        "assessment_publications",
        "assessment_corrections",
        "assessment_diagnostics",
        "assessment_coverage",
        "assessment_analysis_inputs",
        "assessment_claim_dependencies",
        "assessment_claim_evidence",
        "assessment_analysis_outputs",
        "assessment_analyses",
        "assessment_claims",
        "assessment_evidence",
        "assessment_implementations",
        "assessment_contexts",
        "assessment_payloads",
        "assessment_subjects",
    ):
        op.drop_table(table)
    for enum_type in (
        RULE,
        CORRECTION,
        DIAGNOSTIC,
        SEVERITY,
        COMPLETENESS,
        COVERAGE,
        REFERENCE,
        CONTEXT,
        OUTCOME,
        PRODUCER,
        CLAIM,
        SCOPE,
        EVIDENCE,
        SUBJECT_ROLE,
        SUBJECT,
    ):
        enum_type.drop(op.get_bind(), checkfirst=True)
