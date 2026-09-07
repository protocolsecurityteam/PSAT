"""Immutable, table-first canonical Assessment records and publication links."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from schemas.temporal_assessment import (
    AnalysisOutcome,
    AnalysisProducer,
    ClaimKind,
    ContextKind,
    CorrectionReason,
    CorrectionTargetKind,
    CoverageCompleteness,
    CoverageKind,
    DerivationRule,
    DiagnosticCode,
    DiagnosticSeverity,
    EvidenceKind,
    ScopeKind,
    SubjectKind,
    SubjectRole,
)

from .base import Base


def _enum(kind: type, name: str) -> Enum:
    return Enum(kind, name=name, values_callable=lambda values: [value.value for value in values])


class AssessmentSubject(Base):
    __tablename__ = "assessment_subjects"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[SubjectKind] = mapped_column(_enum(SubjectKind, "assessment_subject_kind"), nullable=False)
    identity: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (UniqueConstraint("kind", "identity", name="uq_assessment_subject_identity"),)


class AssessmentPayload(Base):
    __tablename__ = "assessment_payloads"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    media_type: Mapped[str] = mapped_column(String(120), nullable=False)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    byte_length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (CheckConstraint("byte_length >= 0", name="ck_assessment_payload_length"),)


class AssessmentContext(Base):
    __tablename__ = "assessment_contexts"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[ContextKind] = mapped_column(_enum(ContextKind, "assessment_context_kind"), nullable=False)
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (UniqueConstraint("kind", "context", name="uq_assessment_context"),)


class AssessmentImplementation(Base):
    __tablename__ = "assessment_implementations"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    producer: Mapped[AnalysisProducer] = mapped_column(
        _enum(AnalysisProducer, "assessment_analysis_producer"), nullable=False
    )
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AssessmentEvidence(Base):
    __tablename__ = "assessment_evidence"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), nullable=False
    )
    kind: Mapped[EvidenceKind] = mapped_column(_enum(EvidenceKind, "assessment_evidence_kind"), nullable=False)
    payload_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_payloads.id", ondelete="RESTRICT"), nullable=False
    )
    source: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    obtained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    block_number: Mapped[int | None] = mapped_column(Numeric(78, 0), nullable=True)
    block_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    transaction_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    transaction_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    log_index: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index("ix_assessment_evidence_subject_time", "subject_id", "chain_id", "block_number"),
        UniqueConstraint(
            "chain_id",
            "block_hash",
            "transaction_hash",
            "log_index",
            name="uq_assessment_chain_event_occurrence",
        ),
    )


class AssessmentClaim(Base):
    __tablename__ = "assessment_claims"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), nullable=False
    )
    kind: Mapped[ClaimKind] = mapped_column(_enum(ClaimKind, "assessment_claim_kind"), nullable=False)
    proposition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    scope_kind: Mapped[ScopeKind] = mapped_column(_enum(ScopeKind, "assessment_scope_kind"), nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    rule: Mapped[DerivationRule] = mapped_column(_enum(DerivationRule, "assessment_derivation_rule"), nullable=False)
    implementation_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_implementations.id", ondelete="RESTRICT"), nullable=False
    )
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_assessment_claim_subject_scope", "subject_id", "scope_kind"),)


class AssessmentAnalysis(Base):
    __tablename__ = "assessment_analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    producer: Mapped[AnalysisProducer] = mapped_column(
        _enum(AnalysisProducer, "assessment_analysis_producer"), nullable=False
    )
    implementation_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_implementations.id", ondelete="RESTRICT"), nullable=False
    )
    context_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_contexts.id", ondelete="RESTRICT"), nullable=False
    )
    outcome: Mapped[AnalysisOutcome] = mapped_column(_enum(AnalysisOutcome, "assessment_outcome"), nullable=False)
    receipt: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_assessment_analysis_job_time", "job_id", "recorded_at"),)


class AssessmentAnalysisOutput(Base):
    __tablename__ = "assessment_analysis_outputs"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_analyses.id", ondelete="CASCADE"), primary_key=True
    )
    claim_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_claims.id", ondelete="RESTRICT"), primary_key=True
    )


class AssessmentClaimEvidence(Base):
    __tablename__ = "assessment_claim_evidence"

    claim_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_claims.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_evidence.id", ondelete="RESTRICT"), primary_key=True
    )


class AssessmentClaimDependency(Base):
    __tablename__ = "assessment_claim_dependencies"

    claim_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_claims.id", ondelete="CASCADE"), primary_key=True
    )
    prerequisite_claim_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_claims.id", ondelete="RESTRICT"), primary_key=True
    )

    __table_args__ = (
        CheckConstraint("claim_id <> prerequisite_claim_id", name="ck_assessment_claim_not_self_dependent"),
    )


class AssessmentAnalysisInput(Base):
    __tablename__ = "assessment_analysis_inputs"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_analyses.id", ondelete="CASCADE"), primary_key=True
    )
    input_kind: Mapped[CorrectionTargetKind] = mapped_column(
        _enum(CorrectionTargetKind, "assessment_reference_kind"), primary_key=True
    )
    input_id: Mapped[str] = mapped_column(String(80), primary_key=True)


class AssessmentCoverage(Base):
    __tablename__ = "assessment_coverage"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_analyses.id", ondelete="CASCADE"), nullable=False
    )
    subject_id: Mapped[str | None] = mapped_column(
        String(80), ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), nullable=True
    )
    kind: Mapped[CoverageKind] = mapped_column(_enum(CoverageKind, "assessment_coverage_kind"), nullable=False)
    scope_kind: Mapped[ScopeKind] = mapped_column(_enum(ScopeKind, "assessment_scope_kind"), nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    completeness: Mapped[CoverageCompleteness] = mapped_column(
        _enum(CoverageCompleteness, "assessment_coverage_completeness"), nullable=False
    )
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class AssessmentDiagnostic(Base):
    __tablename__ = "assessment_diagnostics"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_analyses.id", ondelete="CASCADE"), nullable=False
    )
    severity: Mapped[DiagnosticSeverity] = mapped_column(
        _enum(DiagnosticSeverity, "assessment_diagnostic_severity"), nullable=False
    )
    code: Mapped[DiagnosticCode] = mapped_column(_enum(DiagnosticCode, "assessment_diagnostic_code"), nullable=False)
    original_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    subject_id: Mapped[str | None] = mapped_column(
        String(80), ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), nullable=True
    )
    scope: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    detail_payload_id: Mapped[str | None] = mapped_column(
        String(80), ForeignKey("assessment_payloads.id", ondelete="RESTRICT"), nullable=True
    )


class AssessmentCorrection(Base):
    __tablename__ = "assessment_corrections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_analyses.id", ondelete="CASCADE"), nullable=False
    )
    target_kind: Mapped[CorrectionTargetKind] = mapped_column(
        _enum(CorrectionTargetKind, "assessment_reference_kind"), nullable=False
    )
    target_id: Mapped[str] = mapped_column(String(80), nullable=False)
    reason: Mapped[CorrectionReason] = mapped_column(
        _enum(CorrectionReason, "assessment_correction_reason"), nullable=False
    )
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class AssessmentPublication(Base):
    __tablename__ = "assessment_publications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sequence: Mapped[int] = mapped_column(BigInteger, Identity(), nullable=False, unique=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    root_subject_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), nullable=False
    )
    context_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_contexts.id", ondelete="RESTRICT"), nullable=False
    )
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    block_number: Mapped[int | None] = mapped_column(Numeric(78, 0), nullable=True)
    block_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_assessment_publication_job_sequence", "job_id", "sequence"),)


class AssessmentPublicationSubject(Base):
    __tablename__ = "assessment_publication_subjects"

    publication_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_publications.id", ondelete="CASCADE"), primary_key=True
    )
    subject_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_subjects.id", ondelete="RESTRICT"), primary_key=True
    )
    role: Mapped[SubjectRole] = mapped_column(_enum(SubjectRole, "assessment_subject_role"), primary_key=True)
    natural_key: Mapped[str] = mapped_column(Text, primary_key=True)


class AssessmentPublicationEvidence(Base):
    __tablename__ = "assessment_publication_evidence"

    publication_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_publications.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    natural_key: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (UniqueConstraint("publication_id", "natural_key", name="uq_assessment_publication_evidence_key"),)


class AssessmentPublicationClaim(Base):
    __tablename__ = "assessment_publication_claims"

    publication_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_publications.id", ondelete="CASCADE"), primary_key=True
    )
    claim_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_claims.id", ondelete="RESTRICT"), primary_key=True
    )
    natural_key: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (UniqueConstraint("publication_id", "natural_key", name="uq_assessment_publication_claim_key"),)


class AssessmentPublicationAnalysis(Base):
    __tablename__ = "assessment_publication_analyses"

    publication_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_publications.id", ondelete="CASCADE"), primary_key=True
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_analyses.id", ondelete="CASCADE"), primary_key=True
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        UniqueConstraint("publication_id", "position", name="uq_assessment_publication_analysis_position"),
    )


class AssessmentImportManifest(Base):
    """Durable receipt for one consumed pre-cutover analytical artifact."""

    __tablename__ = "assessment_import_manifests"

    artifact_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    artifact_name: Mapped[str] = mapped_column(String, nullable=False)
    source_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_payload_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("assessment_payloads.id", ondelete="RESTRICT"), nullable=False
    )
    source_created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    publication_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_publications.id", ondelete="RESTRICT"), nullable=False
    )
    source: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_assessment_import_manifest_job", "job_id", "artifact_name"),)


__all__ = [
    "AssessmentAnalysis",
    "AssessmentAnalysisInput",
    "AssessmentAnalysisOutput",
    "AssessmentClaim",
    "AssessmentClaimDependency",
    "AssessmentClaimEvidence",
    "AssessmentContext",
    "AssessmentCorrection",
    "AssessmentCoverage",
    "AssessmentDiagnostic",
    "AssessmentEvidence",
    "AssessmentImplementation",
    "AssessmentImportManifest",
    "AssessmentPayload",
    "AssessmentPublication",
    "AssessmentPublicationAnalysis",
    "AssessmentPublicationClaim",
    "AssessmentPublicationEvidence",
    "AssessmentPublicationSubject",
    "AssessmentSubject",
]
