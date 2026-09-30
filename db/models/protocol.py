"""Protocol / company entity and audit coverage."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .contracts import Contract
    from .monitoring import MonitoredContract, ProtocolSubscription


class Protocol(Base):
    __tablename__ = "protocols"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    chains: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)), server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    contracts: Mapped[list["Contract"]] = relationship(
        "Contract", back_populates="protocol", foreign_keys="Contract.protocol_id"
    )
    monitored_contracts: Mapped[list["MonitoredContract"]] = relationship(
        "MonitoredContract", backref="protocol", foreign_keys="MonitoredContract.protocol_id"
    )
    protocol_subscriptions: Mapped[list["ProtocolSubscription"]] = relationship(
        "ProtocolSubscription", backref="protocol"
    )
    official_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # DefiLlama family slug (NULL when unmatched). Free-text input resolves to it so spellings collapse to one row.
    canonical_slug: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Set when the enrollment reconciler drains this protocol; the slow sweep takes the oldest first.
    last_balance_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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

    # NULL (not attempted), "processing", "success", "failed", "skipped" (e.g. image-only PDFs).
    text_extraction_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    text_extraction_worker: Mapped[str | None] = mapped_column(String(128), nullable=True)
    text_extraction_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    text_extracted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    text_extraction_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    text_storage_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    text_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    text_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Runs after text extraction succeeds; same state machine. "skipped" means no scope section was found.
    scope_extraction_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    scope_extraction_worker: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scope_extraction_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope_extracted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope_extraction_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_storage_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_contracts: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    reviewed_commits: Mapped[list[str] | None] = mapped_column(ARRAY(String(40)), nullable=True)
    referenced_repos: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    classified_commits: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)

    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_repo: Mapped[str | None] = mapped_column(String(255), nullable=True)
    findings: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)
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
        # For the scope-extraction content-hash cache lookup.
        Index(
            "ix_audit_reports_text_sha256_scoped",
            "text_sha256",
            postgresql_where=text("scope_extraction_status = 'success'"),
        ),
    )


class AuditContractCoverage(Base):
    """An audit-report-to-contract scope link, so "which audits cover this impl?" is a join.

    Links the implementation-era contract actually reviewed, not the proxy. See ``services.audits.coverage``.
    """

    __tablename__ = "audit_contract_coverage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    audit_report_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("audit_reports.id", ondelete="CASCADE"), nullable=False
    )
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    matched_name: Mapped[str] = mapped_column(String(255), nullable=False)
    match_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # A string enum to avoid false numeric precision.
    match_confidence: Mapped[str] = mapped_column(String(10), nullable=False)
    # Impl window the audit applies to; NULL for direct matches.
    covered_from_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    covered_to_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytecode_keccak_at_match: Mapped[str | None] = mapped_column(String(66), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    equivalence_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    equivalence_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    equivalence_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    proof_kind: Mapped[str | None] = mapped_column(String(30), nullable=True)
    # The ``classified_commits`` SHA matched during verification; NULL for heuristic-only or older rows. Full hex for
    # GitHub URLs.
    matched_commit_sha: Mapped[str | None] = mapped_column(String(66), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("contract_id", "audit_report_id", name="uq_audit_contract_coverage_pair"),
        Index("ix_audit_contract_coverage_contract_id", "contract_id"),
        Index("ix_audit_contract_coverage_audit_report_id", "audit_report_id"),
        Index("ix_audit_contract_coverage_protocol_id", "protocol_id"),
        # Partial index over pending rows for ``CoverageVerifyWorker``.
        Index(
            "ix_acc_equivalence_pending",
            "id",
            postgresql_where=text("equivalence_status = 'pending'"),
        ),
    )


# ``ProtocolDeployer.trust_class`` (spec §3.3). Class C is the absence of a row.
DEPLOYER_TRUST_CLASS_A = "A"
DEPLOYER_TRUST_CLASS_B = "B"
# Heuristic affinity (DEPLOYER_HEURISTIC_SPEC.md §1), below the proof classes; only allowed while no active A/B row
# exists.
DEPLOYER_TRUST_CLASS_H = "H"
PROOF_DEPLOYER_TRUST_CLASSES = frozenset({DEPLOYER_TRUST_CLASS_A, DEPLOYER_TRUST_CLASS_B})
DEPLOYER_TRUST_CLASSES = PROOF_DEPLOYER_TRUST_CLASSES | {DEPLOYER_TRUST_CLASS_H}


class ProtocolDeployer(Base):
    """A witnessed, dated, revocable deployer-trust fact.

    EOAs are chain-agnostic. ``evidence`` carries the perimeter fact (A) or corroborating members and snapshot (B).
    Revocation keeps the row.
    """

    __tablename__ = "protocol_deployers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    trust_class: Mapped[str] = mapped_column(String(1), nullable=False)
    evidence: Mapped[Any] = mapped_column(JSONB, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint("trust_class IN ('A', 'B', 'H')", name="ck_protocol_deployers_trust_class"),
        UniqueConstraint("protocol_id", "address", name="uq_protocol_deployers_protocol_address"),
        Index("ix_protocol_deployers_address", "address"),
    )


class DeployerAffinityChallenge(Base):
    """One observed foreign anchor against a class-H row (DEPLOYER_HEURISTIC_SPEC.md §5).

    Derived from a real witness for another protocol (``foreign_witness_id``), revoked with it. The H row's state is
    derived from these, never stored.
    """

    __tablename__ = "deployer_affinity_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    protocol_deployer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("protocol_deployers.id", ondelete="CASCADE"), nullable=False
    )
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    foreign_protocol_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False
    )
    foreign_witness_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("contract_membership_witnesses.id", ondelete="CASCADE"), nullable=False
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "protocol_deployer_id",
            "contract_id",
            "foreign_witness_id",
            name="uq_deployer_affinity_challenge_observation",
        ),
        Index("ix_deployer_affinity_challenges_deployer", "protocol_deployer_id"),
        Index("ix_deployer_affinity_challenges_witness", "foreign_witness_id"),
    )
