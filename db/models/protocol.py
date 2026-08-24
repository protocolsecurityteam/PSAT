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


# ---------------------------------------------------------------------------
# Protocol / company entity
# ---------------------------------------------------------------------------


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
    # Canonical external ID — DefiLlama family slug. NULL when the protocol
    # has no DefiLlama match (long-tail / private). Worker code resolves
    # free-text input to a slug, then keys ``get_or_create_protocol`` on it
    # so different spellings ("ether fi" vs "etherfi") collapse to one row.
    canonical_slug: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Set to NOW() each time the enrollment reconciler successfully drains this
    # protocol. The K-per-tick slow sweep enqueues the least-recently-reconciled
    # protocols (NULLS FIRST) so drift from unknown write sites still converges.
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

    # Text-extraction pipeline state. Populated by workers.audit_text_extraction.
    # status values: NULL (not yet attempted), "processing", "success",
    # "failed", "skipped" (e.g. image-only PDFs that need OCR).
    text_extraction_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    text_extraction_worker: Mapped[str | None] = mapped_column(String(128), nullable=True)
    text_extraction_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    text_extracted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    text_extraction_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    text_storage_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    text_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    text_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Scope-extraction pipeline state. Populated by workers.audit_scope_extraction
    # once text_extraction_status='success'. Mirrors the text_* state machine:
    # NULL (eligible) -> "processing" -> "success"/"failed"/"skipped".
    # "skipped" means no scope-section header was found in the PDF text.
    scope_extraction_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    scope_extraction_worker: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scope_extraction_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope_extracted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope_extraction_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_storage_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_contracts: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Commit SHAs mentioned in the PDF as the reviewed revision.
    reviewed_commits: Mapped[list[str] | None] = mapped_column(ARRAY(String(40)), nullable=True)
    # Lower-cased fallback GitHub repos mentioned anywhere in the PDF body.
    referenced_repos: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    # Phase C: LLM-labeled commit metadata from the audit text.
    classified_commits: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)

    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # GitHub repo the PDF was discovered in.
    source_repo: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Findings extracted from the audit; stored as JSONB so the shape can evolve.
    findings: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)
    # Structured scope-table rows, kept alongside the flat ``scope_contracts`` list.
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
        # Partial index — powers the content-hash cache lookup in the
        # scope-extraction worker.
        Index(
            "ix_audit_reports_text_sha256_scoped",
            "text_sha256",
            postgresql_where=text("scope_extraction_status = 'success'"),
        ),
    )


class AuditContractCoverage(Base):
    """Link between an ``AuditReport`` and a ``Contract`` that was in scope.

    Persisted so "which audits cover this impl?" is a plain join, not a
    query-time scan of ``scope_contracts[]``. Proxy-aware: the row links
    the implementation-era ``Contract`` the audit actually reviewed, not
    the proxy. See ``services.audits.coverage`` for the matcher.
    """

    __tablename__ = "audit_contract_coverage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    audit_report_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("audit_reports.id", ondelete="CASCADE"), nullable=False
    )
    # Denormalized FK so per-protocol queries stay single-hop.
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    # Matching scope entry, kept for debugging and auditability.
    matched_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Match taxonomy lives in ``services.audits.coverage``.
    match_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # String enum to avoid implying false numeric precision downstream.
    match_confidence: Mapped[str] = mapped_column(String(10), nullable=False)
    # Impl active window the audit applies to. NULL for direct matches.
    covered_from_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    covered_to_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Runtime bytecode anchor captured when the coverage row was written.
    bytecode_keccak_at_match: Mapped[str | None] = mapped_column(String(66), nullable=True)
    # Timestamp for the bytecode anchor sample.
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Source-equivalence verdict for this (audit, contract) pair.
    equivalence_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Short human-readable detail for the equivalence verdict.
    equivalence_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Last verification attempt time, distinct from the bytecode anchor sample.
    equivalence_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Phase C proof strength for ``equivalence_status='proven'`` rows.
    proof_kind: Mapped[str | None] = mapped_column(String(30), nullable=True)
    # Specific commit SHA from ``AuditReport.classified_commits`` that matched
    # this contract's bytecode during verification. Populated alongside
    # ``proof_kind``/``equivalence_status``. NULL for heuristic-only matches
    # (direct / impl_era) and for rows verified before this field existed.
    # Stored as the full 40-char hex so downstream can build GitHub tree URLs
    # without having to look up the audit's commit list again.
    matched_commit_sha: Mapped[str | None] = mapped_column(String(66), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("contract_id", "audit_report_id", name="uq_audit_contract_coverage_pair"),
        Index("ix_audit_contract_coverage_contract_id", "contract_id"),
        Index("ix_audit_contract_coverage_audit_report_id", "audit_report_id"),
        Index("ix_audit_contract_coverage_protocol_id", "protocol_id"),
        # Partial queue index for ``CoverageVerifyWorker``: only ``pending``
        # rows are scanned, so the index size tracks the queue depth not
        # the table size. Built in ``a3b4c5d6e7f8_add_coverage_pending_index``.
        Index(
            "ix_acc_equivalence_pending",
            "id",
            postgresql_where=text("equivalence_status = 'pending'"),
        ),
    )


# ``ProtocolDeployer.trust_class`` vocabulary (membership gate, spec §3.3).
# Class C is the ABSENCE of a row — never a row with a third value.
DEPLOYER_TRUST_CLASS_A = "A"
DEPLOYER_TRUST_CLASS_B = "B"
DEPLOYER_TRUST_CLASSES = frozenset({DEPLOYER_TRUST_CLASS_A, DEPLOYER_TRUST_CLASS_B})


class ProtocolDeployer(Base):
    """A witnessed, dated, revocable deployer-trust fact — never a bare flag.

    EOAs are keyed by address only (chain-agnostic: the same key signs on
    every chain). ``evidence`` carries the perimeter fact (Class A) or the
    corroborating member ids + enumeration snapshot + check date (Class B).
    Revocation preserves the row (``revoked_at`` + ``revocation_reason``).
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
        CheckConstraint("trust_class IN ('A', 'B')", name="ck_protocol_deployers_trust_class"),
        UniqueConstraint("protocol_id", "address", name="uq_protocol_deployers_protocol_address"),
        Index("ix_protocol_deployers_address", "address"),
    )
