"""Durable deployment-specific effects coverage and bounded recovery."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class PendingEffectsWork(Base):
    __tablename__ = "pending_effects_work"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"))
    chain_id: Mapped[int] = mapped_column(Integer)
    deployment_address: Mapped[str] = mapped_column(String(42))
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"))
    function_id: Mapped[int] = mapped_column(Integer, ForeignKey("effective_functions.id", ondelete="CASCADE"))
    effect_family: Mapped[str] = mapped_column(String(50))
    reason: Mapped[str] = mapped_column(String(80), default="balance_inputs_pending")
    state: Mapped[str] = mapped_column(String(20), default="pending")
    required_generation: Mapped[int] = mapped_column(BigInteger, default=0)
    consumed_generation: Mapped[int] = mapped_column(BigInteger, default=0)
    evidence_generation: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    evidence_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Explicit asset identities tried by this function; price changes do not reset it.
    covered_tokens: Mapped[list[str]] = mapped_column(JSONB, default=list)
    candidate_tokens: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default=text("'[]'::jsonb"))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    queued_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    __table_args__ = (
        UniqueConstraint(
            "chain_id", "deployment_address", "function_id", "effect_family", name="uq_pending_effects_identity"
        ),
        Index("ix_pending_effects_due", "state", "next_attempt_at"),
    )
