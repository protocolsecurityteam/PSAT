"""Durable coalesced monitoring triggers and generation receipts."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class MonitoringReanalysis(Base):
    __tablename__ = "monitoring_reanalysis"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="1")
    acknowledged_generation: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    request: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class MonitoringReanalysisReceipt(Base):
    __tablename__ = "monitoring_reanalysis_receipts"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    generation: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
