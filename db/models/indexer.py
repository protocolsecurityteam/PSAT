"""Durable indexer work: one revisioned row per enrollment source or chain."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class IndexerWork(Base):
    __tablename__ = "indexer_work"

    kind: Mapped[str] = mapped_column(String(24), primary_key=True)
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="1")
    dirty: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    lease_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_indexer_work_due", "kind", "dirty", "available_at"),
        Index("ix_indexer_work_repair", "kind", "dirty", "completed_at"),
    )
