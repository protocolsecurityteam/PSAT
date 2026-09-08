"""Bounded, replace-in-place prepared public company responses."""

from datetime import datetime
from uuid import UUID as PyUUID

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class CompanyPageSnapshot(Base):
    __tablename__ = "company_page_snapshots"

    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), primary_key=True)
    company_name: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(100))
    source_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    overview_gzip: Mapped[bytes | None] = mapped_column(LargeBinary)
    functions_gzip: Mapped[bytes | None] = mapped_column(LargeBinary)
    dirty_token: Mapped[PyUUID | None] = mapped_column(UUID(as_uuid=True))
    built_token: Mapped[PyUUID | None] = mapped_column(UUID(as_uuid=True))
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    attempts: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
