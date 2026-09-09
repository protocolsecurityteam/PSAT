"""Bounded, replace-in-place prepared public company responses."""

from datetime import datetime
from uuid import UUID as PyUUID

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, LargeBinary, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
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
    source_revisions: Mapped[dict[str, str | None] | None] = mapped_column(JSONB)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    attempts: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)


class CompanyPageRevision(Base):
    """One transactional change token per dependency scope, not an event log."""

    __tablename__ = "company_page_revisions"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    scope: Mapped[str | None] = mapped_column(String(200), index=True)
    token: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), server_default=func.gen_random_uuid())
    transaction_id: Mapped[int] = mapped_column(BigInteger, nullable=False)


class CompanyPagePurge(Base):
    """Durable, coalescing outbox; deliberately survives company deletion."""

    __tablename__ = "company_page_purges"

    company_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    token: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), server_default=func.gen_random_uuid())
    attempts: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
