"""Durable coordination, separate from application work and queue semantics."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class WorkerLifecycle(Base):
    __tablename__ = "worker_lifecycle"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    boot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    machine_id: Mapped[str | None] = mapped_column(Text)
    phase: Mapped[str] = mapped_column(Text, nullable=False, server_default="stopped")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_work_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idle_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_start_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    paused: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")

    __table_args__ = (CheckConstraint("id = 1"), CheckConstraint("phase IN ('running', 'draining', 'stopped')"))
