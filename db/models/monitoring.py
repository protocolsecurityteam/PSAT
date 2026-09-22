"""Unified monitoring tables."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

# ---------------------------------------------------------------------------
# Unified monitoring tables
# ---------------------------------------------------------------------------


class MonitoredContract(Base):
    __tablename__ = "monitored_contracts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    chain: Mapped[str] = mapped_column(String(100), nullable=False, default="ethereum")
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="SET NULL"), nullable=True
    )
    watched_proxy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("watched_proxies.id", ondelete="SET NULL"), nullable=True
    )
    # Vocabulary: ``schemas.observations.MonitoredContractType`` (column
    # stays untyped varchar; rows may carry values minted by older enrollments).
    contract_type: Mapped[str] = mapped_column(String(50), nullable=False, default="regular")
    monitoring_config: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    last_known_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    # Per polling-plan ``field``: how that entry's most recent ANSWERED
    # poll call ended — "ok" (result parsed as the entry's declared type,
    # including the type's conventional empty such as the zero address;
    # only non-empty values reach last_known_state), "error" (the node
    # answered this call with a per-call JSON-RPC error, e.g. a revert),
    # or "no_value" (answered without error but returned nothing that
    # parses as the declared type — empty 0x from a codeless address /
    # permissive fallback, short body). Absent field =
    # not polled; NULL = no completed poll pass since the column landed.
    # Written only from batches the node actually answered: a wholesale
    # transport failure publishes nothing and leaves last_polled_at
    # unstamped, so this map never reports liveness the poller did not
    # observe. Overwritten wholesale each answered poll pass.
    last_poll_status: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    last_scanned_block: Mapped[int] = mapped_column(BigInteger, default=0)
    # Stable block at which monitoring began for this contract — seeded once at
    # enrollment and never advanced (unlike last_scanned_block, which tracks the
    # scan frontier). The scanner treats an event below this floor as
    # pre-enrollment history: recorded, but never notified or reanalyzed. NULL
    # (legacy rows the backfill couldn't stamp) disables the floor — notify.
    enrollment_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Poller rotation cursor: NULLS FIRST selection stamps this at chunk-commit
    # time so never-polled and least-recently-polled contracts rotate first.
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    needs_polling: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    enrollment_source: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    events: Mapped[list["MonitoredEvent"]] = relationship(
        "MonitoredEvent", back_populates="monitored_contract", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("address", "chain", name="uq_monitored_contract_address_chain"),
        Index("ix_monitored_contracts_protocol_id", "protocol_id"),
    )


class MonitoredEvent(Base):
    __tablename__ = "monitored_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    monitored_contract_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("monitored_contracts.id", ondelete="CASCADE"), nullable=False
    )
    # 100, not 50: the witness taxonomy mints ``value_changed:<controller_id>``
    # / ``member_changed:<mapping_var>`` and a real controller id overflows 50.
    # ``event_topics.MAX_EVENT_TYPE_LENGTH`` mirrors this width and demotes any
    # spec whose type would not fit — a truncated controller id names a
    # different slot, so overflow is a demotion, never a trim.
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    block_number: Mapped[int] = mapped_column(Integer, nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    # On-chain log index — the scan path populates it so identity is
    # (contract, tx_hash, log_index, event_type). NULL for poll-path
    # ``state_changed_poll`` rows (tx_hash='' / block 0), which are outside the
    # partial identity index below by design.
    log_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data: Mapped[dict[str, Any] | None] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    monitored_contract: Mapped[MonitoredContract] = relationship("MonitoredContract", back_populates="events")

    __table_args__ = (
        Index("ix_monitored_events_contract_id", "monitored_contract_id"),
        Index("ix_monitored_events_event_type", "event_type"),
        Index("ix_monitored_events_detected_at", "detected_at"),
        Index(
            "uq_monitored_events_identity",
            "monitored_contract_id",
            "tx_hash",
            "log_index",
            "event_type",
            unique=True,
            postgresql_where=text("log_index IS NOT NULL"),
        ),
    )


class ProtocolSubscription(Base):
    __tablename__ = "protocol_subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    discord_webhook_url: Mapped[str | None] = mapped_column(String, nullable=True)
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    event_filter: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_protocol_subscriptions_protocol_id", "protocol_id"),)
