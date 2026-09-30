"""Token delivery evidence and token-protocol references."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from utils.balance_status import (
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    DELIVERY_SHAPE_NOT_DETERMINED,
    TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
    TOKEN_REFERENCE_NOT_DETERMINED,
    TOKEN_REFERENCE_SHAPES,
)

from .base import Base


class TokenDeliveryEvidence(Base):
    """How one (chain, token, holder) balance arrived, from receipts.

    Separate from the balance tables because ``contract_balances`` rows are evicted within ~10 cycles while delivering
    transactions are immutable, and because a (holder, token) pair belongs to no protocol.

    Evidence accretes within one anchored history (a changed checkpoint forces a rebuild): ``delivery_count`` and
    ``unreadable_deliveries`` only rise, ``min_fan_out`` only falls, ``measured_through_block`` only advances,
    ``scanned_from_block`` is fixed. So later cycles can withdraw a positive but never create one;
    ``has_direct_delivery`` is settled.

    ``basis`` is re-derived every pass from the stored extent (``delivery_evidence.compose_basis``).

    ``deliveries`` is a bounded sample (``delivery_evidence.DELIVERY_ENTRIES_RETAINED``) including whichever delivery
    decides the verdict; the scalars are the record.

    ``measured_through_block`` is both the claim's extent and the resume cursor. It may lag the head (``caught_up`` says
    so); read the verdict over ``scanned_from_block..measured_through_block``.

    The claim is delivery shape only (``utils.balance_status.DELIVERY_SHAPES``), never that a token is worthless.
    Fan-outs count same-token transfer logs, an upper bound on recipients.
    """

    __tablename__ = "token_delivery_evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    # Lowercased; the account the filter was built from, never a folded entity key.
    holder_address: Mapped[str] = mapped_column(String(42), nullable=False)
    token_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # The range the all-quantifier covers; from the holder's creation block where known, else 0.
    scanned_from_block: Mapped[int] = mapped_column(BigInteger, nullable=False)
    measured_through_block: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # Anchors to canonical history; NULL legacy rows must be rebuilt before extending.
    measured_through_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    # ``[{tx, block, log_index, fan_out, fan_out_basis}]``, a bounded sample. ``fan_out`` is null exactly when the
    # receipt was unreadable, which forces ``not_determined``. The counts are the record.
    deliveries: Mapped[list] = mapped_column(JSONB(none_as_null=True), nullable=False)
    delivery_count: Mapped[int] = mapped_column(Integer, nullable=False)
    unreadable_deliveries: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # The weakest delivery; NULL if any is unreadable or none recorded.
    min_fan_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Stored per row so a verdict isn't re-read under a different K.
    fan_out_threshold_k: Mapped[int] = mapped_column(Integer, nullable=False)
    delivery_shape: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=DELIVERY_SHAPE_NOT_DETERMINED
    )
    # The balance when last scanned; a skip key (an unchanged balance means no new delivery), never evidence. NULL is
    # scanned.
    observed_balance_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    # False when the pass stopped below the head. Such rows are scanned forward every cycle, and their ``fan_out_all``
    # isn't dispositive (``DeliveryFact.is_airdrop_only``). A settled ``has_direct_delivery`` may stay false forever,
    # which is why only the positive is gated.
    caught_up: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    # The scope sentence for the published claim, never re-authored downstream.
    basis: Mapped[str] = mapped_column(Text, nullable=False)
    first_measured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("chain_id", "holder_address", "token_address", name="uq_tde_chain_holder_token"),
        Index("ix_tde_chain_token", "chain_id", "token_address"),
        Index("ix_tde_chain_holder", "chain_id", "holder_address"),
        # The positive is an all-quantifier: it can't stand beside an unreadable delivery or over an empty set.
        CheckConstraint(
            f"delivery_shape <> '{DELIVERY_SHAPE_FAN_OUT_ALL}' OR "
            "(unreadable_deliveries = 0 AND delivery_count > 0 AND min_fan_out >= fan_out_threshold_k)",
            name="ck_tde_fan_out_all_is_earned",
        ),
        # The negative needs a delivery actually measured below K.
        CheckConstraint(
            f"delivery_shape <> '{DELIVERY_SHAPE_HAS_DIRECT_DELIVERY}' OR "
            "(delivery_count > 0 AND min_fan_out IS NOT NULL AND min_fan_out < fan_out_threshold_k)",
            name="ck_tde_direct_delivery_is_measured",
        ),
        CheckConstraint(
            "delivery_shape IN ('"
            + "', '".join(
                (DELIVERY_SHAPE_FAN_OUT_ALL, DELIVERY_SHAPE_HAS_DIRECT_DELIVERY, DELIVERY_SHAPE_NOT_DETERMINED)
            )
            + "')",
            name="ck_tde_delivery_shape_vocabulary",
        ),
        CheckConstraint("jsonb_typeof(deliveries) = 'array'", name="ck_tde_deliveries_is_array"),
        CheckConstraint("measured_through_block >= scanned_from_block", name="ck_tde_range_is_ordered"),
    )


class TokenProtocolReference(Base):
    """Whether a token address is one this protocol's own discovery names.

    Written by the producers against ``services.scoring.distill.load_protocol_universe`` (a ~26s read), so presentation
    can look it up cheaply.

    Refreshed every cycle, unlike ``TokenDeliveryEvidence``: ``absent_from_universe`` is anti-monotone (discovery
    growing turns absences into presences), so verdicts must be able to withdraw. A row is the answer as of
    ``measured_at`` against ``universe_addresses`` addresses.

    No row means ``not_determined``, and the holding is shown.
    """

    __tablename__ = "token_protocol_reference"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Protocol-scoped: a claim about one protocol's discovery.
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    token_address: Mapped[str] = mapped_column(String(42), nullable=False)
    reference_shape: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=TOKEN_REFERENCE_NOT_DETERMINED
    )
    # The universe size, so a withdrawal shows as this growing.
    universe_addresses: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    basis: Mapped[str] = mapped_column(Text, nullable=False)
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("protocol_id", "chain_id", "token_address", name="uq_tpr_protocol_chain_token"),
        Index("ix_tpr_protocol_chain", "protocol_id", "chain_id"),
        CheckConstraint(
            "reference_shape IN ('" + "', '".join(TOKEN_REFERENCE_SHAPES) + "')",
            name="ck_tpr_reference_shape_vocabulary",
        ),
        # An empty universe can't witness absence (it would condemn everything).
        CheckConstraint(
            f"reference_shape <> '{TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE}' OR universe_addresses > 0",
            name="ck_tpr_absence_needs_a_universe",
        ),
    )
