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
    """How one (chain, token, holder) balance ARRIVED, from the chain's receipts.

    A delivery-shape plane, deliberately separate from every balance table. Two
    reasons, both measured rather than assumed:

    * ``contract_balances`` rows are EVICTED — retention depth 10 plus
      ``ON DELETE CASCADE`` on the fetch — so an annotation carried there is
      gone within ~10 producer cycles and the evidence would have to be
      re-measured every time. A delivering transaction is block-stamped and
      immutable; it outlives every fetch that ever observed the holding.
    * a (holder, token) pair is a fact about two ADDRESSES. It is not owned by
      the protocol whose producer happened to measure it, and nothing here is
      protocol-scoped.

    **The EVIDENCE accretes.** ``delivery_count`` and ``unreadable_deliveries``
    only rise, ``min_fan_out`` only falls, ``measured_through_block`` only
    advances, and ``scanned_from_block`` is written once at insert and never
    again. So the set the all-quantifier ranges over only ever grows: a later
    cycle can withdraw a positive, and can never manufacture one.
    ``has_direct_delivery`` never turns back into ``fan_out_all`` — that verdict
    is an earned negative and it is settled.

    **``basis`` is the exception, and it is re-derived on every pass** — never
    carried, never appended to. It is composed from ``scanned_from_block`` and
    ``measured_through_block`` as they stand on this row
    (``delivery_evidence.compose_basis``), so the extent it names is the union of
    every pass rather than the window of the last one. A pass that finds nothing
    new still rewrites it; that costs no chain request and is how a row authored
    under an older rule is repaired.

    **``deliveries`` is a bounded SAMPLE, not the record.** The scalars above are
    the record and they count every delivery ever seen; the JSONB retains
    ``delivery_evidence.DELIVERY_ENTRIES_RETAINED`` entries, chosen so whichever
    delivery decides the verdict is in it. A pair too heavy to meter stores a
    compact marker — the sample plus the count of the rest, all declared
    unmetered — rather than one entry per delivery.

    ``measured_through_block`` is BOTH the extent of the claim and the cursor
    that keeps this a once-per-pair cost: the all-quantifier is over deliveries
    from ``scanned_from_block`` through it, and a consumer must read the pair to
    know what the verdict covers. Without the cursor the one-shot repeats hourly.
    It is also what makes the bounded sample safe: a later pass resumes strictly
    above it, so a delivery at or below it is already counted and needs no stored
    entry to be recognised as a repeat.

    **The extent MAY LAG the chain head, and the row is the claim's extent.** A
    range-capped chain is scanned a slice per cycle, so a row can be written from
    a window that stopped short of the tip; ``caught_up`` is what says so, and a
    consumer reads the verdict over ``scanned_from_block..measured_through_block``
    and never over "up to now". A pair that was only sliced must never read as a
    pair that was scanned to the head and found nothing.

    The published claim is delivery SHAPE and nothing else — see
    ``utils.balance_status.DELIVERY_SHAPES``. It never says a token is worthless.
    Every fan-out on this row is a count of same-token transfer LOGS, an upper
    bound on distinct recipients.
    """

    __tablename__ = "token_delivery_evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    # Lowercased at the write point. The holder is the address the recipient
    # topic filter was built from — the account the read was issued against,
    # never a canonical/folded entity key: two accounts of one plane entity are
    # two holders here, and folding them would publish one account's evidence
    # over the other's.
    holder_address: Mapped[str] = mapped_column(String(42), nullable=False)
    token_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # The block range the delivery set is an all-quantifier OVER. ``from`` is the
    # holder's creation block where it was obtainable and 0 otherwise; anything
    # else would claim completeness over blocks nobody scanned.
    scanned_from_block: Mapped[int] = mapped_column(BigInteger, nullable=False)
    measured_through_block: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # ``[{tx, block, log_index, fan_out, fan_out_basis}]`` — a BOUNDED sample of
    # the delivering transactions, each carrying the count of same-token transfer
    # LOGS measured from that transaction's own receipt. ``fan_out`` is null
    # exactly where ``fan_out_basis`` is ``receipt_unreadable``, which forces the
    # verdict to ``not_determined``: an unread receipt is not a small fan-out.
    # The counts below, not this list, are the record.
    deliveries: Mapped[list] = mapped_column(JSONB(none_as_null=True), nullable=False)
    # Every delivery ever seen for the pair, sample or not.
    delivery_count: Mapped[int] = mapped_column(Integer, nullable=False)
    unreadable_deliveries: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # The weakest delivery on record, which is what the all-quantifier turns on.
    # NULL where any delivery is unreadable or none is on record.
    min_fan_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The threshold this verdict was decided under, stored per row rather than
    # read from today's constant: K is a published model parameter and a row
    # measured under one K must not be re-read under another.
    fan_out_threshold_k: Mapped[int] = mapped_column(Integer, nullable=False)
    delivery_shape: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=DELIVERY_SHAPE_NOT_DETERMINED
    )
    # The holder's raw balance of this token as the cycle that last SCANNED the
    # pair read it. It is a SKIP key and never evidence: an unmoved balance is
    # what lets the next cycle leave the extent where it is, because a new
    # delivery necessarily moves it. NULL is not "unchanged" — it is a pair
    # nobody stamped, and it is scanned.
    observed_balance_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    # False when the pass that wrote the row stopped at a slice boundary below
    # the chain head. Such a row is scanned forward every cycle whatever its
    # balance does, because the balance argument for skipping only holds over
    # blocks that were already read — and its ``fan_out_all`` is NOT dispositive
    # while it stands (``delivery_evidence.DeliveryFact.is_airdrop_only``): the
    # verdict is true of the slice, and the blocks above it are where a
    # settlement would refute it. A settled ``has_direct_delivery`` written at a
    # partial extent keeps this false forever — catch-up short-circuits on the
    # earned negative — which is why only the POSITIVE is gated on it.
    caught_up: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    # The sentence the published claim derives its scope from — the filter, the
    # block range, the request counts — never re-authored downstream.
    basis: Mapped[str] = mapped_column(Text, nullable=False)
    first_measured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("chain_id", "holder_address", "token_address", name="uq_tde_chain_holder_token"),
        Index("ix_tde_chain_token", "chain_id", "token_address"),
        Index("ix_tde_chain_holder", "chain_id", "holder_address"),
        # The positive verdict is an all-quantifier, so it cannot stand beside a
        # delivery nobody could read, and it cannot stand over an empty set: a
        # holding whose arrival is not on record is not_determined, never
        # airdrop-delivered.
        CheckConstraint(
            f"delivery_shape <> '{DELIVERY_SHAPE_FAN_OUT_ALL}' OR "
            "(unreadable_deliveries = 0 AND delivery_count > 0 AND min_fan_out >= fan_out_threshold_k)",
            name="ck_tde_fan_out_all_is_earned",
        ),
        # The earned negative needs a delivery that actually read BELOW K; a
        # missing measurement must not be laundered into a negative either.
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
    """Whether a token address is one THIS protocol's own discovery names.

    Written by the producers' disposition phase against
    ``services.scoring.distill.load_protocol_universe``, and read by the
    presentation layer, which cannot build the universe itself: that assembly is
    a measured 26.5-second object-storage read, unusable on an API path. The
    verdict is stored here so a surface can consult it in one indexed lookup.

    **THIS TABLE IS REFRESHED EVERY CYCLE. IT IS NOT IMMUTABLE, AND THAT IS THE
    POINT** — the exact opposite discipline from ``TokenDeliveryEvidence``, whose
    evidence accretes and is never taken back. The predicate behind
    ``absent_from_universe`` is ANTI-MONOTONE: discovery growing can only turn an
    absence into a presence, so a verdict taken against a smaller universe must be
    able to WITHDRAW. A row here is the answer as of ``measured_at`` against a
    universe of ``universe_addresses`` addresses, and a later cycle overwrites it.
    Read the two tables with that contrast in mind; assuming this one accretes
    would pin a condemnation that discovery has already dissolved.

    **Absence of a row reads as ``not_determined`` at every consumer**, which is
    to say the holding is presented. Nothing may be pulled from a sheet because
    no verdict was stored for it.
    """

    __tablename__ = "token_protocol_reference"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Protocol-scoped, unlike delivery evidence: "the protocol refers to this
    # address" is a claim about one protocol's discovery and about nothing else.
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    # Lowercased at the write point, as everywhere else in the balance planes.
    token_address: Mapped[str] = mapped_column(String(42), nullable=False)
    reference_shape: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=TOKEN_REFERENCE_NOT_DETERMINED
    )
    # The size of the universe the verdict was taken against. A withdrawal is
    # readable as a number here growing, so a reader can tell "discovery found
    # it" from "the predicate changed" without re-running either.
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
        # A universe of no addresses cannot witness an absence — it would condemn
        # everything. The fail-closed answer under an unbuildable universe is
        # ``not_determined``, and the constraint keeps that from being edited away.
        CheckConstraint(
            f"reference_shape <> '{TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE}' OR universe_addresses > 0",
            name="ck_tpr_absence_needs_a_universe",
        ),
    )
