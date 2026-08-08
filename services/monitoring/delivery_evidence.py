"""The delivery-shape evidence plane: one writer, one reader, one vocabulary.

The producers MEASURE delivery shape (``services.monitoring.delivery_shape``)
and write it here; the value plane READS it here. Both go through this module so
the all-quantifier is evaluated in exactly one place and the row's own stored
fields are what a published claim derives from.

What is stored is how a balance ARRIVED — never what it is worth. A real token
can be airdrop-delivered (measured on this corpus: HEX at fan-out 199/399/399,
uniETH at 101), so the vocabulary in :mod:`utils.balance_status` names delivery
shape and nothing else, and no consumer may rename it to "spam" or "worthless".
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import tuple_
from sqlalchemy.orm import Session

from utils.balance_status import (
    DELIVERY_FAN_OUT_BASIS_RECEIPT,
    DELIVERY_FAN_OUT_BASIS_UNREADABLE,
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    DELIVERY_SHAPE_NOT_DETERMINED,
)

# --- K, the published model parameter ----------------------------------------
# The same-token recipient count above which one delivering transaction is a
# mass distribution rather than a settlement.
#
# CALIBRATION CORPUS (named, as the ruling requires): 37 (holder, token) pairs
# probed live on 2026-08-08 against tip e637585d — 21 junk-side (ethereum 9,
# base 8, optimism 2, including 6 base memecoins the census left undetermined)
# and 16 Pile-B real controls (ethereum 12, optimism 2) — plus the 4 pairs
# recorded in SPAM_CLASSIFIER_FEASIBILITY.md (YIELDX 191, DIXT 450, weETHs 1->1,
# aEthUSDe 39 logs / 1 same-token transfer). Measured separation: the largest
# genuine settlement fan-out is 8 (SY-weETHs) and the smallest observed airdrop
# batch is 48 (a base SHIB impersonation), so the corpus separates on any
# K in [9, 48]. 25 is the log-centred choice inside that interval — 3.1x above
# the largest real settlement and 1.9x below the smallest airdrop batch.
#
# The interval is the honest statement of what is known; the point is a
# parameter. It is stored on every evidence row (``fan_out_threshold_k``) so a
# row measured under one K is never re-read under another, and it is NOT
# env-overridable: a published model parameter that a deployment can move is not
# a published model parameter.
FAN_OUT_THRESHOLD_K = 25

FAN_OUT_CALIBRATION_CORPUS = (
    "37 (holder, token) pairs probed live 2026-08-08 at tip e637585d "
    "(21 airdrop-side: ethereum 9 / base 8 / optimism 2; 16 real controls: ethereum 12 / optimism 2) "
    "plus 4 pairs recorded in SPAM_CLASSIFIER_FEASIBILITY.md; separation interval K in [9, 48], "
    "largest real settlement fan-out 8, smallest airdrop batch 48"
)


@dataclass(frozen=True)
class DeliveryFact:
    """One (chain, holder, token) pair's stored delivery shape, as stored.

    Every field is read off the row. Nothing is re-derived here, so a consumer
    quoting ``basis`` is quoting the carrier and not a sentence written beside
    it.
    """

    chain_id: int
    holder_address: str
    token_address: str
    shape: str
    delivery_count: int
    unreadable_deliveries: int
    min_fan_out: int | None
    fan_out_threshold_k: int
    scanned_from_block: int
    measured_through_block: int
    basis: str

    @property
    def is_airdrop_only(self) -> bool:
        """The all-quantifier, answered from the row and from nowhere else.

        ``True`` only on the earned positive. ``has_direct_delivery`` and
        ``not_determined`` both answer ``False`` here, and they are kept apart on
        the row itself: the first is settled and the second is a gap a readable
        receipt would close.
        """
        return self.shape == DELIVERY_SHAPE_FAN_OUT_ALL


def verdict_for(deliveries: Iterable[dict[str, Any]], *, k: int = FAN_OUT_THRESHOLD_K) -> tuple[str, int | None, int]:
    """``(shape, min_fan_out, unreadable_count)`` for one pair's delivery set.

    The all-quantifier, and it FAILS CLOSED in three directions that are not the
    same fact:

    * any delivery whose receipt could not be read makes the verdict
      ``not_determined``. An unread receipt is not a small fan-out and it is not
      a large one; refusing here is the only reading that cannot publish a
      disposition over a delivery nobody measured.
    * an EMPTY delivery set is ``not_determined`` too, not vacuously true. A
      holding with no incoming Transfer on record is a holding whose arrival the
      scan cannot explain — a non-conforming token, or a mint outside the topic
      filter — and "nothing contradicted it" is not a witness.
    * one delivery below ``k`` settles the pair as ``has_direct_delivery``. That
      is an earned negative, and it is published as such rather than folded into
      the gap state.
    """
    entries = list(deliveries)
    unreadable = sum(1 for entry in entries if entry.get("fan_out_basis") != DELIVERY_FAN_OUT_BASIS_RECEIPT)
    counts = [int(entry["fan_out"]) for entry in entries if entry.get("fan_out") is not None]
    if unreadable or not entries or len(counts) != len(entries):
        return DELIVERY_SHAPE_NOT_DETERMINED, (min(counts) if counts else None), unreadable
    smallest = min(counts)
    if smallest < k:
        return DELIVERY_SHAPE_HAS_DIRECT_DELIVERY, smallest, 0
    return DELIVERY_SHAPE_FAN_OUT_ALL, smallest, 0


def record_delivery_evidence(
    session: Session,
    *,
    chain_id: int,
    holder_address: str,
    token_address: str,
    scanned_from_block: int,
    measured_through_block: int,
    deliveries: list[dict[str, Any]],
    basis: str,
    k: int = FAN_OUT_THRESHOLD_K,
) -> None:
    """Accrete one pair's evidence. Appends and advances; never rewrites.

    The row is the durable record of receipts that were read, so this function
    can do exactly two things to an existing one: add deliveries found above its
    cursor, and move the cursor forward. It never drops a delivery, never lowers
    ``measured_through_block``, and never recomputes a verdict from a smaller
    delivery set than the row already carries — the all-quantifier only ever
    gets more to quantify over.

    A cursor that would go BACKWARDS is dropped rather than applied: it would
    narrow the extent of a claim already published at a greater one.
    """
    from db.models import TokenDeliveryEvidence

    holder = str(holder_address or "").lower()
    token = str(token_address or "").lower()
    row = (
        session.query(TokenDeliveryEvidence)
        .filter(
            TokenDeliveryEvidence.chain_id == chain_id,
            TokenDeliveryEvidence.holder_address == holder,
            TokenDeliveryEvidence.token_address == token,
        )
        .one_or_none()
    )
    if row is None:
        shape, smallest, unreadable = verdict_for(deliveries, k=k)
        session.add(
            TokenDeliveryEvidence(
                chain_id=chain_id,
                holder_address=holder,
                token_address=token,
                scanned_from_block=int(scanned_from_block),
                measured_through_block=max(int(measured_through_block), int(scanned_from_block)),
                deliveries=list(deliveries),
                delivery_count=len(deliveries),
                unreadable_deliveries=unreadable,
                min_fan_out=smallest,
                fan_out_threshold_k=int(k),
                delivery_shape=shape,
                basis=basis,
            )
        )
        return

    existing = list(row.deliveries or [])
    seen = {(str(entry.get("tx")), entry.get("log_index")) for entry in existing}
    added = [entry for entry in deliveries if (str(entry.get("tx")), entry.get("log_index")) not in seen]
    if not added and int(measured_through_block) <= int(row.measured_through_block):
        return
    merged = existing + added
    shape, smallest, unreadable = verdict_for(merged, k=int(row.fan_out_threshold_k))
    row.deliveries = merged
    row.delivery_count = len(merged)
    row.unreadable_deliveries = unreadable
    row.min_fan_out = smallest
    row.delivery_shape = shape
    row.measured_through_block = max(int(row.measured_through_block), int(measured_through_block))
    row.basis = basis
    from sqlalchemy import func as _sql_func

    row.measured_at = _sql_func.now()


def load_delivery_evidence(
    session: Session, holders: Iterable[tuple[int, str]]
) -> dict[tuple[int, str, str], DeliveryFact]:
    """Every stored delivery fact for the named ``(chain_id, holder)`` accounts.

    Keyed by ``(chain_id, holder, token)`` — the ACCOUNT the read was issued
    against, never a folded entity key. A plane entity that sums two accounts
    must satisfy the predicate at each of them, and folding here would let one
    account's evidence answer for the other's holding.
    """
    from db.models import TokenDeliveryEvidence

    pairs = sorted({(int(chain_id), str(address or "").lower()) for chain_id, address in holders})
    if not pairs:
        return {}
    out: dict[tuple[int, str, str], DeliveryFact] = {}
    # Chunked: the IN-tuple list is the holder population, which is small today
    # (91 accounts) but is not bounded by anything in the schema.
    for start in range(0, len(pairs), 500):
        chunk = pairs[start : start + 500]
        rows = (
            session.query(TokenDeliveryEvidence)
            .filter(tuple_(TokenDeliveryEvidence.chain_id, TokenDeliveryEvidence.holder_address).in_(chunk))
            .order_by(TokenDeliveryEvidence.id)
            .all()
        )
        for row in rows:
            out[(int(row.chain_id), str(row.holder_address), str(row.token_address))] = DeliveryFact(
                chain_id=int(row.chain_id),
                holder_address=str(row.holder_address),
                token_address=str(row.token_address),
                shape=str(row.delivery_shape),
                delivery_count=int(row.delivery_count),
                unreadable_deliveries=int(row.unreadable_deliveries),
                min_fan_out=(None if row.min_fan_out is None else int(row.min_fan_out)),
                fan_out_threshold_k=int(row.fan_out_threshold_k),
                scanned_from_block=int(row.scanned_from_block),
                measured_through_block=int(row.measured_through_block),
                basis=str(row.basis or ""),
            )
    return out


__all__ = [
    "DELIVERY_FAN_OUT_BASIS_RECEIPT",
    "DELIVERY_FAN_OUT_BASIS_UNREADABLE",
    "FAN_OUT_CALIBRATION_CORPUS",
    "FAN_OUT_THRESHOLD_K",
    "DeliveryFact",
    "load_delivery_evidence",
    "record_delivery_evidence",
    "verdict_for",
]
