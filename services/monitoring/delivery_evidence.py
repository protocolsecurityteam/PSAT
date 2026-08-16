"""The delivery-shape evidence plane: one writer, one reader, one vocabulary.

The producers MEASURE delivery shape (``services.monitoring.delivery_shape``)
and write it here; the value plane READS it here. Both go through this module so
the all-quantifier is evaluated in exactly one place and the row's own stored
fields are what a published claim derives from.

What is stored is how a balance ARRIVED — never what it is worth. A real token
can be airdrop-delivered (measured on this corpus: HEX at fan-out 199/399/399,
uniETH at 101), so the vocabulary in :mod:`utils.balance_status` names delivery
shape and nothing else, and no consumer may rename it to "spam" or "worthless".

Two invariants govern a row, and they are opposite by design:

* the EVIDENCE accretes — delivery tallies rise, ``min_fan_out`` falls, the
  cursor advances, ``scanned_from_block`` is written once;
* the ``basis`` is RE-DERIVED on every pass from the row's own extent columns,
  so the sentence a consumer quotes always names the union extent the claim was
  earned over rather than the window of the last pass to touch the row.

Every fan-out here is a count of same-token transfer LOGS. See
:data:`FAN_OUT_THRESHOLD_K`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import tuple_
from sqlalchemy.orm import Session, load_only

from utils.balance_status import (
    DELIVERY_FAN_OUT_BASIS_RECEIPT,
    DELIVERY_FAN_OUT_BASIS_UNREADABLE,
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    DELIVERY_SHAPE_NOT_DETERMINED,
)

# --- K, the published model parameter ----------------------------------------
# The same-token transfer-LOG count above which one delivering transaction is a
# mass distribution rather than a settlement.
#
# THE METER IS LOGS. A fan-out is counted off the delivering transaction's own
# receipt as same-token 3-topic ``Transfer`` logs, so it is an UPPER BOUND on the
# distinct recipients paid: a recipient paid twice in one transaction counts
# twice. K is calibrated on that meter — every figure in the corpus below was
# measured in same-token transfer logs — so re-metering fan-out as distinct
# recipients would invalidate the calibration rather than sharpen it, and the
# interval below would have to be re-measured before K could move.
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
    "37 (holder, token) pairs probed live 2026-08-08 at tip e637585d, metered in same-token Transfer LOGS "
    "per delivering transaction "
    "(21 airdrop-side: ethereum 9 / base 8 / optimism 2; 16 real controls: ethereum 12 / optimism 2) "
    "plus 4 pairs recorded in SPAM_CLASSIFIER_FEASIBILITY.md; separation interval K in [9, 48], "
    "largest real settlement fan-out 8, smallest airdrop batch 48"
)

# How many per-delivery entries a row RETAINS in ``deliveries``.
#
# The scalars (``delivery_count``, ``unreadable_deliveries``, ``min_fan_out``)
# are the authoritative record and they count every delivery ever seen; the JSONB
# list is a bounded, deterministic SAMPLE of the entries beside them. Two reasons
# it can be bounded without losing anything the verdict rests on:
#
# * the verdict is a fold over the scalars, never a re-derivation from the stored
#   list, so a sample cannot shrink the set the all-quantifier ranged over;
# * de-duplication is bounded by ``measured_through_block`` — a later pass
#   resumes above the cursor, and any delivery at or below it was already counted
#   inside an extent that was scanned whole — so it does not need the full list
#   either.
#
# Unbounded, this column is a liability rather than a record: one optimism pair
# on the reference corpus carried 518,723 deliveries and 40 MB of JSONB in a
# single row, all of it unmetered by construction (the pair was abandoned as too
# heavy). The retained sample is chosen to be the evidence a reader needs to
# CHECK the published shape — unreadable deliveries first, then the smallest
# fan-out — so the entries that decide the verdict are the entries that survive.
DELIVERY_ENTRIES_RETAINED = 8


@dataclass(frozen=True)
class DeliveryFact:
    """One (chain, holder, token) pair's stored delivery shape, as stored.

    Every field is read off the row. Nothing is re-derived here, so a consumer
    quoting ``basis`` is quoting the carrier and not a sentence written beside
    it — and ``basis`` names ``scanned_from_block..measured_through_block``,
    the row's own extent, because :func:`compose_basis` derives it from those
    two columns at every write.

    ``min_fan_out`` is a count of same-token transfer LOGS, never of distinct
    recipients: see :data:`FAN_OUT_THRESHOLD_K`.

    ``observed_balance_raw`` is the SCANNER's bookkeeping and no part of any
    claim: it is the balance the pair was last stamped at, which is what the next
    cycle decides whether to re-scan on. No verdict reads it.

    ``caught_up`` is NOT bookkeeping. It says whether the extent reached the
    chain head, and the positive is gated on it — see :meth:`is_airdrop_only`.
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
    caught_up: bool = True
    observed_balance_raw: str | None = None

    @property
    def is_airdrop_only(self) -> bool:
        """The all-quantifier, answered from the row and from nowhere else.

        ``True`` only on the earned positive. ``has_direct_delivery`` and
        ``not_determined`` both answer ``False`` here, and they are kept apart on
        the row itself: the first is settled and the second is a gap a readable
        receipt would close.

        **AND ONLY OVER AN EXTENT THAT REACHED THE HEAD.** This is what a
        consumer DISPOSES a holding on, and a row mid-catch-up carries
        ``fan_out_all`` over a slice with millions of unexamined blocks above it.
        The verdict is true of the slice — the row is honest — but the question
        this property answers is about the holding, and the blocks nobody has
        read yet are exactly where a settlement would refute it. So a partial
        extent answers ``False`` here and turns ``True`` by itself once catch-up
        completes; nothing withdraws and nothing is re-measured.

        The gate is inside the positive arm ONLY. ``has_direct_delivery`` needs
        no such guard — it is an earned negative that one delivery below K
        already settles, and widening its extent could only confirm it.
        """
        return self.shape == DELIVERY_SHAPE_FAN_OUT_ALL and self.caught_up


@dataclass(frozen=True)
class _Tally:
    """The three scalars the verdict turns on, over SOME set of deliveries.

    Kept as a value so a pair's evidence can be folded across passes instead of
    re-derived from whatever entries a row happens to retain. Folding is what
    lets ``deliveries`` be a bounded sample: the counts carry the whole history,
    the sample carries only what a reader checks it against.
    """

    count: int
    unreadable: int
    min_fan_out: int | None


def _tally_of(deliveries: Iterable[dict[str, Any]]) -> _Tally:
    """Count one pass's entries. A delivery with no metered fan-out is unreadable."""
    count = 0
    unreadable = 0
    smallest: int | None = None
    for entry in deliveries:
        count += 1
        fan_out = entry.get("fan_out")
        if fan_out is None or entry.get("fan_out_basis") != DELIVERY_FAN_OUT_BASIS_RECEIPT:
            unreadable += 1
        if fan_out is not None:
            smallest = int(fan_out) if smallest is None else min(smallest, int(fan_out))
    return _Tally(count=count, unreadable=unreadable, min_fan_out=smallest)


def _fold(prior: _Tally, later: _Tally) -> _Tally:
    """Union two tallies. Monotone in every direction that matters.

    Counts only rise and ``min_fan_out`` only falls, so the set the
    all-quantifier ranges over only ever grows and a positive can only ever be
    withdrawn by a later pass, never manufactured by one.
    """
    if prior.min_fan_out is None:
        smallest = later.min_fan_out
    elif later.min_fan_out is None:
        smallest = prior.min_fan_out
    else:
        smallest = min(prior.min_fan_out, later.min_fan_out)
    return _Tally(
        count=prior.count + later.count,
        unreadable=prior.unreadable + later.unreadable,
        min_fan_out=smallest,
    )


def _shape_for(tally: _Tally, k: int) -> str:
    """The all-quantifier over a tally, failing closed in three directions.

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
    if tally.unreadable or tally.count == 0 or tally.min_fan_out is None:
        return DELIVERY_SHAPE_NOT_DETERMINED
    if tally.min_fan_out < k:
        return DELIVERY_SHAPE_HAS_DIRECT_DELIVERY
    return DELIVERY_SHAPE_FAN_OUT_ALL


def verdict_for(deliveries: Iterable[dict[str, Any]], *, k: int = FAN_OUT_THRESHOLD_K) -> tuple[str, int | None, int]:
    """``(shape, min_fan_out, unreadable_count)`` for one pair's delivery set.

    The all-quantifier over a single set, for callers that hold the whole set in
    hand. The write path folds tallies instead (a row's stored entries are a
    sample), and both answer through :func:`_shape_for` so there is one rule.

    ``min_fan_out`` counts same-token transfer LOGS: see
    :data:`FAN_OUT_THRESHOLD_K`.
    """
    tally = _tally_of(deliveries)
    return _shape_for(tally, k), tally.min_fan_out, tally.unreadable


def compose_basis(*, scan_basis: str, scanned_from_block: int, measured_through_block: int) -> str:
    """The stored sentence, composed FROM THE ROW'S OWN EXTENT COLUMNS.

    The extent named here is the union of every pass that ever wrote the row —
    ``scanned_from_block`` (insert-only) through ``measured_through_block`` (the
    advancing cursor) — and never the window of the pass doing the writing. A
    steady-state pass covers a few hundred blocks over a claim whose true extent
    is millions; a basis quoting the pass would narrate a scope inside which the
    deciding delivery of nearly every stored positive does not even lie.

    Because the two numbers are read off the row being written, a stored claim
    and the extent it names cannot disagree by construction.

    ``scan_basis`` is the pass-INVARIANT method note: the filter, the window
    sizing, the result cap, the fan-out meter, K. What it deliberately does NOT
    carry is a request count — a cost is a fact about one pass and this string is
    a fact about a claim assembled from many, so cost is logged
    (``delivery_shape.disposition_cost_note``) and never accreted here.
    """
    return (
        f"all-quantifier over every delivery in blocks {int(scanned_from_block)}.."
        f"{int(measured_through_block)} (the row's own measured extent, the union of every pass "
        f"that wrote it); {scan_basis}"
    )


def _set(row: Any, field: str, value: Any) -> None:
    """Assign only on a real change, so an unchanged row stays clean."""
    if getattr(row, field) != value:
        setattr(row, field, value)


def _retained(deliveries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The bounded sample a row stores: the entries a reader checks the shape by.

    Unreadable deliveries first, then the smallest fan-out, then block order —
    so whichever entry DECIDES the verdict is in the sample, and the sample is a
    deterministic function of the set rather than of the order it arrived in.
    """
    if len(deliveries) <= DELIVERY_ENTRIES_RETAINED:
        return list(deliveries)
    ordered = sorted(
        deliveries,
        key=lambda entry: (
            0 if entry.get("fan_out") is None else 1,
            int(entry.get("fan_out") or 0),
            int(entry.get("block") or 0),
            int(entry.get("log_index") or 0),
        ),
    )
    return ordered[:DELIVERY_ENTRIES_RETAINED]


def record_delivery_evidence(
    session: Session,
    *,
    chain_id: int,
    holder_address: str,
    token_address: str,
    scanned_from_block: int,
    measured_through_block: int,
    deliveries: list[dict[str, Any]],
    scan_basis: str,
    unmetered_elided: int = 0,
    k: int = FAN_OUT_THRESHOLD_K,
    observed_balance_raw: str | None = None,
    caught_up: bool | None = None,
) -> None:
    """Accrete one pair's evidence. THE TRUE INVARIANT, stated exactly.

    What ACCRETES and is never taken back: the evidence itself — the tally of
    deliveries seen, the tally of deliveries nobody could meter, the smallest
    fan-out on record — and ``measured_through_block``, the cursor. Counts only
    rise, ``min_fan_out`` only falls, the cursor only advances, and
    ``scanned_from_block`` is written once at insert and never again. So the set
    the all-quantifier ranges over only ever grows, and a later pass can withdraw
    a positive but can never manufacture one. A cursor that would go BACKWARDS is
    dropped rather than applied: it would narrow the extent of a claim already
    published at a greater one.

    What is RE-DERIVED on every pass, deliberately: ``basis``. It is composed by
    :func:`compose_basis` from this row's own extent columns, so it names the
    union extent rather than the window of whichever pass happened to run. A pass
    that finds nothing new still rewrites it — that costs no chain request and is
    what repairs a row whose stored sentence was authored under an older rule.

    What is BOUNDED, not accreted: the ``deliveries`` JSONB, which retains
    :data:`DELIVERY_ENTRIES_RETAINED` entries as a sample. The scalars above are
    the record; see that constant for why bounding them loses nothing the verdict
    or the de-duplication rests on.

    ``unmetered_elided`` is the count of deliveries the caller SAW but did not
    build an entry for, none of them metered — an abandoned heavy pair reports
    its full delivery count that way instead of materialising hundreds of
    thousands of entries. They are folded in as unreadable, which is the truth
    and which forces ``not_determined``.

    ``caught_up`` and ``observed_balance_raw`` are the SKIP keys, and neither is
    evidence — no verdict reads them. ``caught_up`` is False when
    ``measured_through_block`` is a slice boundary rather than the head; ``None``
    means this call did not scan (a pair presented only so its basis is
    re-derived) and the stored answer stands. ``observed_balance_raw`` is
    stamped only where the row is being rewritten anyway, because a stamp is not
    worth an UPDATE of its own over the whole unpriced population.
    """
    from db.models import TokenDeliveryEvidence

    holder = str(holder_address or "").lower()
    token = str(token_address or "").lower()
    elided = _Tally(count=max(0, int(unmetered_elided)), unreadable=max(0, int(unmetered_elided)), min_fan_out=None)
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
        from_block = int(scanned_from_block)
        through = max(int(measured_through_block), from_block)
        tally = _fold(_tally_of(deliveries), elided)
        session.add(
            TokenDeliveryEvidence(
                chain_id=chain_id,
                holder_address=holder,
                token_address=token,
                scanned_from_block=from_block,
                measured_through_block=through,
                deliveries=_retained(list(deliveries)),
                delivery_count=tally.count,
                unreadable_deliveries=tally.unreadable,
                min_fan_out=tally.min_fan_out,
                fan_out_threshold_k=int(k),
                delivery_shape=_shape_for(tally, int(k)),
                observed_balance_raw=observed_balance_raw,
                caught_up=True if caught_up is None else bool(caught_up),
                basis=compose_basis(
                    scan_basis=scan_basis, scanned_from_block=from_block, measured_through_block=through
                ),
            )
        )
        return

    row_k = int(row.fan_out_threshold_k)
    cursor = int(row.measured_through_block)
    existing = list(row.deliveries or [])
    seen = {(str(entry.get("tx")), entry.get("log_index")) for entry in existing}
    # Two guards, and the first is the load-bearing one now that the stored
    # entries are a sample: a delivery at or below the cursor lies inside an
    # extent a previous pass proved whole, so it is already in the row's tally
    # whether or not it survived into the sample.
    added = [
        entry
        for entry in deliveries
        if int(entry.get("block") or 0) > cursor and (str(entry.get("tx")), entry.get("log_index")) not in seen
    ]
    through = max(cursor, int(measured_through_block))
    tally = _fold(
        _Tally(
            count=int(row.delivery_count),
            unreadable=int(row.unreadable_deliveries),
            min_fan_out=None if row.min_fan_out is None else int(row.min_fan_out),
        ),
        _fold(_tally_of(added), elided),
    )
    # Assigned only where the value actually moves, so a cycle that measures
    # nothing new and finds the sentence already correct leaves the row clean and
    # issues no UPDATE at all — the population is every unpriced pair the
    # protocol holds, and re-writing all of them hourly for no change is a cost
    # with no claim behind it.
    _set(row, "delivery_count", tally.count)
    _set(row, "unreadable_deliveries", tally.unreadable)
    _set(row, "min_fan_out", tally.min_fan_out)
    _set(row, "delivery_shape", _shape_for(tally, row_k))
    _set(row, "measured_through_block", through)
    if caught_up is not None:
        _set(row, "caught_up", bool(caught_up))
    # Re-derived every pass, from the row's own columns as they now stand.
    _set(
        row,
        "basis",
        compose_basis(
            scan_basis=scan_basis, scanned_from_block=int(row.scanned_from_block), measured_through_block=through
        ),
    )
    if added or len(existing) > DELIVERY_ENTRIES_RETAINED:
        # Rewritten when there is something new to sample, and when the stored
        # list predates the retention bound — the second arm is what shrinks the
        # rows an unbounded write left behind, through this path and no other.
        row.deliveries = _retained(existing + added)
    if observed_balance_raw is not None and session.is_modified(row):
        # Stamped only onto a row this pass was rewriting anyway. The stamp is a
        # skip key rather than a fact anything publishes, and buying it with an
        # UPDATE per cycle over every unpriced pair the protocol holds is the
        # cost the skip exists to remove.
        _set(row, "observed_balance_raw", observed_balance_raw)
    if added or elided.count or through > cursor:
        from sqlalchemy import func as _sql_func

        # Stamped only when a MEASUREMENT moved. Re-deriving a sentence is not a
        # new observation, and dating it as one would age every untouched row.
        row.measured_at = _sql_func.now()


def load_delivery_evidence(
    session: Session, holders: Iterable[tuple[int, str]]
) -> dict[tuple[int, str, str], DeliveryFact]:
    """Every stored delivery fact for the named ``(chain_id, holder)`` accounts.

    Keyed by ``(chain_id, holder, token)`` — the ACCOUNT the read was issued
    against, never a folded entity key. A plane entity that sums two accounts
    must satisfy the predicate at each of them, and folding here would let one
    account's evidence answer for the other's holding.

    Only the scalar columns are selected. ``DeliveryFact`` carries no delivery
    list, and this loader is on an API path: fetching and deserialising the
    ``deliveries`` JSONB for rows nothing reads it from measured 0.86 s on the
    reference corpus, all of it spent on a column the caller never sees.
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
            .options(
                load_only(
                    TokenDeliveryEvidence.chain_id,
                    TokenDeliveryEvidence.holder_address,
                    TokenDeliveryEvidence.token_address,
                    TokenDeliveryEvidence.delivery_shape,
                    TokenDeliveryEvidence.delivery_count,
                    TokenDeliveryEvidence.unreadable_deliveries,
                    TokenDeliveryEvidence.min_fan_out,
                    TokenDeliveryEvidence.fan_out_threshold_k,
                    TokenDeliveryEvidence.scanned_from_block,
                    TokenDeliveryEvidence.measured_through_block,
                    TokenDeliveryEvidence.basis,
                    TokenDeliveryEvidence.caught_up,
                    TokenDeliveryEvidence.observed_balance_raw,
                )
            )
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
                caught_up=bool(row.caught_up),
                observed_balance_raw=(None if row.observed_balance_raw is None else str(row.observed_balance_raw)),
            )
    return out


__all__ = [
    "DELIVERY_ENTRIES_RETAINED",
    "DELIVERY_FAN_OUT_BASIS_RECEIPT",
    "DELIVERY_FAN_OUT_BASIS_UNREADABLE",
    "FAN_OUT_CALIBRATION_CORPUS",
    "FAN_OUT_THRESHOLD_K",
    "DeliveryFact",
    "compose_basis",
    "load_delivery_evidence",
    "record_delivery_evidence",
    "verdict_for",
]
