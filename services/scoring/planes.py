"""The resolution planes the Layer-2 fold reads to resolve a signal's references.

Signals carry references — ``function_principals`` ids and ``<chain>::<address>``
entity keys — so the fold is the first place that can turn them into units,
dollars and breadth. Every read here is ordered, read-only, and publishes its
own three-state: an unreadable or absent witness lands on ``not_determined`` and
is counted in the provenance block rather than defaulted to a number.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Text, tuple_
from sqlalchemy import false as sql_false
from sqlalchemy import func as sql_func
from sqlalchemy import or_ as sql_or
from sqlalchemy.orm import Session

from services.scoring.schema import NOT_DETERMINED, Tri, coalesce_chain, entity_key, is_entity_key
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    SWEEP_STATUS_COMPLETED,
    TYPED_PER_ID_BASES,
)
from utils.scoring_status import (
    PERIMETER_NOT_DETERMINED,
    PERIMETER_SETTLED,
    PERIMETER_UNSETTLED,
)

if TYPE_CHECKING:
    from services.scoring.distill import ProtocolUniverse

# Confined to the I/O-EDGE loaders in this module — the handlers that swallow a
# database error while reading a plane. The resolution work itself publishes
# every refusal into the document (inv. 11/12: the fold must replay from the
# document alone), so nothing on a compute path logs. These WARNINGs carry no
# ``record_degraded`` because no accumulator is bound here today: the fold runs
# on the score loop's monitor thread and under the offline CLI, and the call
# would be a permanent no-op rather than a record of anything.
logger = logging.getLogger(__name__)

NATIVE_ASSET = "native"

ZERO_ADDRESS = "0x" + "0" * 40

# Control relations that carry authority. ``safe_owner`` is excluded (one owner
# does not satisfy k-of-n) and ``controller_value_unattributed`` is excluded
# (real principals whose authority RELATION was never established — a confidence
# item, not an edge).
CONTROL_RELATIONS = ("controller_value", "role_principal", "mapping_member")

# Why each relation this scorer knows of is NOT walked as reach. The map is a
# vocabulary of reasons, not the published set: ``unconsumed_reach_relations``
# enumerates from what the DATABASE holds (plus every relation the graph writer
# can emit), so a relation nobody has classified still gets published with its
# count rather than being dropped for want of an entry here.
UNCONSUMED_REACH_REASONS: dict[str, str] = {
    "safe_owner": (
        "one owner is not the unit that can act: a k-of-n Safe's authority is folded at "
        "the Safe, and a single owner edge would publish reach that owner cannot exercise "
        "alone. The Safe itself reaches through its own controller_value edges"
    ),
    "controller_value_unattributed": (
        "the principal is real but the authority RELATION behind it was never established "
        "— the label names a value the anchor holds (including dotted paths like "
        "'accountantState.payoutAddress'), not a proven authority over the anchor. An "
        "unestablished relation is a confidence item, never an edge"
    ),
    "external_call_target": (
        "direction: the anchor CALLS the target. Being called is not being controlled, so "
        "walking it as reach would invert the authority arrow"
    ),
    "capability_principal": (
        "a FUNCTION-level claim — this address is a resolved principal of a gated function "
        "on the anchor — not proof of authority over the anchor ENTITY, which is what this "
        "closure walks. Declining it costs confidence rather than earning it: the perimeter "
        "counts the relation whether or not the walk consumes it. The rationale published "
        "before model_version 1.1.0 — that the population is materialization-budget gated "
        "(PSAT_FP_MATERIALIZE_LIMIT) — is WITHDRAWN as refuted: the limit is not reached on "
        "any corpus measured, and the same spawn budget gates every relation equally, so it "
        "never distinguished this one"
    ),
    "timelock_owner": (
        "in the graph writer's authority allowlist (db.CONTROL_EDGE_RELATIONS) but not in "
        "this scorer's consumed set. It carries no rows on any corpus measured; this entry "
        "exists so the day it does, the exclusion is a stated one and not a silent drop"
    ),
    "proxy_admin_owner": (
        "in the graph writer's authority allowlist (db.CONTROL_EDGE_RELATIONS) but not in "
        "this scorer's consumed set. It carries no rows on any corpus measured; this entry "
        "exists so the day it does, the exclusion is a stated one and not a silent drop"
    ),
}

UNCONSUMED_REASON_UNCLASSIFIED = (
    "present in this protocol's control_graph_edges but classified by neither this scorer's "
    "consumed set nor its exclusion register — published with its count so an unrecognised "
    "relation is visible rather than silently unwalked"
)

# --- what one (entity, asset) reading proves ---------------------------------
# ``usd_value`` is a scaled decimal column, so a 0.00 reading may be its STORAGE
# FLOOR rather than a number — a holding below the column's last digit stores
# indistinguishably from a holding of nothing. The column is numeric(38,18)
# today, which puts that floor below any dollar figure a price feed can produce,
# but the discrimination stays: the QUANTITY is what separates the two cases — a
# proven-zero raw balance is worth zero at any price — so a 0.00 reading is only
# ever a determined zero when the quantity proves it, and is otherwise below the
# column's resolution.
ASSET_PRICED = "priced"
ASSET_BELOW_RESOLUTION = "priced_below_resolution"
ASSET_PROVEN_ZERO = "proven_zero"
ASSET_UNPRICED = "unpriced"
# Every incoming delivery of this asset to this entity's accounts arrived in a
# transaction carrying at least K same-token transfer LOGS. The log count is the
# meter — it is what the calibration corpus was measured in — and it is an UPPER
# BOUND on the distinct recipients of that transaction, never a count of them:
# one recipient credited twice raises the meter and lowers nothing.
#
# The claim is DELIVERY SHAPE and nothing else — never worth, never "spam",
# never "scam", never "worthless". The reference corpus carries a class of FIVE
# demonstrably real tokens with this delivery shape, of which the
# protocol-reference conjunct spares three and condemns two: HEX (fan-out 199
# x13, 399 x14, 400 x1, 500 x6), WETH and base USDC are spared; uniETH (one
# delivery, 101) and USDtb (one delivery, 175) are in this state. Any
# worth-naming would be a lie about all five; "arrived by mass distribution" is
# true of every member, spared or not.
ASSET_AIRDROP_DELIVERED = "airdrop_delivered"

# --- what a whole balance sheet proves ---------------------------------------
SHEET_PRICED = "priced"
SHEET_BELOW_RESOLUTION = "priced_below_resolution"
SHEET_UNPRICED = "unpriced"
SHEET_PROVEN_EMPTY = "proven_empty"
SHEET_NO_ROWS = "no_rows"
# The sixth state, and DISTINCT from ``proven_empty`` all the way to the
# consumer: they are different witnesses. Proven-empty says nothing ever arrived
# (every quantity witnessed zero over a list proven whole); this says what DID
# arrive arrived as a mass distribution, so the sheet's determined content is
# nil. Collapsing them would publish one witness under the other's name.
SHEET_AIRDROP_DETERMINED = "airdrop_determined"

# The states in which a sheet total is NOT a number. Kept apart from each other
# all the way to the consumer: "every price lookup answered below the column's
# resolution" and "no price lookup answered" are different facts, and neither is
# "proven to hold nothing".
SHEET_NOT_DETERMINED = (SHEET_BELOW_RESOLUTION, SHEET_UNPRICED, SHEET_NO_ROWS)

# --- why a sheet that observed only zeros may still not be published empty ----
# "Holds nothing" is the strongest negative on this plane, so it is the claim
# with the most ways to be wrong, and each way is closed by different work: a
# chain scan, a typed-receipt read, and the restaking pricing pass. They are
# named apart rather than folded into one boolean because the refusal census is
# the work list. A sheet refused here publishes ``unpriced`` — something WAS
# observed at the entity and no number covers it, which is what that state
# means — never ``proven_empty`` and never a $0.
EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE = "asset_set_not_proven_complete"
EMPTY_REFUSED_UNSCANNED_ACCOUNT = "folded_account_never_scanned"
EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED = "typed_receipt_unresolved"
EMPTY_REFUSED_UNPRICED_POSITIONS = "unpriced_positions_at_this_entity"
EMPTY_REFUSALS = (
    EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE,
    EMPTY_REFUSED_UNSCANNED_ACCOUNT,
    EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED,
    EMPTY_REFUSED_UNPRICED_POSITIONS,
)

# --- why a sheet whose every reading is disposed may still not be determined --
# The disposition claim has its OWN conjuncts and they are NOT proven-empty's,
# which is why they are named apart rather than reusing the tokens above. The
# completeness conjunct in particular is a different question: proven-empty
# needs the asset LIST proven whole, because zeros over a list nobody
# established say nothing; a disposition says only that the readings that ARE on
# the sheet contribute nothing, so what it needs is that the list was not
# observably CUT OFF. Requiring the stronger witness here would refuse every
# sheet on the reference corpus (the sweep publishes ``returned_assets`` as
# not_determined by design), so the claim is scoped in the basis instead: the
# asset set is Etherscan-page-derived and is not proven whole.
DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED = "typed_receipt_unresolved"
DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED = "asset_list_truncated"
DISPOSITION_REFUSED_UNSCANNED_ACCOUNT = "folded_account_never_scanned"
DISPOSITION_REFUSED_UNPRICED_POSITIONS = "unpriced_positions_at_this_entity"
DISPOSITION_REFUSALS = (
    DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED,
    DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED,
    DISPOSITION_REFUSED_UNSCANNED_ACCOUNT,
    DISPOSITION_REFUSED_UNPRICED_POSITIONS,
)


def typed_receipt_is_resolved(entry: Any) -> bool:
    """Whether one ERC-721/1155 receipt's CURRENT holding is a resolved zero.

    The receipt itself is immutable evidence that a typed token once ARRIVED;
    what decides an empty sheet is whether it is still held. Exactly one shape
    resolves it: the quantity was readable AND it read zero — the token arrived
    and provably left. Everything else refuses, and the two failing shapes are
    different facts: an unreadable quantity (ERC-1155 has no
    ``balanceOf(address)`` at all, so the call reverts) is not determined, and a
    readable NON-zero one is a held item this plane cannot price. Neither may
    stand behind "holds nothing".

    A quantity read PER TOKEN ID carries one more condition, derived from the
    record rather than trusted: summing an id inventory is an all-quantifier over
    it, so it says nothing at all unless the record also says the inventory is
    whole. A per-id zero over a PREFIX of the ids is the shape that would publish
    "holds nothing" over ids nobody read, so it is refused here as well as at the
    producer — the published claim derives from the carrier's own fields.
    """
    if not isinstance(entry, dict):
        return False
    if entry.get("quantity_readable") is not True:
        return False
    if entry.get("quantity_basis") in TYPED_PER_ID_BASES and entry.get("ids_complete") is not True:
        return False
    try:
        return float(str(entry.get("quantity"))) == 0.0
    except (TypeError, ValueError):
        return False


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# The presentation rounding this plane applies to dollar figures. Six decimals
# tames float-sum noise on figures a consumer reads, and that is all it is for —
# so it is not allowed to change what the figure PROVES. A determined non-zero
# holding rounded to 0.0 stops being a number and starts being an absence, which
# is a different claim about the entity than the one that was measured; below the
# rounding's own resolution the unrounded figure is therefore what stands.
_PRESENTATION_DECIMALS = 6


def _round_presented(value: float) -> float:
    """Round for presentation, never onto zero."""
    rounded = round(value, _PRESENTATION_DECIMALS)
    return rounded if rounded != 0.0 or value == 0.0 else value


@dataclass
class ValuePlane:
    """Per-entity value, reduced to the LATEST observation per (entity, asset).

    ``contract_entities`` is every entity the protocol's ``contracts`` rows name,
    priced or not. It is the confidence perimeter's base population: discovery
    fixes it, so it does not move with what has been analysed, and an unpriced
    contract outside the control closure still carries its unanswered weight
    instead of vanishing from its own denominator.

    ``per_asset`` carries only DETERMINED dollar readings — an asset whose price
    lookup never answered, or answered below the storage column's resolution, is
    absent from it and named in ``per_asset_state`` instead. The two together are
    the three-state: a number, a stated reason there is no number, or no row at
    all. A key present in ``per_asset`` with no ``per_asset_state`` entry (a
    hand-built plane) is read as determined, which is what that map means.
    """

    contract_entities: set[str] = field(default_factory=set)
    per_asset: dict[str, dict[str, float]] = field(default_factory=dict)
    per_asset_state: dict[str, dict[str, str]] = field(default_factory=dict)
    native_fact: dict[str, str] = field(default_factory=dict)
    # Entities whose latest asset-list read came back AT the endpoint's page cap:
    # the list is a prefix of what they hold, so the rows below it are a floor
    # over the sheet and nothing here bounds it from above. Only the truncated
    # case is carried, in one direction: a page shorter than the cap witnesses
    # that THIS read was not cut off and never that the index is complete, so
    # absence from this set is not a completeness witness (``balance_status``
    # registers no ``complete`` token for the same reason).
    asset_set_truncated: set[str] = field(default_factory=set)
    # The other direction, and NOT the negation of the set above: entities whose
    # ERC-20 asset list is proven WHOLE by the chain's own transfer history
    # through a named block. Absence from ``asset_set_truncated`` says only that
    # no read reported a cap; membership here is an earned positive, and it is
    # the only witness under which an empty sheet may be published as $0 (§2 of
    # SHEET_OBSERVATION_SPEC.md: a third-party index's empty answer is a trigger
    # to scan, never the proof). The value is the CARRIER's own record — the
    # source token, the scanned block range and the fetch's basis string — so a
    # published claim derives from stored evidence rather than being re-authored
    # here.
    asset_set_proven_complete: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Accounts of a sheet that a scan reached at some OTHER account but never at
    # their own address. Kept as its own map, and as its own refusal token, so
    # "one of this sheet's two accounts was never looked at" cannot be read as
    # "nobody has scanned this sheet" — they are closed by different work, and
    # the first is the one that silently publishes a $0 over an address nothing
    # has ever read.
    asset_set_accounts_unscanned: dict[str, list[str]] = field(default_factory=dict)
    # ERC-721/1155 receipts at an entity whose CURRENT holding is not resolved.
    # A receipt proves a typed token arrived; until its holding reads back zero
    # the entity may hold it, so "holds nothing" is false and the sheet refuses
    # ``proven_empty``. Their counts are never summed into a USD total either —
    # ``balanceOf`` on a 721 answers a COUNT of items, not a quantity of anything
    # priceable — so they publish as unpriced and never as dollars.
    typed_receipts_unresolved: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    alias: dict[str, str] = field(default_factory=dict)
    # Implementation keys TWO proxies share. There is no proxy to fold them onto
    # — pinning one is a coin toss that charges the loser's sheet — so they are
    # named here and aliased nowhere.
    alias_ambiguous: set[str] = field(default_factory=set)
    unpriced_positions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Per (canonical entity, asset), the CARRIER RECORD of the delivery evidence
    # that disposed that reading — the shape, K, the smallest fan-out measured,
    # the delivery count, the block range the receipts were read across, the
    # accounts the evidence was held at, and the carriers' own basis strings.
    # Everything a narration says about a disposition derives from these fields,
    # so a published sentence quotes the evidence rather than a claim authored
    # beside it. Empty unless a universe was supplied to the loader: no universe,
    # no condemnation.
    asset_disposition: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    annotations: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def canonical(self, key: str) -> str:
        """An implementation's key folds onto the proxy that deploys it.

        Resolved to a FIXED POINT at load: ``J -> I`` beside ``I -> P`` answers
        ``P`` here and not ``I``, so a two-step alias chain cannot orphan J's
        balances at a key nothing else folds onto while P is counted twice.
        A key in ``alias_ambiguous`` folds onto nothing — two proxies share that
        implementation and neither owns it.
        """
        return self.alias.get(key, key)

    def asset_set_is_truncated(self, key: str) -> bool:
        """Whether the entity's asset list is known to be cut off at the page cap.

        Read at the CANONICAL key, as every other sheet question is: a proxy and
        its implementation are one sheet, and a truncated read of either account
        truncates the list that sheet is assembled from.

        The answer is one-directional. ``True`` is a witness — a stored fetch
        record reported the page at its cap — and ``False`` is only the absence
        of that witness, never a proof that the list is whole.
        """
        return self.canonical(key) in self.asset_set_truncated

    def asset_set_is_proven_complete(self, key: str) -> bool:
        """Whether the chain's own log history proves this sheet's asset list whole.

        Read at the CANONICAL key, and EARNED there: a sheet assembled from two
        accounts is proven complete only where every account that contributes to
        it was scanned, because one unscanned account leaves the list a floor.
        ``False`` is not "the list is incomplete" — it is the absence of the
        scan, which is a third state (:data:`asset_set_truncated` carries the
        proven-incomplete one).
        """
        return self.canonical(key) in self.asset_set_proven_complete

    def unresolved_typed_receipts(self, key: str) -> list[dict[str, Any]]:
        """The ERC-721/1155 receipts at this entity that are not resolved to zero."""
        return self.typed_receipts_unresolved.get(self.canonical(key)) or []

    def proven_empty_refusal(self, key: str) -> str | None:
        """Why this entity's sheet may not be published as a proven $0, or ``None``.

        The conjuncts of the empty claim, each answered from its own witness and
        each fail-closed. They are asked in the order that names the ACTIONABLE
        cause rather than the order they are logically nested in, because the
        token is published and a reader acts on it:

        * a typed ERC-721/1155 receipt nobody could resolve is asked first. It is
          the reason the producer withheld the scan's completeness in the first
          place, so answering "nothing scanned this" there would point a reader
          at a scan that ran and send them to the wrong pipeline.
        * an account of this sheet that no scan reached at its own address is
          asked next: a named, closable gap in a scan that otherwise ran.
        * the generic refusal — no scan on record at all — is what is left.
        * the cross-plane one is last: the restaking plane already publishes
          quantities at this node with no USD column, and a $0 sheet beside them
          would contradict a plane already in the same document.

        Deliberately NOT a conjunct: the third-party index's empty answer. It is
        the trigger that sends the producer to the chain and never the proof, so
        a sheet the scan proves empty publishes whether Etherscan answered
        ``empty``, answered at its page cap, or never answered at all.
        """
        canonical = self.canonical(key)
        if self.typed_receipts_unresolved.get(canonical):
            return EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED
        if canonical not in self.asset_set_proven_complete:
            if self.asset_set_accounts_unscanned.get(canonical):
                return EMPTY_REFUSED_UNSCANNED_ACCOUNT
            return EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE
        if self.unpriced_positions.get(canonical):
            return EMPTY_REFUSED_UNPRICED_POSITIONS
        return None

    def asset_is_disposed(self, key: str, asset: str) -> bool:
        """Whether THIS reading's every incoming delivery was a mass distribution.

        Read at the canonical key, like every other sheet question. ``False`` is
        the absence of the evidence and never a proof that the asset arrived
        some other way.
        """
        return asset in (self.asset_disposition.get(self.canonical(key)) or {})

    def disposition_refusal(self, key: str) -> str | None:
        """Why this sheet's dispositions may not DETERMINE it, or ``None``.

        The disposition claim's own conjuncts, in the order that names the
        ACTIONABLE cause rather than the order they nest in:

        * a typed ERC-721/1155 receipt nobody could resolve. A disposition is a
          fact about fungible deliveries and says nothing about an item the
          entity may still hold, so a sheet carrying one is not determined at
          any total.
        * an asset list read AT the endpoint's page cap. The rows are a PREFIX
          of the holdings, so disposing every one of them says nothing about the
          entries the page never reached. This is the D1-parity gate, and it is
          the only completeness conjunct: the stronger "list proven whole" is
          not available on this corpus, so the claim is scoped in the basis
          instead of being refused into silence.
        * an account of this sheet that no scan reached at its own address — a
          named, closable gap in a scan that otherwise ran.
        * the cross-plane one, last: the restaking plane publishes quantities at
          this node with no USD column, and a determined sheet beside them would
          contradict a plane already in the same document.
        """
        canonical = self.canonical(key)
        if self.typed_receipts_unresolved.get(canonical):
            return DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED
        if canonical in self.asset_set_truncated:
            return DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED
        if self.asset_set_accounts_unscanned.get(canonical):
            return DISPOSITION_REFUSED_UNSCANNED_ACCOUNT
        if self.unpriced_positions.get(canonical):
            return DISPOSITION_REFUSED_UNPRICED_POSITIONS
        return None

    def sheet_state(self, key: str) -> str:
        """What the entity's balance sheet PROVES, in one of six states.

        ``priced`` — at least one determined non-zero reading, so ``total`` is a
        floor over what was priced. ``priced_below_resolution`` — every price
        lookup that answered landed on the storage column's floor, which is a
        holding of *at most* that floor per row and never a proven zero.
        ``unpriced`` — rows exist and no lookup answered. ``proven_empty`` — every
        asset's QUANTITY is proven zero AND the asset list those quantities cover
        is proven whole, the only witness under which 0.00 is a number rather
        than a rounding artefact. ``airdrop_determined`` — every asset left on
        the sheet either arrived only in mass distributions or is a witnessed
        zero. ``no_rows`` — nothing observed.

        The priced branch asks the reading's STATE first and its magnitude only
        as a second carrier. A determined non-zero reading small enough for some
        presentation rounding to render it 0.0 is still a determined non-zero
        reading, and a branch that could only see the float would let it fall
        through to the branches below — where, with the completeness conjunct
        satisfied, it would publish ``proven_empty``: "every asset's quantity is
        proven zero" asserted of a sheet whose quantity was proven NOT zero. The
        magnitude may be rounded; the witness may not be. The magnitude arm stays
        because a plane may carry values without the state map beside them, and a
        determined non-zero dollar figure is itself a priced reading's witness.

        ``proven_empty`` and ``airdrop_determined`` are DIFFERENT witnesses and
        never collapse: "nothing ever arrived" is not "what arrived arrived as a
        mass distribution", and only the first says the accounts are bare. The
        disposition arm is asked AFTER ``priced_below_resolution`` and
        ``unpriced``, so a sheet holding disposed readings beside one asset
        nobody priced stays ``unpriced`` — the disposition covers the readings it
        names and nothing else.

        The empty claim is the only one with a SET conjunct, and it is fail-
        closed: zeros over a list nobody established say nothing about the
        entity, so a refused empty publishes ``unpriced`` — something was
        observed here and no number covers it — never a $0. The refusal is
        reasoned in :meth:`proven_empty_refusal`; a hand-built plane that carries
        no completeness witness therefore answers ``unpriced``, which is the
        direction that cannot publish a false negative.
        """
        canonical = self.canonical(key)
        values = self.per_asset.get(canonical) or {}
        states = self.per_asset_state.get(canonical) or {}
        if any(state == ASSET_PRICED for state in states.values()) or any(value != 0.0 for value in values.values()):
            return SHEET_PRICED
        if any(state == ASSET_BELOW_RESOLUTION for state in states.values()):
            return SHEET_BELOW_RESOLUTION
        if any(state == ASSET_UNPRICED for state in states.values()):
            return SHEET_UNPRICED
        if any(state == ASSET_AIRDROP_DELIVERED for state in states.values()) and all(
            state in (ASSET_AIRDROP_DELIVERED, ASSET_PROVEN_ZERO) for state in states.values()
        ):
            # Refused, this sheet publishes ``unpriced``: something WAS observed
            # here and no number covers it, which is what that state means. The
            # direction that cannot publish a false determination.
            return SHEET_AIRDROP_DETERMINED if self.disposition_refusal(canonical) is None else SHEET_UNPRICED
        if values or any(state == ASSET_PROVEN_ZERO for state in states.values()):
            return SHEET_PROVEN_EMPTY if self.proven_empty_refusal(canonical) is None else SHEET_UNPRICED
        if self.typed_receipts_unresolved.get(canonical):
            # No fungible reading at all, and a typed receipt that may still be
            # held. ``no_rows`` would say nothing was observed here, which is
            # false: an ERC-721/1155 arrival is on record and its current holding
            # is the part nobody answered.
            return SHEET_UNPRICED
        return SHEET_NO_ROWS

    def total(self, key: str) -> float | None:
        """The entity's priced holdings, or ``None`` when they are not a number.

        ``None`` is not zero, and the three ways of not being a number are kept
        apart in ``sheet_state``: an entity whose every row is unpriced, one whose
        every price rounded to the storage floor, and one proven to hold nothing
        are different facts, and only the last may reach a consumer as ``0.0``.

        A sheet whose every reading is disposed answers ``0.0`` too, under its
        own state and its own witness: the determined content of the sheet is
        nil. What that number may be USED for is narrower than what a priced
        total may be used for — see :meth:`trimming_total`.
        """
        state = self.sheet_state(key)
        if state in (SHEET_PROVEN_EMPTY, SHEET_AIRDROP_DETERMINED):
            return 0.0
        if state in SHEET_NOT_DETERMINED:
            return None
        assets = self.per_asset.get(self.canonical(key)) or {}
        return _round_presented(sum(sorted(assets.values())))

    def trimming_total(self, key: str) -> float | None:
        """:meth:`total`, except that a DISPOSED sheet trims nothing.

        The two accessors differ on exactly one state, and the difference is the
        difference between two questions a sheet is asked.

        ``total`` answers "what does this entity HOLD, as a determined figure" —
        and on an ``airdrop_determined`` sheet a determined $0 is the honest
        answer: nothing on it carries a number, and what is on it arrived as a
        mass distribution.

        A trim site asks something else: "how much is there to MOVE", used to
        bound a witnessed magnitude from above. The disposed assets are still
        HELD — a delivery-shape claim says how they arrived and never that they
        are worth nothing, and two of the tokens measured into this state are
        real — so trimming a witnessed magnitude to $0 here would publish "this
        call moves nothing" on the strength of evidence that says no such thing.
        A determined $0 is a real ceiling on what the sheet HOLDS and is not a
        witness of what is there to MOVE, so the trim sites get ``None`` and the
        witness stands alone.
        """
        if self.sheet_state(key) == SHEET_AIRDROP_DETERMINED:
            return None
        return self.total(key)

    @property
    def tracked_total(self) -> float:
        # Only entities with a determined total enter the denominator. One whose
        # total is not a number contributes nothing rather than a zero, so the
        # ratio is over what was measured.
        totals = [self.total(k) for k in set(self.per_asset) | set(self.per_asset_state)]
        return round(sum(sorted(t for t in totals if t is not None)), 2)


# --- the sheet ceiling -------------------------------------------------------
# The closed vocabulary ``ceiling_for`` answers in. Three of the eight are
# ADMITS and five are refusals, and the split is not readable from the names —
# ``no_rows``, ``below_resolution`` and ``unpriced`` refuse for three different
# unmeasured reasons and ``asset_list_truncated`` for a fourth, while
# ``proven_empty`` and ``airdrop_determined`` are EARNED NEGATIVES that admit a
# $0 ceiling on two different witnesses. Kept as eight tokens rather than a bool
# plus a note because the refusals are the work list: "no balance was ever
# observed", "the price lookup never answered" and "the asset list was cut off
# at the endpoint's page cap" are answered by different pipelines.
CEILING_ADMITTED = "admitted"
CEILING_PROVEN_EMPTY = "proven_empty"
# The third admit. Grouped with the admits below because it produces a figure:
# the sheet's determined content is nil. Its claim is DELIVERY SHAPE and never
# worth — see :data:`ASSET_AIRDROP_DELIVERED`.
CEILING_AIRDROP_DETERMINED = "airdrop_determined"
CEILING_NO_ROWS = "no_rows"
CEILING_BELOW_RESOLUTION = "below_resolution"
CEILING_UNPRICED = "unpriced"
CEILING_ASSET_LIST_TRUNCATED = "asset_list_truncated"
CEILING_ALIAS_AMBIGUOUS = "alias_ambiguous"

CEILING_REASONS = (
    CEILING_ADMITTED,
    CEILING_PROVEN_EMPTY,
    CEILING_AIRDROP_DETERMINED,
    CEILING_NO_ROWS,
    CEILING_BELOW_RESOLUTION,
    CEILING_UNPRICED,
    CEILING_ASSET_LIST_TRUNCATED,
    CEILING_ALIAS_AMBIGUOUS,
)

# The reasons under which a ceiling WAS established. Named, because a census that
# counted admits by testing ``reason == "admitted"`` would drop every proven-zero
# ceiling into the refusals and report an under-claim as a coverage gap.
CEILING_ADMITTING_REASONS = (CEILING_ADMITTED, CEILING_PROVEN_EMPTY, CEILING_AIRDROP_DETERMINED)

# The three sheet states that are not a number, each under its own token. A
# ``.get`` with a default would let a sixth sheet state refuse under a reason
# written for a different fact, so an unregistered state raises instead.
_CEILING_REFUSALS: dict[str, str] = {
    SHEET_NO_ROWS: CEILING_NO_ROWS,
    SHEET_BELOW_RESOLUTION: CEILING_BELOW_RESOLUTION,
    SHEET_UNPRICED: CEILING_UNPRICED,
}


def ceiling_for(plane: ValuePlane, key: str) -> tuple[float | None, str]:
    """The most an entity's own priced sheet can bound a code seizure at.

    Answers ONLY the value-side conjuncts of the admission rule: that the sheet
    is determined, and that the key is not an implementation two proxies share.
    The capability-side conjuncts — that the capability is code control, and that
    it is proven for this principal over this node — are the caller's, and this
    function must never be read as having checked them.

    ``(usd, reason)``, with ``reason`` from ``CEILING_REASONS`` and ``usd`` a
    number on exactly the two admitting reasons, so a caller may branch on
    ``usd is not None`` and get the same answer the reason gives. The two admits
    stay distinct tokens all the way out: ``proven_empty`` is a PROVEN $0 —
    every asset's quantity witnessed zero — and refusing it would publish
    ``not_determined`` where an earned negative exists, while reporting it as a
    plain ``admitted`` would hide that the $0 is a witness rather than an
    absence. Both admits band at the floor; only the state distinguishes them.

    The alias conjunct is tested on the key AS PASSED, which is safe under the
    caller's canonicalisation: an ambiguous implementation is aliased onto
    nothing, so ``canonical()`` is the identity on it and folding first cannot
    launder the ambiguity away. Everywhere else the sheet is read at the
    canonical key, which ``sheet_state`` and ``total`` already do for themselves.

    A TRUNCATED asset list refuses before the state is read, and refuses the
    admits as well as the refusals. The rows under a page-capped read are a
    prefix of what the entity holds, so the sheet totals a floor over the
    holdings — and a floor published as an at-most is a false upper bound on the
    security claim this figure exists to make. The state cannot carry that fact:
    ``priced`` says a reading was determined and says nothing about how much of
    the list was read, so a capped sheet and a whole one answer it identically.
    It is refused under its own token rather than folded into ``unpriced``
    because "the list is incomplete" is closed by paging or sweeping the chain,
    which is not the pipeline that answers "nobody priced these rows".

    ``fold._entity_contribution`` and ``fold._unresolved_stake`` are the
    callers, both with canonical keys. Every reason is pinned by ``tests/test_value_plane_ceiling.py``
    over hand-built planes, because the corpus does not carry all of them: it now
    carries proven-empty sheets in quantity — the chain-log sweep earned them —
    but no ambiguous alias and no unregistered sheet state, so those two are
    reachable only by construction.
    """
    if key in plane.alias_ambiguous:
        return None, CEILING_ALIAS_AMBIGUOUS
    if plane.asset_set_is_truncated(key):
        return None, CEILING_ASSET_LIST_TRUNCATED
    state = plane.sheet_state(key)
    if state == SHEET_PRICED:
        return plane.total(key), CEILING_ADMITTED
    if state == SHEET_PROVEN_EMPTY:
        # Written as a literal rather than read back from ``total()``: the
        # witness here is the state — every quantity proven zero — and the
        # figure it implies is $0 whatever the sum of an empty sheet computes to.
        return 0.0, CEILING_PROVEN_EMPTY
    if state == SHEET_AIRDROP_DETERMINED:
        # A literal for the same reason the branch above is one: the witness is
        # the state — every reading on the sheet arrived as a mass distribution,
        # or is a proven zero — and the figure it implies is $0 whatever the sum
        # of a sheet with no determined readings computes to.
        return 0.0, CEILING_AIRDROP_DETERMINED
    refusal = _CEILING_REFUSALS.get(state)
    if refusal is None:
        raise ValueError(f"sheet state {state!r} has no registered ceiling reason")
    return None, refusal


_EPOCH = datetime.min

# Every counter the reduction publishes, so a rule that never fired reports a
# named zero instead of an absence a consumer would have to read as either.
_REDUCTION_COUNTERS = (
    "buckets",
    "single_reading_accounts",
    "multi_observation_accounts",
    "height_witnessed_accounts",
    "write_order_accounts",
    "write_order_decided_accounts",
    "write_order_disagreeing_accounts",
    "multi_account_buckets",
    "unwitnessed_account_buckets",
    "unpriced_supersession_accounts",
    "stale_high_water_marks_dropped",
)


def _write_order(row: Any) -> tuple[bool, Any, int]:
    """Insert order, for observations whose READ height was never recorded."""
    return (row.fetched_at is not None, row.fetched_at or _EPOCH, int(row.id or 0))


def _latest_observation(rows: list[Any]) -> tuple[Any, bool]:
    """The current reading of one account, and whether a HEIGHT witnessed it.

    Ordering by ``block_number`` is the only ordering that proves which reading
    is current, and it is available only where every competing row carries one:
    ``contract_balance_fetches.block_number`` pins the native quantity and is
    deliberately never projected onto ERC-20 rows, so most competing readings
    have no height at all. There the fallback is write order, which is a fact
    about this database rather than about the chain — hence the flag, counted in
    the provenance so the fiat is stated rather than silent.
    """
    if len(rows) == 1:
        return rows[0], rows[0].block_number is not None
    if all(row.block_number is not None for row in rows):
        return max(rows, key=lambda row: (row.block_number, _write_order(row))), True
    return max(rows, key=_write_order), False


def _is_proven_zero_quantity(row: Any) -> bool:
    """Whether the QUANTITY held is proven zero — worth 0 at any price.

    The only witness under which a ``0.00`` dollar reading is a number rather
    than the storage column's floor. An unparseable raw balance proves nothing
    and lands on False, which keeps the reading below-resolution rather than
    minting a proven zero out of a value nobody could read.
    """
    try:
        return float(str(row.raw_balance)) == 0.0
    except (TypeError, ValueError):
        return False


def _asset_reading(row: Any) -> tuple[float | None, str]:
    """One row's dollar reading and the state that reading is in."""
    usd = _float(row.usd_value)
    if usd is None:
        # NULL usd_value is not_determined, never 0: nothing separates a
        # worthless asset from a failed price lookup.
        return None, ASSET_UNPRICED
    if usd != 0.0:
        return usd, ASSET_PRICED
    if _is_proven_zero_quantity(row):
        return 0.0, ASSET_PROVEN_ZERO
    return None, ASSET_BELOW_RESOLUTION


def _reduce_observations(
    observations: dict[tuple[str, str], dict[str, list[Any]]],
) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, str]], dict[str, Any]]:
    """Latest observation per account; SUM across DISTINCT observed accounts.

    Two readings of one account are one holding read twice — the later one is
    the answer and the earlier one is stale, so MAX over them publishes a
    high-water mark that was already false when it was written. Two readings of
    two accounts are two holdings of the same entity, and the entity holds their
    SUM. The discriminator is ``observed_address``, the address the read was
    actually issued against.

    Where the account identity itself is missing on any competing reading the
    sum is not licensed — summing over an unwitnessed identity is how the double
    count this reduction exists to remove gets back in — so those buckets fall
    back to MAX and are counted separately.

    Every counter this returns is published whether or not it fired: a rule that
    reports nothing where it never applied cannot be told apart from one that was
    never wired up.
    """
    per_asset: dict[str, dict[str, float]] = defaultdict(dict)
    per_asset_state: dict[str, dict[str, str]] = defaultdict(dict)
    counters: dict[str, int] = dict.fromkeys(_REDUCTION_COUNTERS, 0)
    for state in (ASSET_PRICED, ASSET_BELOW_RESOLUTION, ASSET_PROVEN_ZERO, ASSET_UNPRICED):
        counters[f"assets_{state}"] = 0
    stale_usd = 0.0
    write_order_selected_usd = 0.0
    write_order_spread_usd = 0.0

    for (key, asset), accounts in sorted(observations.items()):
        counters["buckets"] += 1
        readings: list[tuple[float | None, str]] = []
        for account in sorted(accounts):
            rows = accounts[account]
            competing = len(rows) > 1
            counters["multi_observation_accounts" if competing else "single_reading_accounts"] += 1
            row, height_witnessed = _latest_observation(rows)
            counters["height_witnessed_accounts" if height_witnessed else "write_order_accounts"] += 1
            readings.append(_asset_reading(row))
            priced = [value for value in (_float(candidate.usd_value) for candidate in rows) if value is not None]
            current = _float(row.usd_value)
            if competing and not height_witnessed:
                # The fiat, sized: how many readings write order actually DECIDED,
                # how many of those it decided between figures that differ, and
                # how many dollars it selected. An account whose competing
                # readings agree is not evidence of anything the ordering did.
                counters["write_order_decided_accounts"] += 1
                if len(set(priced)) > 1:
                    counters["write_order_disagreeing_accounts"] += 1
                    write_order_spread_usd += max(priced) - min(priced)
                    if current is not None:
                        write_order_selected_usd += current
            if priced and current is None:
                # The current reading answers no price while an earlier one did:
                # a determined value disappears, and the sheet is not_determined
                # by the same rule that would have published it.
                counters["unpriced_supersession_accounts"] += 1
            highest = max(priced, default=None)
            if highest is not None and current is not None and highest > current:
                counters["stale_high_water_marks_dropped"] += 1
                stale_usd += highest - current

        if len(accounts) > 1:
            counters["multi_account_buckets"] += 1
            if "" in accounts:
                counters["unwitnessed_account_buckets"] += 1

        determined = [value for value, state in readings if value is not None]
        if any(state == ASSET_PRICED for _, state in readings):
            state = ASSET_PRICED
            # The MAX fallback where an account identity is missing: never a sum
            # over readings that may be the same account twice.
            value = max(determined) if "" in accounts and len(accounts) > 1 else sum(determined)
        elif any(pair[1] == ASSET_BELOW_RESOLUTION for pair in readings):
            state, value = ASSET_BELOW_RESOLUTION, None
        elif any(pair[1] == ASSET_UNPRICED for pair in readings):
            state, value = ASSET_UNPRICED, None
        else:
            state, value = ASSET_PROVEN_ZERO, 0.0
        counters[f"assets_{state}"] += 1
        per_asset_state[key][asset] = state
        if value is not None:
            per_asset[key][asset] = _round_presented(value)

    reduction: dict[str, Any] = dict(sorted(counters.items()))
    reduction["stale_high_water_usd_dropped"] = round(stale_usd, 2)
    reduction["write_order_selected_usd"] = round(write_order_selected_usd, 2)
    reduction["write_order_spread_usd"] = round(write_order_spread_usd, 2)
    return (
        {k: dict(sorted(v.items())) for k, v in sorted(per_asset.items())},
        {k: dict(sorted(v.items())) for k, v in sorted(per_asset_state.items())},
        reduction,
    )


class AliasCycleError(ValueError):
    """The implementation alias map contains a cycle. Loud, never resolved."""


def _alias_fixed_point(alias: dict[str, str]) -> dict[str, str]:
    """Follow ``J -> I -> P`` to ``J -> P``, and refuse a cycle out loud.

    A single-level lookup answers ``I`` for J, so J's balances fold onto a key
    that itself folds elsewhere: J is orphaned from the entity that ends up
    holding it and P is counted once for itself and once for I. A cycle is not a
    fold at all — it says two contracts each implement the other — so it raises
    rather than picking a member, which would publish a canonical entity chosen
    by iteration order.
    """
    out: dict[str, str] = {}
    for key in sorted(alias):
        seen = [key]
        current = alias[key]
        while current in alias and alias[current] != current:
            if current in seen:
                raise AliasCycleError("implementation alias cycle: " + " -> ".join([*seen, current]))
            seen.append(current)
            current = alias[current]
        out[key] = current
    return out


# The states a reading may be disposed OUT OF. Pricing-agnostic per the ruling —
# delivery shape is a pricing-independent fact and dust airdrops land in
# ``priced_below_resolution`` — but a PRICED reading is never disposed: a number
# was determined for it, and disposing it would delete a measured dollar from
# the document on evidence about how the token arrived.
_DISPOSABLE_ASSET_STATES = (ASSET_UNPRICED, ASSET_BELOW_RESOLUTION)


def _resolve_asset_disposition(
    session: Session,
    plane: ValuePlane,
    accounts_by_bucket: dict[tuple[str, str], set[tuple[str, str]]],
    universe: ProtocolUniverse | None,
) -> tuple[dict[str, dict[str, dict[str, Any]]], dict[str, int]]:
    """Which (entity, asset) readings arrived only as mass distributions.

    Five conjuncts, every one of them fail-closed:

    1. A UNIVERSE was supplied. No universe, no condemnation — an unset argument
       means the caller could not build the protocol's address set (object
       storage refused, or the fold was handed a plane by hand), and a predicate
       that condemns everything absent from an empty set condemns everything.
    2. The asset is not the native coin. Native ETH has no ``Transfer`` log to
       have a delivery shape, so there is no evidence to read.
    3. The reading's reduced state is unpriced or below-resolution. A PRICED
       reading is never disposed.
    4. P4 — the token address is absent from the protocol's discovered universe,
       tested CHAIN-BLIND. Chain scoping is banned here and the ban is measured,
       not stylistic: on this corpus a chain-scoped P4 falsely condemns
       $3,272,829.37 of real holdings ($2,203,581.37 on optimism, whose contracts
       carry no dependency, control-graph or signal rows at all, and $1,069,248.00
       on base) and buys nothing on base's unpriced population. Absence of chain
       attribution is not proof of absence from a chain — 5.28% of the universe
       has no chain column at all — so an address discovered anywhere admits
       everywhere, and chain-blind is the superset that reading requires.
    5. P2 — EVERY observed account that contributed a reading to this bucket
       holds a delivery fact whose all-quantifier passed. A missing fact for any
       one contributing account refuses the whole bucket: the entity's holding is
       the sum over its accounts, so evidence at one account answers nothing
       about another's.

    Returns the carrier records and a census. Both are published; the census
    names its zeros so a conjunct that never fired is visible.
    """
    from services.monitoring.delivery_evidence import load_delivery_evidence

    census: dict[str, int] = dict.fromkeys(DISPOSITION_REFUSALS, 0)
    if universe is None:
        return {}, census

    from utils.chains import UnknownChainError, chain_by_name

    chain_ids: dict[str, int] = {}
    for chain_name, _ in {account for accounts in accounts_by_bucket.values() for account in accounts}:
        if chain_name in chain_ids:
            continue
        try:
            chain_ids[chain_name] = int(chain_by_name(chain_name).chain_id)
        except (UnknownChainError, ValueError, TypeError):
            # A chain name nothing maps to an id. The evidence table is keyed by
            # id, so there is no row to ask for — and guessing one would ask the
            # wrong chain's question. Refused by omission below.
            continue

    holders = {
        (chain_ids[chain_name], address)
        for accounts in accounts_by_bucket.values()
        for chain_name, address in accounts
        if chain_name in chain_ids and address
    }
    evidence = load_delivery_evidence(session, holders)

    disposition: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for (key, asset), accounts in sorted(accounts_by_bucket.items()):
        if asset == NATIVE_ASSET:
            continue
        if (plane.per_asset_state.get(key) or {}).get(asset) not in _DISPOSABLE_ASSET_STATES:
            continue
        if asset in universe.addresses:
            continue
        facts = []
        for chain_name, address in sorted(accounts):
            chain_id = chain_ids.get(chain_name)
            if chain_id is None or not address:
                facts = []
                break
            fact = evidence.get((chain_id, address, asset))
            if fact is None or not fact.is_airdrop_only:
                facts = []
                break
            facts.append(fact)
        if not facts:
            continue
        disposition[key][asset] = {
            "shape": facts[0].shape,
            "fan_out_threshold_k": max(fact.fan_out_threshold_k for fact in facts),
            # The WEAKEST end of the accounts' evidence, because the claim only
            # holds where all of them do: the smallest fan-out any account
            # measured, the latest block any scan started at, the earliest block
            # any of them ran through.
            "min_fan_out": min((fact.min_fan_out for fact in facts if fact.min_fan_out is not None), default=None),
            "delivery_count": sum(fact.delivery_count for fact in facts),
            "scanned_from_block": max(fact.scanned_from_block for fact in facts),
            "measured_through_block": min(fact.measured_through_block for fact in facts),
            "accounts": [fact.holder_address for fact in facts],
            # The carriers' own basis strings, verbatim, so a published claim
            # quotes stored evidence rather than a sentence re-authored here.
            "basis": [fact.basis for fact in facts if fact.basis],
        }

    out = {key: dict(sorted(assets.items())) for key, assets in sorted(disposition.items())}
    for key in sorted(out):
        refusal = plane.disposition_refusal(key)
        if refusal is not None:
            census[refusal] += len(out[key])
    return out, census


def _balance_account(row: Any) -> Any:
    """The ACCOUNT identity a balance/fetch row is keyed on.

    ``contracts.id`` where the row has one, ``(entity_chain, entity_address)``
    where it does not. The schema keeps exactly one of the two arms populated
    (``ck_*_exactly_one_subject_key``), so this is a read of the row's own key
    and never a choice between two candidates.
    """
    if row.contract_id is not None:
        return row.contract_id
    return (row.entity_chain or "", row.entity_address or "")


def _account_sort_key(item: tuple[Any, Any]) -> tuple[int, str]:
    """A total order over accounts of both kinds, for deterministic iteration.

    ``sorted`` over a mixed int/tuple key space raises; the plane's output must
    not depend on dict insertion order, so the two arms are ordered explicitly —
    contracts first, by id, then entity accounts by their key.
    """
    account = item[0]
    if isinstance(account, tuple):
        return (1, "::".join(str(part) for part in account))
    return (0, f"{int(account):012d}")


def _implementation_alias(
    rows: Iterable[tuple[str | None, str | None, str | None]],
) -> tuple[dict[str, str], set[str], dict[str, set[str]]]:
    """The proxy/impl fold from ``(chain, address, implementation)`` rows.

    Two proxies sharing one implementation. Pinning either of them — by
    ``min``, by ``contracts.id`` order, by anything — charges a finding that
    reaches only proxy B's implementation with proxy A's whole balance sheet,
    publishes A as an entity nothing reached, and spends A's exposure budget.
    The implementation is not a fold of either proxy, so it folds onto
    NEITHER: it keeps its own key and the collision is published.
    """
    impl_to_proxy: dict[str, str] = {}
    impl_proxies: dict[str, set[str]] = defaultdict(set)
    for chain, address, implementation in rows:
        if not implementation:
            continue
        chain_tok = coalesce_chain(chain)
        impl_key = entity_key(chain_tok, implementation)
        proxy_key = entity_key(chain_tok, address)
        impl_proxies[impl_key].add(proxy_key)
        impl_to_proxy[impl_key] = proxy_key
    ambiguous = {impl for impl, proxies in impl_proxies.items() if len(proxies) > 1}
    for impl in ambiguous:
        impl_to_proxy.pop(impl, None)
    return _alias_fixed_point(impl_to_proxy), ambiguous, impl_proxies


def load_entity_alias(session: Session, protocol_id: int) -> tuple[dict[str, str], set[str]]:
    """The value plane's proxy/impl fold alone, without loading any sheet.

    Same admission rules as :func:`load_value_plane` (one extraction, shared),
    for consumers that only need :meth:`ValuePlane.canonical`'s answer.
    """
    from db.models import Contract

    rows = (
        session.query(Contract.chain, Contract.address, Contract.implementation)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(Contract.id)
        .all()
    )
    alias, ambiguous, _ = _implementation_alias(
        (chain, address, implementation) for chain, address, implementation in rows
    )
    return alias, ambiguous


def load_value_plane(session: Session, protocol_id: int, *, universe: ProtocolUniverse | None = None) -> ValuePlane:
    from db.models import Contract, ContractBalanceFetch, ContractBalanceLatest, RestakingPositionLatest
    from services.monitoring.balance_reads import (
        ObservationSubject,
        native_balance_fact,
        winning_asset_fetches,
        winning_entity_asset_fetches,
    )
    from services.monitoring.delivery_evidence import FAN_OUT_CALIBRATION_CORPUS, FAN_OUT_THRESHOLD_K

    plane = ValuePlane()
    contracts = session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    # An ACCOUNT this plane reads, keyed the way its balance records are keyed:
    # a ``contracts.id``, or the ``(chain, address)`` of an entity that has no
    # ``contracts`` row. The two arms are disjoint types, so a contract id and an
    # entity identity can never collide in one of the mappings below — which a
    # single int space with sentinel values could.
    chain_of: dict[Any, str] = {}
    address_of: dict[Any, str] = {}
    for contract in contracts:
        chain = coalesce_chain(contract.chain)
        chain_of[contract.id] = chain
        address_of[contract.id] = _lower(contract.address)
        plane.contract_entities.add(entity_key(chain, contract.address))
    alias, ambiguous, impl_proxies = _implementation_alias(
        (contract.chain, contract.address, contract.implementation) for contract in contracts
    )
    shared_impl = [{"implementation": impl, "proxies": sorted(impl_proxies[impl])} for impl in sorted(ambiguous)]
    plane.alias = alias
    plane.alias_ambiguous = ambiguous

    # The perimeter's proven-codeless principals: entities the control graph
    # reached and the ``contracts`` table does not name. Their balance records
    # are keyed on ``(chain, address)`` and carry no ``contract_id``, so they are
    # loaded by identity rather than by a join — a join to ``contracts`` is what
    # made them unreadable in the first place. Membership is the SAME earned
    # ``eth_getCode`` witness the vacuous-credit arm reads (``resolved_type ==
    # 'eoa'``); an entity outside it is not looked up here at all.
    entity_identities = sorted(
        (chain, address)
        for chain, _, address in (key.partition("::") for key in load_proven_eoa_entities(session, protocol_id))
        if chain and address
    )
    entity_subjects = [ObservationSubject.of_entity(chain, address) for chain, address in entity_identities]
    for chain, address in entity_identities:
        chain_of[(chain, address)] = chain
        address_of[(chain, address)] = address

    native_seen: set[str] = set()
    fetched: list[Any] = []
    rows = (
        session.query(ContractBalanceLatest)
        .join(Contract, Contract.id == ContractBalanceLatest.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ContractBalanceLatest.contract_id, ContractBalanceLatest.token_address, ContractBalanceLatest.id)
        .all()
    )
    if entity_identities:
        rows = list(rows) + (
            session.query(ContractBalanceLatest)
            .filter(
                ContractBalanceLatest.contract_id.is_(None),
                tuple_(ContractBalanceLatest.entity_chain, ContractBalanceLatest.entity_address).in_(entity_identities),
            )
            .order_by(
                ContractBalanceLatest.entity_chain,
                ContractBalanceLatest.entity_address,
                ContractBalanceLatest.token_address,
                ContractBalanceLatest.id,
            )
            .all()
        )
    # One bucket per (entity, asset, observed account). The alias fold puts a
    # proxy's rows and its implementation's rows under one entity key, and those
    # are the SAME on-chain account read twice at two heights by two writers —
    # not two holdings — so the account is what a reading has to be reduced over.
    observations: dict[tuple[str, str], dict[str, list[Any]]] = defaultdict(lambda: defaultdict(list))
    # The same buckets, carrying the (chain, ACCOUNT) identities the readings
    # were issued against. The delivery-evidence table is keyed on that account —
    # never on a folded entity key — so the disposition's all-quantifier is
    # evaluated over exactly the addresses that contributed to the bucket.
    accounts_by_bucket: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
    for row in rows:
        account = _balance_account(row)
        key = plane.canonical(entity_key(chain_of.get(account), address_of.get(account)))
        # A NULL token_address IS the native asset by this column's definition,
        # not a missing value standing in for one.
        asset = _lower(row.token_address) if row.token_address else NATIVE_ASSET
        if asset == NATIVE_ASSET:
            native_seen.add(key)
        if row.fetched_at is not None:
            fetched.append(row.fetched_at)
        observations[(key, asset)][_lower(row.observed_address)].append(row)
        accounts_by_bucket[(key, asset)].add((chain_of.get(account) or "", _lower(row.observed_address)))

    per_asset, per_asset_state, reduction = _reduce_observations(observations)
    plane.per_asset = per_asset
    plane.per_asset_state = per_asset_state

    # The proven-zero / fetch-failed discriminator for an ABSENT native row.
    latest_fetch: dict[Any, Any] = {}
    fetch_rows = list(
        session.query(ContractBalanceFetch)
        .join(Contract, Contract.id == ContractBalanceFetch.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ContractBalanceFetch.contract_id, ContractBalanceFetch.fetched_at, ContractBalanceFetch.id)
        .all()
    )
    if entity_identities:
        fetch_rows += (
            session.query(ContractBalanceFetch)
            .filter(
                ContractBalanceFetch.contract_id.is_(None),
                tuple_(ContractBalanceFetch.entity_chain, ContractBalanceFetch.entity_address).in_(entity_identities),
            )
            .order_by(
                ContractBalanceFetch.entity_chain,
                ContractBalanceFetch.entity_address,
                ContractBalanceFetch.fetched_at,
                ContractBalanceFetch.id,
            )
            .all()
        )
    for fetch in fetch_rows:
        latest_fetch[_balance_account(fetch)] = fetch
    # Completeness is a property of THE ROW SET, so it is read from the fetch
    # whose rows this plane just loaded — never from the latest fetch, which may
    # be a later failure that would withdraw the truncation while the truncated
    # prefix rows are still what the sheet sums.
    winning_asset_fetch: dict[Any, Any] = dict(winning_asset_fetches(session, protocol_id))
    for subject, fetch in winning_entity_asset_fetches(session, entity_subjects).items():
        winning_asset_fetch[(subject.chain, subject.address)] = fetch
    # EVERY account that folds onto a key, with no exemption. The sheet is the
    # sum over its accounts, so its asset list is whole only where every one of
    # those addresses was scanned AT ITSELF. An implementation nothing has ever
    # read is the case this exists for: its rows fold into the proxy's sheet, so
    # publishing that sheet empty asserts the implementation's address holds
    # nothing — which nobody looked at. "We never looked" is not_determined, and
    # neither a missing fetch nor a failed one nor a fetch filed at some other
    # address is a reading of that account. The producer's population is what
    # closes this (``tvl._get_protocol_addresses`` reads the folded
    # implementations of a scanning entity), not a weaker rule here.
    accounts_of: dict[str, set[Any]] = defaultdict(set)
    for contract in contracts:
        accounts_of[plane.canonical(entity_key(chain_of[contract.id], address_of[contract.id]))].add(contract.id)
    # An entity-keyed subject is one account and it IS the entity, so the sheet's
    # "every folded account was scanned at its own address" conjunct is asked of
    # it exactly as it is asked of a contract — never waived because the account
    # happens to have no contracts row.
    for account in entity_identities:
        accounts_of[plane.canonical(entity_key(chain_of[account], address_of[account]))].add(account)
    scanned: dict[str, list[dict[str, Any]]] = defaultdict(list)
    typed_unresolved: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for account, fetch in sorted(winning_asset_fetch.items(), key=_account_sort_key):
        key = plane.canonical(entity_key(chain_of.get(account), address_of.get(account)))
        # Recorded for EVERY contract, independently of the native-row shortcut
        # below: a truncated asset list is a fact about the ERC-20 list and holds
        # whether or not a native row was also stored. Unioned over the contracts
        # that fold onto one key, because one account read at its cap truncates
        # the list the whole sheet is assembled from.
        if fetch.asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP:
            plane.asset_set_truncated.add(key)
        # A malformed typed record is NOT an empty one: it is a scan whose
        # evidence cannot be read, so nothing about typed receipts survives from
        # it and the completeness it would have supported is refused below.
        entries = fetch.typed_assets if isinstance(fetch.typed_assets, list) else None
        for entry in entries or ():
            if typed_receipt_is_resolved(entry):
                continue
            typed_unresolved[key].append(
                {
                    "asset": _lower(entry.get("address")) if isinstance(entry, dict) else None,
                    "quantity_readable": bool(isinstance(entry, dict) and entry.get("quantity_readable") is True),
                    "quantity": (str(entry.get("quantity")) if isinstance(entry, dict) else None),
                }
            )
        if (
            fetch.asset_set_source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP
            and fetch.sweep_status == SWEEP_STATUS_COMPLETED
            and fetch.swept_through_block is not None
            and entries is not None
            # The scan has to have been issued AT this account's own address. A
            # fetch row names the contract it belongs to and, separately, the
            # address the read went to; the recipient-topic filter that makes the
            # scan a proof is built from the second. A scan of the proxy filed
            # against the implementation's row proves nothing about the
            # implementation's address, and that is the exact shape on this
            # corpus.
            and _lower(fetch.observed_address) == address_of.get(account)
        ):
            scanned[key].append(
                {
                    "account": account,
                    "source": str(fetch.asset_set_source),
                    "swept_from_block": int(fetch.swept_from_block or 0),
                    "swept_through_block": int(fetch.swept_through_block),
                    "basis": fetch.asset_set_basis,
                }
            )
    plane.typed_receipts_unresolved = {key: records for key, records in sorted(typed_unresolved.items())}
    for key, records in sorted(scanned.items()):
        unscanned = accounts_of.get(key, set()) - {record["account"] for record in records}
        if unscanned:
            # A scan ran at some of this sheet's accounts and never at these.
            # Named rather than merely refused: it is the one refusal a producer
            # cycle can close, and the addresses are the work list.
            plane.asset_set_accounts_unscanned[key] = sorted(address_of.get(account) or "" for account in unscanned)
            continue
        if key in plane.asset_set_truncated:
            # One account scanned and another came back at the index's page cap.
            # Two witnesses of the same sheet that contradict each other prove
            # nothing together, and the fail-closed reading of a contradiction is
            # the refusal, not the admit.
            continue
        plane.asset_set_proven_complete[key] = {
            "source": ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
            # Both figures, always, and equal by the rule above. A lone
            # "accounts_scanned: 1" lets a two-account sheet read as fully
            # scanned when one of its addresses was; publishing the denominator
            # beside it makes the claim checkable at a glance.
            "accounts_scanned": len(records),
            "accounts_folded": len(accounts_of.get(key, ())),
            "accounts": sorted(address_of.get(record["account"]) or "" for record in records),
            # The WEAKEST end of the accounts' scans, because the sheet is only
            # covered where all of them are: the latest first block any account's
            # scan started at, and the earliest block any of them ran through.
            "swept_from_block": max(record["swept_from_block"] for record in records),
            "swept_through_block": min(record["swept_through_block"] for record in records),
            # The carriers' own basis strings, verbatim. A claim published from
            # this record derives from stored evidence rather than a sentence
            # re-authored here.
            "basis": [record["basis"] for record in records if record["basis"]],
        }
    # The native discriminator for an ABSENT native row, decided per ENTITY and
    # not by whichever folded contract row sorted last. Two rules, and the corpus
    # shows why each is needed:
    #
    #   * the fact must come from the fetch of the account that IS the entity —
    #     the canonical address. A folded implementation's fetch is a reading of
    #     some address (often, on this corpus, of the PROXY, filed against the
    #     implementation's row), and letting it win publishes a height and a
    #     polarity the entity never earned. Live shape: a proxy holding 19.06 ETH
    #     read ``proven_nonzero`` at its own address while its implementation row
    #     carried a stale ``proven_zero``, and the higher ``contracts.id`` won.
    #   * where two accounts disagree on the POLARITY, nothing is published. One
    #     of them is wrong about this entity and the plane cannot say which, so
    #     the honest answer is the third state rather than the majority or the
    #     latest.
    native_by_account: dict[str, dict[str, str]] = defaultdict(dict)
    for account, fetch in sorted(latest_fetch.items(), key=_account_sort_key):
        own = entity_key(chain_of.get(account), address_of.get(account))
        native_by_account[plane.canonical(own)][own] = native_balance_fact(fetch.native_status, fetch.block_number)
    native_facts_refused_on_disagreement = 0
    for key, by_account in sorted(native_by_account.items()):
        if key in native_seen:
            continue
        polarities = {fact.split("_at_block")[0] for fact in by_account.values()}
        if len(polarities) > 1:
            native_facts_refused_on_disagreement += 1
            plane.native_fact[key] = "not_determined"
            continue
        plane.native_fact[key] = by_account.get(key, "not_determined")

    # The restaking plane is separate by construction and carries NO USD column,
    # so its positions cannot enter the band arithmetic. They keep a MAX-per-node
    # fold of their own — this plane records no observation height to order by —
    # and are published as unpriced quantities.
    positions = (
        session.query(RestakingPositionLatest)
        .filter(RestakingPositionLatest.protocol_id == protocol_id)
        .order_by(RestakingPositionLatest.chain_id, RestakingPositionLatest.node_address)
        .all()
    )
    unpriced: dict[str, dict[str, float]] = defaultdict(dict)
    residual_seen = False
    # Every admission rule states where it fired. A position dropped uncounted is
    # a quantity that leaves no trace of having existed, which reads downstream
    # as a node that holds nothing rather than one this plane declined to fold.
    dropped: dict[str, int] = {
        "unknown_chain_id": 0,
        "shares_basis_not_admissible": 0,
        "shares_unreadable": 0,
        "cross_read_inconsistent": 0,
    }
    for position in positions:
        chain = _chain_name(position.chain_id)
        if chain is None:
            dropped["unknown_chain_id"] += 1
            continue
        key = plane.canonical(entity_key(chain, position.node_address))
        shares = _float(position.eigenlayer_beacon_shares_wei)
        if position.shares_basis not in ("eigenlayer_beacon_shares", "no_eigenpod_proven"):
            dropped["shares_basis_not_admissible"] += 1
            continue
        if shares is None:
            dropped["shares_unreadable"] += 1
            continue
        if position.cross_read_agreement == "inconsistent":
            dropped["cross_read_inconsistent"] += 1
            continue
        previous = unpriced[key].get("eigenlayer_beacon_shares_wei")
        if previous is None or shares > previous:
            unpriced[key]["eigenlayer_beacon_shares_wei"] = shares
        residual_seen = residual_seen or position.consensus_layer_residual is not None
    plane.unpriced_positions = {
        key: [{"asset": asset, "quantity_wei": qty} for asset, qty in sorted(assets.items())]
        for key, assets in sorted(unpriced.items())
    }
    if positions:
        plane.annotations.append(
            {
                "fact": "restaking positions folded as UNPRICED entity contributions",
                "entities": len(plane.unpriced_positions),
                "positions_read": len(positions),
                "positions_dropped": dict(sorted(dropped.items())),
                "note": (
                    "the plane carries no USD column and pricing it would need a "
                    "banned price source, so these quantities raise a confidence gap "
                    "and never a band; node_set_completeness is not_determined, so "
                    "any cross-node aggregate is a floor"
                ),
                "consensus_layer_residual": (
                    "not_determined and BANNED as a number; never read as 0" if residual_seen else "no rows"
                ),
            }
        )

    # The disposition pass, run HERE and not beside the reduction: its refusal
    # conjuncts read the typed receipts, the truncation flag, the unscanned
    # accounts and the restaking positions, all of which are resolved above.
    plane.asset_disposition, disposition_refused = _resolve_asset_disposition(
        session, plane, accounts_by_bucket, universe
    )
    # The reading's state is rewritten in place, so every consumer of
    # ``per_asset_state`` — the sheet state, the coverage census, the fold's
    # per-asset publication — sees the determination rather than an unpriced
    # reading with a note attached somewhere else. The row itself is never
    # dropped: a disposed asset stays visible and stays labelled.
    disposed_readings = 0
    for key, assets in sorted(plane.asset_disposition.items()):
        for asset in sorted(assets):
            plane.per_asset_state.setdefault(key, {})[asset] = ASSET_AIRDROP_DELIVERED
            disposed_readings += 1

    # ``native_status = proven_zero`` becomes a real ASSET reading, on the sheets
    # whose asset list a chain scan proved whole. The pair is what carries the
    # claim: the scan says the ERC-20 list is everything that ever arrived, the
    # pinned ``getEthBalance`` says the coin the logs cannot see is zero, and
    # together they are an entity holding nothing. Neither alone is — which is
    # why the completeness witness gates the reading rather than the reading
    # standing on its own.
    #
    # A stored native ROW always wins: ``native_seen`` is the account actually
    # read, and the fetch record's status is the discriminator for an ABSENT row
    # only. The fact itself is the entity's OWN — resolved above at the canonical
    # address and refused outright where two folded accounts disagree — so a
    # sheet can no longer be published empty on a zero read at a neighbouring
    # address.
    native_proven_zero_readings = 0
    for key in sorted(plane.asset_set_proven_complete):
        if key in native_seen:
            continue
        if not (plane.native_fact.get(key) or "").startswith("proven_zero"):
            continue
        plane.per_asset.setdefault(key, {})[NATIVE_ASSET] = 0.0
        plane.per_asset_state.setdefault(key, {})[NATIVE_ASSET] = ASSET_PROVEN_ZERO
        native_proven_zero_readings += 1

    # Every state, including the ones no entity is in: an omitted state and a
    # state with no entities read the same way to a consumer, and only one of
    # them is a fact about the protocol.
    sheet_states: dict[str, int] = dict.fromkeys(
        (
            SHEET_PRICED,
            SHEET_BELOW_RESOLUTION,
            SHEET_UNPRICED,
            SHEET_PROVEN_EMPTY,
            SHEET_AIRDROP_DETERMINED,
            SHEET_NO_ROWS,
        ),
        0,
    )
    # The union INCLUDES entities carried only by a typed receipt. They hold no
    # fungible reading, so the two per-asset maps do not name them — and they are
    # exactly the entities whose state the typed gate moves off ``no_rows``. A
    # census taken over the maps alone published 14 unpriced sheets while the
    # plane answered ``unpriced`` for 29 of them.
    #
    # It also includes the BASE POPULATION, and that is what makes ``no_rows``
    # answerable at all. Every key in the observation maps has, by construction,
    # something observed on it, so a census over those maps alone can never
    # report the one state that means "nothing observed": it published a
    # structural 0 that reads as the earned fact "every entity this protocol
    # names has a balance sheet". The entities with no reading are precisely the
    # ones absent from the maps, and ``contract_entities`` — discovery-fixed, and
    # this plane's own documented base population — is where they are named.
    # Folded through ``canonical`` first: it is canonicalised only after this
    # census runs, and an implementation counted apart from the proxy it folds
    # onto would report one sheet twice.
    for key in sorted(
        {plane.canonical(key) for key in plane.contract_entities}
        | set(plane.per_asset)
        | set(plane.per_asset_state)
        | set(plane.typed_receipts_unresolved)
    ):
        sheet_states[plane.sheet_state(key)] += 1

    # The empty claim's own census, over the sheets whose EVERY observed quantity
    # is zero — the population the claim was available to. Published whether or
    # not any of it fired: a refusal nobody counted is indistinguishable from a
    # rule nobody wired up.
    empty_refused: dict[str, int] = dict.fromkeys(EMPTY_REFUSALS, 0)
    empty_admitted = 0
    # THE COMPLEMENT, published beside it rather than folded into it. A sheet
    # leaves the all-zero population the moment any reading on it is not a proven
    # zero — including the reading the refusal's own evidence produced. A typed
    # receipt read back as a HELD item is exactly that: it writes a non-zero count
    # row, drops its sheet out of the population, and the counter above then
    # reports zero refusals on the very ground that refuses the entity. The two
    # dicts sum, per reason, to every refused sheet in the plane.
    empty_refused_outside: dict[str, int] = dict.fromkeys(EMPTY_REFUSALS, 0)
    # The population includes sheets refused for an UNSCANNED ACCOUNT even though
    # they carry no reading at all: the reading is missing precisely because the
    # refusal fired — the native proven-zero is only promoted onto a sheet whose
    # list is whole — so a census over readings alone would report the refusal it
    # was written to count as zero.
    for key in sorted(
        set(plane.per_asset)
        | set(plane.per_asset_state)
        | set(plane.typed_receipts_unresolved)
        | set(plane.asset_set_accounts_unscanned)
    ):
        states_at_key = plane.per_asset_state.get(key) or {}
        in_population = not any(state != ASSET_PROVEN_ZERO for state in states_at_key.values()) and bool(
            states_at_key or plane.typed_receipts_unresolved.get(key)
        )
        refusal = plane.proven_empty_refusal(key)
        if not in_population:
            if refusal is not None:
                empty_refused_outside[refusal] += 1
            continue
        if refusal is None:
            empty_admitted += 1
        else:
            empty_refused[refusal] += 1

    if reduction.get(f"assets_{ASSET_BELOW_RESOLUTION}"):
        plane.annotations.append(
            {
                "fact": "priced readings at the storage column's resolution floor are NOT proven zeros",
                "assets": reduction[f"assets_{ASSET_BELOW_RESOLUTION}"],
                "entities": sheet_states[SHEET_BELOW_RESOLUTION],
                "note": (
                    "usd_value is a scaled decimal column, so a holding below its last digit "
                    "stores as 0.00. Such a reading answers 'below the column's resolution', "
                    "never 'holds nothing', and an entity whose every priced reading is one has "
                    "NO determined total. Only a proven-zero QUANTITY witnesses an empty sheet"
                ),
                "proven_zero_quantity_assets": reduction.get(f"assets_{ASSET_PROVEN_ZERO}", 0),
                "proven_zero_arm_exercised": bool(reduction.get(f"assets_{ASSET_PROVEN_ZERO}")),
            }
        )

    plane.contract_entities = {plane.canonical(key) for key in plane.contract_entities}
    plane.provenance = {
        "entity_key": "effective_functions.deployment_address -> contracts.address, chain-scoped",
        "contract_entities": len(plane.contract_entities),
        "reduction": (
            "latest observation per (entity, asset, observed account); SUM across DISTINCT observed accounts"
        ),
        "observation_reduction": reduction,
        "observation_reduction_reading": (
            "two readings of ONE account are one holding read twice, so the later one is the "
            "answer and MAX would publish a stale high-water mark; two readings of TWO accounts "
            "are two holdings and the entity holds their sum. height_witnessed_accounts were "
            "ordered by block_number; write_order_accounts had no recorded read height (ERC-20 "
            "rows are never height-pinned by construction) and fell back to insert order, which "
            "is a fact about this database and not about the chain. write_order_accounts counts "
            "the ordering BASIS and includes single_reading_accounts, where nothing was ordered; "
            "write_order_decided_accounts is the subset the fallback actually decided, of which "
            "write_order_disagreeing_accounts decided between figures that DIFFER. "
            "write_order_selected_usd is the dollars those decisions selected and "
            "write_order_spread_usd the max-minus-min they were selected from — together the "
            "size of the fiat, not a claim that the selected figure is wrong"
        ),
        "sheet_states": dict(sorted(sheet_states.items())),
        "sheet_states_reading": (
            "priced = a determined non-zero reading, so the total is a floor; "
            "priced_below_resolution = every price that answered landed on the storage column's "
            "resolution floor and the total is NOT a number; unpriced = no price answered; proven_empty = "
            "every quantity proven zero, the only state in which 0.00 is a number; "
            "airdrop_determined = every reading left on the sheet arrived only in mass "
            "distributions or is a witnessed zero, which is a DIFFERENT witness from proven_empty "
            "and never the same one: proven_empty says nothing ever arrived, airdrop_determined "
            "says what arrived arrived as a mass distribution; no_rows = nothing observed. "
            "The census is taken over this plane's BASE POPULATION (contract_entities, folded "
            "onto canonical keys) unioned with every entity the observation maps carry, so "
            "no_rows counts the entities the protocol names and nobody has read — a count "
            "taken over the observations alone could only ever report 0 there, which is not "
            "the same fact"
        ),
        "asset_disposition": {
            "entities_determined": sheet_states[SHEET_AIRDROP_DETERMINED],
            "readings_disposed": disposed_readings,
            "tokens_disposed": len({asset for assets in plane.asset_disposition.values() for asset in assets}),
            "readings_refused_by_reason": dict(sorted(disposition_refused.items())),
            "fan_out_threshold_k": FAN_OUT_THRESHOLD_K,
            "fan_out_calibration_corpus": FAN_OUT_CALIBRATION_CORPUS,
            "protocol_universe": (
                None
                if universe is None
                else {
                    "addresses": len(universe.addresses),
                    "sources": dict(sorted(universe.sources.items())),
                    "chain_scope": "chain_blind",
                    "basis": universe.basis,
                }
            ),
            "reading": (
                "what is published here is DELIVERY SHAPE and never worth. A disposed reading "
                "says every incoming delivery of that token to that account arrived in a "
                "transaction carrying at least fan_out_threshold_k same-token transfer LOGS — the "
                "meter the threshold is calibrated in, and an upper bound on that transaction's "
                "distinct recipients rather than a count of them. It does not say the token is "
                "worthless: the reference corpus carries a class of FIVE demonstrably real tokens "
                "with this delivery shape (HEX, WETH and base USDC, which the protocol-reference "
                "conjunct spares, plus uniETH at fan-out 101 and USDtb at 175, which are in this "
                "state). The two conjuncts do NOT carry equal weight on every "
                "chain: the protocol-reference conjunct is near-vacuous on base, where it "
                "condemns 1,175 of 1,175 unpriced tokens and so partitions nothing, which means "
                "delivery shape CARRIES THE CLAIM ALONE on base over 1,745 readings. The asset "
                "list a disposition covers is the Etherscan-page-derived one and is NOT proven "
                "whole — the gate here refuses only a list read AT the page cap — so the "
                "determination is over the readings observed and never over the holdings. "
                "protocol_universe is null where no universe was supplied, and no reading is "
                "disposed there: no universe, no condemnation"
            ),
        },
        "asset_set_completeness": {
            "entities_proven_complete": len(plane.asset_set_proven_complete),
            "entities_proven_truncated": len(plane.asset_set_truncated),
            "completeness_source": ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
            "native_proven_zero_sheet_readings": native_proven_zero_readings,
            "native_facts_refused_on_cross_account_disagreement": native_facts_refused_on_disagreement,
            "entities_with_unresolved_typed_receipts": len(plane.typed_receipts_unresolved),
            "unresolved_typed_receipts": sum(len(v) for v in plane.typed_receipts_unresolved.values()),
            "entities_with_an_unscanned_folded_account": len(plane.asset_set_accounts_unscanned),
            "unscanned_folded_accounts": sum(len(v) for v in plane.asset_set_accounts_unscanned.values()),
            "accounts_scanned_over_accounts_folded": {
                "scanned": sum(int(r["accounts_scanned"]) for r in plane.asset_set_proven_complete.values()),
                "folded": sum(int(r["accounts_folded"]) for r in plane.asset_set_proven_complete.values()),
            },
            "sheets_published_empty": empty_admitted,
            "sheets_refused_empty_by_reason": dict(sorted(empty_refused.items())),
            "sheets_refused_empty_by_reason_outside_the_all_zero_population": dict(
                sorted(empty_refused_outside.items())
            ),
            "reading": (
                "the two completeness figures are NOT complements: proven_complete is an earned "
                "positive and proven_truncated an earned negative, and an entity in neither is the "
                "third state. The positive is earned PER ACCOUNT: a sheet sums over every contract "
                "row that folds onto its key, so it is whole only where the chain's transfer "
                "history was scanned at EVERY one of those addresses, at that address itself — a "
                "scan of a proxy filed against its implementation's row proves nothing about the "
                "implementation's address, which is why accounts_scanned is published beside "
                "accounts_folded and why folded_account_never_scanned is its own refusal rather "
                "than a shade of 'nobody scanned this'. Only a proven-complete sheet admits an "
                "empty one as a proven $0; every refusal publishes unpriced, never a zero. "
                "sheets_refused_empty_by_reason counts ONLY the sheets whose every reading is a "
                "proven zero — the population the empty claim was ever available to — so it is NOT "
                "the count of entities a reason refuses, and reading it against "
                "entities_with_unresolved_typed_receipts as though it were will mislead: a receipt "
                "read back as a HELD item writes a non-zero count row, which drops its sheet out of "
                "that population while still refusing it. Those sheets are counted in "
                "sheets_refused_empty_by_reason_outside_the_all_zero_population, and the two dicts "
                "sum per reason to every refused sheet in the plane. Most of the "
                "asset_set_not_proven_complete entries in the second are sheets holding real money, "
                "which were never candidates for an empty claim at all"
            ),
        },
        # The fold's own exposure denominator, published rather than left to be
        # back-solved from grade_exposure — which is undefined whenever the grade
        # is withheld. An empty priced sheet is not_determined, never a zero.
        "tracked_total_usd": plane.tracked_total if plane.per_asset else None,
        "tracked_total_usd_reading": (
            "latest observation per (entity, asset, observed account), implementation folded "
            "onto its proxy; entities with no determined total contribute nothing and are not "
            "read as 0, so this is a floor. null = no priced entity in the perimeter"
        ),
        "balance_rows": len(rows),
        "restaking_rows": len(positions),
        "shared_implementations": shared_impl,
        "shared_implementation_aliases_refused": len(shared_impl),
        "shared_implementation_reading": (
            "an implementation two proxies share folds onto NEITHER: it keeps its own entity "
            "key, so a reach that lands on it is charged that key's own sheet and never the "
            "sheet of whichever proxy an arbitrary pin happened to select. A zero here is the "
            "proven 'no implementation is shared', not an unasked question"
        ),
        "implementation_alias_fixed_point": (
            "resolved transitively, so J->I beside I->P answers P for J; a cycle raises rather than selecting a member"
        ),
        "fetched_at_span_seconds": (
            round((max(fetched) - min(fetched)).total_seconds(), 3) if len(fetched) > 1 else None
        ),
        "fetched_at_is_a_write_timestamp": (
            "not an observation height; a cross-contract sum is not a single-block quantity"
        ),
        "absent_native_row": "not_determined unless contract_balance_fetches.native_status proves zero",
    }
    return plane


def _chain_name(chain_id: int | None) -> str | None:
    if chain_id is None:
        return None
    from utils.chains import UnknownChainError, chain_by_id

    try:
        return coalesce_chain(chain_by_id(int(chain_id)).name)
    except (UnknownChainError, ValueError, TypeError):
        return None


@dataclass
class PrincipalFacts:
    function_principal_id: int
    chain: str
    address: str
    resolved_type: str | None
    owners: frozenset[str]
    threshold: int | None
    delay_seconds: float | None
    protection_credit_withheld: bool
    protection_basis: str
    resolver_bases: tuple[str, ...]
    role_bindings: tuple[tuple[str, str], ...]

    @property
    def key(self) -> str:
        return entity_key(self.chain, self.address)


def load_principal_plane(session: Session, refs: list[Any]) -> dict[int, PrincipalFacts]:
    """``function_principals`` rows behind the signals' references."""
    from db.models import FunctionPrincipal

    ids = sorted({int(ref.function_principal_id) for ref in refs})
    if not ids:
        return {}
    chain_by_id: dict[int, str] = {}
    for ref in refs:
        chain_by_id.setdefault(int(ref.function_principal_id), ref.chain)
    rows = session.query(FunctionPrincipal).filter(FunctionPrincipal.id.in_(ids)).order_by(FunctionPrincipal.id).all()
    out: dict[int, PrincipalFacts] = {}
    for row in rows:
        details = row.details if isinstance(row.details, dict) else {}
        withheld, basis = _safe_protection_verdict(details)
        out[row.id] = PrincipalFacts(
            function_principal_id=row.id,
            chain=coalesce_chain(chain_by_id.get(row.id)),
            address=_lower(row.address),
            resolved_type=row.resolved_type,
            owners=frozenset(_lower(o) for o in (details.get("owners") or []) if o),
            threshold=_int(details.get("threshold")),
            delay_seconds=_float(details.get("delay")),
            protection_credit_withheld=withheld,
            protection_basis=basis,
            resolver_bases=_resolver_bases(details),
            role_bindings=_role_bindings(details),
        )
    return out


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_protection_verdict(details: dict[str, Any]) -> tuple[bool, str]:
    """Whether the k/n demotion is WITHHELD, and on what basis.

    k/n is an upper bound on protection, and only a PROVEN bypass denies the
    credit: a witnessed module (``protection_is_upper_bound`` true, or an
    enumerated non-empty module set) or a witnessed guard address. Everything
    else — an absent plane, an unreadable head word, a basis that proves nothing
    — leaves the credit standing, annotated. Withholding on an unreadable witness
    would be a demotion claim minted from an absence, which the ruling for this
    plane forbids in both directions.
    """
    protection = details.get("safe_protection")
    if not isinstance(protection, dict):
        return False, "safe_protection_absent(not_determined);credit_stands"
    if protection.get("protection_is_upper_bound") is True:
        return True, "protection_is_upper_bound(proven module)"
    module_set = protection.get("module_set")
    if isinstance(module_set, list) and module_set:
        return True, "module_set_enumerated_non_empty(proven module)"
    if protection.get("guard") == "proven_address":
        return True, "guard_proven_present"
    basis = protection.get("module_set_basis")
    if isinstance(module_set, list) and not module_set and basis == "storage_linked_list_terminated":
        return False, f"module_set_proven_empty@{protection.get('probe_block')}"
    return False, f"module_set_not_determined({basis or 'not_determined'});credit_stands"


def _resolver_bases(details: dict[str, Any]) -> tuple[str, ...]:
    bases: set[str] = set()
    for step in details.get("trace") or []:
        if not isinstance(step, dict):
            continue
        basis = step.get("basis")
        if isinstance(basis, str):
            bases.add(basis)
        elif isinstance(basis, list):
            bases.update(str(b) for b in basis)
    return tuple(sorted(bases))


def _role_bindings(details: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """(registry, role_hash) pairs this principal's resolution is bound to.

    Only a trace step naming exactly ONE role hash binds: a fold that published
    several role labels says which roles the registry has, not which one gates
    this function, and attributing a holder floor on that basis would import a
    different role's breadth.
    """
    out: set[tuple[str, str]] = set()
    for step in details.get("trace") or []:
        if not isinstance(step, dict):
            continue
        registry = _lower(step.get("authority") or step.get("registry"))
        labels = step.get("role_labels")
        if not registry or not isinstance(labels, dict) or len(labels) != 1:
            continue
        out.add((registry, _lower(next(iter(labels)))))
    return tuple(sorted(out))


def load_role_holder_floors(session: Session, protocol_id: int) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Proven holder floors per (chain, registry, role hash), protocol-scoped.

    ``holders`` is a LOWER BOUND and ``len(holders)`` is never a count; the floor
    may raise breadth concern and may never lower it. ``holder_set_exhaustive``
    is always ``not_determined``.

    Scoped to the registries THIS protocol's own resolution names — the
    ``authority``/``registry`` of a ``function_principals`` trace step, which is
    the only key the consumer ever looks a floor up by. ``role_holder_planes`` is
    keyed by ``(chain_id, registry_address, role_hash)`` with no protocol column,
    so an unscoped read makes this plane's population a function of which OTHER
    protocols have been analysed: the same protocol scored twice would carry
    different floors, which is a purity break (inv. 11) before it is anything
    else. Scoping loses no floor the fold could have consumed, because a registry
    no trace names has no binding to join to.
    """
    from db.models import Contract, EffectiveFunction, FunctionPrincipal, RoleHolderPlane

    named: set[tuple[str, str]] = set()
    for details, chain in (
        session.query(FunctionPrincipal.details, Contract.chain)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(FunctionPrincipal.id)
        .all()
    ):
        for step in (details or {}).get("trace") or []:
            if not isinstance(step, dict):
                continue
            registry = _lower(step.get("authority") or step.get("registry"))
            if registry:
                named.add((coalesce_chain(chain), registry))
    if not named:
        return {}

    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    rows = (
        session.query(RoleHolderPlane)
        .filter(sql_func.lower(RoleHolderPlane.registry_address).in_(sorted({address for _, address in named})))
        .order_by(RoleHolderPlane.chain_id, RoleHolderPlane.registry_address, RoleHolderPlane.role_hash)
        .all()
    )
    # A row whose chain id maps to no chain is drift, not an admission rule
    # firing: the registry it names may well be one a trace points at, and the
    # floor it would have carried is lost. Counted apart from the rules below,
    # which are this loader's own scoping and holders-basis tests.
    unknown_chain = 0
    for row in rows:
        chain = _chain_name(row.chain_id)
        if chain is None:
            unknown_chain += 1
            continue
        if (chain, _lower(row.registry_address)) not in named:
            continue
        if not isinstance(row.holders, list) or not row.holders:
            continue
        if row.holders_basis != "pinned_has_role_confirmed":
            continue
        out[(chain, _lower(row.registry_address), _lower(row.role_hash))] = {
            "holders_floor": len(row.holders),
            "as_of_block": row.as_of_block,
            "coverage": row.coverage,
            "holder_set_exhaustive": "not_determined",
        }
    if unknown_chain:
        # This loader's return shape is a floor lookup with nowhere to publish a
        # census, so the drift is announced at the boundary instead of silently
        # shortening the floors a unit resolves on.
        logger.warning(
            "role holder floors dropped %d row(s) whose chain id maps to no chain",
            unknown_chain,
            extra={"protocol_id": protocol_id, "rows_dropped": unknown_chain, "rows_read": len(rows)},
        )
    return out


# What an edge's label is allowed to say. A ``role_principal`` label carries the
# role numbers the principal holds ("roles 12", "roles 14,16") or, on 55 of 285,
# the bare relation restatement "role principal" and no role at all. Most other
# labels name a state variable ("owner", "hook", "_roles"), but not all of them
# do: ``controller_value_unattributed`` carries dotted access paths
# ("accountantState.payoutAddress", "fee.treasury"), ``safe_owner`` carries the
# constant "safe owner", and ``capability_principal`` carries no label. Anything
# that is not a role set and not a single identifier is ``not_determined`` — the
# parser earns the state-variable reading rather than assuming it. No label in
# any corpus carries a selector, so an edge never names the function it licenses
# — that join lives in function_principals, not here.
SCOPE_ROLES = "roles"
SCOPE_STATE_VAR = "state_var"
SCOPE_NOT_DETERMINED = "not_determined"

# What produced an edge. ``contracts.admin`` is a column, not a graph row: it
# carries no relation, no label and no id, so it is named by its origin rather
# than given an invented relation.
EDGE_WITNESS_CONTROL_GRAPH = "control_graph_edges"
EDGE_WITNESS_ADMIN_COLUMN = "contracts.admin"
# ``contracts.beacon`` is the same kind of witness as ``contracts.admin`` — a
# column populated by the same slot read, present in no edge table — and it
# carries its own name rather than borrowing admin's, because a consumer that
# wants to know which witness produced a hop must be able to tell them apart.
# Consumers branch on THIS value; ``relation is None`` is a property both share
# and is not a witness.
EDGE_WITNESS_BEACON_COLUMN = "contracts.beacon"

_ROLES_LABEL = re.compile(r"^roles\s+(\d+(?:\s*,\s*\d+)*)$")
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


@dataclass(frozen=True)
class EdgeScope:
    """What an edge's label says its authority is scoped TO.

    Three-valued by construction. A label that names neither a role set nor a
    state variable — the 55 ``role principal`` edges that restate their own
    relation and name no role — is ``not_determined``, never an empty scope: an
    empty scope reads as "licenses nothing", and these edges license something
    nobody wrote down.
    """

    kind: str
    roles: tuple[int, ...] = ()
    state_var: str | None = None
    label: str | None = None

    @property
    def is_determined(self) -> bool:
        return self.kind != SCOPE_NOT_DETERMINED


ROLE_SCOPED_RELATIONS = ("role_principal",)


def parse_edge_scope(label: str | None, relation: str | None = None) -> EdgeScope:
    """The scope an edge label proves, or ``not_determined``.

    The relation decides which readings are AVAILABLE, not which one wins. On a
    ``role_principal`` edge the only positive answer is a role set: the relation
    is the assertion "this principal holds a role", so a label that names no role
    has not named a state variable either, and reading a bare identifier there as
    one fabricated a variable (``state_var="roles"`` on the literal label
    ``roles``) that no source declares and no consumer could check.

    There is deliberately NO relation-restatement branch. One existed to stop a
    single-token label equal to its own relation ("controller_value" on a
    ``controller_value`` edge) from being read as a variable of that name. It
    decided nothing: DB-wide the only labels equal to their relation are the
    multi-word "role principal" and "safe owner", which fail the identifier check
    on their own, and no single-token case exists. What it did carry was an
    inversion hazard — a relation named after a real getter (``authority``) would
    have suppressed the 100 genuine ``authority`` state-var labels the same day
    it was introduced, silently, with no count anywhere. A rule that decides
    nothing and can invert is deleted rather than documented; the role case it
    was covering is now decided by the relation gate above, structurally.
    """
    text = str(label or "").strip()
    if not text:
        return EdgeScope(SCOPE_NOT_DETERMINED)
    match = _ROLES_LABEL.match(text)
    if match:
        return EdgeScope(SCOPE_ROLES, roles=tuple(sorted({int(n) for n in match.group(1).split(",")})), label=text)
    if relation in ROLE_SCOPED_RELATIONS:
        return EdgeScope(SCOPE_NOT_DETERMINED, label=text)
    if _IDENTIFIER.match(text):
        return EdgeScope(SCOPE_STATE_VAR, state_var=text, label=text)
    return EdgeScope(SCOPE_NOT_DETERMINED, label=text)


@dataclass(frozen=True)
class ControlEdge:
    """One proven control edge: ``principal`` has authority over ``anchor``.

    Both ends are chain-scoped entity keys. ``relation`` and ``edge_id`` are
    ``None`` for the ``contracts.admin`` column, which is a witness that exists
    in no edge table.
    """

    principal: str
    anchor: str
    relation: str | None
    scope: EdgeScope
    witness: str
    edge_id: int | None = None


REFUSAL_ZERO_PRINCIPAL = "zero_address_principal"
REFUSAL_ZERO_ANCHOR = "zero_address_anchor"
# A beacon or admin column that names the contract itself. The edge would say
# the entity controls itself, which adds no reach and asserts no authority over
# anyone — refused with a count rather than admitted as a self-loop the walk
# silently absorbs.
REFUSAL_SELF_EDGE = "self_referential_column"
# A stored edge whose endpoint node id carries no address. It is a row this
# loader cannot key, and dropping it uncounted would make a graph writer that
# started emitting unusable ids read as a protocol with less control in it.
REFUSAL_MALFORMED_NODE_ID = "malformed_node_id"


@dataclass(frozen=True)
class RefusedEdge:
    """An edge the closure declined to admit, and the rule that declined it."""

    rule: str
    principal: str
    anchor: str
    relation: str | None
    witness: str
    edge_id: int | None = None


@dataclass(frozen=True)
class RenouncedAuthority:
    """An authority slot proven EMPTY: the anchor's ``label`` holds ``0x0``.

    An earned negative, not a missing edge and not a refused one. For an
    ownership slot this is renunciation; for a configuration pointer it is a
    reference nobody set. Either way the slot names no principal at the observed
    height, which is a resolved constraint — the mirror of the whole defect class
    where a proven fact is discarded because the loader had no shape for it.

    Counted apart from the refusals it coincides with: "we refused to walk an
    edge to the burn address" and "this authority is proven to be held by nobody"
    are different facts and only the second is evidence about the protocol.
    """

    anchor: str
    relation: str | None
    scope: EdgeScope
    witness: str
    edge_id: int | None = None


@dataclass
class ControlClosure:
    """The protocol's control edges, indexed by principal.

    Every edge carries the relation and scope it was proven under, so a walk can
    ask what an edge licenses rather than only whether it exists.
    ``controlled_by`` is the adjacency view — the whole answer this plane used to
    return, now derived from the edges rather than standing in for them.

    ``refusals`` and ``renounced`` are what the loader declined to admit and what
    it read as a proven-absent authority; both are published counts rather than
    silent drops, on the ``5b5db0c4`` template where every admission rule states
    where it fired.
    """

    edges: tuple[ControlEdge, ...] = ()
    refusals: tuple[RefusedEdge, ...] = ()
    renounced: tuple[RenouncedAuthority, ...] = ()
    _out: dict[str, tuple[ControlEdge, ...]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        grouped: dict[str, list[ControlEdge]] = defaultdict(list)
        for edge in self.edges:
            grouped[edge.principal].append(edge)
        self._out = {principal: tuple(rows) for principal, rows in sorted(grouped.items())}

    def principals(self) -> tuple[str, ...]:
        """Every entity with at least one outbound control edge, ordered."""
        return tuple(self._out)

    def edges_from(self, principal: str) -> tuple[ControlEdge, ...]:
        return self._out.get(principal, ())

    def controlled_by(self, principal: str) -> tuple[str, ...]:
        """The distinct entities ``principal`` is a proven controller of."""
        return tuple(sorted({edge.anchor for edge in self.edges_from(principal)}))

    def refusal_counts(self) -> dict[str, int]:
        """Edges refused, per admission rule. A rule that never fired reports 0."""
        counts = {
            REFUSAL_ZERO_PRINCIPAL: 0,
            REFUSAL_ZERO_ANCHOR: 0,
            REFUSAL_SELF_EDGE: 0,
            REFUSAL_MALFORMED_NODE_ID: 0,
        }
        for refusal in self.refusals:
            counts[refusal.rule] = counts.get(refusal.rule, 0) + 1
        return dict(sorted(counts.items()))

    def renounced_counts(self) -> dict[str, Any]:
        """The earned negative, counted three ways because they differ.

        ``control_graph_edges`` carries one row per witnessed read, so the same
        ``owner`` slot on the same anchor appears many times; publishing the row
        count as a slot count multiplies the earned negative by however often the
        resolver looked. The slot is ``(anchor, label)`` — the anchor's named
        authority — and the edge count is kept beside it rather than replaced,
        since it is the citable population.
        """
        slots = {(row.anchor, row.scope.label) for row in self.renounced}
        by_label: dict[str, int] = {}
        for _, label in slots:
            by_label[str(label)] = by_label.get(str(label), 0) + 1
        return {
            "edges": len(self.renounced),
            "authority_slots": len(slots),
            "anchors": len({row.anchor for row in self.renounced}),
            # An ``owner`` slot holding 0x0 is a renunciation; a ``_pendingOwner``
            # or an ``accessController`` holding it is a pointer nobody ever set.
            # Both are proven-absent authority, and the earned negative is the
            # same shape — but they are different facts about the protocol, and
            # the day one of them moves a number the distinction has to already
            # be in the document rather than be reconstructed from it.
            "authority_slots_by_label": dict(sorted(by_label.items())),
        }


def is_zero_key(key: str) -> bool:
    """The burn sentinel, at either end of an edge or as a reach key.

    One helper for every refusal of it — the closure loader here, the reach keys
    and the walk in ``fold`` — so the rule cannot drift between the plane that
    builds the graph and the fold that walks it.
    """
    return key.endswith("::" + ZERO_ADDRESS)


def load_control_closure(session: Session, protocol_id: int) -> ControlClosure:
    """The proven control edges: ``edges_from(X)`` is what X controls.

    Chain-scoped on both ends — an edge is only ever within one chain's graph,
    and keying it unscoped would let one chain's twin inherit the other's reach.

    Two admission rules run here, each publishing its own count. The zero address
    is refused at BOTH ends: it is a burn sentinel, not an assessable entity
    (``msg.sender != 0x0``), and admitting it as a principal makes it the single
    largest control hub in the graph — every anchor that ever renounced an
    authority, folded into one closure that no witness seeds. And a
    ``controller_value`` edge pointing AT it is read as a renounced authority,
    an earned negative, rather than thrown away with the refusal.

    Two column witnesses join the graph rows. ``contracts.admin`` is the proxy
    admin; ``contracts.beacon`` is the beacon whose implementation slot every
    proxy pointing at it follows — the broadest code-control link there is, and
    one the closure carried no representation of at all. Both are populated by
    the same slot read, exist in no edge table, and carry their own witness
    string so a consumer can tell which produced a hop.
    """
    from db.models import Contract, ControlGraphEdge

    edges: list[ControlEdge] = []
    refusals: list[RefusedEdge] = []
    renounced: list[RenouncedAuthority] = []

    def admit(candidate: ControlEdge) -> None:
        zero_principal = is_zero_key(candidate.principal)
        if zero_principal and candidate.relation == "controller_value":
            renounced.append(
                RenouncedAuthority(
                    anchor=candidate.anchor,
                    relation=candidate.relation,
                    scope=candidate.scope,
                    witness=candidate.witness,
                    edge_id=candidate.edge_id,
                )
            )
        # The self-edge rule is scoped to the COLUMN witnesses: a
        # ``contracts.beacon`` naming the proxy itself is a degenerate column
        # read, while a witnessed graph row saying an entity holds authority
        # over itself is a fact this loader has no licence to discard.
        self_column = candidate.principal == candidate.anchor and candidate.relation is None
        if zero_principal or is_zero_key(candidate.anchor) or self_column:
            refusals.append(
                RefusedEdge(
                    rule=(
                        REFUSAL_ZERO_PRINCIPAL
                        if zero_principal
                        else REFUSAL_ZERO_ANCHOR
                        if is_zero_key(candidate.anchor)
                        else REFUSAL_SELF_EDGE
                    ),
                    principal=candidate.principal,
                    anchor=candidate.anchor,
                    relation=candidate.relation,
                    witness=candidate.witness,
                    edge_id=candidate.edge_id,
                )
            )
            return
        edges.append(candidate)

    rows = (
        session.query(ControlGraphEdge, Contract.chain)
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .filter(Contract.protocol_id == protocol_id, ControlGraphEdge.relation.in_(CONTROL_RELATIONS))
        .order_by(ControlGraphEdge.id)
        .all()
    )
    for edge, chain in rows:
        source = _lower(str(edge.from_node_id or "").replace("address:", ""))
        target = _lower(str(edge.to_node_id or "").replace("address:", ""))
        if not source or not target:
            refusals.append(
                RefusedEdge(
                    rule=REFUSAL_MALFORMED_NODE_ID,
                    # Chain-scoped like every sibling refusal; the endpoint that
                    # carried no address has no key to be scoped.
                    principal=entity_key(chain, target) if target else NOT_DETERMINED,
                    anchor=entity_key(chain, source) if source else NOT_DETERMINED,
                    relation=edge.relation,
                    witness=EDGE_WITNESS_CONTROL_GRAPH,
                    edge_id=edge.id,
                )
            )
            continue
        # Stored from=anchor, to=principal; the authority direction is the
        # reverse, so the principal is what controls the anchor.
        admit(
            ControlEdge(
                principal=entity_key(chain, target),
                anchor=entity_key(chain, source),
                relation=edge.relation,
                scope=parse_edge_scope(edge.label, edge.relation),
                witness=EDGE_WITNESS_CONTROL_GRAPH,
                edge_id=edge.id,
            )
        )
    for contract in session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all():
        chain = coalesce_chain(contract.chain)
        for column, witness in (
            (contract.admin, EDGE_WITNESS_ADMIN_COLUMN),
            (contract.beacon, EDGE_WITNESS_BEACON_COLUMN),
        ):
            if not column:
                continue
            admit(
                ControlEdge(
                    principal=entity_key(chain, column),
                    anchor=entity_key(chain, contract.address),
                    relation=None,
                    scope=EdgeScope(SCOPE_NOT_DETERMINED),
                    witness=witness,
                )
            )
    return ControlClosure(edges=tuple(edges), refusals=tuple(refusals), renounced=tuple(renounced))


# --- what a destination's own conditions say about who may call it -----------
#
# A control edge proves AUTHORITY over an entity. It does not prove that the
# entity's own code will accept the controlled node as caller: a destination may
# pin its caller to itself, and no authority relation makes one address another.
# ``effective_functions.conditions`` carries those guards verbatim; the fold read
# none of them, so every hop walked as if the destination had no opinion.
#
# Only ONE shape is recognised as a proven disproof, and it is recognised from
# the verbatim text: a caller-or-initiator identity compared against
# ``address(this)``. Everything else — a balance check, a business predicate, an
# authorization call whose passing is exactly what the control edge witnesses —
# bears on the caller not at all and is not read as one. A recogniser that
# guessed more would turn every unparsed predicate into a refusal and delete a
# proven authority relation on the strength of a string nobody analysed.
HOP_WALKED = "walked"
HOP_NOT_DETERMINED = "not_determined"

# Whose identity the guard pins. ``msg.sender`` is the caller itself; the named
# parameters are the caller as the destination's own callee convention passes it
# on (``initiator`` in a solver callback), which is the same question one frame
# out.
#
# The recogniser is deliberately BROAD on two axes, and both are safe in exactly
# one direction:
#
#   comparator  ``!=`` and ``==`` are both read as a pin. The stored
#               ``description`` is a verbatim predicate with no polarity: the
#               same text is a require-condition in one function and a
#               revert-condition in another, so which comparator means "the
#               caller must be the destination" is not recoverable from it.
#   term        ``sender``/``caller``/``initiator`` (with or without a leading
#               underscore) are read as the caller. A parameter so named is the
#               caller under every callee convention this corpus uses, but the
#               name is the whole evidence — a parameter named ``initiator`` that
#               carried something else would be read as a caller pin here.
#
# Both over-reads land on the same side: a recognised pin only ever moves a hop
# from walked to ``not_determined``. Nothing in this module can turn a pin into a
# proven-clear, so breadth costs withheld reach and never mints reach. The
# reverse error — a pin this regex misses — is the one that would over-claim, and
# it is why the shape is not narrowed further. ``(?<![\w$])`` keeps the terms
# whole, so ``spender``/``resender`` are not caller terms.
_CALLER_TERM = r"(?:msg\.sender|_?sender|_?caller|_?initiator)"
_SELF_PIN = re.compile(
    rf"(?<![\w$])(?:{_CALLER_TERM}\s*[!=]=\s*address\(this\)|address\(this\)\s*[!=]=\s*{_CALLER_TERM}(?![\w$]))"
)

SURFACE_FUNCTION_PRINCIPAL = "function_principal_witness"
SURFACE_DESTINATION_FUNCTIONS = "destination_functions"
SURFACE_NONE = "destination_functions_not_analysed"

# On what a walked hop was walked. "No condition disproved the caller" is three
# different facts, and only the first of them is a read of any condition:
#
#   FULLY          every function consulted at the destination had its
#                  conditions extracted, so the read is complete: a guard was
#                  there to find on all of them and was found on none.
#   PARTLY         at least one permitting function had its conditions
#                  extracted and at least one consulted function did not. A
#                  guard was found on none, but the surface the answer rests on
#                  is not the surface that was consulted.
#   UNANALYSED     every function that permits the caller has ``conditions``
#                  NULL — the extraction never ran there, so "no guard" is a
#                  coverage gap wearing the shape of a clean read.
#   NO_FUNCTION    the destination has no analysed function at all; nothing was
#                  consulted, and the hop stands on the edge alone.
#
# The hop is walked in all three (refusing on an absence would let a coverage
# gap overturn a proven authority relation), so the distinction is a DISCLOSURE
# and not a bound — but a consumer cannot tell a checked hop from an unchecked
# one unless the counts are published apart.
WALKED_ON_ANALYSED_FULLY = "walked_on_fully_analysed_conditions"
WALKED_ON_ANALYSED_PARTLY = "walked_on_partly_analysed_conditions"
WALKED_ON_UNANALYSED = "walked_on_unanalysed_conditions"
WALKED_NO_FUNCTION = "walked_with_no_analysed_function"
WALKED_COVERAGE = (
    WALKED_ON_ANALYSED_FULLY,
    WALKED_ON_ANALYSED_PARTLY,
    WALKED_ON_UNANALYSED,
    WALKED_NO_FUNCTION,
)


@dataclass(frozen=True)
class DestinationFunction:
    """One function of a destination entity, and the caller guards it carries.

    ``analysed`` separates "conditions were extracted and none pins the caller"
    from "the column holds no array and nothing was extracted". Both reach
    ``caller_pinned_to_self == ()``, and reading the second as the first is the
    absence-as-a-witness move at the coverage level. The discriminator is
    ``isinstance(conditions, list)``, which is what puts a SQL null and the
    jsonb scalar null on the same side as each other and the opposite side from
    an empty array — the three-state this column's own read has to make.
    """

    function_id: int
    name: str
    caller_pinned_to_self: tuple[str, ...] = ()
    analysed: bool = False
    # This function's own selector, so a consumer can join to it on the four
    # bytes a licence names rather than on a name — 32 ``(entity, name)`` pairs
    # on the reference corpus carry more than one selector. ``None`` is a
    # function whose selector was never extracted, and it matches nothing.
    selector: str | None = None
    # Every predicate text the column holds, in stored order, verbatim and
    # UNFILTERED. ``caller_pinned_to_self`` above is the one recognised shape;
    # this is the whole population it was recognised out of, kept so a
    # disclosure can point at the evidence. Nothing here is evaluated: the text
    # carries no polarity (see ``_SELF_PIN``), so it is not readable as a
    # condition that must hold or must not.
    predicates: tuple[str, ...] = ()
    # Entries the stored array held. Larger than ``len(predicates)`` when an
    # entry carried no string ``description``, which is a shortfall in the
    # disclosure and not a predicate that is absent.
    predicate_entries_stored: int = 0


# The three states a predicate lookup can land in, kept apart because "the
# column held an empty array" is an extraction that RAN and found nothing, "the
# column holds no array" is one that never ran, and "no function of this entity
# carries that selector" is a join that missed. Collapsing any two of them would
# publish a coverage gap as a proven absence of predicates.
PREDICATES_EXTRACTED = "extracted"
PREDICATES_COLUMN_HOLDS_NO_ARRAY = "column_holds_no_array"
PREDICATES_FUNCTION_NOT_LOCATED = "destination_function_not_located"


@dataclass(frozen=True)
class DestinationPredicates:
    """The verbatim predicate texts one destination function's body carries.

    A DISCLOSURE and nothing else. The texts are stored without polarity — the
    same string is a require-condition in one function and a revert-condition in
    another — so no consumer of this can tell whether any of them must hold or
    must not, and none of them is evaluated anywhere. It exists so a reader can
    see the evidence a claim about that function was NOT made against.

    ``functions_matching`` is published because a selector is not guaranteed
    unique within an entity: an entity that folds a proxy and its implementation
    can carry two rows under one selector, and a reader is owed the fact that
    the texts below are one of them rather than the whole surface.
    """

    state: str
    function_id: int | None
    function_name: str | None
    descriptions: tuple[str, ...] | None
    entries_stored: int | None
    functions_matching: int


@dataclass(frozen=True)
class HopConditions:
    """What the destination's conditions say about one caller reaching it."""

    state: str
    basis: str
    surface: str
    functions_consulted: int
    disproving: tuple[dict[str, Any], ...] = ()
    # For a walked hop, which of the three readings above licensed it. ``None``
    # on a hop that was not walked.
    coverage: str | None = None


@dataclass
class ConditionPlane:
    """``effective_functions.conditions``, indexed for the closure walk.

    ``by_entity`` is every analysed function of an entity. ``licensed`` is the
    narrower and better-evidenced surface: the functions of that entity on which
    a given address is a RESOLVED principal, which is the only positive witness
    this plane has of what one caller may do at one destination.
    """

    by_entity: dict[str, tuple[DestinationFunction, ...]] = field(default_factory=dict)
    licensed: dict[tuple[str, str], tuple[DestinationFunction, ...]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def predicates(self, destination: str, selector: str) -> DestinationPredicates:
        """Every predicate text stored for ``destination``'s function ``selector``.

        Read-only, from ``effective_functions.conditions`` — the CANONICAL
        column, which is the one this plane loads. It is never read from
        ``function_principals.details.conditions``: that copy disagrees with the
        column on 270 of 1593 protocol-1 controller rows and nothing reconciles
        them, so a consumer that read it would be publishing a second, unowned
        extraction as this one.

        Nothing here filters, orders, evaluates or classifies. ``kind`` on the
        stored entry is not read: the label is applied to every entry the
        extractor emits — authorization guards, transfer post-conditions and
        decompiler temporaries all arrive as ``business`` — so branching on it
        would sort by a field that carries no information.
        """
        wanted = (selector or "").lower()
        # A function whose own selector was never extracted matches nothing:
        # four bytes nobody recorded do not name a function, and joining on the
        # empty string would hand back an arbitrary row's predicates.
        matching = (
            [fn for fn in self.by_entity.get(destination, ()) if fn.selector and fn.selector.lower() == wanted]
            if wanted
            else []
        )
        if not matching:
            return DestinationPredicates(PREDICATES_FUNCTION_NOT_LOCATED, None, None, None, None, 0)
        # Lowest ``function_id`` where a selector is carried twice: arbitrary,
        # deterministic, and disclosed through ``functions_matching``.
        function = min(matching, key=lambda fn: fn.function_id)
        if not function.analysed:
            return DestinationPredicates(
                PREDICATES_COLUMN_HOLDS_NO_ARRAY, function.function_id, function.name, None, None, len(matching)
            )
        return DestinationPredicates(
            PREDICATES_EXTRACTED,
            function.function_id,
            function.name,
            function.predicates,
            function.predicate_entries_stored,
            len(matching),
        )

    def hop(self, caller: str, destination: str) -> HopConditions:
        """Whether ``destination``'s own guards permit ``caller`` to act there.

        The consulted surface is the function-level witness where one exists and
        the destination's whole analysed function set otherwise. A hop is walked
        when at least one consulted function carries no guard pinning its caller
        to the destination itself; it is ``not_determined`` when every consulted
        function does. It is never published as a proven negative: the principal
        enumeration behind the licensed surface is a documented LOWER bound, so
        "no function we witnessed is callable" is not "no function is".

        A destination with no analysed function at all consults nothing, and
        nothing is not a disproof — the edge remains the witness and the
        shortfall is counted rather than converted into a refusal.

        A walked hop carries WHICH of the three coverage readings licensed it,
        because "no condition disproved this caller" over a function whose
        conditions were never extracted is not the same fact as over one whose
        were.
        """
        if caller == destination:
            return HopConditions(HOP_WALKED, "caller_is_the_destination", SURFACE_NONE, 0, coverage=WALKED_NO_FUNCTION)
        surface = self.licensed.get((destination, caller))
        surface_kind = SURFACE_FUNCTION_PRINCIPAL
        if not surface:
            surface = self.by_entity.get(destination) or ()
            surface_kind = SURFACE_DESTINATION_FUNCTIONS if surface else SURFACE_NONE
        if not surface:
            return HopConditions(
                HOP_WALKED,
                "destination_functions_not_analysed(no caller condition witnessed)",
                SURFACE_NONE,
                0,
                coverage=WALKED_NO_FUNCTION,
            )
        permitted = [fn for fn in surface if not fn.caller_pinned_to_self]
        if permitted:
            analysed = [fn for fn in permitted if fn.analysed]
            consulted_analysed = sum(1 for fn in surface if fn.analysed)
            coverage = WALKED_ON_UNANALYSED
            if analysed:
                coverage = WALKED_ON_ANALYSED_FULLY if consulted_analysed == len(surface) else WALKED_ON_ANALYSED_PARTLY
            return HopConditions(
                HOP_WALKED,
                (
                    f"caller_condition_permits({len(permitted)} of {len(surface)} consulted "
                    f"functions, {len(analysed)} of them with conditions extracted; "
                    f"{consulted_analysed} of {len(surface)} consulted functions analysed)"
                ),
                surface_kind,
                len(surface),
                coverage=coverage,
            )
        return HopConditions(
            HOP_NOT_DETERMINED,
            "caller_pinned_to_the_destination_itself_on_every_consulted_function",
            surface_kind,
            len(surface),
            tuple(
                {"function": fn.name, "function_id": fn.function_id, "conditions": list(fn.caller_pinned_to_self)}
                for fn in surface
            ),
        )


def _caller_self_pins(conditions: Any) -> tuple[str, ...]:
    """The verbatim conditions that pin this function's caller to itself."""
    if not isinstance(conditions, list):
        return ()
    out: list[str] = []
    for entry in conditions:
        text = entry.get("description") if isinstance(entry, dict) else None
        if isinstance(text, str) and _SELF_PIN.search(text):
            out.append(text)
    return tuple(out)


def _stored_predicates(conditions: Any) -> tuple[tuple[str, ...], int]:
    """Every stored predicate text, verbatim and in stored order, and the entry count.

    The whole array, unfiltered: this is the population ``_caller_self_pins``
    recognises one shape out of, kept so a disclosure can point at what was not
    read rather than assert it was not read. An entry carrying no string
    ``description`` contributes to the count and not to the texts, so the two
    disagreeing is visible instead of silent.
    """
    if not isinstance(conditions, list):
        return (), 0
    texts = [
        entry["description"]
        for entry in conditions
        if isinstance(entry, dict) and isinstance(entry.get("description"), str)
    ]
    return tuple(texts), len(conditions)


def load_condition_plane(session: Session, protocol_id: int) -> ConditionPlane:
    """The destination-side caller guards the closure walk is bounded by."""
    from db.models import Contract, EffectiveFunction, FunctionPrincipal

    plane = ConditionPlane()
    by_entity: dict[str, list[DestinationFunction]] = defaultdict(list)
    entity_of: dict[int, tuple[str, str]] = {}
    functions = (
        session.query(
            EffectiveFunction.id,
            EffectiveFunction.function_name,
            EffectiveFunction.conditions,
            EffectiveFunction.deployment_address,
            EffectiveFunction.selector,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    pinned_functions = 0
    analysed_functions = 0
    stored_predicates = 0
    for function_id, name, conditions, deployment, selector, address, chain in functions:
        chain_name = coalesce_chain(chain)
        key = entity_key(chain_name, deployment or address)
        pins = _caller_self_pins(conditions)
        texts, entries = _stored_predicates(conditions)
        # An ARRAY is an extraction that ran, empty or not. Anything else — a SQL
        # null, the jsonb scalar null a Python ``None`` write stores — is one
        # that never did, and the two are indistinguishable downstream unless
        # they are separated here.
        analysed = isinstance(conditions, list)
        pinned_functions += 1 if pins else 0
        analysed_functions += 1 if analysed else 0
        stored_predicates += entries
        by_entity[key].append(
            DestinationFunction(
                int(function_id),
                str(name),
                pins,
                analysed,
                (str(selector).lower() if selector else None),
                texts,
                entries,
            )
        )
        entity_of[int(function_id)] = (key, chain_name)
    plane.by_entity = {key: tuple(rows) for key, rows in sorted(by_entity.items())}

    licensed: dict[tuple[str, str], list[DestinationFunction]] = defaultdict(list)
    rows = (
        session.query(FunctionPrincipal.function_id, FunctionPrincipal.address)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(FunctionPrincipal.id)
        .all()
    )
    by_id = {fn.function_id: fn for rows_ in plane.by_entity.values() for fn in rows_}
    for function_id, address in rows:
        located = entity_of.get(int(function_id))
        if located is None:
            continue
        destination, chain_name = located
        function = by_id.get(int(function_id))
        if function is None:
            continue
        licensed[(destination, entity_key(chain_name, address))].append(function)
    plane.licensed = {key: tuple(rows_) for key, rows_ in sorted(licensed.items())}
    plane.provenance = {
        "functions": len(functions),
        "entities_with_analysed_functions": len(plane.by_entity),
        # The coverage this recogniser actually had. A function whose
        # ``conditions`` column is NULL carries no guard to find, so it can only
        # ever report "nothing disproves this caller" — which is the answer a
        # clean read gives too. Published apart, because a hop walked over
        # nothing but unextracted functions is not a checked hop.
        "functions_with_conditions_extracted": analysed_functions,
        "functions_with_no_conditions_recorded": len(functions) - analysed_functions,
        "functions_pinning_caller_to_self": pinned_functions,
        # The whole predicate population the recogniser above ran over, counted
        # so the one shape it recognises is readable against a denominator. None
        # of these is evaluated anywhere; they are retained per function only so
        # a composed magnitude can point a reader at the destination body's own
        # guards instead of asserting they were not read.
        "predicate_entries_stored": stored_predicates,
        "caller_licensed_pairs": len(plane.licensed),
        "recognised_shape": (
            "a caller-or-initiator identity compared against address(this), read verbatim from "
            "effective_functions.conditions[].description. No other predicate is read as a "
            "statement about the caller: an authorization call is the gate the control edge "
            "already witnesses, and an unparsed business predicate is not evidence against a "
            "proven authority relation"
        ),
        "recogniser_breadth": (
            "BOTH comparators (!= and ==) count as a pin, because the stored description is a "
            "verbatim predicate carrying no polarity — the same text is a require-condition in "
            "one function and a revert-condition in another. msg.sender and whole-word "
            "sender/caller/initiator (with or without a leading underscore) all count as the "
            "caller, on the name alone. Both over-reads move a hop from walked to "
            "not_determined and NOTHING here can mint a proven-clear, so the breadth costs "
            "withheld reach and never reach"
        ),
        "surface_rule": (
            "the functions of the destination on which the caller is a RESOLVED principal where "
            "such a witness exists, else the destination's whole analysed function set. A "
            "destination with no analysed function consults nothing and the hop stands on the "
            "edge rather than being converted into a refusal. The shortfall that produces is "
            "counted in provenance.reach_bounds.hop_census, which splits every walked hop into "
            "walked_on_fully_analysed_conditions, walked_on_partly_analysed_conditions, "
            "walked_on_unanalysed_conditions and walked_with_no_analysed_function. Only the "
            "first rests on a surface that was read in full; the second found a guard on none "
            "of the functions it could read and could not read all of them; the last two are "
            "hops no condition was ever read for, and they are walked on the edge alone"
        ),
    }
    return plane


# --- what a gate CONFERS -----------------------------------------------------
#
# A control edge proves that an authority relation EXISTS. It does not prove
# that the gate a finding seizes is the authority that relation runs on, and
# until this plane there was nothing to ask: gate control walked every edge whose
# label named a scope at all, which is a label-PRESENCE test wearing a conferral
# test's name. Two witnesses answer it, one per scope kind.
#
#   roles N      The role -> selector join. ``function_principals.details.trace[]``
#                records, per resolved principal, the step that admitted it —
#                ``(step, authority, target, selector, roles)`` — so "role N at
#                target T" resolves to the SELECTORS role N licenses at T. A
#                selector is credited only where ``effective_functions.selector``
#                names a function of T under it: four bytes nobody can name is
#                not a licensed function, and the named function is what a
#                magnitude can later be attributed to. A role that licenses no
#                named function at the destination confers nothing anyone can
#                point at, and the hop is not_determined.
#
#   state_var L  A SAME-KIND BOUND, not a conferral witness. Read exactly:
#                the gate's own ``effective_functions.state_writes`` names the
#                variable IT rewrites, on ITS contract; the edge's label names
#                the authority slot on the DESTINATION's contract. Requiring the
#                two names to match is a name match across two different
#                contracts' storage, and it witnesses no composition step — no
#                row anywhere says that seizing A's ``owner`` lets its holder
#                exercise A's ownership of B. What the match does is REFUSE
#                every hop whose authority is of a different kind from the one
#                the gate is witnessed to seize, which is a bound, and a bound
#                is all it is published as. ownership.transfer is witnessed
#                writing owner/_owner; authority.replace writing authority;
#                roles.grant writing _roles. None is witnessed writing hook,
#                vault, roleRegistry or endpoint, so hops running on those are
#                refused. A same-kind hop is walked as the label-presence test
#                already walked it — this bound removes hops, it adds no
#                evidence to the ones that survive.
#
#                Where the kinds differ the hop is NOT disproved and the row is
#                not the only thing missing: whether the seized gate reaches the
#                other authority turns on the intermediate node's own function
#                surface, and THIS PLANE DOES NOT CONSULT IT. The surface often
#                exists — 0x4df6b733's setUserRole, setRoleCapability and
#                transferOwnership are analysed ``effective_functions`` rows on
#                the reference corpus — so this is a join not performed, not a
#                witness that is missing. The join that would decide it is the
#                intermediate node's own functions (``effective_functions``
#                at A, gated by the authority the capability seizes) against its
#                outbound targets (``effective_functions.sinks`` /
#                ``effect_targets``, and the ``external_call_target`` edges
#                CONTROL_RELATIONS excludes): does a function of A that the
#                seized gate lets its holder call exercise A's authority over B.
#                Until that runs, the hop is not_determined — withheld and
#                published, never walked and never counted as a proven negative.
#
# One residual, named rather than assumed away: the ROLE branch asks only what
# the role licenses at the destination. It does not additionally require the
# seizing capability to be one that governs role assignment, so an
# ``authority.replace`` gate walks a ``roles N`` hop on the join's answer alone.
# That is the same homogeneity question the state-variable branch answers with
# state_writes, and there is no equivalent witness for it — the role edge names a
# role, not the authority slot that grants it. The bound stated here is therefore
# what the role LICENSES, which is the bound a compositional magnitude needs, and
# it is an upper bound on what this gate can exercise.
CONFERRAL_CONFERRED = "conferred"
CONFERRAL_SCOPE_NOT_DETERMINED = "scope_not_determined"
CONFERRAL_ROLE_NOT_LICENSED = "role_licenses_no_named_function_at_the_destination"
CONFERRAL_VARIABLE_NOT_REWRITTEN = "capability_not_witnessed_rewriting_this_variable"
CONFERRAL_WRITES_NOT_EXTRACTED = "capability_state_writes_not_extracted"
CONFERRAL_OUTCOMES = (
    CONFERRAL_CONFERRED,
    CONFERRAL_SCOPE_NOT_DETERMINED,
    CONFERRAL_ROLE_NOT_LICENSED,
    CONFERRAL_VARIABLE_NOT_REWRITTEN,
    CONFERRAL_WRITES_NOT_EXTRACTED,
)

# ``state_writes[].origin``: a write in the function BODY is the function doing
# it. A write attributed to a guard is the modifier's bookkeeping (a reentrancy
# latch, a namespaced-storage pointer read) and is not what the capability
# rewrites, so it is not evidence of the authority the gate seizes.
_WRITE_ORIGIN_BODY = "body"


@dataclass(frozen=True, order=True)
class LicensedFunction:
    """One named function a role licenses at a destination.

    Structured, not a formatted string: the selector is the join key back into
    ``effective_functions`` and the name is for the reader. Publishing
    ``"0x39d6ba32 enter"`` made every consumer re-parse a string this plane had
    already taken apart, and a function name containing a space would have
    broken the parse silently.
    """

    selector: str
    name: str

    def as_json(self) -> dict[str, str]:
        return {"selector": self.selector, "name": self.name}


@dataclass(frozen=True)
class ConferralVerdict:
    """Whether one gate confers one hop, and what it confers there."""

    outcome: str
    licensed: tuple[LicensedFunction, ...] = ()
    basis: str = ""

    @property
    def conferred(self) -> bool:
        return self.outcome == CONFERRAL_CONFERRED


@dataclass(frozen=True)
class GateGrant:
    """One gate-control capability instance, and what its witness says it seizes.

    ``rewrites`` is read from the SPECIFIC function the signal was witnessed on,
    not from the capability's class-wide behaviour: the claim being tested is
    what THIS gate rewrites. ``writes_extracted`` keeps the coverage gap distinct
    from an empty answer — a function whose ``state_writes`` never ran rewrites
    nothing anyone read, which is not the same fact as a function proven to
    rewrite nothing, and both are withheld rather than either being walked.
    """

    capability: str
    rewrites: frozenset[str]
    writes_extracted: bool
    basis: str
    plane: ConferralPlane = field(repr=False, compare=False)

    def confers(self, scope: EdgeScope, destination: str) -> ConferralVerdict:
        if not scope.is_determined:
            return ConferralVerdict(
                CONFERRAL_SCOPE_NOT_DETERMINED,
                basis=(
                    "the edge's label names no role and no state variable, so what this gate "
                    "would confer here is not_determined"
                ),
            )
        if scope.kind == SCOPE_ROLES:
            licensed = self.plane.licensed_functions(destination, scope.roles)
            if not licensed:
                return ConferralVerdict(
                    CONFERRAL_ROLE_NOT_LICENSED,
                    basis=(
                        f"no witnessed trace step licenses role(s) {list(scope.roles)} to a named "
                        f"function of {destination}, so the hop confers nothing that can be named"
                    ),
                )
            return ConferralVerdict(
                CONFERRAL_CONFERRED,
                licensed,
                basis=(
                    f"role(s) {list(scope.roles)} license {len(licensed)} named function(s) at "
                    f"{destination} (function_principals.details.trace[].selector joined to "
                    "effective_functions.selector)"
                ),
            )
        if not self.writes_extracted:
            return ConferralVerdict(CONFERRAL_WRITES_NOT_EXTRACTED, basis=self.basis)
        if scope.state_var not in self.rewrites:
            return ConferralVerdict(
                CONFERRAL_VARIABLE_NOT_REWRITTEN,
                basis=(
                    f"{self.capability} is witnessed rewriting {sorted(self.rewrites)} on its own "
                    f"contract and not '{scope.state_var}', so this hop runs on an authority of a "
                    "different kind from the one the gate seizes. Refused as a same-kind bound; "
                    "whether it composes anyway turns on the intermediate node's function surface, "
                    "which this plane does not consult"
                ),
            )
        return ConferralVerdict(
            CONFERRAL_CONFERRED,
            basis=(
                f"same-kind: {self.capability} is witnessed rewriting a variable named "
                f"'{scope.state_var}' on its own contract, which is the name the hop's authority "
                f"slot carries on the destination's ({self.basis}). A NAME MATCH ACROSS TWO "
                "CONTRACTS' STORAGE, not a witness that seizing one exercises the other — the "
                "composition step is unwitnessed and this bound only removes hops of a different "
                "kind"
            ),
        )


@dataclass
class ConferralPlane:
    """The two conferral witnesses, indexed for the walk.

    ``role_functions`` is the role -> selector join, already narrowed to
    selectors that name a function. ``writes_by_function`` is per-function and is
    what the walk consults; ``writes_by_capability`` is the same evidence rolled
    up to the class and is used ONLY by the census, which has no instance to ask.
    The two are published side by side because the class-wide union is an upper
    bound on the per-function answer, and a reader comparing a census count to a
    finding's walk has to be able to see which one they are looking at.
    """

    role_functions: dict[tuple[str, int], tuple[LicensedFunction, ...]] = field(default_factory=dict)
    writes_by_function: dict[int, frozenset[str]] = field(default_factory=dict)
    writes_by_capability: dict[str, frozenset[str]] = field(default_factory=dict)
    # The recovery key for a signal whose ``function_id`` no longer resolves.
    # Populated only where every function under the key agrees on what it
    # rewrites; a key two functions disagree under is left out, because a
    # recovered answer nobody can attribute to one row is a guess.
    writes_by_deployment_selector: dict[tuple[str, str], frozenset[str]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def licensed_functions(self, destination: str, roles: tuple[int, ...]) -> tuple[LicensedFunction, ...]:
        """The named functions the union of ``roles`` licenses at ``destination``.

        The union is the honest read of a multi-role label: "roles 5,9" is one
        principal holding both, and each licenses what it licenses.
        """
        out: set[LicensedFunction] = set()
        for role in roles:
            out.update(self.role_functions.get((destination, int(role)), ()))
        return tuple(sorted(out))

    def grant_for(
        self, capability: str, function_id: int | None, *, entity: str | None = None, selector: str | None = None
    ) -> GateGrant:
        """What one gate seizes, by its own function where that still resolves.

        ``function_score_signals.function_id`` is ``ON DELETE SET NULL`` against
        ``effective_functions``, and a re-analysis DELETES and reinserts a
        contract's rows — so a persisted signal that outlives one re-analysis
        points at nothing, and this lookup would report every gate as
        "state_writes not extracted" and quietly stop walking hops it walked
        yesterday. The withhold would be counted and its CAUSE would be a stale
        foreign key, indistinguishable from an extraction that never ran.

        So a dangling reference falls back to the signal's own
        ``(deployment entity, selector)`` — the identity the signal carries in
        its own columns and the re-analysis preserves. The fallback is admitted
        only where every function under that key agrees on what it rewrites; a
        key two functions disagree under resolves to nothing, and the grant
        stays unextracted rather than picking one.
        """
        writes = self.writes_by_function.get(function_id) if function_id is not None else None
        if writes is not None:
            return GateGrant(
                capability, writes, True, f"effective_functions.state_writes(function {function_id})", self
            )
        key = (str(entity), _lower(str(selector))) if entity and selector else None
        recovered = self.writes_by_deployment_selector.get(key) if key else None
        if recovered is not None:
            return GateGrant(
                capability,
                recovered,
                True,
                (
                    f"effective_functions.state_writes recovered on (deployment, selector) {key} — "
                    f"function_id {function_id} does not resolve"
                ),
                self,
            )
        return GateGrant(
            capability,
            frozenset(),
            False,
            (
                "effective_functions.state_writes carries no extracted array for this gate: "
                f"function_id {function_id} does not resolve and (deployment, selector) {key} "
                "recovers no single agreed answer, so what this gate rewrites was never read"
            ),
            self,
        )

    def capability_grant(self, capability: str) -> GateGrant:
        """The class-wide grant: the UNION of what every witness of ``capability``
        rewrites anywhere in this protocol. Strictly wider than any one instance's
        grant, so it is a census instrument and never a walk input.
        """
        writes = self.writes_by_capability.get(capability)
        if writes is None:
            return GateGrant(
                capability,
                frozenset(),
                False,
                f"no function carrying {capability} has extracted state_writes in this protocol",
                self,
            )
        return GateGrant(
            capability,
            writes,
            True,
            f"union of effective_functions.state_writes over every {capability} witness in this protocol",
            self,
        )


def load_conferral_plane(session: Session, protocol_id: int) -> ConferralPlane:
    """The role -> selector join and the capability -> rewritten-variable witness."""
    from db.models import Contract, EffectiveFunction, FunctionPrincipal

    named: dict[tuple[str, str], LicensedFunction] = {}
    writes_by_function: dict[int, frozenset[str]] = {}
    writes_by_key: dict[tuple[str, str], set[frozenset[str]]] = defaultdict(set)
    claims_by_function: dict[int, tuple[str, ...]] = {}
    functions = (
        session.query(
            EffectiveFunction.id,
            EffectiveFunction.function_name,
            EffectiveFunction.selector,
            EffectiveFunction.state_writes,
            EffectiveFunction.claims,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    for function_id, name, selector, state_writes, claims, deployment, address, chain in functions:
        key = entity_key(coalesce_chain(chain), deployment or address)
        token = _lower(str(selector)) if selector else None
        if token:
            named.setdefault((key, token), LicensedFunction(token, str(name)))
        # An ARRAY is an extraction that ran; anything else never did, and the
        # two must not reach the walk as the same empty answer.
        if isinstance(state_writes, list):
            written = frozenset(
                str(entry.get("var"))
                for entry in state_writes
                if isinstance(entry, dict) and entry.get("var") and entry.get("origin") == _WRITE_ORIGIN_BODY
            )
            writes_by_function[int(function_id)] = written
            if token:
                writes_by_key[(key, token)].add(written)
        if isinstance(claims, list):
            claims_by_function[int(function_id)] = tuple(
                str(entry.get("claim_id")) for entry in claims if isinstance(entry, dict) and entry.get("claim_id")
            )

    writes_by_capability: dict[str, set[str]] = defaultdict(set)
    capability_functions: dict[str, int] = defaultdict(int)
    capability_functions_extracted: dict[str, int] = defaultdict(int)
    for function_id, claim_ids in claims_by_function.items():
        for claim_id in set(claim_ids):
            capability_functions[claim_id] += 1
            writes = writes_by_function.get(function_id)
            if writes is None:
                continue
            capability_functions_extracted[claim_id] += 1
            writes_by_capability[claim_id].update(writes)

    role_functions: dict[tuple[str, int], set[LicensedFunction]] = defaultdict(set)
    role_authorities: dict[tuple[str, int], set[str]] = defaultdict(set)
    steps = unnamed_selectors = 0
    principals = (
        session.query(FunctionPrincipal.details, Contract.chain)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(FunctionPrincipal.id)
        .all()
    )
    for details, chain in principals:
        trace = (details or {}).get("trace") if isinstance(details, dict) else None
        for step in trace or []:
            if not isinstance(step, dict):
                continue
            selector, target, roles = step.get("selector"), step.get("target"), step.get("roles")
            if not selector or not target or not isinstance(roles, list):
                continue
            steps += 1
            key = entity_key(coalesce_chain(chain), str(target))
            function = named.get((key, _lower(str(selector))))
            if function is None:
                # The step names a selector no analysed function of the target
                # carries. It licenses something, but not something this document
                # can name or later attribute a magnitude to, so it is counted
                # and not credited.
                unnamed_selectors += 1
                continue
            for role in roles:
                try:
                    number = int(role)
                except (TypeError, ValueError):
                    continue
                role_functions[(key, number)].add(function)
                if step.get("authority"):
                    role_authorities[(key, number)].add(_lower(str(step["authority"])))

    recovery = {key: next(iter(rows)) for key, rows in sorted(writes_by_key.items()) if len(rows) == 1}
    plane = ConferralPlane(
        role_functions={key: tuple(sorted(rows)) for key, rows in sorted(role_functions.items())},
        writes_by_function=writes_by_function,
        writes_by_capability={key: frozenset(rows) for key, rows in sorted(writes_by_capability.items())},
        writes_by_deployment_selector=recovery,
    )
    plane.provenance = {
        "role_selector_join": {
            "trace_steps_carrying_a_selector": steps,
            "steps_whose_selector_names_no_analysed_function": unnamed_selectors,
            "role_scopes_resolved": len(plane.role_functions),
            "destinations": len({key[0] for key in plane.role_functions}),
            "role_scopes_resolved_by_more_than_one_authority": sum(
                1 for holders in role_authorities.values() if len(holders) > 1
            ),
            "reading": (
                "a (destination, role) pair resolves to the NAMED functions that role licenses "
                "there: function_principals.details.trace[].selector joined to "
                "effective_functions.selector at the same destination. A step whose selector "
                "names no analysed function of the destination is counted above and credited "
                "nowhere — it licenses something this document cannot name. Role numbers are "
                "per-authority; the join is keyed on (destination, role) because the "
                "destination pins which authority governs it, and the count of pairs resolved "
                "through more than one authority is published so a reader can see whether that "
                "pinning was ambiguous anywhere"
            ),
        },
        "capability_rewrites": {
            "functions_with_state_writes_extracted": len(writes_by_function),
            "functions": len(functions),
            "by_capability": {
                capability: {
                    "rewrites": sorted(writes_by_capability.get(capability, ())),
                    "functions": capability_functions[capability],
                    "functions_with_state_writes_extracted": capability_functions_extracted.get(capability, 0),
                }
                for capability in sorted(capability_functions)
            },
            "reading": (
                "what each capability's own witnesses are observed to REWRITE, from "
                "effective_functions.state_writes with origin=body — a guard-origin write is the "
                "modifier's bookkeeping and not what the capability does. The walk consults the "
                "witnessed function's OWN set, never this union; the union is published because "
                "it is the upper bound the hop census is computed against. This is a SAME-KIND "
                "BOUND and not a conferral witness: the gate's variable is named on its own "
                "contract and the hop's authority slot on the destination's, so requiring the "
                "names to match refuses hops of a different kind and witnesses no composition "
                "step for the ones that survive"
            ),
        },
        "stale_function_reference_recovery": {
            "keys": len(recovery),
            "keys_two_functions_disagree_under": sum(1 for rows in writes_by_key.values() if len(rows) > 1),
            "reading": (
                "function_score_signals.function_id is ON DELETE SET NULL against "
                "effective_functions, and a re-analysis deletes and reinserts a contract's rows, "
                "so a persisted signal that outlives one re-analysis points at nothing. Left "
                "alone that reports every gate as state_writes-not-extracted and silently stops "
                "walking hops it walked yesterday — a withhold that is counted and whose cause is "
                "a stale foreign key. A dangling reference falls back to the signal's own "
                "(deployment entity, selector), which the re-analysis preserves, and only where "
                "every function under that key agrees on what it rewrites"
            ),
        },
    }
    return plane


ACT_AS_WITNESSED = "witnessed"
ACT_AS_NO_CALL_SITE = "no_function_of_the_caller_calls_this_selector"
# No read of this variable was ever recorded: the reader never attempted it.
# Says nothing about what the variable holds, and must never be published for a
# variable whose read was attempted — that is a different fact, below.
ACT_AS_RECEIVER_NOT_READ = "caller_state_variable_never_read_on_chain"
# The read was ISSUED and reverted. A not_determined, distinct from both
# proven-absent and from "never read": the row exists, with an observation kind
# and a block, and calling that a coverage gap of the reader misstates it.
ACT_AS_RECEIVER_READ_FAILED = "caller_state_variable_read_reverted_on_chain"
ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS = "caller_state_variable_holds_a_different_address"
# Two earned negatives the plain address comparison would publish as the weaker
# "holds a different address". The pointer is renounced (address(0), which holds
# no code and never can), or it holds an address proven codeless by an empty
# eth_getCode. Kept apart: an EOA can become a contract at the same address via
# CREATE2, and the zero address cannot, so they are not the same proof.
ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS = "caller_state_variable_holds_the_renounced_zero_address"
ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT = "caller_state_variable_holds_an_address_proven_to_hold_no_code"
ACT_AS_CALL_SITE_IS_PUBLIC = "the_call_site_needs_no_gate"
# The third state of the openness field, and never spelled as either of the
# other two: the pipeline did not determine this function's gate. Publishing it
# as ACT_AS_CALL_SITE_IS_PUBLIC would mint the positive claim "this function
# needs no gate" out of a field nobody read.
ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED = "call_site_caller_gate_openness_is_not_determined"
ACT_AS_CALL_SITE_GATE_NOT_DELEGATED = "call_site_caller_gate_is_not_witnessed_delegated_to_an_authority"
ACT_AS_NO_DESTINATION_ACL = "destination_does_not_accept_this_caller_for_this_selector"
# Asked only by a composition walk past its first hop, which constrains the
# question to "…entering this caller through the function the previous hop
# admitted". The caller does call the selector; it does not call it from that
# function, so nothing witnesses the principal can cause this call.
ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION = (
    "intermediate_calling_function_is_not_the_selector_admitted_at_the_previous_hop"
)
ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE = "destination_access_control_row_names_no_admitting_role"
ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE = "destination_access_control_membership_is_not_enumerable"

# Which of the two witness shapes admitted a step. Published on every step so a
# reader is never left to infer from the basis sentence which evidence was read.
ACT_AS_WITNESS_CALLER_STATE_VARIABLE = "caller_state_variable"
ACT_AS_WITNESS_DESTINATION_ACL = "destination_access_control_list"

# The membership quality a destination-side ACL row must carry to witness
# acceptance: the resolver enumerated the accepted set. A ``lower_bound`` row
# names SOME accepted callers and does not bound the set, so it cannot witness
# that this caller's presence is the whole answer.
_ENUMERATED_MEMBERSHIP = "exact"

# The only principal kind whose acceptance of a caller is an ACL fact: a
# ``controller`` row is the resolver's answer to "who may invoke this function".
# The other kinds answer a different question and are not read here.
_ACCEPTING_PRINCIPAL_TYPE = "controller"

# The method a guard calls when a function's caller set is decided by an
# external authority contract rather than by the function's own code. 748 guard
# sinks on the reference corpus carry it; it is the witness that seizing that
# authority is what opens the function.
_DELEGATED_GUARD_METHOD = "cancall"


def _call_site_order(site: tuple[str, str, str, bool, str | None]) -> tuple[str, str, str, bool, str]:
    """A total order over call sites. ``calling_selector`` is nullable, and
    ordering tuples that mix ``None`` and ``str`` at one position raises."""
    return (site[0], site[1], site[2], site[3], site[4] or "")


@dataclass(frozen=True)
class DestinationAcceptance:
    """One ``function_principals`` row: D's own ACL naming a caller of a selector.

    ``roles`` are the role numbers the resolver walked to reach the caller, and
    is EMPTY when the row reached the caller by some route it did not express as
    a role. Such a row is still indexed: it is the difference between "the
    destination's list does not name this caller" and "it names it, and names no
    role that admits it", and a reader is owed which of the two was found.
    ``membership_quality`` is whether the resolver enumerated the accepted set or
    only bounded it below. ``function_principal_id`` names the row so the
    published basis points at the evidence rather than restating it.
    """

    roles: tuple[int, ...]
    membership_quality: str
    destination_function: str
    function_principal_id: int

    @property
    def enumerated(self) -> bool:
        return self.membership_quality == _ENUMERATED_MEMBERSHIP

    @property
    def strength(self) -> tuple[bool, bool]:
        """How much of the acceptance this row witnesses, for picking between
        two rows that name the same caller at the same selector."""
        return (bool(self.roles), self.enumerated)

    def as_json(self) -> dict[str, Any]:
        return {
            "source": "function_principals",
            "function_principal_id": self.function_principal_id,
            "destination_function": self.destination_function,
            "accepting_roles": list(self.roles),
            "membership_quality": self.membership_quality,
        }


@dataclass(frozen=True)
class ActAsStep:
    """One witnessed "N can be made to call ``selector`` at D" step.

    Every field names a witness, not an inference. ``calling_function`` is the
    function of N whose compiled body carries the call site, and
    ``calling_selector`` is THAT function's own selector — the join key a
    multi-hop walk needs, because a function NAME does not identify a function:
    32 ``(entity, name)`` pairs on the reference corpus carry more than one
    selector, ``manage`` at the BoringVaults among them. ``None`` is a function
    whose selector was never extracted, and it matches nothing. ``witness_kind``
    says which of the two admissible shapes proved the step lands at D, and the
    fields of the other shape are ``None``: for
    ``ACT_AS_WITNESS_CALLER_STATE_VARIABLE`` the ``receiver_*`` fields are the
    state variable the receiver binds to and the on-chain read that proved it
    holds D; for ``ACT_AS_WITNESS_DESTINATION_ACL`` the receiver is
    parameter-bound — nothing in N's storage names D, and ``acceptance`` is D's
    own access-control row naming N.
    """

    caller: str
    destination: str
    selector: str
    calling_function: str
    calling_function_openness: str
    calling_selector: str | None = None
    witness_kind: str = ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    receiver_variable: str | None = None
    receiver_observed_via: str | None = None
    receiver_block: int | None = None
    acceptance: DestinationAcceptance | None = None
    # A fact about this SITE, not about its hop: true exactly when the step was
    # admitted and its calling function carries no delegation witness, which only
    # the hops past the first permit. FALSE means the witness IS present, whether
    # or not this hop required it — so the stored fact is recoverable from the
    # published one at every hop, and a hop-2 step that happens to be delegated
    # is never published as a step that was let through without one. Named for
    # the site because a hop-shaped name ("not required at this hop") would read
    # as false on exactly those steps: the requirement was lifted there and the
    # witness was present anyway, and one field cannot say both.
    admitted_without_a_delegation_witness: bool = False

    def _not_delegation_tested(self) -> str:
        """Named on the basis only where it applies, so no step that carries the
        delegation witness acquires a sentence about not having one."""
        if not self.admitted_without_a_delegation_witness:
            return ""
        return (
            f" This step is past the first hop, where the licence is the selector the previous hop "
            f"admitted rather than the seized authority pointer, so no witness that "
            f"{self.calling_function}'s own caller gate is delegated to an authority was required — "
            f"and none is claimed: this call site carries none."
        )

    def _basis(self) -> str:
        if self.witness_kind == ACT_AS_WITNESS_DESTINATION_ACL and self.acceptance is not None:
            gate = (
                f"{self.calling_function} is a restricted function of {self.caller} entered under "
                f"the selector the previous hop admitted"
                if self.admitted_without_a_delegation_witness
                else (
                    f"{self.calling_function} is a restricted function of {self.caller} whose caller "
                    f"gate is witnessed delegated to an authority"
                )
            )
            return (
                f"{gate}, and whose body calls "
                f"{self.selector} at an address the CALLER of that function supplies — the "
                f"receiver is parameter-bound, so no state variable of {self.caller} names it. "
                f"{self.destination}'s own access-control list is what names the address from the "
                f"other end: function_principals row {self.acceptance.function_principal_id} on "
                f"{self.acceptance.destination_function} accepts {self.caller} as a caller of "
                f"{self.selector} by role(s) {list(self.acceptance.roles)}, with "
                f"membership_quality '{self.acceptance.membership_quality}'" + self._not_delegation_tested()
            )
        return (
            f"{self.calling_function} is a restricted function of {self.caller} whose body "
            f"calls {self.selector} on its own state variable '{self.receiver_variable}', and "
            f"'{self.receiver_variable}' was read {self.receiver_observed_via} at block "
            f"{self.receiver_block} holding {self.destination}" + self._not_delegation_tested()
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "caller": self.caller,
            "destination": self.destination,
            "selector": self.selector,
            "calling_function": self.calling_function,
            "calling_function_openness": self.calling_function_openness,
            "calling_selector": self.calling_selector,
            "witness_kind": self.witness_kind,
            "receiver_variable": self.receiver_variable,
            "receiver_observed_via": self.receiver_observed_via,
            "receiver_block": self.receiver_block,
            "destination_acceptance": (self.acceptance.as_json() if self.acceptance is not None else None),
            "admitted_without_a_delegation_witness": self.admitted_without_a_delegation_witness,
            "basis": self._basis(),
        }


@dataclass(frozen=True)
class ActAsVerdict:
    """The answer, and — where the answer is an earned negative about what a
    receiver holds — the ``resolved_type`` of the address that was read, so the
    refusal carries WHAT it held and not only that it was something else."""

    outcome: str
    step: ActAsStep | None = None
    receiver_resolved_type: str | None = None

    @property
    def witnessed(self) -> bool:
        return self.outcome == ACT_AS_WITNESSED


# An on-chain read of the caller's own storage that RETURNED an address.
_READ_OBSERVATIONS = frozenset({"eth_call", "eth_call_impl_fallback", "beacon_owner", "event_log"})
# A read that was issued and FAILED. Indexed separately and never as a read: it
# carries no address, so it can satisfy no receiver test — but it is a record of
# an attempt, which is not the same fact as no attempt.
_READ_FAILURE_OBSERVATIONS = frozenset({"eth_call_error"})

# The two ``controller_values.resolved_type`` classifications that carry a fact
# BEYOND the address itself. ``zero`` is the renounced pointer; ``eoa`` is an
# address proven codeless by an empty ``eth_getCode`` (an RPC failure classifies
# as ``contract`` and is not cached, so this is an earned witness). Every other
# value — ``contract``, ``safe``, ``timelock``, ``unknown``, NULL — is a
# classification of an address the row already carries, and the receiver test
# reads the address.
_RESOLVED_RENOUNCED = "zero"
_RESOLVED_CODELESS = "eoa"

# ``effective_functions.authority_openness``: the only value that witnesses a
# gate, and the value that witnesses its proven absence. Everything else is the
# third state.
_OPENNESS_RESTRICTED = "restricted"
_OPENNESS_PUBLIC = "open"


@dataclass
class ActAsPlane:
    """Whether seizing a node's gate witnesses making that node ACT somewhere.

    Membership in a gate's licensed set answers "may N call ``s`` at D". It does
    not answer "can the principal make N do it" — the question a composed
    magnitude turns on. Seizing an authority POINTER on N buys the ability to
    call N's own restricted functions; it buys a call at D only if one of those
    functions is witnessed calling D. Pricing the hop on the licence alone is
    the membership-as-capability error one level up from the sheet-as-reach one.

    The CALL SITE is always required — ``effective_functions.sinks``, an
    ``external_call`` entry carrying the called ``selector`` and the receiver it
    is bound to, compiled from N's own verified source. What names the ADDRESS
    that call site lands on has two admissible shapes, and a step is witnessed
    under either:

    * the CALLER'S RECEIVER — ``controller_values``, the on-chain read
      (``eth_call`` at a recorded block) of the state variable that receiver is
      bound to. The row says N's ``vault`` IS D. The WITNESS is the read and the
      address comparison; ``resolved_type`` is a classification of the address
      the row already carries, and admission does not branch on it — a pointer
      classified ``safe`` or ``timelock`` that holds D witnesses the step, and
      refusing it would discard a read on the strength of a label. Where the
      address is NOT D the classification sharpens the earned negative: ``zero``
      is a renounced pointer and ``eoa`` an address proven codeless, each
      published under its own reason rather than as "holds a different address".
      A read that was ISSUED AND FAILED is indexed apart from both and satisfies
      nothing: it is a not_determined, and publishing it as "never read on
      chain" would assert a coverage gap of the reader that the row disproves.
    * the DESTINATION'S ACL — ``function_principals``, D's own resolved
      access-control list naming N as an accepted caller of that selector by an
      enumerated role. This is the only shape available when the receiver is a
      PARAMETER: the callee is chosen at call time, so the binding cannot live
      in N's storage, and D's own list of accepted callers is what bounds which
      choices D honours. It is admitted only when the row names a role AND the
      membership is ``exact`` — a row naming no role reached N by a route it did
      not state, and a ``lower_bound`` membership names some accepted callers
      without bounding the set. Each is refused under its own reason, because
      "the list does not name N", "it names N and no role that admits it" and
      "it names a role and does not bound the set" are three different findings
      and collapsing them publishes one of them as the others.

    A parameter-bound call site with NEITHER witness is REFUSED, not credited:
    whoever calls N chooses that address and no evidence at either end names it,
    so the code witnesses a call at an address nobody named. It is a plausible
    path and it is not a witnessed one, and the difference is the whole
    discipline.

    The destination-ACL shape is a MAGNITUDE admission only. It says D accepts a
    call from N; it says nothing about which entities the principal reaches, and
    it is never consulted by the closure walk. It also does not witness that the
    call SUCCEEDS: the same ``function_principals`` row carries D's own business
    preconditions and this plane consults none of them.

    The calling function must itself be ``restricted`` AND its caller gate must
    be witnessed DELEGATED — a guard-origin sink calling ``canCall`` on an
    authority contract. Restricted alone is not enough and the corpus proves it:
    ``ManagerWithMerkleVerification.receiveFlashLoan`` is restricted, calls
    ``vault.manage``, and is gated by ``msg.sender == balancerVault`` — its
    ``authority_roles`` is the proven-empty ``[]`` and it carries no ``canCall``
    guard. Seizing the manager's authority pointer opens
    ``manageVaultWithMerkleVerification`` and does not open that one, and without
    the guard witness the two are indistinguishable. That conjunct is required at
    the FIRST hop and only there: past it the principal has seized nothing on the
    intermediate and arrives as whoever the previous hop admitted, the via rule
    has already pinned the intermediate's calling function to that admitted
    selector, and an intermediate gated by a direct ``msg.sender ==`` check is
    exactly the shape such a chain runs through — so past hop 1 the delegation
    test asks after a mechanism the principal is not using, and refusing on it
    would discard a witnessed path.

    A public call site is refused at EVERY hop, and not because the rule is
    conservative: an open function is one anyone can call, so the value it moves
    is not conferred by the seized gate and belongs to that function's own
    finding. That is attribution, not caution, and it is the same attribution at
    hop k as at hop 1. An openness the pipeline did NOT determine is neither of
    those two facts and carries its own refusal — a gate nobody read is not a
    gate proven absent.

    What this plane still does NOT witness is that the authority the guard
    consults is the same one the finding's gate seizes: the ``canCall`` receiver
    is a local, and no read pins it. The same-kind bound (``GateGrant``) is what
    stands in for it, and it is a bound, not a witness — recorded here so the
    residual is visible where the composition is built rather than only in a
    review note.
    """

    # (caller entity, selector) -> ((calling function, openness, receiver variable,
    # whether that function's caller gate is delegated to an authority), ...)
    call_sites: dict[tuple[str, str], tuple[tuple[str, str, str, bool, str | None], ...]] = field(default_factory=dict)
    # (caller entity, state variable) -> (address it was read holding, observed_via, block)
    reads: dict[tuple[str, str], tuple[str, str, int | None]] = field(default_factory=dict)
    # The resolved_type beside each read, kept out of ``reads`` so the receiver
    # test reads the address and never the label. Absent where the row carried
    # no classification, which is a third state and not 'contract'.
    read_kinds: dict[tuple[str, str], str] = field(default_factory=dict)
    # (caller entity, state variable) -> (observed_via, block) for a read that
    # was ISSUED AND FAILED. Never a read: it carries no address and witnesses
    # no receiver. Separate from ``reads`` so "the read reverted" cannot be
    # published as "the read never happened".
    read_failures: dict[tuple[str, str], tuple[str, int | None]] = field(default_factory=dict)
    # (destination entity, selector) -> {caller entity: the ACL row accepting it}
    destination_acl: dict[tuple[str, str], dict[str, DestinationAcceptance]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def acts_as(
        self, caller: str, destination: str, selector: str, *, via: frozenset[str] | None = None
    ) -> ActAsVerdict:
        """Whether ``caller`` is witnessed able to be made to call ``selector`` at
        ``destination``, optionally only from the functions ``via`` names.

        ``via`` is the multi-hop constraint and is a SET because a node can be
        admitted under several of its functions; a call site whose own selector
        is in it is considered, every other site is not looked at, and a caller
        with no site under any of them is refused rather than answered from a
        site the constraint excludes. ``via=None`` is the unconstrained question
        the first hop asks — and it is the ONLY thing that distinguishes hop 1
        from hop k, which is why the delegation conjunct is keyed on it.
        """
        token = _lower(selector)
        sites = self.call_sites.get((caller, token))
        if not sites:
            return ActAsVerdict(ACT_AS_NO_CALL_SITE)
        if via is not None:
            admitted = frozenset(_lower(entry) for entry in via)
            # A site whose own selector was never extracted matches nothing: not
            # determined is not a match, and treating it as one would walk a hop
            # on an unread field.
            sites = tuple(site for site in sites if site[4] is not None and site[4] in admitted)
            if not sites:
                return ActAsVerdict(ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION)
        # The sharpest shortfall any call site reported, and — where that
        # shortfall is a statement about what a receiver holds — the resolved
        # type of the address that was read, so the refusal carries WHAT it held.
        # First site in the deterministic site order wins a reason it shares.
        outcome: str | None = None
        held_types: dict[str, str] = {}

        def refuse(reason: str | None) -> ActAsVerdict:
            if reason is None:
                # Every site is either state-variable-bound (reported by the loop
                # below) or parameter-bound (reported by the arm after it), and a
                # caller with no site at all has already returned. Arriving here
                # with nothing reported is a broken invariant, not an answer, and
                # a refusal invented to cover it would be published as evidence.
                raise AssertionError(f"act_as refusal with no reported shortfall: {caller} -> {destination}.{token}")
            return ActAsVerdict(reason, receiver_resolved_type=held_types.get(reason))

        for name, openness, variable, delegated, calling_selector in sites:
            if not variable:
                continue
            read = self.reads.get((caller, variable))
            if read is None:
                # A read that was issued and reverted is not a read, and it is
                # not the absence of one either.
                attempted = (caller, variable) in self.read_failures
                outcome = _rank_outcome(outcome, ACT_AS_RECEIVER_READ_FAILED if attempted else ACT_AS_RECEIVER_NOT_READ)
                continue
            held, observed_via, block = read
            kind = self.read_kinds.get((caller, variable))
            if held != destination:
                # The comparison is the answer; the classification says what the
                # pointer holds instead, and two of its values are sharper
                # negatives than "some other address".
                if kind == _RESOLVED_RENOUNCED:
                    shortfall = ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS
                elif kind == _RESOLVED_CODELESS:
                    shortfall = ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT
                else:
                    shortfall = ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS
                held_types.setdefault(shortfall, kind or "not_determined")
                outcome = _rank_outcome(outcome, shortfall)
                continue
            # The read holds the destination. What the row CALLS that address is
            # not consulted: a 'safe' or 'timelock' pointer holding D witnesses
            # the step exactly as a 'contract' one does.
            gate = self._gate_shortfall(openness, delegated, via=via)
            if gate is not None:
                outcome = _rank_outcome(outcome, gate)
                continue
            return ActAsVerdict(
                ACT_AS_WITNESSED,
                ActAsStep(
                    caller=caller,
                    destination=destination,
                    selector=token,
                    calling_function=name,
                    calling_function_openness=openness,
                    calling_selector=calling_selector,
                    witness_kind=ACT_AS_WITNESS_CALLER_STATE_VARIABLE,
                    receiver_variable=variable,
                    receiver_observed_via=observed_via,
                    receiver_block=block,
                    admitted_without_a_delegation_witness=via is not None and not delegated,
                ),
            )
        # No state variable of the caller names the destination. The second
        # shape: a call site whose callee the caller's own caller supplies, with
        # the destination's ACL naming this caller from the other end. Sorted so
        # a caller with several such sites names one function deterministically.
        # The gate conjuncts are NOT in this filter: a site excluded by one of
        # them would leave the arm reporting that the receiver is parameter-bound
        # — the precondition for this shape, not a shortfall of it — and publish
        # the receiver binding as the failure when the gate is what failed.
        parameter_bound = sorted((site for site in sites if not site[2]), key=_call_site_order)
        if not parameter_bound:
            return refuse(outcome)
        # Acceptance is a fact about the DESTINATION and is the same under every
        # call site, so it is consulted once, before any per-site gate reason.
        accepted = self.destination_acl.get((destination, token), {}).get(caller)
        if accepted is None:
            return refuse(_rank_outcome(outcome, ACT_AS_NO_DESTINATION_ACL))
        if not accepted.roles:
            return refuse(_rank_outcome(outcome, ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE))
        if not accepted.enumerated:
            return refuse(_rank_outcome(outcome, ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE))
        for name, openness, _variable, delegated, calling_selector in parameter_bound:
            gate = self._gate_shortfall(openness, delegated, via=via)
            if gate is not None:
                outcome = _rank_outcome(outcome, gate)
                continue
            return ActAsVerdict(
                ACT_AS_WITNESSED,
                ActAsStep(
                    caller=caller,
                    destination=destination,
                    selector=token,
                    calling_function=name,
                    calling_function_openness=openness,
                    calling_selector=calling_selector,
                    witness_kind=ACT_AS_WITNESS_DESTINATION_ACL,
                    acceptance=accepted,
                    admitted_without_a_delegation_witness=via is not None and not delegated,
                ),
            )
        return refuse(outcome)

    @staticmethod
    def _gate_shortfall(openness: str, delegated: bool, *, via: frozenset[str] | None) -> str | None:
        """Which conjunct this call site's caller gate fails, or ``None`` if it
        clears every one that applies at this hop.

        Openness is three-valued and each value has its own answer: ``open`` is a
        gate proven absent, ``restricted`` is a gate proven present, and anything
        else is a field the pipeline did not determine — which is not a gate, and
        is not the proven absence of one either.

        Delegation is required at the FIRST hop and only there. At hop 1 the
        principal's leverage IS the seized authority pointer, so only an
        authority-delegated gate is opened by seizing it. Past hop 1 the licence
        is the previous hop's admitted selector, which ``via`` has already pinned,
        and the delegation of this function's own gate tests a mechanism the
        principal is not using.
        """
        if openness == _OPENNESS_PUBLIC:
            return ACT_AS_CALL_SITE_IS_PUBLIC
        if openness != _OPENNESS_RESTRICTED:
            return ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED
        if via is None and not delegated:
            return ACT_AS_CALL_SITE_GATE_NOT_DELEGATED
        return None


# How far a call site GOT before it was refused, so a caller with several call
# sites for one selector reports the sharpest shortfall rather than whichever it
# happened to look at last. Lower is further.
#
# The two proven-absent receiver reasons rank first because each ANSWERS the
# question rather than falling short of it: a renounced pointer holds an address
# that has no code and never can, and a codeless one holds an address proven to
# hold none today. The three gate reasons come next — a site whose receiver
# resolved and whose destination ACL was consulted got as far as its own gate.
# They rank ahead of the three destination-ACL reasons, which report on the
# destination rather than on this site. Among the ACL three, a row that names a
# role but bounds its membership only below got further than one that names no
# role at all, which got further than no row at all. Among the read reasons, an
# address that was read and is somebody else got further than a read that was
# issued and reverted, which got further than a read never attempted.
#
# Every constant that ``acts_as`` can rank MUST appear here: ``_rank_outcome``
# indexes this map, so an unregistered outcome raises at runtime.
_ACT_AS_RANK = {
    ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS: 0,
    ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT: 1,
    ACT_AS_CALL_SITE_GATE_NOT_DELEGATED: 2,
    ACT_AS_CALL_SITE_IS_PUBLIC: 3,
    ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED: 4,
    ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS: 5,
    ACT_AS_RECEIVER_READ_FAILED: 6,
    ACT_AS_RECEIVER_NOT_READ: 7,
    ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE: 8,
    ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE: 9,
    ACT_AS_NO_DESTINATION_ACL: 10,
    # A call site exists and the multi-hop constraint excluded every one of
    # them, so nothing about the receiver was ever consulted — further than no
    # call site at all, and short of every reason that did consult one.
    ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION: 11,
    ACT_AS_NO_CALL_SITE: 12,
}


def _rank_outcome(current: str | None, candidate: str) -> str:
    """``current`` is ``None`` until some call site has reported. Nothing is not
    a shortfall, so the first candidate wins outright rather than competing with
    a sentinel that would be published if no site reported at all."""
    if current is None:
        return candidate
    return candidate if _ACT_AS_RANK[candidate] < _ACT_AS_RANK[current] else current


def load_act_as_plane(session: Session, protocol_id: int) -> ActAsPlane:
    """The call-site, receiver and destination-acceptance witnesses, indexed for
    the composition walk."""
    from db.models import Contract, ControllerValue, EffectiveFunction, FunctionPrincipal

    call_sites: dict[tuple[str, str], list[tuple[str, str, str, bool, str | None]]] = defaultdict(list)
    sinks_read = external_calls = selector_bearing = state_variable_bound = delegated_gates = 0
    call_sites_naming_their_own_selector = 0
    functions = (
        session.query(
            EffectiveFunction.function_name,
            EffectiveFunction.authority_openness,
            EffectiveFunction.sinks,
            EffectiveFunction.selector,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    for name, openness, sinks, own_selector, deployment, address, chain in functions:
        if not isinstance(sinks, list):
            # SQL NULL is "the effects stage did not run here", which is a
            # different fact from a function proven to call nothing. Neither
            # produces a call site, and only the second is an answer.
            continue
        sinks_read += 1
        key = entity_key(coalesce_chain(chain), deployment or address)
        delegated = any(
            isinstance(sink, dict)
            and sink.get("origin") == "guard"
            and _lower(str(sink.get("target") or "")).rsplit(".", 1)[-1] == _DELEGATED_GUARD_METHOD
            for sink in sinks
        )
        delegated_gates += 1 if delegated else 0
        # The calling function's OWN selector, so a multi-hop walk can ask which
        # function of this caller a step is issued from. A fallback or receive
        # names none, and stays None rather than being spelled as an empty match.
        calling_selector = _lower(str(own_selector)) if own_selector else None
        if calling_selector is not None and not calling_selector.startswith("0x"):
            calling_selector = None
        for sink in sinks:
            if not isinstance(sink, dict) or sink.get("kind") != "external_call":
                continue
            external_calls += 1
            selector = _lower(str(sink.get("selector") or ""))
            if not selector.startswith("0x"):
                continue
            selector_bearing += 1
            receiver = sink.get("receiver") if isinstance(sink.get("receiver"), dict) else {}
            variable = ""
            if (receiver or {}).get("binding") == "state_variable":
                variable = str((receiver or {}).get("variable") or "")
                if variable:
                    state_variable_bound += 1
            call_sites_naming_their_own_selector += 1 if calling_selector is not None else 0
            call_sites[(key, selector)].append(
                (str(name), str(openness or "not_determined"), variable, delegated, calling_selector)
            )

    reads: dict[tuple[str, str], tuple[str, str, int | None]] = {}
    read_kinds: dict[tuple[str, str], str] = {}
    read_failures: dict[tuple[str, str], tuple[str, int | None]] = {}
    resolved_type_histogram: dict[str, int] = defaultdict(int)
    ambiguous: set[tuple[str, str]] = set()
    rows = (
        session.query(
            ControllerValue.source,
            ControllerValue.value,
            ControllerValue.resolved_type,
            ControllerValue.observed_via,
            ControllerValue.block_number,
            ControllerValue.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == ControllerValue.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ControllerValue.id)
        .all()
    )
    for source, value, resolved_type, observed_via, block, deployment, address, chain in rows:
        if not source:
            continue
        key = (entity_key(coalesce_chain(chain), deployment or address), str(source))
        if observed_via in _READ_FAILURE_OBSERVATIONS:
            # The reader tried and the call reverted. Indexed so the refusal can
            # say so; never a read, because it carries no address.
            read_failures.setdefault(key, (str(observed_via), int(block) if block is not None else None))
            continue
        if observed_via not in _READ_OBSERVATIONS:
            continue
        held = _lower(str(value or ""))
        if not held.startswith("0x"):
            continue
        # Every read that RETURNED an address is indexed, whatever the row calls
        # that address. resolved_type is a classification of a value the row
        # already carries, and the receiver test is the address comparison; a
        # pointer dropped for its label is a read discarded on a name.
        kind = str(resolved_type) if resolved_type else ""
        resolved_type_histogram[kind or "not_determined"] += 1
        held_key = entity_key(coalesce_chain(chain), held)
        previous = reads.get(key)
        if previous is not None and previous[0] != held_key:
            # Two reads of one variable disagreeing on which address it holds.
            # Picking one publishes a call destination out of row order, so the
            # variable resolves to nothing and the hop stays unwitnessed.
            ambiguous.add(key)
            continue
        reads.setdefault(key, (held_key, str(observed_via), int(block) if block is not None else None))
        if kind:
            read_kinds.setdefault(key, kind)
    for key in ambiguous:
        reads.pop(key, None)
        read_kinds.pop(key, None)
        # The failure record goes with them. A variable read twice to two
        # different addresses AND carrying a failed read would otherwise be
        # refused as caller_state_variable_read_reverted_on_chain — a sharper
        # claim than the evidence supports, since the reads that DID return are
        # what defeated it. It falls back to never_read_on_chain, which is the
        # standing (registered) mislabel for the disagreement case and awaits its
        # own reason; this must not make it a second, more specific one.
        read_failures.pop(key, None)

    destination_acl: dict[tuple[str, str], dict[str, DestinationAcceptance]] = defaultdict(dict)
    acl_rows_keyed = acl_rows_naming_a_role = 0
    quality_histogram: dict[str, int] = defaultdict(int)
    acl_rows = (
        session.query(
            FunctionPrincipal.id,
            FunctionPrincipal.address,
            FunctionPrincipal.details,
            EffectiveFunction.selector,
            EffectiveFunction.function_name,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .filter(FunctionPrincipal.principal_type == _ACCEPTING_PRINCIPAL_TYPE)
        .order_by(FunctionPrincipal.id)
        .all()
    )
    for row_id, principal, details, selector, function_name, deployment, address, chain in acl_rows:
        token = _lower(str(selector or ""))
        holder = _lower(str(principal or ""))
        if not token.startswith("0x") or not holder.startswith("0x") or not isinstance(details, dict):
            continue
        acl_rows_keyed += 1
        roles: set[int] = set()
        trace = details.get("trace")
        if isinstance(trace, list):
            for step in trace:
                if not isinstance(step, dict):
                    continue
                named = step.get("roles")
                if isinstance(named, list):
                    roles.update(role for role in named if isinstance(role, int) and not isinstance(role, bool))
        if roles:
            acl_rows_naming_a_role += 1
        quality = str(details.get("membership_quality") or "not_determined")
        quality_histogram[quality] += 1
        chain_key = coalesce_chain(chain)
        accepting = DestinationAcceptance(
            roles=tuple(sorted(roles)),
            membership_quality=quality,
            destination_function=str(function_name),
            function_principal_id=int(row_id),
        )
        # Both ends keyed on the destination's own chain: an ACL is a fact about
        # one deployment, and a same-address caller on another chain is a
        # different contract.
        bucket = destination_acl[(entity_key(chain_key, deployment or address), token)]
        previous = bucket.get(entity_key(chain_key, holder))
        # Several rows can name one caller at one selector. Keep the one that
        # witnesses the most, so a row bounded below or naming no role never
        # displaces one that names an enumerated role for the same pair.
        if previous is None or accepting.strength > previous.strength:
            bucket[entity_key(chain_key, holder)] = accepting

    plane = ActAsPlane(
        call_sites={key: tuple(sorted(set(rows), key=_call_site_order)) for key, rows in sorted(call_sites.items())},
        reads=reads,
        read_kinds=read_kinds,
        read_failures=read_failures,
        destination_acl={key: dict(sorted(callers.items())) for key, callers in sorted(destination_acl.items())},
    )
    plane.provenance = {
        "call_sites": {
            "functions_with_sinks_extracted": sinks_read,
            "functions": len(functions),
            "external_call_sinks": external_calls,
            "sinks_naming_a_selector": selector_bearing,
            "sinks_whose_receiver_is_a_state_variable": state_variable_bound,
            "functions_whose_caller_gate_is_delegated_to_an_authority": delegated_gates,
            "call_sites_naming_their_own_selector": call_sites_naming_their_own_selector,
        },
        "receiver_reads": {
            # Not "…holding_a_contract": admission no longer branches on what the
            # row calls the address, so the count is every VARIABLE read to an
            # address. The histogram beside it counts ROWS — one variable read
            # twice contributes twice, and a variable dropped for disagreeing
            # reads still contributes — so the two do not sum to each other and
            # the names say which unit each is in.
            "state_variables_read_on_chain": len(reads),
            "state_variables_whose_read_failed": len(read_failures),
            "resolved_type_of_each_read_row": dict(sorted(resolved_type_histogram.items())),
            "variables_two_reads_disagree_under": len(ambiguous),
            "observations_admitted": sorted(_READ_OBSERVATIONS),
            "observations_recorded_as_a_failed_read": sorted(_READ_FAILURE_OBSERVATIONS),
        },
        "destination_acceptance": {
            "function_principal_rows_returned": len(acl_rows),
            "rows_naming_a_selector_and_a_caller_address": acl_rows_keyed,
            "rows_naming_an_admitting_role": acl_rows_naming_a_role,
            "destination_selectors_with_an_indexed_caller": len(destination_acl),
            "indexed_callers": sum(len(callers) for callers in destination_acl.values()),
            "membership_quality": dict(sorted(quality_histogram.items())),
            "principal_type_read": _ACCEPTING_PRINCIPAL_TYPE,
            "membership_quality_admitted": _ENUMERATED_MEMBERSHIP,
        },
        "reading": (
            "the witnesses a composed magnitude needs on top of a licence. The CALL SITE is "
            "always required (effective_functions.sinks, an external_call carrying the called "
            "selector and the receiver it binds to, compiled from the caller's own source). "
            "What names the ADDRESS it lands on has two shapes and either witnesses the step: "
            "the RECEIVER (controller_values, an on-chain read at a recorded block, compared "
            "against the destination address) — the READ and the comparison are the witness, and "
            "controller_values.resolved_type is context, not a filter: a pointer classified "
            "'safe' or 'timelock' that holds the destination witnesses the step exactly as a "
            "'contract' one does, because what the pointer holds is the question and what the "
            "row calls it is not. Where the address read is NOT the destination the "
            "classification sharpens the earned negative into one of three: "
            "caller_state_variable_holds_the_renounced_zero_address (the pointer is renounced, "
            "and address(0) holds no code and never can), "
            "caller_state_variable_holds_an_address_proven_to_hold_no_code (an empty "
            "eth_getCode, which an RPC failure does not produce), and otherwise "
            "caller_state_variable_holds_a_different_address. A read that was ISSUED AND "
            "REVERTED is none of those: it is indexed apart as "
            "caller_state_variable_read_reverted_on_chain, a not_determined, and is never "
            "published as caller_state_variable_never_read_on_chain — the row exists, with an "
            "observation kind and a block, and calling it a read that never happened asserts a "
            "coverage gap the evidence disproves. The second shape is — when the receiver is "
            "bound to a "
            "parameter, a local or an unresolved head, where no storage of the caller CAN name "
            "it because the callee is chosen at call time — the DESTINATION'S OWN ACL "
            "(function_principals, a principal_type='controller' row naming this caller as an "
            "accepted caller of that selector by an enumerated role). The second shape is "
            "admitted only on a row whose trace names at least one role, only where "
            "membership_quality is 'exact', and "
            "only for MAGNITUDE: it is never read into reach, and it does not witness that the "
            "call succeeds — the same row carries the destination's own preconditions and none "
            "of them are consulted. UNDER BOTH SHAPES the call site's own caller gate is tested, "
            "and its three states are published as three reasons: authority_openness 'restricted' "
            "passes, 'open' is refused as the_call_site_needs_no_gate — a proven-absent gate, and "
            "the refusal is ATTRIBUTION rather than caution, since a function anyone can call "
            "moves value that no seized gate conferred and that belongs to that function's own "
            "finding — and anything else, not_determined included, is refused as "
            "call_site_caller_gate_openness_is_not_determined, never collapsed into either: a "
            "gate the pipeline did not read is not a gate proven absent. The gate reasons and the "
            "destination-ACL reasons are ranked, not merged, so a parameter-bound site reports "
            "the conjunct that actually failed rather than the fact that its receiver is "
            "parameter-bound — which is the PRECONDITION for this shape and never a shortfall of "
            "it. Each shortfall is published as its own reason rather than "
            "collapsed into one: no row naming this caller at all is "
            "destination_does_not_accept_this_caller_for_this_selector; a row that names the "
            "caller but expresses no role that admits it is "
            "destination_access_control_row_names_no_admitting_role — the destination's list "
            "reached this caller by a route it did not state as a role, which is not the same "
            "fact as the list not naming it; and a row that names a role without bounding the "
            "accepted set is destination_access_control_membership_is_not_enumerable, because "
            "naming some accepted callers is not the same fact as bounding which they are. "
            "A composition walk past its first hop additionally constrains the question to "
            "the functions of the caller a previous hop admitted, matched on the calling "
            "function's OWN selector because a function name does not identify a function; "
            "a caller with no call site under any admitted function is refused as "
            "intermediate_calling_function_is_not_the_selector_admitted_at_the_previous_hop "
            "rather than answered from a site that constraint excludes. That admitted selector "
            "is also what REPLACES the delegation conjunct past the first hop: the calling "
            "function's gate must be witnessed delegated to an authority at hop 1, where the "
            "principal's leverage IS the seized authority pointer and only a delegated gate is "
            "opened by seizing it, and it is NOT required past hop 1, where the principal has "
            "seized nothing on the intermediate and arrives as whoever the previous hop admitted "
            "— an intermediate gated by a direct msg.sender check is exactly the shape such a "
            "chain runs through, and refusing it would discard a witnessed path over a mechanism "
            "the principal is not using. A step admitted with no delegation witness carries "
            "admitted_without_a_delegation_witness: true and says so in its basis. The field is "
            "a fact about the SITE and not about the hop: false on a step past the first hop "
            "means the requirement was lifted there and that call site carries the delegation "
            "witness anyway — a different fact from a step let through without one, and "
            "published as one. The "
            "openness conjunct is NOT relaxed with it and applies at every hop, for the "
            "attribution reason above and not because it is conservative. "
            "THE RESIDUAL THIS PLANE DOES NOT CLOSE: the calling function's guard is witnessed "
            "consulting AN authority (a canCall call), never that it is the same authority the "
            "finding's gate seizes — the guard's receiver is a local and no read pins it. The "
            "same-kind GateGrant bound stands in for it, and a bound is not a witness. THIS "
            "PLANE DOES NOT MEASURE HOW WIDE THAT GAP IS: it counts no contracts by how many "
            "authority-kind state variables they carry, and it does not ask which variable a "
            "given guard reads, so nothing published here rules out a second candidate. On a "
            "contract carrying two, the bound is doing work a witness should — and no field of "
            "this document says whether that happened"
        ),
    }
    return plane


def load_proven_eoa_entities(session: Session, protocol_id: int) -> set[str]:
    """Entity keys proven codeless: ``resolved_type == 'eoa'`` is only ever
    written after an empty ``eth_getCode`` (an RPC failure classifies as
    ``contract`` and is not cached), so membership here is an earned witness,
    never an inference from a name or a missing row.
    """
    from db.models import Contract, ControlGraphNode

    rows = (
        session.query(ControlGraphNode.address, Contract.chain)
        .join(Contract, Contract.id == ControlGraphNode.contract_id)
        .filter(Contract.protocol_id == protocol_id, ControlGraphNode.resolved_type == "eoa")
        .order_by(ControlGraphNode.id)
        .all()
    )
    return {entity_key(chain, address) for address, chain in rows}


def unconsumed_reach_relations(session: Session, protocol_id: int) -> dict[str, Any]:
    """Every edge that exists but is NOT walked as reach, and why. Provenance.

    DISCOVERY-FIXED: the enumeration is built from what the database holds —
    ``GROUP BY relation`` over this protocol's edges, with no filter — unioned
    with every relation the graph writer is able to emit
    (``db.CONTROL_EDGE_RELATIONS``). It is deliberately NOT built from what this
    scorer chose to name: a relation nobody classified, and a relation that
    carries no rows today and rows tomorrow, would both be silently unwalked
    under an enumeration keyed on the consumed set. A zero count is a named
    exclusion, not an absence.
    """
    from db.models import CONTROL_EDGE_RELATIONS as WRITER_RELATIONS
    from db.models import Contract, ControlGraphEdge, EffectiveFunction, FunctionPrincipal
    from services.governance.control_graph_types import FP_MATERIALIZE_LIMIT

    counts: dict[str, int] = {
        str(relation): int(total or 0)
        for relation, total in session.query(ControlGraphEdge.relation, sql_func.count(ControlGraphEdge.id))
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .group_by(ControlGraphEdge.relation)
        .order_by(ControlGraphEdge.relation)
        .all()
    }
    excluded = sorted((set(counts) | set(WRITER_RELATIONS)) - set(CONTROL_RELATIONS))
    relations = {
        relation: {
            "edges": counts.get(relation, 0),
            "reason": UNCONSUMED_REACH_REASONS.get(relation, UNCONSUMED_REASON_UNCLASSIFIED),
            "classified": relation in UNCONSUMED_REACH_REASONS,
        }
        for relation in excluded
    }
    # The withdrawn rationale for excluding ``capability_principal`` was that its
    # population is materialization-budget gated. Withdrawing it in prose leaves
    # a reader unable to check the refutation, so the budget and the observed
    # headroom are published beside the exclusion: the perimeter above is a full
    # enumeration only if nothing was clipped, and that is a number, not a claim.
    per_anchor = [
        int(total or 0)
        for _, _, total in session.query(
            EffectiveFunction.contract_id,
            EffectiveFunction.deployment_address,
            sql_func.count(sql_func.distinct(sql_func.lower(FunctionPrincipal.address))),
        )
        .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .group_by(EffectiveFunction.contract_id, EffectiveFunction.deployment_address)
        .order_by(EffectiveFunction.contract_id, EffectiveFunction.deployment_address)
        .all()
    ]
    observed_max = max(per_anchor, default=0)
    return {
        "relations": relations,
        "edges_excluded_total": sum(entry["edges"] for entry in relations.values()),
        "consumed": sorted(CONTROL_RELATIONS),
        "materialization_budget": {
            "limit": FP_MATERIALIZE_LIMIT,
            "distinct_principals_per_anchor_scope_max": observed_max,
            "headroom": FP_MATERIALIZE_LIMIT - observed_max,
            "anchor_scopes_at_the_limit": sum(1 for total in per_anchor if total >= FP_MATERIALIZE_LIMIT),
            "anchor_scopes": len(per_anchor),
            "reading": (
                "PSAT_FP_MATERIALIZE_LIMIT caps the principals materialised per (contract, "
                "deployment) scope. Published so the enumeration above can be read as UN-CLIPPED "
                "rather than trusted to be: anchor_scopes_at_the_limit is the number of scopes "
                "that could have lost a tail, and a zero there is the proven 'nothing was cut'"
            ),
        },
        "basis": (
            "every relation present in this protocol's control_graph_edges, unioned with "
            "every relation db.CONTROL_EDGE_RELATIONS lets the writer emit, minus the "
            "consumed set. Counts are of edges, not of principals: duplicate (principal, "
            "anchor) pairs are distinct witnesses and are counted as the rows they are"
        ),
        "reading": (
            "an excluded relation is reach this scorer is NOT claiming, published so a "
            "consumer can see the size of the bound and re-open the ruling when a "
            "witnessed licence lands. Declining to walk one costs confidence — it never "
            "earns it"
        ),
    }


def discovery_relation_entities(session: Session, protocol_id: int) -> dict[str, set[str]]:
    """Every endpoint of every AUTHORITY relation discovery recorded, per relation.

    ``CONTROL_EDGE_RELATIONS`` is the database's own vocabulary for a relation
    that carries authority; this scorer walks three of its seven. The four it
    declines are still work discovery did, and the entities they name are still
    entities this document must answer for — so they enter the confidence
    perimeter whether or not the walk consumes them. Relations outside that set
    (``external_call_target``, ``controller_value_unattributed``) assert no
    authority by their own register entries and are not admitted here.

    Sibling of :func:`unconsumed_reach_relations`, which counts the same excluded
    edges: that one publishes how much reach is not being claimed, this one puts
    the entities behind it into the denominator that has to account for them.
    """
    from db.models import CONTROL_EDGE_RELATIONS, Contract, ControlGraphEdge

    out: dict[str, set[str]] = {relation: set() for relation in sorted(CONTROL_EDGE_RELATIONS)}
    rows = (
        session.query(
            ControlGraphEdge.relation, ControlGraphEdge.from_node_id, ControlGraphEdge.to_node_id, Contract.chain
        )
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .filter(Contract.protocol_id == protocol_id, ControlGraphEdge.relation.in_(sorted(CONTROL_EDGE_RELATIONS)))
        .order_by(ControlGraphEdge.id)
        .all()
    )
    for relation, source, target, chain in rows:
        for raw in (source, target):
            address = str(raw or "").replace("address:", "").lower()
            if address:
                out[str(relation)].add(entity_key(chain, address))
    return out


def load_upgrade_provenance(session: Session, protocol_id: int) -> dict[str, Any]:
    """Upgrade history as PROVENANCE only — it moves no severity in v1.

    Counted through the action folds, never ``COUNT(upgrade_events.id)``: the
    unit is the transaction, one of which carried 19 ``Upgraded`` logs. A
    post-exclusion zero publishes ``None``, because "no event recorded" never
    licenses "no upgrade happened" over a recording surface that is itself
    unwitnessed.
    """
    from db.models import Contract
    from services.discovery.upgrade_history import governance_actions_for, upgrade_action_counts

    contract_ids = [
        row[0]
        for row in session.query(Contract.id).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    ]
    if not contract_ids:
        return {"contracts": 0, "governance_actions": 0, "per_contract": {}}
    counts = upgrade_action_counts(session, contract_ids)
    actions = governance_actions_for(session, contract_ids)
    per_contract = {
        str(cid): {
            "upgrade_count": entry.get("count"),
            "executor_kinds": entry.get("basis", {}).get("executor_kinds"),
            "recorded_event_coverage": entry.get("basis", {}).get("recorded_event_coverage"),
            "direct_upgrade_witnessed_at_block": entry.get("basis", {}).get("direct_upgrade_witnessed_at_block"),
        }
        for cid, entry in sorted(counts.items())
    }
    return {
        "contracts": len(per_contract),
        "governance_actions": len(actions),
        "per_contract": per_contract,
        "note": (
            "upper bound; deployments excluded, unproven events kept. Executor kind "
            "annotates and does not modify the upgrade-authority weakness in v1"
        ),
    }


def load_ledgers(session: Session, protocol_id: int) -> dict[str, Any]:
    """The omission ledgers, as provenance references.

    Nothing was dropped only if BOTH selection ledgers are empty, and the spawn
    dispositions partition the node list only when ``walked`` is true. An absent
    artifact means the ledger predates the writer, never "omitted nothing".
    """
    from db.models import Artifact, Job

    out: dict[str, Any] = {}
    for name in ("selection_summary", "perimeter_spawn_summary", "fp_materialization_summary"):
        rows = (
            session.query(Artifact.job_id)
            .join(Job, Job.id == Artifact.job_id)
            .filter(Job.protocol_id == protocol_id, Artifact.name == name)
            .order_by(Artifact.job_id)
            .all()
        )
        out[name] = {
            "artifacts": len(rows),
            "job_ids": [str(row[0]) for row in rows][:8],
            "reading": "absent = predates the ledger, never 'omitted nothing'",
        }
    return out


def perimeter_state(session: Session, protocol_id: int) -> tuple[str, dict[str, Any]]:
    """Whether the perimeter was settled when this score was computed.

    A failed queue read lands on ``not_determined`` rather than either polarity:
    stamping "unsettled" on an unreadable queue would be a positive claim with no
    witness.
    """
    from db.models import Job, JobStatus

    try:
        pending = (
            session.query(sql_func.count(Job.id))
            .filter(
                Job.protocol_id == protocol_id,
                Job.status.in_([JobStatus.queued, JobStatus.processing]),
            )
            .scalar()
        )
    except Exception as exc:  # pragma: no cover - a failed read is a real third state
        return PERIMETER_NOT_DETERMINED, {"error": type(exc).__name__}
    if pending is None:
        return PERIMETER_NOT_DETERMINED, {"pending_jobs": None}
    return (PERIMETER_SETTLED if pending == 0 else PERIMETER_UNSETTLED), {"pending_jobs": int(pending)}


def load_audit_posture(session: Session, protocol_id: int, value_plane: ValuePlane) -> dict[str, Any]:
    """Audit coverage, classified and weighted by contracts and by value.

    Coverage rows are per (audit, contract), so counting them answers neither
    "how much of the protocol is audited" nor "how much of the money is": one
    contract reviewed by four audits is four rows and one contract, and the
    contracts that hold the value are a handful of the total. Both weightings
    are computed here, over the same reduction the fold's exposure uses — the
    latest observation per (entity, asset, observed account), implementation
    folded onto its proxy — so a consumer joining these counts to a value plane
    of its own would re-introduce the double count that reduction exists to
    remove. An entity whose total is not a number contributes nothing and is
    never read as $0.
    """
    from db.models import AuditContractCoverage, AuditReport, Contract

    equivalence_classes = {
        "candidate_path_missing": "our_side_data_gap",
        "commit_not_found_in_repo": "our_side_data_gap",
        "hash_mismatch": "deployed_source_provably_differs",
        "etherscan_fetch_failed": "infrastructure",
    }
    rows = (
        session.query(AuditContractCoverage)
        .filter(AuditContractCoverage.protocol_id == protocol_id)
        .order_by(AuditContractCoverage.contract_id, AuditContractCoverage.id)
        .all()
    )
    proven = [r for r in rows if r.equivalence_status == "proven" and r.matched_commit_sha]
    classified: dict[str, int] = defaultdict(int)
    for row in rows:
        bucket = equivalence_classes.get(str(row.equivalence_status))
        if bucket:
            classified[bucket] += 1

    contracts = session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    covered_ids = {row.contract_id for row in rows}
    proven_ids = {row.contract_id for row in proven}
    covered_value, covered_priced = _audited_value(contracts, covered_ids, value_plane)
    proven_value, proven_priced = _audited_value(contracts, proven_ids, value_plane)

    reports = int(
        session.query(sql_func.count(AuditReport.id)).filter(AuditReport.protocol_id == protocol_id).scalar() or 0
    )
    # A published zero is a claim that the protocol has no audits, and an empty
    # table is that fact only where discovery is proven to have looked. A stage
    # that never ran, or died before persisting (the billing-failure shape),
    # leaves the same empty table and lands on not_determined instead.
    reports_on_file = reports if reports or _audit_discovery_witnessed(session, protocol_id) else None
    # Zero covered contracts needs its own licence: with no audit on file there
    # was nothing that could match, but audits with no coverage row are a
    # matcher run this fold has no witness for.
    coverage_zero_licensed = reports_on_file == 0
    return {
        "rows": len(rows),
        "proven_equivalence": len(proven),
        "reports_on_file": reports_on_file,
        "contracts_total": len(contracts),
        "contracts_covered": len(covered_ids) if rows or coverage_zero_licensed else None,
        "contracts_proven": len(proven_ids) if rows or coverage_zero_licensed else None,
        "value_covered_usd": covered_value,
        "value_proven_usd": proven_value,
        "value_entities_priced": {"covered": covered_priced, "proven": proven_priced},
        "non_coverage_classified": dict(sorted(classified.items())),
        "reading": (
            "equivalence_status='proven' + matched_commit_sha is the admissible core; "
            "proof_kind is banned in every value; a non-proven row is UNKNOWN, not 0. "
            "The value figures are floors over the PRICED covered entities — an unpriced "
            "audited contract contributes nothing and is never read as $0 — and null means "
            "no covered entity was priced at all. A null count is an unwitnessed stage, "
            "never a zero: the discovery witness is the persisted audit_reports artifact, "
            "and a failure INSIDE the row sync after that artifact committed is recorded "
            "only in the stage_errors artifact body, which this DB-only fold does not read"
        ),
    }


def _audit_discovery_witnessed(session: Session, protocol_id: int) -> bool:
    """Whether audit discovery is proven to have run and persisted its result.

    ``store_artifact(job, "audit_reports", ...)`` commits on the one path that
    persists discovered reports, so the row is the witness that the stage got
    that far. Existence only — the body lives in the bucket and this fold reads
    the database alone.
    """
    from db.models import Artifact, Job

    return (
        session.query(Artifact.id)
        .join(Job, Job.id == Artifact.job_id)
        .filter(Job.protocol_id == protocol_id, Artifact.name == "audit_reports")
        .order_by(Artifact.id)
        .first()
    ) is not None


def _audited_value(
    contracts: list[Any], audited_contract_ids: set[int], value_plane: ValuePlane
) -> tuple[float | None, int]:
    """Canonical priced value behind a set of audited contracts, and how many priced.

    An entity counts when its own contract is audited OR when the implementation
    it delegates to is: a proxy holds the balance and an audit reviews the
    implementation's source, so keying on the audited row's contract alone would
    report the money as unaudited.
    """
    audited_keys = {entity_key(c.chain, c.address) for c in contracts if c.id in audited_contract_ids}
    entities: set[str] = set()
    for contract in contracts:
        own = entity_key(contract.chain, contract.address)
        implementation = entity_key(contract.chain, contract.implementation) if contract.implementation else None
        if own in audited_keys or (implementation is not None and implementation in audited_keys):
            entities.add(value_plane.canonical(own))
    totals = [value_plane.total(key) for key in sorted(entities)]
    priced = [total for total in totals if total is not None]
    if not priced:
        return None, 0
    return round(sum(sorted(priced)), 2), len(priced)


def plane_row_counts(session: Session, protocol_id: int) -> dict[str, Any]:
    """Per-plane row counts + max ``updated_at``, for the provenance block."""
    from db.models import (
        Contract,
        ContractBalanceLatest,
        EffectiveFunction,
        EffectVerdict,
        FunctionPrincipal,
        FunctionScoreSignal,
        RestakingPositionLatest,
        RoleHolderPlane,
    )

    def _count(query: Any, plane: str) -> int | None:
        """A plane that cannot be read is ``None`` — not_determined, never 0.

        A missing table (a database this build's migration has not reached) and
        a genuinely empty plane are different facts, and a zero here would make
        an unread plane look like a proven-empty one in the provenance block.
        """
        try:
            return int(query.scalar() or 0)
        except Exception as exc:
            session.rollback()
            # The document says "not_determined"; only the exception type says
            # WHY, and schema drift is the usual answer.
            logger.warning(
                "plane row count unreadable for %s",
                plane,
                extra={"protocol_id": protocol_id, "plane": plane, "exc_type": type(exc).__name__},
            )
            return None

    contracts = session.query(sql_func.count(Contract.id)).filter(Contract.protocol_id == protocol_id)
    functions = (
        session.query(sql_func.count(EffectiveFunction.id))
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
    )
    principals = (
        session.query(sql_func.count(FunctionPrincipal.id))
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
    )
    verdicts = (
        session.query(sql_func.count(EffectVerdict.id))
        .join(EffectiveFunction, EffectiveFunction.id == EffectVerdict.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
    )
    # Both keying arms, because both are rows the value plane reads. Counting
    # only the join to ``contracts`` would report a plane smaller than the one
    # the score was computed over the moment an entity-keyed holder is observed.
    entity_identities = sorted(
        (chain, address)
        for chain, _, address in (key.partition("::") for key in load_proven_eoa_entities(session, protocol_id))
        if chain and address
    )
    balances = session.query(sql_func.count(ContractBalanceLatest.id)).filter(
        sql_or(
            ContractBalanceLatest.contract_id.in_(
                session.query(Contract.id).filter(Contract.protocol_id == protocol_id)
            ),
            (
                tuple_(ContractBalanceLatest.entity_chain, ContractBalanceLatest.entity_address).in_(entity_identities)
                if entity_identities
                else sql_false()
            ),
        )
    )
    signals = session.query(sql_func.count(FunctionScoreSignal.id)).filter(
        FunctionScoreSignal.protocol_id == protocol_id
    )
    try:
        max_verdict_updated = (
            session.query(sql_func.max(EffectVerdict.updated_at))
            .join(EffectiveFunction, EffectiveFunction.id == EffectVerdict.function_id)
            .join(Contract, Contract.id == EffectiveFunction.contract_id)
            .filter(Contract.protocol_id == protocol_id)
            .scalar()
        )
    except Exception as exc:
        session.rollback()
        logger.warning(
            "plane freshness unreadable for %s",
            "max_effect_verdict_updated_at",
            extra={
                "protocol_id": protocol_id,
                "plane": "max_effect_verdict_updated_at",
                "exc_type": type(exc).__name__,
            },
        )
        max_verdict_updated = None
    return {
        "contracts": _count(contracts, "contracts"),
        "effective_functions": _count(functions, "effective_functions"),
        "function_principals": _count(principals, "function_principals"),
        "effect_verdicts": _count(verdicts, "effect_verdicts"),
        "contract_balances_latest": _count(balances, "contract_balances_latest"),
        "function_score_signals": _count(signals, "function_score_signals"),
        "restaking_positions_latest": _count(
            session.query(sql_func.count(RestakingPositionLatest.id)).filter(
                RestakingPositionLatest.protocol_id == protocol_id
            ),
            "restaking_positions_latest",
        ),
        "role_holder_planes": _count(session.query(sql_func.count(RoleHolderPlane.role_hash)), "role_holder_planes"),
        "max_effect_verdict_updated_at": max_verdict_updated.isoformat() if max_verdict_updated else None,
    }


def native_value_state(plane: ValuePlane, key: str) -> Tri[float]:
    """The native holding of an entity with no native balance row.

    ``proven_zero`` is a real answer and enters as 0.0; everything else —
    including a failed fetch — is ``not_determined`` and is never read as zero.

    The label a proven zero carries is the same whichever witness supplied it: a
    stored zero-quantity native row and the fetch record's ``proven_zero`` status
    are the same fact read two ways, and calling one of them plain ``proven``
    would make the label depend on which writer got there first.
    """
    canonical = plane.canonical(key)
    assets = plane.per_asset.get(canonical) or {}
    if NATIVE_ASSET in assets:
        held = assets[NATIVE_ASSET]
        return Tri.proven("proven_zero" if held == 0.0 else "proven", held)
    fact = plane.native_fact.get(canonical)
    if fact and fact.startswith("proven_zero"):
        return Tri.proven("proven_zero", 0.0)
    return Tri[float].not_determined()


# --- authority deletability --------------------------------------------------
# Can this principal DELETE the authority that gates this destination function?
#
# A composed magnitude is a figure proven by a call the principal did not make:
# the proof is a direct impersonated call to the destination, the published
# route runs through a wrapper that authors the call's arguments. The figure
# transfers to the principal only where the principal can author that calldata
# itself — which it can if it can repoint or rewrite the authority the
# destination's gate consults, because then there is no gate left to satisfy.
#
# The question is asked per (principal, destination, selector) and answered from
# ``function_principals`` rows on the four setters below. It is NEVER answered
# from a hop count, a selector name or a contract shape: on the corpus this was
# calibrated against, ``len(act_as_chain) == 1`` partitions the population
# identically, and shipping that correlation would publish an abstraction above
# an available witness (inv. 16).
#
# THREE OUTCOMES, none collapsible (inv. 1):
#   * a qualifying row exists                     -> ``deletable``
#   * the join ran and returned no row            -> ``proven_not_deletable``
#   * the join could not be run, or was run on a  -> ``not_determined``
#     witness that proves less than membership
# The third is not the second. An unresolvable authority failing to "not
# deletable" mints an earned negative out of an absence; failing to "deletable"
# republishes a figure on an unproven control claim. Both are banned, so the
# third state carries its own typed reason all the way to the consumer.

# The two arms, each INDEPENDENTLY sufficient — arm (a) is not a relaxation of
# arm (b). HOST: ``setAuthority`` repoints the destination's own authority
# pointer and ``transferOwnership`` takes the owner slot that may repoint it.
# AUTHORITY: the role-writing setters ON the authority the destination is
# witnessed to consult let the principal write itself the admitting role.
#
# Matched on ``effective_functions.function_name``, which is what the ruling
# this implements specifies and what its 28/12 partition was measured against.
# A name is not a signature, so the matched row's own selector is published in
# the basis rather than assumed: measured on this snapshot, ``transferOwnership``
# carries TWO selectors (``0xf2fde38b`` x122, ``0x078dfbe7`` x4) and a reader
# who needs to know which one proved the control can read it off the basis.
DELETABILITY_HOST_SETTERS = ("setAuthority", "transferOwnership")
DELETABILITY_AUTHORITY_SETTERS = ("setRoleCapability", "setUserRole")
DELETABILITY_SETTERS = tuple(sorted(DELETABILITY_HOST_SETTERS + DELETABILITY_AUTHORITY_SETTERS))

# ``membership_quality`` is NOT a column — it lives at
# ``details->>'membership_quality'``, domain measured as
# {lower_bound: 26493, exact: 2196}. Only ``exact`` proves this address is in
# the admitting set; ``lower_bound`` proves the set has at least these members,
# which is a floor on the SET and not a proof about this address. Measured cost
# of requiring it on the four setters: zero — all 262 rows are already exact.
MEMBERSHIP_QUALITY_EXACT = "exact"

# ``principal_type`` is NEVER a filter here: it is ``'controller'`` on 28,689 of
# 28,689 rows, so a join carrying it fails open while looking scoped.

# The NORMATIVE authority witness: the destination function's own resolution
# record, per (destination, selector). The corroborating one is contract-scoped
# and cannot separate two selectors on one host that consult different
# authorities, so it is admitted as a cross-check and never as the source.
SOLMATE_ROLES_AUTHORITY_STEP = "solmate_roles_authority"
AUTHORITY_CONTROLLER_ID = "external_contract:authority"
# The gate's own admission that it could not resolve the authority it consults.
CALLER_TAINTED_AUTHORITY_UNRESOLVED = "caller_tainted_authority_unresolved"

DELETABILITY_DELETABLE = "deletable"
DELETABILITY_PROVEN_NOT_DELETABLE = "proven_not_deletable"
DELETABILITY_NOT_DETERMINED = "not_determined"
DELETABILITY_STATES = (
    DELETABILITY_DELETABLE,
    DELETABILITY_PROVEN_NOT_DELETABLE,
    DELETABILITY_NOT_DETERMINED,
)

DELETABILITY_ARM_HOST = "host"
DELETABILITY_ARM_GATING_AUTHORITY = "gating_authority"
DELETABILITY_ARMS = (DELETABILITY_ARM_HOST, DELETABILITY_ARM_GATING_AUTHORITY)

# One reason per evidential situation. The consumer counts refusals by these
# tokens, so two situations sharing one token would publish a count nobody can
# decompose.
DELETABILITY_NO_SETTER_ROW = "no_setter_row_names_this_principal_at_the_host_or_at_the_gating_authority"
DELETABILITY_MEMBERSHIP_NOT_EXACT = "every_setter_row_naming_this_principal_is_a_lower_bound_on_the_admitting_set"
DELETABILITY_AUTHORITY_UNRESOLVED = "no_witness_names_the_authority_this_destination_selector_consults"
DELETABILITY_AUTHORITY_NOT_UNIQUE = "the_selector_scoped_witnesses_name_more_than_one_authority_for_this_selector"
DELETABILITY_AUTHORITY_SOURCES_DISAGREE = "the_selector_scoped_and_contract_scoped_authority_witnesses_disagree"
DELETABILITY_AUTHORITY_TAINTED = "the_destination_gate_carries_an_unresolved_caller_authority"
DELETABILITY_NO_PRINCIPAL_ADDRESS = "the_row_names_no_principal_address_to_ask_the_join_about"
DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED = "the_destination_key_carries_no_chain_scope"
DELETABILITY_REASONS = (
    DELETABILITY_AUTHORITY_NOT_UNIQUE,
    DELETABILITY_AUTHORITY_SOURCES_DISAGREE,
    DELETABILITY_AUTHORITY_TAINTED,
    DELETABILITY_AUTHORITY_UNRESOLVED,
    DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED,
    DELETABILITY_MEMBERSHIP_NOT_EXACT,
    DELETABILITY_NO_PRINCIPAL_ADDRESS,
    DELETABILITY_NO_SETTER_ROW,
)

# What the contract-scoped cross-check had to say. ``not_corroborated`` and
# ``disagrees`` are different facts: the first is a witness that did not answer,
# the second is one that answered differently, and only the second is evidence.
CROSSCHECK_AGREES = "agrees"
CROSSCHECK_DISAGREES = "disagrees"
CROSSCHECK_NOT_CORROBORATED = "not_corroborated"
CROSSCHECK_NOT_COMPARED = "not_compared"


@dataclass(frozen=True, order=True)
class SetterPrincipal:
    """One ``function_principals`` row on a setter of one contract.

    ``membership_quality`` is carried raw, including ``None``: an absent quality
    is an unread witness, and reading it as ``exact`` would let a row that
    proves nothing about this address prove control.
    """

    function_principal_id: int
    chain: str
    contract_address: str
    function_name: str
    selector: str | None
    principal_address: str
    membership_quality: str | None

    @property
    def is_membership_exact(self) -> bool:
        return self.membership_quality == MEMBERSHIP_QUALITY_EXACT


@dataclass(frozen=True)
class DeletabilityVerdict:
    """The three-state answer for one (principal set, destination, selector).

    ``reason`` is populated in exactly the two withholding states and is the
    token a consumer counts refusals by; ``basis`` is populated in exactly the
    deletable state and names the row that proved it. The two authority witness
    fields are published in every state, because "which authority did you even
    ask about" is the first question a reader of a refusal has.
    """

    state: str
    destination_key: str
    selector: str
    principal_addresses: tuple[str, ...]
    reason: str | None = None
    arm: str | None = None
    basis: SetterPrincipal | None = None
    gating_authorities: tuple[str, ...] = ()
    crosscheck_authorities: tuple[str, ...] = ()
    crosscheck: str = CROSSCHECK_NOT_COMPARED

    def __post_init__(self) -> None:
        # The pairing is the whole point of the type: a deletable verdict with
        # no basis is a control claim with no witness, and a withheld one with
        # no reason is a refusal a consumer cannot publish or count.
        if self.state not in DELETABILITY_STATES:
            raise ValueError(f"unknown deletability state: {self.state!r}")
        if self.state == DELETABILITY_DELETABLE:
            if self.basis is None or self.arm is None or self.reason is not None:
                raise ValueError("a deletable verdict carries an arm and a basis row, and no reason")
        elif self.basis is not None or self.arm is not None or self.reason is None:
            raise ValueError("a withheld verdict carries a reason, and neither an arm nor a basis row")

    @property
    def is_deletable(self) -> bool:
        return self.state == DELETABILITY_DELETABLE

    def disclosure(self) -> dict[str, Any]:
        """The verdict as a publishable block — the whole verdict, every state.

        Published on WITHHELD entries too, and that is not decoration: under
        this rule a protocol whose gating authority cannot be resolved lands on
        ``not_determined``, its figure is withheld, and its published exposure
        FALLS. Obscuring evidence must not pay (inv. 13), so the withheld entry
        discloses the state, the typed reason, the authority it asked about and
        which witnesses answered — a suppressed authority then presents as a
        disclosed unknown rather than as an absent finding. The caller pairs
        this with its own ``refused`` counter, keyed on ``reason``.
        """
        block: dict[str, Any] = {
            "state": self.state,
            "reason": self.reason,
            "destination": self.destination_key,
            "selector": self.selector,
            "principal_addresses": list(self.principal_addresses),
            "gating_authority_witness": {
                "selector_scoped": list(self.gating_authorities),
                "contract_scoped_crosscheck": list(self.crosscheck_authorities),
                "crosscheck": self.crosscheck,
            },
        }
        block["basis"] = None if self.basis is None else self.basis_block()
        return block

    def basis_block(self) -> dict[str, Any] | None:
        """What proved it: the arm, the setter row, and the row's own id.

        ``function_principal_id`` and the setter's own selector are the two
        fields a reader needs to re-run this join by hand, which is what makes
        the republished figure checkable rather than asserted.
        """
        if self.basis is None:
            return None
        return {
            "arm": self.arm,
            "function_principal_id": self.basis.function_principal_id,
            "principal_address": self.basis.principal_address,
            "setter_function_name": self.basis.function_name,
            "setter_selector": self.basis.selector,
            "setter_contract": entity_key(self.basis.chain, self.basis.contract_address),
            "membership_quality": self.basis.membership_quality,
        }


@dataclass
class DeletabilityPlane:
    """The rows :func:`authority_deletability` decides from, loaded once.

    Every map is keyed on ``(chain, lowercased address)`` — chain-scoped,
    because the same address on two chains is two contracts and an unscoped key
    would let one chain's setter row prove control on the other.
    """

    setters: dict[tuple[str, str], tuple[SetterPrincipal, ...]] = field(default_factory=dict)
    gating: dict[tuple[str, str, str], tuple[str, ...]] = field(default_factory=dict)
    crosscheck: dict[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)
    tainted: frozenset[tuple[str, str, str]] = frozenset()

    def setter_rows(
        self,
        chain: str,
        address: str,
        function_names: Iterable[str],
        principal_addresses: Iterable[str],
    ) -> tuple[SetterPrincipal, ...]:
        """Setter rows at one contract naming one of these principals.

        Membership quality is NOT filtered here: the caller has to be able to
        tell "no row names this principal" from "a row does, and it proves less
        than membership", because those are different published states.
        """
        wanted = frozenset(function_names)
        principals = frozenset(_lower(a) for a in principal_addresses)
        rows = self.setters.get((coalesce_chain(chain), _lower(address)), ())
        return tuple(r for r in rows if r.function_name in wanted and r.principal_address in principals)

    def counts(self) -> dict[str, int]:
        """Row counts, for the provenance block."""
        return {
            "setter_principal_rows": sum(len(rows) for rows in self.setters.values()),
            "setter_contracts": len(self.setters),
            "gating_authority_witnesses": len(self.gating),
            "authority_crosscheck_contracts": len(self.crosscheck),
            "tainted_destination_gates": len(self.tainted),
        }


def _authority_address(value: Any) -> str:
    """A stored authority value as a plain lowercased address, or ``""``.

    Only the two shapes the column is known to carry are read: a 42-character
    address, and a 66-character 32-byte word whose low 20 bytes are one.
    Anything else is left unread rather than sliced into a plausible address.
    """
    token = _lower(value)
    if not token.startswith("0x"):
        return ""
    if len(token) == 42:
        return token
    if len(token) == 66:
        return "0x" + token[-40:]
    return ""


def load_deletability_plane(session: Session) -> DeletabilityPlane:
    """Every witness :func:`authority_deletability` reads, in four queries.

    NOT protocol-scoped, deliberately, and this is the one scoping decision in
    this plane that could go wrong in a way nothing downstream would show. The
    join asks about specific ``(chain, address)`` contracts — the destination a
    figure was proven at, and the authority its gate is witnessed to consult —
    and a ``(chain, address)`` is a global on-chain identity, not a
    protocol-relative one. Measured on this snapshot: 51 of the 262 setter rows
    sit on 33 contracts whose ``protocol_id`` is NULL, and a protocol-scoped
    read would drop them. Dropping a witness here does not fail safe: the join
    would return no row and the entry would publish ``proven_not_deletable`` —
    an earned negative minted from our own scoping, which is exactly the defect
    class this plane exists to close. The population is a pure function of the
    database state, so replay (inv. 11) is unaffected.

    The queries are narrow by construction — four setter names, one trace step,
    one controller id, one basis tag — so "unscoped" is a few hundred rows, not
    a table scan of ``function_principals``.
    """
    from db.models import Contract, ControllerValue, EffectiveFunction, FunctionPrincipal

    setters: dict[tuple[str, str], list[SetterPrincipal]] = defaultdict(list)
    for fp_id, fp_address, details, function_name, selector, address, chain in (
        session.query(
            FunctionPrincipal.id,
            FunctionPrincipal.address,
            FunctionPrincipal.details,
            EffectiveFunction.function_name,
            EffectiveFunction.selector,
            Contract.address,
            Contract.chain,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(EffectiveFunction.function_name.in_(DELETABILITY_SETTERS))
        .order_by(FunctionPrincipal.id)
        .all()
    ):
        principal = _lower(fp_address)
        host = _lower(address)
        if not principal or not host:
            continue
        quality = (details or {}).get("membership_quality") if isinstance(details, dict) else None
        setters[(coalesce_chain(chain), host)].append(
            SetterPrincipal(
                function_principal_id=int(fp_id),
                chain=coalesce_chain(chain),
                contract_address=host,
                function_name=str(function_name),
                selector=_lower(selector) or None,
                principal_address=principal,
                membership_quality=None if quality is None else str(quality),
            )
        )

    # The gating authority, per (destination, selector). The LIKE is a prefilter
    # only — the step name is matched exactly, in Python, below; a row whose
    # trace merely mentions the string contributes nothing.
    gating: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for details, selector, address, chain in (
        session.query(
            FunctionPrincipal.details,
            EffectiveFunction.selector,
            Contract.address,
            Contract.chain,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(FunctionPrincipal.details.cast(Text).like(f"%{SOLMATE_ROLES_AUTHORITY_STEP}%"))
        .filter(EffectiveFunction.selector.isnot(None))
        .order_by(FunctionPrincipal.id)
        .all()
    ):
        key = (coalesce_chain(chain), _lower(address), _lower(selector))
        for step in (details or {}).get("trace") or []:
            if not isinstance(step, dict) or step.get("step") != SOLMATE_ROLES_AUTHORITY_STEP:
                continue
            authority = _authority_address(step.get("authority"))
            if authority:
                gating[key].add(authority)

    crosscheck: dict[tuple[str, str], set[str]] = defaultdict(set)
    for value, address, chain in (
        session.query(ControllerValue.value, Contract.address, Contract.chain)
        .join(Contract, Contract.id == ControllerValue.contract_id)
        .filter(ControllerValue.controller_id == AUTHORITY_CONTROLLER_ID)
        .order_by(ControllerValue.id)
        .all()
    ):
        authority = _authority_address(value)
        if authority:
            crosscheck[(coalesce_chain(chain), _lower(address))].add(authority)

    tainted = {
        (coalesce_chain(chain), _lower(address), _lower(selector))
        for selector, address, chain in (
            session.query(EffectiveFunction.selector, Contract.address, Contract.chain)
            .join(Contract, Contract.id == EffectiveFunction.contract_id)
            .filter(EffectiveFunction.capability_expr.cast(Text).like(f"%{CALLER_TAINTED_AUTHORITY_UNRESOLVED}%"))
            .filter(EffectiveFunction.selector.isnot(None))
            .order_by(EffectiveFunction.id)
            .all()
        )
    }

    return DeletabilityPlane(
        setters={key: tuple(sorted(rows)) for key, rows in sorted(setters.items())},
        gating={key: tuple(sorted(values)) for key, values in sorted(gating.items())},
        crosscheck={key: tuple(sorted(values)) for key, values in sorted(crosscheck.items())},
        tainted=frozenset(tainted),
    )


def authority_deletability(
    plane: DeletabilityPlane,
    principal_addresses: Iterable[str],
    destination_key: str,
    selector: str,
) -> DeletabilityVerdict:
    """Can this principal author a call to ``destination_key.selector`` itself?

    ``principal_addresses`` is the ROW's ``principal_addresses`` list, never its
    ``principal_unit``. The two differ wherever a row is reached through an
    ``access_path``: measured on the reference corpus, the row whose unit is a
    Safe but whose addresses name the timelock it acts through holds all four
    setters at its destination under the timelock and NONE under the Safe, so
    keying on the unit withholds a $11.36M figure the evidence supports and
    publishes no diagnostic saying why. Any one of the addresses qualifying is
    enough; the row that qualified is named in the basis.

    Destination-scoped, and that scope is load-bearing in the other direction:
    unscoped ("does this principal hold a setter ANYWHERE"), the EOA of the
    reference corpus holds all four setters on solver contracts it has nothing
    to do with these vaults, and every withheld entry is republished.

    Deterministic: the arms are asked in a fixed order and the basis is the
    lowest-id qualifying row, so the same database state answers identically.
    """
    addresses = tuple(sorted({_lower(a) for a in (principal_addresses or ()) if _lower(a)}))
    selector = _lower(selector)

    def withheld(state: str, reason: str, **kwargs: Any) -> DeletabilityVerdict:
        return DeletabilityVerdict(
            state=state,
            destination_key=destination_key,
            selector=selector,
            principal_addresses=addresses,
            reason=reason,
            **kwargs,
        )

    if not addresses:
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_NO_PRINCIPAL_ADDRESS)
    if not is_entity_key(destination_key):
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED)
    chain, _, host = destination_key.partition("::")
    chain = coalesce_chain(chain)

    # Arm (a), the HOST arm, first: it asks nothing about the gating authority,
    # so it stands whatever the authority witnesses do or do not say.
    host_rows = plane.setter_rows(chain, host, DELETABILITY_HOST_SETTERS, addresses)
    exact_host = [row for row in host_rows if row.is_membership_exact]
    if exact_host:
        return DeletabilityVerdict(
            state=DELETABILITY_DELETABLE,
            destination_key=destination_key,
            selector=selector,
            principal_addresses=addresses,
            arm=DELETABILITY_ARM_HOST,
            basis=min(exact_host),
            gating_authorities=plane.gating.get((chain, _lower(host), selector), ()),
            crosscheck_authorities=plane.crosscheck.get((chain, _lower(host)), ()),
            crosscheck=CROSSCHECK_NOT_COMPARED,
        )

    # Arm (b) needs to know WHICH authority the destination's own gate consults.
    normative: tuple[str, ...] = plane.gating.get((chain, _lower(host), selector)) or ()
    corroborating: tuple[str, ...] = plane.crosscheck.get((chain, _lower(host))) or ()
    if not normative:
        crosscheck_state = CROSSCHECK_NOT_COMPARED
    elif not corroborating:
        crosscheck_state = CROSSCHECK_NOT_CORROBORATED
    elif set(normative) == set(corroborating):
        crosscheck_state = CROSSCHECK_AGREES
    else:
        crosscheck_state = CROSSCHECK_DISAGREES
    witnesses = {
        "gating_authorities": tuple(normative),
        "crosscheck_authorities": tuple(corroborating),
        "crosscheck": crosscheck_state,
    }

    if (chain, _lower(host), selector) in plane.tainted:
        # The gate itself records that it could not resolve the authority it
        # consults. A trace that names one anyway is naming a candidate, not the
        # gate's answer, and control over a candidate proves nothing.
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_TAINTED, **witnesses)
    if not normative:
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_UNRESOLVED, **witnesses)
    if len(normative) > 1:
        # Two answers to "which authority gates this selector" is no answer.
        # Asking the arm over each in turn would take the union — control over
        # any candidate read as control over the real one.
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_NOT_UNIQUE, **witnesses)
    if crosscheck_state == CROSSCHECK_DISAGREES:
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_SOURCES_DISAGREE, **witnesses)

    authority = next(iter(normative))
    authority_rows = plane.setter_rows(chain, authority, DELETABILITY_AUTHORITY_SETTERS, addresses)
    exact_authority = [row for row in authority_rows if row.is_membership_exact]
    if exact_authority:
        return DeletabilityVerdict(
            state=DELETABILITY_DELETABLE,
            destination_key=destination_key,
            selector=selector,
            principal_addresses=addresses,
            arm=DELETABILITY_ARM_GATING_AUTHORITY,
            basis=min(exact_authority),
            **witnesses,
        )
    if host_rows or authority_rows:
        # Rows DO name this principal on a setter; none of them proves
        # membership. That is not "the join found nothing" and must not be
        # published as the earned negative.
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_MEMBERSHIP_NOT_EXACT, **witnesses)
    # Both arms were asked, on witnesses that answered, and neither returned a
    # row. This is the earned negative.
    return withheld(DELETABILITY_PROVEN_NOT_DELETABLE, DELETABILITY_NO_SETTER_ROW, **witnesses)


# How an INTERMEDIATE's own body treats the destination call it makes. Three
# outcomes and the third is the fall-through: a route this reader cannot
# classify is ``not_determined``, never an arm. The two positive tokens are the
# spec's, and each is earned from ONE named field of the intermediate function's
# own stored value-flow witness — never from the function's name, its selector,
# its hop position or the shape of the contract it sits on.
ROUTE_AMOUNT_AUTHORED = "destination_amount_is_authored_by_the_intermediate"
# Named for the field it is EARNED from — ``target_constraint`` on the
# intermediate's own flow witness, which pins the destination call's counterparty
# ARGUMENT. It is deliberately not called a callee restriction: ``callee`` is an
# intra-unit AST name for the object the external call is made on
# (``services/static/claims/matchers/flows.py``), and no stored witness says the
# intermediate restricts THAT. A token asserting a restricted callee set would be
# a positive security claim on evidence that answers a different question.
ROUTE_TARGET_CONSTRAINED = "destination_target_is_constrained_by_the_intermediate"
ROUTE_NOT_DETERMINED = "not_determined"
ROUTE_CLASSIFICATIONS = (ROUTE_AMOUNT_AUTHORED, ROUTE_TARGET_CONSTRAINED, ROUTE_NOT_DETERMINED)

# Why a route stayed unclassified. Two different evidential situations: the
# intermediate's body carries no flow witness naming this destination call at
# all, or it carries one and the two conjuncts below are both unproven on it.
ROUTE_NO_FLOW_WITNESS = "the_intermediate_body_names_no_value_flow_into_this_destination_selector"
ROUTE_NEITHER_CONJUNCT = "the_intermediate_flow_witness_proves_neither_an_authored_amount_nor_a_constrained_target"

# The two field values that earn the two tokens, read off
# ``effective_functions.claims[].witness.flows[]``:
#
# * ``amount_kind.kind == "param_derived"`` — the intermediate COMPUTES the
#   quantity the destination moves out of its own parameters and state rather
#   than forwarding one the caller supplied, so the destination's own figure is
#   not a figure this caller can ask for. (``param`` is the pass-through case
#   and earns nothing.)
# * ``target_constraint.state == "constrained"`` — the intermediate pins the
#   destination call's counterparty argument under a guard it enforces, so the
#   admissible destination calls are a subset the caller does not choose.
#   ``unconstrained_proven`` is an EARNED negative and ``not_determined`` is the
#   absence; neither earns the token, and they are not the same fact.
_FLOW_AMOUNT_PARAM_DERIVED = "param_derived"
_FLOW_TARGET_CONSTRAINED = "constrained"


@dataclass(frozen=True)
class RouterFlow:
    """One stored value-flow of an intermediate function into a named callee op."""

    sink_id: str | None
    destination_selector: str
    amount_kind: str | None
    target_constraint_state: str | None
    target_constraint_guard: str | None

    def as_json(self) -> dict[str, Any]:
        return {
            "sink_id": self.sink_id,
            "destination_selector": self.destination_selector,
            "amount_kind": self.amount_kind,
            "target_constraint_state": self.target_constraint_state,
            "target_constraint_guard": self.target_constraint_guard,
        }


@dataclass(frozen=True)
class RouteClassification:
    """What the traversed body proves about the destination call it makes."""

    state: str
    reason: str | None
    flows: tuple[RouterFlow, ...]
    amount_authored: bool | None
    target_constrained: bool | None

    def __post_init__(self) -> None:
        if self.state in (ROUTE_AMOUNT_AUTHORED, ROUTE_TARGET_CONSTRAINED):
            if self.reason is not None or not self.flows:
                raise ValueError("a classified route names no reason and rests on at least one flow witness")
        elif self.state == ROUTE_NOT_DETERMINED:
            if self.reason not in (ROUTE_NO_FLOW_WITNESS, ROUTE_NEITHER_CONJUNCT):
                raise ValueError(f"an unclassified route must name a registered reason, got {self.reason!r}")
        else:
            raise ValueError(f"unknown route classification {self.state!r}")

    def as_json(self) -> dict[str, Any]:
        return {
            "source": "effective_functions.claims[].witness.flows[]",
            "state": self.state,
            "reason": self.reason,
            # The two conjuncts, published whatever the state, so a reader sees
            # which one carried the classification and which one did not — and
            # so ``not_determined`` is legible as "both unproven" rather than as
            # "nothing was read". Three-valued: ``null`` where no flow witness
            # answered at all.
            "amount_is_authored_by_the_intermediate": self.amount_authored,
            "destination_target_is_constrained_by_the_intermediate": self.target_constrained,
            "flows": [flow.as_json() for flow in self.flows],
            "reading": (
                "read from the INTERMEDIATE function's own compiled body — the function the "
                "act-as chain's last step enters the destination through — and only from the "
                "flows whose router op names THIS entry's destination selector. Two conjuncts, "
                "each its own field above and each earned separately: amount_kind == "
                "'param_derived' proves the intermediate computes the quantity the destination "
                "moves rather than forwarding one its caller supplied, and target_constraint "
                "== 'constrained' proves it pins the destination call's counterparty under a "
                "guard it enforces. Both are statements about the INTERMEDIATE's body and "
                "neither is read from the destination's own witness, from a function name, "
                "from a selector or from how many hops the chain has. Where no flow of the "
                "intermediate names this destination selector, or where both conjuncts are "
                "unproven, the state is not_determined — which withholds the magnitude just as "
                "a classified route does and claims nothing about why"
            ),
        }


@dataclass
class RouterFlowPlane:
    """Every intermediate function's stored value-flows, keyed by the call it makes.

    Keyed on ``(chain, intermediate address, that function's own selector)`` —
    the pair the act-as step publishes as ``caller`` and ``calling_selector`` —
    so the body consulted is the body the chain actually traverses and not some
    other function of the same contract.
    """

    flows: dict[tuple[str, str, str], tuple[RouterFlow, ...]] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        return {
            "router_flow_functions": len(self.flows),
            "router_flow_witnesses": sum(len(rows) for rows in self.flows.values()),
        }

    def classify(self, caller_key: str, calling_selector: str | None, destination_selector: str) -> RouteClassification:
        """How the traversed body treats this destination call."""
        rows: tuple[RouterFlow, ...] = ()
        if is_entity_key(caller_key) and calling_selector:
            chain, _, address = caller_key.partition("::")
            key = (coalesce_chain(chain), address.lower(), calling_selector.lower())
            rows = tuple(
                flow for flow in self.flows.get(key, ()) if flow.destination_selector == destination_selector.lower()
            )
        if not rows:
            return RouteClassification(ROUTE_NOT_DETERMINED, ROUTE_NO_FLOW_WITNESS, (), None, None)
        # EVERY matching flow, not any: two flows of one function into the same
        # destination selector that disagree about the amount have not proved
        # the amount is authored, and taking the first would publish whichever
        # one the extractor stored first as if it were the answer.
        amount_authored = all(flow.amount_kind == _FLOW_AMOUNT_PARAM_DERIVED for flow in rows)
        target_constrained = all(flow.target_constraint_state == _FLOW_TARGET_CONSTRAINED for flow in rows)
        if amount_authored:
            # Both conjuncts can hold at once and the amount is the one that
            # speaks about the FIGURE, which is what this rule withholds. The
            # other conjunct is published beside it either way, so nothing is
            # hidden by the order.
            return RouteClassification(ROUTE_AMOUNT_AUTHORED, None, rows, True, target_constrained)
        if target_constrained:
            return RouteClassification(ROUTE_TARGET_CONSTRAINED, None, rows, False, True)
        return RouteClassification(ROUTE_NOT_DETERMINED, ROUTE_NEITHER_CONJUNCT, rows, False, False)


def load_router_flow_plane(session: Session, protocol_id: int) -> RouterFlowPlane:
    """Every value-flow an analysed function routes into a named callee op.

    Read from ``effective_functions.claims`` — the same stored witness the
    destination's own magnitude was distilled from, asked a different question:
    not "how much does this function move" but "what does this function decide
    about the call it makes". Protocol-scoped, unlike the deletability plane,
    because an unclassified route withholds: a missing row can only make a route
    less classified, never more, so scoping cannot mint a positive here.
    """
    from db.models import Contract, EffectiveFunction

    plane = RouterFlowPlane()
    rows = (
        session.query(
            EffectiveFunction.selector,
            EffectiveFunction.claims,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id, EffectiveFunction.selector.is_not(None))
        .order_by(EffectiveFunction.id)
        .all()
    )
    flows: dict[tuple[str, str, str], list[RouterFlow]] = defaultdict(list)
    for selector, claims, address, chain in rows:
        key = (coalesce_chain(chain), str(address).lower(), str(selector).lower())
        for claim in claims if isinstance(claims, list) else ():
            witness = (claim or {}).get("witness") if isinstance(claim, dict) else None
            if not isinstance(witness, dict):
                continue
            for flow in witness.get("flows") or ():
                if not isinstance(flow, dict):
                    continue
                amount = flow.get("amount_kind")
                constraint = flow.get("target_constraint")
                for op in flow.get("router_ops") or ():
                    op_selector = (op or {}).get("selector") if isinstance(op, dict) else None
                    if not isinstance(op_selector, str) or not op_selector.startswith("0x"):
                        continue
                    flows[key].append(
                        RouterFlow(
                            sink_id=_first_str(witness.get("sink_ids")),
                            destination_selector=op_selector.lower(),
                            amount_kind=(amount or {}).get("kind") if isinstance(amount, dict) else None,
                            target_constraint_state=(
                                (constraint or {}).get("state") if isinstance(constraint, dict) else None
                            ),
                            target_constraint_guard=(
                                (constraint or {}).get("guard") if isinstance(constraint, dict) else None
                            ),
                        )
                    )
    plane.flows = {key: tuple(rows_here) for key, rows_here in sorted(flows.items())}
    return plane


def _first_str(values: Any) -> str | None:
    return next((v for v in values if isinstance(v, str)), None) if isinstance(values, list) else None


__all__ = [
    "ACT_AS_CALL_SITE_GATE_NOT_DELEGATED",
    "ACT_AS_CALL_SITE_IS_PUBLIC",
    "ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED",
    "ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE",
    "ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE",
    "ACT_AS_NO_CALL_SITE",
    "ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION",
    "ACT_AS_NO_DESTINATION_ACL",
    "ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT",
    "ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS",
    "ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS",
    "ACT_AS_RECEIVER_NOT_READ",
    "ACT_AS_RECEIVER_READ_FAILED",
    "ACT_AS_WITNESSED",
    "ACT_AS_WITNESS_CALLER_STATE_VARIABLE",
    "ACT_AS_WITNESS_DESTINATION_ACL",
    "ASSET_AIRDROP_DELIVERED",
    "ASSET_BELOW_RESOLUTION",
    "ASSET_PRICED",
    "ASSET_PROVEN_ZERO",
    "ASSET_UNPRICED",
    "CEILING_ADMITTED",
    "CEILING_ADMITTING_REASONS",
    "CEILING_AIRDROP_DETERMINED",
    "CEILING_ALIAS_AMBIGUOUS",
    "CEILING_ASSET_LIST_TRUNCATED",
    "CEILING_BELOW_RESOLUTION",
    "CEILING_NO_ROWS",
    "CEILING_PROVEN_EMPTY",
    "CEILING_REASONS",
    "CEILING_UNPRICED",
    "DISPOSITION_REFUSALS",
    "DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED",
    "DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED",
    "DISPOSITION_REFUSED_UNPRICED_POSITIONS",
    "DISPOSITION_REFUSED_UNSCANNED_ACCOUNT",
    "EMPTY_REFUSALS",
    "EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE",
    "EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED",
    "EMPTY_REFUSED_UNSCANNED_ACCOUNT",
    "EMPTY_REFUSED_UNPRICED_POSITIONS",
    "CONFERRAL_CONFERRED",
    "CONFERRAL_OUTCOMES",
    "CONFERRAL_ROLE_NOT_LICENSED",
    "CONFERRAL_SCOPE_NOT_DETERMINED",
    "CONFERRAL_VARIABLE_NOT_REWRITTEN",
    "CONFERRAL_WRITES_NOT_EXTRACTED",
    "CONTROL_RELATIONS",
    "AUTHORITY_CONTROLLER_ID",
    "CALLER_TAINTED_AUTHORITY_UNRESOLVED",
    "CROSSCHECK_AGREES",
    "CROSSCHECK_DISAGREES",
    "CROSSCHECK_NOT_COMPARED",
    "CROSSCHECK_NOT_CORROBORATED",
    "DELETABILITY_ARMS",
    "DELETABILITY_ARM_GATING_AUTHORITY",
    "DELETABILITY_ARM_HOST",
    "DELETABILITY_AUTHORITY_NOT_UNIQUE",
    "DELETABILITY_AUTHORITY_SETTERS",
    "DELETABILITY_AUTHORITY_SOURCES_DISAGREE",
    "DELETABILITY_AUTHORITY_TAINTED",
    "DELETABILITY_AUTHORITY_UNRESOLVED",
    "DELETABILITY_DELETABLE",
    "DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED",
    "DELETABILITY_HOST_SETTERS",
    "DELETABILITY_MEMBERSHIP_NOT_EXACT",
    "DELETABILITY_NOT_DETERMINED",
    "DELETABILITY_NO_PRINCIPAL_ADDRESS",
    "DELETABILITY_NO_SETTER_ROW",
    "DELETABILITY_PROVEN_NOT_DELETABLE",
    "DELETABILITY_REASONS",
    "DELETABILITY_SETTERS",
    "DELETABILITY_STATES",
    "MEMBERSHIP_QUALITY_EXACT",
    "SOLMATE_ROLES_AUTHORITY_STEP",
    "EDGE_WITNESS_ADMIN_COLUMN",
    "EDGE_WITNESS_CONTROL_GRAPH",
    "PREDICATES_COLUMN_HOLDS_NO_ARRAY",
    "PREDICATES_EXTRACTED",
    "PREDICATES_FUNCTION_NOT_LOCATED",
    "REFUSAL_MALFORMED_NODE_ID",
    "REFUSAL_ZERO_ANCHOR",
    "REFUSAL_ZERO_PRINCIPAL",
    "SCOPE_NOT_DETERMINED",
    "SCOPE_ROLES",
    "SCOPE_STATE_VAR",
    "SHEET_AIRDROP_DETERMINED",
    "SHEET_BELOW_RESOLUTION",
    "SHEET_NOT_DETERMINED",
    "SHEET_NO_ROWS",
    "SHEET_PRICED",
    "SHEET_PROVEN_EMPTY",
    "SHEET_UNPRICED",
    "UNCONSUMED_REACH_REASONS",
    "ZERO_ADDRESS",
    "is_zero_key",
    "ActAsPlane",
    "ActAsStep",
    "ActAsVerdict",
    "ConferralPlane",
    "ConferralVerdict",
    "ControlClosure",
    "ControlEdge",
    "DeletabilityPlane",
    "ROUTE_AMOUNT_AUTHORED",
    "ROUTE_CLASSIFICATIONS",
    "ROUTE_NEITHER_CONJUNCT",
    "ROUTE_NOT_DETERMINED",
    "ROUTE_NO_FLOW_WITNESS",
    "ROUTE_TARGET_CONSTRAINED",
    "RouteClassification",
    "RouterFlow",
    "RouterFlowPlane",
    "DeletabilityVerdict",
    "DestinationAcceptance",
    "DestinationPredicates",
    "EdgeScope",
    "GateGrant",
    "LicensedFunction",
    "PrincipalFacts",
    "RefusedEdge",
    "RenouncedAuthority",
    "SetterPrincipal",
    "ValuePlane",
    "authority_deletability",
    "ceiling_for",
    "load_act_as_plane",
    "load_audit_posture",
    "discovery_relation_entities",
    "load_conferral_plane",
    "load_control_closure",
    "load_deletability_plane",
    "load_router_flow_plane",
    "load_ledgers",
    "load_principal_plane",
    "load_proven_eoa_entities",
    "load_role_holder_floors",
    "load_upgrade_provenance",
    "load_value_plane",
    "native_value_state",
    "parse_edge_scope",
    "perimeter_state",
    "plane_row_counts",
    "typed_receipt_is_resolved",
]
