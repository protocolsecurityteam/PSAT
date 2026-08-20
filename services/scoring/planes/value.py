"""The value plane: what each entity's balance sheet proves, in dollars."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import tuple_
from sqlalchemy.orm import Session

from services.scoring.planes._shared import (
    NATIVE_ASSET,
    _chain_name,
    _float,
    _lower,
    _round_presented,
    typed_receipt_is_resolved,
)
from services.scoring.schema import coalesce_chain, entity_key
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    SWEEP_STATUS_COMPLETED,
)

if TYPE_CHECKING:
    from services.scoring.distill import ProtocolUniverse


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
