"""Prose tables, published vocabulary, and pure phrase helpers the fold's narration is assembled from."""

from __future__ import annotations

from typing import Any

from services.scoring import planes as P
from services.scoring.schema import NOT_DETERMINED
from utils.scoring_status import (
    MAGNITUDE_STATE_PROVEN_EXACT,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
)

# The composition rule's arms, as a closed vocabulary. Named here so the entry
# can PUBLISH which one it took rather than leave a reader to infer it from
# whether a figure is present — and so an unrecognised route has a token of its
# own to fail to. There is no default arm and no ``else`` that republishes: a
# candidate whose route earns none of the typed outcomes is ``not_determined``
# and its figure is withheld.
ARM_GATE_ONLY = "gate_only"


ARM_WITHHELD = "withheld"


ARM_REPUBLISHED_DIRECT = "republished_direct"


ARM_NOT_DETERMINED = NOT_DETERMINED


COMPOSITION_ARMS = (ARM_GATE_ONLY, ARM_WITHHELD, ARM_REPUBLISHED_DIRECT, ARM_NOT_DETERMINED)


# True on every withheld entry whatever arm withheld it: the candidate reached
# the rule at all, which is what a destination magnitude plus a witnessed reach
# buys, and the figure is gone anyway.
_WITHHELD_OPENING = (
    "the destination carries a flow.out magnitude and this principal is witnessed able to reach "
    "it, and the DOLLARS are still withheld"
)


# One middle per arm, because the three arms withhold for three different
# reasons and a single sentence for all of them is false on at least one. The
# transport-fault arm is the sharp case: :func:`_admit_composed` computes the
# route classification and the deletability verdict BEFORE the fault branch, so
# a faulted entry can publish ``authority_deletability.state == "deletable"`` —
# and a sentence saying "neither answered in favour of the figure" is then false
# beside the block that disproves it. Naming the arm's own reason is the fix;
# softening the sentence until it is true everywhere would trade a false claim
# for an unfalsifiable one.
_WITHHELD_ARM_READINGS = {
    ARM_WITHHELD: (
        ". The figure's own execution could not be READ at all: proving_execution above carries "
        "the typed transport fault that stopped it, so there is no proven call here for "
        "route_comparison to compare this entry's claimed route against, and it reports that "
        "rather than a match. The act_as_chain is published above in full — it is the act-as "
        "plane's witness and is established without any transcript — and whether the proof was "
        "admitted for THIS caller is answered separately under gate_claim, which has no recorded "
        "caller to read. route_classification and authority_deletability were both computed "
        "before this arm was reached and are published above unchanged: a deletability licence "
        "standing beside this refusal does NOT release it, because an execution that could not "
        "be read is not a proven call to republish"
    ),
    ARM_GATE_ONLY: (
        ". What was proven is the call recorded under proving_execution; what this entry claims "
        "is a route through an intermediate, and the two are compared under route_comparison "
        "rather than assumed equal. The gate claim survives that difference — an authorization "
        "check reads msg.sender and msg.sig and no ARGUMENT, so a route the proof did not take "
        "says nothing about it — and the act_as_chain above is published in full. Whether the "
        "proof was admitted for THIS caller is a separate question and is answered separately, "
        "under gate_claim: a different caller is not covered by that argument, because "
        "msg.sender is what the check reads. The MAGNITUDE does not survive it: "
        "route_classification witnesses the traversed body acting on what the destination call "
        "carries, under the typed finding withheld_reason names, and authority_deletability did "
        "not prove this principal could have issued the proven call itself. The refusal is the "
        "route's; what the join answered — a proven negative or an undetermined one — is "
        "published beside it either way and is not collapsed into it"
    ),
    ARM_NOT_DETERMINED: (
        ". What was proven is the call recorded under proving_execution; what this entry claims "
        "is a route through an intermediate, and the two are compared under route_comparison "
        "rather than assumed equal. The gate claim survives that difference — an authorization "
        "check reads msg.sender and msg.sig and no ARGUMENT, so a route the proof did not take "
        "says nothing about it — and the act_as_chain above is published in full. Whether the "
        "proof was admitted for THIS caller is a separate question and is answered separately, "
        "under gate_claim: a different caller is not covered by that argument, because "
        "msg.sender is what the check reads. The MAGNITUDE is refused by neither question and "
        "carried by neither: route_classification earned no typed finding about the traversed "
        "body and stands at not_determined, and authority_deletability did not prove this "
        "principal could have issued the proven call itself. There is no fourth arm that "
        "publishes on an unanswered route"
    ),
}


# A field-description: it says what a consumer may not conclude and asserts
# nothing about the entry carrying it.
_WITHHELD_CLOSING = (
    ". This is a REFUSAL and not a zero: nothing here says the principal moves nothing, only "
    "that what it moves is not determined by this evidence"
)


# How much a magnitude witness state CLAIMS, lowest first. Read only to settle a
# tie between two candidates at the same figure: the state published is the
# least-claiming of them, because an exactness that one tied candidate does not
# support would be exactness minted by whichever candidate the iteration reached
# first.
# ``proven_upper_bound`` ranks WITH ``proven_exact`` rather than below it, and
# that is a deliberate hold rather than a judgement about how much it claims. The
# rank exists only to settle a tie between two candidates at the same figure, so
# moving it moves which candidate is published — a number-shaped change that
# belongs with the composition ruling, not with the relabel. Ranking it apart
# from the map (``_WITNESS_STATE_UNRANKED``) would be worse than either: that
# slot is reserved for states this fold cannot rank, and a KNOWN state parked
# there launders a known fact into the unknown bucket.
_WITNESS_STATE_CLAIM = {
    MAGNITUDE_STATE_PROVEN_FLOOR: 1,
    MAGNITUDE_STATE_PROVEN_EXACT: 2,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND: 2,
}


# A state this map cannot rank is ranked so that it can never WIN a tie. Sorting
# it with the weakest would be the fail-open: "we do not know what this claims"
# would beat a state proven to claim little, and an unrankable string would be
# published in preference to a witness. Losing every tie means it is published
# only where it is the sole candidate — where it is the only thing there is to
# publish and no comparison was made.
_WITNESS_STATE_UNRANKED = len(_WITNESS_STATE_CLAIM) + 1


# Where the published dollars came from, one sentence per value of
# ``bounded_by``. A single sentence for both is a claim about the row and it is
# FALSE on one of them: the entry's figure is the MIN of the destination
# function's own flow.out witness and the destination entity's balance sheet, so
# on every entry the sheet won, "not the destination's balance sheet" names as
# excluded the very thing that capped the figure — and ``destination_sheet_usd``
# beside it equals ``published_usd``, so the document contradicts itself in two
# adjacent keys. Neither sentence asserts which ceiling is the smaller in
# general; each says which one bound THIS figure and points at the other.
_BOUNDED_BY_WITNESS = "flow.out witness"


_BOUNDED_BY_SHEET = "destination sheet"


_COMPOSED_SOURCE_READINGS = {
    _BOUNDED_BY_WITNESS: (
        "the dollars are the DESTINATION function's own flow.out witness, and not this row's "
        "balance sheet. The destination entity's own sheet did not bind them here — bounded_by "
        "beside destination_sheet_usd and sheet_not_determined says which of the two ceilings "
        "did and what the other one was"
    ),
    _BOUNDED_BY_SHEET: (
        "the dollars are the DESTINATION entity's own BALANCE SHEET, and not this row's. The "
        "sheet is BELOW that function's flow.out witness here and is what capped the figure — "
        "bounded_by beside destination_sheet_usd and flow_out_witness.usd says which of the two "
        "ceilings did and what the other one was"
    ),
}


# The publication rounding this document applies to dollar figures. Cents are
# the unit a reader reads a balance in, and that is all this rounding is for —
# so, as in the value plane's own presentation rounding (``planes._round_presented``,
# same rule at six decimals), it is not allowed to change what a figure PROVES.
# A proven bound of $0.00156 published as $0.00 stops being a number and starts
# being "nothing at stake", which is a different claim about the entity than the
# one that was measured — and on a ceiling it is the claim that reads as safety.
# Below the rounding's own resolution the unrounded figure is therefore what
# stands.
_PUBLISHED_DECIMALS = 2


def _round_published(value: float) -> float:
    """Round to cents for publication, never onto zero."""
    rounded = round(value, _PUBLISHED_DECIMALS)
    return rounded if rounded != 0.0 or value == 0.0 else value


# The token a figure carries where a sheet EXISTS, is determined, and still may
# not bound a witness. One token, used at both trim sites and published on both
# surfaces, so the two cannot drift into describing the same fact differently.
SHEET_BOUND_REFUSED_BY_DISPOSITION = "sheet_determined_by_disposition_does_not_bound"


# And what that token means, in the one sentence both surfaces publish. It says
# what the sheet DOES determine as well as what it does not, because the
# alternative reading — "the sheet is not determined" — is false here and is the
# word a reader would otherwise act on.
_DISPOSED_SHEET_DOES_NOT_BOUND = (
    "a witnessed magnitude charged against an entity whose sheet IS determined, at $0, by "
    "delivery-shape disposition: every reading on it arrived only in transactions carrying at "
    "least the published fan-out threshold of same-token transfer LOGS. That determination is "
    "over the "
    "readings observed, on an asset list that is NOT proven whole, and it is a claim about how "
    "the holdings arrived and never about what they are worth — two of the tokens measured into "
    "that state on this corpus are real ones. So the $0 bounds what the entity HOLDS and not "
    "what is there to MOVE, the sheet does not trim this figure, and the witness stands alone"
)


# The other thing a trim owes, and the one the entry used to leave unsaid: the
# sheet trimmed the figure and is NOT proven to cover everything the destination
# holds. A priced sheet that does not cover its node is a floor over what was
# priced, so ``min(witness, sheet)`` against it publishes a number SMALLER than
# the witness on a bound nothing established — an under-report of what the call
# reaches, dressed as a tighter ceiling. The figure still stands (it is the
# honest min of what is known) and the entry stops calling it an at-most. The
# sentence POINTS at the fields the direction is derived from rather than
# restating the shortfall, which is derived once and published there.
_TRIMMED_TO_AN_UNPROVEN_CEILING = (
    "The sheet that capped this figure is NOT proven to cover everything observed at that "
    "destination, so the cap is not a proven at-most and the published figure may sit below "
    "what the call reaches: destination_sheet_bound_direction says which of the two it is, and "
    "destination_sheet_bound_direction_basis enumerates, off the destination's own coverage, "
    "the conjunct(s) of that proof this sheet fails"
)


# --- the two ceilings, kept apart ------------------------------------------
# A row's figure can be an upper bound for two unrelated reasons, and the
# document may not spell them the same. The COMPOSED extraction ceiling is a
# destination function's own flow.out witness, reused across a gate the
# principal is witnessed able to make the seized node use; the SHEET ceiling is
# the controlled node's own priced holdings, admitted because replacing that
# node's code leaves nothing of that node's between the principal and what it
# holds. They differ in provenance, in what could tighten them, and — the reason
# the distinction is load-bearing rather than cosmetic — in whether they spend
# the exposure budget: an extraction ceiling is a witnessed move and charges it,
# a sheet ceiling is an at-most on a move nobody witnessed and does not.
CEILING_KIND_COMPOSED = "composed_extraction"


CEILING_KIND_SHEET = "sheet"


# The refusal token a code-control call writes into a row's ``why`` vocabulary
# when the capability qualified for a sheet ceiling and the SHEET did not. One
# constant because it is written in one place and read back in another — the
# document-level rollup counts these refusals off the published rows — and two
# copies of the spelling would drift apart silently, publishing a census of
# zero refusals over a corpus full of them.
SHEET_CEILING_REFUSED_PREFIX = "code_control_sheet_ceiling_refused("


# The reasons a sheet ceiling was REFUSED: the closed ceiling vocabulary minus
# the two that admit. DERIVED from the plane's own tuples rather than listed
# here, because a fifth refusal added there and not here would be published by
# the fold and counted by nothing — the census would report it as absent, which
# is the one thing a census of refusals must never do.
CEILING_REFUSAL_REASONS = tuple(r for r in P.CEILING_REASONS if r not in P.CEILING_ADMITTING_REASONS)


# Where a sheet ceiling's dollars came from, keyed on the admitting reason AND
# on whether the sheet covers everything the entity holds. Its own registry and
# not a third key in ``_COMPOSED_SOURCE_READINGS`` above: that map is keyed on
# ``_ComposedMagnitude.bounded_by`` and a sheet ceiling constructs no
# ``_ComposedMagnitude``, so an entry there is one nothing can carry.
#
# The second axis is the one that was got wrong first. The three
# ADMITS are different proofs — a priced sheet bounds at a number that was
# observed, a proven-empty one bounds at zero because every quantity on it was
# witnessed zero — and a single sentence would have to call one of them the
# other. The COVERAGE axis is not a shade of either: ``SHEET_PRICED`` means the
# total is a FLOOR over what was priced (``planes.ValuePlane.sheet_state``), so
# on an entity holding assets nobody priced the figure is not an at-most on the
# move at all. It is an at-most on the PRICED PORTION, and saying otherwise
# claims a bound over holdings this fold never observed. Every ADMITTED entry on
# the reference corpus takes the partial arm — those entities hold assets nobody
# priced — while the PROVEN-EMPTY ones take the full-coverage arm, which is the
# only shape in which coverage is trivially whole: a sheet whose every quantity
# is witnessed zero has nothing left over to be uncovered.
#
# The AIRDROP-DETERMINED admit carries BOTH arms, and its partial one is the
# COMMON case rather than an unreachable combination. Coverage there is earned,
# not implied: a disposition says an asset's contribution is nil and says
# nothing about whether the LIST is whole, so a disposed sheet clears
# ``_asset_coverage["complete"]`` only where the list is separately proven — and
# the below-resolution readings that sit beside the disposed ones on this corpus
# are not disposed and not priced, which is exactly the partial arm.
_CEILING_SOURCE_READINGS = {
    (P.CEILING_ADMITTED, True): (
        "the dollars are THIS entity's own priced holdings, and every asset observed at it was "
        "priced — so the figure is an AT-MOST on what replacing this node's code can move from "
        "it. The principal can replace that code, so none of the code that would have stood "
        "between them and these holdings is still standing; what is not witnessed is the other "
        "direction, that replaced code reaches every asset in the total, and an accounting entry "
        "rather than a held balance is inside the sheet and outside the move"
    ),
    (P.CEILING_ADMITTED, False): (
        "the dollars are THIS entity's own priced holdings and they DO NOT bound the move: the "
        "sheet does not cover everything observed here, so the total is a floor over what was "
        "priced and the entity holds more than it. What the figure bounds from above is the "
        "COVERED PORTION — replacing this node's code can move no more of those assets than the "
        "sum of them — and what the part it does not cover adds is not_determined here, which is "
        "why bound_direction is not a ceiling on this entry"
    ),
    (P.CEILING_PROVEN_EMPTY, True): (
        "the ceiling is a PROVEN ZERO and not a missing number: every asset observed at this "
        "entity carries a quantity witnessed zero, so replacing its code can move nothing from "
        "it. This is an earned negative — a sheet nobody priced publishes not_determined instead "
        "— and it bands at the floor for the same reason any small figure does"
    ),
    (P.CEILING_AIRDROP_DETERMINED, True): (
        "the ceiling is a DETERMINED ZERO of a different kind: every asset observed at this "
        "entity either carries a quantity witnessed zero or arrived ONLY in transactions "
        "carrying at least the published fan-out threshold of same-token transfer LOGS, so this "
        "sheet's determined content is nil and replacing the node's code moves nothing the "
        "document can price. The claim is DELIVERY SHAPE and never worth — real tokens have "
        "been measured arriving this way — and the asset list it covers is the one the index "
        "returned, refused only where that list was read AT the page cap"
    ),
    (P.CEILING_AIRDROP_DETERMINED, False): (
        "the ceiling is a determined zero of what this sheet PRICES: nothing observed at this "
        "entity carries a determined dollar reading above zero, and every reading that is not a "
        "witnessed zero arrived only in transactions carrying at least the published fan-out "
        "threshold of same-token transfer LOGS. It is NOT a figure over the disposed assets "
        "themselves — the claim admitting it is DELIVERY SHAPE, which says how they arrived and "
        "never what they are worth — and the coverage is not whole either, so what the part it "
        "does not cover adds is not_determined"
    ),
    # ``(PROVEN_EMPTY, False)`` is ABSENT, and its absence is a rule rather than
    # an omission. It described a proven-empty priced sheet at a node the
    # restaking plane also carries unpriced positions for; the sheet plane now
    # REFUSES the empty state there outright (``ValuePlane.proven_empty_refusal``
    # — a $0 beside those positions both contradicts a plane already in this
    # document and bounds a magnitude at zero over holdings nobody priced), so
    # such an entity publishes ``unpriced`` and earns no ceiling at all. A
    # sentence nothing can publish is removed on the same rule the uncalibrated
    # register is kept by, and the lookup below stays strict so a fifth
    # combination raises instead of borrowing one of these.
}


# True of every sheet ceiling whatever admitted it and whatever its coverage, so
# it is constant: it states what the entry does NOT claim, and asserts nothing
# about the row's own data.
_CEILING_CLOSING = (
    ". Whatever it bounds, it bounds from ABOVE and is never an amount — nothing here says the "
    "principal moves this — and it is scoped to THIS node: what the node in turn governs keeps "
    "its own rules, because that node's code is still standing. It charges no exposure for the "
    "same reason: an upper bound on an unwitnessed move is not expected loss, and spending an "
    "entity's exposure budget on one would displace a row that measured a real extraction there"
)


# Why the per-entity figure is or is not an at-most on the move, derived from
# that entity's OWN asset coverage. The row header asks the same question over
# the whole row (:func:`_bound_direction`) and refuses on the same conjunct; two
# surfaces answering it differently is the contradiction these strings exist to
# stop.
_SHEET_CEILING_DIRECTION_BASIS = {
    True: (
        "every asset observed at this entity carries a determined reading — a price, or a "
        "QUANTITY witnessed zero, which is worth nothing at any price — and no position carries "
        "an absent USD column, so the total covers the holdings and bounds the move from above"
    ),
    False: (
        "the priced sheet does not cover everything observed at this entity, so the total is a "
        "floor over what was priced and bounds the holdings in neither direction. What it does "
        "not cover, on this entity: "
    ),
}


# The conjuncts of ``_asset_coverage["complete"]``, each with the field the row
# publishes it under, so a refused direction names the cause that actually
# fired. Written as a table rather than as one sentence listing all three
# because two of them read EMPTY on live carriers — the $575M stETH proxy
# refuses on the third alone — and a sentence naming causes that did not fire
# is a sentence a reader cannot check against the row beside it.
#
# ONE table, and :func:`_coverage_shortfall` is its one reader, because the row
# publishes the same shortfall twice: once as the reason its direction is not a
# ceiling and once inside the reading that explains its figure. Two hand-written
# sentences over one fact is how they came to disagree — the direction basis was
# corrected and the reading's stem was left asserting the same false premise.
# Each entry is (published field, the value that FAILS the conjunct, the clause).
_SHEET_CEILING_INCOMPLETE_CAUSES: tuple[tuple[str, bool, str], ...] = (
    (
        "assets_not_priced",
        True,
        "assets observed here that no price lookup answered for (assets_not_priced)",
    ),
    (
        "unpriced_positions",
        True,
        "positions the restaking plane carries at this node with no USD column at all (unpriced_positions)",
    ),
    (
        "asset_list_proven_whole",
        False,
        "the asset LIST itself is not proven whole (asset_list_proven_whole, "
        "asset_set_completeness): the rows are what an index returned, and a disposition covers "
        "the readings observed and never the holdings, so nothing here establishes that these "
        "assets are all the entity has",
    ),
)


def _coverage_shortfall(coverage: dict[str, Any]) -> str:
    """Which conjuncts of ``complete`` this entity FAILED, off its own fields.

    The single derivation behind both surfaces that publish the shortfall. Every
    caller is on the ``complete is False`` arm, where at least one conjunct
    failed by construction, so the result is never empty.
    """
    return "; ".join(
        clause for field, fails_when, clause in _SHEET_CEILING_INCOMPLETE_CAUSES if bool(coverage[field]) is fails_when
    )


# The reading's own lead-in to the same derived clause the direction basis ends
# with. Only the framing differs — one sentence answers "why is this not a
# ceiling", the other "what does this figure leave out" — and the fact itself is
# derived once.
_CEILING_COVERAGE_SHORTFALL_PREFIX = ". What it does not cover, on this entity: "


def _sheet_ceiling_direction_basis(coverage: dict[str, Any], complete: bool) -> str:
    """Why this entity's own figure is or is not an at-most on the move.

    The refusing arm ENUMERATES the conjuncts that failed, off the row's own
    published fields, because the sentence has to explain its own carrier: two
    entities on the reference corpus refuse with ``assets_not_priced`` empty and
    ``unpriced_positions`` zero, and a constant naming only those two told a
    reader to look at fields that say nothing.
    """
    if complete:
        return _SHEET_CEILING_DIRECTION_BASIS[True]
    return _SHEET_CEILING_DIRECTION_BASIS[False] + _coverage_shortfall(coverage)


# One name per component of :func:`_composed_order`'s key, positionally. The
# published ``chosen_by`` reads the component that ACTUALLY separated this
# candidate from each one it was chosen over, so the names have to line up with
# the tuple; a length mismatch is a fixture-free way for the string to name the
# wrong rule, and it is asserted rather than trusted.
_ORDER_COMPONENT_NAMES = (
    "the published figure, highest",
    "the weakest witness state",
    "the lowest selector",
    "the lowest destination function",
    "the chain's calling selectors, in order",
    "the chain's own published identity",
)


# Which direction the row's own ``value_at_stake_usd`` bounds the principal in.
# A DIFFERENT axis from ``VALUE_BOUND_*`` on a signal (whether the entity SET is
# the whole reach or a floor over it) and from ``flow_out_witness.state`` (which
# grades the pricing of one call), and the three are not interchangeable.
#
# Three states, and only two of them are claims. ``not_determined`` is the third
# and it is the fall-through, because a direction is a positive fact about a SUM
# and this fold does not grade every contribution for direction: a total with no
# coverage gap and no composed ceiling in it is still summed out of figures that
# may each be a priced floor, so "neither signal fired" is not a proof that the
# figure is two-sided. It publishes the bare band, exactly as before this field
# existed, and says in the basis what it did not establish — but only where a
# ceiling is what defeated the claim: the no-ceiling fall-through leaves the
# row's own basis untouched, because that basis was never a bound claim to
# correct and rewriting it would move prose on rows nothing moved on.
BOUND_DIRECTION_FLOOR = "floor"


BOUND_DIRECTION_CEILING = "ceiling"


BOUND_DIRECTION_NOT_DETERMINED = NOT_DETERMINED


# The band label's qualifier, written only for the two proven directions. A
# qualifier that cannot be earned is not written at all.
_BAND_PREFIX = {BOUND_DIRECTION_FLOOR: ">= ", BOUND_DIRECTION_CEILING: "<= "}


# The two directions a per-entity SHEET figure can earn, the same pair
# ``_SHEET_CEILING_DIRECTION_BASIS`` is keyed on: an entity whose priced sheet
# covers everything observed at it bounds the move from above, and one holding
# assets nobody priced bounds it in neither direction. ``floor`` is absent
# deliberately — a sheet figure is never one — so the rollup's census reports
# the two that can be earned and does not invent a bucket for the one that
# cannot.
SHEET_CEILING_BOUND_DIRECTIONS = (BOUND_DIRECTION_CEILING, BOUND_DIRECTION_NOT_DETERMINED)
