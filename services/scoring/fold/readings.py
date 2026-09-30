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

# The composition rule's arms, published so the entry says which one it took. No default arm: an unmatched route is
# ``not_determined`` and withheld.
ARM_GATE_ONLY = "gate_only"


ARM_WITHHELD = "withheld"


ARM_REPUBLISHED_DIRECT = "republished_direct"


ARM_NOT_DETERMINED = NOT_DETERMINED


COMPOSITION_ARMS = (ARM_GATE_ONLY, ARM_WITHHELD, ARM_REPUBLISHED_DIRECT, ARM_NOT_DETERMINED)


_WITHHELD_OPENING = (
    "the destination carries a flow.out magnitude and this principal is witnessed able to reach "
    "it, and the DOLLARS are still withheld"
)


# One middle sentence per arm, since they withhold for different reasons. A faulted entry can still publish
# ``deletable`` (the join runs before the fault branch), so a shared sentence would be false there.
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


_WITHHELD_CLOSING = (
    ". This is a REFUSAL and not a zero: nothing here says the principal moves nothing, only "
    "that what it moves is not determined by this evidence"
)


# How much each witness state claims, lowest first, used only to break ties: the published state is the least-claiming.
# ``proven_upper_bound`` deliberately ranks with ``proven_exact``; moving it would change which candidate publishes,
# which belongs with the composition ruling.
_WITNESS_STATE_CLAIM = {
    MAGNITUDE_STATE_PROVEN_FLOOR: 1,
    MAGNITUDE_STATE_PROVEN_EXACT: 2,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND: 2,
}


# Unrankable states lose every tie (fail closed), so they publish only when they're the sole candidate.
_WITNESS_STATE_UNRANKED = len(_WITNESS_STATE_CLAIM) + 1


# One sentence per ``bounded_by`` value; a shared sentence would contradict ``destination_sheet_usd`` whenever the sheet
# was the binding ceiling.
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


# Cents for readability, but rounding must not change what a figure proves: below a cent the unrounded figure stands, so
# a tiny ceiling never reads as $0.
_PUBLISHED_DECIMALS = 2


def _round_published(value: float) -> float:
    rounded = round(value, _PUBLISHED_DECIMALS)
    return rounded if rounded != 0.0 or value == 0.0 else value


# Shared by both trim sites and both surfaces so they can't drift.
SHEET_BOUND_REFUSED_BY_DISPOSITION = "sheet_determined_by_disposition_does_not_bound"


# Says what the sheet does determine, since "not determined" would be false here.
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


# An unproven-complete sheet is a floor over what was priced, so trimming onto it under-reports. The figure stands; the
# sentence points at the fields the direction is derived from.
_TRIMMED_TO_AN_UNPROVEN_CEILING = (
    "The sheet that capped this figure is NOT proven to cover everything observed at that "
    "destination, so the cap is not a proven at-most and the published figure may sit below "
    "what the call reaches: destination_sheet_bound_direction says which of the two it is, and "
    "destination_sheet_bound_direction_basis enumerates, off the destination's own coverage, "
    "the conjunct(s) of that proof this sheet fails"
)


# Two ceiling kinds, kept apart: the composed extraction ceiling (a destination's witnessed flow.out, reused through a
# gate) charges the exposure budget; the sheet ceiling (the controlled node's own holdings under code control) is an
# at-most on an unwitnessed move and doesn't.
CEILING_KIND_COMPOSED = "composed_extraction"


CEILING_KIND_SHEET = "sheet"


# Written here and counted back from published rows by the rollup; one constant so the spelling can't drift.
SHEET_CEILING_REFUSED_PREFIX = "code_control_sheet_ceiling_refused("


# Derived from the plane's tuples so a new refusal can't be published but left uncounted.
CEILING_REFUSAL_REASONS = tuple(r for r in P.CEILING_REASONS if r not in P.CEILING_ADMITTING_REASONS)


# Where a sheet ceiling's dollars came from, keyed on (admitting reason, full coverage). Separate from
# ``_COMPOSED_SOURCE_READINGS`` because sheet ceilings build no ``_ComposedMagnitude``.
#
# ``SHEET_PRICED`` is a floor over what was priced, so with partial coverage it bounds only the priced portion.
# Proven-empty sheets are trivially complete. Airdrop-determined sheets can take either arm: disposition doesn't prove
# the asset list whole.
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
    # ``(PROVEN_EMPTY, False)`` is intentionally absent: ``ValuePlane.proven_empty_refusal`` makes that case
    # ``unpriced``. The lookup stays strict so an unexpected combination raises.
}


# Constant: states what the entry does not claim.
_CEILING_CLOSING = (
    ". Whatever it bounds, it bounds from ABOVE and is never an amount — nothing here says the "
    "principal moves this — and it is scoped to THIS node: what the node in turn governs keeps "
    "its own rules, because that node's code is still standing. It charges no exposure for the "
    "same reason: an upper bound on an unwitnessed move is not expected loss, and spending an "
    "entity's exposure budget on one would displace a row that measured a real extraction there"
)


# Per-entity, from the entity's own coverage; must agree with the row-level :func:`_bound_direction`.
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


# The conjuncts of ``_asset_coverage["complete"]`` as (published field, failing value, clause), so a refusal names only
# the causes that fired. :func:`_coverage_shortfall` is the one reader, feeding both the direction basis and the
# reading.
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
    """The ``complete`` conjuncts this entity failed.

    Callers are on the ``complete is False`` arm, so it's never empty.
    """
    return "; ".join(
        clause for field, fails_when, clause in _SHEET_CEILING_INCOMPLETE_CAUSES if bool(coverage[field]) is fails_when
    )


_CEILING_COVERAGE_SHORTFALL_PREFIX = ". What it does not cover, on this entity: "


def _sheet_ceiling_direction_basis(coverage: dict[str, Any], complete: bool) -> str:
    """Why this entity's figure is or isn't an at-most on the move; the refusing arm lists only the conjuncts that
    actually failed.
    """
    if complete:
        return _SHEET_CEILING_DIRECTION_BASIS[True]
    return _SHEET_CEILING_DIRECTION_BASIS[False] + _coverage_shortfall(coverage)


# Positional names for :func:`_composed_order`'s key components; length is asserted.
_ORDER_COMPONENT_NAMES = (
    "the published figure, highest",
    "the weakest witness state",
    "the lowest selector",
    "the lowest destination function",
    "the chain's calling selectors, in order",
    "the chain's own published identity",
)


# The direction the row's ``value_at_stake_usd`` bounds the principal in. Distinct from ``VALUE_BOUND_*`` and
# ``flow_out_witness.state``.
#
# ``not_determined`` is the fall-through: summed figures may each be floors, so the absence of a ceiling doesn't prove a
# two-sided figure. Only a ceiling-defeated claim rewrites the basis.
BOUND_DIRECTION_FLOOR = "floor"


BOUND_DIRECTION_CEILING = "ceiling"


BOUND_DIRECTION_NOT_DETERMINED = NOT_DETERMINED


# Only proven directions get a qualifier.
_BAND_PREFIX = {BOUND_DIRECTION_FLOOR: ">= ", BOUND_DIRECTION_CEILING: "<= "}


# ``floor`` is absent on purpose: a sheet figure is never one, so the rollup has no bucket for it.
SHEET_CEILING_BOUND_DIRECTIONS = (BOUND_DIRECTION_CEILING, BOUND_DIRECTION_NOT_DETERMINED)
