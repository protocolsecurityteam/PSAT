"""Sheet ceilings: asset coverage, bound direction, disposition, unresolved stake, and ceiling narration."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from services.scoring import planes as P
from services.scoring.fold.readings import (
    _CEILING_CLOSING,
    _CEILING_COVERAGE_SHORTFALL_PREFIX,
    _CEILING_SOURCE_READINGS,
    BOUND_DIRECTION_CEILING,
    BOUND_DIRECTION_FLOOR,
    BOUND_DIRECTION_NOT_DETERMINED,
    CEILING_KIND_COMPOSED,
    CEILING_KIND_SHEET,
    CEILING_REFUSAL_REASONS,
    SHEET_CEILING_BOUND_DIRECTIONS,
    SHEET_CEILING_REFUSED_PREFIX,
    _coverage_shortfall,
    _round_published,
    _sheet_ceiling_direction_basis,
)
from services.scoring.schema import NOT_DETERMINED
from utils import execution_record as EX
from utils.execution_record import PROVING_EXECUTION_KEY

if TYPE_CHECKING:
    from services.scoring.fold.composition import _ComposedMagnitude


def _order_tie_reading(shared_entities: list[str], position_in_tie: int) -> str:
    """What the tie-break string decided on THIS row, read off what the row holds.

    The λ half is true of every carrier — a tied row's index is that string's
    doing whatever else is true — so it is constant. Two things after it are
    not, and both are published in the same block a line away.

    ``shared_entities``: the order splits a budget only where an entity is
    actually held in common, and a row that shares none has no split. Publishing
    the split sentence there asserts an apportionment that provably did not
    happen, which is the same defect one level down from the figures.

    ``position_in_tie``: which SIDE of the split this row is on. The first row in
    a tie group has no tied row ahead of it and is charged FIRST; saying it "is
    charged the remainder" is false of exactly the carrier the field beside it
    identifies. The two directions are the same fact told from two ends, and
    naming the wrong end inverts who the order cost.
    """
    lam = "this row's λ position is decided by that string, not by evidence"
    if not shared_entities:
        return (
            lam + "; and it holds NO entity in common with the tied rows — shared_entities is "
            "an asked-and-empty, not an unasked question — so no exposure budget was split by the "
            "order here and none of this row's dollars is an order-determined apportionment"
        )
    shared_clause = (
        f"{lam}, and so is its share of the {len(shared_entities)} entity(ies) it holds in "
        "common with the tied rows (named under shared_entities): "
    )
    if position_in_tie == 0:
        charged = (
            "this row is FIRST in the tie (position_in_tie 0), so it consumes that shared exposure "
            "budget before any row tied with it and the rows behind it are charged the remainder"
        )
    else:
        charged = (
            f"the {position_in_tie} row(s) ahead of this one in the tie (position_in_tie "
            f"{position_in_tie}) consume that shared exposure budget first and this row is charged "
            "what is left of it"
        )
    return (
        shared_clause + charged + ", so the split among them is order-determined and is not a "
        "measurement of who reaches what"
    )


def _disclose_order_ties(findings: list[dict[str, Any]]) -> None:
    """Where rows tie on the sort key, say so: the order decides, and it is a string.

    Two rows with equal points and capability are separated by the unit address
    alone, and that order is spent twice — on the λ position, which discounts by
    index, and on the exposure budget, which the earlier row consumes first and
    the later row gets the remainder of. Splitting the shared entity correctly
    needs evidence this fold does not have, so the order stays fixed (inv. 8) and
    what it decided is published instead of read as an attribution.

    Findings only. A subsumed row has no λ position and spends no exposure
    budget — the order decides nothing for it — so its ``exposure_order_tie``
    stays ``None``, which here is the proven "nothing was decided by order",
    not an unasked question.
    """
    groups: dict[tuple[Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        groups[(finding["raw_points"], finding["capability"])].append(finding)
    for group in groups.values():
        if len(group) < 2:
            continue
        units = [f["principal_unit"] for f in group]
        for position, finding in enumerate(group):
            others = {key for other in group if other is not finding for key in other["value_by_entity"]}
            shared = sorted(set(finding["value_by_entity"]) & others)
            finding["exposure_order_tie"] = {
                "tied_with": [unit for unit in units if unit != finding["principal_unit"]],
                "shared_entities": shared,
                "position_in_tie": position,
                "basis": "equal raw_points and capability; the remaining order is the principal_unit string",
                "reading": _order_tie_reading(shared, position),
            }


# Every published dollar is rounded to the cent, so a share below half a cent
# reaches a consumer as $0.00 whatever it really was.
_PUBLISHED_CENT = 0.005


_UNPRICED_ASSET_STATES = frozenset({P.ASSET_UNPRICED, P.ASSET_BELOW_RESOLUTION})


def _asset_coverage(value_plane: P.ValuePlane, canonical: str) -> dict[str, Any]:
    """What one entity's priced sheet does and does not cover, per asset.

    The per-ASSET maps are read and the sheet STATE is not, for the reason
    :func:`_partially_priced_entities` reads them: the state collapses a mixed
    entity to whichever fact ranks highest, so an entity with one priced asset
    and a hundred unanswered ones reads as ``priced`` there and the shortfall
    disappears. ``below_resolution`` counts as not priced — an asset whose price
    landed on the storage floor is a holding of at most half a cent that the
    total does not carry, which is the same shortfall as one nobody priced — and
    the restaking plane is the second source, with no USD column at all.

    ``complete`` is the conjunct the ceiling claim turns on and it is an EARNED
    positive: an entity with no observed assets at all does not clear it by
    having nothing to fail on. Nothing here reads a block height or an observed
    account: the plane reduces observations to the latest per (entity, asset) at
    load, so those are gone by the time this runs and are not claimed.

    A complete inventory requires positive coverage evidence, resolved prices
    and positions, and fresh balance and quote observations. A short provider
    page alone does not establish coverage. Partial observations remain useful
    for the separately scoped code-control valuation.
    """
    values = value_plane.per_asset.get(canonical) or {}
    states = value_plane.per_asset_state.get(canonical) or {}
    positions = value_plane.unpriced_positions.get(canonical) or []
    names = sorted(set(values) | set(states))
    # A key present in ``per_asset`` with no state entry is read as determined,
    # which is what that map means (see ``ValuePlane``'s docstring).
    not_priced = sorted(
        name for name in names if states.get(name) in (*_UNPRICED_ASSET_STATES, P.ASSET_AIRDROP_DELIVERED)
    )
    disposed: list[str] = []  # Retired category; legacy readings are unpriced.
    list_is_whole = not value_plane.asset_set_is_truncated(canonical) and value_plane.asset_set_is_proven_complete(
        canonical
    )
    return {
        "per_asset": [
            # The evidence a sheet-ceiling record's figure is checked against, so
            # it carries the same rounding the figure does: per-asset rows that
            # all read $0.00 under a published $0.00156 would contradict the sum
            # they are published to support.
            {
                "asset": name,
                "usd": (_round_published(values[name]) if name in values else None),
                "state": states.get(name),
            }
            for name in names
        ],
        "assets_observed": len(names),
        # Assets carrying a determined DOLLAR reading — a price, or a quantity
        # witnessed zero. The three populations partition ``assets_observed``:
        # a disposed asset carries no dollar figure at all (its ``usd`` is null
        # in ``per_asset``), so it is counted under ``assets_disposed`` and
        # under neither of the other two. Folding it in here published a sheet
        # whose every asset arrived by mass distribution as fully priced.
        "assets_priced": len(names) - len(not_priced) - len(disposed),
        "assets_not_priced": not_priced,
        "assets_disposed": disposed,
        # The LIST conjunct of ``complete``, published rather than left inside
        # it: a reader who sees the direction refused with both asset lists
        # empty has no other field to read the cause off, and an unpublished
        # conjunct is one the sentence beside it cannot name.
        "asset_list_proven_whole": list_is_whole,
        "unpriced_positions": len(positions),
        "typed_receipts_unresolved": len(value_plane.unresolved_typed_receipts(canonical)),
        "observation_fresh": canonical in value_plane.fresh_entities,
        "complete": bool(names)
        and not not_priced
        and not disposed
        and not positions
        and not value_plane.unresolved_typed_receipts(canonical)
        and list_is_whole
        and canonical in value_plane.fresh_entities,
    }


def _reconcile_sheet_ceilings(
    ceiling_kinds: dict[str, str], per_entity: dict[str, float], value_plane: P.ValuePlane
) -> list[dict[str, Any]]:
    """Drop any sheet ceiling whose standing figure is not that node's sheet.

    S6's invariant is PER KEY: a sheet ceiling is capped by its own node's sheet
    by construction, because it IS that sheet, and the per-entity MAX only ever
    replaces it with something larger that is no longer a ceiling. It may not be
    checked on the row's total, which legitimately sums across priced hosts and
    exceeds any single sheet — $4.217B over eight of them on the reference
    corpus.

    Checked at the published resolution rather than exactly, because that is the
    resolution the claim is made at — and the check therefore goes through
    ``_round_published``, the function that DEFINES that resolution, rather than
    through a hand-written ``round(x, 2)`` that used to agree with it. The two
    stopped agreeing in the sub-cent band, where the published resolution is the
    unrounded figure: at cents a standing $0.004 and a sheet of $0.001 both read
    0.00, the gate passed, and a figure that is not this node's sheet was
    labelled its ceiling. The comparison is strictly tighter than the old one and
    admits nothing it did not admit before.

    Reconciled rather than raised: an
    unreachable-by-construction mismatch is still a claim this fold cannot
    support, and the honest response is to withhold the LABEL from that one key —
    the figure stands, ungraded for direction, and charges the exposure budget
    like any other — not to take a protocol's whole score down with it. Mutates
    ``ceiling_kinds`` in place and returns what it withheld, so the caller
    publishes the refusal rather than a silence.
    """
    withheld: list[dict[str, Any]] = []
    for entity in sorted(ceiling_kinds):
        if ceiling_kinds[entity] != CEILING_KIND_SHEET:
            continue
        usd, reason = P.observed_holdings_for(value_plane, entity)
        if usd is not None and _round_published(per_entity[entity]) == _round_published(usd):
            continue
        del ceiling_kinds[entity]
        withheld.append(
            {
                "entity": entity,
                # The two figures the gate above just found unequal, published at
                # the resolution it compared them at. At cents a pair that
                # differs only below one would print here as two identical
                # numbers under a record whose whole claim is that they differ.
                "standing_usd": _round_published(per_entity[entity]),
                "sheet_usd": (_round_published(usd) if usd is not None else None),
                "ceiling_reason": reason,
                "why": "standing_figure_is_not_this_nodes_sheet(ceiling_label_withheld)",
                "reading": (
                    "the figure standing at this entity is not the one its own sheet answers, so "
                    "it is not a sheet ceiling and is not labelled one. The dollars are published "
                    "unchanged and graded in no direction, and they charge the exposure budget: "
                    "the exemption belongs to a proven upper bound and this figure has not been "
                    "shown to be one"
                ),
            }
        )
    return withheld


def _partially_priced_entities(value_plane: P.ValuePlane, keys: set[str]) -> list[str]:
    """Reached entities whose priced sheet does not cover everything they hold.

    Whole-entity unpricedness already lands in ``undetermined_instances``; this
    is the case one level in, where the entity IS priced but only partly — ten
    priced rows beside a hundred unpriced ones answer ten questions, and a total
    over them is a floor, not the entity's value.

    Two sources, ORed, and the per-ASSET map is read rather than the sheet
    state: the sheet state collapses a mixed entity to whichever fact ranks
    highest, so an entity with one priced asset and a hundred unanswered ones
    reads as ``priced`` there and the shortfall disappears. ``below_resolution``
    counts as unpriced here — an asset whose price landed on the storage floor
    is a holding of at most half a cent that the total does not carry, which is
    the same shortfall as one nobody priced. The restaking plane is the second
    source: it has no USD column at all, so a position there is unpriced by
    construction.
    """
    partial: set[str] = set()
    for key in keys:
        canonical = value_plane.canonical(key)
        if value_plane.total(canonical) is None:
            # Nothing determined at all: an undetermined entity, not a floor.
            continue
        # The same predicate the per-entity sheet-ceiling record publishes its
        # bound direction from, called rather than restated: the row header and
        # the per-entity record answer the same coverage question, and two
        # copies of the rule are how they came to answer it differently.
        if not _asset_coverage(value_plane, canonical)["complete"]:
            partial.add(canonical)
    return sorted(partial)


def _bound_direction(
    value_usd: float | None,
    entities: frozenset[str],
    ceiling_entities: frozenset[str],
    coverage_gap: bool,
    withheld_reach: bool,
    non_attributed_entities: frozenset[str],
) -> str:
    """Which direction the row's published total bounds this principal in.

    Two independent axes, and the header used to publish only one of them. The
    COVERAGE axis is what ``is_floor`` was designed for: instances that answered
    nothing and entities holding assets the priced sheet never covered leave
    value out of the sum, so what is in it is a floor. The BOUND axis is the
    other one: a composed figure is the DESTINATION function's witness for one
    call, and it is a ceiling on what this principal extracts because the
    witness bounds the FUNCTION whoever calls it and carries no model of who
    calls it.

    Summing ceilings does not make a floor, so ``floor`` requires that NO
    contributing entity's figure came through the composed branch — the
    invariant that keeps a genuinely witnessed floor exactly where it was.

    The composed branch is not the only ceiling in the building, which is the
    F5 correction. An ATTRIBUTION-DERIVED contribution — a holder's whole priced
    balance credited off a constant-amount probe — bounds this principal from
    above too, and it arrives through the instance's OWN witness, where the
    ceiling test above never looks. So ``floor`` additionally requires that
    every contributing entity's standing figure be PROVEN not attribution-derived.

    That conjunct is written as a membership test and not as "no contribution is
    attributed", deliberately. A universal over contributions is VACUOUSLY TRUE
    on a row with no contributions at all, and a row that lost every figure would
    then earn a floor over an empty sum — today that is unreachable only because
    :func:`_row_value` returns early with ``value_usd = None`` when ``per_entity``
    empties, i.e. because of a guard in a different function. An earned positive
    does not depend on a guard somewhere else: ``entities`` must be non-empty and
    every one of its members must be in the proven-not-attributed set.

    ``ceiling`` is the mirror and is earned no more cheaply: EVERY contributing
    entity's figure must be a proven ceiling (one ungraded contribution and the
    sum is not bounded above by these), nothing may be missing from the sum (a
    coverage gap or a withheld hop is value this row reaches that the total does
    not carry, and either one breaks an at-most while leaving an at-least
    intact), and the two are checked here rather than asserted in the prose.

    ``ceiling_entities`` carries TWO populations and this function reads neither
    apart: a composed extraction ceiling and a controlled node's own sheet
    ceiling are proven differently and narrowed differently, and both bound this
    principal from above, which is the whole of what direction asks. The
    per-entity records say which is which, and the coverage conjunct above is
    what stops a partly priced sheet from being summed into an at-most — the
    same conjunct the per-entity record derives its own direction from.

    Everything else is ``not_determined``, including a total with no gap and no
    ceiling in it: the contributions are then a mix this fold does not grade for
    direction — a priced floor bounded by a sheet is not an exact figure — and
    the absence of the two signals above is not a witness that the sum is
    two-sided. It publishes the bare band and claims nothing.
    """
    if value_usd is None:
        return BOUND_DIRECTION_NOT_DETERMINED
    if ceiling_entities:
        if ceiling_entities == entities and not coverage_gap and not withheld_reach:
            return BOUND_DIRECTION_CEILING
        return BOUND_DIRECTION_NOT_DETERMINED
    if not coverage_gap:
        return BOUND_DIRECTION_NOT_DETERMINED
    if entities and entities <= non_attributed_entities:
        return BOUND_DIRECTION_FLOOR
    return BOUND_DIRECTION_NOT_DETERMINED


# One clause per ceiling KIND, each naming the population it counted and the
# per-entry block a reader can check it against. Assembled per row rather than
# written once, because a row can carry either ceiling or both and a sentence
# naming only one of them is false about the figures it does not mention.
_CEILING_KIND_CLAUSES = {
    CEILING_KIND_COMPOSED: (
        "priced from a composed extraction CEILING — the DESTINATION function's own flow.out "
        "witness, which bounds one call to that function whoever makes it (see "
        "reach_composed_magnitudes[])"
    ),
    CEILING_KIND_SHEET: (
        "valued from the controlled node's observed own holdings, with coverage and freshness "
        "published separately (see "
        "reach_sheet_ceiling_magnitudes[])"
    ),
}


# What each kind of ceiling bounds, for the arm that earned a direction. The
# composed sentence is about one CALL; the sheet sentence is about one NODE, and
# each is false of the other kind.
_CEILING_KIND_BOUNDS = {
    CEILING_KIND_COMPOSED: "Each composed figure bounds ONE call to the destination function",
    CEILING_KIND_SHEET: (
        "Each complete fresh sheet figure bounds only that node's holdings at the observations; "
        "future deposits, mint authority and downstream assets are outside that scope"
    ),
}


def _asset_set_completeness(value_plane: P.ValuePlane, entity: str) -> dict[str, Any] | None:
    """The carrier record proving this entity's asset list whole, or ``None``.

    Copied out of the plane rather than rebuilt: the strings inside are the
    producer's own ``asset_set_basis`` values, so what the document publishes
    about a scan is the scan's own record and not a sentence authored at the
    point of publication.
    """
    record = value_plane.asset_set_proven_complete.get(value_plane.canonical(entity))
    return dict(record) if record is not None else None


# Where each missing-witness class sits on the proof chain. The frontier is the
# EARLIEST missing link: a row missing only pricing is one lookup from proven,
# one missing reach itself is furthest. Unregistered tokens publish a
# not_determined frontier rather than borrowing a place on the chain.
_MISSING_LINK_CHAIN = ("reach", "effect", "magnitude", "value")


_MISSING_LINK_OF = {
    "reach_not_witnessed": "reach",
    "pause_effective_not_witnessed": "effect",
    "reach_magnitude_not_witnessed": "magnitude",
    "code_control_sheet_ceiling_refused": "value",
    "closure_entity_value_not_determined": "value",
    "token_identity_not_decidable": "value",
}


def _unresolved_stake(
    undetermined: list[dict[str, Any]],
    withheld_behind_hops: dict[str, Any],
    sized_entities: set[str],
    value_plane: P.ValuePlane,
    hops_not_determined: list[dict[str, Any]] | tuple = (),
) -> dict[str, Any]:
    """The at-most behind this row's unanswered questions. Never enters lambda
    or exposure: the reach/magnitude is not witnessed, only the entities' own
    sheets are, so the figure is a ceiling on what resolution could put in play.

    Two bases, disjoint, reached takes precedence: ``reached_unwitnessed`` holds
    entities the row reaches whose contribution was refused; ``behind_unestablished_hops``
    holds entities the closure places behind hops the row could not establish —
    a bound on a bound, since that subtree is itself the widest walk's upper
    bound. Entities already carrying a published figure on this row are sized,
    not unresolved, and are excluded. An earned $0 sheet contributes 0.0 and
    counts as contributing; a refused sheet is counted under its refusal token
    (the work list), never as a zero. ``missing_witnesses`` counts the witness
    class each unresolved entity (or hop) waits on, so a consumer reads what
    closes the gap off the entry instead of re-parsing the instance lists.
    """
    # Canonical keys throughout: an implementation folds onto its proxy, so a
    # raw impl key would pass the sized-exclusion and then draw the proxy's
    # sheet out of ``ceiling_for`` — re-counting dollars the row already sized.
    sized = {value_plane.canonical(key) for key in sized_entities}
    reached = {value_plane.canonical(str(record["entity"])) for record in undetermined} - sized
    behind = (
        {value_plane.canonical(str(key)) for key in withheld_behind_hops.get("entity_keys") or ()} - sized - reached
    )
    reached_missing: dict[str, set[str]] = {}
    for record in undetermined:
        key = value_plane.canonical(str(record["entity"]))
        if key in reached:
            # 'token(detail) x qualifier' -> 'token'; the detail and qualifier
            # stay on the instance record, this is the class count.
            token = str(record.get("why", "")).partition("(")[0].partition(" x ")[0]
            reached_missing.setdefault(token, set()).add(key)
    hop_missing: dict[str, int] = {}
    for hop in hops_not_determined:
        reason = str(hop.get("reason", "hop_not_determined"))
        hop_missing[reason] = hop_missing.get(reason, 0) + 1
    entity_missing: dict[str, set[str]] = {}
    for token, keys in reached_missing.items():
        for key in keys:
            entity_missing.setdefault(key, set()).add(token)
    total = 0.0
    any_contributing = False
    by_basis: dict[str, Any] = {}
    for basis, keys, missing in (
        ("reached_unwitnessed", reached, {k: len(v) for k, v in reached_missing.items()}),
        ("behind_unestablished_hops", behind, hop_missing),
    ):
        if not keys:
            continue
        ceiling = 0.0
        contributing = 0
        refused: dict[str, int] = {}
        itemized: list[dict[str, Any]] = []
        for key in sorted(keys):
            usd, reason = P.ceiling_for(value_plane, key)
            if usd is not None:
                usd, reason = None, "capability_scope_not_proven"
            entry: dict[str, Any] = {
                "entity": key,
                "ceiling_usd": _round_published(usd) if usd is not None else None,
                "refusal": None if usd is not None else reason,
            }
            if basis == "reached_unwitnessed":
                entry["missing"] = sorted(entity_missing.get(key, ()))
            itemized.append(entry)
            if usd is not None:
                ceiling += usd
                contributing += 1
            else:
                refused[reason] = refused.get(reason, 0) + 1
        by_basis[basis] = {
            "ceiling_usd": _round_published(ceiling) if contributing else None,
            "entities": len(keys),
            "entities_contributing": contributing,
            "entities_refused_by_reason": dict(sorted(refused.items())),
            "missing_witnesses": dict(sorted(missing.items())),
            "entities_itemized": itemized,
        }
        if contributing:
            total += ceiling
            any_contributing = True
    links = {_MISSING_LINK_OF[t] for t in reached_missing if t in _MISSING_LINK_OF}
    if behind or hop_missing:
        links.add("reach")
    frontier = next((link for link in _MISSING_LINK_CHAIN if link in links), None)
    if frontier is None and (reached or behind):
        frontier = NOT_DETERMINED
    return {
        "ceiling_usd": _round_published(total) if any_contributing else None,
        "entities_total": len(reached) + len(behind),
        "proof_frontier": frontier,
        "by_basis": by_basis,
    }


def _unresolved_levers(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Document rollup: partial-proof rows ranked by the points ceiling — the
    proven half's weight times the unresolved ceiling's band, so an almost-
    proven EOA over $2M outranks a diffuse low-severity gap over similar
    dollars. Dollar ceiling breaks ties; an unbounded unknown publishes its
    entity count and refusals instead of a rank it never earned. Carries no
    lambda figures; join to findings on (principal_unit, capability,
    principal)."""
    admitted = [f for f in findings if f.get("partial_proof")]
    ranked = sorted(
        admitted,
        key=lambda f: (
            f["unresolved_stake"]["points_ceiling"] is None,
            -(f["unresolved_stake"]["points_ceiling"] or 0.0),
            -(f["unresolved_stake"]["ceiling_usd"] or 0.0),
            -f["unresolved_stake"]["entities_total"],
            f["principal_unit"],
            f["capability"],
        ),
    )
    return {
        "levers": [
            {
                "capability": f["capability"],
                "principal": f["principal"],
                "principal_unit": f["principal_unit"],
                "chain": f["chain"],
                "points_ceiling": f["unresolved_stake"]["points_ceiling"],
                "ceiling_usd": f["unresolved_stake"]["ceiling_usd"],
                "proof_frontier": f["unresolved_stake"]["proof_frontier"],
                "entities_total": f["unresolved_stake"]["entities_total"],
                "by_basis": f["unresolved_stake"]["by_basis"],
            }
            for f in ranked
        ],
        "findings_admitted": len(admitted),
        "findings_fully_determined": len(findings) - len(admitted),
    }


def _sheet_ceiling_records(
    sheet_ceilings: frozenset[str],
    per_entity: dict[str, float],
    value_plane: P.ValuePlane,
    capability: str,
) -> list[dict[str, Any]]:
    """One published record per entity whose figure is its own sheet.

    Assembled off the row's STANDING figures rather than at the moment the branch
    fired, for the same reason the ceiling set is: a row folds several calls and
    only the figure that survived the per-entity MAX is the one published, so a
    record written per call would name entities the row does not price this way.

    Each record answers #170 in the only shape that is true here. Every published
    magnitude carries the execution that proved it; this one was not proven by a
    call at all, so it carries the registered NON-FAULT reason saying so. That
    the reason is outside :data:`EX.FAULT_REASONS` is load-bearing rather than
    incidental: the structural census walks every ``proving_execution`` key in
    the document and a fault reason here would qualify the whole grade as
    fault-degraded on the strength of a proof that is intact. The observations
    the record stands on are PUBLISHED here — the per-asset figures at the
    canonical key — because a record whose reading names evidence the document
    does not carry is the authored-string defect one level up from the one the
    execution block exists to close.

    ``bound_direction`` is DERIVED from this entity's own asset coverage and is
    not the constant the branch's name suggests. A priced sheet is a floor over
    what was priced, so on an entity holding assets nobody priced the figure
    bounds the priced portion and not the move — publishing ``ceiling`` there
    would claim an at-most over holdings this fold never observed, and would
    contradict the row header, which refuses a ceiling on exactly this conjunct.

    ``sheet_state`` and ``ceiling_reason`` are read back off the plane instead of
    carried down from the branch, so the record cannot claim a state the plane
    would not answer for the same key at the same moment.
    """
    records: list[dict[str, Any]] = []
    for entity in sorted(sheet_ceilings):
        usd, reason = P.observed_holdings_for(value_plane, entity)
        coverage = _asset_coverage(value_plane, entity)
        complete = coverage.pop("complete")

        records.append(
            {
                "entity": entity,
                "capability": capability,
                # Both figures, and the per-asset evidence below them, take the
                # SAME rounding — see ``_round_published``. The two keys are equal
                # by construction and the ``per_asset`` block is what the sum is
                # checked against, so a convention that rounded one of them onto
                # zero would publish a record contradicting itself at exactly the
                # sub-cent sheets this rounding was hiding.
                "published_usd": _round_published(per_entity[entity]),
                # What the plane answers now, beside the figure the fold took.
                # Equal by construction and RECONCILED before this runs, so an
                # entry reaching here has been checked rather than asserted —
                # and checked through the SAME ``_round_published`` these two
                # keys are printed with, so the equality a reader sees is the
                # equality the gate tested. They drifted once and the gap was
                # exactly the sub-cent band.
                "sheet_usd": (_round_published(usd) if usd is not None else None),
                "sheet_state": value_plane.sheet_state(entity),
                "ceiling_reason": reason,
                "bound_direction": (BOUND_DIRECTION_CEILING if complete else BOUND_DIRECTION_NOT_DETERMINED),
                "value_scope": "observed_own_holdings",
                "bound_direction_basis": _sheet_ceiling_direction_basis(coverage, complete),
                # What proves the asset list this figure is summed over is the
                # WHOLE list, carried from the observation record rather than
                # restated here: the source token, the block range the chain's
                # own transfer history was read across, and the producer's own
                # basis strings. ``null`` is the third state — no scan on record
                # — which is every ADMITTED entry on this corpus and is why they
                # bound the priced portion and not the move.
                "asset_set_completeness": _asset_set_completeness(value_plane, entity),
                # The delivery evidence a disposed reading stands on, carried
                # from the plane's own records rather than restated: the
                # sentence below quotes these fields, so a reader checks the
                # claim against the evidence and not against the prose.
                # ``null`` where no reading here is disposed.
                "asset_disposition": None,
                **coverage,
                PROVING_EXECUTION_KEY: EX.not_determined(EX.REASON_NOT_PROVEN_BY_A_CALL).as_json(),
                "reading": (
                    _CEILING_SOURCE_READINGS[(reason, complete)]
                    # The shortfall, from the SAME derivation the direction
                    # basis publishes it from. The stems above may not name a
                    # cause: on a live carrier two of the three read empty, so a
                    # stem that presupposed one pointed a reader at fields that
                    # said nothing while the conjunct that failed went unnamed.
                    + (_CEILING_COVERAGE_SHORTFALL_PREFIX + _coverage_shortfall(coverage) if not complete else "")
                    + _CEILING_CLOSING
                ),
            }
        )
    return records


def _ceilings_present(
    composed_ceilings: frozenset[str], sheet_ceilings: frozenset[str]
) -> list[tuple[str, frozenset[str]]]:
    """The ceiling kinds this row actually carries, in a fixed order.

    An empty kind writes no clause anywhere. A row carrying one kind therefore
    reads exactly as it did before the other existed — which is what keeps a row
    that did not move from having its prose move.
    """
    present = ((CEILING_KIND_COMPOSED, composed_ceilings), (CEILING_KIND_SHEET, sheet_ceilings))
    return [(kind, entities) for kind, entities in present if entities]


def _ceiling_source_phrase(
    composed_ceilings: frozenset[str], sheet_ceilings: frozenset[str], *, all_of_them: bool
) -> str:
    """Which ceiling(s) the row's figures came from, counted per kind.

    ``all_of_them`` is the arm where every contributing entity is a ceiling, and
    it is passed rather than inferred from the sets: the caller has already
    established it against the coverage axes, and re-deriving it here off a
    length comparison would restate a conclusion this function cannot check.
    """
    parts = _ceilings_present(composed_ceilings, sheet_ceilings)
    if len(parts) == 1:
        return ("every one of them " if all_of_them else "") + _CEILING_KIND_CLAUSES[parts[0][0]]
    counts = "; ".join(f"{len(entities)} {_CEILING_KIND_CLAUSES[kind]}" for kind, entities in parts)
    return ("every one of them a proven ceiling — " if all_of_them else "of which ") + counts


def _ceiling_bound_phrase(composed_ceilings: frozenset[str], sheet_ceilings: frozenset[str]) -> str:
    """What each kind of ceiling on this row bounds, one sentence per kind."""
    return "; ".join(_CEILING_KIND_BOUNDS[kind] for kind, _ in _ceilings_present(composed_ceilings, sheet_ceilings))


def _ceiling_untightened(
    composed_ceilings: frozenset[str],
    sheet_ceilings: frozenset[str],
    composed: dict[str, _ComposedMagnitude],
) -> str:
    """What, in THIS document, could put the true figure below each ceiling.

    Two different answers, so two clauses. For a COMPOSED ceiling it is the
    destination function's own stored conditions, counted off the row's own
    entries rather than named from a field that no longer exists. For a SHEET
    ceiling it is which of the node's assets replaced code can actually reach —
    a question nothing here asks, and the reason the figure is typed as a bound
    and not as an amount.
    """
    parts: list[str] = []
    if composed_ceilings:
        with_conditions = sum(
            1 for entity in composed_ceilings if entity in composed and composed[entity].predicates.descriptions
        )
        if with_conditions:
            parts.append(
                f"the destination function's own stored conditions travel with {with_conditions} of "
                f"those {len(composed_ceilings)} figure(s) (destination_predicates) and this fold "
                "evaluates none of them"
            )
        else:
            parts.append(
                f"no condition text was extracted for any of those {len(composed_ceilings)} figure(s) "
                "(destination_predicates), so the destination's own conditions are not available "
                "here to check the ceiling against at all"
            )
    if sheet_ceilings:
        parts.append(
            f"the {len(sheet_ceilings)} holdings figure(s) value observed assets at controlled nodes; "
            "no call demonstrated extracting those amounts, and other assets and times are outside the scope"
        )
    return "and nothing here tightens it: " + "; ".join(parts)


def _ceiling_bearing_basis(
    direction: str,
    per_entity: dict[str, float],
    composed_ceilings: frozenset[str],
    sheet_ceilings: frozenset[str],
    undetermined: list[dict[str, Any]],
    partially_priced: list[str],
    proven_no_reach: list[dict[str, Any]],
    zero_reach_stripped: list[dict[str, Any]],
    hops_not_determined: list[dict[str, Any]],
    withheld_behind_hops: dict[str, Any],
    composed: dict[str, _ComposedMagnitude],
    value_plane: P.ValuePlane,
) -> str:
    """The basis for a row some of whose figures bound the principal from above.

    Written here rather than in :func:`_row_value` because the coverage half of
    the question is only complete once the zero-reach instances and the partly
    priced entities are known. The floor basis is left untouched: a row whose
    direction did not move must not have its prose move either.

    TWO ceiling kinds reach this writer and they are counted apart, never summed
    into one "ceiling" population. A composed extraction ceiling is a
    destination function's witness for one CALL and what could narrow it is that
    function's own stored conditions; a sheet ceiling is one NODE's whole priced
    holdings and what could narrow it is which of those assets replaced code can
    actually reach. One sentence over both would be a claim about the row that is
    false of whichever half it was not written for.

    Every clause names the population it counted. The ceiling arm in particular
    may not say "nothing is missing" as an unchecked flourish — the hops this
    row could not establish and the graph withheld behind them are value the sum
    does not carry, and they are named here because they were consulted in
    :func:`_bound_direction` before the arm was taken.

    ``composed`` is read for one clause only, and it is read rather than
    asserted: a ceiling can overstate what this principal actually extracts, and
    the only evidence in this document that could narrow a COMPOSED one is the
    destination function's OWN stored conditions, which travel with each composed
    entry and which this fold evaluates none of. How many of the row's
    ceiling-bearing figures carry that text is a fact about the row and is
    counted here. It replaces a clause naming an extraction precondition this
    document no longer publishes — a definite reference to a deleted field, which
    reads as a constraint that was consulted.
    """
    ceiling_entities = composed_ceilings | sheet_ceilings
    n_entities = len(per_entity)
    counted = f"{len(ceiling_entities)} of {n_entities} entity(ies)"
    scoped = ""
    if direction == BOUND_DIRECTION_CEILING:
        return (
            (
                f"<= the sum over {n_entities} entity(ies), "
                + _ceiling_source_phrase(composed_ceilings, sheet_ceilings, all_of_them=True)
                + "; no instance is not_determined, no entity holds assets the priced sheet does not "
                "cover, and no hop of this row was left undetermined or withheld behind one — so "
                "the total bounds only the stated observation scopes. "
                + _ceiling_bound_phrase(composed_ceilings, sheet_ceilings)
            )
            + (f"; {len(proven_no_reach)} instance(s) proven_no_reach" if proven_no_reach else "")
            + scoped
        )

    # Why it is not a ceiling either, counted rather than asserted: value this
    # row reaches that the sum does not carry, plus contributions that are not
    # ceilings and that this fold does not grade for direction at all.
    missing: list[str] = []
    if undetermined:
        clause = f"{len(undetermined)} instance(s) not_determined"
        if zero_reach_stripped:
            clause += f" (of which {len(zero_reach_stripped)} reached only the refused zero address)"
        missing.append(clause)
    if partially_priced:
        missing.append(f"{len(partially_priced)} entity(ies) holding assets the priced sheet does not cover")
    incomplete_observations = sum(not _asset_coverage(value_plane, key)["complete"] for key in sheet_ceilings)
    if incomplete_observations:
        missing.append(f"{incomplete_observations} holdings observation(s) lack a complete fresh inventory")
    if hops_not_determined:
        missing.append(f"{len(hops_not_determined)} hop(s) not_determined withholding reach")
    behind = withheld_behind_hops.get("entities") or 0
    if behind:
        missing.append(f"{behind} entity(ies) withheld behind those hops (see reach_withheld_behind_hops)")
    ungraded = n_entities - len(ceiling_entities)
    if ungraded:
        missing.append(f"{ungraded} entity(ies) whose figure is not a proven ceiling and is graded in no direction")
    untightened = _ceiling_untightened(composed_ceilings, sheet_ceilings, composed)
    basis = (
        f"bounded in NEITHER direction: {counted} "
        + _ceiling_source_phrase(composed_ceilings, sheet_ceilings, all_of_them=False)
        + f"; the figures retain their individual scopes, {untightened}; "
        + ", ".join(missing)
        + " prevent a bound on the row total"
    )
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    return basis + scoped


def _coverage_bearing_basis(
    direction: str,
    per_entity: dict[str, float],
    undetermined: list[dict[str, Any]],
    partially_priced: list[str],
    non_attributed_entities: frozenset[str],
    proven_no_reach: list[dict[str, Any]],
    zero_reach_stripped: list[dict[str, Any]],
) -> str:
    """The basis for a row with a coverage gap and no ceiling-bearing figure.

    The gap is what a floor is made of — value this row reaches that the sum
    does not carry can only push the truth up — but it is not the whole of it.
    :func:`_bound_direction` also requires every contributing entity's standing
    figure to be PROVEN free of an upper-bounding witness, and where that second
    axis refuses, the row bounds this principal in neither direction. The two
    arms are written together here so the prose and the header can never come
    apart: the floor sentence is reachable only from the branch that earned the
    floor.

    Both arms count the SAME two populations. The gap the floor is earned from
    is instances that answered nothing AND entities holding assets the priced
    sheet never covered — the coverage axis reads both, and the floor string
    used to name only the first, which read as a floor over a fully priced
    entity set on a row where one entity was partly priced.
    """
    n_entities = len(per_entity)
    missing: list[str] = []
    if undetermined:
        clause = f"{len(undetermined)} instance(s) not_determined"
        if zero_reach_stripped:
            clause += f" (of which {len(zero_reach_stripped)} reached only the refused zero address)"
        missing.append(clause)
    if partially_priced:
        missing.append(f"{len(partially_priced)} entity(ies) holding assets the priced sheet does not cover")
    if direction == BOUND_DIRECTION_FLOOR:
        basis = f">= proven floor over {n_entities} entity(ies); " + ", ".join(missing)
    else:
        # Counted off the membership test the direction was refused on, and
        # named as what that test establishes: NOT proven free of an
        # upper-bounding witness. The attribution path is the live producer of
        # this refusal and is glossed, but a sheet ceiling whose label was
        # withheld lands here too, so the population may not be asserted to be
        # attribution-derived — only that none of it is proven not to be.
        ungraded = len(set(per_entity) - non_attributed_entities)
        basis = (
            f"bounded in NEITHER direction: {ungraded} of {n_entities} entity(ies) contribute a figure "
            "NOT proven free of an upper-bounding witness — the attribution path credits a holder's "
            "whole priced balance off a constant-amount probe, which bounds this principal from ABOVE "
            "— so the sum is not an at-least; " + ", ".join(missing) + " leave it short of an at-most too"
        )
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    return basis


def _named_zeros(counted: dict[str, set[Any]], vocabulary: tuple[str, ...]) -> dict[str, int]:
    """Every token in a CLOSED vocabulary, counted, including the ones at zero.

    A census keyed on a closed set publishes the whole set or it publishes an
    ambiguity: a token missing from the map reads identically as "this rule did
    not fire on this corpus" and "this rule is not in the model", and only the
    first of those is a fact about the protocol. The same rule the credit-path
    reading follows one level up, and the same one ``planes._REDUCTION_COUNTERS``
    follows for the value plane's own counters.

    A token OUTSIDE the vocabulary is not silently dropped. It is a fact the
    document carries and a census that cannot name it would publish a total
    smaller than its own carriers — so it is counted beside the registered ones
    and the caller's vocabulary is what needs fixing.
    """
    out = dict.fromkeys(vocabulary, 0)
    for token, members in counted.items():
        out[token] = len(members)
    return {k: out[k] for k in sorted(out)}


def _sheet_ceiling_totals(
    findings: list[dict[str, Any]],
    subsumed: list[dict[str, Any]],
    credited_by_capability: dict[str, int],
) -> dict[str, Any]:
    """The sheet-ceiling population and its dollars, rolled up to the protocol.

    Every figure here is DERIVED from what the rows published — the per-entity
    records, the refusal tokens in their ``why`` vocabulary, the reconciliation
    withholdings — and from the confidence pass's own credit census. Nothing is
    carried down from the branch that fired: a rollup written at the moment of
    firing would count candidates the per-entity MAX later displaced, which are
    exactly the figures no row publishes.

    Dollars are summed over DISTINCT ENTITIES and not over rows. A sheet ceiling
    is a fact about one node's sheet, so two rows pricing the same node this way
    publish the same number twice and summing them would report twice the money
    that exists. That the two agree is checked rather than assumed: an entity
    whose rows disagree is COUNTED and published, because a disagreement here
    would mean the per-key reconciliation let two different figures stand under
    one claim.

    ``signals_credited_in_confidence`` is the OTHER meter and is deliberately in
    a different unit: the confidence term counts SIGNALS whose magnitude question
    a ceiling answered, while everything above it counts entities and dollars.
    The two are related but not convertible — one node's sheet can answer several
    signals — and the credited population is the standing one, so a ceiling
    displaced by a larger figure or withdrawn by the reconciliation is in neither
    this block's entity count nor that credit.
    """
    populations = (("findings", findings), ("subsumed_rows", subsumed))
    figures: dict[str, set[float]] = defaultdict(set)
    entities_by_capability: dict[str, set[str]] = defaultdict(set)
    by_reason: dict[str, set[str]] = defaultdict(set)
    by_direction: dict[str, set[str]] = defaultdict(set)
    refused: dict[str, set[tuple[str, str]]] = defaultdict(set)
    withheld: set[str] = set()
    rows_publishing = {name: 0 for name, _ in populations}
    for name, rows in populations:
        for row in rows:
            records = row.get("reach_sheet_ceiling_magnitudes") or []
            if records:
                rows_publishing[name] += 1
            for record in records:
                entity = str(record["entity"])
                figures[entity].add(round(float(record["published_usd"]), 2))
                entities_by_capability[str(record["capability"])].add(entity)
                by_reason[str(record["ceiling_reason"])].add(entity)
                by_direction[str(record["bound_direction"])].add(entity)
            for record in row.get("reach_sheet_ceiling_magnitudes_withheld") or []:
                withheld.add(str(record["entity"]))
            for gap in row.get("undetermined_instances") or []:
                why = str(gap.get("why") or "")
                if not why.startswith(SHEET_CEILING_REFUSED_PREFIX):
                    continue
                reason = why[len(SHEET_CEILING_REFUSED_PREFIX) :].removesuffix(")")
                # Deduped on the CALL, so two rows reaching one call through two
                # principals report the one refusal that happened rather than two.
                refused[reason].add((str(gap.get("entity")), str(gap.get("function"))))
    disagreeing = sorted(key for key, seen in figures.items() if len(seen) > 1)
    # An entity reached by two code-control capabilities is priced this way under
    # BOTH, so the capability buckets sum past the distinct-entity count and a
    # reader adding them up over-counts the population. Counted rather than left
    # to be noticed: the dollars are deduped and the breakdown is not, and only
    # one of those two facts was published.
    shared_capability = sorted(
        key for key in figures if sum(1 for members in entities_by_capability.values() if key in members) > 1
    )
    return {
        "entities_priced_from_a_sheet_ceiling": len(figures),
        "entities_by_capability": {k: len(v) for k, v in sorted(entities_by_capability.items())},
        "entities_in_more_than_one_capability": len(shared_capability),
        "ceiling_usd_over_distinct_entities": round(sum(max(seen) for _, seen in sorted(figures.items())), 2),
        "entities_publishing_more_than_one_figure": disagreeing,
        "entities_by_ceiling_reason": _named_zeros(by_reason, P.CEILING_ADMITTING_REASONS),
        "entities_by_bound_direction": _named_zeros(by_direction, SHEET_CEILING_BOUND_DIRECTIONS),
        "rows_publishing_a_sheet_ceiling": rows_publishing,
        "calls_refused_by_reason": _named_zeros(refused, CEILING_REFUSAL_REASONS),
        "entities_withheld_on_sheet_reconciliation": len(withheld),
        "signals_credited_in_confidence": sum(credited_by_capability.values()),
        "signals_credited_by_capability": dict(sorted(credited_by_capability.items())),
        "reading": _sheet_ceiling_totals_reading(figures, refused, withheld, disagreeing, shared_capability),
    }


def _sheet_ceiling_totals_reading(
    figures: dict[str, set[float]],
    refused: dict[str, set[tuple[str, str]]],
    withheld: set[str],
    disagreeing: list[str],
    shared_capability: list[str],
) -> str:
    """The rollup's account of itself, with every count taken from its own data."""
    admitted = len(figures)
    refusals = sum(len(calls) for calls in refused.values())
    head = (
        f"{admitted} entity(ies) are priced from their own sheet here and "
        f"{refusals} code-control call(s) asked for a sheet ceiling and were refused one, "
        "counted by the reason the SHEET gave — 'no balance was ever observed at this node', "
        "'the price lookup never answered' and 'the asset list was read at its page cap' are "
        "the work of three different pipelines and a reader who cannot tell them apart cannot "
        "act on any of them"
        if admitted or refusals
        else "no entity is priced from its own sheet here and no code-control call was refused "
        "one: the branch had nothing to fire on, which is a measured zero and not a silence"
    )
    reconciled = (
        f" {len(withheld)} entity(ies) carried a figure that did not reconcile against the sheet "
        "it claimed to be, so the ceiling LABEL was withheld there while the dollars stand"
        if withheld
        else " Every figure reconciled against the sheet it claims to be; none was withheld"
    )
    disagreement = (
        f" {len(disagreeing)} entity(ies) publish more than one figure across rows, which the "
        "per-key reconciliation is supposed to make impossible — the total takes the largest and "
        "names them here rather than absorbing the disagreement"
        if disagreeing
        else " No entity publishes two different figures across rows, so the total double-counts nothing"
    )
    # The dollars are deduped and the capability breakdown is NOT, so the two
    # answer different questions and only saying so keeps a reader from adding
    # the buckets up. Every count in the reading is of the entity population;
    # entities_by_capability counts memberships in it.
    buckets = (
        f" The dollars, not the breakdown: {len(shared_capability)} entity(ies) are priced this way "
        "under MORE THAN ONE code-control capability and appear in that many buckets, so "
        "entities_by_capability sums past the distinct-entity count above and is a count of "
        "memberships rather than of entities"
        if shared_capability
        else " No entity is priced this way under more than one capability, so the "
        "entities_by_capability buckets happen to sum to the distinct-entity count here — an "
        "arithmetic coincidence of this corpus and not a property of the breakdown"
    )
    return (
        head
        + "."
        + reconciled
        + "."
        + disagreement
        + "."
        + buckets
        + ". These dollars value observed holdings at controlled nodes. Only records with "
        "complete fresh coverage establish a bound, scoped to those holdings at their observations. "
        "Partial or stale records do not bound current holdings. Future deposits and assets "
        "elsewhere are outside the scope. The figures do not measure extraction and remain "
        "outside exposure_usd; economic overlap between different entities is not resolved here"
    )
