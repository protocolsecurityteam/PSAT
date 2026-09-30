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
    """What the tie-break string decided on this row.

    ``shared_entities``: a split only happens where an entity is shared. ``position_in_tie``: the first row is charged
    first, later ones the remainder.
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
    """Where rows tie on the sort key, the unit address decides the order (λ position and the exposure budget).

    Correct splitting needs evidence the fold lacks, so the order stays fixed and is published. Findings only: subsumed
    rows have no λ position or budget, so ``None``.
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


# Shares below half a cent publish as $0.00.
_PUBLISHED_CENT = 0.005


_UNPRICED_ASSET_STATES = frozenset({P.ASSET_UNPRICED, P.ASSET_BELOW_RESOLUTION})


def _asset_coverage(value_plane: P.ValuePlane, canonical: str) -> dict[str, Any]:
    """What one entity's priced sheet covers, per asset (the sheet state collapses mixed entities).

    ``below_resolution`` and restaking positions count as not priced.

    ``complete`` is earned: an entity with no observed assets doesn't clear it. Two list conjuncts: a list at the page
    cap is never complete, and a disposed reading doesn't extend coverage, so a sheet with disposed assets needs its
    list proven whole by chain history.
    """
    values = value_plane.per_asset.get(canonical) or {}
    states = value_plane.per_asset_state.get(canonical) or {}
    positions = value_plane.unpriced_positions.get(canonical) or []
    names = sorted(set(values) | set(states))
    # A ``per_asset`` key without a state entry is determined.
    not_priced = sorted(name for name in names if states.get(name) in _UNPRICED_ASSET_STATES)
    disposed = sorted(name for name in names if states.get(name) == P.ASSET_AIRDROP_DELIVERED)
    list_is_whole = not value_plane.asset_set_is_truncated(canonical) and (
        not disposed or value_plane.asset_set_is_proven_complete(canonical)
    )
    return {
        "per_asset": [
            # Same rounding as the figure, so the evidence doesn't contradict it.
            {
                "asset": name,
                "usd": (_round_published(values[name]) if name in values else None),
                "state": states.get(name),
            }
            for name in names
        ],
        "assets_observed": len(names),
        # Assets with a determined dollar reading; with not-priced and disposed they partition ``assets_observed``
        # (disposed assets have no dollar figure).
        "assets_priced": len(names) - len(not_priced) - len(disposed),
        "assets_not_priced": not_priced,
        "assets_disposed": disposed,
        # The list conjunct, published so a refused direction's cause is readable.
        "asset_list_proven_whole": list_is_whole,
        "unpriced_positions": len(positions),
        "complete": bool(names) and not not_priced and not positions and list_is_whole,
    }


def _reconcile_sheet_ceilings(
    ceiling_kinds: dict[str, str], per_entity: dict[str, float], value_plane: P.ValuePlane
) -> list[dict[str, Any]]:
    """Drop sheet ceilings whose standing figure isn't that node's sheet (checked per key, never on the total).

    Compared through ``_round_published``, the published resolution (a hand-written ``round(x, 2)`` once let sub-cent
    mismatches through). Withholds the label from that key rather than raising; the figure stands. Mutates
    ``ceiling_kinds`` and returns the withheld entries.
    """
    withheld: list[dict[str, Any]] = []
    for entity in sorted(ceiling_kinds):
        if ceiling_kinds[entity] != CEILING_KIND_SHEET:
            continue
        usd, reason = P.ceiling_for(value_plane, entity)
        if usd is not None and _round_published(per_entity[entity]) == _round_published(usd):
            continue
        del ceiling_kinds[entity]
        withheld.append(
            {
                "entity": entity,
                # Both figures at the resolution they were compared at.
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
    """Reached entities priced only partly (a total over them is a floor).

    Read per asset, since sheet state collapses mixed entities; ``below_resolution`` counts as unpriced, and restaking
    positions have no USD column.
    """
    partial: set[str] = set()
    for key in keys:
        canonical = value_plane.canonical(key)
        if value_plane.total(canonical) is None:
            continue
        # The same predicate the per-entity records use, so the two can't disagree.
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
    """Which direction the row's total bounds the principal in.

    Coverage axis: unanswered instances or partly priced entities make the sum a floor. Bound axis: a composed figure is
    a ceiling (the destination witness bounds the function, not who calls it), and summing ceilings doesn't make a
    floor. So ``floor`` requires no composed contribution and every contributing entity proven not attribution-derived,
    written as membership (a universal over contributions would be vacuously true on an empty row).

    ``ceiling`` requires every contribution to be a proven ceiling and nothing missing (gaps or withheld hops). Composed
    and sheet ceilings both bound from above. Everything else is ``not_determined``.
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


# One clause per ceiling kind present; a sentence naming only one would be false about the other.
_CEILING_KIND_CLAUSES = {
    CEILING_KIND_COMPOSED: (
        "priced from a composed extraction CEILING — the DESTINATION function's own flow.out "
        "witness, which bounds one call to that function whoever makes it (see "
        "reach_composed_magnitudes[])"
    ),
    CEILING_KIND_SHEET: (
        "priced from a SHEET CEILING — the controlled node's own priced holdings, which bound "
        "from above what replacing that node's code can move at it (see "
        "reach_sheet_ceiling_magnitudes[])"
    ),
}


# Composed ceilings bound one call; sheet ceilings one node.
_CEILING_KIND_BOUNDS = {
    CEILING_KIND_COMPOSED: "Each composed figure bounds ONE call to the destination function",
    CEILING_KIND_SHEET: (
        "Each sheet figure bounds what replacing ONE node's code can move AT THAT NODE, and "
        "nothing about what that node in turn governs"
    ),
}


def _asset_set_completeness(value_plane: P.ValuePlane, entity: str) -> dict[str, Any] | None:
    """The carrier record proving the asset list whole (the producer's own strings), or ``None``."""
    record = value_plane.asset_set_proven_complete.get(value_plane.canonical(entity))
    return dict(record) if record is not None else None


def _disposition_carrier(value_plane: P.ValuePlane, entity: str, disposed: list[str]) -> dict[str, Any] | None:
    """The delivery evidence behind this entity's disposed readings, from ``ValuePlane.asset_disposition``, or
    ``None``.

    Aggregated at the weakest end of each field (smallest fan-out, latest start block, earliest end block).
    """
    carriers = [
        record
        for asset in disposed
        if (record := (value_plane.asset_disposition.get(value_plane.canonical(entity)) or {}).get(asset)) is not None
    ]
    if not carriers:
        return None
    fan_outs = [record["min_fan_out"] for record in carriers if record["min_fan_out"] is not None]
    return {
        "assets": len(carriers),
        "shapes": sorted({record["shape"] for record in carriers}),
        "fan_out_threshold_k": max(record["fan_out_threshold_k"] for record in carriers),
        # No recorded fan-out is null, never zero.
        "min_fan_out": (min(fan_outs) if fan_outs else None),
        "delivery_count": sum(record["delivery_count"] for record in carriers),
        "scanned_from_block": max(record["scanned_from_block"] for record in carriers),
        "measured_through_block": min(record["measured_through_block"] for record in carriers),
        "accounts": sorted({account for record in carriers for account in record["accounts"]}),
        "basis": sorted({line for record in carriers for line in record["basis"]}),
    }


def _disposition_scope(coverage: dict[str, Any], carrier: dict[str, Any]) -> str:
    """What this entity's figure covers and doesn't, from the row's counts and the carrier's fields.

    A fully disposed sheet totals $0 over zero priced assets: "prices nothing", not "holds nothing".
    """
    fan_out = carrier["min_fan_out"]
    return (
        f". The figure is SCOPED, and the scope is this row's own counts: it totals the "
        f"{coverage['assets_priced']} asset(s) here that carry a determined dollar reading, and "
        f"the {len(coverage['assets_disposed'])} asset(s) under assets_disposed are STILL HELD at "
        f"{len(carrier['accounts'])} account(s) and carry no valuation anywhere in this document. "
        f"What was measured of those is how they ARRIVED — {carrier['delivery_count']} recorded "
        f"delivery(ies), the smallest of them carrying "
        f"{fan_out if fan_out is not None else NOT_DETERMINED} same-token transfer log(s) in one "
        f"transaction against a published threshold of {carrier['fan_out_threshold_k']}, read over "
        f"blocks {carrier['scanned_from_block']}-{carrier['measured_through_block']} (see "
        "asset_disposition) — and never what they are worth, which is not_determined here. So "
        "this figure is a total over what the document PRICES at this node, and nothing on the "
        "entry says the held assets are worth nothing or that the entity holds nothing"
    )


# Order of links on the proof chain; the frontier is the earliest missing. Unregistered tokens are not_determined.
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
    """The at-most behind unanswered questions, never in lambda or exposure.

    Two disjoint bases: reached entities whose contribution was refused, and entities behind unestablished hops (a bound
    on a bound). Already-sized entities are excluded; an earned $0 sheet counts as 0.0; refused sheets are counted under
    their token. ``missing_witnesses`` counts what each gap waits on.
    """
    # Canonical keys, so an implementation key can't slip past the sized check and recount the proxy's sheet.
    sized = {value_plane.canonical(key) for key in sized_entities}
    reached = {value_plane.canonical(str(record["entity"])) for record in undetermined} - sized
    behind = (
        {value_plane.canonical(str(key)) for key in withheld_behind_hops.get("entity_keys") or ()} - sized - reached
    )
    reached_missing: dict[str, set[str]] = {}
    for record in undetermined:
        key = value_plane.canonical(str(record["entity"]))
        if key in reached:
            # The class token; details stay on the instance.
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
    """Partial-proof rows ranked by points ceiling (proven weight x unresolved band), dollar ceiling breaking ties;
    unbounded unknowns publish counts instead of a rank. Join to findings on (principal_unit, capability,
    principal).
    """
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
    """One record per entity whose standing figure is its own sheet (per-entity MAX survivors only).

    Proven by an observation, not a call, so it carries a registered non-fault reason (a fault reason would mark the
    whole grade degraded). The per-asset observations are published with it. ``bound_direction`` is derived from the
    entity's coverage (``ceiling`` over unpriced holdings would claim an unobserved at-most). ``sheet_state`` and
    ``ceiling_reason`` are read back from the plane.
    """
    records: list[dict[str, Any]] = []
    for entity in sorted(sheet_ceilings):
        usd, reason = P.ceiling_for(value_plane, entity)
        coverage = _asset_coverage(value_plane, entity)
        complete = coverage.pop("complete")
        carrier = _disposition_carrier(value_plane, entity, coverage["assets_disposed"])
        records.append(
            {
                "entity": entity,
                "capability": capability,
                # Both figures and the per-asset evidence share one rounding (``_round_published``).
                "published_usd": _round_published(per_entity[entity]),
                # Equal by construction and reconciled through the same rounding.
                "sheet_usd": (_round_published(usd) if usd is not None else None),
                "sheet_state": value_plane.sheet_state(entity),
                "ceiling_reason": reason,
                "bound_direction": (BOUND_DIRECTION_CEILING if complete else BOUND_DIRECTION_NOT_DETERMINED),
                "bound_direction_basis": _sheet_ceiling_direction_basis(coverage, complete),
                # The carrier record proving the list whole; null means no scan, true of every admitted entry here,
                # which is why they bound the priced portion only.
                "asset_set_completeness": _asset_set_completeness(value_plane, entity),
                # The delivery evidence the sentence quotes; null where nothing is disposed.
                "asset_disposition": carrier,
                **coverage,
                PROVING_EXECUTION_KEY: EX.not_determined(EX.REASON_NOT_PROVEN_BY_A_CALL).as_json(),
                "reading": (
                    _CEILING_SOURCE_READINGS[(reason, complete)]
                    # The shortfall from the same derivation as the direction basis.
                    + (_CEILING_COVERAGE_SHORTFALL_PREFIX + _coverage_shortfall(coverage) if not complete else "")
                    + (_disposition_scope(coverage, carrier) if carrier is not None else "")
                    + _CEILING_CLOSING
                ),
            }
        )
    return records


def _ceilings_present(
    composed_ceilings: frozenset[str], sheet_ceilings: frozenset[str]
) -> list[tuple[str, frozenset[str]]]:
    """Ceiling kinds on this row, in fixed order; absent kinds write no clause."""
    present = ((CEILING_KIND_COMPOSED, composed_ceilings), (CEILING_KIND_SHEET, sheet_ceilings))
    return [(kind, entities) for kind, entities in present if entities]


def _ceiling_source_phrase(
    composed_ceilings: frozenset[str], sheet_ceilings: frozenset[str], *, all_of_them: bool
) -> str:
    """Which ceiling kinds the figures came from; ``all_of_them`` is passed in (already established against
    coverage), not inferred.
    """
    parts = _ceilings_present(composed_ceilings, sheet_ceilings)
    if len(parts) == 1:
        return ("every one of them " if all_of_them else "") + _CEILING_KIND_CLAUSES[parts[0][0]]
    counts = "; ".join(f"{len(entities)} {_CEILING_KIND_CLAUSES[kind]}" for kind, entities in parts)
    return ("every one of them a proven ceiling — " if all_of_them else "of which ") + counts


def _ceiling_bound_phrase(composed_ceilings: frozenset[str], sheet_ceilings: frozenset[str]) -> str:
    return "; ".join(_CEILING_KIND_BOUNDS[kind] for kind, _ in _ceilings_present(composed_ceilings, sheet_ceilings))


def _ceiling_untightened(
    composed_ceilings: frozenset[str],
    sheet_ceilings: frozenset[str],
    composed: dict[str, _ComposedMagnitude],
) -> str:
    """What could put the true figure below each ceiling: for composed ceilings, the destination's stored conditions
    (counted); for sheet ceilings, which assets replaced code can actually reach (unasked).
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
            f"each of the {len(sheet_ceilings)} sheet figure(s) is that node's WHOLE priced sheet, and "
            "nothing here witnesses that replaced code reaches every asset on it — an accounting "
            "entry, or a balance another contract holds, is inside the sheet and outside the move"
        )
    return "and nothing here tightens it: " + "; ".join(parts)


def _disposed_ceiling_clause(value_plane: P.ValuePlane, sheet_ceilings: frozenset[str]) -> str:
    """The header clause for a sheet ceiling determined at $0 (empty otherwise): the assets are still held; what was
    proven is how they arrived. From the plane's disposition records.
    """
    scoped = [
        entity
        for entity in sorted(sheet_ceilings)
        if P.ceiling_for(value_plane, entity)[1] == P.CEILING_AIRDROP_DETERMINED
    ]
    if not scoped:
        return ""
    assets = sum(len(value_plane.asset_disposition.get(value_plane.canonical(entity)) or {}) for entity in scoped)
    return (
        f"; {len(scoped)} of those sheet figure(s) is a DETERMINED ZERO of a scoped kind — "
        f"{assets} asset(s) at those node(s) are STILL HELD and this document values none of "
        "them, so the zero totals what it prices there and is never a claim that the holdings "
        "are worth nothing (reach_sheet_ceiling_magnitudes[].asset_disposition carries the "
        "delivery evidence, and their worth is not_determined)"
    )


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
    """The basis for a row with figures that bound from above, written once coverage is fully known.

    Composed and sheet ceilings are counted apart (different evidence could narrow each). Every clause names what it
    counted; missing hops and withheld graph are named. Stored destination conditions (not evaluated) are counted for
    composed ceilings.
    """
    ceiling_entities = composed_ceilings | sheet_ceilings
    n_entities = len(per_entity)
    counted = f"{len(ceiling_entities)} of {n_entities} entity(ies)"
    scoped = _disposed_ceiling_clause(value_plane, sheet_ceilings)
    if direction == BOUND_DIRECTION_CEILING:
        return (
            (
                f"<= the sum over {n_entities} entity(ies), "
                + _ceiling_source_phrase(composed_ceilings, sheet_ceilings, all_of_them=True)
                + "; no instance is not_determined, no entity holds assets the priced sheet does not "
                "cover, and no hop of this row was left undetermined or withheld behind one — so "
                "nothing this row reaches is missing from the sum and the total bounds this "
                "principal from ABOVE. " + _ceiling_bound_phrase(composed_ceilings, sheet_ceilings)
            )
            + (f"; {len(proven_no_reach)} instance(s) proven_no_reach" if proven_no_reach else "")
            + scoped
        )

    # Why it isn't a ceiling either, counted.
    missing: list[str] = []
    if undetermined:
        clause = f"{len(undetermined)} instance(s) not_determined"
        if zero_reach_stripped:
            clause += f" (of which {len(zero_reach_stripped)} reached only the refused zero address)"
        missing.append(clause)
    if partially_priced:
        missing.append(f"{len(partially_priced)} entity(ies) holding assets the priced sheet does not cover")
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
        + " — a ceiling does not become a floor "
        f"by being summed, {untightened}; " + ", ".join(missing) + " leave the sum short of a ceiling on the row too"
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
    """The basis for a row with a coverage gap and no ceiling figures.

    The gap makes a floor only if every contribution is also proven free of an upper-bounding witness; otherwise the row
    bounds in neither direction. Both arms count unanswered instances and partly priced entities.
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
        # Counted from the failed membership test: not proven free of an upper-bounding witness (attribution-derived or
        # a withheld ceiling label).
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
    """Every token of a closed vocabulary, zeros included, so "didn't fire" and "not in the model" differ.

    Unknown tokens are counted too.
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
    """Sheet-ceiling population and dollars for the protocol, derived from what rows published (not from branch
    firings, which include displaced candidates). Dollars sum over distinct entities (two rows pricing one node
    would double it); disagreeing rows are counted. ``signals_credited_in_confidence`` is a different unit
    (signals, not entities).
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
                # One refusal per call.
                refused[reason].add((str(gap.get("entity")), str(gap.get("function"))))
    disagreeing = sorted(key for key, seen in figures.items() if len(seen) > 1)
    # An entity reached by two code-control capabilities appears in both buckets; counted so buckets aren't summed.
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
    # Dollars are deduped, the capability breakdown isn't; the reading says so.
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
        + ". The dollars are an AT-MOST and never an amount: they bound what replacing each "
        "node's code can move AT THAT NODE, they say nothing about what those nodes in turn "
        "govern, and they are deliberately outside exposure_usd — an upper bound on a move "
        "nobody witnessed is not expected loss, and charging one would displace a row that "
        "measured a real extraction. They must never be rendered as dollars at risk"
    )
