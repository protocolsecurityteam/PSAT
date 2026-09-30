from __future__ import annotations

from collections import defaultdict
from typing import Any

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.fold.gates import SINGLE_ASSET_CLASSES, _gate, _signal_identity
from services.scoring.schema import FunctionSignal, entity_key
from utils.scoring_status import OPENNESS_OPEN, PRINCIPAL_STATE_ENUMERATED, VALUE_STATE_PROVEN_REACH


def _entities_outside_perimeter(
    signals: list[FunctionSignal],
    answered: dict[str, list[int]],
    perimeter: dict[str, float],
    value_plane: P.ValuePlane,
) -> list[str]:
    """Deployment and reach keys the confidence denominator never asked about.

    Closure-added keys are in the perimeter by construction, so only witnessed keys can fall outside. The zero address
    has its own admission count and isn't reported.
    """
    outside = {key for key in answered if key not in perimeter}
    for signal in signals:
        for raw in signal.value_entity_keys:
            key = value_plane.canonical(raw)
            if key not in perimeter and not P.is_zero_key(key):
                outside.add(key)
    return sorted(outside)


# The three ways the reach-magnitude term counts a signal as answered. Named separately because they are proofs of
# different strength.
CREDIT_PATH_OWN = "own_call_witness"


CREDIT_PATH_COMPOSED = "composed_destination_witness"


CREDIT_PATH_SHEET_CEILING = "sheet_ceiling"


_CREDIT_PATH_CLAUSES = {
    CREDIT_PATH_OWN: "a witness on the signal's OWN call, which measures what that call moves",
    CREDIT_PATH_COMPOSED: (
        "the DESTINATION function's own flow.out witness, COMPOSED along a path every hop of "
        "which carries an act-as witness — the same kind of answer reached through one more "
        "join, itemised per row under reach_composed_magnitudes"
    ),
    CREDIT_PATH_SHEET_CEILING: (
        "the controlled node's own priced SHEET, which bounds the move from ABOVE and never "
        "measures it: replacing that node's code leaves none of that node's code between the "
        "principal and what it holds, so at-most-what-is-there is proven without a call being "
        "witnessed at all, itemised per row under reach_sheet_ceiling_magnitudes"
    ),
}


def _credit_path_reading(counts: dict[str, int]) -> str:
    """How the answered population splits across the three credit paths.

    Every path is named even at zero so "didn't fire" is distinguishable from "doesn't exist".
    """
    parts = [f"{counts.get(path, 0)} from {clause}" for path, clause in _CREDIT_PATH_CLAUSES.items()]
    return (
        "an answer counts here from any of THREE witnesses, and the population splits "
        + "; ".join(parts)
        + ". They are not equally strong and are counted apart so a consumer can subtract "
        "whichever of them it does not want to credit"
    )


def _mixed_witness_cause(mixed: int, composed: int, ceiling: int, fold_only: int) -> str:
    """What put entities in the mixed population, as counts, so a mechanism that didn't fire isn't implied.

    The empty case still names entities mixed by their own witnesses.
    """
    if not mixed:
        return (
            "No entity is in this population, so the edge has no carriers here — a measured "
            "zero and not an absence of the shape"
        )
    if not composed and not ceiling:
        return (
            f"None of the {mixed} entity(ies) here was put in this population by an answer the "
            "FOLD supplied: every one of them carries a witness on some of its own calls and "
            "none on others, which is the edge in its plainest form"
        )
    return (
        f"Of the {mixed} entity(ies) here, {composed} carry a COMPOSED destination witness and "
        f"{ceiling} a SHEET CEILING — answers the fold supplied rather than the signal — and "
        f"{fold_only} of them carry no call witness of their own at all, so for those the "
        "fold's own answer is the only thing that moved them off 0/n and is what put them in "
        "this population"
    )


def _confidence(
    signals: list[FunctionSignal],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    proven_eoas: set[str],
    discovery_entities: dict[str, set[str]] | None = None,
    composed_signals: set[tuple[Any, ...]] | None = None,
    ceiling_signals: set[tuple[Any, ...]] | None = None,
) -> dict[str, Any]:
    """Monotone in resolution work: the denominator is the perimeter.

    The perimeter is the protocol's ``contracts`` rows plus the value plane and the control closure. Discovery fixes it,
    so losing analysis can't raise confidence. ``discovery_entities`` adds every endpoint of every discovered relation,
    walked or not, so declining a relation can only charge confidence (inv. 6). The headline is the minimum of four
    terms: reachability, capability, pricing, and reach magnitude.

    Reach magnitude counts a proven reach with no proven magnitude as unanswered. Its denominator is the whole
    perimeter, the only shape monotone under lost work. ``ceiling_signals`` is the third credit path (sheet ceilings),
    used as the fold built it: only ceilings that are the standing published figure, ties included.

    Keys go through ``value_plane.canonical`` so an implementation doesn't get a second copy of its proxy's band. The
    zero address is excluded. A proven-codeless entity answers reach and capability vacuously but not pricing.
    """
    perimeter: dict[str, float] = {}
    folded: set[str] = set()
    zero_excluded: set[str] = set()

    def admit(raw: str) -> None:
        if P.is_zero_key(raw):
            zero_excluded.add(raw)
            return
        key = value_plane.canonical(raw)
        if key != raw:
            folded.add(raw)
        perimeter.setdefault(key, K.band(value_plane.total(key)))

    for key in sorted(value_plane.contract_entities):
        admit(key)
    for key in sorted(value_plane.per_asset):
        admit(key)
    for key in closure.principals():
        admit(key)
        for controlled in closure.controlled_by(key):
            admit(controlled)
    # Below here is what discovery proved exists, counted per relation against the walked base.
    walked = set(perimeter)
    discovery = discovery_entities or {}
    discovery_admitted: dict[str, int] = {}
    for relation in sorted(discovery):
        keys = sorted(discovery[relation])
        for key in keys:
            admit(key)
        discovery_admitted[relation] = len(
            {value_plane.canonical(key) for key in keys if not P.is_zero_key(key)} - walked
        )
    denominator = round(sum(sorted(perimeter.values())), 6)

    reach: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    scored: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    priced: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    magnitude: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    magnitude_census: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    composed_census: dict[str, int] = defaultdict(int)
    ceiling_census: dict[str, int] = defaultdict(int)
    # Counted directly rather than as a residual, so a broken exclusivity assumption would show.
    own_witness_signals = 0
    # Per key, so the mixed-entity reading can name its cause.
    credit_paths_by_key: dict[str, set[str]] = defaultdict(set)
    for signal in signals:
        key = value_plane.canonical(entity_key(signal.chain, signal.deployment_address))
        answered = (
            signal.authority_openness == OPENNESS_OPEN
            or signal.principal_state == PRINCIPAL_STATE_ENUMERATED
            or _gate(signal, "exact_empty_credit").is_determined
        )
        reach[key][1] += 1
        scored[key][1] += 1
        if answered:
            reach[key][0] += 1
        if answered and signal.enters_grade:
            scored[key][0] += 1
        if signal.claim_id == "flow.out":
            # Unpriceable reach is a real gap; omitting it would make unpriceable value free.
            priced[key][1] += 1
            asset_class = _gate(signal, "asset_class")
            decidable = not _gate(signal, "token_identity").is_determined and (
                not asset_class.is_determined
                or asset_class.value not in SINGLE_ASSET_CLASSES
                or _gate(signal, "asset_identity").is_determined
            )
            if decidable and value_plane.total(key) is not None:
                priced[key][0] += 1
        if signal.value_state == VALUE_STATE_PROVEN_REACH:
            # The reach-magnitude term. Every proven-reach signal is in the denominator (a per-capability exclusion list
            # was removed: dropping signals raised the term).
            #
            # A signal is answered by its own witness, a composed destination witness, or a sheet ceiling (an at-most
            # bound from a balance observation, so not vacuous). Paths are tried in fixed order and each signal takes at
            # most one, so the counters partition the answered set. Credit is per signal: one composed of two reaches is
            # 1/2.
            own = _gate(signal, "reach_magnitude_usd").is_determined
            identity = _signal_identity(signal)
            by_composition = not own and identity in (composed_signals or set())
            by_ceiling = not own and not by_composition and identity in (ceiling_signals or set())
            magnitude[key][1] += 1
            magnitude_census[signal.claim_id][1] += 1
            if own or by_composition or by_ceiling:
                magnitude[key][0] += 1
                magnitude_census[signal.claim_id][0] += 1
                if by_composition:
                    composed_census[signal.claim_id] += 1
                    credit_paths_by_key[key].add(CREDIT_PATH_COMPOSED)
                elif by_ceiling:
                    ceiling_census[signal.claim_id] += 1
                    credit_paths_by_key[key].add(CREDIT_PATH_SHEET_CEILING)
                else:
                    own_witness_signals += 1
                    credit_paths_by_key[key].add(CREDIT_PATH_OWN)

    def weighted(table: dict[str, list[int]]) -> float:
        total = 0.0
        for key in sorted(table):
            answered, seen = table[key]
            if seen and key in perimeter:
                total += perimeter[key] * (answered / seen)
        return round(total, 6)

    codeless_answered = sorted(key for key in perimeter if key in proven_eoas and not scored.get(key, [0, 0])[1])
    for key in codeless_answered:
        reach[key] = [1, 1]
        scored[key] = [1, 1]
        # Codeless means no capability and no magnitude to witness: a vacuous answer, disclosed as
        # ``reach_magnitude_vacuous_credit_pct``. Pricing still stands alone.
        magnitude[key] = [1, 1]

    outside = _entities_outside_perimeter(signals, reach, perimeter, value_plane)
    reach_pct = round(100.0 * weighted(reach) / denominator, 1) if denominator else 0.0
    capability_pct = round(100.0 * weighted(scored) / denominator, 1) if denominator else 0.0
    priced_weight = sum(perimeter[k] for k in sorted(perimeter) if value_plane.total(k) is not None)
    priced_pct = round(100.0 * priced_weight / denominator, 1) if denominator else 0.0
    magnitude_pct = round(100.0 * weighted(magnitude) / denominator, 1) if denominator else 0.0
    # The best this term could reach, separating unwitnessed magnitude from perimeter no signal covered.
    magnitude_ceiling = sum(perimeter[k] for k in sorted(magnitude) if magnitude[k][1] and k in perimeter)
    magnitude_ceiling_pct = round(100.0 * magnitude_ceiling / denominator, 1) if denominator else 0.0
    # Vacuous (codeless) credit is published beside the headline so EOAs don't read as answered magnitude.
    vacuous = {key for key in codeless_answered if key in perimeter}
    vacuous_weight = sum(perimeter[key] for key in sorted(vacuous))
    vacuous_pct = round(100.0 * vacuous_weight / denominator, 1) if denominator else 0.0
    reaching = [key for key in sorted(magnitude) if key not in vacuous and magnitude[key][1] and key in perimeter]
    reaching_weight = sum(perimeter[key] for key in reaching)
    reaching_answered = sum(perimeter[key] * (magnitude[key][0] / magnitude[key][1]) for key in reaching)
    witnessed_of_reaching_pct = round(100.0 * reaching_answered / reaching_weight, 1) if reaching_weight else 0.0
    # From the census, since the weighted table includes codeless entities.
    signals_seen = sum(v[1] for v in magnitude_census.values())
    signals_witnessed = sum(v[0] for v in magnitude_census.values())
    # Known monotonicity edge: deleting an unwitnessed signal at a mixed entity (e.g. 1/2 to 1/1) raises the term.
    # Waived: all four terms share this per-entity fraction shape, and any posed-questions denominator has it. Instead
    # the exposure is sized: the largest single-deletion gain and the all-deletions gain, with counts of which fold
    # answer (composed or ceiling) created the mixed entities.
    mixed = [key for key in sorted(magnitude) if key not in vacuous and 0 < magnitude[key][0] < magnitude[key][1]]
    single_gain = total_gain = 0.0
    for key in mixed:
        answered, seen = magnitude[key]
        weight = perimeter.get(key, 0.0)
        if seen > 1:
            single_gain = max(single_gain, weight * answered / (seen * (seen - 1)))
        total_gain += weight * (1.0 - answered / seen)
    mixed_single_pct = round(100.0 * single_gain / denominator, 2) if denominator else 0.0
    mixed_total_pct = round(100.0 * total_gain / denominator, 2) if denominator else 0.0
    mixed_paths = {key: credit_paths_by_key.get(key, set()) for key in mixed}
    mixed_composed = sum(1 for paths in mixed_paths.values() if CREDIT_PATH_COMPOSED in paths)
    mixed_ceiling = sum(1 for paths in mixed_paths.values() if CREDIT_PATH_SHEET_CEILING in paths)
    # Entities moved off 0/n only by a fold-supplied answer; tested directly, not inferred.
    mixed_fold_only = sum(1 for paths in mixed_paths.values() if paths and CREDIT_PATH_OWN not in paths)
    return {
        "pct": min(reach_pct, capability_pct, priced_pct, magnitude_pct),
        "reachability_answered_pct": reach_pct,
        "capability_scored_pct": capability_pct,
        "value_priced_pct": priced_pct,
        "reach_magnitude_witnessed_pct": magnitude_pct,
        "reach_magnitude_ceiling_pct": magnitude_ceiling_pct,
        # Same units as the term, so ``witnessed_pct - vacuous_credit_pct`` is the witness-backed share.
        "reach_magnitude_vacuous_credit_pct": vacuous_pct,
        # No vacuous credit in this one.
        "reach_magnitude_witnessed_of_reaching_pct": witnessed_of_reaching_pct,
        "reach_magnitude_signals": {
            "proven_reach_in_denominator": signals_seen,
            "magnitude_witnessed": signals_witnessed,
            # Composed answers, published apart so a reader can subtract them from own-call coverage.
            "magnitude_composed": sum(composed_census.values()),
            "composed_by_capability": {k: v for k, v in sorted(composed_census.items())},
            # Sheet-ceiling answers carry no call witness and are a weaker claim, so they're published apart. Not the
            # same as reach_magnitude_ceiling_pct (the term's headroom).
            "magnitude_sheet_ceiling": sum(ceiling_census.values()),
            "sheet_ceiling_by_capability": {k: v for k, v in sorted(ceiling_census.items())},
            "credit_path_reading": _credit_path_reading(
                {
                    CREDIT_PATH_OWN: own_witness_signals,
                    CREDIT_PATH_COMPOSED: sum(composed_census.values()),
                    CREDIT_PATH_SHEET_CEILING: sum(ceiling_census.values()),
                }
            ),
            "by_capability": {k: v for k, v in sorted(magnitude_census.items())},
            "mixed_witness_entities": len(mixed),
            "mixed_witness_entities_with_a_fold_supplied_answer": {
                CREDIT_PATH_COMPOSED: mixed_composed,
                CREDIT_PATH_SHEET_CEILING: mixed_ceiling,
                "no_own_call_witness_at_all": mixed_fold_only,
            },
            # Size of the monotonicity edge: max gain from deleting one unwitnessed signal, and from deleting all of
            # them at mixed entities.
            "mixed_witness_max_single_deletion_gain_pct": mixed_single_pct,
            "mixed_witness_total_deletion_gain_pct": mixed_total_pct,
            "mixed_witness_reading": (
                "entities carrying BOTH an answered and an unanswered proven reach. The term "
                "is a per-entity fraction, so deleting an unanswered signal from one of these "
                "raises it — a monotonicity edge this model does not close, published rather "
                "than hidden, because every denominator that closes it charges a signal for a "
                "magnitude it does not owe. It is not this term's shape alone: the "
                "reachability and capability terms are the same fraction over the same "
                "population and move the same way. The two gain figures beside this bound the "
                "exposure in the term's own units, so a reader can see what the edge is worth "
                "rather than only that it exists. "
                + _mixed_witness_cause(len(mixed), mixed_composed, mixed_ceiling, mixed_fold_only)
            ),
            "denominator_rule": (
                "EVERY proven-reach signal, with no per-capability exclusions: a capability "
                "that publishes proven_reach is claiming it moves value, so 'how much' is a "
                "question it owes an answer to. The freeze fraction (pause.set) is in the "
                "denominator and unanswered by design until a witness for it exists. On the "
                "numerator side there is no single witness class either: "
                + _credit_path_reading(
                    {
                        CREDIT_PATH_OWN: own_witness_signals,
                        CREDIT_PATH_COMPOSED: sum(composed_census.values()),
                        CREDIT_PATH_SHEET_CEILING: sum(ceiling_census.values()),
                    }
                )
            ),
        },
        "flow_pricing_decidable": {k: v for k, v in sorted(priced.items()) if v[1]},
        "perimeter_entities": len(perimeter),
        # Entities a signal answers for or reaches into that the denominator never asked about. Should be empty;
        # non-empty is a discovery gap.
        "signal_entities_outside_perimeter": outside,
        "perimeter_value_weighted_denominator": denominator,
        # Each admission rule is counted where it fired.
        "implementation_entities_folded": len(folded),
        "zero_address_entities_excluded": len(zero_excluded),
        "proven_codeless_answered": len(codeless_answered),
        "discovery_relation_entities_admitted": discovery_admitted,
        "headline_rule": "report the MINIMUM; any larger figure over-claims",
        "monotonicity": (
            "the denominator is the protocol's contracts rows unioned with the value "
            "plane, the walked control closure and every endpoint of every authority "
            "relation discovery recorded — walked or not — folded through the "
            "discovery-fixed implementation alias map, and built without reference to "
            "the signal population, so analysis work can only move value from "
            "unanswered to answered and declining to walk a relation can only charge "
            "confidence, never free it"
        ),
    }
