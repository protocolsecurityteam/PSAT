"""The confidence term."""

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
    """Deployment AND reach keys the confidence denominator never asked about.

    A signal answers questions about the entity it was distilled on, and it
    charges value against the entities it REACHES. Checking only the first left
    a reach key that no denominator accounts for invisible to the disclosure
    that exists to name it — value carried into a finding by an entity whose
    unanswered weight is nowhere. The keys the closure walk ADDS to a reach are
    admitted to the perimeter by construction (every principal and everything it
    controls), so the witnessed keys are the ones that can fall outside. The zero
    address is refused by an admission rule with its own published count, so its
    absence is a decision rather than a gap and it is not reported here.
    """
    outside = {key for key in answered if key not in perimeter}
    for signal in signals:
        for raw in signal.value_entity_keys:
            key = value_plane.canonical(raw)
            if key not in perimeter and not P.is_zero_key(key):
                outside.add(key)
    return sorted(outside)


# The three ways the reach-magnitude term counts a signal as ANSWERED, as
# tokens, so the reading below is assembled from the same names the loop counts
# under. Each clause states which evidence supplied the answer, because that is
# the fact a consumer subtracting one class from the term needs: they are three
# different proofs of three different strengths and one word for all of them
# ("witnessed") is what made the split necessary in the first place.
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

    Every registered path is named whatever it counted, including zero. A clause
    dropped for having no carriers would leave a reader unable to tell a path
    that did not fire on this corpus from one this model does not have, and the
    counts are the whole point of publishing the split.
    """
    parts = [f"{counts.get(path, 0)} from {clause}" for path, clause in _CREDIT_PATH_CLAUSES.items()]
    return (
        "an answer counts here from any of THREE witnesses, and the population splits "
        + "; ".join(parts)
        + ". They are not equally strong and are counted apart so a consumer can subtract "
        "whichever of them it does not want to credit"
    )


def _mixed_witness_cause(mixed: int, composed: int, ceiling: int, fold_only: int) -> str:
    """What put entities in the mixed population, counted rather than asserted.

    An answer the FOLD supplied is what turns a 0/n entity into a mixed one, and
    there are now two of those. The sentence names the counts of each because
    naming only the mechanism would keep reading as though both fired on a corpus
    where one of them has no carriers. The empty case is an earned negative: the
    edge exists on its own, from entities that carry a call witness of their own
    at some signals and not at others, and saying so is a different fact from
    saying nothing.
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
    """Monotone in resolution work: the denominator is the PERIMETER.

    The perimeter's base population is the protocol's ``contracts`` rows, unioned
    with the value plane and the control closure. Discovery fixes that base, so it
    does not move with what has been analysed — losing a contract's signals cannot
    drop its unanswered weight out of its own denominator — while an unpriced
    contract outside the closure still carries ``band(None)`` of unanswered
    weight rather than vanishing. Seeding it from the signal population instead
    is what let LESS analysis publish MORE confidence. Four figures, and the
    headline is the MINIMUM — knowing who can call something, knowing what it
    does, being able to price what it reaches, and knowing HOW MUCH the reach
    moves are different questions.

    The closure the scorer WALKS is a subset of the relations discovery proved
    exist, so seeding the perimeter from the walked closure alone let declining a
    relation FREE confidence: the entities that relation proved are principals of
    gated functions never entered the denominator. ``discovery_entities`` carries
    every endpoint of every relation in the DB's own authority vocabulary, walked
    or not, so declining one charges confidence and can never relieve it (inv. 6).

    The fourth term is the honest home for an unproven magnitude. A signal that
    proved reach but not how much value that reach moves is UNANSWERED here — the
    unknown that otherwise has nowhere to land but the grade. Its denominator is
    the whole perimeter, exactly as the reachability and capability terms', which
    is the only shape monotone under losing work: an entity whose signals vanish
    contributes zero either way, while a denominator scoped to entities that
    happen to carry a signal would RISE when a signal is lost.

    ``ceiling_signals`` is the fold's OTHER answer to the magnitude question and
    the THIRD credit path: the signals whose controlled node was priced from its
    own SHEET. It is consumed exactly as the fold built it and is never
    re-derived here — a second derivation of "which signals got an answer" is
    precisely what drifts from the rows that publish one.

    What that population IS matters as much as that it is credited. It is
    per-entity and STANDING: the signals whose sheet ceiling is the figure the
    row actually publishes at that entity. A ceiling a larger contribution
    displaced is not in it, and neither is one the per-key sheet reconciliation
    withdrew, so every credited answer has a carrier in the published document
    rather than a number the fold computed and then discarded. Ties keep their
    credit — several calls on one node read the same sheet and each of them
    proved the figure the row publishes — and only a ceiling strictly beaten
    loses it.

    Every key is admitted through ``value_plane.canonical``: an implementation
    is the same entity as the proxy that deploys it, and admitting both hands
    the impl a second copy of the proxy's value band that no signal can ever
    answer (signals are distilled at the proxy address). The alias map comes
    from the same discovery-fixed ``contracts`` rows as the base population, so
    folding through it keeps the denominator independent of analysis. The zero
    address is excluded outright — it is a burn sentinel, not an assessable
    entity (``msg.sender != 0x0``). A perimeter entity proven codeless
    (``resolved_type == 'eoa'``, earned from an empty ``eth_getCode``) has no
    capability surface to leave unanswered: its reach and capability terms are
    vacuously answered, while its pricing term is untouched — holding value is
    a question code-lessness does not answer.
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
    # Everything above is what the scorer WALKED. Everything below is what
    # discovery PROVED exists, per relation — counted against the walked base so
    # each relation's own contribution is visible rather than assigned to
    # whichever relation happened to be admitted first.
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
    # Counted rather than subtracted. The three credit paths are exclusive by the
    # order they are tried below, and a count taken directly cannot report a
    # population that an arithmetic residual would silently absorb if that ever
    # stopped being true.
    own_witness_signals = 0
    # Which of the three paths answered at each entity, so the mixed-entity
    # reading below can say what put an entity in that population instead of
    # asserting a cause. Kept per key because "mixed" is a per-entity fact.
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
            # The pricing term: an unpriceable reach is a real gap in what the
            # grade could measure, and leaving it out of confidence would make
            # unpriceable value free.
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
            # The reach-magnitude term. A proven reach whose magnitude has no
            # witness is the unknown that otherwise lands in the grade as the
            # entity's whole balance sheet; here it lands as UNANSWERED, which is
            # the only place it can sit without being published as a number.
            #
            # EVERY proven-reach signal is in the denominator. A per-capability
            # exclusion list was tried and removed: a capability that publishes
            # proven_reach is claiming it can move value, and its only live effect
            # was on entities carrying both an excluded and an admitted signal,
            # where dropping the excluded one RAISED the term by discarding a real
            # unanswered question — the shape this term exists to stop.
            #
            # A magnitude the fold COMPOSED counts as answered here on the same
            # terms as one the signal carried itself: the answer is a witness
            # either way (the destination function's own flow.out figure), and
            # the whole point of composing it is that the question stops being
            # open. It is counted separately below so a reader can see which of
            # the two supplied it, and composed answers are recorded per signal
            # rather than per entity — an entity carrying two proven reaches of
            # which one composed is 1/2 answered, not answered.
            #
            # A SHEET CEILING is the third path, credited on the same terms and
            # counted apart for the same reason. "How much can this reach move"
            # has been given a proven bound — the controlled node's own priced
            # holdings, which bound it because the code that would have stood in
            # the way is the code the principal can replace — and a question
            # answered with an at-most is not the same as one nobody answered.
            # The credit is NOT vacuous: unlike the codeless credit below it
            # rests on a balance observation, which is why it moves the witnessed
            # term without moving the vacuous share published beside it.
            #
            # The three paths are tried in a fixed order and each signal takes at
            # most one, so the three counters partition the answered population
            # instead of overlapping it. Composition and the sheet ceiling are
            # disjoint by construction anyway — one fires only for gate control
            # and the other only for code control — and the order is what keeps
            # that a property of this loop rather than of a rule elsewhere.
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
        # No code is no capability, and no capability moves no value: there is no
        # reach magnitude here to leave unwitnessed. Same earned getCode witness,
        # same VACUOUS answer — counted in the term and disclosed separately as
        # ``reach_magnitude_vacuous_credit_pct``, because a vacuous answer is not
        # a witness. The pricing term still stands alone.
        magnitude[key] = [1, 1]

    outside = _entities_outside_perimeter(signals, reach, perimeter, value_plane)
    reach_pct = round(100.0 * weighted(reach) / denominator, 1) if denominator else 0.0
    capability_pct = round(100.0 * weighted(scored) / denominator, 1) if denominator else 0.0
    priced_weight = sum(perimeter[k] for k in sorted(perimeter) if value_plane.total(k) is not None)
    priced_pct = round(100.0 * priced_weight / denominator, 1) if denominator else 0.0
    magnitude_pct = round(100.0 * weighted(magnitude) / denominator, 1) if denominator else 0.0
    # The share of the denominator this term could reach at its best: every entity
    # already answered vacuously, plus every reach-carrying entity if all of its
    # proven reaches carried a magnitude witness. Without it a consumer cannot
    # tell how much of the gap is unwitnessed magnitude from how much is perimeter
    # the signal population never covered — two different pieces of work.
    magnitude_ceiling = sum(perimeter[k] for k in sorted(magnitude) if magnitude[k][1] and k in perimeter)
    magnitude_ceiling_pct = round(100.0 * magnitude_ceiling / denominator, 1) if denominator else 0.0
    # Most of this term can be VACUOUS: a proven-codeless entity answers it with
    # no magnitude witness at all. Publishing the headline alone would let a
    # perimeter full of EOAs read as answered magnitude, so the vacuous share is
    # published beside it (term minus this is the witness-backed share of the
    # denominator) together with the witnessed share of the weight that actually
    # carries a proven reach — the figure that only rises when W3/W4b do work.
    vacuous = {key for key in codeless_answered if key in perimeter}
    vacuous_weight = sum(perimeter[key] for key in sorted(vacuous))
    vacuous_pct = round(100.0 * vacuous_weight / denominator, 1) if denominator else 0.0
    reaching = [key for key in sorted(magnitude) if key not in vacuous and magnitude[key][1] and key in perimeter]
    reaching_weight = sum(perimeter[key] for key in reaching)
    reaching_answered = sum(perimeter[key] * (magnitude[key][0] / magnitude[key][1]) for key in reaching)
    witnessed_of_reaching_pct = round(100.0 * reaching_answered / reaching_weight, 1) if reaching_weight else 0.0
    # Counted off the census, not off the weighted table: the table also carries
    # the vacuous credit for proven-codeless entities, which are not signals.
    signals_seen = sum(v[1] for v in magnitude_census.values())
    signals_witnessed = sum(v[0] for v in magnitude_census.values())
    # The term is a per-entity FRACTION, so an entity carrying one witnessed and
    # one unwitnessed proven reach sits at 1/2 — and removing the unwitnessed
    # signal moves it to 1/1, RAISING the term for having proven less.
    #
    # RE-EXAMINED at W4b and WAIVED again, now with a measured bound instead of
    # an argument. Two facts decided it. First, the shape is not this term's: all
    # four terms are the same per-entity answered/seen fraction over the same
    # signal population, so deleting an unanswered signal raises the
    # reachability and capability terms identically — it is a property of the
    # model's shape, and closing it here alone would leave the headline (a MIN
    # over the four) moving on the others anyway. Second, no denominator closes
    # it: every ratio whose denominator counts only the questions that were POSED
    # rises when an unanswered one is deleted, and a denominator that does not
    # shrink would have to count magnitude questions an entity owes independently
    # of its signals — a population nothing in the schema supplies. Denominating
    # over signals rather than entities (the alternative named in the W3 review)
    # has the identical algebra and additionally breaks the min() comparability
    # with the other three terms.
    #
    # So the exposure is SIZED and published rather than closed. An answer the
    # FOLD supplied — a composed destination witness or a sheet ceiling — widens
    # it, because that is what turns a 0/n entity into a mixed one, and the two
    # figures below say by exactly how much: the largest single deletion that
    # could move the term, and the move if every unwitnessed signal at every
    # mixed entity vanished at once. Which of the two did it is MEASURED rather
    # than asserted: the reading names the counts, so a corpus where only one of
    # them fires does not read as though both did.
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
    # The entities the fold's own answer is the ONLY thing that moved off 0/n:
    # no signal at them carried a magnitude witness of its own, so without the
    # composed figure or the sheet ceiling they would not be in this population
    # at all. A stronger claim than "carries a fold-supplied answer" and the one
    # worth publishing, so it is tested rather than inferred from the counts.
    mixed_fold_only = sum(1 for paths in mixed_paths.values() if paths and CREDIT_PATH_OWN not in paths)
    return {
        "pct": min(reach_pct, capability_pct, priced_pct, magnitude_pct),
        "reachability_answered_pct": reach_pct,
        "capability_scored_pct": capability_pct,
        "value_priced_pct": priced_pct,
        "reach_magnitude_witnessed_pct": magnitude_pct,
        "reach_magnitude_ceiling_pct": magnitude_ceiling_pct,
        # Both in the same units as the term (share of the perimeter denominator),
        # so ``witnessed_pct - vacuous_credit_pct`` is the witness-backed share.
        "reach_magnitude_vacuous_credit_pct": vacuous_pct,
        # Of the perimeter weight that actually carries a proven reach, the share
        # whose magnitude is witnessed. No vacuous credit is in this figure.
        "reach_magnitude_witnessed_of_reaching_pct": witnessed_of_reaching_pct,
        "reach_magnitude_signals": {
            "proven_reach_in_denominator": signals_seen,
            "magnitude_witnessed": signals_witnessed,
            # Of those, the ones answered by COMPOSING the destination
            # function's witness rather than by a witness on the signal's own
            # call. Published apart because they are the same kind of answer
            # arrived at through one more join, and a reader sizing the
            # pipeline's own magnitude coverage needs to be able to subtract
            # them.
            "magnitude_composed": sum(composed_census.values()),
            "composed_by_capability": {k: v for k, v in sorted(composed_census.items())},
            # The THIRD answer, counted apart from both for the reason the
            # composed one is: it carries no call witness at all. The controlled
            # node's own priced sheet bounds the move from above, which is a
            # different and weaker claim than either of the other two, so a
            # reader sizing what the pipeline MEASURED has to be able to
            # subtract it. The name says which ceiling this is —
            # reach_magnitude_ceiling_pct beside it is the term's HEADROOM and
            # is a different quantity entirely.
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
            # The size of the monotonicity edge below, in the term's own units.
            # The first is the most the term could rise from deleting ONE
            # unwitnessed proven-reach signal; the second from deleting every
            # unwitnessed signal at every mixed entity.
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
        # Entities a signal answers FOR or reaches INTO that the denominator
        # never asked about, so the work is invisible to this figure and, for a
        # reach key, the value is charged into a finding while its own
        # unanswered weight sits in no denominator. With the contracts base
        # population this should be empty; a non-empty list is a discovery gap,
        # published rather than absorbed.
        "signal_entities_outside_perimeter": outside,
        "perimeter_value_weighted_denominator": denominator,
        # Each admission rule, counted where it fired, so a consumer can see
        # what the denominator folded or refused rather than inferring it.
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
