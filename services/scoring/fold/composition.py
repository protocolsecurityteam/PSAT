"""Cross-contract composition: ordering, selection, admission, the engine, and its report."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any, cast

from services.scoring import planes as P
from services.scoring.fold.ceilings import _asset_coverage
from services.scoring.fold.closure import ACT_AS_CALLER_UNREACHED
from services.scoring.fold.gates import _gate, _is_number, _signal_execution
from services.scoring.fold.readings import (
    _BOUNDED_BY_SHEET,
    _BOUNDED_BY_WITNESS,
    _COMPOSED_SOURCE_READINGS,
    _DISPOSED_SHEET_DOES_NOT_BOUND,
    _ORDER_COMPONENT_NAMES,
    _TRIMMED_TO_AN_UNPROVEN_CEILING,
    _WITNESS_STATE_CLAIM,
    _WITNESS_STATE_UNRANKED,
    ARM_GATE_ONLY,
    ARM_NOT_DETERMINED,
    ARM_REPUBLISHED_DIRECT,
    ARM_WITHHELD,
    BOUND_DIRECTION_CEILING,
    BOUND_DIRECTION_NOT_DETERMINED,
    COMPOSITION_ARMS,
    SHEET_BOUND_REFUSED_BY_DISPOSITION,
    _round_published,
    _sheet_ceiling_direction_basis,
)
from services.scoring.fold.types import (
    _AdmissionPlanes,
    _DestinationMagnitude,
    _gate_claim,
    _WalkedHop,
    _WithheldComposition,
)
from services.scoring.schema import FunctionSignal, entity_key
from utils import claim_ids as C
from utils import execution_record as EX


@dataclass(frozen=True)
class _ComposedMagnitude:
    """A destination function's own magnitude witness, reached along a witnessed path.

    ``tied_with`` is the other candidates at the same figure that :func:`_composed_order` passed over; empty publishes
    as ``composed_selector_tie: null``. ``predicates`` has no default because the lookup is three-state and a default
    would merge "nobody asked" with "no function carries that selector".
    """

    entity: str
    selector: str
    function: str
    witness_state: str
    witnessed_usd: float
    usd: float
    sheet_usd: float | None
    chain: tuple[P.ActAsStep, ...]
    predicates: P.DestinationPredicates
    # No default: a published magnitude must carry the execution that proved it.
    execution: EX.ProvingExecution
    # Set only where a determined sheet exists but may not trim; "no number" (``sheet_not_determined``) and "a number
    # that doesn't answer" stay distinct.
    sheet_bound_refused: str | None = None
    # Read from the same :func:`_asset_coverage` the sheet-ceiling records use. ``None`` means nobody read coverage and
    # publishes ``not_determined``, never ``ceiling``: trimming onto an unproven ceiling silently turns a witnessed
    # magnitude into a floor.
    sheet_is_proven_complete: bool | None = None
    sheet_bound_direction_basis: str | None = None
    tied_with: tuple[_ComposedMagnitude, ...] = ()
    # Set by :func:`_admit_composed` after selection. A published entry is always ``republished_direct``; the other arms
    # withhold.
    arm_taken: str = ARM_NOT_DETERMINED
    deletability: P.DeletabilityVerdict | None = None
    route: P.RouteClassification | None = None

    def __post_init__(self) -> None:
        if (self.sheet_is_proven_complete is None) != (self.sheet_bound_direction_basis is None):
            raise ValueError("sheet coverage and its basis are read together and publish together")

    @property
    def sheet_bound_direction(self) -> str | None:
        """Whether the destination sheet proves an at-most on this entry's figure.

        A priced sheet that doesn't cover everything observed at the node is a floor, so the min against it stands as a
        figure but stops being called a ceiling.
        """
        if self.sheet_usd is None:
            return None
        return BOUND_DIRECTION_CEILING if self.sheet_is_proven_complete else BOUND_DIRECTION_NOT_DETERMINED

    def _chain_identity_gloss(self) -> str:
        """The fields the order's tail ranges over, read off the steps so the gloss stays exhaustive as steps grow
        fields.
        """
        fields = sorted({name for entry in (self, *self.tied_with) for step in entry.chain for name in step.as_json()})
        if not fields:
            return (
                "Its last component is every field each act_as_chain step publishes, and no "
                "candidate here publishes a step at all, so that component is empty on all of "
                "them and separates nothing"
            )
        return (
            "Its last component is EVERY field each act_as_chain step publishes — on these "
            "candidates " + ", ".join(fields) + " — taken from the step's own published shape "
            "rather than from a list written into this sentence, so the key stays total over "
            "the entry on the day a step publishes a new field"
        )

    def _chosen_by(self) -> str:
        """The rule, and the component that decided THIS tie (``None`` published as itself when nothing separated the
        candidates).
        """
        key = _composed_order(self)
        decided: dict[int, int] = defaultdict(int)
        unseparated = 0
        for other in self.tied_with:
            component = _first_differing_component(key, _composed_order(other))
            if component is None:
                unseparated += 1
            else:
                decided[component] += 1
        named = [
            f"{_ORDER_COMPONENT_NAMES[index]} (component {index + 1} of {len(key)}) against {hits} candidate(s)"
            for index, hits in sorted(decided.items())
        ]
        if not named:
            what_decided = (
                f"This order decides NOTHING here: every component of the key holds the same "
                f"value on all {unseparated} of them, so which one is published rests on the "
                f"order the candidates were built in and not on this rule"
            )
        else:
            what_decided = (
                "What decided it: "
                + "; ".join(named)
                + " — in each case the FIRST component on which this entry differs from that "
                "candidate. The components ahead of a deciding one hold the same value on every "
                "candidate in this tie and decided nothing, and the components behind it were "
                "never reached"
            )
            if unseparated:
                what_decided += (
                    f". It separates this entry from {unseparated} of them not at all — every "
                    "component of the key is equal there, so which of those is published rests "
                    "on the order the candidates were built in and not on this rule"
                )
        return (
            f"the total order at _composed_order, over the {len(self.tied_with) + 1} candidates "
            "this entity offered at the same published figure: "
            + "; then ".join(_ORDER_COMPONENT_NAMES)
            + ". "
            + self._chain_identity_gloss()
            + ". "
            + what_decided
        )

    def _tie_json(self) -> dict[str, Any] | None:
        if not self.tied_with:
            return None
        return {
            "tied_at_usd": _round_published(self.usd),
            "candidates": [
                {
                    "selector": entry.selector,
                    "destination_function": entry.function,
                    "witness_state": entry.witness_state,
                    "witnessed_usd": _round_published(entry.witnessed_usd),
                    "chosen": entry is self,
                }
                for entry in sorted((self, *self.tied_with), key=_composed_order)
            ],
            "chosen_by": self._chosen_by(),
            "reading": (
                "this entity carries more than one call at the same PUBLISHED figure, and "
                "which of them names the published selector, destination_function and "
                "act_as_chain is decided by that rule and not by evidence. The published "
                "dollars are the same under every one of them, so nothing about the figure "
                "rests on the choice — but the candidates are not therefore equally "
                "witnessed: witnessed_usd is each one's OWN flow.out figure and they can "
                "differ where the destination's sheet is what capped them to the same number. "
                "The witness state published is the WEAKEST of the tied candidates, so no "
                "exactness is claimed that a tied candidate does not support"
            ),
        }

    @property
    def bounded_by(self) -> str:
        """A property because the published ``reading`` derives from it; computing it twice lets them drift."""
        return (
            _BOUNDED_BY_WITNESS if self.sheet_usd is None or self.witnessed_usd <= self.sheet_usd else _BOUNDED_BY_SHEET
        )

    def _predicates_json(self) -> dict[str, Any]:
        found = self.predicates
        reading = (
            "the predicate texts extracted from the DESTINATION function's compiled body, "
            "published verbatim and in stored order so this entry's ceiling can be checked "
            "against the evidence rather than taken on the fold's word. Three things about "
            "them. (1) They are stored WITHOUT POLARITY: the same text is a require-condition "
            "in one function and a revert-condition in another, so nothing here can tell "
            "whether any one of them must hold or must not. (2) The scorer therefore EVALUATES "
            "NONE of them and no published figure, band, refusal or count is affected by any "
            "one of them — removing this block changes no number. (3) The list is not a list of "
            "unmet business conditions: it may include the authorization guard that this step's "
            "own act-as witness proves satisfied, and it may include transfer post-conditions "
            "and compiler or decompiler artefacts, all of which the extractor labels 'business' "
            "alike — which is why the label is not read and the list is not filtered. state is "
            "three-valued and the three are not "
            "interchangeable: 'extracted' is a read (count 0 under it means the extractor ran "
            "and found no predicate), 'column_holds_no_array' is an extraction that never ran, "
            "and 'destination_function_not_located' is a join that found no function of this "
            "entity under this selector — under the last two, descriptions is null and not an "
            "empty list, because nothing was read. function_name is the row the selector join "
            "landed on, published so a reader can check it against destination_function above "
            "rather than take the join on the fold's word"
        )
        return {
            "source": "effective_functions.conditions",
            "state": found.state,
            "function_id": found.function_id,
            # The joined row's name, not ``destination_function`` restated, so a disagreement between the two sources
            # stays visible.
            "function_name": found.function_name,
            "functions_matching_selector": found.functions_matching,
            "count": (None if found.descriptions is None else len(found.descriptions)),
            "entries_stored": found.entries_stored,
            "descriptions": (None if found.descriptions is None else list(found.descriptions)),
            "evaluated": False,
            "reading": reading,
        }

    def as_json(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "destination_function": self.function,
            "selector": self.selector,
            "proving_execution": self.execution.as_json(),
            "route_comparison": EX.route_comparison(
                self.execution,
                claimed_caller=self.chain[-1].caller if self.chain else None,
                claimed_target=self.chain[-1].destination if self.chain else None,
                claimed_selector=self.chain[-1].calling_selector if self.chain else None,
            ),
            "arm_taken": self.arm_taken,
            "gate_claim": _gate_claim(self.chain, self.execution),
            # Republished as this entry's route only where the deletability join proved the principal can author the
            # calldata; the basis names the proving row.
            "authority_deletability": (None if self.deletability is None else self.deletability.disclosure()),
            "route_classification": (None if self.route is None else self.route.as_json()),
            "flow_out_witness": {
                "state": self.witness_state,
                "usd": _round_published(self.witnessed_usd),
                "function": self.function,
                "entity": self.entity,
            },
            # The figure is entity-level: every selector at a vault carries the same number, so the pair isn't a
            # per-function decomposition.
            "witness_granularity": "entity",
            # Every dollar figure here takes the same rounding because the record publishes ordering/equality claims
            # across them; mixed rounding produces contradictions at sub-cent values.
            "destination_sheet_usd": (_round_published(self.sheet_usd) if self.sheet_usd is not None else None),
            "published_usd": _round_published(self.usd),
            # Not flow_out_witness.state, which says whether the destination figure is exact or a floor.
            "bounded_by": self.bounded_by,
            # Strictly "no number available"; a barred sheet publishes its bar separately.
            "sheet_not_determined": self.sheet_usd is None and self.sheet_bound_refused is None,
            "sheet_bound_refused": self.sheet_bound_refused,
            "destination_sheet_bound_direction": self.sheet_bound_direction,
            "destination_sheet_bound_direction_basis": (
                None if self.sheet_usd is None else self.sheet_bound_direction_basis
            ),
            "act_as_chain": [step.as_json() for step in self.chain],
            "act_as_chain_length": len(self.chain),
            "destination_predicates": self._predicates_json(),
            # ``null`` is the proven single-candidate case, not an unfilled field.
            "composed_selector_tie": self._tie_json(),
            "reading": (
                _COMPOSED_SOURCE_READINGS[self.bounded_by]
                + (f". {_DISPOSED_SHEET_DOES_NOT_BOUND}" if self.sheet_bound_refused else "")
                # Gated on the basis, which is null when nobody read coverage; the sentence would otherwise point
                # readers at an empty field.
                + (
                    f". {_TRIMMED_TO_AN_UNPROVEN_CEILING}"
                    if self.bounded_by == _BOUNDED_BY_SHEET
                    and self.sheet_bound_direction != BOUND_DIRECTION_CEILING
                    and self.sheet_bound_direction_basis is not None
                    else ""
                )
                + ". "
                "Every hop from the seized node to it carries "
                "its own act-as witness, in one of two admissible shapes named per step under "
                "witness_kind: "
                "the CALLER'S OWN state variable, read on-chain holding the next node, or — "
                "where the call site takes its callee as a parameter, so no storage of the "
                "caller CAN name it — the next node's OWN access-control list naming this "
                "caller as an accepted caller of that selector by an enumerated role. Beyond "
                "the first hop the calling function must also be one the previous hop "
                "admitted, matched on that function's own selector — compare each step's "
                "calling_selector against the selector of the step before it — because no hop "
                "inherits its predecessor's authority and a function name does not identify a "
                "function. Remove any one of those witnesses and this figure is not_determined. "
                "Two further blocks say what this entry does NOT rest on. "
                "composed_selector_tie, where more than one call at this entity carried the "
                "same published figure and a stated rule rather than evidence picked which of "
                "them names the fields above — null there is the proven 'one candidate, and "
                "the rule decided nothing', never an unasked question. And "
                "destination_predicates, the destination function's own stored condition "
                "texts, published verbatim and evaluated by nothing here"
            ),
        }


def _composed_order(entry: _ComposedMagnitude) -> tuple[Any, ...]:
    """The total, evidence-first order a composed candidate is chosen by.

    Dollars first and highest: two selectors at one entity are independent calls and a max of ceilings is a ceiling
    (unlike the lower-of-two rule in :func:`_destination_magnitudes`, which reconciles two distillations of one
    quantity). Ties then go to the weakest witness state, then an arbitrary but stated tail.

    The tail is each step's own :meth:`P.ActAsStep.as_json`, rendered to text, so the key stays total over everything
    the entry publishes even when steps gain fields; otherwise ties fall back to construction order. Rendered to text
    because the shape mixes nested objects and ``None``.
    """
    return (
        -entry.usd,
        _WITNESS_STATE_CLAIM.get(entry.witness_state, _WITNESS_STATE_UNRANKED),
        entry.selector,
        entry.function,
        # Equal calling selectors imply equal length.
        tuple(step.calling_selector or "" for step in entry.chain),
        tuple(tuple(sorted((key, repr(value)) for key, value in step.as_json().items())) for step in entry.chain),
    )


def _first_differing_component(chosen: tuple[Any, ...], other: tuple[Any, ...]) -> int | None:
    """The index of the component that decided ``chosen`` over ``other``, or ``None`` if the key doesn't separate
    them (they may still differ in unordered fields such as the execution).
    """
    for index, (mine, theirs) in enumerate(zip(chosen, other)):
        if mine != theirs:
            return index
    return None


def _select_composed(candidates: list[_ComposedMagnitude]) -> _ComposedMagnitude:
    """The one candidate published for an entity, carrying the ones it beat.

    The whole candidate is selected so selector, function, state, execution and chain stay one call's account.
    Candidates tied at the figure are retained so the entry can show the choice was by rule; those below it lost on
    evidence and are dropped.
    """
    ordered = sorted(candidates, key=_composed_order)
    best = ordered[0]
    tied = tuple(other for other in ordered[1:] if other.usd == best.usd)
    return replace(best, tied_with=tuple(replace(other, tied_with=()) for other in tied))


def _pool_composed(into: dict[str, list[_ComposedMagnitude]], published: dict[str, _ComposedMagnitude]) -> None:
    """Fold one composition's published entries back into a candidate pool.

    Re-selecting over ``entry`` plus ``entry.tied_with`` matches selecting over the whole population, so the
    per-:func:`_compose` and per-row selections compose without treating the first tie-break as evidence. Duplicates
    (same call via two instances) are dropped so they don't fake a tie.
    """
    for key, entry in published.items():
        pool = into.setdefault(key, [])
        for candidate in (replace(entry, tied_with=()), *entry.tied_with):
            if candidate not in pool:
                pool.append(candidate)


def _counted(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for value in values:
        out[value] += 1
    return dict(sorted(out.items()))


# Why each arm withheld, for the census's ``composed_withheld`` account. One cause per arm (not one sentence for all)
# because the arms fail for different reasons.
#
# ``ARM_GATE_ONLY`` is keyed on the route token because it fires on two tokens with different meanings (intermediate
# computes the quantity vs. pins the counterparty).
_GATE_ONLY_ROUTE_CAUSES = {
    P.ROUTE_AMOUNT_AUTHORED: (
        "a route witnessed AUTHORING what the destination call carries, so the destination's own "
        "figure is not a figure for this route"
    ),
    P.ROUTE_TARGET_CONSTRAINED: (
        "a route witnessed PINNING which counterparty the destination call pays, so the "
        "destination's own figure is not a figure this caller can direct"
    ),
}


_ARM_ONLY_CAUSES = {
    ARM_WITHHELD: (
        "an execution that could not be READ at all — which is a finding about neither the route "
        "nor the join: both were computed before this arm was reached and are published, and a "
        "deletability licence standing among them does not release the figure"
    ),
    ARM_NOT_DETERMINED: (
        "a route that earned no typed finding in either direction, with no arm left to fall through to"
    ),
}


# No default: an unregistered pair raises instead of reaching the document with unwritten prose.
_WITHHELD_CAUSE_ORDER: tuple[tuple[str, str | None], ...] = tuple(
    (ARM_GATE_ONLY, state) for state in (P.ROUTE_AMOUNT_AUTHORED, P.ROUTE_TARGET_CONSTRAINED)
) + tuple((arm, None) for arm in COMPOSITION_ARMS if arm in _ARM_ONLY_CAUSES)


def _withheld_cause_key(record: "_WithheldComposition") -> tuple[str, str | None]:
    return (record.arm, record.route.state if record.arm == ARM_GATE_ONLY else None)


def _withheld_cause(key: tuple[str, str | None]) -> str:
    arm, route_state = key
    if arm == ARM_GATE_ONLY:
        return _GATE_ONLY_ROUTE_CAUSES[cast(str, route_state)]
    return _ARM_ONLY_CAUSES[arm]


def _withheld_cause_clause(withheld: tuple["_WithheldComposition", ...]) -> str:
    """The census's account of ``composed_withheld``, derived from the arms and route tokens that fired on this row."""
    counts: dict[tuple[str, str | None], int] = defaultdict(int)
    for record in withheld:
        counts[_withheld_cause_key(record)] += 1
    fired = [(key, counts[key]) for key in _WITHHELD_CAUSE_ORDER if counts.get(key)]
    if not fired:
        return (
            "composed_withheld is 0 here: no candidate that cleared the witnesses above lost its "
            "figure to the composition rule, which is a count of nothing and not a claim that the "
            "rule was not asked"
        )
    return (
        "composed_withheld is a LATER and different refusal: those candidates cleared every "
        "witness above and then lost their figure to the composition rule — "
        + "; ".join(f"{hits} to {_withheld_cause(key)}" for key, hits in fired)
        + f". The {len(_WITHHELD_CAUSE_ORDER)} registered causes are not interchangeable. "
        "composed_withheld_by_arm beside this separates the arms, and because one arm withholds "
        "under either of two route tokens, composed_withheld_by_reason is what separates those "
        "two — each entry's own withheld_reason names the token it was refused under"
    )


def _composition_report(
    composed: dict[str, _ComposedMagnitude],
    census: dict[str, int],
    refusals: dict[str, int],
    withheld: tuple[_WithheldComposition, ...],
    refused_magnitudes: dict[str, int],
    gate_claims: dict[str, int],
) -> dict[str, Any]:
    """What composition proved and, in the same object, what it refused.

    The refusals are the larger population and the honest denominator; listing only successes would read as coverage.
    """
    return {
        **{key: value for key, value in sorted(census.items())},
        # Per-entity, to line up with reach_composed_magnitudes; the per-instance counts above double-count shared
        # destinations.
        "composed": len(composed),
        "composed_usd": round(sum(sorted(entry.usd for entry in composed.values())), 2),
        # Published beside the admitted count so survivors don't read as coverage.
        "composed_withheld": len(withheld),
        # keyed on state and reason so "no row" is apart from "authority unresolvable"; otherwise obscuring the
        # authority would look like an absent finding.
        "composed_withheld_by_deletability": refused_magnitudes,
        "composed_withheld_by_arm": _counted(record.arm for record in withheld),
        "composed_withheld_by_reason": _counted(record.reason for record in withheld),
        # An entry proven for a different caller is counted apart so gate-claim transfer is never a silent default.
        "gate_claim_by_state": gate_claims,
        # The rule doesn't bound chain length, so this is the only place growth shows. 1 is a direct call; 2 traverses
        # an unseized node.
        "longest_composed_chain": max((len(entry.chain) for entry in composed.values()), default=0),
        "act_as_refused": dict(sorted(refusals.items())),
        "reading": (
            "licensed_selectors counts every (hop, licensed function) pair the walk offered "
            "composition. act_as_witnessed is the subset where the CALLER is witnessed able to "
            "be made to call that selector at that destination — the step a licence does not "
            "imply and without which a magnitude is priced on membership alone. It is witnessed "
            "under either of two shapes, named per step: a restricted, authority-gated function "
            "of the caller calling that selector on a state variable of its own read on-chain "
            "holding the destination, or — where that call site takes its callee as a "
            "parameter, so no storage of the caller CAN name the address — the destination's "
            "own access-control list naming this caller as an accepted caller of that selector "
            "by an enumerated role. Past the first hop the calling function must additionally "
            "be one the previous hop admitted, matched on that function's own selector, "
            "because no hop inherits its predecessor's authority: the finding's seized gate is "
            "spent at hop 1 and only there. The two per-site conjuncts do NOT both survive "
            "that boundary and neither is conservative-only. The DELEGATION conjunct is not "
            "applied past hop 1 — the licence there is the previous hop's admitted selector, "
            "and a direct msg.sender gate on the intermediate is exactly the shape such a "
            "chain runs through; a step admitted without the delegation witness says so on "
            "itself, under admitted_without_a_delegation_witness, so the published basis "
            "names the conjunct that was not applied rather than dropping it silently. A call "
            "site whose calling function needs no gate is refused "
            "at EVERY hop, and not because the rule is conservative: an open function is one "
            "anyone can call, so the value it moves is not conferred by the seized gate and "
            "belongs to that function's own finding. destination_magnitude_witnessed "
            "is the subset of those "
            "whose destination function also carries its own flow.out witness. composed is the "
            "distinct entities that cleared every one, and every figure they carry is a ceiling "
            "on one call rather than a floor. One entity may clear all three under MORE THAN "
            "ONE selector, and composed counts it once: two selectors at one entity are two "
            "independent calls, so the dollars published are the largest of them — a max of "
            "ceilings, never their sum and never the lower of the two, which is the rule for "
            "two distillations of one quantity and not for two calls. Where the largest is a "
            "tie, the entry names which candidates tied and by what rule the published "
            "selector, destination_function and act_as_chain were picked out of them, under "
            "composed_selector_tie; null there is the proven 'one candidate'. Everything in "
            "act_as_refused stayed not_determined and is charged to confidence. "
            + _withheld_cause_clause(withheld)
            + ". Each keeps its act-as chain and publishes its gate_claim and proving_execution "
            "blocks whatever state those reached — a withheld figure retracts neither question, "
            "and where either could not be answered the block carries its own typed reason rather "
            "than going quiet. They are listed per row under "
            "reach_composed_magnitudes_withheld. gate_claim_by_state is a DIFFERENT axis again and "
            "cuts across both populations: it says, per entry, whether the execution that proved "
            "the destination's figure was admitted for the caller this entry's chain names. Where "
            "it was not, the gate claim rests on the act-as witness alone and says so — an "
            "authorization check reads msg.sender, so a proof admitted for another address does "
            "not establish this one"
        ),
    }


def _destination_magnitudes(signals: list[FunctionSignal]) -> dict[tuple[str, str], _DestinationMagnitude]:
    """Every witnessed ``flow.out`` magnitude, keyed by (entity, selector).

    The same population the fold prices flow rows from, read as what a destination function moves; composition adds no
    witness. Functions with no selector (fallback, receive) can't be licensed and are skipped.
    """
    out: dict[tuple[str, str], _DestinationMagnitude] = {}
    for signal in signals:
        if signal.claim_id != C.FLOW_OUT or not signal.selector.startswith("0x"):
            continue
        magnitude = _gate(signal, "reach_magnitude_usd")
        if not magnitude.is_determined or not _is_number(magnitude.value):
            continue
        key = (entity_key(signal.chain, signal.deployment_address), signal.selector.lower())
        usd = float(magnitude.value)  # pyright: ignore[reportArgumentType]  # _is_number narrows it
        previous = out.get(key)
        # Two signals on one selector are one function distilled twice: take the lower figure, with the execution from
        # that same signal.
        if previous is None or usd < previous.usd:
            out[key] = _DestinationMagnitude(magnitude.state, usd, signal.function_name, _signal_execution(signal))
    return out


def _admit_composed(
    composed: dict[str, _ComposedMagnitude],
    *,
    principal_addresses: Iterable[str],
    planes: _AdmissionPlanes,
) -> tuple[dict[str, _ComposedMagnitude], list[_WithheldComposition]]:
    """The composition rule's three arms, applied to the SELECTED entries.

    Applied after selection, never to the pool: filtering the pool promotes the next candidate instead of withholding
    (dropping ten entries once yielded thirty-six).

    1. The gate claim transfers across a route mismatch (the check reads ``msg.sender``/``msg.sig``, not arguments), but
    not across a different caller; :func:`_gate_claim` publishes that conjunct separately.
    2. The magnitude is withheld on a transport fault (``ARM_WITHHELD``) or where the traversed body authors the
    destination call's arguments (``ARM_GATE_ONLY``).
    3. The direct path is republished where the deletability join proves the principal can author the calldata itself.

    Anything else is ``ARM_NOT_DETERMINED`` with the figure withheld. ``execution_record_not_persisted`` is not a fault:
    the record is derivable from the transcript, and refusing on it withholds every figure.
    """
    kept: dict[str, _ComposedMagnitude] = {}
    withheld: list[_WithheldComposition] = []
    addresses = tuple(principal_addresses)
    for key, entry in sorted(composed.items()):
        last = entry.chain[-1] if entry.chain else None
        route = planes.routes.classify(
            last.caller if last else "",
            last.calling_selector if last else None,
            entry.selector,
        )
        verdict = P.authority_deletability(planes.deletability, addresses, key, entry.selector)
        if entry.execution.reason in EX.FAULT_REASONS:
            arm, reason = ARM_WITHHELD, entry.execution.reason
        elif verdict.is_deletable:
            kept[key] = replace(entry, arm_taken=ARM_REPUBLISHED_DIRECT, deletability=verdict, route=route)
            continue
        elif route.state in (P.ROUTE_AMOUNT_AUTHORED, P.ROUTE_TARGET_CONSTRAINED):
            arm, reason = ARM_GATE_ONLY, route.state
        else:
            arm, reason = ARM_NOT_DETERMINED, cast(str, route.reason)
        withheld.append(
            _WithheldComposition(
                entity=entry.entity,
                selector=entry.selector,
                function=entry.function,
                chain=entry.chain,
                execution=entry.execution,
                arm=arm,
                reason=reason,
                route=route,
                deletability=verdict,
            )
        )
    return kept, withheld


def _compose(
    seeds: set[str],
    hops: list[_WalkedHop],
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    value_plane: P.ValuePlane,
    conditions: P.ConditionPlane,
    admission: _AdmissionPlanes,
    principal_addresses: Iterable[str],
) -> tuple[dict[str, _ComposedMagnitude], dict[str, int], dict[str, int], list[_WithheldComposition]]:
    """The gate-control magnitude the destination's own witness supplies.

    Requires three witnesses: the licence (the role licenses this selector at the destination), the destination's
    ``flow.out`` magnitude, and an act-as step at every hop (the caller can be made to call that selector, via a caller
    state variable pointing at the next node or the next node's ACL naming the caller). A licence alone doesn't show the
    principal can make the intermediate call; pricing on membership is the banned move.

    The walk is breadth-first from the seeds. The seized gate is spent at hop 1 only; past it, the licence at hop k+1 is
    that the calling function is one hop k admitted, matched by selector. The delegation conjunct isn't applied past hop
    1 (steps say ``admitted_without_a_delegation_witness``); openness is applied at every hop, since an open function's
    value belongs to its own finding.

    Among several licensed selectors at one entity, :func:`_composed_order` picks the published candidate and ties are
    published beside it.
    """
    census: dict[str, int] = dict.fromkeys(
        (
            "licensed_hops",
            "licensed_selectors",
            "destination_magnitude_witnessed",
            "act_as_witnessed",
            "composed",
        ),
        0,
    )
    refusals: dict[str, int] = defaultdict(int)
    by_caller: dict[str, list[_WalkedHop]] = defaultdict(list)
    for hop in hops:
        if hop.licensed:
            census["licensed_hops"] += 1
            by_caller[hop.caller].append(hop)

    candidates: dict[str, list[_ComposedMagnitude]] = {}
    # Per node, every admitted function keyed by selector, with its admitting chain, so each hop publishes the path
    # actually taken. Seed maps are never read.
    chains: dict[str, dict[str, tuple[P.ActAsStep, ...]]] = {key: {} for key in sorted(seeds)}
    # Not re-expanded on a longer path; conservative on both dollars and refusal reasons.
    visited: set[str] = set(seeds)
    frontier = sorted(seeds)
    while frontier:
        nxt: list[str] = []
        for caller in frontier:
            entries = chains[caller]
            # The seized gate is spent at hop 1 only, so seeds are unconstrained. ``frozenset(entries)`` not ``or
            # None``: an empty set must be a constraint nothing satisfies, not the unconstrained hop-1 question.
            admitted = None if caller in seeds else frozenset(entries)
            for hop in by_caller.get(caller, ()):
                for licensed in sorted(hop.licensed):
                    census["licensed_selectors"] += 1
                    verdict = act_as.acts_as(caller, hop.destination, licensed.selector, via=admitted)
                    if not verdict.witnessed or verdict.step is None:
                        refusals[verdict.outcome] += 1
                        continue
                    census["act_as_witnessed"] += 1
                    # Indexed, not ``get``: ``via`` guarantees the key, so a miss is a broken invariant.
                    prefix = () if caller in seeds else entries[verdict.step.calling_selector or ""]
                    chain = prefix + (verdict.step,)
                    # First witnessed path wins, so the published chain is the shortest.
                    chains.setdefault(hop.destination, {}).setdefault(licensed.selector, chain)
                    if hop.destination not in visited:
                        visited.add(hop.destination)
                        nxt.append(hop.destination)
                    magnitude = magnitudes.get((hop.destination, licensed.selector))
                    if magnitude is None:
                        refusals["destination_carries_no_flow_out_magnitude_witness"] += 1
                        continue
                    census["destination_magnitude_witnessed"] += 1
                    key = value_plane.canonical(hop.destination)
                    sheet = value_plane.trimming_total(key)
                    # A disposition-determined $0 sheet may not trim (disposed assets are still held); recorded
                    # separately because ``sheet_not_determined`` would be false.
                    refused = (
                        SHEET_BOUND_REFUSED_BY_DISPOSITION
                        if sheet is None and value_plane.total(key) is not None
                        else None
                    )
                    # R4: the witness bounds the call, the sheet bounds what's there; take the min, never the sum.
                    # Coverage is read for every sheet so the entry can publish its direction whichever ceiling wins.
                    coverage = _asset_coverage(value_plane, key) if sheet is not None else None
                    complete = None if coverage is None else bool(coverage["complete"])
                    usd = min(magnitude.usd, sheet) if sheet is not None else magnitude.usd
                    # Keep every candidate; collapsing on a running max would let loop order decide ties. The predicate
                    # lookup uses the same (raw destination, selector) the magnitude was read at.
                    candidates.setdefault(key, []).append(
                        _ComposedMagnitude(
                            entity=key,
                            selector=licensed.selector,
                            function=magnitude.function,
                            witness_state=magnitude.state,
                            witnessed_usd=magnitude.usd,
                            usd=usd,
                            sheet_usd=sheet,
                            sheet_bound_refused=refused,
                            sheet_is_proven_complete=complete,
                            sheet_bound_direction_basis=(
                                None
                                if coverage is None or complete is None
                                else _sheet_ceiling_direction_basis(coverage, complete)
                            ),
                            chain=chain,
                            predicates=conditions.predicates(hop.destination, licensed.selector),
                            # Composition observes nothing itself, so it carries the destination witness's execution
                            # unchanged.
                            execution=magnitude.execution,
                        )
                    )
        frontier = sorted(nxt)
    # Hops never offered because the walk never reached their caller; named so this doesn't read as "no licensed hops".
    for caller, hops_here in sorted(by_caller.items()):
        if caller in visited:
            continue
        for hop in hops_here:
            refusals[ACT_AS_CALLER_UNREACHED] += len(hop.licensed)
    selected = {key: _select_composed(pool) for key, pool in sorted(candidates.items())}
    census["composed_selected"] = len(selected)
    # On the selected entries, never the pool.
    composed, withheld = _admit_composed(selected, principal_addresses=principal_addresses, planes=admission)
    census["composed"] = len(composed)
    census["composed_withheld"] = len(withheld)
    return composed, census, dict(sorted(refusals.items())), withheld
