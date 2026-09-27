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
from utils import execution_record as EX


@dataclass(frozen=True)
class _ComposedMagnitude:
    """A destination function's own magnitude witness, reached along a witnessed path.

    ``chain`` is every act-as step from the seized node to the destination, in
    order. ``usd`` is the destination witness's figure after the R4 bound against
    the destination's own sheet; the published ``bounded_by`` says which of the
    two bound it, and ``sheet_not_determined`` marks the case where no sheet was
    available to bound it with at all. Both of those bounds are ceilings and so
    is their min.

    ``tied_with`` is the other candidates this entity offered at the SAME figure,
    which this one was chosen over by :func:`_composed_order`. Empty is the
    proven "one candidate, nothing was decided by the rule", and it publishes as
    ``composed_selector_tie: null`` rather than as a missing field.

    ``predicates`` is the destination function's own stored condition texts, a
    disclosure carried so the entry can point at them; nothing in this class or
    anywhere downstream evaluates one. It is REQUIRED, with no default: the
    lookup answers in three states of its own and a default would have to spell
    one of them, putting "nobody asked" and "asked, and no function of this
    entity carries that selector" under one name — inside the very block whose
    reading argues those must stay apart.
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
    # The call that PROVED ``witnessed_usd`` at the destination. REQUIRED, with
    # no default: the invariant is that a published magnitude carries its
    # execution, and a default would let an entry ship the figure while silently
    # claiming nothing about the call — which is the state every entry is in
    # today and precisely what this field exists to make visible.
    execution: EX.ProvingExecution
    # Why the destination's sheet did not bound this figure, where a sheet
    # EXISTS and is determined and still may not trim. ``None`` on every other
    # entry, including the ones with no sheet at all: "there is no number here"
    # and "there is a number and it does not answer this question" are different
    # facts, and ``sheet_not_determined`` may only ever spell the first.
    sheet_bound_refused: str | None = None
    # What the destination sheet's OWN asset coverage proves about the cap it
    # applied — read at the trim site from the same :func:`_asset_coverage` the
    # sheet-ceiling records publish their ``bound_direction`` from, so the two
    # surfaces answer "is this sheet an at-most" the same way. ``None`` is the
    # third state and the only one available to an entry built without a plane:
    # nobody read the coverage. It publishes ``not_determined``, never
    # ``ceiling`` — the absence of a completeness proof is not a completeness
    # proof, and a trim onto an unproven ceiling is how a witnessed magnitude
    # gets quietly reduced to a floor over what somebody happened to price.
    sheet_is_proven_complete: bool | None = None
    sheet_bound_direction_basis: str | None = None
    tied_with: tuple[_ComposedMagnitude, ...] = ()
    # Which arm of the composition rule this entry took, and the two witnesses
    # the arm was taken from. All three are set by :func:`_admit_composed` after
    # selection and default to "nothing was decided": a candidate that never
    # reached the rule publishes ``not_determined`` and no basis, which is what
    # it is. A PUBLISHED entry always carries ``republished_direct``, because the
    # other three arms withhold the figure and leave the composed dict.
    arm_taken: str = ARM_NOT_DETERMINED
    deletability: P.DeletabilityVerdict | None = None
    route: P.RouteClassification | None = None

    def __post_init__(self) -> None:
        # The two coverage fields are one answer read at one place, so they are
        # present together or absent together. Split, an entry could publish a
        # direction with no basis — the shape this fix exists to remove.
        if (self.sheet_is_proven_complete is None) != (self.sheet_bound_direction_basis is None):
            raise ValueError("sheet coverage and its basis are read together and publish together")

    @property
    def sheet_bound_direction(self) -> str | None:
        """Whether the destination sheet PROVES an at-most on this entry's figure.

        ``None`` where no sheet bounded anything — the entry says that under
        ``sheet_not_determined`` and ``sheet_bound_refused`` and does not need a
        direction for it. Otherwise the same two-valued answer the per-entity
        sheet-ceiling records publish, off the same conjunction: a priced sheet
        that does not cover everything observed at the node is a floor over what
        was priced, and ``min(witness, sheet)`` against such a figure hands back
        a NUMBER SMALLER than the witness on the strength of a bound nothing
        proved. The figure stands — it is the honest min of what is known — and
        the entry stops calling it a ceiling.
        """
        if self.sheet_usd is None:
            return None
        return BOUND_DIRECTION_CEILING if self.sheet_is_proven_complete else BOUND_DIRECTION_NOT_DETERMINED

    def _chain_identity_gloss(self) -> str:
        """What the order's last component actually ranges over, read off the steps.

        The shipped gloss named five fields — caller, selector, calling selector,
        receiver variable, receiver block — and :func:`_composed_order`'s tail is
        every field ``P.ActAsStep.as_json`` publishes, which is more than five and
        grows. Under-stating the key it describes made the string false of every
        carrier (``COMPOSITION_WITNESS_SHAPE_SPEC.md`` §11.2 (k)). Reading the
        field names off the steps in hand keeps the gloss exhaustive by
        construction, including on the day a step publishes a new field.
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
        """The rule, and the component of it that decided THIS tie.

        Reciting the whole ladder reads as though every component applied. It did
        not: on a tie the components ahead of the deciding one hold the same
        value on every candidate — the figure always does, by the definition of
        a tie — and the ones behind it are never reached. So the deciding
        component is computed per tie, against each candidate this entry was
        chosen over, and the case where the order separates nothing is published
        as itself rather than left to read as a decision.
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
        """Which of the two ceilings was the binding one on THIS entry.

        A property rather than an inline expression in :meth:`as_json` because
        the published ``reading`` is derived from it: the sentence naming where
        the dollars came from has to say the same thing this field does, and
        computing the answer twice is how the two drift apart.
        """
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
            # The name of the row the join reached, NOT this entry's
            # ``destination_function`` restated: the first comes from
            # ``effective_functions``, the second from the flow.out signal, and
            # printing one twice would hide the day they disagree.
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
            # The invariant, published: a magnitude names the execution that
            # produced it, and every claim attached to it is derived from that
            # record. Where the record is not_determined the block says so with
            # a typed reason and publishes no caller — an unread execution is
            # never a matching one.
            "proving_execution": self.execution.as_json(),
            "route_comparison": EX.route_comparison(
                self.execution,
                claimed_caller=self.chain[-1].caller if self.chain else None,
                claimed_target=self.chain[-1].destination if self.chain else None,
                claimed_selector=self.chain[-1].calling_selector if self.chain else None,
            ),
            # Which arm of the composition rule produced this entry, and what
            # licensed it. Published beside the comparison it is decided from
            # rather than left to be inferred from whether a figure is present.
            "arm_taken": self.arm_taken,
            # §7.2 arm 1's caller conjunct, evaluated rather than left implicit.
            "gate_claim": _gate_claim(self.chain, self.execution),
            # The route the proof took is republished as this entry's own only
            # where the deletability join proved this principal can author the
            # destination's calldata itself. The basis names the row that proved
            # it — the setter selector and the ``function_principals`` id — so
            # the licence can be checked rather than taken on the fold's word.
            "authority_deletability": (None if self.deletability is None else self.deletability.disclosure()),
            "route_classification": (None if self.route is None else self.route.as_json()),
            "flow_out_witness": {
                "state": self.witness_state,
                "usd": _round_published(self.witnessed_usd),
                "function": self.function,
                "entity": self.entity,
            },
            # The figure was READ from the row destination_function/selector
            # name, and what it measures is the ENTITY's: every selector at a
            # vault on the reference corpus carries the identical number. Named
            # so the pair is not read as a per-function decomposition.
            "witness_granularity": "entity",
            # EVERY dollar figure on this record takes the same rounding, and the
            # reason is not tidiness: the record publishes ORDERING and EQUALITY
            # claims across these fields. ``published_usd`` is the min of
            # ``flow_out_witness.usd`` and ``destination_sheet_usd``, ``bounded_by``
            # names which of the two it equals, and ``composed_selector_tie`` says
            # the candidates tie AT the published figure. Round one of them onto
            # zero and not its neighbours and the record breaks its own
            # invariants — a $0.00 witness above a $0.00156 published bound — so
            # the sub-cent case is exactly where a mixed convention publishes a
            # contradiction instead of a rounding.
            "destination_sheet_usd": (_round_published(self.sheet_usd) if self.sheet_usd is not None else None),
            "published_usd": _round_published(self.usd),
            # Which of the two ceilings was the binding one. Not
            # flow_out_witness.state, which says whether the destination's own
            # dollar figure for one call is exact or a priced floor.
            "bounded_by": self.bounded_by,
            # STRICTLY "no number was available". A sheet that carries a number
            # and is barred from trimming publishes its bar under its own key
            # below, so this one never has to stand for two facts.
            "sheet_not_determined": self.sheet_usd is None and self.sheet_bound_refused is None,
            "sheet_bound_refused": self.sheet_bound_refused,
            # Whether the sheet that capped this figure is proven to be an
            # at-most, and — where it is not — WHICH conjunct of that proof is
            # missing, enumerated off the destination's own coverage by the same
            # derivation the per-entity ceiling records use. ``null`` on an entry
            # no sheet bounded: there is no direction to publish and
            # ``sheet_not_determined`` beside it already says so.
            "destination_sheet_bound_direction": self.sheet_bound_direction,
            "destination_sheet_bound_direction_basis": (
                None if self.sheet_usd is None else self.sheet_bound_direction_basis
            ),
            "act_as_chain": [step.as_json() for step in self.chain],
            "act_as_chain_length": len(self.chain),
            "destination_predicates": self._predicates_json(),
            # ``null`` is the proven "one candidate — the order decided nothing
            # here", which is a different fact from a field nobody filled in.
            "composed_selector_tie": self._tie_json(),
            "reading": (
                _COMPOSED_SOURCE_READINGS[self.bounded_by]
                + (f". {_DISPOSED_SHEET_DOES_NOT_BOUND}" if self.sheet_bound_refused else "")
                # Gated on the BASIS being present, not on the direction alone.
                # The sentence's job is to point a reader at two fields, and the
                # basis is null in the third state — a sheet exists and nobody
                # read its coverage — so emitting it there would send a reader
                # to a field that says nothing, which is the defect one level up
                # from the one it was written to fix. The typed direction still
                # publishes not_determined in that state and carries the refusal
                # on its own.
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

    Dollars first and highest: two selectors at one entity are two INDEPENDENT
    calls, the row asks what the principal can move, and a max of ceilings is a
    ceiling. (That is not the lower-of-two rule at
    :func:`_destination_magnitudes`, which settles two distillations of ONE
    quantity.) Everything after the figure breaks a tie between candidates that
    carry the same dollars, where the remaining published fields — the witness
    state, the selector, the destination function and the chain — are not
    dollars and are not interchangeable. The witness state goes to the weakest;
    the rest is arbitrary, and being arbitrary is exactly why it is stated here
    and published on the entry rather than left to the order instances arrive
    in.

    The tail is TOTAL over everything the entry publishes, and that is the point
    rather than a nicety. Two candidates can agree on the figure, the state, the
    selector, the function and the chain's shape and still differ in the raw
    destination the walk anchored on, the calling function's name, the witness
    kind, the observation the pointer was read under or the destination's
    acceptance row — all of which are rendered into ``act_as_chain`` and every
    step ``basis``. A key that stopped short would hand that difference back to
    the order the candidates were built in, which is the defect this ordering
    exists to remove, one level down.

    So the tail is the step's OWN published identity, taken from
    :meth:`P.ActAsStep.as_json` rather than from a hand-written list of fields.
    That is what makes it total by construction, and what keeps it total on the
    day a field is added to the step: a list written out here would silently
    stop covering the entry the moment the step published something new. Values
    are rendered to text because the published shape is not orderable as it
    stands — ``destination_acceptance`` is a nested object on one step and
    ``None`` on the next, and comparing those two directly raises.
    """
    return (
        -entry.usd,
        _WITNESS_STATE_CLAIM.get(entry.witness_state, _WITNESS_STATE_UNRANKED),
        entry.selector,
        entry.function,
        # Length needs no component of its own: two chains whose calling
        # selectors compare equal are the same length by construction.
        tuple(step.calling_selector or "" for step in entry.chain),
        tuple(tuple(sorted((key, repr(value)) for key, value in step.as_json().items())) for step in entry.chain),
    )


def _first_differing_component(chosen: tuple[Any, ...], other: tuple[Any, ...]) -> int | None:
    """The index of the component that decided ``chosen`` over ``other``.

    ``None`` where no component differs — the two candidates are equal under the
    whole key and the order decided nothing between them. That is a real third
    state on a total-by-construction key (two candidates can agree on every
    ordered field and still differ in fields the key does not read, such as the
    execution that proved each one), and the published ``chosen_by`` says so
    rather than naming a component that separated nothing.
    """
    for index, (mine, theirs) in enumerate(zip(chosen, other)):
        if mine != theirs:
            return index
    return None


def _select_composed(candidates: list[_ComposedMagnitude]) -> _ComposedMagnitude:
    """The one candidate published for an entity, carrying the ones it beat.

    The WHOLE candidate is selected, never a field of it: ``selector``,
    ``function``, ``witness_state``, ``execution`` and ``chain`` are one
    call's account of itself, and a chain taken from a different candidate than
    the selector would publish a path that does not end at the function named
    beside it.

    Candidates tied at the published figure are retained on the winner so the
    entry can say that its selector, destination function and chain were decided
    by a stated rule rather than by evidence. Candidates BELOW the figure are
    dropped: they lost on dollars, which is a decision the evidence made, and
    keeping them would spell a resolved comparison as a tie.
    """
    ordered = sorted(candidates, key=_composed_order)
    best = ordered[0]
    tied = tuple(other for other in ordered[1:] if other.usd == best.usd)
    return replace(best, tied_with=tuple(replace(other, tied_with=()) for other in tied))


def _pool_composed(into: dict[str, list[_ComposedMagnitude]], published: dict[str, _ComposedMagnitude]) -> None:
    """Fold one composition's published entries back into a candidate pool.

    A published entry carries the candidates it was chosen over, so re-selecting
    over ``entry`` plus ``entry.tied_with`` reaches the same answer as selecting
    over the whole population at once — which is what lets the two selection
    points (one per :func:`_compose`, one across a row's instances) compose
    without the second inheriting the first's tie-break as if it were evidence.

    Duplicates are dropped on the entry's own fields: the same call reached by
    two instances of one row is one candidate, and counting it twice would
    publish a tie where nothing was ever ambiguous.
    """
    for key, entry in published.items():
        pool = into.setdefault(key, [])
        for candidate in (replace(entry, tied_with=()), *entry.tied_with):
            if candidate not in pool:
                pool.append(candidate)


def _counted(values: Iterable[str]) -> dict[str, int]:
    """A sorted count per distinct token. Empty where nothing was counted."""
    out: dict[str, int] = defaultdict(int)
    for value in values:
        out[value] += 1
    return dict(sorted(out.items()))


# Why each arm withheld, for the CENSUS's account of ``composed_withheld``. The
# sentence these replace gave a single cause for a counter three different arms
# feed — "because the route they publish is not the route the proof took and
# nothing proved this principal could have issued the proven call itself" — and
# both halves are the two clauses B1-N1 removed from the per-entry reading,
# failing on the same carriers: there is no proven route to differ from on the
# transport-fault arm, no typed route finding either way on the unclassified
# arm, and the fault arm is reached BEFORE the join is consulted, so it can
# publish ``deletable`` beside its own refusal. Rolling three findings into one
# cause at the aggregate is the same collapse the per-entry fix removed, one
# level up.
#
# ``ARM_GATE_ONLY`` is keyed on the ROUTE TOKEN and not on the arm, because the
# arm fires on two of them (:func:`_admit_composed`) and they are two different
# findings about the traversed body: one says the intermediate computes the
# quantity, the other says it pins the counterparty. Keyed on the arm alone, a
# target-constrained carrier read "AUTHORING" in the census beside its own
# ``withheld_reason`` naming the other token — the same disagreement between two
# adjacent blocks, one level down. The other two arms do not read the route at
# all: the transport fault is a finding about neither witness, and the
# unclassified arm's own reason IS the route's.
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


# Every (arm, route token) pair that has a registered cause, in the order the
# census lists them. There is no default: a pair absent here raises rather than
# reaching the document through a sentence nobody wrote for it.
_WITHHELD_CAUSE_ORDER: tuple[tuple[str, str | None], ...] = tuple(
    (ARM_GATE_ONLY, state) for state in (P.ROUTE_AMOUNT_AUTHORED, P.ROUTE_TARGET_CONSTRAINED)
) + tuple((arm, None) for arm in COMPOSITION_ARMS if arm in _ARM_ONLY_CAUSES)


def _withheld_cause_key(record: "_WithheldComposition") -> tuple[str, str | None]:
    """The (arm, route token) pair this record's census cause is keyed on."""
    return (record.arm, record.route.state if record.arm == ARM_GATE_ONLY else None)


def _withheld_cause(key: tuple[str, str | None]) -> str:
    arm, route_state = key
    if arm == ARM_GATE_ONLY:
        return _GATE_ONLY_ROUTE_CAUSES[cast(str, route_state)]
    return _ARM_ONLY_CAUSES[arm]


def _withheld_cause_clause(withheld: tuple["_WithheldComposition", ...]) -> str:
    """The census's account of ``composed_withheld``, derived from the arms and
    route tokens that actually fired on THIS row rather than authored once for
    all of them."""
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
    """What composition proved, and — in the same object — what it refused.

    A report listing only the entities that composed would read as a coverage
    figure. The refusals are the larger population by an order of magnitude on
    the reference corpus and they are the honest denominator: a licensed hop that
    composed nothing is a hop whose magnitude is still not_determined, and the
    reason it stayed there is the difference between "no witness exists" and
    "this fold declined to look".
    """
    return {
        **{key: value for key, value in sorted(census.items())},
        # Per-ENTITY, so it lines up with reach_composed_magnitudes. The
        # per-instance counts above are over (hop, selector) pairs and two
        # instances reaching one destination raise them twice.
        "composed": len(composed),
        "composed_usd": round(sum(sorted(entry.usd for entry in composed.values())), 2),
        # What the three-arm rule refused, in the same per-entity units. Beside
        # the count of what it admitted and never instead of it: a report that
        # published only the survivors would read as a coverage figure over a
        # population the rule had already narrowed.
        "composed_withheld": len(withheld),
        # inv. 13's disclosure hook. Keyed on the deletability verdict's STATE
        # and reason together, so a join that ran and found no row is counted
        # apart from a join whose authority could not be resolved. A protocol
        # that makes its gating authority unresolvable lands in the second
        # bucket and its published figure falls — so the bucket has to be
        # visible, or obscuring evidence would look like an absent finding.
        "composed_withheld_by_deletability": refused_magnitudes,
        "composed_withheld_by_arm": _counted(record.arm for record in withheld),
        "composed_withheld_by_reason": _counted(record.reason for record in withheld),
        # §7.2 arm 1's caller conjunct over every entry this row publishes. An
        # entry the proof was admitted for a DIFFERENT caller at keeps its gate
        # claim on the act-as witness and is counted apart, so "the gate claim
        # transferred" is never a silent default.
        "gate_claim_by_state": gate_claims,
        # Chain length is unbounded by the rule and bounded by the corpus, and a
        # reader has no other way to see the day it grows. 1 is a direct call
        # from the seized node; 2 is the first chain that traverses a node the
        # principal seized nothing on.
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

    This is the same 55-row population the fold already prices flow rows from —
    ``distill._flow_reach``'s ``_proven_number`` is its only constructor — read a
    second time as what a DESTINATION function is proven to move. Composition
    adds no witness; it joins an existing one to a reach that was already proven.

    Keyed on the selector because that is what a role licenses. A destination
    function with no selector (fallback, receive) can never be the far end of a
    licence and is left out.
    """
    out: dict[tuple[str, str], _DestinationMagnitude] = {}
    for signal in signals:
        if signal.claim_id != "flow.out" or not signal.selector.startswith("0x"):
            continue
        magnitude = _gate(signal, "reach_magnitude_usd")
        if not magnitude.is_determined or not _is_number(magnitude.value):
            continue
        key = (entity_key(signal.chain, signal.deployment_address), signal.selector.lower())
        usd = float(magnitude.value)  # pyright: ignore[reportArgumentType]  # _is_number narrows it
        previous = out.get(key)
        # Two signals on one selector are the same function distilled twice; the
        # LOWER figure is the one both witnesses support. The execution is taken
        # from the SAME signal as the figure, never merged across the two: it is
        # that call's account of itself, and pairing one signal's dollars with
        # another's caller would publish an execution that proved a different
        # number.
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

    Applied to the returned ``composed`` dict and never inside the candidate
    pool. Filtering the pool lets the selection promote a different candidate at
    the same entity, so a withheld figure would be replaced by the next one down
    rather than withheld — the document is not monotone under withholding and
    dropping ten entries once yielded thirty-six.

    The arms, in the order they are asked:

    1. **The gate claim transfers ACROSS A ROUTE MISMATCH, and its caller
       conjunct is evaluated separately.** It is not one of the branches below:
       every outcome publishes the act-as chain, because an authorization check
       reads ``msg.sender`` and ``msg.sig`` and no ARGUMENT, so a proof that
       entered by a different path still exercised the same check. That argument
       does NOT carry across a different CALLER — ``msg.sender`` is exactly what
       the check reads — so the caller half is asked per entry by
       :func:`_gate_claim` and published as its own three-state outcome beside
       the chain. A mismatch qualifies the claim; it does not retract it, because
       the chain is the act-as plane's witness and is established without any
       transcript.
    2. **The magnitude is withheld** where the figure's own execution could not
       be reached at all (a transport fault — ``ARM_WITHHELD``), or where the
       body the chain traverses is witnessed authoring the destination call's
       arguments (``ARM_GATE_ONLY``, under the route classification's own typed
       token).
    3. **The direct path is republished** where the deletability join proves
       this principal can author the destination's calldata itself. The route
       published is then the one the probe ran, and the entry names the
       ``function_principals`` row that licensed it.

    And there is no fourth: a candidate whose route earns neither typed token
    and whose principal the join did not prove lands on ``ARM_NOT_DETERMINED``
    with its figure withheld. There is no ``else`` that publishes, and no branch
    reads a hop count, a selector name or a contract's shape.

    The fault scoping is the load-bearing detail. ``execution_record_not_persisted``
    is NOT a fault: the record is derivable from the transcript the verdict
    points at, and refusing on it withholds every figure in the corpus — the
    blanket refusal already measured and refuted.
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
    """The gate-control magnitude the destination's own witness supplies (Phase 6).

    Phase 4 floored every gate-control magnitude to ``not_determined`` because
    nothing proved how much the reach moves. For a licensed hop that is
    recoverable without new evidence: the destination function the gate licenses
    may already carry its OWN ``flow.out`` magnitude witness, and that witness
    bounds what a call to it moves whoever makes the call.

    Three witnesses, and all three are required:

    1. the LICENCE (W4a) — the role the hop walks is witnessed licensing this
       named selector at this destination;
    2. the destination's ``flow.out`` MAGNITUDE — a fork-proven figure for that
       selector, reused, never re-derived;
    3. the ACT-AS step, at EVERY hop from the seized node to the destination —
       the caller is witnessed able to be made to call that selector THERE,
       under either of the two shapes :class:`P.ActAsPlane` admits: a state
       variable of the caller read on-chain holding the next node, or — where
       the call site takes its callee as a parameter, so no storage of the
       caller can name it — the next node's own access-control list naming this
       caller as an accepted caller of that selector by an enumerated role.

    (3) is the one the licence does not imply and the one this pass exists to
    enforce. A role saying N MAY call D says nothing about whether the principal
    can make N do it: seizing an authority pointer on N buys N's own restricted
    functions, and unless one of those is witnessed calling D, the path stops at
    N. Pricing on membership alone is the banned move at one remove. What that
    costs on the reference corpus is visible in the census rather than in any
    one shape: the two rows seized at a RolesAuthority carry eleven and three
    licensed hops and publish ``caller_not_reachable_from_the_seized_node`` on
    all of them — the walk never reaches those hops' callers, so no witness
    shape is ever asked, and their magnitude stays not_determined for a reason
    upstream of this pass.

    The path is walked breadth-first from the seeds, which are act-as reachable
    by definition (they are the entities the finding's own signal was witnessed
    on). A destination inherits reachability only through a hop that carries its
    own act-as witness, so a chain is only ever as strong as its weakest step.

    MULTI-HOP: no hop inherits its predecessor's authority. The finding's seized
    gate is spent at hop 1 and only there — at a SEED, never at a node some hop
    was witnessed reaching — which is where the plane's ``restricted`` +
    delegated conjuncts are the licence. Past it the principal has seized
    nothing on the intermediate; it arrives as whoever the previous hop
    admitted, so the licence at hop k+1 is that the intermediate's calling
    function is one hop k admitted, matched on that function's OWN selector
    because a function name does not identify a function. ``chains`` holds those
    admitted functions per node, keyed by that selector, each with the path that
    admitted it.

    The plane's two per-site conjuncts are NOT symmetric past hop 1, and neither
    is "conservative-only". The DELEGATION conjunct is not applied there: the
    licence is the previous hop's admitted selector, and a direct ``msg.sender``
    gate on the intermediate is exactly the shape such a chain runs through. A
    step admitted without that witness carries
    ``admitted_without_a_delegation_witness: true``, so the conjunct that was
    not applied is named on the step rather than dropped silently. The OPENNESS
    conjunct IS applied at every hop, and not out of caution — an open function
    is one anyone can call, so the value it moves is not conferred by the seized
    gate and belongs to that function's own finding.

    Where one entity offers more than one licensed selector carrying a
    magnitude, the entry published is chosen by :func:`_composed_order` and the
    losers tied at the same figure are published beside it: the dollars are a
    max of ceilings, but the selector, function, witness state and chain are one
    call's account of itself and are taken from the chosen candidate together.
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
    # Per node, every function of it a hop admitted — keyed by that function's
    # own SELECTOR — and the chain that admitted it. A node entered under two
    # functions carries two chains, and each licensed hop out of it is published
    # with the one whose entry function that hop is issued from: the chain must
    # BE the path, not a path. A SEED's map is never READ — a hop landing on a
    # seed still records its entry, but a seed is entered by the finding's own
    # seized gate, so both the via constraint and the prefix lookup below skip
    # it.
    chains: dict[str, dict[str, tuple[P.ActAsStep, ...]]] = {key: {} for key in sorted(seeds)}
    # Nodes already placed on a frontier. A node reached again from a longer
    # path is not re-expanded, so a function admitted only on that path is never
    # offered — conservative on dollars AND on the refusal reason, since a
    # refusal is published only once every admitted function has been tried.
    visited: set[str] = set(seeds)
    frontier = sorted(seeds)
    while frontier:
        nxt: list[str] = []
        for caller in frontier:
            entries = chains[caller]
            # Ruling 4 rule 2: the seized gate is spent at hop 1 and ONLY there,
            # so a seed is never constrained — not even by a hop some sibling
            # seed was witnessed making into it. Past hop 1 the plane is asked
            # the narrower question, and answers it over EVERY call site the
            # constraint admits rather than the first one it happens to hold.
            # ``frozenset(entries)``, never ``… or None``: an EMPTY admitted set
            # and hop 1 are different questions, and spelling them identically
            # would hand a non-seed node the unconstrained question — the via
            # rule gone and the seized gate spent a second time. Empty reaches
            # the plane as a constraint nothing satisfies and is refused under
            # ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION, which is what it
            # is. Only ``caller in seeds`` may produce the hop-1 question.
            admitted = None if caller in seeds else frozenset(entries)
            for hop in by_caller.get(caller, ()):
                for licensed in sorted(hop.licensed):
                    census["licensed_selectors"] += 1
                    verdict = act_as.acts_as(caller, hop.destination, licensed.selector, via=admitted)
                    if not verdict.witnessed or verdict.step is None:
                        refusals[verdict.outcome] += 1
                        continue
                    census["act_as_witnessed"] += 1
                    # The chain that admitted THIS step's own calling function.
                    # Indexed, not ``get``: ``via`` admitted the step only if
                    # its calling selector is one of these keys, so a miss is a
                    # broken invariant and must not publish a truncated chain.
                    prefix = () if caller in seeds else entries[verdict.step.calling_selector or ""]
                    chain = prefix + (verdict.step,)
                    # This licensed function of the destination is now one the
                    # principal can be made to enter it through, along this
                    # chain. First witnessed path wins, so the published chain
                    # is the shortest one the walk proved.
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
                    # A sheet DETERMINED at $0 by delivery-shape disposition may
                    # not trim: the disposed assets are still held and delivery
                    # shape is not a claim about worth, so the sheet bounds what
                    # the entity holds and not what is there to move. Recorded
                    # rather than merged into "no sheet" — the entry publishes
                    # ``sheet_not_determined``, and that word would be false.
                    refused = (
                        SHEET_BOUND_REFUSED_BY_DISPOSITION
                        if sheet is None and value_plane.total(key) is not None
                        else None
                    )
                    # R4: the witness bounds the call, the sheet bounds what is
                    # there to move. Neither alone, and never their sum.
                    #
                    # And the sheet's COMPLETENESS is read here, with the sheet,
                    # rather than left for the entry to imply: a sheet that does
                    # not cover its node is a floor over what was priced, and a
                    # min against a floor hands back a smaller number than the
                    # witness on a bound nothing proved. Read for every sheet
                    # that exists, not only the ones that end up binding, so the
                    # entry can publish the direction whichever ceiling wins.
                    coverage = _asset_coverage(value_plane, key) if sheet is not None else None
                    complete = None if coverage is None else bool(coverage["complete"])
                    usd = min(magnitude.usd, sheet) if sheet is not None else magnitude.usd
                    # Every candidate is kept. Collapsing here on a running MAX
                    # would decide the selector, destination function, witness
                    # state and chain by whichever licensed selector the loop
                    # reached first whenever two of them tie on dollars, and
                    # would delete the losing candidate before that could be
                    # seen. The choice is made once, by a stated rule, below.
                    #
                    # The predicate lookup is keyed at the RAW destination and
                    # the licensed selector — the same pair the magnitude was
                    # read at — so the texts are the body of exactly the
                    # function this figure was read from.
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
                            # The destination witness's OWN execution, carried
                            # through unchanged. Composition joins an existing
                            # witness to a reach that was already proven; it
                            # observes nothing itself, so it has no execution of
                            # its own to name and must not invent one.
                            execution=magnitude.execution,
                        )
                    )
        frontier = sorted(nxt)
    # Hops the BFS never offered because it never reached their CALLER. Without
    # a name they leave the largest negative result on this corpus published as
    # silence: the two rows seized at a RolesAuthority carry eleven and three
    # licensed hops, offer nothing and refuse nothing, and a reader has no way
    # to tell that from a walk that found no licensed hop at all. Counted in the
    # same (hop, licensed function) units as every other refusal.
    for caller, hops_here in sorted(by_caller.items()):
        if caller in visited:
            continue
        for hop in hops_here:
            refusals[ACT_AS_CALLER_UNREACHED] += len(hop.licensed)
    selected = {key: _select_composed(pool) for key, pool in sorted(candidates.items())}
    census["composed_selected"] = len(selected)
    # The three-arm rule, on the SELECTED entries and never on the pool above.
    composed, withheld = _admit_composed(selected, principal_addresses=principal_addresses, planes=admission)
    census["composed"] = len(composed)
    census["composed_withheld"] = len(withheld)
    return composed, census, dict(sorted(refusals.items())), withheld
