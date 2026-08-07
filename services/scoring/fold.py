"""Layer 2 — the whole-protocol grade fold. Pure, read-only, deterministic.

The fold is a recompute, never an accumulator. Three facts make a running total
wrong: value is MAX per (entity, asset) so two contracts reaching one vault must
charge it once; principal units are cross-contract and get RE-KEYED when a later
contract reveals an owner overlap; and which finding subsumes which is only
decidable with the whole finding set present.

Its population is the signal plane and nothing else — read through the one
pinned, totally ordered query — plus the resolution planes in
:mod:`services.scoring.planes`, which is where a reference becomes a unit, a
dollar or a breadth floor.

THE ROOT RULE
-------------
**Never substitute an available field for an unread one.** Every ``x or y`` on a
nullable or three-state expression is that substitution written as an idiom: an
owner set that did not resolve is not the threshold, an unread delay is not zero,
an unpriced entity is not ``$0.00``, and a principal address is not its own owner
set unless the principal IS a key. Where a witness is missing the answer is the
uncredited rung, an explicit ``None``, or a withheld row — chosen so the mistake
costs a credit rather than fabricating one. Every remaining fallback in this
module is guarded by a proof that the substituted value IS the fact.

Every arithmetic branch fails closed. A signal whose severity was not proven is
not scored; a value that could not be priced falls to the unpriced branch rather
than to zero; a malformed gate envelope withholds its own row rather than
raising out of the whole fold.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy.orm import Session

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.population import current_signals_with_faults
from services.scoring.schema import (
    NOT_DETERMINED,
    FunctionSignal,
    ScoreDocument,
    Tri,
    entity_key,
)
from utils import execution_record as EX
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.scoring_status import (
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    MAGNITUDE_STATE_PROVEN_EXACT,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    MAGNITUDE_STATES_ATTRIBUTION_DERIVED,
    MODEL_VERSION,
    OPENNESS_NOT_DETERMINED,
    OPENNESS_OPEN,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NONE_REQUIRED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    SCORE_TRIGGER_MANUAL,
    SEVERITY_STATE_PROVEN,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
)

ANYONE = "anyone"

# The closed vocabulary of every gate the fold reads: gate name → the proven
# state tokens that license its positive branch. ``gate_inputs`` is free-form
# JSONB with no CHECK behind it, so a reader that branches on "is not
# not_determined" treats a WITHHELD envelope (say ``not_earned``) as the earned
# one. Branching on the exact token is what makes the two different facts again.
GATE_PROVEN_TOKENS: dict[str, tuple[str, ...]] = {
    "exact_empty_credit": ("earned",),
    "latch_witness": ("witnessed",),
    # F4: ``proven_upper_bound`` is the ATTRIBUTION path's own state and MUST be
    # listed. ``_malformed_gates`` withholds any row whose gate state is neither
    # ``not_determined`` nor a member here, and ``_gate`` degrades it — so
    # omitting it would take every attribution-derived magnitude out at once,
    # which is a number movement dressed as a vocabulary omission.
    "reach_magnitude_usd": (
        MAGNITUDE_STATE_PROVEN_EXACT,
        MAGNITUDE_STATE_PROVEN_FLOOR,
        MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    ),
    # Both states are PROVEN: the distiller always performed the lookup, and the
    # earned negative carries the typed reason there is no record. The
    # execution's own three-state answer lives inside the payload — see
    # ``utils.execution_record``.
    PROVING_EXECUTION_KEY: EX.GATE_STATES,
    "token_identity": ("proven",),
    "asset_class": ("proven",),
    "input_seeded": ("proven",),
    "contract_balance_seeded": ("proven",),
    "amount_capped_by_balance": ("proven",),
    "asset_identity": ("resolved",),
    "pause_effective": ("proven",),
    "freeze_recovery_principals": ("enumerated",),
    "freeze_coverage_fraction": ("observed_blast_radius",),
    "destination_basis": ("basis",),
}

# Gates whose payload enters arithmetic. Validated as a real, finite number at
# READ as well as at construction: a string "1e12" compares and multiplies just
# fine in Python and would charge $1T off an untyped payload.
NUMERIC_GATES = frozenset({"reach_magnitude_usd"})

# Every gate's payload SHAPE, checked before any consumer walks it. ``gate_inputs``
# is free-form JSONB, so a list the fold iterates as dicts can arrive as a list of
# ints; without this the walk raises out of ``compute_protocol_score`` and one bad
# payload on one function silently costs the whole protocol its score.
GATE_PAYLOAD_SHAPES: dict[str, str] = {
    "exact_empty_credit": "object",
    "latch_witness": "object",
    "asset_identity": "object",
    "reach_magnitude_usd": "number",
    PROVING_EXECUTION_KEY: "object",
    "token_identity": "bool",
    "input_seeded": "bool",
    "contract_balance_seeded": "bool",
    "amount_capped_by_balance": "bool",
    "asset_class": "string",
    "destination_basis": "string",
    "pause_effective": "bool",
    "freeze_coverage_fraction": "string_list",
    "freeze_recovery_principals": "principal_ref_list",
}

# The gates the fold WILL read for a given claim. A signal missing one of them is
# a distiller bug, and it withholds its own row: reading a gate that was never
# written would put a default where a witness belongs, and raising would let one
# malformed row take the whole protocol's grade down with it.
REQUIRED_GATES = ("exact_empty_credit", "latch_witness", "reach_magnitude_usd")
REQUIRED_GATES_BY_CLAIM: dict[str, tuple[str, ...]] = {
    "flow.out": ("token_identity", "asset_class", "asset_identity"),
    "pause.set": ("freeze_recovery_principals",),
}

SINGLE_ASSET_CLASSES = frozenset({"erc20_only", "mixed"})

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


@dataclass
class _Instance:
    """One signal's contribution to one (unit, capability, weakness) row."""

    signal: FunctionSignal
    severity: float
    severity_basis: tuple[str, ...]
    entity_keys: tuple[str, ...]
    magnitude: Tri[float]
    value_bound: str
    pricing_blocked: str | None
    native_only: bool
    asset_identity_undecidable: bool
    # The principal this instance was witnessed under. A merged unit's row folds
    # instances from several members, and without this the row cannot say WHICH
    # member is proven to reach a given entity (inv.5 is the weakest path to that
    # entity, not the weakest member of the unit).
    principal_address: str = ""


@dataclass
class _Row:
    unit: str
    capability: str
    path: str
    weakness: float = 0.0
    weakest_label: str = ""
    principal_kind: str = ""
    weakest_address: str = ""
    principal_addresses: set[str] = field(default_factory=set)
    # Per contributing member address, the ``(weakness, label, kind)`` IT earned.
    # The row-level ``weakness`` is the max over these, which is only the right
    # price for an entity every member reaches; ``_aggregate`` re-attributes the
    # rest from this map.
    member_gate: dict[str, tuple[float, str, str]] = field(default_factory=dict)
    # The burn-sentinel admission rule's own count, and the instances it emptied
    # outright — an admission rule publishes what it refused (§3.1 pt 5).
    zero_reach_keys_refused: int = 0
    zero_reach_stripped: list[dict[str, Any]] = field(default_factory=list)
    instances: list[_Instance] = field(default_factory=list)
    seeds: set[str] = field(default_factory=set)
    tiers: set[str] = field(default_factory=set)
    notes: set[str] = field(default_factory=set)
    citations: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _WalkedHop:
    """One hop the closure walk admitted, and what it licensed at its far end."""

    caller: str
    destination: str
    licensed: frozenset[P.LicensedFunction]


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

    def _tie_json(self) -> dict[str, Any] | None:
        if not self.tied_with:
            return None
        return {
            "tied_at_usd": round(self.usd, 2),
            "candidates": [
                {
                    "selector": entry.selector,
                    "destination_function": entry.function,
                    "witness_state": entry.witness_state,
                    "witnessed_usd": round(entry.witnessed_usd, 2),
                    "chosen": entry is self,
                }
                for entry in sorted((self, *self.tied_with), key=_composed_order)
            ],
            "chosen_by": (
                "the weakest witness state; then the lowest selector; then the lowest "
                "destination function; then the chain's calling selectors; then "
                "the chain's own identity — each step's caller, selector, calling selector, "
                "receiver variable and receiver block. Total over every field the entry "
                "publishes, so nothing is left to the order the candidates were built in"
            ),
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

    def _predicates_json(self) -> dict[str, Any]:
        found = self.predicates
        reading = (
            "the predicate texts extracted from the DESTINATION function's compiled body, "
            "published verbatim and in stored order so this entry's ceiling can be checked "
            "against the evidence rather than taken on the fold's word. Four things about "
            "them. (1) They are stored WITHOUT POLARITY: the same text is a require-condition "
            "in one function and a revert-condition in another, so nothing here can tell "
            "whether any one of them must hold or must not. (2) The scorer therefore EVALUATES "
            "NONE of them and no published figure, band, refusal or count is affected by any "
            "one of them — removing this block changes no number. (3) The list is not a list of "
            "unmet business conditions: it includes the authorization guard that this step's "
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
            # The route the proof took is republished as this entry's own only
            # where the deletability join proved this principal can author the
            # destination's calldata itself. The basis names the row that proved
            # it — the setter selector and the ``function_principals`` id — so
            # the licence can be checked rather than taken on the fold's word.
            "authority_deletability": (None if self.deletability is None else self.deletability.disclosure()),
            "route_classification": (None if self.route is None else self.route.as_json()),
            "flow_out_witness": {
                "state": self.witness_state,
                "usd": round(self.witnessed_usd, 2),
                "function": self.function,
                "entity": self.entity,
            },
            # The figure was READ from the row destination_function/selector
            # name, and what it measures is the ENTITY's: every selector at a
            # vault on the reference corpus carries the identical number. Named
            # so the pair is not read as a per-function decomposition.
            "witness_granularity": "entity",
            "destination_sheet_usd": (round(self.sheet_usd, 2) if self.sheet_usd is not None else None),
            "published_usd": round(self.usd, 2),
            # Which of the two ceilings was the binding one. Not
            # flow_out_witness.state, which says whether the destination's own
            # dollar figure for one call is exact or a priced floor.
            "bounded_by": (
                "flow.out witness"
                if self.sheet_usd is None or self.witnessed_usd <= self.sheet_usd
                else "destination sheet"
            ),
            "sheet_not_determined": self.sheet_usd is None,
            "act_as_chain": [step.as_json() for step in self.chain],
            "act_as_chain_length": len(self.chain),
            "destination_predicates": self._predicates_json(),
            # ``null`` is the proven "one candidate — the order decided nothing
            # here", which is a different fact from a field nobody filled in.
            "composed_selector_tie": self._tie_json(),
            "reading": (
                "the dollars are the DESTINATION function's own flow.out witness, not this "
                "row's and not the destination's balance sheet. Every hop from the seized node to it carries "
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


@dataclass
class _RowValue:
    """What one row's instances proved about value, and what they did not."""

    per_entity: dict[str, float]
    total_usd: float | None
    basis: str
    undetermined: list[dict[str, Any]]
    proven_no_reach: list[dict[str, Any]]
    # Witnessed membership, NOT the keys of ``per_entity``: an entity whose
    # dollars are not_determined is still an entity the row provably reaches.
    reach: set[str]
    magnitude_caps: list[dict[str, Any]]
    # Hops the walk could not establish either way, deduped on the distinct
    # (caller, destination) pair, and the census of which instances carried a
    # magnitude witness at all.
    hops_not_determined: list[dict[str, Any]] = field(default_factory=list)
    magnitude_census: dict[str, int] = field(default_factory=dict)
    # What the walked gate hops LICENSE at each destination: the named functions
    # the role -> selector join resolved. Empty for a destination reached only
    # through state-variable hops, where nothing named which functions the gate
    # reaches — an absence, never an empty licence.
    licensed_functions: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    # How much of the graph the withheld hops hide. A frontier hop published as
    # not_determined names ONE destination; everything the closure places behind
    # it is withheld too and appears nowhere on the row.
    withheld_behind_hops: dict[str, Any] = field(default_factory=dict)
    # Floor magnitudes charged against an entity whose priced sheet is
    # not_determined, so nothing was available to bound them with. Published
    # rather than absorbed: the figure is the witness's, not the entity's.
    unbounded_floor_magnitudes: list[dict[str, Any]] = field(default_factory=list)
    # Phase 6: the destination witnesses that supplied a gate-control magnitude,
    # the census of how far every licensed hop got, and the signals whose
    # magnitude question composition answered.
    composed_magnitudes: dict[str, _ComposedMagnitude] = field(default_factory=dict)
    composition_census: dict[str, Any] = field(default_factory=dict)
    composed_signals: frozenset[tuple[Any, ...]] = frozenset()
    # Entities whose PUBLISHED figure in ``per_entity`` came through
    # :func:`_entity_contribution`'s composed branch, so that figure is a ceiling
    # on what this principal extracts and not a floor. Threaded rather than
    # re-derived from ``composed_magnitudes``: that map holds every entity a
    # composed candidate was built for, including ones whose own witness beat it
    # in the per-entity MAX, and the header's question is which figures WON.
    ceiling_entities: frozenset[str] = frozenset()
    # F5: the entities whose STANDING figure is PROVEN not to be
    # attribution-derived. An earned positive and NOT the complement of
    # ``ceiling_entities`` — that one says which BRANCH supplied a figure, this
    # one says what the WITNESS behind it claims, and the two are orthogonal (an
    # attribution-derived figure bounds from above whether it arrived through
    # composition or through the instance's own witness). An entity missing from
    # this set is one whose provenance was not established, which is exactly as
    # disqualifying for a floor as a proven attribution.
    non_attributed_entities: frozenset[str] = frozenset()
    # The composed candidates whose FIGURE the three-arm rule refused, and the
    # refusal counter keyed on the deletability verdict's ``(state, reason)``.
    # Carried on the row rather than summed away, because a row that loses EVERY
    # composed figure publishes an empty ceiling list, and an empty list on such
    # a row is otherwise indistinguishable from an empty list on the seventy-odd
    # rows that never composed anything — which launders a typed refusal into
    # silence.
    withheld_composed_magnitudes: tuple[_WithheldComposition, ...] = ()
    refused_composed_magnitudes: dict[str, int] = field(default_factory=dict)


def compute_protocol_score(
    session: Session,
    protocol_id: int,
    *,
    signals: list[FunctionSignal] | None = None,
    trigger: str = SCORE_TRIGGER_MANUAL,
    trigger_job_id: Any | None = None,
    computed_at: datetime | None = None,
) -> ScoreDocument:
    """The protocol's score document, folded over its current signal rows.

    ``signals`` is the §7.5 in-memory feeding mode and nothing else: the offline
    CLI distils every contract without persisting, and passes the result in the
    population order :func:`order_signals` pins. Left unset — every persisted
    path — the population comes from the one pinned query and from nowhere else,
    so no caller can hand the fold a filtered or re-ordered population.
    """
    row_faults: list[dict[str, Any]] = []
    if signals is None:
        # A row whose persisted JSONB does not hold its declared shape withholds
        # ITSELF: the schema's canonical-key checks are the right checks, but
        # raising them through the population read costs the whole protocol its
        # score over one bad column.
        signals, row_faults = current_signals_with_faults(session, protocol_id)

    value_plane = P.load_value_plane(session, protocol_id)
    closure = P.load_control_closure(session, protocol_id)
    conditions = P.load_condition_plane(session, protocol_id)
    conferral = P.load_conferral_plane(session, protocol_id)
    act_as = P.load_act_as_plane(session, protocol_id)
    # ``load_deletability_plane`` takes NO protocol_id, unlike every loader
    # around it: it asks about specific (chain, address) contracts, which are
    # global on-chain identities, and scoping it would drop setter rows on
    # contracts this protocol does not own — turning our own scoping into an
    # earned negative about somebody's control.
    admission = _AdmissionPlanes(P.load_deletability_plane(session), P.load_router_flow_plane(session, protocol_id))
    role_floors = P.load_role_holder_floors(session, protocol_id)
    refs = [ref for signal in signals for ref in signal.principal_refs]
    refs.extend(_recovery_refs(signals))
    principal_facts = P.load_principal_plane(session, refs)

    warnings: list[dict[str, Any]] = [
        {
            "kind": "signal_row_malformed",
            "entity": fault["entity"],
            "function": fault["function_name"],
            "capability": fault["claim_id"],
            "note": f"signal row withheld: {fault['column']} does not hold its declared shape",
            "column": fault["column"],
            "detail": fault["detail"],
        }
        for fault in row_faults
    ]
    earned_negatives: list[dict[str, Any]] = []
    seen_negatives: set[tuple[str, str]] = set()

    units = _UnitResolver(signals, principal_facts, role_floors)
    rows_by_key: dict[tuple[str, str, str], _Row] = {}

    for signal in signals:
        malformed = _malformed_gates(signal)
        if malformed:
            # One unreadable envelope withholds its own row. Raising here would
            # take the whole protocol's grade down with one bad payload, and
            # scoring around it would read a payload nobody validated.
            warnings.append(_warning("gate_input_malformed", signal, f"unreadable gate envelopes: {malformed}"))
            continue

        _collect_disclosures(signal, earned_negatives, seen_negatives, warnings)
        if not signal.enters_grade:
            continue

        if signal.authority_openness == OPENNESS_OPEN:
            severity, severity_basis, extra_notes = _fold_severity(signal, None, principal_facts, warnings)
            instance = _instance(signal, severity, severity_basis, ANYONE)
            unit = entity_key(signal.chain, ANYONE)
            row = _row_for(rows_by_key, unit, signal.claim_id, "direct", K.WEAKNESS_ANYONE, "ANYONE", ANYONE, ANYONE)
            _attach(row, signal, instance, extra_notes)
            continue

        if signal.authority_openness == OPENNESS_NOT_DETERMINED:
            warnings.append(_warning("unresolved_reachability", signal, "authority_openness is not_determined"))
            continue

        if signal.principal_state != PRINCIPAL_STATE_ENUMERATED:
            warnings.append(
                _warning("restricted_privileged_no_principal", signal, "no resolved principal and no earned empty")
            )
            continue

        for ref in signal.principal_refs:
            facts = principal_facts.get(int(ref.function_principal_id))
            if facts is None:
                warnings.append(_warning("principal_row_missing", signal, f"principal {ref.address} not readable"))
                continue
            severity, severity_basis, extra_notes = _fold_severity(signal, facts, principal_facts, warnings)
            instance = _instance(signal, severity, severity_basis, facts.address)
            weakness, label, kind, notes = units.weakness_for(
                facts,
                recovery_proven_independent=any(n.startswith("keyset_independent") for n in extra_notes),
            )
            if weakness is None:
                warnings.append(
                    _warning(
                        "contract_gated_unknown_path" if kind == "contract" else "unresolved_principal",
                        signal,
                        f"gated by a {label} principal whose own authority is not reduced to a key",
                        principal=facts.address,
                    )
                )
                continue
            unit = units.unit_for(facts)
            row = _row_for(
                rows_by_key,
                unit,
                signal.claim_id,
                units.path_for(facts),
                weakness,
                label,
                kind,
                facts.address,
            )
            _attach(row, signal, instance, extra_notes | set(notes))

    composed_signals: set[tuple[Any, ...]] = set()
    composition_census: dict[str, Any] = {}
    findings, subsumed, value_warnings = _aggregate(
        rows_by_key,
        value_plane,
        closure,
        conditions,
        conferral,
        act_as,
        _destination_magnitudes(signals),
        admission,
        units,
        composed_signals,
    )
    warnings.extend(value_warnings)
    composition_census = _composition_totals(findings, subsumed)

    grade_lambda, grade_exposure, exposure_usd, exposure_gaps, exposure_coverage = _grade(findings, value_plane)
    confidence = _confidence(
        signals,
        value_plane,
        closure,
        P.load_proven_eoa_entities(session, protocol_id),
        P.discovery_relation_entities(session, protocol_id),
        composed_signals,
    )

    perimeter, perimeter_detail = P.perimeter_state(session, protocol_id)
    provenance: dict[str, Any] = {
        "plane_row_counts": P.plane_row_counts(session, protocol_id),
        "population": {
            "signals": len(signals),
            "signals_entering_grade": sum(1 for s in signals if s.enters_grade),
            "findings": len(findings),
            "subsumed_rows": len(subsumed),
            # The distinction the read surface cannot make on its own: an
            # un-analysed protocol and a fully-undetermined one both reach a
            # consumer as grade_state=not_determined.
            "disposition": _population_disposition(signals, findings),
            "rows_withheld_malformed": len(row_faults),
        },
        "value": value_plane.provenance,
        "value_annotations": value_plane.annotations,
        # Each closure admission rule, counted where it fired AND where it did
        # not. A refusal and an earned negative are different facts about the
        # same row: the first says what this scorer declined to walk, the second
        # says the protocol has proven an authority slot empty, and only the
        # second is evidence about the protocol.
        "closure_admission": {
            "refusals": closure.refusal_counts(),
            "renounced": closure.renounced_counts(),
            "reading": (
                "refusals are EDGES this closure declined to admit, by rule: the zero address "
                "is a burn sentinel and not an assessable entity, so it is refused as principal "
                "and as anchor rather than becoming the largest control hub in the graph. "
                "renounced counts controller_value edges pointing AT the zero address, which is "
                "an authority slot proven EMPTY — renunciation for an ownership slot, an unset "
                "reference for a configuration pointer, proven-absent authority either way. "
                "edges is the citable row population; authority_slots is the distinct "
                "(anchor, label) it resolves to, which is the number of facts — the edge table "
                "carries one row per witnessed read, so the two differ by how often the "
                "resolver looked and never by how much authority was renounced"
            ),
        },
        # What bounds a reach hop, and where the bound could not be established.
        # A closure that walks every edge publishes reach it never proved; one
        # that silently drops the edges it cannot establish publishes a smaller
        # number with the same defect. Both classes' populations are counted.
        "reach_bounds": {
            "code_control_capabilities": sorted(K.CODE_CONTROL_CAPABILITIES),
            "gate_control_capabilities": sorted(K.GATE_CONTROL_CAPABILITIES),
            "caller_conditions": conditions.provenance,
            "gate_conferral": conferral.provenance,
            "act_as_composition": {**act_as.provenance, "census": composition_census},
            "hop_census": _hop_census(closure, conditions, conferral),
            "reading": (
                "code control expands over the whole closure of the controlled node — owning "
                "the code exercises everything the code is authorized to exercise. Gate control "
                "expands only through edges it passes a test on, and the test is no longer the "
                "label-presence test that walked any edge whose label named a scope at all. The "
                "two scope kinds are tested differently and the two tests are not equally strong. "
                "A `roles N` edge is walked where function_principals.details.trace[].selector, "
                "joined to effective_functions.selector at the destination, names the functions "
                "role N licenses there — a positive witness of what the hop delivers, published "
                "per finding as reach_licensed_functions. A state-variable edge is tested by a "
                "SAME-KIND BOUND, which is weaker and is not a conferral witness: the gate's own "
                "function is observed (effective_functions.state_writes, origin=body) to rewrite "
                "a variable of that name on ITS contract, while the edge's label names the "
                "authority slot on the DESTINATION's, so the match is a name match across two "
                "contracts' storage and witnesses no composition step. What it does is REFUSE "
                "hops whose authority is of a different kind from the one the gate seizes "
                "('hook', 'vault', 'roleRegistry'); the same-kind hops that survive it walk on no "
                "more evidence than the label-presence test gave them. A refused hop is NOT "
                "disproved: whether it composes anyway turns on the intermediate node's own "
                "function surface, and this plane DOES NOT CONSULT IT — that surface usually "
                "exists (0x4df6b733's setUserRole/setRoleCapability/transferOwnership are "
                "analysed effective_functions rows), so this is a join not performed and not a "
                "witness that is missing. The join that would decide it is the intermediate "
                "node's own functions against its outbound targets "
                "(effective_functions.sinks/effect_targets and the external_call_target edges "
                "CONTROL_RELATIONS excludes). Until it runs the hop is withheld as "
                "not_determined. That join NOW RUNS, under act_as_composition, and it is worth "
                "being exact about what it decides: it bounds the MAGNITUDE of a licensed hop, "
                "not the membership of the walk. A hop with no act-as witness is still walked as "
                "reach — the licence witnessed it — and simply carries no composed dollars. "
                "Widening the reach on the same join is a separate change nobody has argued for "
                "here. Both classes are bounded by the destination's own caller "
                "conditions. Every hop neither class could establish is published per finding as "
                "reach_hops_not_determined, never dropped, and reach_withheld_behind_hops sizes "
                "the subtree each withheld frontier hop hides"
            ),
        },
        "unpriced_positions": value_plane.unpriced_positions,
        "exposure_gaps": exposure_gaps,
        # How much of the perimeter grade_exposure was measured over. Without
        # it the ratio's numerator (a few findings) and its denominator (the
        # whole priced perimeter) are not comparable quantities, and the figure
        # reads as a measurement of safety rather than of coverage.
        "exposure_coverage": exposure_coverage,
        "principal_units": units.published_units(),
        "safe_keyset_overlaps": units.overlaps,
        "unit_evidence_scope": (
            "principal_units and safe_keyset_overlaps cover only the Safes reachable "
            "from claim-bearing signals: a Safe that gates nothing this scorer scored "
            "is absent from the union-find, so an overlap it would have merged is "
            "not_determined rather than proven absent"
        ),
        "upgrade_history": P.load_upgrade_provenance(session, protocol_id),
        "unconsumed_reach_relations": P.unconsumed_reach_relations(session, protocol_id),
        "ledgers": P.load_ledgers(session, protocol_id),
        "audit_posture": P.load_audit_posture(session, protocol_id, value_plane),
        "perimeter": perimeter_detail,
        "signal_scope": (
            "a signal is keyed on a CAPABILITY, so a function carrying no claim produces "
            "none: its earned empty caller set and its one_shot latch witness are outside "
            "this document. That is a distillation gap, never a proven absence"
        ),
        "determinism": (
            "every query carries a total ORDER BY and every sort a total tiebreak; "
            "the same DB state yields an identical document modulo computed_at"
        ),
    }

    # The three grade figures stand or fall together, and so does everything
    # derived from them. An exposure ratio with no priced denominator is not a
    # 100 — it is a quantity that was never measured — so a protocol with
    # findings but no priced value publishes the findings and parks every
    # derived number under provenance instead of serving it beside a withheld
    # grade.
    scored = bool(findings) and grade_exposure is not None
    if not scored:
        withheld_rows = [
            {
                "principal_unit": finding["principal_unit"],
                "capability": finding["capability"],
                "net_points_lambda": finding.pop("net_points_lambda", None),
                "exposure_usd": finding.pop("exposure_usd", None),
            }
            for finding in findings
        ]
        if findings:
            provenance["grade_withheld"] = {
                "grade_lambda_computed": grade_lambda,
                "confidence_pct_computed": confidence.pop("pct", None),
                "exposure_usd_computed": exposure_usd,
                "per_finding": withheld_rows,
                "reason": "no priced value in the perimeter, so the exposure denominator is not_determined",
            }
        else:
            confidence.pop("pct", None)

    return ScoreDocument(
        protocol_id=protocol_id,
        model_version=MODEL_VERSION,
        computed_at=computed_at or datetime.now(timezone.utc),
        trigger=trigger,
        trigger_job_id=trigger_job_id,
        perimeter_state=perimeter,
        grade_state=GRADE_STATE_COMPUTED if scored else GRADE_STATE_NOT_DETERMINED,
        grade_lambda=grade_lambda if scored else None,
        grade_exposure=grade_exposure if scored else None,
        confidence_pct=confidence.get("pct") if scored else None,
        findings=findings,
        earned_negatives=sorted(earned_negatives, key=lambda e: (e["entity"], e["function"], e["capability"])),
        warnings=_summarise_warnings(warnings),
        model_parameters={**K.model_parameters(), "confidence_detail": confidence},
        provenance={**provenance, "subsumed_rows": subsumed, "exposure_usd": exposure_usd if scored else None},
        uncalibrated_arms=K.UNCALIBRATED_ARMS,
    )


def _row_for(
    rows: dict[tuple[str, str, str], _Row],
    unit: str,
    capability: str,
    path: str,
    weakness: float,
    label: str,
    kind: str,
    address: str,
) -> _Row:
    """The row for one (unit, capability, ACCESS PATH), at its weakest gate.

    The path is part of the key because a unit can hold the same capability
    through paths that cost different things: a Safe that also proposes-and-
    executes on a timelock reaches the timelock's contracts only by paying the
    delay, and one max-weakness row would charge that delayed value at the
    Safe's undelayed rung. Within one path the weakest gate still wins (inv.5),
    which is what keeps two merged Safes one power rather than two.
    """
    key = (unit, capability, path)
    row = rows.get(key)
    if row is None:
        row = _Row(unit=unit, capability=capability, path=path)
        rows[key] = row
    if weakness > row.weakness or not row.weakest_label:
        row.weakness = weakness
        row.weakest_label = label
        row.principal_kind = kind
        row.weakest_address = address
    row.principal_addresses.add(address)
    # The member's OWN rung, kept beside the unit's weakest: a merged Safe unit
    # publishes one reach union, and pricing an entity only the 4/8 member
    # reaches at the 3/7 member's rung charges a coalition nobody proved.
    previous = row.member_gate.get(address)
    if previous is None or weakness > previous[0]:
        row.member_gate[address] = (weakness, label, kind)
    return row


# ---------------------------------------------------------------- gate reads


def _malformed_gates(signal: FunctionSignal) -> list[str]:
    """Gate envelopes this fold refuses to read, by name.

    A state outside the gate's closed vocabulary, or a numeric payload that is
    not a finite number, is a row this fold cannot score honestly.
    """
    bad: list[str] = []
    for name in REQUIRED_GATES + REQUIRED_GATES_BY_CLAIM.get(signal.claim_id, ()):
        if name not in signal.gate_inputs:
            bad.append(f"{name}(absent)")
    for name, raw in sorted(signal.gate_inputs.items()):
        expected = GATE_PROVEN_TOKENS.get(name)
        if expected is None:
            continue
        try:
            tri = Tri.from_json(raw)
        except ValueError:
            bad.append(name)
            continue
        if tri.state == NOT_DETERMINED:
            continue
        if tri.state not in expected:
            bad.append(name)
            continue
        if not _payload_has_shape(name, tri.value):
            bad.append(name)
    return bad


def _payload_has_shape(name: str, value: Any) -> bool:
    """Whether a proven gate payload is the shape its consumers walk."""
    shape = GATE_PAYLOAD_SHAPES.get(name)
    if shape is None:
        return True
    if shape == "number":
        return _is_number(value)
    if shape == "bool":
        return isinstance(value, bool)
    if shape == "string":
        return isinstance(value, str)
    if shape == "object":
        return isinstance(value, dict)
    if shape == "string_list":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if shape == "principal_ref_list":
        return isinstance(value, list) and all(_is_principal_ref(item) for item in value)
    return False


def _is_principal_ref(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    raw_id = entry.get("function_principal_id")
    if isinstance(raw_id, bool) or not isinstance(raw_id, int):
        return False
    for key in ("chain", "address"):
        if key in entry and entry[key] is not None and not isinstance(entry[key], str):
            return False
    return True


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def _gate(signal: FunctionSignal, name: str) -> Tri[Any]:
    """One gate, read on its EXACT proven token. Never "is not not_determined".

    A state the gate's vocabulary does not name is returned as
    ``not_determined``: an unrecognised token is a witness this fold cannot
    vouch for, and reading it as the positive branch is how a withheld arm
    publishes an earned one.
    """
    try:
        tri = signal.gate_input(name)
    except KeyError:
        # ``_malformed_gates`` has already withheld any row whose required gates
        # are missing; this arm keeps an incidental read from raising out of the
        # fold rather than inventing a value.
        return Tri.not_determined()
    expected = GATE_PROVEN_TOKENS.get(name, ())
    if tri.state == NOT_DETERMINED or tri.state in expected:
        if name in NUMERIC_GATES and tri.is_determined and not _is_number(tri.value):
            return Tri.not_determined()
        return tri
    return Tri.not_determined()


# ---------------------------------------------------------------- principals


class _UnitResolver:
    """Principal units: per (chain, address), with the two licensed collapses.

    Safes that can ACT AS each other are one unit — independence is a property of
    owner KEY SETS, and two Safes sharing enough owners are one power. A timelock
    whose proposer-executor is a Safe collapses into that Safe: upgrade-by-
    timelock is a subset of exec-by-proposer, so two rows would charge the same
    value twice. The collapse needs BOTH halves proven — proposing without
    executing is not acting as the timelock — and neither collapse ever crosses a
    chain, because same-address is not proof of same owner set.
    """

    def __init__(
        self,
        signals: list[FunctionSignal],
        principal_facts: dict[int, P.PrincipalFacts],
        role_floors: dict[tuple[str, str, str], dict[str, Any]],
    ) -> None:
        self._facts = principal_facts
        self._role_floors = role_floors
        by_key: dict[str, list[P.PrincipalFacts]] = defaultdict(list)
        for facts in sorted(principal_facts.values(), key=lambda f: f.key):
            if facts.resolved_type == "safe" and facts.owners:
                by_key[facts.key].append(facts)
        # Last row wins, exactly as before: which contradictory owner set to adopt
        # is an open ruling (R17), and this fold does not arbitrate it. What it
        # will not do is arbitrate SILENTLY — a Safe whose witnesses disagree
        # publishes the disagreement beside the set the merge decision used.
        self._safe_by_key = {key: rows[-1] for key, rows in by_key.items()}
        self.owner_set_contradictions = [
            {
                "safe": key,
                "adopted_owner_set": sorted(rows[-1].owners),
                "adopted_k_of_n": (
                    f"{rows[-1].threshold}/{len(rows[-1].owners)}"
                    if rows[-1].threshold is not None
                    else f"k not_determined/{len(rows[-1].owners)}"
                ),
                "witnesses": [
                    {
                        "function_principal_id": row.function_principal_id,
                        "owners": sorted(row.owners),
                        "threshold": row.threshold,
                    }
                    for row in sorted(rows, key=lambda r: r.function_principal_id)
                ],
                "basis": (
                    "function_principals rows disagree on this Safe's owner set; the adopted "
                    "row is the one this fold read, NOT an adjudication that the others are wrong"
                ),
            }
            for key, rows in sorted(by_key.items())
            if len({frozenset(row.owners) for row in rows}) > 1
        ]
        self._parent = {key: key for key in self._safe_by_key}
        self.overlaps: list[dict[str, Any]] = []
        self._union_overlapping_safes()
        self._proposers = self._timelock_proposer_executors(signals)
        self._members: dict[str, set[str]] = defaultdict(set)

    def _find(self, key: str) -> str:
        while self._parent[key] != key:
            self._parent[key] = self._parent[self._parent[key]]
            key = self._parent[key]
        return key

    def _union_overlapping_safes(self) -> None:
        keys = sorted(self._safe_by_key)
        for i, a in enumerate(keys):
            for b in keys[i + 1 :]:
                left, right = self._safe_by_key[a], self._safe_by_key[b]
                if left.chain != right.chain:
                    continue
                shared = left.owners & right.owners
                if not shared:
                    continue
                # An unread threshold cannot license a merge: "these two Safes are
                # one power" needs both thresholds proven, and a sentinel standing
                # in for one would publish a coalition size nobody measured.
                if left.threshold is None or right.threshold is None:
                    self.overlaps.append(
                        {
                            "a": a,
                            "b": b,
                            "shared_owners": len(shared),
                            "merged": False,
                            "basis": "threshold_not_determined_on_at_least_one_side",
                        }
                    )
                    continue
                k_left, k_right = left.threshold, right.threshold
                can_act = len(shared) >= max(k_left, k_right)
                block_left = len(left.owners) - k_left + 1
                block_right = len(right.owners) - k_right + 1
                self.overlaps.append(
                    {
                        "a": a,
                        "b": b,
                        "a_k_of_n": f"{k_left}/{len(left.owners)}",
                        "b_k_of_n": f"{k_right}/{len(right.owners)}",
                        "shared_owners": len(shared),
                        "shared_can_act_as_both": can_act,
                        "shared_can_block_both": len(shared) >= max(block_left, block_right),
                        "min_coalition_to_act_as_both": max(k_left, k_right) if can_act else None,
                        "merged": can_act,
                        "basis": "owner_key_set_intersection",
                    }
                )
                if can_act:
                    root_a, root_b = self._find(a), self._find(b)
                    if root_a != root_b:
                        self._parent[root_b] = root_a
        self.overlaps.sort(key=lambda o: (o["a"], o["b"]))

    def _timelock_proposer_executors(self, signals: list[FunctionSignal]) -> dict[str, dict[str, Any]]:
        """The weakest Safe proven able to BOTH propose and execute on a timelock.

        Both halves are required because the collapse asserts the Safe can act as
        the timelock. A propose-only witness proves the right to start a delayed
        action, not the right to complete one, and treating it as the collapse
        would re-price every timelock-gated dollar at the proposer's undelayed
        weakness on the strength of a witness that never mentioned execution.
        """
        by_role: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"schedule": set(), "execute": set()})
        facts_by_key: dict[str, P.PrincipalFacts] = {}
        for signal in sorted(signals, key=lambda s: (s.chain, s.deployment_address, s.selector, s.claim_id)):
            role = {"timelock.schedule": "schedule", "timelock.execute": "execute"}.get(signal.claim_id)
            if role is None:
                continue
            timelock_key = entity_key(signal.chain, signal.deployment_address)
            for ref in signal.principal_refs:
                facts = self._facts.get(int(ref.function_principal_id))
                if facts is None or facts.resolved_type != "safe" or not facts.owners:
                    continue
                by_role[timelock_key][role].add(facts.key)
                facts_by_key[facts.key] = facts

        out: dict[str, dict[str, Any]] = {}
        for timelock_key in sorted(by_role):
            both = sorted(by_role[timelock_key]["schedule"] & by_role[timelock_key]["execute"])
            best: dict[str, Any] | None = None
            for safe_key in both:
                facts = facts_by_key[safe_key]
                # inv.5 is the WEAKEST path. An unread threshold cannot lose that
                # comparison: it sorts first, and is then priced at the uncredited
                # rung rather than at a ratio nobody measured.
                rank = (0, 0.0) if facts.threshold is None else (1, facts.threshold / len(facts.owners))
                candidate = {
                    "key": safe_key,
                    "k": facts.threshold,
                    "n": len(facts.owners),
                    "rank": rank,
                }
                if best is None or candidate["rank"] < best["rank"]:
                    best = candidate
            if best is not None:
                out[timelock_key] = best
        return out

    def unit_for(self, facts: P.PrincipalFacts) -> str:
        key = facts.key
        if facts.resolved_type == "timelock":
            proposer = self._proposers.get(key)
            if proposer:
                key = str(proposer["key"])
        if key in self._parent:
            # The unit is named by its LOWEST member key, not by whichever root
            # the union order happened to leave: a union-find root is an
            # implementation artefact, and naming a unit with one would make the
            # same set of Safes carry different identities across runs.
            root = self._find(key)
            members = {member for member in self._parent if self._find(member) == root}
            unit = min(members)
            self._members[unit] |= members
            return unit
        self._members[key].add(key)
        return key

    def published_units(self) -> dict[str, Any]:
        """The unit memberships this fold folded, as the document's own evidence.

        A unit id is only meaningful beside the members it collapsed: without
        them a consumer cannot tell a re-labelled unit from a re-keyed one, and
        cannot check the inv.13 collapse that removed a double charge.
        """
        return {
            "members": {unit: sorted(members) for unit, members in sorted(self._members.items())},
            "timelock_collapses": {
                timelock: {
                    "into": entry["key"],
                    "proposer_k_of_n": (f"{entry['k']}/{entry['n']}" if entry["k"] is not None else "not_determined"),
                    "basis": "proven proposer AND executor",
                }
                for timelock, entry in sorted(self._proposers.items())
            },
            "owner_set_contradictions": self.owner_set_contradictions,
        }

    def proposer_for(self, facts: P.PrincipalFacts) -> dict[str, Any] | None:
        return self._proposers.get(facts.key)

    def path_for(self, facts: P.PrincipalFacts) -> str:
        """How this principal reaches the unit's capability: directly, or via a delay."""
        if facts.resolved_type == "timelock" and facts.key in self._proposers:
            return f"via_timelock:{facts.key}"
        return "direct"

    def weakness_for(
        self, facts: P.PrincipalFacts, *, recovery_proven_independent: bool = False
    ) -> tuple[float | None, str, str, list[str]]:
        notes: list[str] = []
        if facts.resolver_bases:
            weak = [b for b in facts.resolver_bases if K.resolver_basis_tier(b) == K.WEAKEST_RESOLVER_BASIS_TIER]
            if weak:
                notes.append("resolver_basis_convention:" + ",".join(sorted(weak)))

        if facts.resolved_type == "eoa":
            weakness, label, kind = K.WEAKNESS_EOA, "EOA", "eoa"
        elif facts.resolved_type == "safe":
            weakness, label, notes = _safe_weakness(facts, notes, recovery_proven_independent)
            kind = "safe"
        elif facts.resolved_type == "timelock":
            weakness, label, notes = self._timelock_weakness(facts, notes)
            kind = "timelock"
        elif facts.resolved_type == "contract":
            # "An EOA controls the gating CONTRACT" is not "an EOA can call this
            # function": the gating contract may impose its own conditions. The
            # hop is a confidence fact, never this row's weakness.
            return None, "contract", "contract", notes
        else:
            return None, facts.resolved_type or "unresolved", "unknown", notes

        raised = self._role_breadth(facts)
        if raised is not None and raised > weakness:
            notes.append(f"role_holder_floor_raises_breadth:{raised}")
            weakness = raised
        return weakness, label, kind, notes

    def _timelock_weakness(self, facts: P.PrincipalFacts, notes: list[str]) -> tuple[float, str, list[str]]:
        discount = K.delay_discount(facts.delay_seconds)
        proposer = self.proposer_for(facts)
        if discount is None:
            notes.append("timelock_delay_not_determined")
            return K.WEAKNESS_TIMELOCK_UNDETERMINED, "timelock(delay not_determined)", notes
        # Reached only where the discount resolved, which requires a read delay.
        delay_seconds = float(facts.delay_seconds) if facts.delay_seconds is not None else 0.0
        days = int(delay_seconds // 86400)
        if delay_seconds == 0:
            # A proven ZERO delay is proven-absent protection, not an unread one.
            # It earns no discount and does not land on the undetermined rung.
            notes.append("timelock_delay_proven_zero:no_protection")
            if proposer is None:
                return K.WEAKNESS_SAFE_UNCREDITED, "timelock(0d, proposer not_determined)", notes
            base = K.quorum_weakness(proposer["k"], proposer["n"], credit_withheld=False)
            notes.append(f"proposer={_kn(proposer)}")
            return base, f"timelock 0d via {_kn(proposer)}", notes
        if proposer is None:
            # A proven delay whose proposer-executor set is undetermined is not
            # proven protection, so the delay earns no discount.
            notes.append("timelock_proposer_not_determined:no_delay_credit")
            return K.WEAKNESS_TIMELOCK_UNDETERMINED, f"timelock {days}d(proposer not_determined)", notes
        base = K.quorum_weakness(proposer["k"], proposer["n"], credit_withheld=False)
        notes.append(f"delay_discount={discount};proposer={_kn(proposer)}")
        return round(base * discount, 4), f"timelock {days}d via {_kn(proposer)}", notes

    def _role_breadth(self, facts: P.PrincipalFacts) -> float | None:
        """A proven holder floor above one is proven BREADTH. It may only raise."""
        for registry, role_hash in facts.role_bindings:
            entry = self._role_floors.get((facts.chain, registry, role_hash))
            if entry and entry["holders_floor"] > 1:
                return K.ROLE_BREADTH_MULTI_HOLDER_WEAKNESS
        return None


def _kn(proposer: dict[str, Any]) -> str:
    """A proposer's k/n, or the honest refusal. Never a fabricated ratio."""
    return f"{proposer['k']}/{proposer['n']}" if proposer["k"] is not None else "k not_determined"


def _safe_weakness(
    facts: P.PrincipalFacts, notes: list[str], recovery_proven_independent: bool
) -> tuple[float, str, list[str]]:
    """A Safe's weakness from its PROVEN k and n, or the uncredited rung.

    An unread owner set is not an n. Backfilling n from k publishes a k-of-k Safe
    — the strongest rung on the ladder — out of a witness that never existed, and
    prints the fabricated ratio as the finding's own principal.
    """
    if not facts.owners:
        notes.append("safe_owner_set_not_determined:kn_uncomputable")
        label = "Safe (owners not_determined)" if facts.threshold is None else f"Safe k={facts.threshold}/n?"
        return K.WEAKNESS_SAFE_UNCREDITED, label, notes
    n = len(facts.owners)
    weakness = K.quorum_weakness(
        facts.threshold,
        n,
        credit_withheld=facts.protection_credit_withheld,
        waive_single_signer_cliff=recovery_proven_independent,
    )
    if facts.protection_credit_withheld:
        notes.append(f"safe_kn_credit_withheld:{facts.protection_basis}")
    label = f"Safe {facts.threshold}/{n}" if facts.threshold is not None else f"Safe k?/{n}"
    return weakness, label, notes


def _recovery_refs(signals: list[FunctionSignal]) -> list[Any]:
    """Principal references named by pause recovery gates, so the fold can read them."""

    @dataclass(frozen=True)
    class _Ref:
        function_principal_id: int
        chain: str
        address: str

    out: list[Any] = []
    for signal in signals:
        # Runs before the per-signal gate check in the main loop, so it repeats
        # it: a malformed payload must not be walked HERE either.
        if signal.claim_id != "pause.set" or _malformed_gates(signal):
            continue
        gate = _gate(signal, "freeze_recovery_principals")
        if not gate.is_determined or not isinstance(gate.value, list):
            continue
        for entry in gate.value:
            if _is_principal_ref(entry):
                out.append(
                    _Ref(
                        function_principal_id=int(entry["function_principal_id"]),
                        # The gate's entries are minted beside the pause signal on
                        # the same contract, so the chain is the same fact, not a
                        # substitute for an unread one. A JSONB null falls back to
                        # that same fact rather than stringifying to "None".
                        chain=str(entry.get("chain") or signal.chain),
                        address=str(entry.get("address") or ""),
                    )
                )
    return out


# ---------------------------------------------------------------- severity


def _fold_severity(
    signal: FunctionSignal,
    principal: P.PrincipalFacts | None,
    principal_facts: dict[int, P.PrincipalFacts],
    warnings: list[dict[str, Any]],
) -> tuple[float, tuple[str, ...], set[str]]:
    """The distilled severity, plus the components only the fold can prove.

    Per PRINCIPAL, not per function: whether a freeze is recoverable is a
    property of the freezing key set against the recovery key set, so evaluating
    it once over the union of a function's principals would charge a key set for
    an overlap another principal contributed.
    """
    severity = signal.severity.require(SEVERITY_STATE_PROVEN)
    basis = tuple(signal.severity_basis)
    notes: set[str] = set()
    if signal.claim_id != "pause.set" or principal is None:
        return severity, basis, notes

    verdict, coalition, note = _keyset_independence(signal, principal, principal_facts)
    if verdict is False:
        # PROVEN: this key set can freeze and also deny the recovery quorum.
        severity = max(severity, K.FREEZE_SUSTAINABLE)
        basis = basis + ("freeze_keyset_not_independent",)
        warnings.append(
            _warning(
                "freeze_keyset_not_independent",
                signal,
                "this key set can freeze AND deny the recovery quorum",
                min_coalition_to_sustain=coalition,
            )
        )
    elif verdict is None:
        # Every undetermined arm — no recovery claim, an unresolved recovery
        # principal, an unread freezing key set — leaves the rung where the
        # capability's proven existence put it. Raising here would move severity
        # on an absent witness; lowering would credit one. The question itself is
        # published instead.
        notes.add(note)
        basis = basis + ("freeze_recovery_independence_not_determined",)
        warnings.append(_warning("freeze_recovery_independence_not_determined", signal, note))
    else:
        # PROVEN independence: the credited rung, which equals the existence rung
        # today, so what changes is the basis rather than the number.
        severity = min(severity, K.FREEZE_KEYSET_RECOVERABLE)
        notes.add(note)
        basis = basis + ("freeze_keyset_independent",)
    return severity, basis, notes


def _keyset_independence(
    signal: FunctionSignal, principal: P.PrincipalFacts, principal_facts: dict[int, P.PrincipalFacts]
) -> tuple[bool | None, int | None, str]:
    """Is the recovery quorum independent of the freezing one, in KEYS?

    Independence is a property of owner key sets: P and U are independent iff
    ``|owners(U) \\ owners(P)| >= threshold(U)``. Comparing principal ADDRESSES
    publishes a protective credit for a configuration where a handful of keys
    freeze the protocol and hold it — and an address stands in for a key set only
    where the principal IS a single key, i.e. an EOA. For every other type an
    unread owner set makes the test uncomputable, not favourable.
    """
    if principal.owners:
        pauser_owners = principal.owners
    elif principal.resolved_type == "eoa":
        pauser_owners = frozenset({principal.address})
    else:
        return None, None, "pauser_key_set_not_determined"

    gate = _gate(signal, "freeze_recovery_principals")
    if not gate.is_determined or not isinstance(gate.value, list):
        return None, None, "recovery_path_not_determined_no_unset_claim"
    saw_safe = False
    best: int | None = None
    for entry in sorted((e for e in gate.value if _is_principal_ref(e)), key=lambda e: str(e.get("address"))):
        facts = principal_facts.get(int(entry["function_principal_id"]))
        if facts is None or facts.resolved_type != "safe" or not facts.owners or facts.threshold is None:
            continue
        saw_safe = True
        residual = len(facts.owners - pauser_owners)
        if residual >= facts.threshold:
            return True, None, f"keyset_independent:{residual}>={facts.threshold}"
        block = max(1, len(facts.owners) - facts.threshold + 1)
        best = block if best is None else min(best, block)
    if saw_safe:
        return False, best, "keyset_dependent"
    return None, None, "recovery_principal_unresolved"


# ---------------------------------------------------------------- value fold


def _instance(
    signal: FunctionSignal, severity: float, basis: tuple[str, ...], principal_address: str = ""
) -> _Instance:
    magnitude = _gate(signal, "reach_magnitude_usd")
    pricing_blocked = None
    native_only = False
    asset_identity_undecidable = False
    if signal.claim_id == "flow.out":
        if _gate(signal, "token_identity").is_determined:
            # Exactly one NON-FUNGIBLE token moves: pricing the row off a
            # fungible balance sheet is forbidden, not merely imprecise.
            pricing_blocked = "token_identity(non-fungible; pricing forbidden)"
        asset_class = _gate(signal, "asset_class")
        native_only = asset_class.is_determined and asset_class.value == "native_only"
        # The W2 pricing precondition: single-asset pricing is licensed only by a
        # decidable token identity. Undecidable ⇒ the unpriced branch, never the
        # entity's whole fungible sheet read as this call's magnitude.
        asset_identity_undecidable = (
            asset_class.is_determined
            and asset_class.value in SINGLE_ASSET_CLASSES
            and not _gate(signal, "asset_identity").is_determined
        )
    return _Instance(
        signal=signal,
        severity=severity,
        severity_basis=basis,
        entity_keys=signal.value_entity_keys,
        magnitude=magnitude,
        value_bound=signal.value_bound,
        pricing_blocked=pricing_blocked,
        native_only=native_only,
        asset_identity_undecidable=asset_identity_undecidable,
        principal_address=principal_address,
    )


def _attach(row: _Row, signal: FunctionSignal, instance: _Instance, notes: set[str]) -> None:
    # The burn sentinel is refused as a REACH key here, one admission short of the
    # walk: ``msg.sender != 0x0``, so nothing routes value through it and a
    # repoint witness that names it has proved no reach. The confidence perimeter
    # refuses it on the same rule; this is the value side of that discipline.
    kept = tuple(key for key in instance.entity_keys if not P.is_zero_key(key))
    if len(kept) != len(instance.entity_keys):
        row.zero_reach_keys_refused += len(instance.entity_keys) - len(kept)
        row.notes.add("zero_address_reach_key_refused")
        if not kept:
            # Every reach key this instance carried was the sentinel, so it now
            # witnesses nothing. Dropping it silently would read as "this call
            # reaches no priced entity" — an earned negative it never earned.
            row.zero_reach_stripped.append(
                {
                    "function": signal.function_name,
                    "entity": entity_key(signal.chain, signal.deployment_address),
                    "why": "every_reach_key_was_the_zero_address(refused; reach not_determined)",
                }
            )
        instance.entity_keys = kept
    row.instances.append(instance)
    row.seeds.add(entity_key(signal.chain, signal.deployment_address))
    row.tiers.add(signal.witness_tier)
    row.notes.update(signal.witness_notes)
    row.notes.update(notes)
    row.citations.extend(signal.citations)


def _member_weakness(
    row: _Row,
    per_entity: dict[str, float],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    admission: _AdmissionPlanes,
) -> tuple[dict[str, float], float, tuple[str, str, str]]:
    """A merged unit's weakness, per REACHED ENTITY (inv. 5).

    ``_row_for`` keeps the max weakness over a merged Safe unit's members while
    the row folds the UNION of their reach, with no tie between a member's rung
    and the entities that member reaches — so value only the 4/8 member can move
    is published at the 3/7 member's rung, a coalition nobody proved.

    inv. 5's weakest path is the weakest path TO THAT ENTITY: entity ``e`` is
    priced at the max over ONLY the members proven to reach ``e``. The row still
    publishes a single weakness against a union no single member reaches, so that
    union is priced at **the hardest rung among the contributing members** — the
    ``min`` over the per-entity rungs. That is NOT the overlap record's
    ``min_coalition_to_act_as_both``: that field is ``max(k)``, and weakness is
    keyed on ``k/n``, so a 3/4 member (0.20) and a 5/20 member (0.55) put the
    coalition size on the 5/20 Safe while this rung is the 3/4's 0.20. The
    hardest rung is the deliberate under-claim — inv. 5 forbids pricing a union
    at a rung no contributing member has to clear. Naming a member's reach needs
    the member's own witness, so a row whose instances cannot be attributed to a
    member keeps the unit-level rung rather than inventing an attribution.
    """
    unchanged = ({}, row.weakness, (row.weakest_label, row.principal_kind, row.weakest_address))
    if len(row.member_gate) < 2 or not per_entity:
        return unchanged
    by_member: dict[str, list[_Instance]] = defaultdict(list)
    for instance in row.instances:
        if instance.principal_address not in row.member_gate:
            return unchanged
        by_member[instance.principal_address].append(instance)

    reach_by_member: dict[str, set[str]] = {}
    for address, instances in by_member.items():
        probe = _Row(unit=row.unit, capability=row.capability, path=row.path)
        probe.instances = instances
        # Reach is MEMBERSHIP, so it is read off ``.reach`` and never off the
        # value map: W2b's per-call magnitude cap scales what a member is charged
        # and can empty ``per_entity`` outright, but it moves no entity out of
        # what the member provably reaches.
        reached = _row_value(probe, value_plane, closure, conditions, conferral, act_as, magnitudes, admission).reach
        reach_by_member[address] = reached

    weakness_by_entity: dict[str, float] = {}
    holders_by_entity: dict[str, list[str]] = {}
    for key in sorted(per_entity):
        holders = sorted(a for a, reached in reach_by_member.items() if key in reached)
        if not holders:
            # The union carries an entity no single member's fold reproduces.
            # That is an attribution this function cannot witness, so the row
            # keeps the unit rung rather than pricing it at a guess.
            return unchanged
        holders_by_entity[key] = holders
        weakness_by_entity[key] = max(row.member_gate[a][0] for a in holders)

    if len({*weakness_by_entity.values(), row.weakness}) == 1:
        return unchanged
    binding_key = min(weakness_by_entity, key=lambda k: (weakness_by_entity[k], k))
    published = weakness_by_entity[binding_key]
    binding = max(holders_by_entity[binding_key], key=lambda a: (row.member_gate[a][0], a))
    _, label, kind = row.member_gate[binding]
    return weakness_by_entity, published, (label, kind, binding)


CITATION_CAP = 8
# A citation that points AT evidence: a transcript pointer, a verdict, the block
# a reading was pinned to. Everything else is a field restatement, and a
# ``reading`` key marks the ones that are prose about how to read a field rather
# than a pointer to anything.
_CITATION_EVIDENCE_KEYS = ("transcript_ptr", "verdict", "block_source")


def _cited(citations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The row's citations, evidence first, capped for display.

    The cap is a display bound and the eviction it causes is arbitrary, so the
    order it evicts in must not be. A citation pointing at a transcript is the
    one a reader can check; a prose ``reading`` restating how to read a field is
    not, and it evicted two transcript pointers off a shipped row. Stable within
    each tier, so the population order still decides among equals.
    """

    def rank(citation: dict[str, Any]) -> int:
        if not isinstance(citation, dict):
            return 1
        if any(key in citation for key in _CITATION_EVIDENCE_KEYS):
            return 0
        return 2 if "reading" in citation else 1

    return sorted(citations, key=rank)[:CITATION_CAP]


def _aggregate(
    rows_by_key: dict[tuple[str, str, str], _Row],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    admission: _AdmissionPlanes,
    units: _UnitResolver,
    composed_signals: set[tuple[Any, ...]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    warnings: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for key in sorted(rows_by_key):
        row = rows_by_key[key]
        if not row.instances:
            continue
        valued = _row_value(row, value_plane, closure, conditions, conferral, act_as, magnitudes, admission)
        composed_signals.update(valued.composed_signals)
        per_entity, value_usd, undetermined = valued.per_entity, valued.total_usd, valued.undetermined
        value_basis = valued.basis
        if row.zero_reach_stripped:
            undetermined = undetermined + row.zero_reach_stripped
            value_basis += f"; {len(row.zero_reach_stripped)} instance(s) reached only the refused zero address"
        # A priced total over an entity that also holds assets the priced sheet
        # never covered is a FLOOR over that entity, not its value: an instance
        # that answered is not the same fact as an entity that was answered.
        partially_priced = _partially_priced_entities(value_plane, valued.reach)
        # Coverage alone decides nothing about direction. A contribution that is
        # itself an extraction ceiling cannot be summed into a floor because
        # OTHER contributions are missing, so the two axes are read together.
        direction = _bound_direction(
            value_usd,
            frozenset(per_entity),
            valued.ceiling_entities,
            bool(undetermined or partially_priced),
            # The withheld-reach block is ALWAYS a dict — it carries its own
            # reading even when nothing was withheld — so its counts are what is
            # read here and never its truthiness.
            bool(
                valued.hops_not_determined
                or valued.withheld_behind_hops.get("hops")
                or valued.withheld_behind_hops.get("entities")
            ),
            valued.non_attributed_entities,
        )
        # Only a row that HAS a total and carries a ceiling in it has a
        # direction to explain. A row whose value is not_determined publishes
        # that word as its basis, and a proven_no_reach row publishes an earned
        # negative consumers branch on by name — neither is a bound claim.
        if valued.ceiling_entities:
            value_basis = _ceiling_bearing_basis(
                direction,
                per_entity,
                valued.ceiling_entities,
                undetermined,
                partially_priced,
                valued.proven_no_reach,
                row.zero_reach_stripped,
                valued.hops_not_determined,
                valued.withheld_behind_hops,
            )
        is_floor = direction == BOUND_DIRECTION_FLOOR
        weakness_by_entity, weakness, weakest = _member_weakness(
            row, per_entity, value_plane, closure, conditions, conferral, act_as, magnitudes, admission
        )
        severity = max(instance.severity for instance in row.instances)
        band = K.band(value_usd)
        if value_usd is None or value_usd < 100_000:
            warnings.append(
                {
                    "kind": "value_at_stake_at_band_floor",
                    "unit": row.unit,
                    "capability": row.capability,
                    "note": (
                        "the weight sits at the band floor because the value this "
                        "capability is proven to reach is undetermined or below it. "
                        "This is not a claim that the entities hold nothing: position "
                        "and unpriced value are absent from the priced sheet, and this "
                        "is the one direction in which the model under-scores"
                    ),
                    "missing_witness": "priced value for the reached entities",
                }
            )
        rows.append(
            {
                "principal_unit": row.unit,
                "unit_members": sorted(units.published_units()["members"].get(row.unit, [row.unit])),
                # The published principal IS the one that set the weakness, not
                # whichever row was folded last.
                "principal": f"{weakest[0]} {weakest[2]}",
                "access_path": row.path,
                "principal_addresses": sorted(row.principal_addresses),
                "principal_kind": weakest[1],
                "capability": row.capability,
                "chain": row.unit.split("::", 1)[0],
                "value_at_stake_usd": (round(value_usd, 2) if value_usd is not None else None),
                "value_state": (VALUE_STATE_PROVEN_REACH if value_usd is not None else NOT_DETERMINED),
                "value_by_entity": {k: round(v, 2) for k, v in sorted(per_entity.items())},
                "value_at_stake_basis": value_basis,
                # Which direction the total bounds the principal in, and the
                # reason the flag below is no longer the whole answer: a sum of
                # composed extraction ceilings is not an at-least. Three-valued,
                # and ``not_determined`` is the fall-through — a direction is
                # published only where one was proven.
                "value_at_stake_bound_direction": direction,
                # Retained, and now derived: it is TRUE only where the direction
                # is a floor, so a consumer reading the boolean alone can no
                # longer read a ceiling as an at-least.
                "value_at_stake_is_floor": is_floor,
                # The entities whose published figure is a composed extraction
                # ceiling, named rather than left to be counted out of
                # reach_composed_magnitudes — that list holds every candidate,
                # including ones an entity's own witness beat.
                "entities_priced_from_a_composed_ceiling": sorted(valued.ceiling_entities),
                # Its refusal counterpart, and the reason it is published rather
                # than left to be counted out of the list above: on a row whose
                # every composed figure was withheld the ceiling list is EMPTY,
                # and an empty list there is otherwise the same shape as an
                # empty list on a row that never composed anything. One is a
                # typed refusal, the other is a question nobody asked, and
                # spelling them identically is the collapse three-valued logic
                # exists to prevent.
                "entities_withheld_from_a_composed_ceiling": [
                    {
                        "entity": record.entity,
                        "selector": record.selector,
                        "arm_taken": record.arm,
                        "withheld_reason": record.reason,
                        "authority_deletability_state": record.deletability.state,
                        "authority_deletability_reason": record.deletability.reason,
                    }
                    for record in valued.withheld_composed_magnitudes
                ],
                # The entities behind the coverage gap, named rather than left to
                # be inferred from the direction alone.
                "entities_holding_unpriced_assets": partially_priced,
                "value_band": (
                    (_BAND_PREFIX.get(direction, "") + K.band_label(value_usd))
                    if value_usd is not None
                    else NOT_DETERMINED
                ),
                "undetermined_instances": undetermined,
                "proven_no_reach_instances": valued.proven_no_reach,
                "witnessed_magnitude_caps": valued.magnitude_caps,
                # A floor witness the entity's own sheet could not bound. The
                # published dollars for these entities are the witness's figure
                # standing alone, which is a different fact from a figure two
                # witnesses agreed on.
                "unbounded_floor_magnitudes": valued.unbounded_floor_magnitudes,
                # Phase 6: every dollar this row carries that came from a
                # DESTINATION function's own flow.out witness rather than from a
                # witness on this row's own call, with the act-as chain that
                # licensed it published beside it (inv. 9 exact decomposition).
                "reach_composed_magnitudes": [
                    entry.as_json() for _, entry in sorted(valued.composed_magnitudes.items())
                ],
                # The other half of the same population: every candidate that
                # cleared all three composition witnesses and then lost its
                # FIGURE to the three-arm rule. Each one publishes its gate
                # claim, its execution record and its typed refusal, and no
                # dollar figure of any kind.
                "reach_composed_magnitudes_withheld": [
                    record.as_json() for record in valued.withheld_composed_magnitudes
                ],
                "reach_composition_census": valued.composition_census,
                # ``witnessed_magnitude_caps`` lists only the calls a witness
                # actually TRIMMED. Read alone it says nothing about the calls
                # that carried no witness at all, which are the majority and
                # which a reader would otherwise take for "checked and within
                # bound". The census separates the three: capped, witnessed and
                # within its bound, and never witnessed.
                "magnitude_witness_census": {
                    **valued.magnitude_census,
                    "reading": (
                        "magnitude_not_witnessed is the population whose dollar figure is "
                        "not_determined and whose weight therefore sits at the unpriced band's "
                        "floor: no witness proved how much this reach moves, so nothing is "
                        "published as if one had. magnitude_composed is counted apart from both "
                        "— those calls carry no witness of their own and were priced on the "
                        "DESTINATION function's, itemised under reach_composed_magnitudes. "
                        "within_witnessed_bound means a witness exists "
                        "and did not have to trim; it is not the same fact as no witness. "
                        "hops_not_determined counts every hop this row could not establish, of "
                        "which hops_not_determined_withholding_reach are the ones no other path "
                        "reached anyway — the rest bound nothing and are listed nowhere"
                    ),
                },
                # Hops the walk could establish neither way, deduped on the
                # distinct (caller, destination) pair. Reach withheld is still
                # reach this row does not claim — published so the bound is
                # visible instead of the closure quietly getting smaller.
                "reach_hops_not_determined": valued.hops_not_determined,
                "zero_address_reach_keys_refused": row.zero_reach_keys_refused,
                # Filled in after the sort, which is where a tie can be seen.
                # Present on every row: null is the proven "nothing tied".
                "exposure_order_tie": None,
                "severity_proven": round(severity, 4),
                "severity_basis": sorted({b for instance in row.instances for b in instance.severity_basis}),
                "weakness": round(weakness, 4),
                "weakest_gate": weakest[0],
                # inv.5 read as the weakest path TO AN ENTITY: present only where a
                # merged unit's members reach different entities at different rungs,
                # and then the union is priced at the hardest rung among the
                # contributing members. Absent means one rung priced the whole union.
                "weakness_by_entity": {k: round(v, 4) for k, v in sorted(weakness_by_entity.items())},
                "raw_points": round(K.SEV_SCALE * severity * weakness * band, 4),
                "n_functions": len({(i.signal.deployment_address, i.signal.selector) for i in row.instances}),
                "n_entities": len(row.seeds),
                # The deployment entities the row's instances were witnessed ON
                # — the direct targets — as distinct from reach_entities, the
                # closure the capability reaches through control edges. That
                # closure is MEMBERSHIP and is not filtered by pricing: the
                # entities in it whose dollars are undetermined are named in
                # the row's exposure gap, not dropped from the fact that this
                # capability reaches them.
                "host_entities": sorted(row.seeds),
                "reach_entities": sorted(valued.reach),
                # What the gate hops this row walked LICENSE at each destination
                # — the role -> selector join's named functions, keyed on the
                # canonical entity the reach set uses, as {selector, name}
                # objects rather than a string a consumer would have to re-parse.
                # A reached entity absent from this map was reached through a hop
                # that named no function, which is a reach whose "to do what" is
                # unanswered and not a reach to nothing.
                "reach_licensed_functions": valued.licensed_functions,
                # The size of what the withheld hops hide. Two published hops can
                # withhold twenty-two entities; without this the other twenty
                # appear nowhere in the document.
                "reach_withheld_behind_hops": valued.withheld_behind_hops,
                "example_functions": sorted({i.signal.function_name for i in row.instances})[:6],
                "witness_tiers": sorted(row.tiers),
                "witness_notes": sorted(row.notes),
                "citations": _cited(row.citations),
                # The slice above is a display cap, and a cap that is not counted
                # reads as the whole population. Two witness citations were
                # evicted by a reading-string on one shipped row before the
                # ordering below existed; the total says how many were not shown.
                "citations_total": len(row.citations),
                "counterfactual": _counterfactual(weakest[1]),
            }
        )

    by_unit: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_unit[row["principal_unit"]].append(row)
    findings: list[dict[str, Any]] = []
    subsumed: list[dict[str, Any]] = []
    for unit in sorted(by_unit):
        ordered = sorted(
            by_unit[unit], key=lambda r: (-r["raw_points"], r["capability"], r["access_path"], r["weakness"])
        )
        top = dict(ordered[0])
        rest = ordered[1:]
        top["subsumed_capabilities"] = [
            {
                "capability": r["capability"],
                "access_path": r["access_path"],
                "weakness": r["weakness"],
                "raw_points": r["raw_points"],
                "value_at_stake_usd": r["value_at_stake_usd"],
                "n_entities": r["n_entities"],
            }
            for r in rest
        ]
        top["subsumed_raw_points"] = round(sum(r["raw_points"] for r in rest), 4)
        # Subsumption removes a row's POINTS, never the unit's reach. Value that
        # only a subsumed row names is still value this unit provably reaches, and
        # dropping it from the exposure accounting would publish a smaller
        # exposure for a unit that got no smaller.
        #
        # The contributing row's OWN fraction travels with the value. The top row
        # is a different access path — often an undelayed one — and charging the
        # delayed row's value at the undelayed fraction would re-merge in the
        # exposure term exactly what keying rows by access path separated.
        exclusive: dict[str, dict[str, float]] = {}
        for row in rest:
            per_entity_weakness = row["weakness_by_entity"]
            for key, held in row["value_by_entity"].items():
                if key in top["value_by_entity"]:
                    continue
                fraction = row["severity_proven"] * per_entity_weakness.get(key, row["weakness"])
                previous = exclusive.get(key)
                if previous is None or held * fraction > previous["usd"] * previous["fraction"]:
                    exclusive[key] = {"usd": held, "fraction": round(fraction, 6)}
        top["subsumed_exclusive_value_by_entity"] = dict(sorted(exclusive.items()))
        if rest:
            top["counterfactual"] += (
                "; this row subsumes " + ", ".join(r["capability"] for r in rest) + " — fixing the top "
                "capability alone does not release them"
            )
        findings.append(top)
        subsumed.extend(rest)
    findings.sort(key=lambda r: (-r["raw_points"], r["capability"], r["principal_unit"]))
    subsumed.sort(key=lambda r: (-r["raw_points"], r["capability"], r["principal_unit"]))
    _disclose_order_ties(findings)
    return findings, subsumed, warnings


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
            finding["exposure_order_tie"] = {
                "tied_with": [unit for unit in units if unit != finding["principal_unit"]],
                "shared_entities": sorted(set(finding["value_by_entity"]) & others),
                "position_in_tie": position,
                "basis": "equal raw_points and capability; the remaining order is the principal_unit string",
                "reading": (
                    "this row's λ position and its share of any entity it holds in common with "
                    "the tied rows are decided by that string, not by evidence; the split among "
                    "them is order-determined and is not a measurement of who reaches what"
                ),
            }


# Every published dollar is rounded to the cent, so a share below half a cent
# reaches a consumer as $0.00 whatever it really was.
_PUBLISHED_CENT = 0.005

_UNPRICED_ASSET_STATES = frozenset({P.ASSET_UNPRICED, P.ASSET_BELOW_RESOLUTION})


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
        states = value_plane.per_asset_state.get(canonical) or {}
        if any(state in _UNPRICED_ASSET_STATES for state in states.values()):
            partial.add(canonical)
        elif value_plane.unpriced_positions.get(canonical):
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
    entity's figure must be a composed ceiling (one ungraded contribution and
    the sum is not bounded above by these), nothing may be missing from the sum
    (a coverage gap or a withheld hop is value this row reaches that the total
    does not carry, and either one breaks an at-most while leaving an at-least
    intact), and the two are checked here rather than asserted in the prose.

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


def _ceiling_bearing_basis(
    direction: str,
    per_entity: dict[str, float],
    ceiling_entities: frozenset[str],
    undetermined: list[dict[str, Any]],
    partially_priced: list[str],
    proven_no_reach: list[dict[str, Any]],
    zero_reach_stripped: list[dict[str, Any]],
    hops_not_determined: list[dict[str, Any]],
    withheld_behind_hops: dict[str, Any],
) -> str:
    """The basis for a row some of whose figures are extraction ceilings.

    Written here rather than in :func:`_row_value` because the coverage half of
    the question is only complete once the zero-reach instances and the partly
    priced entities are known. The floor basis is left untouched: a row whose
    direction did not move must not have its prose move either.

    Every clause names the population it counted. The ceiling arm in particular
    may not say "nothing is missing" as an unchecked flourish — the hops this
    row could not establish and the graph withheld behind them are value the sum
    does not carry, and they are named here because they were consulted in
    :func:`_bound_direction` before the arm was taken.
    """
    n_entities = len(per_entity)
    counted = f"{len(ceiling_entities)} of {n_entities} entity(ies)"
    ceilings = (
        "priced from a composed extraction CEILING — the DESTINATION function's own flow.out "
        "witness, which bounds one call to that function whoever makes it (see "
        "reach_composed_magnitudes[])"
    )
    if direction == BOUND_DIRECTION_CEILING:
        return (
            f"<= the sum over {n_entities} entity(ies), every one of them {ceilings}; "
            "no instance is not_determined, no entity holds assets the priced sheet does not "
            "cover, and no hop of this row was left undetermined or withheld behind one — so "
            "nothing this row reaches is missing from the sum and the total bounds this "
            "principal from ABOVE. Each composed figure bounds ONE call to the destination "
            "function"
        ) + (f"; {len(proven_no_reach)} instance(s) proven_no_reach" if proven_no_reach else "")

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
    if hops_not_determined:
        missing.append(f"{len(hops_not_determined)} hop(s) not_determined withholding reach")
    behind = withheld_behind_hops.get("entities") or 0
    if behind:
        missing.append(f"{behind} entity(ies) withheld behind those hops (see reach_withheld_behind_hops)")
    ungraded = n_entities - len(ceiling_entities)
    if ungraded:
        missing.append(f"{ungraded} entity(ies) whose figure is not a composed ceiling and is graded in no direction")
    basis = (
        f"bounded in NEITHER direction: {counted} {ceilings} — a ceiling does not become a floor "
        "by being summed, and the precondition can put the true extraction below it; "
        + ", ".join(missing)
        + " leave the sum short of a ceiling on the row too"
    )
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    return basis


def _row_value(
    row: _Row,
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    admission: _AdmissionPlanes,
) -> _RowValue:
    """Value at stake for one row: MAX per entity, never SUM.

    Two functions reaching the same vault charge it once, and the only dollar
    figure this function will publish against an entity is one a magnitude
    WITNESS proved — the entity's whole balance sheet answers "what is there",
    never "what this reach can move". The magnitude is also one number for the
    whole CALL, so it caps that call's sum across the keys it reached rather than
    being re-charged at each of them.

    The reach itself is bounded by the capability's class: code control expands
    over the whole closure of the controlled node, gate control only through
    edges whose scope the gate confers, and both only where the destination's
    own conditions do not pin their caller to the destination itself.

    Where a gate's own call carries no magnitude witness, the DESTINATION
    function's may supply one (:func:`_compose`, Phase 6). That is a reuse of an
    existing witness and never a second source of dollars: it applies only where
    the instance proved no magnitude itself, and each composed figure is capped
    at the destination's own witness and at the destination's own sheet.

    The conferral question is asked with the WITNESSED FUNCTION's own grant, per
    instance: two ownership.transfer functions that rewrite different variables
    confer different hops, and asking the capability class would walk one row's
    reach on another row's witness.
    """
    per_entity: dict[str, float] = {}
    # The entities whose standing figure in ``per_entity`` is a composed
    # extraction ceiling. Maintained beside the MAX rather than after it: which
    # branch produced a figure is only knowable where the figure is chosen.
    ceiling_entities: set[str] = set()
    # Maintained beside the MAX for the same reason ``ceiling_entities`` is: the
    # witness behind a figure is only knowable where that figure is chosen.
    non_attributed_entities: set[str] = set()
    reached: set[str] = set()
    undetermined: list[dict[str, Any]] = []
    proven_no_reach: list[dict[str, Any]] = []
    magnitude_caps: list[dict[str, Any]] = []
    unbounded_floors: list[dict[str, Any]] = []
    # Every candidate every instance offered per entity, kept rather than
    # collapsed on arrival: the merge below has to choose between candidates
    # that tie on dollars, and a running MAX destroys the losers before the tie
    # can be seen, let alone published.
    composition_candidates: dict[str, list[_ComposedMagnitude]] = {}
    composition_census: dict[str, int] = {}
    composition_refusals: dict[str, int] = defaultdict(int)
    # Every composed candidate whose FIGURE the three-arm rule refused, keyed on
    # the call it refused so two instances reaching it report one refusal.
    withheld_composed: dict[tuple[str, str], _WithheldComposition] = {}
    composed_signals: set[tuple[Any, ...]] = set()
    hops: dict[tuple[str, str], dict[str, Any]] = {}
    licensed: dict[str, set[P.LicensedFunction]] = defaultdict(set)
    census: dict[str, Any] = dict.fromkeys(
        (
            "instances",
            "magnitude_witnessed",
            "magnitude_composed",
            "magnitude_not_witnessed",
            "capped",
            "within_witnessed_bound",
        ),
        0,
    )
    code_control = row.capability in K.CODE_CONTROL_CAPABILITIES
    transitive = code_control or row.capability in K.GATE_CONTROL_CAPABILITIES

    for instance in sorted(row.instances, key=lambda i: (i.signal.deployment_address, i.signal.function_name)):
        entity = entity_key(instance.signal.chain, instance.signal.deployment_address)
        if instance.pricing_blocked:
            undetermined.append(
                {"function": instance.signal.function_name, "entity": entity, "why": instance.pricing_blocked}
            )
            continue
        if instance.asset_identity_undecidable and not instance.magnitude.is_determined:
            undetermined.append(
                {
                    "function": instance.signal.function_name,
                    "entity": entity,
                    "why": "token_identity_not_decidable(unpriced branch)",
                }
            )
            continue
        if instance.signal.value_state == VALUE_STATE_PROVEN_NO_REACH:
            # An EARNED negative, not a gap: reach was witnessed and reached
            # nothing. Counting it among the undetermined instances would make a
            # proven fact read as a missing one.
            proven_no_reach.append(
                {"function": instance.signal.function_name, "entity": entity, "basis": instance.signal.value_basis}
            )
            continue
        if instance.signal.value_state != VALUE_STATE_PROVEN_REACH:
            # The transitive closure is a REACH, not a licence: a signal whose own
            # reach was never witnessed contributes no seed, however much value
            # its deployment's neighbours hold.
            undetermined.append(
                {"function": instance.signal.function_name, "entity": entity, "why": instance.signal.value_basis}
            )
            continue

        keys = set(instance.entity_keys)
        composed: dict[str, _ComposedMagnitude] = {}
        if transitive:
            grant = (
                None
                if code_control
                else conferral.grant_for(
                    instance.signal.claim_id,
                    instance.signal.function_id,
                    entity=entity,
                    selector=instance.signal.selector,
                )
            )
            seeds = set(keys)
            keys, withheld, licensed_here, walked_hops = _closure(keys, closure, conditions, grant=grant)
            for hop in withheld:
                hops.setdefault((hop["caller"], hop["destination"]), hop)
            # Keyed on the CANONICAL entity, the same key ``reached`` uses. The
            # walk speaks in raw edge anchors and an implementation folded onto
            # its proxy is one entity under two of them, so a consumer joining
            # the licensed functions to the reach set would silently miss every
            # destination that folds.
            for destination, functions in licensed_here.items():
                licensed[value_plane.canonical(destination)].update(functions)
            if not code_control:
                # Phase 6. Code control asks no conferral question, so it names
                # no destination function and has no compositional source; its
                # magnitude question is a different one and stays where Phase 4
                # left it.
                composed, counts, refused, refused_entries = _compose(
                    seeds,
                    walked_hops,
                    act_as,
                    magnitudes,
                    value_plane,
                    conditions,
                    admission,
                    row.principal_addresses,
                )
                for record in refused_entries:
                    # Deduped on (entity, selector): two instances of one row
                    # reaching the same call refused it once, and counting it
                    # twice would double the refusal a reader is shown.
                    withheld_composed.setdefault((record.entity, record.selector), record)
                _pool_composed(composition_candidates, composed)
                for name, count in counts.items():
                    composition_census[name] = composition_census.get(name, 0) + count
                for reason, hits in refused.items():
                    composition_refusals[reason] += hits
                if composed:
                    composed_signals.add(_signal_identity(instance.signal))
        # Reach is MEMBERSHIP, and it is witnessed here. It may not be read off
        # the value map: an entity drops out of that map whenever its dollars
        # are not_determined — an unpriced sheet today, a refused magnitude once
        # the magnitude discipline lands — and deleting a proven fact because an
        # unproven one is missing is the whole error this fold is being repaired
        # for. Priced or not, the row reaches these entities.
        reached.update(value_plane.canonical(key) for key in keys)
        contributions, gaps, cap, unbounded, from_ceilings, non_attributed = _instance_contributions(
            instance, keys, value_plane, transitive=transitive, composed=composed
        )
        unbounded_floors.extend(unbounded)
        census["instances"] += 1
        if _witnessed_magnitude(instance) is None:
            # A composed magnitude is a witness — the DESTINATION's — so it is
            # counted apart from both the calls that carried their own and the
            # calls that carry none. Folding it into either reports a different
            # fact than the one that was proved, and leaving it at zero on the
            # rows that composed says no witness answered where one did.
            census["magnitude_composed" if composed else "magnitude_not_witnessed"] += 1
        else:
            census["magnitude_witnessed"] += 1
            census["capped" if cap is not None else "within_witnessed_bound"] += 1
        undetermined.extend(gaps)
        if cap is not None:
            magnitude_caps.append(cap)
        for canonical, contribution in contributions.items():
            previous = per_entity.get(canonical)
            if previous is None or contribution > previous:
                per_entity[canonical] = contribution
                ceiling_entities.discard(canonical)
                non_attributed_entities.discard(canonical)
            # The bound travels with the figure that stands, and a tie is
            # settled by the weaker of the two claims: an extraction ceiling
            # equal to a witnessed figure is still only a ceiling.
            if canonical in from_ceilings and contribution >= per_entity[canonical]:
                ceiling_entities.add(canonical)
            # Same rule, same direction: an attribution-derived figure tying the
            # standing one revokes the grade, because either candidate may be
            # the number published.
            if contribution >= per_entity[canonical]:
                if canonical in non_attributed:
                    non_attributed_entities.add(canonical)
                else:
                    non_attributed_entities.discard(canonical)

    # One selection over every instance's candidates, not a running MAX: the
    # figure is the same either way, but the selector, destination function,
    # witness state and chain published beside it are the CHOSEN candidate's own
    # and must be taken from it together.
    composition = {key: _select_composed(pool) for key, pool in sorted(composition_candidates.items())}
    # The rule again, on the row's own selection. The pool holds only entries an
    # instance-level pass already admitted, so this changes nothing today — it is
    # here so that the PUBLISHED entry is the one the rule was applied to,
    # whatever a later edit does to the two selection points.
    composition, refused_again = _admit_composed(
        composition, principal_addresses=row.principal_addresses, planes=admission
    )
    for record in refused_again:
        withheld_composed.setdefault((record.entity, record.selector), record)
    refused_composed: dict[str, int] = defaultdict(int)
    for record in withheld_composed.values():
        refused_composed[record.counter_key] += 1
    hop_gaps = [hops[pair] for pair in sorted(hops) if value_plane.canonical(pair[1]) not in reached]
    census["hops_not_determined"] = len(hops)
    census["hops_not_determined_withholding_reach"] = len(hop_gaps)
    withheld_behind = _behind_the_frontier(hop_gaps, closure, conditions, value_plane, reached)
    licensed_out = {key: [fn.as_json() for fn in sorted(rows)] for key, rows in sorted(licensed.items())}
    refusals_out = dict(sorted(refused_composed.items()))
    withheld_out = tuple(withheld_composed[key] for key in sorted(withheld_composed))
    composition_report = _composition_report(
        composition, composition_census, dict(composition_refusals), withheld_out, refusals_out
    )
    if not per_entity:
        basis = "proven_no_reach" if proven_no_reach and not undetermined else "not_determined"
        return _RowValue(
            per_entity,
            None,
            basis,
            undetermined,
            proven_no_reach,
            reached,
            magnitude_caps,
            hop_gaps,
            census,
            licensed_out,
            withheld_behind,
            unbounded_floors,
            composition,
            composition_report,
            frozenset(composed_signals),
            withheld_composed_magnitudes=withheld_out,
            refused_composed_magnitudes=refusals_out,
        )
    basis = (
        "witnessed reach magnitude over the "
        + ("code-control" if code_control else "gate-control")
        + " closure, MAX per entity"
        if transitive
        else "per-instance witnessed value, MAX per entity over latest-observation sheets"
    )
    if undetermined:
        basis = f">= proven floor over {len(per_entity)} entity(ies); {len(undetermined)} instance(s) not_determined"
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    total = round(sum(sorted(per_entity.values())), 6)
    return _RowValue(
        per_entity,
        total,
        basis,
        undetermined,
        proven_no_reach,
        reached,
        magnitude_caps,
        hop_gaps,
        census,
        licensed_out,
        withheld_behind,
        unbounded_floors,
        composition,
        composition_report,
        frozenset(composed_signals),
        frozenset(ceiling_entities),
        frozenset(non_attributed_entities),
        withheld_out,
        refusals_out,
    )


def _composition_totals(findings: list[dict[str, Any]], subsumed: list[dict[str, Any]]) -> dict[str, Any]:
    """Every row's composition census, summed to the protocol.

    Findings and subsumed rows are rolled up SEPARATELY because a subsumed row is
    usually the same walk seen through a weaker capability: adding the two counts
    one composition twice and publishes twice the recovery. That is the whole
    reason for the split, and it is NOT that a subsumed row's dollars stay out of
    the grade — they do not. A subsumed row's entities that no surviving row
    reaches are charged to the top row's exposure at its own fraction
    (``subsumed_exclusive_value_by_entity``), and on the reference corpus a
    subsumed ``authority.replace`` row's composed ``ethereum::0x657e8c86``
    ($11,358,880.43) enters the top finding's published exposure that way.

    Entities are counted DISTINCT within each population — two findings composing
    the same vault composed one entity — while the dollars are summed per row,
    because that is how they enter the grade: each row is charged what it reaches
    and the exposure budget, not this figure, is what keeps one entity from being
    paid for twice.
    """

    # Per-row counts sum; a per-row MAXIMUM does not, and summing chain lengths
    # across rows would publish an arithmetic artefact as the longest chain the
    # corpus grows.
    maxima = ("longest_composed_chain",)
    # Census keys whose value is itself a count-per-token map. They roll by
    # merging the maps, never by summing them into one number: the whole point
    # of keying a refusal on its reason is that the reasons stay apart.
    breakdowns = (
        "composed_withheld_by_deletability",
        "composed_withheld_by_arm",
        "composed_withheld_by_reason",
    )

    def roll(rows: list[dict[str, Any]]) -> dict[str, Any]:
        totals: dict[str, int] = defaultdict(int)
        longest: dict[str, int] = dict.fromkeys(maxima, 0)
        refused: dict[str, int] = defaultdict(int)
        broken: dict[str, dict[str, int]] = {key: defaultdict(int) for key in breakdowns}
        entities: set[str] = set()
        withheld_entities: set[str] = set()
        usd = 0.0
        for row in rows:
            census = row.get("reach_composition_census") or {}
            for key, value in census.items():
                if key in ("reading", "act_as_refused", "composed", "composed_usd"):
                    continue
                if key in broken:
                    for token, hits in (value or {}).items():
                        broken[key][token] += int(hits)
                    continue
                if key in longest:
                    longest[key] = max(longest[key], int(value))
                    continue
                totals[key] += int(value)
            for reason, hits in (census.get("act_as_refused") or {}).items():
                refused[reason] += int(hits)
            for entry in row.get("reach_composed_magnitudes") or []:
                entities.add(str(entry["entity"]))
                usd += float(entry["published_usd"])
            for entry in row.get("reach_composed_magnitudes_withheld") or []:
                withheld_entities.add(str(entry["entity"]))
        return {
            **dict(sorted(totals.items())),
            **longest,
            "act_as_refused": dict(sorted(refused.items())),
            **{key: dict(sorted(rows_here.items())) for key, rows_here in broken.items()},
            "rows_composing": sum(1 for row in rows if row.get("reach_composed_magnitudes")),
            "rows_withholding_every_composed_figure": sum(
                1
                for row in rows
                if row.get("reach_composed_magnitudes_withheld") and not row.get("reach_composed_magnitudes")
            ),
            "entities_composed": len(entities),
            "entities_withheld": len(withheld_entities),
            "composed_usd_summed_over_rows": round(usd, 2),
        }

    return {
        "findings": roll(findings),
        "subsumed_rows": roll(subsumed),
        "reading": (
            "the composition pass rolled up to the protocol, findings and subsumed rows kept "
            "APART because a subsumed row is usually the same walk under a weaker capability "
            "and summing the two would double one composition and read as twice the recovery. "
            "It is NOT that a subsumed row's dollars stay out of the grade: its entities that "
            "no surviving row reaches charge the top row's exposure at that row's own fraction "
            "(subsumed_exclusive_value_by_entity), and one composed subsumed entity does so "
            "here. licensed_selectors is every "
            "(hop, licensed function) pair a gate-control walk offered; act_as_witnessed is "
            "the subset where the caller is witnessed able to make that call at that "
            "destination; the pairs under act_as_refused are the ones whose magnitude stayed "
            "not_determined and went to confidence instead of the grade. composed_usd is "
            "summed over ROWS and entities are counted distinct, so the two disagree wherever "
            "two rows compose the same entity; the exposure budget, not this figure, is what "
            "stops that entity being paid for twice. A large act_as_refused beside a small "
            "entities_composed is the honest shape of this corpus, not a shortfall in the "
            "pass: most licensed hops have no witness that the licensed party can be made to "
            "use the licence"
        ),
    }


def _signal_identity(signal: FunctionSignal) -> tuple[Any, ...]:
    """What names one signal row across the fold and the confidence pass.

    ``contract_id`` is part of it because split-proxy secondary implementations
    share a ``deployment_address`` and are legitimately different contracts.
    """
    return (signal.contract_id, signal.chain, signal.deployment_address, signal.selector, signal.claim_id)


def _counted(values: Iterable[str]) -> dict[str, int]:
    """A sorted count per distinct token. Empty where nothing was counted."""
    out: dict[str, int] = defaultdict(int)
    for value in values:
        out[value] += 1
    return dict(sorted(out.items()))


def _composition_report(
    composed: dict[str, _ComposedMagnitude],
    census: dict[str, int],
    refusals: dict[str, int],
    withheld: tuple[_WithheldComposition, ...],
    refused_magnitudes: dict[str, int],
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
            "composed_withheld is a LATER and different refusal: those candidates cleared every "
            "witness above and then lost their figure to the composition rule, because the "
            "route they publish is not the route the proof took and nothing proved this "
            "principal could have issued the proven call itself. They keep their gate claim and "
            "their execution record and are listed per row under "
            "reach_composed_magnitudes_withheld"
        ),
    }


@dataclass(frozen=True)
class _DestinationMagnitude:
    """A ``flow.out`` witness at one destination function, as the fold received it.

    ``execution`` is the call that PROVED ``usd`` — caller, target, selector, raw
    calldata, pinned height, seeded-or-not — read off the destination signal's own
    gate rather than reconstructed here. It travels WITH the figure because the
    two are one fact: a magnitude whose execution is not_determined is a number
    with no account of itself, and the composition rule that decides whether the
    figure survives a route the proof never took cannot be written without it.

    ``attribution_derived`` is a property rather than a stored field so the state
    stays the single source of truth: an attribution-derived figure is exactly one
    whose magnitude state says so, and a second copy of that fact could disagree
    with the first.
    """

    state: str
    usd: float
    function: str
    execution: EX.ProvingExecution

    @property
    def attribution_derived(self) -> bool:
        """Whether the figure bounds its principal from ABOVE and never below.

        True on the attribution path, where a constant-amount probe credited a
        holder's whole priced balance. A row summing such contributions has not
        earned a ">=" band, whatever its coverage looks like.
        """
        return self.state in MAGNITUDE_STATES_ATTRIBUTION_DERIVED


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
        usd = float(magnitude.value)  # type: ignore[arg-type]  # _is_number narrows it
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


def _signal_execution(signal: FunctionSignal) -> EX.ProvingExecution:
    """The execution this signal's magnitude was proven by, or the typed reason
    there is none.

    A gate this fold cannot read is not an execution it may assume. ``_gate``
    already degrades an unrecognised token to ``not_determined``, and a
    ``not_determined`` envelope carries no payload — so both of those land on
    :data:`EX.REASON_NOT_PERSISTED`, the same state a row written before the
    record existed lands on. Absence never becomes a match, an empty caller, or
    an unseeded probe.
    """
    gate = _gate(signal, PROVING_EXECUTION_KEY)
    payload = gate.value if isinstance(gate.value, dict) else {}
    ptr = payload.get("transcript_ptr")
    verdict_id = payload.get("effect_verdict_id")
    # The two POINTERS survive the negative branch. They are the row's own
    # identity, not part of the record, and they are exactly what a reader needs
    # in order to go and look at the transcript the record is missing from —
    # dropping them would turn a traceable gap into an untraceable one.
    if gate.state != EX.GATE_STATE_RECORDED:
        reason = payload.get("reason")
        return EX.not_determined(
            reason if reason in EX.NOT_DETERMINED_REASONS else EX.REASON_NOT_PERSISTED,
            transcript_ptr=ptr if isinstance(ptr, str) else None,
            effect_verdict_id=verdict_id if isinstance(verdict_id, int) else None,
        )
    return EX.from_residue(
        payload,
        transcript_ptr=ptr if isinstance(ptr, str) else None,
        effect_verdict_id=verdict_id if isinstance(verdict_id, int) else None,
    )


@dataclass(frozen=True)
class _AdmissionPlanes:
    """The two witnesses the composition rule decides an arm from.

    Bundled because they travel together through five call sites and neither is
    ever consulted without the other: one says whether the principal could have
    authored the destination's calldata itself, the other says what the body the
    chain traverses does to that calldata on the way.
    """

    deletability: P.DeletabilityPlane
    routes: P.RouterFlowPlane


@dataclass(frozen=True)
class _WithheldComposition:
    """A composed candidate whose FIGURE the rule refused, and everything else it keeps.

    Arm 2 withholds the magnitude and nothing else. The gate claim transfers —
    ``isAuthorized(msg.sender, msg.sig)`` reads no argument, so a routing
    mismatch says nothing about it — and the act-as chain that carries it is
    published here in full, beside the execution that was actually run and the
    typed reason the dollars did not survive the difference between them.

    There is no ``published_usd`` and no witnessed figure of any kind. A refusal
    that still prints the number it refused has published it.
    """

    entity: str
    selector: str
    function: str
    chain: tuple[P.ActAsStep, ...]
    execution: EX.ProvingExecution
    arm: str
    reason: str
    route: P.RouteClassification
    deletability: P.DeletabilityVerdict

    @property
    def counter_key(self) -> str:
        """The ``(state, reason)`` pair the refusal counter keys on.

        BOTH halves, never the reason alone: the deletability vocabulary mixes
        one earned negative (a join that ran and returned no row) with three
        undetermined kinds, and bucketing them together would put a proven fact
        and a disclosed unknown under one count — the inv. 1 collapse the whole
        join exists to prevent, relocated into the counter.
        """
        return f"{self.deletability.state}/{self.deletability.reason}"

    def as_json(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "destination_function": self.function,
            "selector": self.selector,
            "arm_taken": self.arm,
            "withheld_reason": self.reason,
            # Spelled, not omitted: a missing key reads as a field nobody filled
            # in, and this one is a refusal somebody made.
            "published_usd": None,
            "proving_execution": self.execution.as_json(),
            "route_comparison": EX.route_comparison(
                self.execution,
                claimed_caller=self.chain[-1].caller if self.chain else None,
                claimed_target=self.chain[-1].destination if self.chain else None,
                claimed_selector=self.chain[-1].calling_selector if self.chain else None,
            ),
            # The gate claim, which survives the refusal in full.
            "act_as_chain": [step.as_json() for step in self.chain],
            "act_as_chain_length": len(self.chain),
            "route_classification": self.route.as_json(),
            "authority_deletability": self.deletability.disclosure(),
            "reading": (
                "the destination carries a flow.out magnitude and this principal is witnessed "
                "able to reach it, and the DOLLARS are still withheld. What was proven is a "
                "call the probe made directly to the destination; what this entry claims is a "
                "route through an intermediate, and the two are compared under route_comparison "
                "rather than assumed equal. The gate claim survives that difference — an "
                "authorization check reads msg.sender and msg.sig and no argument, so a route "
                "the proof did not take says nothing about it — and the act_as_chain above is "
                "published in full. The magnitude does not survive it: route_classification "
                "names what the traversed body does to the destination's arguments, and "
                "authority_deletability names whether this principal could have issued the "
                "proven call itself. Neither answered in favour of the figure, so no figure is "
                "published. This is a REFUSAL and not a zero: nothing here says the principal "
                "moves nothing, only that what it moves is not determined by this evidence"
            ),
        }


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

    1. **The gate claim transfers, always.** It is not one of the branches
       below: every outcome publishes the act-as chain, because an authorization
       check reads ``msg.sender`` and ``msg.sig`` and no argument, so the route
       the proof took is irrelevant to it.
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
        elif route.state in (P.ROUTE_AMOUNT_AUTHORED, P.ROUTE_CALLEE_RESTRICTED):
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
                    sheet = value_plane.total(key)
                    # R4: the witness bounds the call, the sheet bounds what is
                    # there to move. Neither alone, and never their sum.
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


def _instance_contributions(
    instance: _Instance,
    keys: set[str],
    value_plane: P.ValuePlane,
    *,
    transitive: bool,
    composed: dict[str, _ComposedMagnitude] | None = None,
) -> tuple[
    dict[str, float],
    list[dict[str, Any]],
    dict[str, Any] | None,
    list[dict[str, Any]],
    frozenset[str],
    frozenset[str],
]:
    """One call's per-entity contributions, bounded by the one magnitude it proved.

    The fifth member names the keys whose figure came from a composed DESTINATION
    witness, which bounds this principal from above only. It is a subset of the
    returned map's keys: a key the cap below emptied contributes nothing and
    carries no bound either.

    The SIXTH names the keys whose standing figure is PROVEN not to be
    attribution-derived — an earned positive, not the complement of the fifth.
    A key is in it only where a registered magnitude state said so, so a
    contribution whose provenance this fold cannot grade appears in neither set
    and cannot help a row earn a floor. Kept beside the per-key MAX for the same
    reason ``ceilings`` is: which witness produced the figure that STANDS is only
    knowable where the figure is chosen.

    A witnessed magnitude is a per-CALL quantity: ``withdraw`` proven to move
    $28.1M moves $28.1M whichever of the keys it reached holds it. Charging it
    once per key multiplies a single proven number by the size of the reach set,
    which is the balance-sheet-as-a-reach error one level up from the one
    :func:`_entity_contribution` already refuses.

    An ``exact`` witness bounds the whole call, so its keys consume it as a
    budget: the trim falls on whichever key the deterministic order reaches
    last, an arbitrary basis that is published rather than absorbed. A key left
    with no room is ``not_determined``, never a published ``$0.00`` — an
    exhausted budget is not a measurement that the entity holds nothing.

    A ``floor`` witness bounds nothing above: it proves the call moves *at
    least* that much and says nothing about how the amount divides between two
    holders, so over more than one key the call's magnitude is
    ``not_determined`` rather than the floor charged once per key. At one key
    both rules leave the witness exactly as proven.
    """
    per_key: dict[str, float] = {}
    gaps: list[dict[str, Any]] = []
    unbounded: list[dict[str, Any]] = []
    ceilings: set[str] = set()
    non_attributed: set[str] = set()
    for key in sorted(keys):
        contribution, why, note, from_composed, state = _entity_contribution(
            instance, key, value_plane, transitive=transitive, composed=composed
        )
        if note is not None:
            unbounded.append(note)
        if contribution is None:
            # The RAW key the walk reached, not its canonical fold — pre-existing
            # and kept, because this row names where the walk landed and folding
            # it would report a proxy the closure never visited. The keys this
            # unit adds below are canonical, matching ``value_by_entity``.
            gaps.append({"function": instance.signal.function_name, "entity": key, "why": why})
            continue
        # An implementation and the proxy that deploys it are ONE priced entity:
        # the plane already folded the balance onto the proxy, so a row reaching
        # both keys would charge that one balance twice — once in this sum and
        # again in the exposure budget, which is keyed on these same entities.
        canonical = value_plane.canonical(key)
        previous = per_key.get(canonical)
        if previous is None or contribution > previous:
            per_key[canonical] = contribution
            ceilings.discard(canonical)
            # The provenance travels with the figure that replaced the previous
            # one; a stale grade left standing beside a new figure is the same
            # class of error as a stale bound.
            non_attributed.discard(canonical)
        # A tie between a composed ceiling and a witnessed figure publishes the
        # ceiling's bound: the weaker claim is the one both candidates support.
        if from_composed and contribution >= per_key[canonical]:
            ceilings.add(canonical)
        # Symmetrically weak on a tie: a figure equal to the standing one that is
        # attribution-derived REVOKES the grade, because the row may then be
        # publishing the attributed candidate's number.
        if contribution >= per_key[canonical]:
            if state is not None and state not in MAGNITUDE_STATES_ATTRIBUTION_DERIVED:
                non_attributed.add(canonical)
            else:
                non_attributed.discard(canonical)

    magnitude = _witnessed_magnitude(instance)
    if magnitude is None or len(per_key) < 2:
        return (
            per_key,
            gaps,
            None,
            unbounded,
            frozenset(ceilings & set(per_key)),
            frozenset(non_attributed & set(per_key)),
        )

    uncapped = round(sum(sorted(per_key.values())), 6)
    # Only an EXACT witness apportions as a budget. A floor and an
    # attribution-derived upper bound both fail this test and both take the
    # refusal below, for reasons that happen to converge: a floor says nothing
    # about how the amount divides, and an upper bound split across two entities
    # with no apportionment witness would attribute up to the whole bound at
    # each. Neither may join the exact side of this comparison.
    if instance.magnitude.state != MAGNITUDE_STATE_PROVEN_EXACT:
        for key in sorted(per_key):
            gaps.append(
                {
                    "function": instance.signal.function_name,
                    "entity": key,
                    "why": "floor_magnitude_over_multiple_keys_without_apportionment_witness(not_determined)",
                }
            )
        return (
            {},
            gaps,
            {
                "function": instance.signal.function_name,
                "capability": instance.signal.claim_id,
                "witness_state": instance.magnitude.state,
                "witnessed_usd": magnitude,
                "entities": sorted(per_key),
                "uncapped_sum_usd": uncapped,
                "published_sum_usd": None,
                "reading": (
                    "a floor proves the call moves at least this much, never how it divides "
                    "between holders; with no apportionment witness the magnitude of this call "
                    "is not_determined rather than the floor charged once per entity"
                ),
            },
            unbounded,
            frozenset(),
            frozenset(),
        )
    if uncapped <= magnitude:
        return (
            per_key,
            gaps,
            None,
            unbounded,
            frozenset(ceilings & set(per_key)),
            frozenset(non_attributed & set(per_key)),
        )

    capped: dict[str, float] = {}
    exhausted: list[str] = []
    remaining = magnitude
    for key in sorted(per_key):
        take = round(min(per_key[key], remaining), 6)
        remaining = round(remaining - take, 6)
        # A residual under half a cent publishes as $0.00 at the row's rounding,
        # which is the phantom proven-zero this branch exists to refuse — the
        # threshold is the published resolution, not exact equality with zero.
        if take < _PUBLISHED_CENT:
            exhausted.append(key)
            gaps.append(
                {
                    "function": instance.signal.function_name,
                    "entity": key,
                    "why": "call_magnitude_consumed_by_earlier_keys(share_not_determined)",
                }
            )
            continue
        capped[key] = take
    return (
        capped,
        gaps,
        {
            "function": instance.signal.function_name,
            "capability": instance.signal.claim_id,
            "witness_state": instance.magnitude.state,
            "witnessed_usd": magnitude,
            "entities": sorted(per_key),
            "entities_left_not_determined": exhausted,
            "uncapped_sum_usd": uncapped,
            "published_sum_usd": round(sum(sorted(capped.values())), 6),
            "reading": (
                "the witness bounds one call, so its keys consume it as a budget; which key "
                "the trim falls on is decided by the deterministic key order, not by evidence, "
                "and no witness apportions this magnitude between the entities"
            ),
        },
        unbounded,
        frozenset(ceilings & set(capped)),
        frozenset(non_attributed & set(capped)),
    )


def _witnessed_magnitude(instance: _Instance) -> float | None:
    """The one dollar figure this call's witness proved, if it proved one."""
    raw = instance.magnitude.value
    if instance.magnitude.is_determined and _is_number(raw):
        return float(raw)  # type: ignore[arg-type]  # _is_number narrows it
    return None


def _entity_contribution(
    instance: _Instance,
    key: str,
    value_plane: P.ValuePlane,
    *,
    transitive: bool,
    composed: dict[str, _ComposedMagnitude] | None = None,
) -> tuple[float | None, str, dict[str, Any] | None, bool, str | None]:
    """The dollars this call is PROVEN to move against one entity, or ``None``.

    The fourth member says the figure came from the composed branch, which is
    the one branch whose number bounds this principal from ABOVE and never from
    below. It is returned rather than parsed back out of the basis string: the
    row header's bound direction turns on it, and a prose prefix is not a field.

    The FIFTH member is the magnitude state the figure came from — the witness's
    own token, handed back rather than reduced to a boolean here. Two axes read
    it and they are not the same question: the composed flag above says WHICH
    BRANCH supplied the number, and this says what the WITNESS behind it claims.
    An attribution-derived figure (a constant-amount probe crediting a holder's
    whole priced balance) bounds from above whether it arrived through the
    composed branch or through the instance's own witness, so a row cannot grade
    its direction off the branch alone. ``None`` where no figure was produced —
    there is no state to report about a contribution that does not exist.

    There is exactly one source of a number here: a magnitude witness. Reach
    membership answers "can this principal act on that entity"; it does not
    answer "how much does acting move", and the entity's balance sheet answers
    only "how much is there". Substituting the third for the second is the
    balance-sheet-as-a-reach error — an unproven quantity published as a positive
    number — and it is what charged 387 of 442 proven-reach signals a sheet
    nobody proved they could move.

    So the fallthrough is ``not_determined``, and the row does NOT disappear:
    membership stands, ``value_at_stake_usd`` publishes null, the band falls to
    ``UNPRICED_BAND`` (inv. 7's floor — a rug-shaped capability on an empty
    contract still scores), and the missing magnitude is charged to confidence's
    reach-magnitude term, which is the only place an unknown can sit without
    being published as a number.

    A FLOOR witness is bounded by the sheet exactly as an exact one is. The
    witness proves the call moves at least that much SOMEWHERE; against one
    entity it can still move no more than that entity holds, so a $28M floor
    charged against a $1k sheet publishes $28M of a protocol that has $1k — the
    same substitution one step over, with the direction of the error hidden by
    the word "floor". Where the sheet is not determined there is nothing to bound
    it with: the floor stands, and it is DISCLOSED as a figure exceeding an
    unknown sheet rather than published as if the sheet had agreed.

    ``key`` is refused outright when two proxies share it as an implementation:
    the plane folds it onto neither, and charging a shared implementation
    against a proxy picked by sort order publishes the other proxy's sheet.
    """
    if key in value_plane.alias_ambiguous:
        return None, "shared_implementation_folds_onto_no_proxy(not_determined)", None, False, None
    if instance.native_only:
        # A provably native-only flow may only be valued against the native
        # holding, and an absent native row is not_determined, never $0.
        native = P.native_value_state(value_plane, key)
        if not native.is_determined:
            return None, "native_only_flow+absent_native_row(not_determined)", None, False, None
        # Proven, and proven zero carries 0.0 — the pairing is enforced by Tri.
        held: float | None = float(native.value if native.value is not None else 0.0)
        basis = "native_only_flow x native_balance"
    else:
        held = value_plane.total(key)
        basis = "entity_holdings"

    magnitude = _witnessed_magnitude(instance)
    if magnitude is not None:
        state = instance.magnitude.state
        if state == MAGNITUDE_STATE_PROVEN_EXACT:
            # The witness bounds what this call moves; the entity's sheet bounds
            # what is there to move. Neither alone is the answer, and the sheet
            # alone is the balance-sheet-as-a-reach error.
            return (
                (min(held, magnitude) if held is not None else magnitude),
                f"witnessed_reach(exact) x {basis}",
                None,
                False,
                state,
            )
        if held is not None:
            return min(held, magnitude), f"witnessed_reach({_state_word(state)}) x {basis}", None, False, state
        # NEITHER a floor NOR an upper bound may be charged against an entity
        # whose priced sheet is not_determined without saying so. The arithmetic
        # is the same on both — nothing was available to bound the figure with —
        # but the two disclosures are opposite claims and are published under
        # opposite names: a floor says the call moves AT LEAST this much
        # somewhere, an upper bound says the whole figure is a ceiling that no
        # witness says the call reaches. Writing an upper bound under
        # ``witnessed_floor_usd`` would republish it as the one thing it is not.
        return (
            magnitude,
            f"witnessed_reach({_state_word(state)})+sheet_not_determined",
            {
                "function": instance.signal.function_name,
                "capability": instance.signal.claim_id,
                "entity": key,
                "witness_state": state,
                **_unbounded_figure(state, magnitude),
                "reading": _unbounded_reading(state),
            },
            False,
            state,
        )
    supplied = (composed or {}).get(value_plane.canonical(key))
    if supplied is not None:
        # The dollars are the DESTINATION function's witness, composed along a
        # path every hop of which carries an act-as witness. The bound against
        # this entity's sheet was already applied where a sheet existed; where it
        # did not, the same disclosure the floor branch owes is owed here.
        note = (
            None
            if supplied.sheet_usd is not None
            else {
                "function": instance.signal.function_name,
                "capability": instance.signal.claim_id,
                "entity": supplied.entity,
                "witness_state": supplied.witness_state,
                **_unbounded_figure(supplied.witness_state, supplied.usd),
                "reading": (
                    "a composed magnitude charged against an entity whose priced sheet is "
                    f"not_determined: {supplied.function} at {supplied.entity} is witnessed "
                    "moving this much, and no sheet was available to bound it against"
                ),
            }
        )
        return (
            supplied.usd,
            f"composed_reach_magnitude({supplied.function}) x {basis}",
            note,
            True,
            supplied.witness_state,
        )
    if held is None:
        return (
            None,
            ("entity_value_not_determined" if not transitive else "closure_entity_value_not_determined"),
            None,
            False,
            None,
        )
    return (
        None,
        ("reach_magnitude_not_witnessed(not_determined) x " + basis + ("+closure" if transitive else "")),
        None,
        False,
        None,
    )


def _state_word(state: str) -> str:
    """The magnitude state as the one word the basis prose uses.

    Derived from the token rather than written per branch, so a state that joins
    the vocabulary cannot silently keep publishing another state's word. An
    unregistered token prints as itself: a reader who sees a raw token knows the
    prose was not written for it, which is better than seeing "floor".
    """
    return state.removeprefix("proven_")


def _unbounded_figure(state: str, usd: float) -> dict[str, float]:
    """The disclosed figure, under the name its DIRECTION earns.

    A floor and an upper bound charged against an unpriced sheet are the same
    arithmetic and opposite claims, so they are published under different keys —
    a consumer reading ``witnessed_floor_usd`` must never pick up a ceiling. A
    state with no registered direction publishes the figure under a name that
    claims neither.
    """
    if state == MAGNITUDE_STATE_PROVEN_FLOOR:
        return {"witnessed_floor_usd": usd}
    if state in MAGNITUDE_STATES_ATTRIBUTION_DERIVED:
        return {"witnessed_upper_bound_usd": usd}
    return {"witnessed_usd": usd}


def _unbounded_reading(state: str) -> str:
    if state in MAGNITUDE_STATES_ATTRIBUTION_DERIVED:
        return (
            "an attribution-derived magnitude charged against an entity whose priced sheet is "
            "not_determined: the figure is a holder's whole priced balance credited off a "
            "constant-amount probe, so it bounds this call from ABOVE and nothing here says "
            "the call moves it — and no sheet was available to bound it against this entity"
        )
    return (
        "a floor witness charged against an entity whose priced sheet is "
        "not_determined: nothing here says the entity holds this much, only that "
        "the call moves at least this much somewhere, and no sheet was available "
        "to bound it against this entity"
    )


# A licensed hop the composition walk never offered, because it never reached
# the hop's CALLER: every path from the seized node to it broke at an earlier
# hop that carried no act-as witness. Not an act-as refusal at this hop — the
# question was never asked here — and named separately for exactly that reason.
ACT_AS_CALLER_UNREACHED = "caller_not_reachable_from_the_seized_node"

HOP_REFUSED_SCOPE = "gate_scope_not_determined"
HOP_REFUSED_CONFERRAL = "gate_does_not_confer_this_scope"
HOP_REFUSED_CONDITION = "caller_condition_not_satisfiable"

# Every gate-control capability, each asking the conferral question with its own
# witness. The census has no signal instance to ask, so it asks the class-wide
# union — an upper bound on what any one instance's walk can confer, and labelled
# as one wherever it is published.
_CENSUS_GATE_CAPABILITIES = tuple(sorted(K.GATE_CONTROL_CAPABILITIES))

# Duplicate edge rows are real — 2,937 rows over 565 distinct pairs — and a pair
# is walked when ANY of its edges licenses it, so the census counts pairs and has
# to pick which of a pair's answers to report. Each ranking reports the answer
# that got FURTHEST, so a pair is never filed under a shortfall one of its own
# edges did not have. Ordering is by rank, ties impossible (the keys are total).
_CONFERRAL_RANK = {
    P.CONFERRAL_CONFERRED: 0,
    # The gate was asked and the label was readable; these two are the real
    # negative answers and rank alike.
    P.CONFERRAL_ROLE_NOT_LICENSED: 1,
    P.CONFERRAL_VARIABLE_NOT_REWRITTEN: 2,
    # Coverage shortfalls: nothing about this gate or this label was read.
    P.CONFERRAL_WRITES_NOT_EXTRACTED: 3,
    P.CONFERRAL_SCOPE_NOT_DETERMINED: 4,
}
# A pair every edge of which was bound reports the SHARPEST bound it hit: being
# disproved at the destination is a fact about the destination's own code, and
# outranks "this gate does not confer it", which outranks "the label said
# nothing".
_REFUSAL_RANK = {HOP_REFUSED_CONDITION: 0, HOP_REFUSED_CONFERRAL: 1, HOP_REFUSED_SCOPE: 2}
# Among the edges that DID walk a pair, the most specific scope reported it.
_SCOPE_KIND_RANK = {P.SCOPE_ROLES: 0, P.SCOPE_STATE_VAR: 1, P.SCOPE_NOT_DETERMINED: 2}


def _hop_census(closure: P.ControlClosure, conditions: P.ConditionPlane, conferral: P.ConferralPlane) -> dict[str, Any]:
    """Every hop in the graph, by what each class of capability can prove of it.

    Counted over DISTINCT ``(principal, anchor)`` pairs. ``control_graph_edges``
    holds one row per witnessed read — several times the pair count — so an
    edge-keyed census would report the same hop as many findings as the resolver
    happened to look.

    Published whether or not a bound ever bit: a rule with no fired count and a
    rule that was never wired read identically from the outside.

    Gate control is now capability-dependent — ownership.transfer and
    authority.replace confer different hops — so the class-level block is the
    UNION over the five gate capabilities (a hop is counted walked there if ANY
    of them confers it) and ``by_capability`` carries each one's own answer. The
    union is an upper bound twice over: over the capabilities, and over the
    instances, because each capability is asked with the union of what its
    witnesses rewrite anywhere rather than with one function's own set.
    """
    pairs: dict[tuple[str, str], list[P.ControlEdge]] = defaultdict(list)
    for edge in closure.edges:
        pairs[(edge.principal, edge.anchor)].append(edge)
    census: dict[str, Any] = {"distinct_hops": len(pairs), "edges": len(closure.edges)}

    def count(grant: P.GateGrant | None) -> dict[str, Any]:
        counts: dict[str, int] = {"walked": 0, HOP_REFUSED_SCOPE: 0, HOP_REFUSED_CONFERRAL: 0, HOP_REFUSED_CONDITION: 0}
        counts.update(dict.fromkeys(P.WALKED_COVERAGE, 0))
        by_scope_kind = {P.SCOPE_ROLES: 0, P.SCOPE_STATE_VAR: 0, P.SCOPE_NOT_DETERMINED: 0}
        conferral_outcomes: dict[str, int] = dict.fromkeys(P.CONFERRAL_OUTCOMES, 0)
        for (principal, anchor), edges in pairs.items():
            if grant is not None:
                outcomes = [grant.confers(edge.scope, edge.anchor).outcome for edge in edges]
                conferral_outcomes[min(outcomes, key=lambda o: _CONFERRAL_RANK[o])] += 1
            bounds = [(_hop_bound(edge, conditions, grant=grant), edge) for edge in edges]
            walked = [edge for bound, edge in bounds if bound is None]
            if not walked:
                refusals = [str(bound["reason"]) for bound, _ in bounds if bound is not None]
                counts[min(refusals, key=lambda r: _REFUSAL_RANK[r])] += 1
                continue
            counts["walked"] += 1
            by_scope_kind[min((edge.scope.kind for edge in walked), key=lambda k: _SCOPE_KIND_RANK[k])] += 1
            counts[conditions.hop(principal, anchor).coverage or P.WALKED_NO_FUNCTION] += 1
        out: dict[str, Any] = dict(counts)
        out["walked_by_scope_kind"] = dict(sorted(by_scope_kind.items()))
        if grant is not None:
            out["conferral"] = dict(sorted(conferral_outcomes.items()))
        return out

    census["code_control"] = count(None)
    by_capability: dict[str, Any] = {}
    walked_by_any: set[tuple[str, str]] = set()
    conferred_by_any: set[tuple[str, str]] = set()
    for capability in _CENSUS_GATE_CAPABILITIES:
        grant = conferral.capability_grant(capability)
        by_capability[capability] = count(grant)
        for pair, edges in pairs.items():
            for edge in edges:
                if grant.confers(edge.scope, edge.anchor).conferred:
                    conferred_by_any.add(pair)
                    if _hop_bound(edge, conditions, grant=grant) is None:
                        walked_by_any.add(pair)
    census["gate_control"] = {
        "walked_by_at_least_one_gate_capability": len(walked_by_any),
        "conferred_by_at_least_one_gate_capability": len(conferred_by_any),
        "conferred_by_none": len(pairs) - len(conferred_by_any),
        "reading": (
            "the union over the five gate capabilities, each asked with the class-wide union of "
            "what its witnesses rewrite. It is an upper bound on every real walk twice over — "
            "over capabilities and over instances — and no finding walks it. by_capability is "
            "the per-capability answer at the same class-wide width"
        ),
    }
    census["gate_control_by_capability"] = by_capability
    # The label-names-nothing population, counted three ways because a pair is
    # not an edge and a pair carrying one unlabelled edge is not a pair a gate
    # can be withheld on: the walk reaches a destination if ANY of the pair's
    # edges confers it, so only pairs with no labelled edge at all can lose their
    # hop to this rule. Publishing only the deduped number would report the 55
    # unlabelled role edges as 9.
    unlabelled_edges = [edge for edge in closure.edges if not edge.scope.is_determined]
    unlabelled_pairs = {(edge.principal, edge.anchor) for edge in unlabelled_edges}
    by_relation: dict[str, int] = defaultdict(int)
    for edge in unlabelled_edges:
        by_relation[str(edge.relation) if edge.relation else edge.witness] += 1
    census["scope_not_determined"] = {
        "edges": len(unlabelled_edges),
        "pairs_carrying_one": len(unlabelled_pairs),
        "pairs_with_no_labelled_edge": sum(
            1 for pair in unlabelled_pairs if all(not edge.scope.is_determined for edge in pairs[pair])
        ),
        "edges_by_relation": dict(sorted(by_relation.items())),
        "reading": (
            "edges whose label names neither a role nor a state variable — the role_principal "
            "rows that restate their own relation, and the column witnesses that carry no label "
            "at all. Every one is published as not_determined for gate control and none is "
            "dropped; code control does not ask the question"
        ),
    }
    census["reading"] = (
        "what each class could establish about every hop the closure holds, before any "
        "signal seeds it. A hop counted not_determined here is withheld from a finding "
        "only when that finding's walk actually needs it and no other path reaches the "
        "destination; the per-finding lists carry that narrower population. The four "
        "walked_* counts partition `walked` by what was READ to walk it: only "
        "walked_on_fully_analysed_conditions rests on a surface read in full, "
        "walked_on_partly_analysed_conditions found no guard on the functions it could read "
        "and could not read all of them, and the last two are hops where no condition "
        "existed to read at all, walked on the edge alone. walked_by_scope_kind partitions "
        "the same total by what the edge label named. `conferral` partitions every hop by "
        "the CONFERRAL test — whether the gate is witnessed to seize the authority the hop "
        "runs on — which replaced the label-presence test that walked any labelled edge"
    )
    return census


def _hop_bound(
    edge: P.ControlEdge, conditions: P.ConditionPlane, *, grant: P.GateGrant | None
) -> dict[str, Any] | None:
    """Why this hop is NOT walked as proven, or ``None`` when it is.

    Two bounds, in the order that costs least to decide. The SCOPE bound is
    gate-control's alone — ``grant`` is the gate asking, and ``None`` is code
    control, which does not ask: controlling the code exercises everything the
    code is authorized to exercise, whatever the label happened to record.

    For a gate the question is CONFERRAL, not label presence: a ``roles N`` edge
    is walked where the role -> selector join names functions role N licenses at
    the destination, and a ``state_var`` edge where the gate's own witness is
    observed to rewrite a variable of that name. A label naming a scope the gate
    is not witnessed to seize (`hook`, `vault`, `roleRegistry`) is no longer
    enough, and neither is a label naming nothing at all — 55 of the role edges
    restate their own relation and name no role.

    The CONDITION bound is shared: the destination's own guards may pin their
    caller to the destination itself, and no authority relation makes one
    address another.

    A refused hop is a published ``not_determined``, never a silent drop and
    never a proven negative.
    """
    if grant is not None:
        verdict = grant.confers(edge.scope, edge.anchor)
        if not verdict.conferred:
            return {
                "caller": edge.principal,
                "destination": edge.anchor,
                # The unlabelled edges keep their own reason: "the label named
                # nothing" and "the label named something this gate does not
                # seize" are different shortfalls and only the first is a
                # pipeline gap.
                "reason": (
                    HOP_REFUSED_SCOPE if verdict.outcome == P.CONFERRAL_SCOPE_NOT_DETERMINED else HOP_REFUSED_CONFERRAL
                ),
                "conferral": verdict.outcome,
                "capability": grant.capability,
                "relation": edge.relation,
                "witness": edge.witness,
                "edge_label": edge.scope.label,
                "basis": verdict.basis,
            }
    hop = conditions.hop(edge.principal, edge.anchor)
    if hop.state == P.HOP_WALKED:
        return None
    return {
        "caller": edge.principal,
        "destination": edge.anchor,
        "reason": HOP_REFUSED_CONDITION,
        "relation": edge.relation,
        "witness": edge.witness,
        "edge_label": edge.scope.label,
        "basis": hop.basis,
        "surface": hop.surface,
        "functions_consulted": hop.functions_consulted,
        "disproving_conditions": list(hop.disproving),
    }


def _behind_the_frontier(
    gaps: list[dict[str, Any]],
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    value_plane: P.ValuePlane,
    reached: set[str],
) -> dict[str, Any]:
    """The entities a row's withheld hops hide, counted rather than left implicit.

    A hop published as ``not_determined`` names one destination. The closure
    places a whole subtree behind that destination, and none of it appears on the
    row: two published hops can withhold twenty-two entities, twenty of which are
    named nowhere in the document. The withheld population is therefore SIZED
    here, by walking the closure from the withheld destinations with no scope
    bound at all — the widest walk this fold performs, which is code control's —
    and subtracting what the row reached anyway.

    This is the size of what was withheld and NOT a claim of reach: the row does
    not reach these entities, that is the whole point. The number is an upper
    bound on the subtree for the same reason the code-control walk is an upper
    bound on any gate's, and it is published as one.
    """
    if not gaps:
        return {"hops": 0, "entities": 0, "entity_keys": [], "reading": "no hop was withheld"}
    frontier = {str(gap["destination"]) for gap in gaps}
    seen, _, _, _ = _closure(frontier, closure, conditions, grant=None)
    behind = sorted({value_plane.canonical(key) for key in seen} - reached)
    return {
        "hops": len(gaps),
        "entities": len(behind),
        "entity_keys": behind,
        "reading": (
            "entities the closure places behind the hops this row could not establish, and which "
            "the row therefore does NOT reach. Sized by walking from the withheld destinations "
            "with no scope bound — the widest walk this fold performs — so it is an upper bound "
            "on the withheld subtree, published because a withheld frontier hop otherwise hides "
            "everything behind it with no trace in the document"
        ),
    }


def _closure(
    seeds: set[str], closure: P.ControlClosure, conditions: P.ConditionPlane, *, grant: P.GateGrant | None
) -> tuple[set[str], list[dict[str, Any]], dict[str, set[P.LicensedFunction]], list[_WalkedHop]]:
    """The reach the walk proves, every hop it could not establish, and what the
    hops it did walk LICENSE at each destination.

    ``grant`` is the gate doing the walking; ``None`` is code control, which asks
    no conferral question. The third return value is the role -> selector join's
    output, keyed by the RAW anchor: the named functions a walked ``roles`` hop
    licenses there. Callers that publish it re-key onto the canonical entity,
    which is what the reach set is keyed on and what a consumer joins against.
    It is the reach's own answer to "to do *what*", and it is
    what a compositional magnitude is later attributed to — a destination reached
    only through state-variable hops has no entry, because nothing named which of
    its functions the gate reaches.

    The burn sentinel is refused at every hop. ``load_control_closure`` already
    refuses ``0x0`` at both ends of an edge, so on the production path that guard
    never fires. It is here because the fold's guarantee must not be a property
    of how the closure was BUILT: the sentinel is the single largest fan-out in
    the graph, and one edge into it — from a repoint witness, a hand-built
    closure, or a future loader — would otherwise hand a row everything behind
    ``msg.sender != 0x0``. Refusing reach is always monotone, so the second line
    of defence costs nothing.

    The second return value is the hops this walk did not walk AS PROVEN, keyed
    on the distinct ``(caller, destination)`` pair. The edge table carries one
    row per witnessed read — 2,937 rows over 565 pairs on the reference corpus —
    so counting refusals per EDGE would report the same withheld hop five times
    and read as five findings.

    The fourth return value is the walked hops themselves — (caller, destination,
    what that hop licensed there). The licensed map above collapses every caller
    that reached a destination into one entry, which is the right shape for "what
    does this row reach it to do" and the wrong one for composing a magnitude:
    the question a composition asks is whether THAT caller can be made to act,
    and a map keyed on the destination alone cannot say which caller a licence
    came from.
    """
    seen: set[str] = set()
    withheld: dict[tuple[str, str], dict[str, Any]] = {}
    licensed: dict[str, set[P.LicensedFunction]] = defaultdict(set)
    walked: dict[tuple[str, str], set[P.LicensedFunction]] = {}
    stack = [key for key in sorted(seeds) if not P.is_zero_key(key)]
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        for edge in closure.edges_from(key):
            if P.is_zero_key(edge.anchor):
                continue
            bound = _hop_bound(edge, conditions, grant=grant)
            if bound is None:
                here: set[P.LicensedFunction] = set()
                if grant is not None:
                    here = set(grant.confers(edge.scope, edge.anchor).licensed)
                    licensed[edge.anchor].update(here)
                walked.setdefault((edge.principal, edge.anchor), set()).update(here)
                if edge.anchor not in seen:
                    stack.append(edge.anchor)
                continue
            withheld.setdefault((edge.principal, edge.anchor), bound)
    # A hop another path reached anyway withheld nothing: the destination is in
    # reach either way, and reporting it as a gap would publish a shortfall the
    # walk does not have.
    gaps = [bound for pair, bound in sorted(withheld.items()) if pair[1] not in seen]
    hops = [
        _WalkedHop(caller=pair[0], destination=pair[1], licensed=frozenset(rows))
        for pair, rows in sorted(walked.items())
    ]
    return seen, gaps, {key: set(rows) for key, rows in sorted(licensed.items()) if rows}, hops


def _gap_reading(exposure: float | None, unpriced: list[Any], exhausted: list[Any], partial: list[Any]) -> str:
    """How to read one gap entry, assembled from the reasons that actually fired.

    A null exposure and a published one are opposite cases and cannot share a
    sentence: the first measured nothing, the second measured a MARGINAL share
    and understates by an amount this accounting can name.
    """
    parts = [
        (
            "not counted and not read as zero; where the exposure is null nothing "
            "about this finding's dollar exposure was measured"
        )
        if exposure is None
        else (
            "the published figure is this row's MARGINAL share of what it reaches, so it is "
            "a floor on this finding's exposure and not a measurement of it"
        )
    ]
    if unpriced:
        parts.append(
            "the unpriced entities are absent from it rather than counted as zero, so nothing "
            "here says they hold nothing"
        )
    if exhausted:
        parts.append(
            "the entities under budget_exhausted_entities were charged in full by the findings "
            "listed against them, so this row's share of those entities is unmeasured, not zero"
        )
    if partial:
        parts.append(
            "the entities under budget_partially_exhausted_entities were charged at less than "
            "this row's own fraction, and the difference is missing from the figure"
        )
    return "; ".join(parts)


def _grade(
    findings: list[dict[str, Any]], value_plane: P.ValuePlane
) -> tuple[float | None, float | None, float | None, list[dict[str, Any]], dict[str, Any]]:
    if not findings:
        return None, None, None, [], _exposure_coverage([], value_plane, value_plane.tracked_total)
    for index, finding in enumerate(findings):
        finding["net_points_lambda"] = round(finding["raw_points"] * (K.LAMBDA**index), 4)
    cumulative = round(sum(f["net_points_lambda"] for f in findings), 4)
    grade_lambda = round(100.0 - min(cumulative, 100.0), 4)

    claimed: dict[str, float] = defaultdict(float)
    # Which findings spent each entity's budget, so a later row that finds it
    # empty can name them instead of publishing the emptiness as a measurement.
    claimed_by: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exposure = 0.0
    gaps: list[dict[str, Any]] = []
    any_priced = False
    for finding in findings:
        # W2c/R9 hook (this dict lookup is the whole change to this function):
        # inv.5 is the weakest path TO THAT ENTITY, so a merged unit charges each
        # entity at the rung of the members proven to reach it, not at the unit's
        # weakest member.
        per_entity_weakness = finding.get("weakness_by_entity") or {}
        mine = 0.0
        # Entities this row could actually measure a share of. An entity whose
        # budget earlier rows already spent is priced and still unmeasurable,
        # so counting it here is what published the exhaustion as a zero.
        measured_entities = 0
        exhausted: list[dict[str, Any]] = []
        partial: list[dict[str, Any]] = []
        unpriced: list[str] = []
        exclusive = finding.get("subsumed_exclusive_value_by_entity") or {}
        charged_entities = list(finding["reach_entities"]) + [
            k for k in exclusive if k not in finding["reach_entities"]
        ]
        for key in charged_entities:
            # The row's OWN per-entity contribution, not its total: charging the
            # row total against each entity would multiply one witnessed
            # magnitude by the number of entities it was spread across.
            held = finding["value_by_entity"].get(key)
            # An entity only a subsumed row reaches is charged at THAT row's
            # fraction, never at this one's.
            key_fraction = finding["severity_proven"] * per_entity_weakness.get(key, finding["weakness"])
            if held is None and key in exclusive:
                held = exclusive[key]["usd"]
                key_fraction = exclusive[key]["fraction"]
            if held is None:
                # An unpriced entity contributes nothing AND is disclosed. Reading
                # it as $0.00 publishes "this capability exposes nothing" out of a
                # price lookup that never answered.
                unpriced.append(key)
                continue
            room = max(0.0, 1.0 - claimed[key])
            if room <= 0.0:
                # Earlier findings spent this entity's whole budget. The
                # remainder is not a measured $0.00 — it is a share this
                # accounting cannot separate from theirs, so it is disclosed
                # with the rows that took it rather than summed as a zero.
                exhausted.append({"entity": key, "claimed_by": list(claimed_by[key])})
                continue
            measured_entities += 1
            take = min(key_fraction, room)
            if room < key_fraction:
                # A partial charge understates by exactly the difference, and it
                # does so silently: the published figure is this row's MARGINAL
                # share, not its exposure to the entity. Which row was marginal
                # is a function of the sort order, not of what anyone reaches.
                partial.append(
                    {
                        "entity": key,
                        "fraction_wanted": round(key_fraction, 6),
                        "fraction_taken": round(take, 6),
                        "claimed_by": list(claimed_by[key]),
                    }
                )
            if take > 0:
                claimed[key] += take
                claimed_by[key].append(
                    {
                        "principal_unit": finding["principal_unit"],
                        "capability": finding["capability"],
                        "fraction_taken": round(take, 6),
                    }
                )
                mine += take * held
        finding["exposure_entities_charged"] = sorted(
            key for key in charged_entities if finding["value_by_entity"].get(key) is not None or key in exclusive
        )
        if measured_entities:
            any_priced = True
            finding["exposure_usd"] = round(mine, 2)
        else:
            # Either no priced entity in reach, or every priced one's budget was
            # already spent: the exposure of this finding is a quantity nobody
            # measured, and null is the only honest answer.
            finding["exposure_usd"] = None
        if unpriced or exhausted or partial or finding["exposure_usd"] is None:
            # One gap per finding, never two: a row with an unpriced entity AND
            # a spent budget has one set of reasons, not one entry per reason.
            # Every key is present on every entry — an empty list is the proven
            # negative "this did not happen", which is not the same published
            # fact as a key that is missing.
            #
            # S5: repopulated from the row's own undetermined instances, which
            # is where an unpriced entity actually lands.
            unpriced_entities = sorted(set(unpriced) | {row["entity"] for row in finding["undetermined_instances"]})
            gaps.append(
                {
                    "principal_unit": finding["principal_unit"],
                    "capability": finding["capability"],
                    "unpriced_entities": unpriced_entities,
                    "undetermined_instances": finding["undetermined_instances"],
                    "budget_exhausted_entities": exhausted,
                    "budget_partially_exhausted_entities": partial,
                    "exposure_usd": finding["exposure_usd"],
                    "reading": _gap_reading(finding["exposure_usd"], unpriced_entities, exhausted, partial),
                }
            )
        # A finding whose exposure is not_determined contributes nothing to the
        # total and is disclosed in exposure_gaps; it is never summed as a zero.
        if finding["exposure_usd"] is not None:
            exposure += finding["exposure_usd"]

    tracked = value_plane.tracked_total
    coverage = _exposure_coverage(findings, value_plane, tracked)
    if not tracked or not any_priced:
        return grade_lambda, None, round(exposure, 2), gaps, coverage
    return grade_lambda, round(100.0 * (1.0 - exposure / tracked), 3), round(exposure, 2), gaps, coverage


def _exposure_coverage(findings: list[dict[str, Any]], value_plane: P.ValuePlane, tracked: float) -> dict[str, Any]:
    """How much of the perimeter the exposure ratio was actually measured over.

    ``grade_exposure`` is ``100 * (1 - exposure / tracked_total)``. The
    denominator is the whole priced perimeter; the numerator is a sum over only
    the findings whose exposure could be measured at all. Once an unwitnessed
    magnitude publishes ``not_determined`` instead of a balance sheet, most
    findings contribute nothing to that numerator — and a ratio near 100 then
    reads as "almost nothing is exposed" when what it says is "almost nothing
    was measurable". The ratio is not adjusted for this: adjusting it would mint
    a number out of the same absence. It is DISCLOSED, so the figure cannot be
    read as a measurement it is not.

    ``perimeter_usd_charged`` is the priced value of the entities that received
    a charge, and ``perimeter_usd_reached_unmeasured`` the priced value reached
    by findings whose own exposure is ``not_determined`` and which no charged
    row covers — the weight the ratio is silent about.
    """
    determined = [f for f in findings if f.get("exposure_usd") is not None]
    undetermined = [f for f in findings if f.get("exposure_usd") is None]
    charged: set[str] = set()
    for finding in determined:
        charged.update(finding.get("exposure_entities_charged") or [])

    def priced(keys: set[str]) -> float:
        total = 0.0
        for key in sorted(keys):
            value = value_plane.total(value_plane.canonical(key))
            if value is not None:
                total += value
        return round(total, 2)

    unmeasured: set[str] = set()
    for finding in undetermined:
        unmeasured.update(value_plane.canonical(key) for key in finding.get("reach_entities") or [])
    unmeasured -= {value_plane.canonical(key) for key in charged}
    charged_usd = priced(charged)
    return {
        "findings": len(findings),
        "findings_with_determined_exposure": len(determined),
        "findings_with_exposure_not_determined": len(undetermined),
        "entities_charged": len(charged),
        "perimeter_usd_charged": charged_usd,
        "perimeter_usd_reached_unmeasured": priced(unmeasured),
        "tracked_total_usd": round(tracked, 2) if tracked else None,
        "tracked_share_measured_pct": (round(100.0 * charged_usd / tracked, 3) if tracked else None),
        "reading": (
            "grade_exposure divides a numerator summed over "
            f"{len(determined)} of {len(findings)} findings by the WHOLE priced perimeter. The "
            "other findings publish exposure_usd null — no witness proved how much their reach "
            "moves — and contribute nothing rather than a zero, so a grade_exposure near 100 is "
            "'this much of the perimeter was not measured against', never 'this much is safe'. "
            "perimeter_usd_reached_unmeasured is the priced value those findings reach that no "
            "charged row covers"
        ),
    }


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


def _confidence(
    signals: list[FunctionSignal],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    proven_eoas: set[str],
    discovery_entities: dict[str, set[str]] | None = None,
    composed_signals: set[tuple[Any, ...]] | None = None,
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
            own = _gate(signal, "reach_magnitude_usd").is_determined
            by_composition = not own and _signal_identity(signal) in (composed_signals or set())
            magnitude[key][1] += 1
            magnitude_census[signal.claim_id][1] += 1
            if own or by_composition:
                magnitude[key][0] += 1
                magnitude_census[signal.claim_id][0] += 1
            if by_composition:
                composed_census[signal.claim_id] += 1

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
    # So the exposure is SIZED and published rather than closed. Composition does
    # widen it — it is what turns a 0/n entity into a mixed one — and the two
    # figures below say by exactly how much: the largest single deletion that
    # could move the term, and the move if every unwitnessed signal at every
    # mixed entity vanished at once.
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
            "by_capability": {k: v for k, v in sorted(magnitude_census.items())},
            "mixed_witness_entities": len(mixed),
            # The size of the monotonicity edge below, in the term's own units.
            # The first is the most the term could rise from deleting ONE
            # unwitnessed proven-reach signal; the second from deleting every
            # unwitnessed signal at every mixed entity.
            "mixed_witness_max_single_deletion_gain_pct": mixed_single_pct,
            "mixed_witness_total_deletion_gain_pct": mixed_total_pct,
            "mixed_witness_reading": (
                "entities carrying BOTH a witnessed and an unwitnessed proven reach. The term "
                "is a per-entity fraction, so deleting an unwitnessed signal from one of these "
                "raises it — a monotonicity edge this model does not close, published rather "
                "than hidden, because every denominator that closes it charges a signal for a "
                "magnitude it does not owe. It is not this term's shape alone: the "
                "reachability and capability terms are the same fraction over the same "
                "population and move the same way. The two gain figures beside this bound the "
                "exposure in the term's own units, so a reader can see what the edge is worth "
                "rather than only that it exists"
            ),
            "denominator_rule": (
                "EVERY proven-reach signal, with no per-capability exclusions: a capability "
                "that publishes proven_reach is claiming it moves value, so 'how much' is a "
                "question it owes an answer to. The freeze fraction (pause.set) is in the "
                "denominator and unanswered by design until a witness for it exists"
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


# ---------------------------------------------------------------- disclosures


def _collect_disclosures(
    signal: FunctionSignal,
    earned_negatives: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    warnings: list[dict[str, Any]],
) -> None:
    entity = entity_key(signal.chain, signal.deployment_address)
    credit = _gate(signal, "exact_empty_credit")
    if credit.is_determined:
        if signal.principal_state != PRINCIPAL_STATE_NOT_DETERMINED:
            # "No resolved caller can reach this" cannot be published beside ANY
            # determined caller state: ``enumerated`` names callers that reach it,
            # and ``none_required`` is a PROVEN PUBLIC PATH — the opposite pole,
            # and the worse contradiction of the two.
            warnings.append(
                _warning(
                    "exact_empty_credit_contradicted_by_principals",
                    signal,
                    (
                        "an earned empty caller set on a function with a proven public path"
                        if signal.principal_state == PRINCIPAL_STATE_NONE_REQUIRED
                        else "an earned empty caller set on a function whose principals resolved"
                    ),
                    principal_state=signal.principal_state,
                )
            )
        elif (entity, signal.function_name) not in seen:
            seen.add((entity, signal.function_name))
            payload = credit.value if isinstance(credit.value, dict) else {}
            earned_negatives.append(
                {
                    "entity": entity,
                    "function": signal.function_name,
                    "capability": signal.claim_id,
                    "fact": "no resolved caller can reach this function",
                    "state": "currently_unreachable",
                    "observed_at_block": payload.get("block"),
                    "empty_reason": payload.get("empty_reason"),
                    "counterfactual": "one ownership/authority write restores reachability",
                    "axiom": (
                        "msg.sender != 0x0, so an owner disjunct of {0x0} is a singleton rather than the empty set"
                    ),
                    "re_enablable_by": NOT_DETERMINED,
                }
            )
    if signal.value_state == VALUE_STATE_PROVEN_NO_REACH and (entity, signal.function_name + ":no_reach") not in seen:
        # An earned negative in its own right: reach was WITNESSED and reached
        # nothing. Publishing it beside the undetermined rows would lose the one
        # value fact on the page that was actually proven.
        seen.add((entity, signal.function_name + ":no_reach"))
        earned_negatives.append(
            {
                "entity": entity,
                "function": signal.function_name,
                "capability": signal.claim_id,
                "fact": "reach was witnessed and reached no value",
                "state": "proven_no_reach",
                "basis": signal.value_basis,
                "counterfactual": "funding the entity would give this capability something to reach",
                "re_enablable_by": NOT_DETERMINED,
            }
        )
    latch = _gate(signal, "latch_witness")
    if latch.is_determined:
        payload = latch.value if isinstance(latch.value, dict) else {}
        warnings.append(
            _warning(
                "one_shot_latch_is_reopenable",
                signal,
                "a consumed latch is a now-fact, re-openable by the upgrade authority of the probed proxy",
                latch_state=payload.get("latch_state"),
                probe_block=payload.get("probe_block"),
            )
        )
    for note in signal.witness_notes:
        if note in _NOTE_WARNINGS:
            warnings.append(_warning(note, signal, _NOTE_WARNINGS[note]))


_NOTE_WARNINGS = {
    "destination_not_determined_row_withheld": (
        "the destination was not proven, so no severity is assigned and the row does not "
        "enter the grade; absence of a resolved constraint is not proof the destination is open"
    ),
    "destination_witnesses_contradict": (
        "two destination witnesses cannot both be true, so neither is adopted and the row is withheld"
    ),
    "caller_arbitrary_escalation_withheld": "caller_arbitrary carries no behavioural existence proof",
    "reach_floor_not_a_bound": "a 0.00 floor is 'no proven bound', not a proven zero",
    "reach_floor_absent": "reach_indeterminate with no floor key: nothing about the balance was witnessed",
    "reach_seeded_balance_only": "the contract's balance was overridden before the payout",
    "reach_partially_priced": "the reach is a proven floor; the unpriced remainder is a confidence gap",
    "freeze_effectiveness_not_determined": (
        "no fork proof that the latch takes effect, so no value membership is charged"
    ),
    "freeze_immobilised_fraction_not_determined": (
        "the value held at the frozen entity is measured; what fraction is immobilised has no witness"
    ),
    "product_claim_reachability_unproven": "treated as product on claim_id alone, but openness is not_determined",
    "claim_type_not_scored": "no severity model exists for this claim type; exclusion is not a benign verdict",
    "restricted_privileged_no_principal": "restricted privileged function with no resolved principal",
    "empty_caller_set_not_earned": (
        "an empty caller set that did not earn the served credit: neither reachable nor "
        "proven unreachable, so no earned negative is published"
    ),
    "registry_escalation_mutators_unverified": "an owner resolves but the role mutator selectors are not present",
    "delay_change_gate_not_self_gated": (
        "the delay-change path's own gate is not the contract itself, so no anti-decoy credit is taken"
    ),
    "destination_redirectable_by_unresolved_setter": "the destination's setter is named by no witness",
    "concrete_destination_existential_not_a_fixed_destination": (
        "an observed sink is existential and cannot prove a fixed destination"
    ),
}


def _warning(kind: str, signal: FunctionSignal, note: str, **extra: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "entity": entity_key(signal.chain, signal.deployment_address),
        "function": signal.function_name,
        "capability": signal.claim_id,
        "note": note,
        **{k: v for k, v in sorted(extra.items()) if v is not None},
    }


def _summarise_warnings(warnings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        warnings,
        key=lambda w: (
            str(w.get("kind")),
            str(w.get("entity")),
            str(w.get("function")),
            str(w.get("capability")),
            str(w.get("note")),
        ),
    )


def _population_disposition(signals: list[FunctionSignal], findings: list[dict[str, Any]]) -> str:
    if not signals:
        return "no_population(no current signals for this protocol)"
    if not findings:
        return "population_scored_to_nothing(every signal failed closed)"
    return "scored"


def _counterfactual(kind: str) -> str:
    return {
        ANYONE: "gate this capability behind a multisig or timelock",
        "eoa": "move behind a strong multisig (>= 0.67 k/n) or a timelock",
        "safe": "raise the threshold ratio, diversify signers across units, and/or add a timelock in front",
        "timelock": "already timelock-gated; the residual is the proposer quorum and the delay length",
        "contract": "resolve the controlling principal of the gating contract",
    }.get(kind, "n/a")


__all__ = ["GATE_PROVEN_TOKENS", "compute_protocol_score"]
