"""Shared dataclasses of the fold: instances, rows, walked hops, row values, admission planes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from services.scoring import planes as P
from services.scoring.fold.readings import _WITHHELD_ARM_READINGS, _WITHHELD_CLOSING, _WITHHELD_OPENING
from services.scoring.schema import FunctionSignal, Tri
from utils import execution_record as EX
from utils.scoring_status import MAGNITUDE_STATES_UPPER_BOUNDING

if TYPE_CHECKING:
    from services.scoring.fold.composition import _ComposedMagnitude


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
    # Entities whose PUBLISHED figure in ``per_entity`` bounds this principal
    # from ABOVE and not from below, from EITHER ceiling — the composed
    # destination witness or the controlled node's own sheet. Threaded rather
    # than re-derived from ``composed_magnitudes``: that map holds every entity a
    # composed candidate was built for, including ones whose own witness beat it
    # in the per-entity MAX, and the header's question is which figures WON.
    ceiling_entities: frozenset[str] = frozenset()
    # The SHEET half of the set above, published apart and never inferred as the
    # complement: the two ceilings are not each other's negation (a row can carry
    # both, and an entity is in exactly one), and only this half is kept out of
    # the exposure numerator. An entity here is one whose standing figure is its
    # own priced sheet, admitted because this row's capability replaces that
    # node's code.
    sheet_ceiling_entities: frozenset[str] = frozenset()
    # The signals whose sheet ceiling STANDS as this row's published figure at
    # some entity, on ``composed_signals``' pattern. Rolled up to the protocol so
    # the confidence pass can credit a proven bound as an answered magnitude
    # question without re-deriving which signals produced one. A signal whose
    # ceiling was displaced by a larger figure is absent: a credited answer has
    # to have a carrier in the document.
    ceiling_signals: frozenset[tuple[Any, ...]] = frozenset()
    # Entities the S6 reconciliation refused the ceiling LABEL to, with both
    # figures. Carried rather than dropped for the reason every refusal on this
    # row is: an entity silently absent from the ceiling list is
    # indistinguishable from one the branch never fired on.
    sheet_ceilings_withheld: list[dict[str, Any]] = field(default_factory=list)
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

        The registry it reads is the DIRECTION set, which also carries the sheet
        ceiling. That is not a widening here: a ``_DestinationMagnitude`` is
        built only from a destination function's own witnessed ``flow.out``
        figure, and a sheet ceiling — proven by a balance observation, not by a
        call — never constructs one, so the ceiling state cannot reach this
        property.
        """
        return self.state in MAGNITUDE_STATES_UPPER_BOUNDING


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

    def __post_init__(self) -> None:
        # An arm with no registered sentence would otherwise reach the published
        # reading through a default, which is a claim nobody wrote for it.
        if self.arm not in _WITHHELD_ARM_READINGS:
            raise ValueError(f"no withheld reading is registered for arm {self.arm!r}")

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
            # The gate claim, which survives the refusal — qualified by its own
            # caller conjunct rather than by the arm that took the figure.
            "gate_claim": _gate_claim(self.chain, self.execution),
            "act_as_chain": [step.as_json() for step in self.chain],
            "act_as_chain_length": len(self.chain),
            "route_classification": self.route.as_json(),
            "authority_deletability": self.deletability.disclosure(),
            "reading": _WITHHELD_OPENING + _WITHHELD_ARM_READINGS[self.arm] + _WITHHELD_CLOSING,
        }


def _gate_claim(chain: tuple[P.ActAsStep, ...], execution: EX.ProvingExecution) -> dict[str, Any]:
    """§7.2 arm 1's conjunct, EVALUATED, for one entry.

    The arm is "gate claims transfer ON CALLER MATCH", and the conjunct is not
    satisfied by publishing ``caller_matches`` and leaving a reader to apply it:
    an entry that says nothing about the comparison reads as one where it
    passed. So the outcome is published under its own three-state token, on the
    republished entries and the withheld ones alike, and it is counted per row.
    """
    return EX.gate_claim(execution, claimed_caller=chain[-1].caller if chain else None)
