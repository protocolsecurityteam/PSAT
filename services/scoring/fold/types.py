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
    signal: FunctionSignal
    severity: float
    severity_basis: tuple[str, ...]
    entity_keys: tuple[str, ...]
    magnitude: Tri[float]
    value_bound: str
    pricing_blocked: str | None
    native_only: bool
    asset_identity_undecidable: bool
    # Lets a merged unit's row say which member reaches each entity (inv.5 is per entity).
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
    # Each member's own gate; row-level ``weakness`` is their max, and ``_aggregate`` re-attributes per entity.
    member_gate: dict[str, tuple[float, str, str]] = field(default_factory=dict)
    # §3.1 pt 5: the zero-address rule's count and the instances it emptied.
    zero_reach_keys_refused: int = 0
    zero_reach_stripped: list[dict[str, Any]] = field(default_factory=list)
    instances: list[_Instance] = field(default_factory=list)
    seeds: set[str] = field(default_factory=set)
    tiers: set[str] = field(default_factory=set)
    notes: set[str] = field(default_factory=set)
    citations: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _WalkedHop:
    caller: str
    destination: str
    licensed: frozenset[P.LicensedFunction]


@dataclass
class _RowValue:
    per_entity: dict[str, float]
    total_usd: float | None
    basis: str
    undetermined: list[dict[str, Any]]
    proven_no_reach: list[dict[str, Any]]
    # Witnessed membership, not ``per_entity`` keys: undetermined-dollar entities are still reached.
    reach: set[str]
    magnitude_caps: list[dict[str, Any]]
    hops_not_determined: list[dict[str, Any]] = field(default_factory=list)
    magnitude_census: dict[str, int] = field(default_factory=dict)
    # Empty for state-variable-only destinations: an absence, not an empty licence.
    licensed_functions: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    # Everything behind a not_determined frontier hop, which the row doesn't otherwise show.
    withheld_behind_hops: dict[str, Any] = field(default_factory=dict)
    # Floors charged against an undetermined sheet, disclosed rather than absorbed.
    unbounded_floor_magnitudes: list[dict[str, Any]] = field(default_factory=list)
    composed_magnitudes: dict[str, _ComposedMagnitude] = field(default_factory=dict)
    composition_census: dict[str, Any] = field(default_factory=dict)
    composed_signals: frozenset[tuple[Any, ...]] = frozenset()
    # Entities whose winning figure is an upper bound (either ceiling kind). Threaded, since ``composed_magnitudes``
    # includes candidates that lost the per-entity max.
    ceiling_entities: frozenset[str] = frozenset()
    # The sheet half, published explicitly (not the complement); only this half is kept out of exposure.
    sheet_ceiling_entities: frozenset[str] = frozenset()
    # Signals whose sheet ceiling stands as a published figure, rolled up for confidence credit. Displaced ceilings are
    # excluded.
    ceiling_signals: frozenset[tuple[Any, ...]] = frozenset()
    # S6: entities refused the ceiling label, kept so they don't read as the branch never firing.
    sheet_ceilings_withheld: list[dict[str, Any]] = field(default_factory=list)
    # F5: entities whose standing figure is proven non-attribution-derived. Orthogonal to ``ceiling_entities``; absence
    # disqualifies a floor.
    non_attributed_entities: frozenset[str] = frozenset()
    # Keeps typed refusals visible on rows that lost every composed figure, which otherwise look like rows that never
    # composed.
    withheld_composed_magnitudes: tuple[_WithheldComposition, ...] = ()
    refused_composed_magnitudes: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class _DestinationMagnitude:
    """A ``flow.out`` witness at one destination function, as the fold received it.

    ``execution`` travels with the figure because composition can't decide the figure's fate without it.
    ``attribution_derived`` is derived from the state so there's one source of truth.
    """

    state: str
    usd: float
    function: str
    execution: EX.ProvingExecution

    @property
    def attribution_derived(self) -> bool:
        """Whether the figure bounds its principal only from above (the constant-amount probe path).

        The registry also holds the sheet ceiling, but sheet ceilings never build this type.
        """
        return self.state in MAGNITUDE_STATES_UPPER_BOUNDING


@dataclass(frozen=True)
class _AdmissionPlanes:
    """The two witnesses an arm is decided from: whether the principal could author the calldata, and what the
    traversed body does to it.
    """

    deletability: P.DeletabilityPlane
    routes: P.RouterFlowPlane


@dataclass(frozen=True)
class _WithheldComposition:
    """A composed candidate whose figure the rule refused; the gate claim, chain and execution are still published.

    No ``published_usd`` or figure of any kind: a refusal that prints the number has published it.
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
        if self.arm not in _WITHHELD_ARM_READINGS:
            raise ValueError(f"no withheld reading is registered for arm {self.arm!r}")

    @property
    def counter_key(self) -> str:
        """Both halves, because the vocabulary mixes an earned negative with undetermined kinds (inv. 1)."""
        return f"{self.deletability.state}/{self.deletability.reason}"

    def as_json(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "destination_function": self.function,
            "selector": self.selector,
            "arm_taken": self.arm,
            "withheld_reason": self.reason,
            # Spelled, not omitted: this is a refusal, not an unfilled field.
            "published_usd": None,
            "proving_execution": self.execution.as_json(),
            "route_comparison": EX.route_comparison(
                self.execution,
                claimed_caller=self.chain[-1].caller if self.chain else None,
                claimed_target=self.chain[-1].destination if self.chain else None,
                claimed_selector=self.chain[-1].calling_selector if self.chain else None,
            ),
            # Survives the refusal, qualified by its own caller conjunct.
            "gate_claim": _gate_claim(self.chain, self.execution),
            "act_as_chain": [step.as_json() for step in self.chain],
            "act_as_chain_length": len(self.chain),
            "route_classification": self.route.as_json(),
            "authority_deletability": self.deletability.disclosure(),
            "reading": _WITHHELD_OPENING + _WITHHELD_ARM_READINGS[self.arm] + _WITHHELD_CLOSING,
        }


def _gate_claim(chain: tuple[P.ActAsStep, ...], execution: EX.ProvingExecution) -> dict[str, Any]:
    """§7.2 arm 1's caller conjunct, evaluated and published as a three-state token rather than left for the reader
    to apply.
    """
    return EX.gate_claim(execution, claimed_caller=chain[-1].caller if chain else None)
