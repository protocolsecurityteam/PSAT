"""Typed schemas for runtime control tracking plans and change events."""

from __future__ import annotations

from typing import Annotated, Any, Literal, cast, get_args

from pydantic import StringConstraints
from typing_extensions import NotRequired, TypedDict

from .static_facts import (
    AssociatedEvent,
    ControllerKind,
    ControllerProvenance,
    ControllerReadSpec,
    ControllerTrackingMode,
)

TrackingStrategy = Literal["event_first_with_polling_fallback"]
PollingCadence = Literal["realtime_confirm", "periodic_reconciliation", "state_only"]
WatchTransport = Literal["wss_logs"]
ResolvedControllerType = Literal[
    "zero",
    "eoa",
    "safe",
    "timelock",
    "proxy_admin",
    "contract",
    "unknown",
    "off_chain_witness",
    "cross_chain_authority",
]
RESOLVED_CONTROLLER_TYPES: frozenset[str] = frozenset(get_args(ResolvedControllerType))


def coerce_resolved_controller_type(value: object) -> ResolvedControllerType:
    if value is None:
        return "unknown"
    text = str(value)
    if text in RESOLVED_CONTROLLER_TYPES:
        return cast(ResolvedControllerType, text)
    return "unknown"


MonitoredContractType = Literal["regular", "proxy", "safe", "timelock", "pausable"]
MONITORED_CONTRACT_TYPES: frozenset[str] = frozenset(get_args(MonitoredContractType))

MonitoringWitnessTier = Literal["self_describing", "hint", "activity"]
MonitoringWriterOpenness = Literal["open", "restricted", "not_determined"]
Topic0 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{64}$")]


class TrackedTopic(TypedDict):
    topic0: Topic0
    signature: NotRequired[str | None]
    event_type: NotRequired[str]
    controller_id: NotRequired[str | None]
    inputs: NotRequired[list[dict[str, Any]]]
    effect_tags: NotRequired[dict[str, Any]]
    witness_tier: NotRequired[MonitoringWitnessTier]
    writer_openness: NotRequired[MonitoringWriterOpenness]
    member_witness: NotRequired[dict[str, Any]]


class MonitoringConfig(TypedDict, total=False):
    """Analyzer and operator configuration persisted for one monitored contract."""

    tracked_topics: list[TrackedTopic]
    polling_plan: list[dict[str, Any]]
    observation_plan_not_determined: str
    tracked_topics_stale_since: str
    polling_plan_stale_since: str
    scan_gaps: list[dict[str, Any]]
    watch_upgrades: bool
    watch_ownership: bool
    watch_pause: bool
    watch_roles: bool
    watch_safe_signers: bool
    watch_safe_modules: bool
    watch_timelock: bool
    watch_authority: bool


class EventWatch(TypedDict):
    transport: WatchTransport
    contract_address: str
    events: list[AssociatedEvent]
    writer_functions: list[str]


class PollingFallback(TypedDict):
    contract_address: str
    polling_sources: list[str]
    cadence: PollingCadence
    notes: list[str]


class ControllerInstruction(TypedDict):
    controller_id: str
    label: str
    source: str
    kind: ControllerKind
    read_spec: ControllerReadSpec | None
    tracking_mode: ControllerTrackingMode
    event_watch: EventWatch | None
    polling_fallback: PollingFallback
    notes: list[str]
    authority_provenance: NotRequired[ControllerProvenance]


class ObservationPlan(TypedDict):
    schema_version: str
    contract_address: str
    contract_name: str
    tracking_strategy: TrackingStrategy
    # Required on every fresh build; legacy persisted artifacts may lack it,
    # but those are read as untyped JSONB (``.get``), never as this type.
    tracked_controllers: list[ControllerInstruction]


class ControllerObservation(TypedDict):
    source: str
    value: str | None
    block_number: int
    observed_via: str
    resolved_type: ResolvedControllerType
    details: dict[str, object]
    # Carried from the tracked controller so the resolution stage can tell a
    # gate from a callee without re-reading the static artifacts. Absent = not
    # determined. See ``ControllerProvenance``.
    authority_provenance: NotRequired[ControllerProvenance]


class ObservationBatch(TypedDict):
    schema_version: str
    contract_address: str
    # contract_name/controller_values: required on every fresh build; legacy
    # persisted artifacts may lack them, but those are read as untyped JSONB
    # (``.get``), never as this type.
    contract_name: str
    block_number: int
    controller_values: dict[str, ControllerObservation]
