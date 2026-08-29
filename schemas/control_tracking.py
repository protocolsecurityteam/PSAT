"""Typed schemas for runtime control tracking plans and change events."""

from __future__ import annotations

from typing import Literal, get_args

from typing_extensions import NotRequired, TypedDict

from .contract_analysis import (
    AssociatedEvent,
    ControllerKind,
    ControllerProvenance,
    ControllerReadSpec,
    ControllerTrackingMode,
)

# Core principal vocabulary — defined once in ``schemas.core`` and re-exported
# here so the many ``from schemas.control_tracking import ResolvedControllerType``
# sites keep working unchanged.
from .core import (
    RESOLVED_CONTROLLER_TYPES,
    ArtifactEnvelope,
    ResolvedControllerType,
    coerce_resolved_controller_type,
)

__all__ = [
    "RESOLVED_CONTROLLER_TYPES",
    "ArtifactEnvelope",
    "ControlSnapshot",
    "ControlSnapshotValue",
    "ControlTrackingPlan",
    "EventWatch",
    "MONITORED_CONTRACT_TYPES",
    "MonitoredContractType",
    "PollingCadence",
    "PollingFallback",
    "ResolvedControllerType",
    "TrackingStrategy",
    "TrackedController",
    "WatchTransport",
    "coerce_resolved_controller_type",
]

TrackingStrategy = Literal["event_first_with_polling_fallback"]
PollingCadence = Literal["realtime_confirm", "periodic_reconciliation", "state_only"]
WatchTransport = Literal["wss_logs"]


# ``monitored_contracts.contract_type``. ``proxy_admin`` controllers are stored
# as ``"proxy"`` (the historical mapping in ``controllers_for_protocol``).
# ``role_control`` and ``contract`` are legacy-row shapes no producer mints today
# (watcher tests register them directly); both stay admissible so re-upserts of
# such rows cannot 422 and the DB CHECK admits the test-planted states.
MonitoredContractType = Literal["regular", "proxy", "safe", "timelock", "pausable", "role_control", "contract"]
MONITORED_CONTRACT_TYPES: frozenset[str] = frozenset(get_args(MonitoredContractType))


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


class TrackedController(TypedDict):
    controller_id: str
    label: str
    source: str
    kind: ControllerKind
    read_spec: ControllerReadSpec | None
    tracking_mode: ControllerTrackingMode
    event_watch: EventWatch | None
    polling_fallback: PollingFallback
    notes: list[str]
    # Absent = not determined. See ``ControllerProvenance``.
    authority_provenance: NotRequired[ControllerProvenance]


class ControlTrackingPlan(ArtifactEnvelope):
    tracking_strategy: TrackingStrategy
    # Required on every fresh build; legacy persisted artifacts may lack it,
    # but those are read as untyped JSONB (``.get``), never as this type.
    tracked_controllers: list[TrackedController]


class ControlSnapshotValue(TypedDict):
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


class ControlSnapshot(ArtifactEnvelope):
    # contract_name/controller_values: required on every fresh build; legacy
    # persisted artifacts may lack them, but those are read as untyped JSONB
    # (``.get``), never as this type.
    block_number: int
    controller_values: dict[str, ControlSnapshotValue]
