from __future__ import annotations

from typing import Literal, TypedDict, cast, get_args

from typing_extensions import NotRequired

from .contract_analysis import (
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
    # No finite on-chain principal set.
    "off_chain_witness",
    # Aliased L1 owner or OP-stack bridge predeploy. A label, not a cross-chain control edge.
    "cross_chain_authority",
]

RESOLVED_CONTROLLER_TYPES: frozenset[str] = frozenset(get_args(ResolvedControllerType))


def coerce_resolved_controller_type(value: object) -> ResolvedControllerType:
    """Validate ``resolved_type`` from untrusted stores (artifacts, caches, JSONB).

    ``None``, legacy ``"None"`` and unknown tokens become ``"unknown"``.
    """
    if value is None:
        return "unknown"
    text = str(value)
    if text in RESOLVED_CONTROLLER_TYPES:
        return cast(ResolvedControllerType, text)
    return "unknown"


# ``proxy_admin`` is stored as ``"proxy"``. ``role_control`` / ``contract`` are legacy shapes no producer mints; kept so
# re-upserts can't 422.
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
    authority_provenance: NotRequired[ControllerProvenance]


class ControlTrackingPlan(TypedDict):
    schema_version: str
    contract_address: str
    contract_name: str
    tracking_strategy: TrackingStrategy
    # Legacy artifacts lacking it are read as untyped JSONB, never as this type.
    tracked_controllers: list[TrackedController]


class ControlSnapshotValue(TypedDict):
    source: str
    value: str | None
    block_number: int
    observed_via: str
    resolved_type: ResolvedControllerType
    details: dict[str, object]
    # Lets resolution tell a gate from a callee without re-reading static artifacts.
    authority_provenance: NotRequired[ControllerProvenance]


class ControlSnapshot(TypedDict):
    schema_version: str
    contract_address: str
    # Legacy artifacts lacking these are read as untyped JSONB, never as this type.
    contract_name: str
    block_number: int
    controller_values: dict[str, ControlSnapshotValue]
