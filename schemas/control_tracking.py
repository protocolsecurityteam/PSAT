"""Typed schemas for runtime control tracking plans and change events."""

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
    # Signature- and Merkle-gated functions: no finite on-chain
    # principal set (whoever holds the signer key / matching proof).
    "off_chain_witness",
    # L2 principal that is an aliased L1 owner or an OP-stack bridge predeploy.
    # A label, not a cross-chain control edge.
    "cross_chain_authority",
]

# Derived from the Literal so a membership set can never drift from the type.
RESOLVED_CONTROLLER_TYPES: frozenset[str] = frozenset(get_args(ResolvedControllerType))


def coerce_resolved_controller_type(value: object) -> ResolvedControllerType:
    """Boundary validator for ``resolved_type`` values of unproven provenance
    (persisted artifacts, pre-seeded caches, JSONB rows).

    Only a proven vocabulary member passes through; ``None``, the stringified
    ``"None"`` a legacy store could carry, and any out-of-vocabulary token all
    surface as ``"unknown"`` — the vocabulary's not-determined arm — because a
    token nothing downstream knows licenses no concrete branch.
    """
    if value is None:
        return "unknown"
    text = str(value)
    if text in RESOLVED_CONTROLLER_TYPES:
        return cast(ResolvedControllerType, text)
    return "unknown"


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


class ControlTrackingPlan(TypedDict):
    schema_version: str
    contract_address: str
    contract_name: str
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


class ControlSnapshot(TypedDict):
    schema_version: str
    contract_address: str
    # contract_name/controller_values: required on every fresh build; legacy
    # persisted artifacts may lack them, but those are read as untyped JSONB
    # (``.get``), never as this type.
    contract_name: str
    block_number: int
    controller_values: dict[str, ControlSnapshotValue]
