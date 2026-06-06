"""Public schemas for runtime control-tracking artifacts."""

from __future__ import annotations

from typing_extensions import TypedDict

from schemas.common import Address, Contract, JsonObject, PrincipalType

TrackingStrategy = str
PollingCadence = str
WatchTransport = str
ChangeKind = str
ResolvedControllerType = PrincipalType

EventWatch = JsonObject
PollingFallback = JsonObject
TrackedController = JsonObject
ControlSnapshotValue = JsonObject


class ControlTrackingPlan(TypedDict):
    schema_version: str
    contract: Contract
    contract_address: Address
    contract_name: str
    tracking_strategy: TrackingStrategy
    tracked_controllers: list[TrackedController]


class ControlSnapshot(TypedDict):
    schema_version: str
    contract: Contract
    contract_address: Address
    contract_name: str
    block_number: int
    controller_values: dict[str, ControlSnapshotValue]


class ControlChangeEvent(TypedDict):
    schema_version: str
    contract: Contract
    contract_address: Address
    contract_name: str
    change_kind: ChangeKind
    controller_id: str
    block_number: int
    tx_hash: str | None
    old_value: str | None
    new_value: str | None
    observed_via: str
    notes: list[str]
    event_signature: str | None


__all__ = [
    "ChangeKind",
    "ControlChangeEvent",
    "ControlSnapshot",
    "ControlSnapshotValue",
    "ControlTrackingPlan",
    "EventWatch",
    "PollingCadence",
    "PollingFallback",
    "ResolvedControllerType",
    "TrackedController",
    "TrackingStrategy",
    "WatchTransport",
]
