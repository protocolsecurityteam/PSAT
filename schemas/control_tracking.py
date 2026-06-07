"""Public schemas for runtime control-tracking artifacts."""

from __future__ import annotations

from typing_extensions import TypedDict

from schemas.common import Address, Contract, JsonObject, PrincipalType

ResolvedControllerType = PrincipalType

EventWatch = JsonObject
PollingFallback = JsonObject
TrackedController = JsonObject


class ControlTrackingPlan(TypedDict):
    schema_version: str
    contract: Contract
    contract_address: Address
    contract_name: str
    tracking_strategy: str
    tracked_controllers: list[TrackedController]


class ControlSnapshot(TypedDict):
    schema_version: str
    contract: Contract
    contract_address: Address
    contract_name: str
    block_number: int
    controller_values: dict[str, JsonObject]


__all__ = [
    "ControlSnapshot",
    "ControlTrackingPlan",
    "EventWatch",
    "PollingFallback",
    "ResolvedControllerType",
    "TrackedController",
]
