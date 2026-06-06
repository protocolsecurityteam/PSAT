"""Schemas owned by discovery services."""

from __future__ import annotations

from typing import Literal, TypedDict

UpgradeEventType = Literal["upgraded", "admin_changed", "beacon_upgraded"]


class UpgradeEvent(TypedDict, total=False):
    event_type: UpgradeEventType
    block_number: int
    timestamp: int | None
    tx_hash: str | None
    log_index: int | None
    implementation: str | None
    previous_admin: str | None
    new_admin: str | None
    beacon: str | None


class ImplementationRecord(TypedDict, total=False):
    address: str
    contract_name: str | None
    block_introduced: int
    timestamp_introduced: int | None
    tx_hash: str | None
    block_replaced: int | None
    timestamp_replaced: int | None


class ProxyUpgradeHistory(TypedDict):
    proxy_address: str
    proxy_type: str
    current_implementation: str | None
    upgrade_count: int
    first_upgrade_block: int | None
    last_upgrade_block: int | None
    implementations: list[ImplementationRecord]
    events: list[UpgradeEvent]


class UpgradeHistoryOutput(TypedDict):
    schema_version: str
    target_address: str
    proxies: dict[str, ProxyUpgradeHistory]
    total_upgrades: int


__all__ = [
    "ImplementationRecord",
    "ProxyUpgradeHistory",
    "UpgradeEvent",
    "UpgradeEventType",
    "UpgradeHistoryOutput",
]
