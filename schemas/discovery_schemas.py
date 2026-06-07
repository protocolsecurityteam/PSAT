"""Public schemas for discovery service boundaries."""

from __future__ import annotations

from typing_extensions import NotRequired, TypedDict

from schemas.common import (
    Address,
    Contract,
    JsonObject,
    StageArtifact,
)


class UpgradeHistoryOutput(TypedDict):
    schema_version: str
    contract: NotRequired[Contract]
    target_address: Address
    proxies: dict[str, JsonObject]
    total_upgrades: int


class DiscoveryPayload(TypedDict):
    contracts: list[Contract]
    inventory: NotRequired[JsonObject]
    metadata: NotRequired[JsonObject]
    audit_reports: NotRequired[JsonObject]
    summary: NotRequired[JsonObject]
    upgrade_history: NotRequired[UpgradeHistoryOutput]


DiscoveryArtifact = StageArtifact[DiscoveryPayload]


class SelectionPayload(TypedDict):
    company: str | None
    ranked_count: int
    analyzed_count: int
    ranked_contracts: list[JsonObject]
    selected_contracts: list[JsonObject]
    child_jobs: list[JsonObject]
    summary: JsonObject


SelectionArtifact = StageArtifact[SelectionPayload]


__all__ = [
    "DiscoveryArtifact",
    "DiscoveryPayload",
    "SelectionArtifact",
    "SelectionPayload",
    "UpgradeHistoryOutput",
]
