"""Public schemas for discovery service boundaries."""

from __future__ import annotations

from typing_extensions import NotRequired, TypeAlias, TypedDict

from schemas.common import (
    Address,
    ChainId,
    Contract,
    JsonObject,
    ServiceBoundaryMetadata,
    StageArtifact,
    StageContext,
)

UpgradeEventType: TypeAlias = str
UpgradeEvent: TypeAlias = JsonObject
ImplementationRecord: TypeAlias = JsonObject
ProxyUpgradeHistory: TypeAlias = JsonObject
DiscoveryContractCandidate: TypeAlias = JsonObject
DiscoveryInventory: TypeAlias = JsonObject


class UpgradeHistoryOutput(TypedDict):
    schema_version: str
    contract: NotRequired[Contract]
    target_address: Address
    proxies: dict[str, ProxyUpgradeHistory]
    total_upgrades: int


class DiscoveryInput(TypedDict, total=False):
    context: StageContext
    metadata: ServiceBoundaryMetadata
    address: Address | None
    company: str | None
    name: str | None
    chain: str | None
    chain_id: ChainId | None
    rpc_url: str | None
    dapp_urls: list[str] | None
    defillama_protocol: str | None
    analyze_limit: int
    force: bool


class DiscoveryPayload(TypedDict):
    contracts: list[Contract]
    inventory: NotRequired[DiscoveryInventory]
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
    "DiscoveryContractCandidate",
    "DiscoveryInput",
    "DiscoveryInventory",
    "DiscoveryArtifact",
    "DiscoveryPayload",
    "ImplementationRecord",
    "ProxyUpgradeHistory",
    "UpgradeEvent",
    "UpgradeEventType",
    "SelectionArtifact",
    "SelectionPayload",
    "UpgradeHistoryOutput",
]
