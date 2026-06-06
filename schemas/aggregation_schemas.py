"""Public schemas for aggregation service boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field

from typing_extensions import NotRequired, TypedDict

from schemas.common import Contract, JsonObject, ServiceBoundaryMetadata, StageArtifact, StageContext
from schemas.governance_schemas import GovernancePrincipal

TokenBalanceEntry = JsonObject
ContractControlGraphNode = JsonObject
ContractControlGraphEdge = JsonObject
ContractControlGraph = JsonObject
GovernanceOtherCaller = JsonObject
GovernanceContract = JsonObject
GovernanceHierarchyContract = JsonObject
GovernanceHierarchyEntry = JsonObject
GovernanceFundFlow = JsonObject


@dataclass
class GovernanceView:
    contracts: list[GovernanceContract] = field(default_factory=list)
    principals: list[GovernancePrincipal] = field(default_factory=list)
    hierarchy: list[GovernanceHierarchyEntry] = field(default_factory=list)
    fund_flows: list[GovernanceFundFlow] = field(default_factory=list)


class AggregationStageRequest(TypedDict):
    context: StageContext
    company: str
    contracts: list[Contract]
    upstream_artifacts: list[StageArtifact[JsonObject]]
    metadata: NotRequired[ServiceBoundaryMetadata]


class AggregationPayload(TypedDict):
    company: str
    governance: GovernanceView
    payload: JsonObject


AggregationArtifact = StageArtifact[AggregationPayload]


__all__ = [
    "AggregationArtifact",
    "AggregationPayload",
    "AggregationStageRequest",
    "ContractControlGraph",
    "ContractControlGraphEdge",
    "ContractControlGraphNode",
    "GovernanceContract",
    "GovernanceFundFlow",
    "GovernanceHierarchyContract",
    "GovernanceHierarchyEntry",
    "GovernanceOtherCaller",
    "GovernanceView",
    "TokenBalanceEntry",
]
