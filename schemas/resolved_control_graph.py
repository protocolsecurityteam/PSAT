from __future__ import annotations

from typing import Literal, TypedDict

from typing_extensions import NotRequired

from .control_tracking import ResolvedControllerType

ResolvedNodeType = Literal["contract", "principal"]

# ``analyzed=False`` alone collapses four populations; this says which, so a limit of the walk isn't read as a property
# of the address.
ResolvedAnalysisState = Literal[
    "analyzed",
    # Analysis never applied; nothing adverse.
    "not_analyzable",
    # Materialization ran and failed (``details.materialize_error``). Formerly ``not_a_contract`` (false for Safes);
    # never persisted, so no legacy member.
    "attempt_failed",
    # A fact about the walk, not the contract.
    "beyond_depth_horizon",
]
ResolvedEdgeRelation = Literal[
    "controller_value",
    "role_principal",
    # A materialized ``function_principals`` row: "principal of a gated function", never "holder of role R", which the
    # resolver declined to claim.
    "capability_principal",
    "safe_owner",
    "timelock_owner",
    "proxy_admin_owner",
    "mapping_member",
    # Not a control relation; moves no authority.
    "external_call_target",
    # Neither gate nor callee: provenance was absent. Published for visibility; moves no authority.
    "controller_value_unattributed",
]


class ResolvedGraphNode(TypedDict):
    id: str
    address: str
    node_type: ResolvedNodeType
    resolved_type: ResolvedControllerType
    label: str
    contract_name: str | None
    depth: int
    analyzed: bool
    # Absent/None = not determined; ``analyzed`` equals ``analysis_state == "analyzed"`` when set.
    analysis_state: NotRequired[ResolvedAnalysisState | None]
    details: dict[str, object]
    artifacts: dict[str, str]


class ResolvedGraphEdge(TypedDict):
    from_id: str
    to_id: str
    relation: ResolvedEdgeRelation
    label: str
    source_controller_id: str | None
    notes: list[str]


class ResolvedControlGraph(TypedDict):
    schema_version: str
    root_contract_address: str
    max_depth: int
    nodes: list[ResolvedGraphNode]
    edges: list[ResolvedGraphEdge]
