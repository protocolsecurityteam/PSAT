"""Typed schemas for recursive control-resolution artifacts."""

from __future__ import annotations

from typing import Literal, TypedDict

from typing_extensions import NotRequired

from .control_tracking import ResolvedControllerType

ResolvedNodeType = Literal["contract", "principal"]

# Why a node is or is not analysed. ``analyzed`` alone is a non-nullable bool
# and collapses four populations into its ``False``: a principal that was never
# a candidate, a contract whose materialization was attempted and failed, a
# contract left unattempted because the walk's depth horizon cut it off, and
# "we cannot say". A consumer reading only the bool cannot tell a limit of the
# walk from a property of the address.
ResolvedAnalysisState = Literal[
    "analyzed",
    # Not an analyzable type (eoa / safe / zero / off-chain witness / …) — i.e.
    # ``resolved_type not in ANALYZABLE_TYPES``. Analysis was never applicable,
    # so its absence says nothing adverse.
    "not_analyzable",
    # (Renamed from ``not_a_contract``. The old spelling said something literally
    # false about the largest population it covered — a Gnosis Safe IS a
    # contract, it is just not an ANALYZABLE type.
    # No legacy member is kept because nothing has ever persisted either token:
    # ``control_graph_nodes.analysis_state`` is SQL NULL on 2,506/2,506 local rows
    # and ABSENT on 2,531/2,531 nodes across all 107 stored
    # ``resolved_control_graph`` artifacts, and the migration that adds the
    # column has never been deployed. The rename therefore lands before the
    # first value is ever written.)
    # Materialization ran and failed. ``details.materialize_error`` carries why.
    "attempt_failed",
    # An analyzable contract the BFS never reached: its depth exceeded
    # ``max_depth``. A fact about the walk, not about the contract.
    "beyond_depth_horizon",
]
ResolvedEdgeRelation = Literal[
    "controller_value",
    "role_principal",
    # A ``function_principals`` row materialized into the graph plane. A control
    # relation (it IS in ``db.models.CONTROL_EDGE_RELATIONS``), but distinct from
    # ``role_principal``: it asserts "resolved principal of a gated function on
    # the from-node", never "holder of role R" — the claim the upstream
    # capability resolver explicitly declined to make for this population.
    "capability_principal",
    "safe_owner",
    "timelock_owner",
    "proxy_admin_owner",
    "mapping_member",
    # NOT a control relation: the from-node calls the to-node. Kept out of
    # ``db.models.CONTROL_EDGE_RELATIONS`` so it moves no authority.
    "external_call_target",
    # NOT a control relation, and NOT a claim that the target is merely called:
    # the tracked controller's ``authority_provenance`` was ABSENT, so neither
    # question was answered. The edge is published so the address stays visible;
    # it moves no authority. See ``db.models``.
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
    # Absent / None = not determined. ``analyzed`` stays for compatibility and
    # is exactly ``analysis_state == "analyzed"`` when this is populated.
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
