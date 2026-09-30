"""Persist a resolved control graph to ``control_graph_nodes`` / ``control_graph_edges``.

One writer for both the resolution stage (the first graph) and the policy stage (the refresh that adds
``role_principal`` edges once ``effective_permissions`` exists). Before the policy stage wrote tables, those edges and
some ``controller_value`` edges existed only in the artifact, so table readers (the value closure, Surface, chat,
enrollment) missed authority structure.

A scoped replace under ``(contract_id, deployment_scope(deployment_address))``, so re-running either stage converges.
"""

from __future__ import annotations

from typing import Any, Mapping

from sqlalchemy.orm import Session

from db.deployment import deployment_scope
from db.models import ControlGraphEdge, ControlGraphNode


def replace_control_graph_rows(
    session: Session,
    *,
    contract_id: int,
    deployment_address: str | None,
    resolved_graph: Mapping[str, Any],
) -> tuple[int, int]:
    """Replace the rows for one (contract, deployment) with *resolved_graph*.

    Returns ``(nodes, edges)``. Doesn't commit.
    """
    session.query(ControlGraphNode).filter(
        ControlGraphNode.contract_id == contract_id,
        deployment_scope(ControlGraphNode.deployment_address, deployment_address),
    ).delete(synchronize_session=False)
    session.query(ControlGraphEdge).filter(
        ControlGraphEdge.contract_id == contract_id,
        deployment_scope(ControlGraphEdge.deployment_address, deployment_address),
    ).delete(synchronize_session=False)

    graph_max_depth = resolved_graph.get("max_depth")
    nodes = resolved_graph.get("nodes", []) or []
    edges = resolved_graph.get("edges", []) or []
    for node in nodes:
        session.add(
            ControlGraphNode(
                contract_id=contract_id,
                deployment_address=deployment_address,
                address=(node.get("address") or "").lower(),
                node_type=node.get("node_type"),
                resolved_type=node.get("resolved_type"),
                label=node.get("label"),
                contract_name=node.get("contract_name"),
                depth=node.get("depth"),
                analyzed=node.get("analyzed", False),
                analysis_state=node.get("analysis_state"),
                # Without the horizon, ``depth`` can't distinguish cut-off from not attempted.
                graph_max_depth=graph_max_depth,
                details=node.get("details"),
            )
        )
    for edge in edges:
        session.add(
            ControlGraphEdge(
                contract_id=contract_id,
                deployment_address=deployment_address,
                from_node_id=edge.get("from_id", ""),
                to_node_id=edge.get("to_id", ""),
                relation=edge.get("relation"),
                label=edge.get("label"),
                source_controller_id=edge.get("source_controller_id"),
                notes=edge.get("notes"),
            )
        )
    return len(nodes), len(edges)
