"""Persist a resolved control graph to ``control_graph_nodes`` / ``control_graph_edges``.

One writer, two call sites, deliberately the SAME code path:

* the **resolution stage** (``workers/resolution_worker``) persists the walk's
  first graph, and
* the **policy stage** (``workers/policy_worker``) persists the refreshed graph
  it rebuilds once ``effective_permissions`` exists — the refresh that projects
  ``role_principal`` edges into the graph.

Until the second call site existed, the policy refresh rewrote ONLY the
artifact, so the table plane was a strict subset of the artifact plane: every
``role_principal`` edge (they need effective_permissions, absent at resolution
time) lived in the artifact and in ``principal_labels`` but was structurally
unreachable in ``control_graph_edges`` — while every row still carried the
walk's ``graph_max_depth``, a completeness assertion the rows did not support.
``role_principal`` is a member of ``db.models.CONTROL_EDGE_RELATIONS``, so the
missing rows silently dropped authority from the effects value closure (a
scorer input) and from every thin-plane consumer (Surface, chat, enrollment)
that reads the tables instead of the artifact.

The write is a scoped replace — delete + insert under
``(contract_id, deployment_scope(deployment_address))`` — so it is idempotent:
re-running either stage converges on that stage's graph, and the policy-stage
rewrite touches exactly the rows the resolution stage wrote for the same job.
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
    """Replace the persisted graph rows for one (contract, deployment) with
    *resolved_graph*'s nodes and edges. Returns ``(nodes, edges)`` written.

    Does not commit; the caller owns the transaction boundary.
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
                # Absent in the graph => NULL, not a guessed value.
                analysis_state=node.get("analysis_state"),
                # The walk's horizon, which the row otherwise loses:
                # without it ``depth`` cannot distinguish "cut off"
                # from "not attempted for some other reason".
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
