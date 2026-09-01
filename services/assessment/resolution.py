"""Merge resolved entities and relationships into an Assessment."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any, cast

from pydantic import JsonValue

from schemas.assessment import Analysis, Assessment, Claim, Entity, Evidence, Proposition

from .keys import content_key, entity_key
from .slices import prune_unreferenced_entities, remove_analysis_slice
from .validation import checked

AUTHORITY_RELATIONS = frozenset(
    {
        "controller_value",
        "safe_owner",
        "timelock_owner",
        "proxy_admin_owner",
        "role_principal",
        "mapping_member",
        "capability_principal",
    }
)
DEPENDENCY_RELATIONS = frozenset({"external_call_target"})


def _json(value: Any) -> JsonValue:
    return cast(JsonValue, json.loads(json.dumps(value, sort_keys=True, default=str)))


def _entity(chain_id: int, address: str, node: Mapping[str, Any]) -> tuple[str, Entity]:
    normalized = address.lower()
    resolved_type = str(node.get("resolved_type") or "unknown")
    contract_types = {"safe", "timelock", "proxy_admin", "contract", "cross_chain_authority"}
    tags = [] if resolved_type in ("eoa", "contract", "unknown") else [resolved_type]
    key = entity_key(chain_id, normalized)
    return key, {
        "chain_id": chain_id,
        "address": normalized,
        "kind": "contract" if resolved_type in contract_types else "account",
        "tags": tags,
    }


def _node_evidence(contract: Mapping[str, Any], key: str, node: Mapping[str, Any]) -> tuple[str, Evidence]:
    observation = _json(
        {
            "resolved_type": node.get("resolved_type"),
            "node_type": node.get("node_type"),
            "label": node.get("label"),
            "contract_name": node.get("contract_name"),
            "depth": node.get("depth"),
            "analysis_state": node.get("analysis_state"),
            "details": node.get("details") or {},
            "artifacts": node.get("artifacts") or {},
        }
    )
    evidence_key = content_key(
        "evidence",
        {"contract": contract, "method": "graph_resolution", "entity": key, "observation": observation},
    )
    return evidence_key, {
        "method": "graph_resolution",
        "subject_kind": "entity",
        "subject": key,
        "observation": observation,
        "producer": "resolution.graph",
        "version": "resolution/1",
        "locator": _json({"node_id": node.get("id")}),
    }


def add_resolution(assessment: Assessment, graph: Mapping[str, Any], *, chain_id: int) -> Assessment:
    """Replace the resolution-owned evidence and claims."""

    result = cast(Assessment, copy.deepcopy(assessment))
    remove_analysis_slice(result, "resolution.graph")
    root_address = graph.get("root_contract_address")
    if isinstance(root_address, str) and root_address:
        result["contract"]["deployment_address"] = root_address.lower()

    nodes = graph.get("nodes")
    edges = graph.get("edges")
    node_items = nodes if isinstance(nodes, list) else []
    edge_items = edges if isinstance(edges, list) else []
    node_entities: dict[str, str] = {}
    omissions: list[dict[str, str]] = []
    evidence_keys: list[str] = []
    claim_keys: list[str] = []

    for node in node_items:
        if not isinstance(node, Mapping):
            continue
        node_id = node.get("id")
        address = node.get("address")
        if not isinstance(node_id, str) or not isinstance(address, str) or not address:
            continue
        key, entity = _entity(chain_id, address, node)
        result["entities"][key] = entity
        node_entities[node_id] = key
        evidence_key, evidence = _node_evidence(result["contract"], key, node)
        result["evidence"][evidence_key] = evidence
        evidence_keys.append(evidence_key)

        resolved_type = node.get("resolved_type")
        if isinstance(resolved_type, str) and resolved_type != "unknown":
            proposition: Proposition = {
                "kind": "entity_classification",
                "entity": key,
                "entity_kind": entity["kind"],
                "tags": entity["tags"],
            }
            claim_key = content_key("claim", {"contract": result["contract"], "proposition": proposition})
            result["claims"][claim_key] = {
                "proposition": proposition,
                "rule": "resolution.entity_classification/v1",
                "evidence": [evidence_key],
                "claims": [],
            }
            claim_keys.append(claim_key)

        analysis_state = node.get("analysis_state")
        if analysis_state in ("attempt_failed", "beyond_depth_horizon"):
            omissions.append({"target_kind": "entity", "target": key, "reason": str(analysis_state)})

    for index, edge in enumerate(edge_items):
        if not isinstance(edge, Mapping):
            continue
        from_entity = node_entities.get(str(edge.get("from_id")))
        to_entity = node_entities.get(str(edge.get("to_id")))
        relation = edge.get("relation")
        if from_entity is None or to_entity is None or not isinstance(relation, str):
            omissions.append(
                {
                    "target_kind": "contract",
                    "target": result["contract"]["deployment_address"],
                    "reason": f"unresolved_graph_edge:{index}",
                }
            )
            continue

        observation = _json(
            {
                "from_entity": from_entity,
                "to_entity": to_entity,
                "relation": relation,
                "source_controller_id": edge.get("source_controller_id"),
                "notes": edge.get("notes") or [],
            }
        )
        evidence_key = content_key(
            "evidence",
            {"contract": result["contract"], "method": "graph_resolution", "edge": observation},
        )
        edge_evidence: Evidence = {
            "method": "graph_resolution",
            "subject_kind": "entity",
            "subject": from_entity,
            "observation": observation,
            "producer": "resolution.graph",
            "version": str(graph.get("schema_version") or "resolution/1"),
            "locator": _json({"edge_index": index}),
        }
        result["evidence"][evidence_key] = edge_evidence
        evidence_keys.append(evidence_key)

        if relation in AUTHORITY_RELATIONS:
            proposition = {
                "kind": "authority_relationship",
                "authority": {"kind": "entity", "entity": to_entity},
                "target": from_entity,
                "relationship": relation,
            }
            claim_key = content_key("claim", {"contract": result["contract"], "proposition": proposition})
            claim: Claim = {
                "proposition": cast(Proposition, proposition),
                "rule": f"resolution.{relation}/v1",
                "evidence": [evidence_key],
                "claims": [],
            }
            result["claims"][claim_key] = claim
            claim_keys.append(claim_key)
        elif relation not in DEPENDENCY_RELATIONS:
            omissions.append(
                {"target_kind": "entity", "target": from_entity, "reason": f"unattributed_graph_relation:{relation}"}
            )

    receipt: Analysis = {
        "detector": "resolution.graph",
        "version": str(graph.get("schema_version") or "resolution/1"),
        "status": "completed" if not omissions else "partial",
        "targets_total": len(node_items) + len(edge_items),
        "targets_completed": len(node_items) + len(edge_items) - len(omissions),
        "omissions": omissions,
        "diagnostics": [],
        "claims": sorted(set(claim_keys)),
        "evidence": sorted(set(evidence_keys)),
    }
    result["analyses"].append(receipt)
    prune_unreferenced_entities(result)
    return checked(result)


__all__ = ["AUTHORITY_RELATIONS", "DEPENDENCY_RELATIONS", "add_resolution"]
