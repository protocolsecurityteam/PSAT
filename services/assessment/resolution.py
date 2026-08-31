"""Merge resolved entities and authority relationships into an Assessment."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any, cast

from pydantic import JsonValue

from schemas.assessment import (
    Account,
    Analysis,
    Assessment,
    AuthorityEdge,
    AuthorityRelationship,
    Basis,
    Claim,
    DependencyEdge,
    Entity,
    EntityClassification,
    Evidence,
    Omission,
    Scope,
)

from .ids import stable_id
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


def _account(chain_id: int, address: str) -> Account:
    normalized = address.lower()
    account_id = stable_id("account", {"chain_id": chain_id, "address": normalized})
    return {"id": account_id, "chain_id": chain_id, "address": normalized}


def _entity(account: Account, node: Mapping[str, Any]) -> Entity:
    resolved_type = str(node.get("resolved_type") or "unknown")
    contract_types = {"safe", "timelock", "proxy_admin", "contract", "cross_chain_authority"}
    tags = [] if resolved_type in ("eoa", "contract", "unknown") else [resolved_type]
    entity_id = stable_id("entity", {"account_id": account["id"]})
    return {
        "id": entity_id,
        "account_id": account["id"],
        "kind": "contract" if resolved_type in contract_types else "account",
        "tags": tags,
    }


def _node_evidence(scope: Scope, entity: Entity, node: Mapping[str, Any]) -> Evidence:
    observation = _json(
        {
            "resolved_type": node.get("resolved_type"),
            "node_type": node.get("node_type"),
            "label": node.get("label"),
            "contract_name": node.get("contract_name"),
            "depth": node.get("depth"),
            "analyzed": node.get("analyzed"),
            "analysis_state": node.get("analysis_state"),
            "details": node.get("details") or {},
            "artifacts": node.get("artifacts") or {},
        }
    )
    evidence_id = stable_id(
        "evidence",
        {"scope": scope, "method": "graph_resolution", "entity_id": entity["id"], "observation": observation},
    )
    return {
        "id": evidence_id,
        "method": "graph_resolution",
        "subject": {"kind": "entity", "id": entity["id"]},
        "observation": observation,
        "source": {
            "producer": "resolution.graph",
            "version": "resolution/1",
            "locator": _json({"node_id": node.get("id")}),
        },
        "scope": scope,
    }


def add_resolution(assessment: Assessment, graph: Mapping[str, Any], *, chain_id: int) -> Assessment:
    """Return ``assessment`` enriched with resolved graph facts and claims."""

    result = cast(Assessment, copy.deepcopy(assessment))
    root_address = graph.get("root_contract_address")
    if isinstance(root_address, str) and root_address:
        deployment_account = _account(chain_id, root_address)
        result["accounts"][deployment_account["id"]] = deployment_account
        # Replace, do not mutate: static claims intentionally retain the code
        # account scope their stable ids were minted from, while live claims use
        # the deployment account (a proxy for implementation-context jobs).
        result["scope"] = {**result["scope"], "account_id": deployment_account["id"]}
    scope = result["scope"]
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    node_items = nodes if isinstance(nodes, list) else []
    edge_items = edges if isinstance(edges, list) else []
    node_entities: dict[str, str] = {}
    omissions: list[Omission] = []
    evidence_ids: list[str] = []
    claim_ids: list[str] = []

    for node in node_items:
        if not isinstance(node, Mapping):
            continue
        node_id = node.get("id")
        address = node.get("address")
        if not isinstance(node_id, str) or not isinstance(address, str) or not address:
            continue
        account = _account(chain_id, address)
        entity = _entity(account, node)
        result["accounts"][account["id"]] = account
        result["entities"][entity["id"]] = entity
        node_entities[node_id] = entity["id"]
        evidence = _node_evidence(scope, entity, node)
        result["evidence"][evidence["id"]] = evidence
        evidence_ids.append(evidence["id"])

        resolved_type = node.get("resolved_type")
        if isinstance(resolved_type, str) and resolved_type != "unknown":
            classification_proposition: EntityClassification = {
                "kind": "entity_classification",
                "entity_id": entity["id"],
                "entity_kind": entity["kind"],
                "tags": entity["tags"],
            }
            claim_id = stable_id("claim", {"scope": scope, "proposition": classification_proposition})
            basis: Basis = {
                "rule": "resolution.entity_classification/v1",
                "evidence_ids": [evidence["id"]],
                "claim_ids": [],
            }
            result["claims"][claim_id] = {
                "id": claim_id,
                "proposition": classification_proposition,
                "basis": basis,
                "scope": scope,
            }
            claim_ids.append(claim_id)

        analysis_state = node.get("analysis_state")
        if analysis_state in ("attempt_failed", "beyond_depth_horizon"):
            omissions.append(
                {
                    "target_kind": "entity",
                    "target_id": entity["id"],
                    "reason": str(analysis_state),
                }
            )

    authority_edges: list[AuthorityEdge] = []
    dependency_edges: list[DependencyEdge] = []
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
                    "target_id": result["contract"]["id"],
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
        evidence_id = stable_id(
            "evidence",
            {"scope": scope, "method": "graph_resolution", "edge": observation},
        )
        edge_evidence: Evidence = {
            "id": evidence_id,
            "method": "graph_resolution",
            "subject": {"kind": "entity", "id": from_entity},
            "observation": observation,
            "source": {
                "producer": "resolution.graph",
                "version": str(graph.get("schema_version") or "resolution/legacy"),
                "locator": _json({"edge_index": index}),
            },
            "scope": scope,
        }
        result["evidence"][evidence_id] = edge_evidence
        evidence_ids.append(evidence_id)

        if relation in AUTHORITY_RELATIONS:
            # Stored graph direction is controlled -> authority. The canonical
            # proposition names that semantic direction explicitly.
            proposition: AuthorityRelationship = {
                "kind": "authority_relationship",
                "authority": {"kind": "entity", "entity_id": to_entity},
                "target_id": from_entity,
                "relationship": relation,
            }
            claim_id = stable_id("claim", {"scope": scope, "proposition": proposition})
            claim: Claim = {
                "id": claim_id,
                "proposition": proposition,
                "basis": {
                    "rule": f"resolution.{relation}/v1",
                    "evidence_ids": [evidence_id],
                    "claim_ids": [],
                },
                "scope": scope,
            }
            result["claims"][claim_id] = claim
            claim_ids.append(claim_id)
            authority_edges.append(
                {
                    "authority_id": to_entity,
                    "target_id": from_entity,
                    "relationship": relation,
                    "claim_id": claim_id,
                }
            )
        elif relation in DEPENDENCY_RELATIONS:
            dependency_edges.append(
                {
                    "source_id": from_entity,
                    "target_id": to_entity,
                    "relationship": relation,
                    "evidence_ids": [evidence_id],
                }
            )
        else:
            omissions.append(
                {
                    "target_kind": "entity",
                    "target_id": from_entity,
                    "reason": f"unattributed_graph_relation:{relation}",
                }
            )

    result["authority_edges"] = authority_edges
    result["dependency_edges"] = dependency_edges
    status = "completed" if not omissions else "partial"
    receipt: Analysis = {
        "detector": "resolution.graph",
        "version": str(graph.get("schema_version") or "resolution/legacy"),
        "status": status,
        "coverage": {
            "targets_total": len(node_items) + len(edge_items),
            "targets_completed": len(node_items) + len(edge_items) - len(omissions),
            "omissions": omissions,
        },
        "diagnostics": [],
        "claim_ids": sorted(set(claim_ids)),
        "evidence_ids": sorted(set(evidence_ids)),
    }
    result["analyses"] = [item for item in result["analyses"] if item["detector"] != "resolution.graph"]
    result["analyses"].append(receipt)
    return checked(result)


__all__ = ["AUTHORITY_RELATIONS", "DEPENDENCY_RELATIONS", "add_resolution"]
