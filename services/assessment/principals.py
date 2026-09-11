"""Principal observations belong to Assessment before any labels are projected."""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from typing import Any, cast

from schemas.assessment import Analysis, Assessment, Diagnostic, Proposition
from services.assessment.keys import content_key, entity_record, json_value
from services.assessment.slices import prune_unreferenced_entities, remove_analysis_slice
from services.assessment.validation import checked

PRODUCER = "policy.principal_observation"
GRAPH_PRODUCER = "policy.principal_graph"


def add_principal_observations(assessment: Assessment, observations: Iterable[Mapping[str, Any]]) -> Assessment:
    result = cast(Assessment, copy.deepcopy(assessment))
    previous_entities = {
        evidence["subject"]
        for evidence in result["evidence"].values()
        if evidence["producer"] == PRODUCER and evidence["subject_kind"] == "entity"
    }
    remove_analysis_slice(result, PRODUCER)
    classified = {
        claim["proposition"].get("entity")
        for claim in result["claims"].values()
        if claim["proposition"]["kind"] == "entity_classification"
    }
    for key in previous_entities - classified:
        entity = result["entities"].get(key)
        if entity is not None:
            result["entities"][key] = entity_record(entity["chain_id"], entity["address"], "unknown")[1]
    evidence_keys: list[str] = []
    claim_keys: list[str] = []
    omissions: list[dict[str, str]] = []
    diagnostics: list[Diagnostic] = []
    total = completed = 0
    for raw in observations:
        address = raw.get("address")
        if not isinstance(address, str):
            continue
        total += 1
        resolved_type = str(raw.get("resolved_type") or "unknown")
        complete = raw.get("complete") is True and resolved_type != "unknown"
        key, entity = entity_record(result["contract"]["chain_id"], address, resolved_type if complete else "unknown")
        if complete or key not in result["entities"]:
            result["entities"][key] = entity
        observation = json_value(dict(raw))
        evidence_key = content_key(
            "evidence",
            {"contract": result["contract"], "producer": PRODUCER, "entity": key, "observation": observation},
        )
        result["evidence"][evidence_key] = {
            "method": "policy_derivation",
            "subject_kind": "entity",
            "subject": key,
            "observation": observation,
            "producer": PRODUCER,
            "version": "principals/1",
            "locator": {},
        }
        evidence_keys.append(evidence_key)
        if complete:
            completed += 1
            proposition: Proposition = {
                "kind": "entity_classification",
                "entity": key,
                "entity_kind": entity["kind"],
                "tags": entity["tags"],
            }
            claim_key = content_key(
                "claim",
                {
                    "contract": result["contract"],
                    "producer": PRODUCER,
                    "proposition": proposition,
                    "evidence": [evidence_key],
                    "rule": "policy.principal_classification/v1",
                },
            )
            result["claims"][claim_key] = {
                "proposition": proposition,
                "rule": "policy.principal_classification/v1",
                "evidence": [evidence_key],
                "claims": [],
            }
            claim_keys.append(claim_key)
            details = raw.get("details")
            terminal = details.get("terminal_principal") if isinstance(details, Mapping) else None
            if isinstance(terminal, Mapping) and terminal.get("status") not in {"terminated", "multi_plane"}:
                completed -= 1
                omissions.append(
                    {
                        "target_kind": "entity",
                        "target": key,
                        "reason": f"terminal_principal:{terminal.get('status') or 'not_determined'}",
                    }
                )
        else:
            omissions.append({"target_kind": "entity", "target": key, "reason": "principal_observation_incomplete"})
            if raw.get("error"):
                diagnostics.append(
                    {
                        "severity": "degraded",
                        "code": "PrincipalObservationFailed",
                        "message": str(raw["error"]),
                        "target_kind": "entity",
                        "target": key,
                    }
                )
    receipt: Analysis = {
        "detector": PRODUCER,
        "version": "principals/1",
        "status": "completed" if not omissions else ("partial" if claim_keys else "failed"),
        "targets_total": total,
        "targets_completed": completed,
        "omissions": omissions,
        "diagnostics": diagnostics,
        "claims": claim_keys,
        "evidence": evidence_keys,
    }
    result["analyses"].append(receipt)
    prune_unreferenced_entities(result)
    return checked(result)


def add_principal_graph_nodes(
    assessment: Assessment,
    nodes: Iterable[Mapping[str, Any]],
) -> Assessment:
    """Record FP-derived graph nodes separately from the observed graph walk."""
    result = cast(Assessment, copy.deepcopy(assessment))
    remove_analysis_slice(result, GRAPH_PRODUCER)
    evidence_keys: list[str] = []
    claim_keys: list[str] = []
    omissions: list[dict[str, str]] = []
    root_address = result["contract"]["deployment_address"].lower()
    root_node_id = f"address:{root_address}"
    root_entity_id, root_entity = entity_record(result["contract"]["chain_id"], root_address, "contract")
    result["entities"].setdefault(root_entity_id, root_entity)
    total = 0
    for raw in nodes:
        total += 1
        address = raw.get("address")
        node_id = raw.get("id")
        if not isinstance(address, str) or not isinstance(node_id, str):
            omissions.append(
                {"target_kind": "contract", "target": result["contract"]["address"], "reason": "invalid_graph_node"}
            )
            continue
        resolved_type = str(raw.get("resolved_type") or "unknown")
        entity_id, entity = entity_record(result["contract"]["chain_id"], address, resolved_type)
        result["entities"][entity_id] = entity
        observation = json_value(dict(raw))
        evidence_key = content_key(
            "evidence",
            {
                "contract": result["contract"],
                "producer": GRAPH_PRODUCER,
                "entity": entity_id,
                "node": observation,
            },
        )
        result["evidence"][evidence_key] = {
            "method": "policy_derivation",
            "subject_kind": "entity",
            "subject": entity_id,
            "observation": observation,
            "producer": GRAPH_PRODUCER,
            "version": "principal_graph/1",
            "locator": {"node_id": node_id},
        }
        evidence_keys.append(evidence_key)
        graph_details = raw.get("details")
        function_count = graph_details.get("fp_function_count", 0) if isinstance(graph_details, Mapping) else 0
        edge_observation = {
            "from_node_id": root_node_id,
            "to_node_id": node_id,
            "relation": "capability_principal",
            "label": None,
            "source_controller_id": None,
            "notes": [f"functions={function_count}"],
        }
        edge_key = content_key(
            "evidence",
            {
                "contract": result["contract"],
                "producer": GRAPH_PRODUCER,
                "edge": edge_observation,
            },
        )
        result["evidence"][edge_key] = {
            "method": "policy_derivation",
            "subject_kind": "entity",
            "subject": entity_id,
            "observation": edge_observation,
            "producer": GRAPH_PRODUCER,
            "version": "principal_graph/1",
            "locator": {"edge": f"{root_node_id}->{node_id}"},
        }
        evidence_keys.append(edge_key)
        proposition: Proposition = {
            "kind": "authority_relationship",
            "authority": {"kind": "entity", "entity": entity_id},
            "target": root_entity_id,
            "relationship": "capability_principal",
        }
        claim_key = content_key(
            "claim",
            {
                "contract": result["contract"],
                "producer": GRAPH_PRODUCER,
                "proposition": proposition,
                "evidence": [evidence_key, edge_key],
                "rule": "policy.function_principal_graph/v1",
            },
        )
        result["claims"][claim_key] = {
            "proposition": proposition,
            "rule": "policy.function_principal_graph/v1",
            "evidence": [evidence_key, edge_key],
            "claims": [],
        }
        claim_keys.append(claim_key)
    result["analyses"].append(
        {
            "detector": GRAPH_PRODUCER,
            "version": "principal_graph/1",
            "status": "completed" if not omissions else ("partial" if claim_keys else "failed"),
            "targets_total": total,
            "targets_completed": total - len(omissions),
            "omissions": omissions,
            "diagnostics": [],
            "claims": claim_keys,
            "evidence": evidence_keys,
        }
    )
    prune_unreferenced_entities(result)
    return checked(result)


__all__ = ["GRAPH_PRODUCER", "PRODUCER", "add_principal_graph_nodes", "add_principal_observations"]
