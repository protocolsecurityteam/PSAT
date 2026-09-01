"""Transient runtime inputs projected from the canonical assessment.

These helpers exist for algorithms that still prefer batch-shaped dictionaries.
The dictionaries are never persisted: ``Assessment`` remains the only durable
analytical document.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from schemas.assessment import Assessment


def _list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def contract_subject(assessment: Assessment) -> dict[str, Any]:
    return {
        "subject": {
            "address": assessment["contract"]["deployment_address"],
            "name": assessment["contract"]["name"],
        }
    }


def observation_plan(assessment: Assessment) -> dict[str, Any]:
    """Compile controller read/watch instructions without another wire type."""

    tracked: list[dict[str, Any]] = []
    for controller_key, controller in assessment["controllers"].items():
        tracking = controller["tracking"] if isinstance(controller["tracking"], Mapping) else {}
        events = _list(tracking.get("associated_events"))
        writers = [
            item["function"]
            for item in _list(tracking.get("writer_functions"))
            if isinstance(item, Mapping) and isinstance(item.get("function"), str)
        ]
        mode = tracking.get("mode")
        cadence = "state_only"
        if mode == "event_plus_state":
            cadence = "realtime_confirm"
        elif mode == "manual_review":
            cadence = "periodic_reconciliation"
        item: dict[str, Any] = {
            "controller_id": controller_key,
            "label": controller["label"],
            "source": controller["source"],
            "kind": controller["kind"],
            "read_spec": controller["read_strategy"],
            "tracking_mode": mode,
            "event_watch": (
                {
                    "transport": "wss_logs",
                    "contract_address": assessment["contract"]["deployment_address"],
                    "events": events,
                    "writer_functions": writers,
                }
                if events
                else None
            ),
            "polling_fallback": {
                "contract_address": assessment["contract"]["deployment_address"],
                "polling_sources": _list(tracking.get("polling_sources")),
                "cadence": cadence,
                "notes": _list(tracking.get("notes")),
            },
            "notes": _list(tracking.get("notes")),
        }
        provenance = tracking.get("authority_provenance")
        if provenance is not None:
            item["authority_provenance"] = provenance
        tracked.append(item)
    return {
        "schema_version": assessment["schema_version"],
        "contract_address": assessment["contract"]["deployment_address"],
        "contract_name": assessment["contract"]["name"],
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": sorted(tracked, key=lambda item: str(item["label"])),
    }


def controller_observations(assessment: Assessment) -> dict[str, Any]:
    """Project successful observation evidence for runtime policy evaluation."""

    controllers = assessment["controllers"]
    values: dict[str, dict[str, Any]] = {}
    block_number = 0
    for evidence in assessment["evidence"].values():
        if evidence["subject_kind"] != "controller" or evidence["producer"] != "resolution.observation":
            continue
        controller = controllers.get(evidence["subject"])
        observation = evidence["observation"]
        if controller is None or not isinstance(observation, Mapping):
            continue
        observed_block = observation.get("block_number")
        if isinstance(observed_block, int):
            block_number = max(block_number, observed_block)
        values[evidence["subject"]] = {
            "source": controller["source"],
            "value": observation.get("value"),
            "block_number": observed_block,
            "observed_via": observation.get("observed_via"),
            "resolved_type": observation.get("resolved_type"),
            "details": observation.get("details") or {},
            **(
                {"authority_provenance": observation["authority_provenance"]}
                if observation.get("authority_provenance") is not None
                else {}
            ),
        }
    return {
        "schema_version": assessment["schema_version"],
        "contract_address": assessment["contract"]["deployment_address"],
        "contract_name": assessment["contract"]["name"],
        "block_number": block_number,
        "controller_values": values,
    }


def control_graph(assessment: Assessment) -> dict[str, Any]:
    """Project resolved entities and relationships for graph algorithms."""

    entity_nodes: dict[str, dict[str, Any]] = {}
    for evidence in assessment["evidence"].values():
        if evidence["subject_kind"] != "entity" or evidence["producer"] != "resolution.graph":
            continue
        observation = evidence["observation"]
        locator = evidence["locator"]
        if not isinstance(observation, Mapping) or not isinstance(locator, Mapping) or "node_id" not in locator:
            continue
        entity = assessment["entities"].get(evidence["subject"])
        if entity is None:
            continue
        entity_nodes[evidence["subject"]] = {
            "id": str(locator["node_id"]),
            "address": entity["address"],
            "node_type": observation.get("node_type") or entity["kind"],
            "resolved_type": observation.get("resolved_type") or "unknown",
            "label": observation.get("label") or entity["address"],
            "contract_name": observation.get("contract_name"),
            "depth": observation.get("depth") or 0,
            "analysis_state": observation.get("analysis_state"),
            "details": observation.get("details") or {},
            "artifacts": observation.get("artifacts") or {},
        }

    edges: list[dict[str, Any]] = []
    for evidence in assessment["evidence"].values():
        if evidence["producer"] != "resolution.graph":
            continue
        observation = evidence["observation"]
        if not isinstance(observation, Mapping) or "from_entity" not in observation:
            continue
        source = entity_nodes.get(str(observation.get("from_entity")))
        target = entity_nodes.get(str(observation.get("to_entity")))
        if source is None or target is None:
            continue
        edges.append(
            {
                "from_id": source["id"],
                "to_id": target["id"],
                "relation": observation.get("relation"),
                "label": observation.get("relation"),
                "source_controller_id": observation.get("source_controller_id"),
                "notes": _list(observation.get("notes")),
            }
        )

    return {
        "schema_version": assessment["schema_version"],
        "root_contract_address": assessment["contract"]["deployment_address"],
        "max_depth": max((int(node["depth"]) for node in entity_nodes.values()), default=0),
        "nodes": list(entity_nodes.values()),
        "edges": edges,
    }


__all__ = ["contract_subject", "control_graph", "controller_observations", "observation_plan"]
