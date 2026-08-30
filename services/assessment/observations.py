"""Controller observations become evidence; read failures become diagnostics."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any, cast

from pydantic import JsonValue

from schemas.assessment import Analysis, Assessment, Diagnostic, Evidence, EvidenceMethod, Omission

from .ids import stable_id
from .validation import checked


def _json(value: Any) -> JsonValue:
    return cast(JsonValue, json.loads(json.dumps(value, sort_keys=True, default=str)))


def _method(observed_via: object) -> EvidenceMethod:
    if observed_via == "event_log":
        return "event"
    if observed_via == "storage_poll":
        return "storage"
    return "rpc"


def add_observations(assessment: Assessment, snapshot: Mapping[str, Any]) -> Assessment:
    """Add successful controller reads and an observation analysis receipt."""

    result = cast(Assessment, copy.deepcopy(assessment))
    controller_ids = {controller["key"]: controller_id for controller_id, controller in result["controllers"].items()}
    raw_values = snapshot.get("controller_values")
    values = raw_values if isinstance(raw_values, Mapping) else {}
    omissions: list[Omission] = []
    diagnostics: list[Diagnostic] = []
    evidence_ids: list[str] = []
    completed = 0

    for key, raw in sorted(values.items(), key=lambda item: str(item[0])):
        if not isinstance(key, str) or not isinstance(raw, Mapping):
            continue
        controller_id = controller_ids.get(key)
        if controller_id is None:
            omissions.append(
                {
                    "target_kind": "contract",
                    "target_id": result["contract"]["id"],
                    "reason": f"snapshot_controller_not_defined:{key}",
                }
            )
            continue
        observed_via = raw.get("observed_via")
        if isinstance(observed_via, str) and (observed_via.endswith("_error") or observed_via == "read_error"):
            omissions.append(
                {
                    "target_kind": "controller",
                    "target_id": controller_id,
                    "reason": observed_via,
                }
            )
            diagnostics.append(
                {
                    "severity": "degraded",
                    "code": "ControllerReadFailed",
                    "message": f"controller {key} could not be observed via {observed_via}",
                    "target_kind": "controller",
                    "target_id": controller_id,
                }
            )
            continue

        completed += 1
        observation = _json(
            {
                "value": raw.get("value"),
                "resolved_type": raw.get("resolved_type"),
                "block_number": raw.get("block_number", snapshot.get("block_number")),
                "observed_via": observed_via,
                "details": raw.get("details") or {},
                "authority_provenance": raw.get("authority_provenance"),
            }
        )
        method = _method(observed_via)
        evidence_id = stable_id(
            "evidence",
            {
                "scope": result["scope"],
                "method": method,
                "controller_id": controller_id,
                "observation": observation,
            },
        )
        evidence: Evidence = {
            "id": evidence_id,
            "method": method,
            "subject": {"kind": "controller", "id": controller_id},
            "observation": observation,
            "source": {
                "producer": "resolution.observation",
                "version": str(snapshot.get("schema_version") or "observation/legacy"),
                "locator": _json({"controller_key": key}),
            },
            "scope": result["scope"],
        }
        result["evidence"][evidence_id] = evidence
        evidence_ids.append(evidence_id)

    status = "completed" if not omissions else ("partial" if completed else "failed")
    receipt: Analysis = {
        "detector": "observe.controllers",
        "version": str(snapshot.get("schema_version") or "observation/legacy"),
        "status": status,
        "coverage": {
            "targets_total": len(values),
            "targets_completed": completed,
            "omissions": omissions,
        },
        "diagnostics": diagnostics,
        "claim_ids": [],
        "evidence_ids": sorted(set(evidence_ids)),
    }
    result["analyses"] = [item for item in result["analyses"] if item["detector"] != "observe.controllers"]
    result["analyses"].append(receipt)
    return checked(result)


__all__ = ["add_observations"]
