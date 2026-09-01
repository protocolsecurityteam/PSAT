"""Controller observations become evidence; read failures become diagnostics."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any, cast

from pydantic import JsonValue

from schemas.assessment import Analysis, Assessment, Diagnostic, Evidence, EvidenceMethod

from .keys import content_key
from .slices import remove_analysis_slice
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
    remove_analysis_slice(result, "observe.controllers")
    raw_values = snapshot.get("controller_values")
    values = raw_values if isinstance(raw_values, Mapping) else {}
    omissions: list[dict[str, str]] = []
    diagnostics: list[Diagnostic] = []
    evidence_keys: list[str] = []
    completed = 0

    for key, raw in sorted(values.items(), key=lambda item: str(item[0])):
        if not isinstance(key, str) or not isinstance(raw, Mapping):
            continue
        controller = key if key in result["controllers"] else None
        if controller is None:
            omissions.append(
                {
                    "target_kind": "contract",
                    "target": result["contract"]["deployment_address"],
                    "reason": f"snapshot_controller_not_defined:{key}",
                }
            )
            continue
        observed_via = raw.get("observed_via")
        if isinstance(observed_via, str) and (observed_via.endswith("_error") or observed_via == "read_error"):
            omissions.append(
                {
                    "target_kind": "controller",
                    "target": controller,
                    "reason": observed_via,
                }
            )
            diagnostics.append(
                {
                    "severity": "degraded",
                    "code": "ControllerReadFailed",
                    "message": f"controller {key} could not be observed via {observed_via}",
                    "target_kind": "controller",
                    "target": controller,
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
        evidence_key = content_key(
            "evidence",
            {
                "contract": result["contract"],
                "method": method,
                "controller": controller,
                "observation": observation,
            },
        )
        evidence: Evidence = {
            "method": method,
            "subject_kind": "controller",
            "subject": controller,
            "observation": observation,
            "producer": "resolution.observation",
            "version": str(snapshot.get("schema_version") or "observation/1"),
            "locator": _json({"controller_key": key}),
        }
        result["evidence"][evidence_key] = evidence
        evidence_keys.append(evidence_key)

    status = "completed" if not omissions else ("partial" if completed else "failed")
    receipt: Analysis = {
        "detector": "observe.controllers",
        "version": str(snapshot.get("schema_version") or "observation/1"),
        "status": status,
        "targets_total": len(values),
        "targets_completed": completed,
        "omissions": omissions,
        "diagnostics": diagnostics,
        "claims": [],
        "evidence": sorted(set(evidence_keys)),
    }
    result["analyses"].append(receipt)
    return checked(result)


__all__ = ["add_observations"]
