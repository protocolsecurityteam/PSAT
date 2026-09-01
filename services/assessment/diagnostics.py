"""Attach pipeline failures to analysis receipts, never to claims."""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from typing import Any, cast

from schemas.assessment import Analysis, Assessment, Diagnostic

from .validation import checked


def _field(error: Any, name: str, default: Any = None) -> Any:
    if isinstance(error, Mapping):
        return error.get(name, default)
    return getattr(error, name, default)


def add_stage_errors(assessment: Assessment, errors: Iterable[Any]) -> Assessment:
    """Merge StageError-shaped values into per-stage analysis receipts."""

    result = cast(Assessment, copy.deepcopy(assessment))
    grouped: dict[str, list[Any]] = {}
    for error in errors:
        stage = str(_field(error, "stage", "unknown"))
        grouped.setdefault(stage, []).append(error)

    for stage, stage_errors in grouped.items():
        detector = f"stage.{stage}"
        prior = next((item for item in result["analyses"] if item["detector"] == detector), None)
        diagnostics = list(prior["diagnostics"]) if prior is not None else []
        for error in stage_errors:
            severity = _field(error, "severity", "degraded")
            diagnostic: Diagnostic = {
                "severity": "error" if severity == "error" else "degraded",
                "code": str(_field(error, "exc_type", "PipelineError")),
                "message": str(_field(error, "message", "pipeline analysis failed")),
                "target_kind": "contract",
                "target": result["contract"]["deployment_address"],
            }
            if diagnostic not in diagnostics:
                diagnostics.append(diagnostic)
        status = "failed" if any(item["severity"] == "error" for item in diagnostics) else "partial"
        receipt: Analysis = {
            "detector": detector,
            "version": "pipeline/1",
            "status": status,
            "targets_total": 1,
            "targets_completed": 0,
            "omissions": [
                {
                    "target_kind": "contract",
                    "target": result["contract"]["deployment_address"],
                    "reason": f"{stage}_stage_degraded",
                }
            ],
            "diagnostics": diagnostics,
            "claims": [],
            "evidence": [],
        }
        result["analyses"] = [item for item in result["analyses"] if item["detector"] != detector]
        result["analyses"].append(receipt)
    return checked(result)


__all__ = ["add_stage_errors"]
