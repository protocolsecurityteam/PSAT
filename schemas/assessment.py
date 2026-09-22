"""Canonical envelope for the analytical artifacts produced for one job."""

from __future__ import annotations

from typing import Any, Literal, TypedDict, cast

from typing_extensions import NotRequired

from .contract_analysis import ContractAnalysis
from .control_tracking import ControlSnapshot, ControlTrackingPlan
from .effective_permissions import EffectivePermissions
from .principal_labels import PrincipalLabels
from .resolved_control_graph import ResolvedControlGraph

AssessmentVersion = Literal["assessment/1"]
ASSESSMENT_VERSION: AssessmentVersion = "assessment/1"
ASSESSMENT_SECTIONS = (
    "contract_analysis",
    "predicate_trees",
    "effects",
    "control_tracking_plan",
    "control_snapshot",
    "resolved_control_graph",
    "effective_permissions",
    "principal_labels",
    "principal_history",
)
AssessmentSectionName = Literal[
    "contract_analysis",
    "predicate_trees",
    "effects",
    "control_tracking_plan",
    "control_snapshot",
    "resolved_control_graph",
    "effective_permissions",
    "principal_labels",
    "principal_history",
]


class Assessment(TypedDict):
    schema_version: AssessmentVersion
    contract_analysis: NotRequired[ContractAnalysis]
    predicate_trees: NotRequired[dict[str, Any]]
    effects: NotRequired[dict[str, Any]]
    control_tracking_plan: NotRequired[ControlTrackingPlan]
    control_snapshot: NotRequired[ControlSnapshot]
    resolved_control_graph: NotRequired[ResolvedControlGraph]
    effective_permissions: NotRequired[EffectivePermissions]
    principal_labels: NotRequired[PrincipalLabels]
    principal_history: NotRequired[dict[str, Any]]
    recursive: NotRequired[dict[str, "Assessment"]]


def validate_assessment(value: object) -> Assessment:
    """Validate the envelope without rewriting or interpreting section data."""
    if not isinstance(value, dict):
        raise ValueError("assessment must be an object")
    if value.get("schema_version") != ASSESSMENT_VERSION:
        raise ValueError(f"assessment.schema_version must be {ASSESSMENT_VERSION!r}")
    unknown = set(value) - {"schema_version", "recursive", *ASSESSMENT_SECTIONS}
    if unknown:
        raise ValueError(f"assessment has unknown fields: {sorted(unknown)!r}")
    for name in ASSESSMENT_SECTIONS:
        if name in value and not isinstance(value[name], dict):
            raise ValueError(f"assessment.{name} must be an object")
    recursive = value.get("recursive")
    if "recursive" in value:
        if not isinstance(recursive, dict):
            raise ValueError("assessment.recursive must be an object")
        for key, child in recursive.items():
            if not isinstance(key, str) or not key:
                raise ValueError("assessment.recursive keys must be non-empty strings")
            validate_assessment(child)
    return cast(Assessment, value)


__all__ = [
    "ASSESSMENT_SECTIONS",
    "ASSESSMENT_VERSION",
    "Assessment",
    "AssessmentSectionName",
    "AssessmentVersion",
    "validate_assessment",
]
