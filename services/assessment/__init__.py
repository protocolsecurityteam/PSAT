"""Canonical evidence-backed assessment construction."""

from .diagnostics import add_stage_errors
from .effects import add_effects
from .observations import add_observations
from .policy import add_policy
from .resolution import add_resolution
from .runtime import contract_subject, control_graph, controller_observations, observation_plan
from .static import build_static_assessment
from .validation import checked
from .views import (
    capability_claims,
    effect_matches_by_function,
    effect_presence,
    function_effect_claims,
    project_permission_index,
    static_index_view,
    static_inputs,
)

__all__ = [
    "add_effects",
    "add_observations",
    "add_policy",
    "add_resolution",
    "contract_subject",
    "control_graph",
    "controller_observations",
    "observation_plan",
    "add_stage_errors",
    "build_static_assessment",
    "capability_claims",
    "checked",
    "effect_presence",
    "function_effect_claims",
    "effect_matches_by_function",
    "project_permission_index",
    "static_index_view",
    "static_inputs",
]
