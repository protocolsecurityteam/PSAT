"""Canonical evidence-backed assessment construction."""

from .diagnostics import add_stage_errors
from .effects import add_effects
from .governance import (
    record_applied_configuration,
    record_configuration,
    record_proposal_state,
    record_scenario_configuration,
)
from .observations import add_observations
from .policy import add_policy, derive_policy
from .principals import add_principal_graph_nodes
from .resolution import add_resolution
from .runtime import contract_subject, control_graph, controller_observations, observation_plan
from .static import build_static_assessment
from .validation import checked
from .views import (
    effect_matches_by_function,
    effect_presence,
    function_authority_claims,
    function_effect_claims,
    project_permission_index,
    static_index_view,
    static_inputs,
)

__all__ = [
    "add_effects",
    "add_observations",
    "add_policy",
    "add_principal_graph_nodes",
    "derive_policy",
    "add_resolution",
    "contract_subject",
    "control_graph",
    "controller_observations",
    "observation_plan",
    "add_stage_errors",
    "build_static_assessment",
    "checked",
    "effect_presence",
    "function_effect_claims",
    "function_authority_claims",
    "effect_matches_by_function",
    "project_permission_index",
    "static_index_view",
    "static_inputs",
    "record_applied_configuration",
    "record_configuration",
    "record_proposal_state",
    "record_scenario_configuration",
]
