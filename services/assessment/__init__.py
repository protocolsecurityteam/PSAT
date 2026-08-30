"""Canonical evidence-backed assessment construction."""

from .diagnostics import add_stage_errors
from .effects import add_effects
from .ids import stable_id
from .observations import add_observations
from .policy import add_policy
from .resolution import add_resolution
from .static import build_static_assessment
from .validation import checked
from .views import (
    capability_claims,
    effect_presence,
    function_effect_claims,
    legacy_claims_by_function,
    project_effective_permissions,
)

__all__ = [
    "add_effects",
    "add_observations",
    "add_policy",
    "add_resolution",
    "add_stage_errors",
    "build_static_assessment",
    "capability_claims",
    "checked",
    "effect_presence",
    "function_effect_claims",
    "legacy_claims_by_function",
    "project_effective_permissions",
    "stable_id",
]
