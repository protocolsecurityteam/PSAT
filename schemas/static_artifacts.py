"""The required semantic outputs of a successful static analysis."""

from typing import Any, TypeGuard


def analysis_is_reusable(analysis: Any) -> TypeGuard[dict[str, Any]]:
    """Partial results may be reported on their job, but must not become a successful cache donor."""
    if not isinstance(analysis, dict) or "error" in analysis:
        return False
    status = analysis.get("analysis_status", {})
    return (
        isinstance(status, dict) and status.get("static_analysis_completed", True) is True and not status.get("errors")
    )


def validate_static_artifacts(predicate_trees: Any, effects: Any) -> None:
    # Empty maps are valid for unguarded/no-effect contracts; a missing map is not.
    for name, artifact, key in (("predicate_trees", predicate_trees, "trees"), ("effects", effects, "functions")):
        if not isinstance(artifact, dict) or "error" in artifact or not isinstance(artifact.get(key), dict):
            raise ValueError(f"Incomplete static artifact: {name}")
