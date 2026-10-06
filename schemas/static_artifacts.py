"""The required semantic outputs of a successful static analysis."""

from typing import Any


def validate_static_artifacts(predicate_trees: Any, effects: Any) -> None:
    # Empty maps are valid for unguarded/no-effect contracts; a missing map is not.
    for name, artifact, key in (("predicate_trees", predicate_trees, "trees"), ("effects", effects, "functions")):
        if not isinstance(artifact, dict) or "error" in artifact or not isinstance(artifact.get(key), dict):
            raise ValueError(f"Incomplete static artifact: {name}")
