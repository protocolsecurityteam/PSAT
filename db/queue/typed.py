"""Validated reader for the canonical assessment wire.

``store_artifact`` / ``get_artifact`` transport arbitrary JSON; the type of
an artifact dies at serialization and readers used to resurrect it with
``cast`` — a promise pyright believes and Python never checks. The loaders
here make the read boundary honest: each named artifact is validated against
its ``schemas`` TypedDict (via pydantic ``TypeAdapter``) the moment it comes
back out of storage, so schema drift fails LOUDLY at the boundary with the
offending field named, instead of surfacing as a missing key three stages
downstream.

Design points:

- **Fail closed.** A stored document that violates its schema raises
  :class:`ArtifactSchemaError`. ``None`` means "no artifact row" — never
  "artifact present but unusable".
- **No data loss.** Validation returns the ORIGINAL dict object after it
  passes the type check (pydantic's own output would drop unknown keys a
  future producer added, silently truncating the artifact).
"""

from __future__ import annotations

from typing import Any

from pydantic import TypeAdapter, ValidationError

from schemas.assessment import Assessment, assessment_problems

__all__ = ["ArtifactSchemaError", "load_assessment", "load_assessment_inputs"]


class ArtifactSchemaError(RuntimeError):
    """An artifact row exists but its body violates the declared schema."""

    def __init__(self, artifact_name: str, problems: list[str]) -> None:
        self.artifact_name = artifact_name
        self.problems = problems
        super().__init__(f"artifact {artifact_name!r} failed schema validation: {'; '.join(problems)}")


def _problem_list(exc: ValidationError) -> list[str]:
    return [f"{'.'.join(str(loc) for loc in err['loc']) or '<root>'}: {err['msg']}" for err in exc.errors()]


def _load_typed(
    read: Any,
    session: Any,
    job_id: Any,
    name: str,
    adapter: TypeAdapter[Any],
) -> Any:
    raw = read(session, job_id, name)
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ArtifactSchemaError(name, [f"expected a JSON object, got {type(raw).__name__}"])
    try:
        adapter.validate_python(raw)
    except ValidationError as exc:
        raise ArtifactSchemaError(name, _problem_list(exc)) from None
    return raw


_ASSESSMENT_ADAPTER = TypeAdapter(Assessment)


def load_assessment(read: Any, session: Any, job_id: Any) -> Assessment | None:
    """The canonical evidence-backed pipeline output."""
    assessment = _load_typed(read, session, job_id, "assessment", _ASSESSMENT_ADAPTER)
    if assessment is None:
        return None
    problems = assessment_problems(assessment)
    if problems:
        raise ArtifactSchemaError("assessment", problems)
    return assessment


def load_assessment_inputs(
    read: Any, session: Any, job_id: Any
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Load static facts, predicate trees, and effects from Assessment evidence."""

    assessment = load_assessment(read, session, job_id)
    if assessment is None:
        return None
    from services.assessment import static_inputs

    return static_inputs(assessment)
