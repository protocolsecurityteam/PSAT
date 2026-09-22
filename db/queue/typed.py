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

import json
from typing import Any, cast

from pydantic import ValidationError

from schemas.assessment import Assessment, assessment_problems
from schemas.assessment_projection import LegacyAssessmentProjection

__all__ = [
    "ArtifactSchemaError",
    "load_assessment",
    "load_assessment_projection",
    "load_assessment_inputs",
    "validate_assessment",
]


class ArtifactSchemaError(RuntimeError):
    """An artifact row exists but its body violates the declared schema."""

    def __init__(self, artifact_name: str, problems: list[str]) -> None:
        self.artifact_name = artifact_name
        self.problems = problems
        super().__init__(f"artifact {artifact_name!r} failed schema validation: {'; '.join(problems)}")


def _problem_list(exc: ValidationError) -> list[str]:
    return [f"{'.'.join(str(loc) for loc in err['loc']) or '<root>'}: {err['msg']}" for err in exc.errors()]


def load_assessment(read: Any, session: Any, job_id: Any) -> Assessment | None:
    """Read and strictly validate the canonical analytical document."""
    raw = read(session, job_id, "assessment")
    if raw is None:
        return None
    return validate_assessment(raw)


def validate_assessment(raw: object) -> Assessment:
    """Validate an already-loaded body through the same storage boundary."""
    from pydantic import TypeAdapter

    if not isinstance(raw, dict):
        raise ArtifactSchemaError("assessment", [f"expected a JSON object, got {type(raw).__name__}"])
    try:
        TypeAdapter(Assessment).validate_json(json.dumps(raw), strict=True)
        assessment = cast(Assessment, raw)
        problems = assessment_problems(assessment)
        if problems:
            raise ArtifactSchemaError("assessment", problems)
        return assessment
    except ValidationError as exc:
        raise ArtifactSchemaError("assessment", _problem_list(exc)) from None
    except ValueError as exc:
        raise ArtifactSchemaError("assessment", [str(exc)]) from None


def load_assessment_projection(session: Any, job_id: Any) -> LegacyAssessmentProjection | None:
    """Load the transient compact projection required by legacy pipeline builders."""
    from db.queue.artifacts import get_artifact, get_assessment_projection
    from services.assessment.validation import checked

    canonical = load_assessment(get_artifact, session, job_id)
    if canonical is None:
        return None
    raw = get_assessment_projection(session, job_id)
    if raw is None:
        return None
    try:
        return checked(raw)
    except ValidationError as exc:
        raise ArtifactSchemaError("assessment projection", _problem_list(exc)) from None
    except ValueError as exc:
        raise ArtifactSchemaError("assessment projection", [str(exc)]) from None


def load_assessment_inputs(session: Any, job_id: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Load static facts, predicate trees, and effects from Assessment evidence."""

    assessment = load_assessment_projection(session, job_id)
    if assessment is None:
        return None
    from services.assessment import static_inputs

    return static_inputs(assessment)
