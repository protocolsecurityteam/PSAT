"""Runtime gate for canonical assessment writers."""

from __future__ import annotations

from typing import cast

from pydantic import TypeAdapter

from schemas.assessment import Assessment, assessment_problems

_ADAPTER = TypeAdapter(Assessment)


def checked(value: object) -> Assessment:
    """Validate shape and references, returning the original document."""

    _ADAPTER.validate_python(value, strict=True)
    assessment = cast(Assessment, value)
    problems = assessment_problems(assessment)
    if problems:
        raise ValueError("invalid assessment: " + "; ".join(problems))
    return assessment


__all__ = ["checked"]
