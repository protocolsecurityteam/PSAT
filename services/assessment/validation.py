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
    from services.abi import is_canonical_abi_signature, selector_for_signature

    for signature, function in assessment["functions"].items():
        abi_signature = function["abi_signature"]
        selector = function["selector"]
        if abi_signature is not None:
            if not is_canonical_abi_signature(abi_signature):
                problems.append(f"functions.{signature}.abi_signature: not a canonical ABI signature")
            elif selector is not None and selector != selector_for_signature(abi_signature):
                problems.append(f"functions.{signature}.selector: does not match ABI signature")
    if problems:
        raise ValueError("invalid assessment: " + "; ".join(problems))
    return assessment


__all__ = ["checked"]
