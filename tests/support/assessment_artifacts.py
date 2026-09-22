"""Pack existing stage-output fixtures into the canonical storage layout."""

from __future__ import annotations

from typing import Any

from schemas.assessment import ASSESSMENT_SECTIONS, ASSESSMENT_VERSION


def assessment_artifacts(artifacts: dict[str, Any]) -> dict[str, Any]:
    """Keep fixture payloads identical while changing their storage container."""
    sections = {name: value for name, value in artifacts.items() if name in ASSESSMENT_SECTIONS}
    result = {name: value for name, value in artifacts.items() if name not in ASSESSMENT_SECTIONS}
    if sections:
        result["assessment"] = {"schema_version": ASSESSMENT_VERSION, **sections}
    return result
