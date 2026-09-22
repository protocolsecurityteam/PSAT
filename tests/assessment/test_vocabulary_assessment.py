"""Canonical effect vocabulary cannot drift from registered claim rules."""

from __future__ import annotations

from typing import get_args

import schemas.assessment as assessment_schema
import services.effects.claims_bridge  # noqa: F401
import services.static.cross_contract  # noqa: F401
from schemas.assessment_projection import EffectKind, LegacyAssessmentProjection
from services.static.claims import discover, registry


def test_effect_kind_is_exactly_the_registry_vocabulary() -> None:
    discover()
    assert set(get_args(EffectKind)) == set(registry())


def test_assessment_public_model_is_one_row_shaped_type() -> None:
    assert set(assessment_schema.__all__) == {"Assessment", "assessment_problems"}
    assert assessment_schema.Assessment.__required_keys__ == {
        "view",
        "subjects",
        "evidence",
        "claims",
        "analyses",
        "corrections",
        "contexts",
        "implementations",
        "payloads",
    }
    assert "schema_version" not in assessment_schema.Assessment.__required_keys__
    assert LegacyAssessmentProjection.__required_keys__ != assessment_schema.Assessment.__required_keys__
    assert "LegacyAssessmentProjection" not in assessment_schema.__all__
