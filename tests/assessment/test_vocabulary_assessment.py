"""Canonical effect vocabulary cannot drift from registered claim rules."""

from __future__ import annotations

from typing import get_args

import schemas.assessment as assessment_schema
import services.effects.claims_bridge  # noqa: F401
import services.static.cross_contract  # noqa: F401
from schemas.assessment import EffectKind
from services.static.claims import discover, registry


def test_effect_kind_is_exactly_the_registry_vocabulary() -> None:
    discover()
    assert set(get_args(EffectKind)) == set(registry())


def test_assessment_public_model_stays_small_and_has_no_id_wrappers() -> None:
    records = {
        name for name in assessment_schema.__all__ if hasattr(getattr(assessment_schema, name), "__required_keys__")
    }
    assert records == {
        "Analysis",
        "Assessment",
        "Authority",
        "Claim",
        "Contract",
        "Controller",
        "Diagnostic",
        "Effect",
        "Entity",
        "Evidence",
        "Function",
        "Proposition",
    }
    assert not any(name.endswith(("Id", "Ref", "Model")) for name in assessment_schema.__all__)
