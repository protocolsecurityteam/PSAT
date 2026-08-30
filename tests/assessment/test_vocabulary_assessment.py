"""Canonical effect vocabulary cannot drift from registered claim rules."""

from __future__ import annotations

from typing import get_args

import services.effects.claims_bridge  # noqa: F401
import services.static.cross_contract  # noqa: F401
from schemas.assessment import EffectKind
from services.static.claims import discover, registry


def test_effect_kind_is_exactly_the_registry_vocabulary() -> None:
    discover()
    assert set(get_args(EffectKind)) == set(registry())
