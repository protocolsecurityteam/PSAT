"""Static effect matcher subsystem.

Facts (``effects.py``, Plane 0) are the substrate; this package runs the matcher
registry emits positive ``EffectMatch`` records. The assessment builder turns
each successful match into first-class Evidence,
Basis, and Claim records; matcher failures ride analysis receipts instead.

- ``build_claims`` / ``attach_claims_to_effects`` — produce the claims artifact
  and ride it through the effects transport (called from the static pipeline).
- ``emit_claim`` / ``registry`` / ``RegistryEntry`` — the registry contract.
- ``claim_matcher`` — the decorator matcher agents use to ADD a matcher module.
- ``ClaimContext`` — the tolerant read-only facts view matchers consult.
"""

from __future__ import annotations

from .builder import attach_claims_to_effects, build_claims
from .context import ClaimContext
from .decorator import claim_matcher
from .matchers import discover
from .registry import (
    RegistryEntry,
    emit_claim,
    entry_for,
    is_registered,
    register,
    registry,
    resolve_claim_precedence,
)
from .types import (
    CONSUMER_FAMILIES,
    SCHEMA_VERSION,
    TIERS,
    ConsumerFamily,
    EffectMatch,
    MatchedEvidence,
    MatchResults,
    Tier,
    Witness,
)

__all__ = [
    "CONSUMER_FAMILIES",
    "ClaimContext",
    "MatchedEvidence",
    "EffectMatch",
    "MatchResults",
    "ConsumerFamily",
    "RegistryEntry",
    "SCHEMA_VERSION",
    "TIERS",
    "Tier",
    "Witness",
    "attach_claims_to_effects",
    "build_claims",
    "claim_matcher",
    "discover",
    "emit_claim",
    "entry_for",
    "is_registered",
    "register",
    "registry",
    "resolve_claim_precedence",
]
