"""Two-plane claims subsystem (Plane 1).

Facts (``effects.py``, Plane 0) are the substrate; this package turns them into
typed, machine-checkable CLAIM objects ``{claim_id, tier, witness}`` minted only
through a code registry. Public surface:

- ``build_claims`` / ``attach_claims_to_effects`` — produce the claims artifact
  and ride it through the effects transport (called from the static pipeline).
- ``emit_claim`` / ``registry`` / ``RegistryEntry`` — the registry contract.
- ``claim_matcher`` — the decorator matcher agents use to ADD a matcher module.
- ``ClaimContext`` — the tolerant read-only facts view matchers consult.
"""

from __future__ import annotations

from .builder import attach_claims_to_effects, build_claims
from .consumers import CONSUMER_REFERENCED_CLAIM_IDS
from .context import ClaimContext
from .decorator import claim_matcher
from .matchers import discover
from .registry import (
    RegistryEntry,
    emit_claim,
    entry_for,
    is_registered,
    legacy_projections,
    register,
    registry,
    resolve_claim_precedence,
)
from .types import (
    CONSUMER_FAMILIES,
    SCHEMA_VERSION,
    TIERS,
    Claim,
    ClaimEvidence,
    ClaimsArtifact,
    ConsumerFamily,
    Tier,
    Witness,
)

__all__ = [
    "CONSUMER_FAMILIES",
    "CONSUMER_REFERENCED_CLAIM_IDS",
    "Claim",
    "ClaimContext",
    "ClaimEvidence",
    "ClaimsArtifact",
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
    "legacy_projections",
    "register",
    "registry",
    "resolve_claim_precedence",
]
