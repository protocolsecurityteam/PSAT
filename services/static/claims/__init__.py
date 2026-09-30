"""Claims: typed, machine-checkable statements about functions, minted from the Plane-0 facts only through the
registry.
"""

from __future__ import annotations

from .builder import attach_claims_to_effects, build_claims, project_effect_labels
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
    "project_effect_labels",
    "emit_claim",
    "entry_for",
    "is_registered",
    "legacy_projections",
    "register",
    "registry",
    "resolve_claim_precedence",
]
