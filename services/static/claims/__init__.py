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
    claim_ids_of_class,
    emit_claim,
    entry_for,
    grant_class_of,
    is_registered,
    legacy_projections,
    register,
    registry,
    resolve_claim_precedence,
    single_contract_static_tier,
)
from .types import (
    CONSUMER_FAMILIES,
    CONTROL_GRANT_CLASSES,
    GRANT_CLASSES,
    SCHEMA_VERSION,
    SINGLE_CONTRACT_STATIC_TIERS,
    STATIC_TIER_WITNESS_KEY,
    TIERS,
    Claim,
    ClaimEvidence,
    ClaimsArtifact,
    ConsumerFamily,
    GrantClass,
    Tier,
    Witness,
)

__all__ = [
    "CONSUMER_FAMILIES",
    "CONTROL_GRANT_CLASSES",
    "GRANT_CLASSES",
    "CONSUMER_REFERENCED_CLAIM_IDS",
    "Claim",
    "ClaimContext",
    "ClaimEvidence",
    "ClaimsArtifact",
    "ConsumerFamily",
    "GrantClass",
    "RegistryEntry",
    "SCHEMA_VERSION",
    "SINGLE_CONTRACT_STATIC_TIERS",
    "STATIC_TIER_WITNESS_KEY",
    "TIERS",
    "Tier",
    "Witness",
    "attach_claims_to_effects",
    "build_claims",
    "claim_ids_of_class",
    "claim_matcher",
    "discover",
    "project_effect_labels",
    "emit_claim",
    "entry_for",
    "grant_class_of",
    "is_registered",
    "legacy_projections",
    "register",
    "registry",
    "resolve_claim_precedence",
    "single_contract_static_tier",
]
