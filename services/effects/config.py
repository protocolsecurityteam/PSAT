"""Feature flag + shared vocabulary for the effects-resolution stage.

Kept deliberately light (no DB / worker imports) so ``policy_worker`` can read
the transition flag without importing the effects worker itself. The flag ships
**default-off** and gates the ``policy`` -> ``effects`` *transition* (§3a.4 /
inv. 15), not merely worker processing: a job parked at a stage no worker drains
sits forever, so ``policy.next_stage`` consults this before ever routing into
``effects``.
"""

from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}


def effects_stage_enabled() -> bool:
    """Whether the ``policy`` -> ``effects`` transition is armed.

    Default-off (inv. 15). Unlike ``PSAT_DIFFERENTIAL_PROBE`` — which now
    defaults *on* — this stays off until the worker is deployed and the
    preview cycle validates it; enabling it without an effects worker running
    parks every job (§3a.4)."""
    return os.getenv("PSAT_EFFECTS_STAGE", "0").strip().lower() in _TRUTHY


# Effect classes (v1). Behavioral labels — never name-derived (inv. 1). The
# string values are the ``effect_class`` cache-key component (inv. 12).
EFFECT_CLASS_FREEZE_PAUSE = "freeze_pause"
EFFECT_CLASS_VALUE_OUT = "value_out"
EFFECT_CLASS_CODE_UPGRADE = "code_upgrade"
EFFECT_CLASS_AUTHORITY_CHANGE = "authority_change"
EFFECT_CLASS_SUPPLY = "supply"

EFFECT_CLASSES = frozenset(
    {
        EFFECT_CLASS_FREEZE_PAUSE,
        EFFECT_CLASS_VALUE_OUT,
        EFFECT_CLASS_CODE_UPGRADE,
        EFFECT_CLASS_AUTHORITY_CHANGE,
        EFFECT_CLASS_SUPPLY,
    }
)

# Cache scope discriminator (inv. 3): function-local kernels transfer on the
# resolved-function hash; contract-scoped projections additionally key on the
# whole-contract surface hash.
SCOPE_KERNEL = "kernel"
SCOPE_PROJECTION = "projection"

# Verdict vocabulary. ``unknown`` is the §8 fail-closed value used for every
# non-observation and for the inv. 15 fail-forward exhaustion path.
VERDICT_PROVEN = "proven"
VERDICT_UNKNOWN = "unknown"

# Evidence tiers (§3), cheapest/most-authoritative first.
#
# WARNING — these strings name the effects stage's INTERNAL evidence ladder
# (historical index → eth_call → fork), NOT the scoring framework's Tier 1/2/3.
# They collide numerically with it and the collision is a trap: a fork-OBSERVED
# verdict persists ``"tier2"`` (``TIER_FORK``), yet a fork observation is scoring
# **Tier 1** — a witnessed on-chain state transition, the STRONGEST evidence —
# whereas scoring "Tier 2" means *static-with-fallback*, the opposite provenance.
# Every effects tier below is observation-origin, so all three are scoring Tier 1.
# No consumer (scorer, frontend, aggregation) may map a stored tier by its raw
# string; translate by semantic origin through :func:`scoring_tier_for_effects_tier`.
TIER_HISTORICAL = "tier0"
TIER_CALL = "tier1"
TIER_FORK = "tier2"

# Scoring-framework tiers (the vocabulary the eventual scorer/consumers read).
# Kept distinct from the ``tierN`` strings above precisely so nothing round-trips
# through the colliding raw string. Observed = grade-admissible (a proven positive
# / proven negative); static-with-fallback is never minted by this stage.
SCORING_TIER_OBSERVED = "scoring_tier_1"
SCORING_TIER_STATIC_FALLBACK = "scoring_tier_2"

# Every effects verdict tier is a fork/observation tier, so each maps to the
# OBSERVED scoring tier — never to scoring Tier 2, despite ``TIER_FORK == "tier2"``.
_EFFECTS_TIER_SCORING_ORIGIN = {
    TIER_HISTORICAL: SCORING_TIER_OBSERVED,
    TIER_CALL: SCORING_TIER_OBSERVED,
    TIER_FORK: SCORING_TIER_OBSERVED,
}


def scoring_tier_for_effects_tier(stored_tier: str | None) -> str | None:
    """Translate a stored effects verdict-tier string (``"tier0"``/``"tier1"``/
    ``"tier2"``, e.g. a claim witness's ``verdict_tier``) to its SCORING-framework
    tier by semantic origin — the ONE place the collision is resolved.

    Every effects tier is an on-chain observation tier, so all map to
    :data:`SCORING_TIER_OBSERVED` (scoring Tier 1); the ``"tier2"`` string never
    means scoring Tier 2 here. Returns ``None`` for an unrecognized string so an
    unknown provenance fails closed (never silently promoted to observed)."""
    if stored_tier is None:
        return None
    return _EFFECTS_TIER_SCORING_ORIGIN.get(stored_tier)
