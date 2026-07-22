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
TIER_HISTORICAL = "tier0"
TIER_CALL = "tier1"
TIER_FORK = "tier2"
