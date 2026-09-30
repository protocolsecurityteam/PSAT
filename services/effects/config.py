"""Feature flag and shared vocabulary for the effects stage.

No DB or worker imports, so ``policy_worker`` can read the flag. The flag defaults off and gates the ``policy`` ->
``effects`` transition itself: a job routed to a stage nobody drains sits forever.
"""

from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}


def effects_stage_enabled() -> bool:
    """Whether the ``policy`` -> ``effects`` transition is armed.

    Default off until the worker is deployed; enabling it with no effects worker parks every job.
    """
    return os.getenv("PSAT_EFFECTS_STAGE", "0").strip().lower() in _TRUTHY


# Behavioural labels, never name-derived; the values are cache-key components.
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

# Kernels transfer on the resolved-function hash; projections also key on the whole-contract surface hash.
SCOPE_KERNEL = "kernel"
SCOPE_PROJECTION = "projection"

# Destination shapes for value-out. Only ``immutable_fixed`` is benign. Static can prove the fixed shapes (universals);
# simulation can only prove ``caller_arbitrary`` (a landed sentinel).
SHAPE_CALLER_ARBITRARY = "caller_arbitrary"
SHAPE_STORAGE_DETERMINED = "storage_determined"
SHAPE_IMMUTABLE_FIXED = "immutable_fixed"
SHAPE_UNKNOWN = "unknown"

# ``details["observation"]``, carried on every verdict (unknowns included, via ``effects_worker._write_verdicts``):
#
# * ``executed``: the call succeeded; other keys describe F.
# * ``reverted``: other keys describe a call that never happened (``value_moved: false`` means not measured). Always
# ``unknown``.
# * ``not_run``: no call was issued.
#
# Absent means a pre-discriminator row; treat as unmeasured unless proven. Lives here so every emitter uses it (a
# reverted pause once looked like a pause that froze nothing).
OBSERVATION_EXECUTED = "executed"
OBSERVATION_REVERTED = "reverted"
OBSERVATION_NOT_RUN = "not_run"

# ``details["duration_bound_source"]``: how a latch's window was established, produced by
# ``calldata.read_max_pause_duration`` and published by ``anvil.pause_recipe``.
#
# * ``guard_constant``: a guard compares the clock against a constant offset of this latch; trust the bound as a reducer
# only with ``auto_expiry is True``.
# * ``no_time_reference``: proven indefinite (the most severe freeze). The latch is read by a lowered guard, no leaf in
# that tree touches a clock, operand lists are complete (``calldata._absorption_recorded``) and no operand is opaque
# (``calldata._OPAQUE_OPERAND_SOURCES``). Each condition blocks a reproduced false proof (``||`` lowering, pre-widening
# trees, clocks behind view helpers).
# * ``not_determined``: the window wasn't established (stored in state like etherfi's ``$.pauseUntilDuration``, or no
# leaf reads the latch). A confidence gap, neither indefinite nor bounded.
#
# Absent means the row predates this; treat as ``not_determined`` (the old contract read ``None`` as indefinite,
# wrongly).
DURATION_BOUND_GUARD_CONSTANT = "guard_constant"
DURATION_BOUND_NO_TIME_REFERENCE = "no_time_reference"
DURATION_BOUND_NOT_DETERMINED = "not_determined"

# The pseudo-address ``traceTransfers`` uses as the emitter of synthetic native-ETH Transfer logs (measured:
# ``0xeeee…``, and a WETH deposit emits both it and the token log). Reach is per asset, and native ETH has no token
# emitter, so without this native moves match nothing.
NATIVE_ASSET_LOG_EMITTER = "0x" + "ee" * 20

# ``unknown`` is the fail-closed value for every non-observation.
VERDICT_PROVEN = "proven"
VERDICT_UNKNOWN = "unknown"

# The effects stage's internal evidence ladder (history, eth_call, fork), not the scoring framework's tiers. The numbers
# collide: ``TIER_FORK`` is ``"tier2"`` but a fork observation is scoring Tier 1. Always translate via
# :func:`scoring_tier_for_effects_tier`, never by raw string.
TIER_HISTORICAL = "tier0"
TIER_CALL = "tier1"
TIER_FORK = "tier2"

# Provenance of the observation height (``witness.block_source`` beside ``witness.block_number``), naming the scope the
# pin is shared across. Today one pin per stage invocation (``effects_worker._preflight``), so one run can span many
# heights; ``job_pin`` and ``run_pin`` are reserved. Both keys are absent when the height isn't proven; ``0`` is the
# preflight failure sentinel and never published.
BLOCK_SOURCE_INVOCATION_PIN = "invocation_pin"
BLOCK_SOURCE_JOB_PIN = "job_pin"
BLOCK_SOURCE_RUN_PIN = "run_pin"
BLOCK_SOURCES = (BLOCK_SOURCE_INVOCATION_PIN, BLOCK_SOURCE_JOB_PIN, BLOCK_SOURCE_RUN_PIN)

# Scoring-framework tiers, kept distinct from the ``tierN`` strings.
SCORING_TIER_OBSERVED = "scoring_tier_1"
SCORING_TIER_STATIC_FALLBACK = "scoring_tier_2"

# Every effects tier is an observation, so all map to scoring Tier 1.
_EFFECTS_TIER_SCORING_ORIGIN = {
    TIER_HISTORICAL: SCORING_TIER_OBSERVED,
    TIER_CALL: SCORING_TIER_OBSERVED,
    TIER_FORK: SCORING_TIER_OBSERVED,
}


def scoring_tier_for_effects_tier(stored_tier: str | None) -> str | None:
    """Translate a stored effects tier (``"tier0"``/``"tier1"``/``"tier2"``) to its scoring tier: all are
    :data:`SCORING_TIER_OBSERVED`. ``None`` for unrecognized strings (fail closed).
    """
    if stored_tier is None:
        return None
    return _EFFECTS_TIER_SCORING_ORIGIN.get(stored_tier)
