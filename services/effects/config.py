"""Feature flag + shared vocabulary for the effects-resolution stage.

Kept deliberately light (no DB / worker imports) so ``policy_worker`` can read
the transition flag without importing the effects worker itself. The flag ships
**default-off** and gates the ``policy`` -> ``effects`` *transition*, not merely
worker processing: a job parked at a stage no worker drains
sits forever, so ``policy.next_stage`` consults this before ever routing into
``effects``.
"""

from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}


def effects_stage_enabled() -> bool:
    """Whether the ``policy`` -> ``effects`` transition is armed.

    Default-off. Unlike ``PSAT_DIFFERENTIAL_PROBE`` — which now
    defaults *on* — this stays off until the worker is deployed and the
    preview cycle validates it; enabling it without an effects worker running
    parks every job."""
    return os.getenv("PSAT_EFFECTS_STAGE", "0").strip().lower() in _TRUTHY


# Effect classes (v1). Behavioral labels — never name-derived. The string
# values are the ``effect_class`` cache-key component.
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

# Cache scope discriminator: function-local kernels transfer on the
# resolved-function hash; contract-scoped projections additionally key on the
# whole-contract surface hash.
SCOPE_KERNEL = "kernel"
SCOPE_PROJECTION = "projection"

# Destination-shape vocabulary for the value-out class. Only ``immutable_fixed``
# is benign; only static can positively PROVE the two fixed shapes (universals,
# argued from the source); simulation can only PROVE ``caller_arbitrary`` (an
# existential, via a sentinel that lands). Shared vocabulary because both planes speak it: the
# synthesizer derives a shape from static facts and the recipe checks it
# against what the fork observed.
SHAPE_CALLER_ARBITRARY = "caller_arbitrary"
SHAPE_STORAGE_DETERMINED = "storage_determined"
SHAPE_IMMUTABLE_FIXED = "immutable_fixed"
SHAPE_UNKNOWN = "unknown"

# ``details["observation"]`` — the DISCRIMINATOR every verdict row carries. It is
# not decoration: ``effect_verdicts.witness`` is written for ``unknown`` rows too
# (``workers.effects_worker._write_verdicts``), so a payload like
# ``{"value_moved": false}`` sits on disk with no self-contained way to tell a
# call that RAN and moved nothing from one that never got past its own
# precondition.
#
# CONTRACT for any consumer of ``witness`` (scorer included), stated the way
# ``claims_bridge._observed_summary`` states its own:
#   * ``executed`` — the probe call SUCCEEDED. Every other key in the payload is
#     then a statement about F.
#   * ``reverted`` — the probe call REVERTED. The other keys describe a call that
#     never happened; ``value_moved: false`` here means "not measured", NEVER
#     "F moves no value". The verdict on such a row is always ``unknown``.
#   * ``not_run`` — no probe call was issued at all (capability fallback,
#     malformed response, insufficient inputs). Nothing was measured.
# An ABSENT key means the row predates this discriminator; treat it as unmeasured
# unless ``verdict == proven``.
#
# It lives HERE, in the shared vocabulary, because it binds every module that
# emits a verdict — ``recipes`` and the fork-tier ``anvil`` pause recipe alike.
# While it sat in ``recipes`` the pause paths quietly published no discriminator
# at all, and a pause probe that REVERTED went to disk carrying
# ``{"pause_effective": false, "observed_blast_radius": []}`` — indistinguishable,
# to anything reading the documented contract, from a pause that froze nothing.
OBSERVATION_EXECUTED = "executed"
OBSERVATION_REVERTED = "reverted"
OBSERVATION_NOT_RUN = "not_run"

# ``details["duration_bound_source"]`` — how a freeze latch's window was
# established. Here in the shared vocabulary for the same reason
# ``observation`` is: the static reader (``calldata.read_max_pause_duration``)
# produces it and the fork recipe (``anvil.pause_recipe``) publishes it, and while
# the answer was a bare ``int | None`` the two states ``None`` conflates were
# published as one — with the SEVERE one asserted by default.
#
# CONTRACT for any consumer of ``duration_bound_seconds`` (scorer, inspector):
#   * ``guard_constant`` — a mandatory guard leaf compares the clock against a
#     constant offset of THIS latch. ``duration_bound_seconds`` is that window;
#     trust it as a severity REDUCER only together with ``auto_expiry is True``
#     (the fork warped past it and the frozen entry points came back).
#   * ``no_time_reference`` — PROVEN indefinite: the latch IS read by a lowered
#     guard, NO leaf anywhere in that guard tree touches a clock, and no operand
#     anywhere in that tree stands for something the builder never read — the
#     operand lists are known-complete (``calldata._absorption_recorded``) and no
#     operand is an undecomposed expression or an unentered callee
#     (``calldata._OPAQUE_OPERAND_SOURCES``). Only then does no passage of time lift
#     the freeze. ``duration_bound_seconds`` is ``None`` and that ``None`` is a fact
#     about the contract. This is the most severe freeze there is, so the extra
#     conditions are not pedantry — each corresponds to a false proof reproduced
#     from compiled Solidity, all three on freezes that demonstrably expire:
#     ``require(!frozen || block.timestamp > unpauseAt)`` (Solidity lowers ``||``
#     into sibling leaves, so no single leaf holds both facts); any pre-widening tree
#     of ``require(block.timestamp - pausedUntil < 2592000)`` (a two-slot operand
#     list dropped the clock); and ``require(!frozen || _clock() > unpauseAt)``,
#     where the clock is read through an internal view helper or a time oracle — the
#     Uniswap-V3 / OZ-Governor idiom — so no ``block_context`` operand exists
#     anywhere in the tree to find.
#   * ``not_determined`` — the window was NOT established: either the guard
#     compares the latch against ``block.timestamp`` with the window held in
#     storage (etherfi ``PausableUntil``: ``$.pauseUntilDuration``), or no lowered
#     leaf reads the latch at all. ``duration_bound_seconds`` is ``None`` and that
#     ``None`` means "unknown". It must NOT be scored as indefinite and must not
#     be scored as bounded — it is a confidence gap.
# An ABSENT key means the row predates the discriminator: those rows were written
# under the earlier contract, which read ``None`` as indefinite, and every one of
# the four proven rows in the local corpus was a ``pauseUntil`` latch that DOES
# expire — so treat an absent source as ``not_determined``, never as indefinite.
DURATION_BOUND_GUARD_CONSTANT = "guard_constant"
DURATION_BOUND_NO_TIME_REFERENCE = "no_time_reference"
DURATION_BOUND_NOT_DETERMINED = "not_determined"

# The pseudo-address ``eth_simulateV1``'s ``traceTransfers`` puts in the ``address``
# (emitter) field of the SYNTHETIC ``Transfer`` log it emits for a NATIVE value move.
# MEASURED against the live node, not assumed: 3 reads at head-10 plus a pinned read
# at block 25619159 all return ``0xeeee…eeee`` for a plain ETH send, and a WETH
# ``deposit()`` control in the same request emits BOTH that log and one whose emitter
# is the token — so the field discriminates assets and this value is a real answer
# rather than a parser artifact.
#
# It exists here because the downstream value-reach measurement is per ASSET: a holding
# is matched against the emitter of the log that moved it, and native ETH has no token
# contract to be the emitter. Without this key a native move matches no holding at all,
# which is precisely why the "just pass ``only_asset``" fix was refuted — it would have
# under-claimed 100%.
NATIVE_ASSET_LOG_EMITTER = "0x" + "ee" * 20

# Verdict vocabulary. ``unknown`` is the fail-closed value used for every
# non-observation and for the fail-forward exhaustion path.
VERDICT_PROVEN = "proven"
VERDICT_UNKNOWN = "unknown"

# Evidence tiers, cheapest/most-authoritative first.
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

# Provenance of the height an observation was taken at
# (``effect_verdicts.witness.block_source``, beside ``witness.block_number``). The
# value names the SCOPE the pin is shared across, which is the only thing that
# tells a consumer whether two verdicts describe the same world state: the stage
# pins ONE ``eth_blockNumber`` per stage INVOCATION today
# (``effects_worker._preflight``), so verdicts from two invocations of one job can
# sit at different heights (measured: 51 distinct heights spanning 495 blocks in a
# single run, 7 jobs carrying two). ``job_pin`` and ``run_pin`` are the wider
# scopes this vocabulary reserves — nothing emits them, and a per-run pin needs a
# run/batch column ``jobs`` does not have.
#
# Both keys are ABSENT when the height is not proven: an unpinnable head, a fork
# spawned without ``--fork-block-number``, or a Tier-0 index read that has no
# single height. Absence is the not_determined state; ``0`` is the preflight's
# FAILURE sentinel and reads as genesis, so it is never published as a height.
BLOCK_SOURCE_INVOCATION_PIN = "invocation_pin"
BLOCK_SOURCE_JOB_PIN = "job_pin"
BLOCK_SOURCE_RUN_PIN = "run_pin"
BLOCK_SOURCES = (BLOCK_SOURCE_INVOCATION_PIN, BLOCK_SOURCE_JOB_PIN, BLOCK_SOURCE_RUN_PIN)

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
