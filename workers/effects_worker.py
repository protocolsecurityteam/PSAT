"""Effects worker — behavioral effect simulation.

The sixth pipeline stage worker, inserted between ``policy`` and ``coverage``.
It determines what a gated function *does* by observing state transitions on a
fork (idiom-agnostic witnesses), backed by a persistent behavioral-hash cache.

The policy->effects transition is feature-flagged (``PSAT_EFFECTS_STAGE``,
default-off, read in ``PolicyWorker.next_stage``); with the flag off no job ever
enters this stage and the worker simply idles.

**Consumption boundary: labels-observable, scoring-deferred.** Verdicts persist
to ``effect_behavior_cache`` / ``effect_verdicts`` and static-vs-witness
discrepancies to the warning channel (``record_degraded``). Beyond that,
*proven* verdicts are minted into registry claims on the matching
``effective_functions`` rows through ``services.effects.claims_bridge`` (after
``verdict_write``), so the frontend renders them as labels through the one
shared claims vocabulary. The **score** still does not consume verdicts — that
integration is deliberately unwired; the frontend score path neutralises the
``behavioral_observed`` tier so it stays byte-identical.

Orchestration lives here; the per-candidate probe wiring is a ``Prober`` seam
(``services.effects.orchestrator``) and every wire (simulate / call-batch / anvil
/ transcript store / capability store / behavioral-hash resolver) is injectable,
so the offline suite drives the whole stage against stubs with recorded
transcripts and the **zero-candidate path touches no wire at all**.

Inherited from ``BaseWorker`` (never reimplemented): lease claim, stale reclaim,
background heartbeat, SIGTERM release, the ``[BOOT]`` banner, ``StageErrors``,
and per-worker concurrency via ``PSAT_EFFECTS_JOB_CONCURRENCY`` (default 1,
single-flight because anvil snapshot/revert is process-global). This file
overrides ``process()`` and the fail-forward finalizer only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from db.effect_cache import (
    AUDIT_FAILED,
    bump_hit,
    code_plane_details,
    deployment_plane_details,
    find_cached_verdict,
    find_cached_verdicts_batch,
    find_verdict_residue_batch,
    kernel_signature_is_comparable,
    kernel_verdicts_agree,
    mark_audited,
    record_effect_verdict,
    upsert_cached_verdict,
)
from db.models import EffectBehaviorCache, EffectiveFunction, EffectVerdict, Job, JobStage
from db.queue import advance_job, store_artifact
from services.effects import claims_bridge
from services.effects.config import (
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
    SHAPE_CALLER_ARBITRARY,
    TIER_CALL,
    TIER_HISTORICAL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.discrepancies import authority_contradiction, file_new_idiom_candidate, route_discrepancy
from services.effects.exceptions import AnvilRssUnmeasured, BehaviorHashUnavailable
from services.effects.harness import Discrepancy, ObservedEffect
from services.effects.orchestrator import (
    HashResolver,
    ProbeContext,
    Prober,
    default_prober,
    make_bytecode_hash_resolver,
)
from services.effects.prefetch import clear_prefetch, install_prefetch
from services.effects.preflight import CapabilityStore, InMemoryCapabilityStore, probe_simulate_support
from services.effects.seeding import SimulateSeeder, input_seeding_enabled
from services.effects.seeding import budget_of as seeding_budget_of
from services.effects.selection import Candidate, JobScope, record_empty_planning, select_candidates
from utils.chains import UnknownChainError, chain_by_id
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker

logger = logging.getLogger("workers.effects_worker")

_PHASES_AFTER_SELECTION = ("preflight", "cache_lookup", "tier1_probes", "tier2_fork", "verdict_write")

# ``unknown`` reasons that are genuine CODE-PLANE non-observations — safe to
# transfer on the behavioral hash (a re-run/twin sees the same structural
# result). Every OTHER unknown (capability fallback, precondition/mint revert,
# malformed response) is chain-/state-/transient-dependent and must NEVER enter
# the code-plane cache — those re-probe instead of transferring.
#
# Membership turns on ONE question: did the probe call EXECUTE? Every reason
# below is recorded only on a row whose ``details["observation"] == "executed"``
# (``services.effects.recipes``) — the call ran and the transition simply was not
# there, which a bytecode twin genuinely inherits. The reverted counterparts
# (``value_probe_reverted``, ``upgrade_probe_reverted``, ``mint_call_reverted``,
# ``mutation_call_reverted``) are deliberately ABSENT: a revert on a precondition
# or on an argument the prober guessed says nothing structural, and caching one
# published a guessed-argument failure as a fact about every twin.
_CACHEABLE_UNKNOWN_REASONS = frozenset(
    {
        "no_value_observed",
        "no_supply_delta",
        "impl_slot_unchanged",
        "no_authorization_delta_observed",
        "no_blast_radius_observed",
        "bare_sentinel_proves_nothing",
    }
)


def _is_cacheable(eff: ObservedEffect) -> bool:
    """Whether a verdict may transfer on the behavioral hash. Proven verdicts
    that are code-plane structural transfer; unknowns only when the
    non-observation is code-plane structural.

    Tier-0 (historical) verdicts NEVER transfer, even when proven: their truth
    depends on per-deployment state (the indexed upgrade *and* the current-state
    check), so they are state-plane and live only in ``effect_verdicts`` — a
    state-determined verdict is never cached. Caching one would let a present-tense
    "upgradeable now" mint for a bytecode twin whose own current-state check was
    never run — EIP-1967 proxies of the same type share runtime bytecode, so the
    kernel hash collides across many real twins."""
    if eff.tier == TIER_HISTORICAL:
        return False
    if eff.state_dependent:
        # The verdict depended on state THIS probe manufactured on the fork (a
        # timelock's scheduled operation landing, time advancing past its delay),
        # so it is state-plane exactly as a Tier-0 historical verdict is — not a
        # code-plane structural fact a twin inherits. Refused whatever the reason
        # or verdict: a proven ``value_moved`` from a schedule→warp→execute is as
        # untransferable as its reverts.
        return False
    if eff.verdict == VERDICT_PROVEN:
        return True
    return eff.reason in _CACHEABLE_UNKNOWN_REASONS


# Post-Cancun default per chain for the Tier-1 SimContext hardfork stamp. The
# Tier-2 pause recipe asserts post-Cancun against the live fork separately;
# this is only the recorded value for eth_call/eth_simulateV1 probes.
_CHAIN_HARDFORK = {1: "prague", 8453: "prague"}


def _fork_enabled() -> bool:
    """Tier-2 fork kill switch. Default ON in production — the stage itself is
    already behind ``PSAT_EFFECTS_STAGE`` (default off), so this exists to disable
    forking alone (a host without foundry, an incident) without losing Tier 0/1."""
    return os.getenv("PSAT_EFFECTS_FORK", "1").strip().lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------
# State-plane residue re-observation on a cache HIT
# --------------------------------------------------------------------------
# A cache hit resolves the code-plane question and carries NO concrete values, so
# ``_resolve_item`` returns ``concrete=None`` on both hit paths.
# That is right for the CACHE, but it leaves a hole in ``effect_verdicts``: a
# deployment whose FIRST write is a hit — the second deployment of a behavior
# some other contract already cached — gets NULL residue and, because a later
# hit carries none either, never acquires any. In a protocol built from repeated
# deployment patterns that blank is permanent.
#
# The fix re-runs the plan for its ``concrete`` ONLY. The verdict, tier, details
# and transcript still come from the cache — the cache remains the code-plane
# answer and nothing observed here is ever written back to it.
#
# Scoping is what makes this affordable. Re-observing every hit would delete the
# cache's purpose (61% hit rate on the last live run), so an observation runs
# only when ALL of these hold:
#   * the class has residue this schema can store — ``value_out``'s destination
#     is the only such column reachable from a cache hit;
#     ``authority_change``/``supply``/``freeze_pause`` recipes emit no
#     ``concrete`` at all, so there is nothing to go and get, and
#     ``code_upgrade``'s ``current_check_passed`` belongs exclusively to the
#     Tier-0 branch, which ``_is_cacheable`` refuses to cache (so no cache HIT
#     can ever want it — see ``_residue_observable``);
#   * the CACHED verdict is one that can carry residue (below), so a probe that
#     provably cannot produce a value is never issued;
#   * the persisted row for THIS deployment lacks the value AND has not already
#     spent its attempts — one batched read per job answers both for every hit at
#     once. That bound is what makes this once per deployment EVER: without it a
#     behavior that is proven in the cache but unreproducible at THIS deployment
#     (a precondition only the first-sighting contract met) re-probes on every
#     job of every run, forever, always for the same NULL.
#
# Cost: at most ``_RESIDUE_PROBE_MAX_ATTEMPTS`` Tier-1 probes per deployment and
# class, ever. ``freeze_pause`` is excluded on cost as well as content — its
# observation needs the Tier-2 anvil fork, the single most expensive thing the
# stage does.
_RESIDUE_KEY = {
    EFFECT_CLASS_VALUE_OUT: "destination",
}

# ``observed_residue`` key holding how many hit-path observations this deployment
# has already spent on its destination. Bookkeeping, not a published fact — the
# claims bridge projects a fixed whitelist and never sees it.
_RESIDUE_ATTEMPTS_KEY = "destination_probe_attempts"

# Two, not one: a first attempt lost to an RPC flake gets exactly one retry, and
# then the gap is accepted as genuine rather than re-probed for the life of the
# deployment.
_RESIDUE_PROBE_MAX_ATTEMPTS = 2

# How many hash-less candidates get their own ``StageError``. A cold bytecode
# cache can refuse every candidate of a large protocol, and the stage_errors
# artifact is uncapped and rewritten per retry, so the individual records are
# a sample and the exact total rides one summary record (mirrors selection's
# ``_DROPPED_SAMPLE``).
_NO_HASH_SAMPLE = 8

# State-plane residue that has no column of its own and rides ``observed_residue``.
# A strict whitelist: ``concrete`` is what a recipe chose to hand back, and only
# these keys are per-deployment facts this table is meant to publish.
_RESIDUE_JSON_KEYS = (
    "observed_reach_value_usd",
    "observed_reach_holders",
    "reach_indeterminate",
    # The three-state discriminator, and the floor under its own name. Both are
    # load-bearing rather than decorative — while the not-measured branch published
    # the acting balance AS ``observed_reach_value_usd``, a consumer reading the
    # number without the flag got "$0 reach" for a zero-balance router that may move
    # millions. Omitting either key here would drop it before it reaches the row.
    "reach_determined",
    "observed_reach_floor_usd",
    # Which ASSETS the reach was measured over, and the (holder, asset) pairs whose
    # USD is not known. Per-deployment observations, so they ride the state plane with
    # the figures they qualify. ``observed_reach_unvalued_pairs`` and
    # ``observed_reach_priced_holders`` are what keep the disclosure and the figure on
    # the same key: dropping either here would restore the row that named one asset as
    # the only thing that moved AND the only thing that could not be valued, beside a
    # concrete USD figure computed from another holder's balance.
    "observed_reach_assets",
    "observed_reach_unvalued_pairs",
    "observed_reach_unvalued_assets",
    "observed_reach_unvalued_reasons",
    "observed_reach_priced_usd",
    "observed_reach_priced_holders",
    # The reach-vs-TVL ceiling's OUTCOME, including "skipped_no_tvl". A check whose
    # result is dropped before the consumer is indistinguishable from no check.
    "reach_tvl_check",
    "observed_reach_rejected_usd",
    "protocol_tvl_usd",
    # Backing COUNTS. The booleans (``inflow_observed``/``minted``) are the
    # code-plane witness and stay on ``details``; how many Transfer logs one
    # execution emitted is an observation of this deployment at this block and
    # would otherwise be republished as every bytecode twin's own count.
    "backing_inflow_transfers",
    "backing_mint_transfers",
    # The call that PROVED the figure — caller, target, selector, raw calldata,
    # pinned height, seeded-or-not. Per-deployment by construction (an
    # impersonated caller at one block), so it rides the state plane with the
    # reach figures it accounts for and never the behavioral cache. Dropping it
    # here would leave the magnitude published with no execution behind it,
    # which is the whole defect it exists to close.
    PROVING_EXECUTION_KEY,
)


def _residue_observable(cached: EffectBehaviorCache, effect_class: str) -> bool:
    """Can a re-probe of this cached behavior actually yield residue?

    ``value_out`` records a destination only on the PROVEN branch (both the
    unknown returns drop ``concrete``), so an unknown hit would burn two
    ``eth_simulateV1`` calls for a guaranteed NULL.

    ``code_upgrade`` is deliberately absent. Its only storable residue
    (``current_check_passed``) comes from the Tier-0 historical branch, and
    ``_is_cacheable`` refuses to cache Tier-0 verdicts at all — so no
    cached row can exist for that branch and the arm that used to test for one
    was unreachable. Its Tier-1 branch yields ``impl_before``/``impl_after``,
    which this schema does not store.

    A ``caller_arbitrary`` destination is excluded for the same reason: the
    recipe now WITHHOLDS the address on that shape — whatever a probe observes there
    is the recipient argument the prober itself supplied — so a re-probe is a
    guaranteed NULL by construction, and the attempt bound would otherwise be spent
    twice per deployment chasing a value this stage refuses to store.
    """
    if effect_class == EFFECT_CLASS_VALUE_OUT:
        if cached.verdict != VERDICT_PROVEN:
            return False
        details = cached.details if isinstance(cached.details, dict) else {}
        return details.get("destination_shape") != SHAPE_CALLER_ARBITRARY
    return False


def _residue_attempts(residue: Any) -> int:
    value = residue.get(_RESIDUE_ATTEMPTS_KEY) if isinstance(residue, dict) else None
    return value if isinstance(value, int) and value > 0 else 0


def _observed_residue(it: "_Item", concrete: dict[str, Any] | None) -> dict[str, Any] | None:
    """The ``effect_verdicts.observed_residue`` payload for one write.

    Two things live here, both per-deployment: the value-reach figures (holder
    ADDRESSES and this protocol's USD — state-plane, so they must never travel on
    the behavioral cache the way they did while they sat in ``details``), and the
    hit-path re-probe attempt count that bounds ``_mark_residue_gaps``. The column
    is merged key-wise on conflict, so a write carrying only one of them leaves
    the other standing."""
    payload: dict[str, Any] = {}
    if concrete:
        payload.update({k: concrete[k] for k in _RESIDUE_JSON_KEYS if k in concrete})
    if it.residue_probe:
        # Counted whether or not the probe produced anything: an attempt that
        # yielded nothing is exactly the case the bound exists for.
        payload[_RESIDUE_ATTEMPTS_KEY] = it.residue_attempts + 1
    return payload or None


def _residue_only(concrete: dict[str, Any] | None, effect_class: str) -> dict[str, Any] | None:
    """The one residue key this class is allowed to contribute from a hit.

    A whitelist rather than the raw ``concrete`` dict: the observation exists to
    fill a specific blank, and must not become a side channel for anything else a
    recipe happens to put there."""
    key = _RESIDUE_KEY.get(effect_class)
    if not concrete or key is None:
        return None
    value = concrete.get(key)
    return {key: value} if value is not None else None


def _details_with_fresh_deployment_plane(
    cached_details: dict[str, Any] | None, fresh: ObservedEffect
) -> dict[str, Any] | None:
    """The details an AUDITED hit persists as this deployment's witness: the
    cache's code-plane facts with the fresh re-simulation's own deployment-plane
    keys re-attached.

    The cache stripped those keys at the write (they are one deployment's fork
    observations), so serving ``cached.details`` verbatim rewrote the producing
    verdict's witness WITHOUT its seeding qualifiers / blast-radius set — and
    their absence is itself a contract ("no seeding was needed"), so the rewrite
    published a stronger claim than the observation (the realized case: a proven
    ``supply_burn`` whose own transcript records ``input_seeded: true`` and the
    unseeded probe reverting). The audit just re-ran the full recipe against
    THIS deployment, so its payload's deployment-plane keys are the current
    measurement — including their honest absence when nothing was seeded.
    ``code_plane_details`` on the cached side launders any same-version row
    minted before a key joined ``DEPLOYMENT_PLANE_KEYS``."""
    merged = dict(code_plane_details(cached_details) or {})
    merged.update(deployment_plane_details(fresh.witness_payload))
    return merged or None


def _residue_probe_enabled() -> bool:
    """Kill-valve for the hit-path residue re-observation. Default ON; turning it
    off restores the previous behavior exactly (hits write NULL residue and the
    upsert's preservation guard keeps whatever is already stored)."""
    return os.getenv("PSAT_EFFECTS_RESIDUE_PROBE", "1").strip().lower() in ("1", "true", "yes", "on")


def _batch_plan_enabled() -> bool:
    """Batch the ``cache_lookup`` phase's per-candidate DB round-trips (bulk
    prefetch + one composite verdict lookup) instead of the serial N+1. Default
    ON; the switch exists as a kill-valve and as the A/B seam the parity test
    drives to prove the two paths return byte-identical verdicts."""
    return os.getenv("PSAT_EFFECTS_BATCH_PLAN", "1").strip().lower() in ("1", "true", "yes", "on")


def _anvil_port() -> int:
    try:
        return int(os.getenv("PSAT_EFFECTS_ANVIL_PORT", "8546"))
    except ValueError:
        return 8546


def _resource_cap() -> int | None:
    """Hard safety-valve only — value orders candidates, it never gates them.
    Unset ⇒ no cap; every distinct behavior is simulated. When set and exceeded,
    ``select_candidates`` logs exactly what it dropped."""
    raw = os.getenv("PSAT_EFFECTS_RESOURCE_CAP")
    if not raw:
        return None
    try:
        return max(0, int(raw))
    except ValueError:
        return None


@dataclass
class _Seams:
    """The stage's real I/O bundle, built from ``job.request`` exactly like
    ``policy_worker`` is RPC-bound. Injectable so offline tests supply stubs; the
    real defaults are constructed lazily and ONLY when candidates exist."""

    simulate: Any
    transcript_store: Any
    capability_store: CapabilityStore
    chain_id: int
    call_batch: Any = None
    anvil_factory: Any = None
    # ``() -> int | None`` — the chain head, pinned once at preflight so every
    # Tier-1 probe simulates at the same real block. ``None`` (tests) ⇒ no wire.
    block_number: Any = None


@dataclass
class _Item:
    """One (candidate, plan) unit tracked across the cache_lookup → probe →
    verdict_write phases."""

    candidate: Candidate
    effect_class: str
    scope: str
    gate_ref: str
    behavior_hash: str
    surface_hash: str
    run: Any
    cached: EffectBehaviorCache | None
    needs_audit: bool
    probed: ObservedEffect | None = None
    # A cache HIT whose persisted verdict row has no state-plane residue yet:
    # run the plan for its ``concrete`` alone (see ``_RESIDUE_KEY``). Never set
    # on a miss or an audit — both already probe.
    residue_probe: bool = False
    # Hit-path observations this deployment has already spent on that gap, read
    # from the stored row so the re-probe is bounded across jobs and runs.
    residue_attempts: int = 0


@dataclass
class _Counters:
    candidates_in: int = 0
    cache_hits_kernel: int = 0
    cache_hits_projection: int = 0
    cache_misses: int = 0
    verdicts_written: int = 0
    discrepancies_filed: int = 0
    new_idiom_candidates: int = 0
    upstream_requests: int = 0
    # ``None`` until a sample succeeds: a fork that was never measured must not
    # publish ``0`` MB, which reads as a measured "used no memory".
    peak_anvil_rss_mb: int | None = None
    # CANDIDATE units: candidates that never reached the worklist (hash refused,
    # prober raised). Not part of the item identity below — one candidate can
    # yield many plans, or none.
    skipped: int = 0
    # ITEM units, and the accounting is exact in those units:
    #   items == cache_hits_kernel + cache_hits_projection + cache_misses
    #            + probes_failed + withheld
    # ``probes_failed`` is a cache-missing item whose probe produced nothing
    # (fail-closed ``unknown``, deliberately not cached); ``withheld`` is a hit
    # refused by the self-audit / collision guard, which is neither served nor
    # re-counted as a miss.
    probes_failed: int = 0
    withheld: int = 0
    residue_observations: int = 0
    contracts_planned_empty: int = 0
    # The pre-candidate funnel from ``select_candidates`` (bare rows_in,
    # skipped_already_explained, cap_dropped, selected keys);
    # ``selection_fields()`` adds the ``selection_`` prefix every sink
    # publishes it under.
    selection_funnel: dict[str, Any] = field(default_factory=dict)
    # Input-asset seeding spend/yield for the job (see ``SeedBudget.metrics``).
    seed_metrics: dict[str, int] = field(default_factory=dict)

    def selection_fields(self) -> dict[str, Any]:
        """The funnel under the one key spelling every sink publishes it with —
        the phase span, the stage metrics, and the completion summary."""
        return {f"selection_{name}": value for name, value in self.selection_funnel.items()}


class EffectsWorker(BaseWorker):
    stage = JobStage.effects
    next_stage = JobStage.coverage

    def __init__(
        self,
        *,
        prober: Prober | None = None,
        hash_resolver: HashResolver | None = None,
        seams: _Seams | None = None,
        capability_store: CapabilityStore | None = None,
    ) -> None:
        super().__init__()
        # Injection seams (tests set these; production uses the lazy real defaults).
        self.prober: Prober = prober or default_prober
        self._injected_hash_resolver = hash_resolver
        self._injected_seams = seams
        self._capability_store: CapabilityStore = capability_store or InMemoryCapabilityStore()
        # Single-flight fork state: one anvil per job, memoized on first
        # Tier-2 plan and closed in ``process()``'s finally.
        self._anvil: Any = None
        self._anvil_error: Exception | None = None
        # The preflight height the job's fork is spawned at. Set in
        # ``_probe_context`` rather than ``_make_seams`` because the factory is
        # BUILT before the head is pinned and only CALLED after — and cleared with
        # the fork, so one job's pin can never spawn the next job's.
        self._fork_block_pin: int | None = None
        # Per-job input-asset seeder, rebuilt in ``_probe_context`` so its budget
        # counters start at zero for every job.
        self._seeder: SimulateSeeder | None = None
        # One RSS-sample failure line per job, reset with the fork.
        self._rss_sample_failed = False

    # -- seam construction (lazy; real I/O only here) ----------------------

    def _make_seams(self, session: Session, job: Job) -> _Seams:
        """Build the real I/O bundle from ``job.request``. Only reached when the
        candidate set is non-empty, so a zero-candidate job never constructs a
        wire seam. Tests inject ``seams=`` to bypass this entirely."""
        if self._injected_seams is not None:
            return self._injected_seams

        from services.effects.simulate import eth_simulate_v1
        from utils.rpc import eth_call_batch, require_rpc_url

        chain_id = _chain_id_for_job(job)
        request = job.request if isinstance(job.request, dict) else {}
        explicit = request.get("rpc_url")
        rpc_url = require_rpc_url(
            explicit_rpc_url=explicit if isinstance(explicit, str) else None,
            chain_id=chain_id,
            context=f"effects rpc for job {job.id}",
        )

        def simulate(calls, block_tag, overrides):
            return eth_simulate_v1(rpc_url, calls, block_tag, overrides, chain_id=chain_id)

        def call_batch(calls, block_tag="latest"):
            return eth_call_batch(rpc_url, calls, block_tag, chain_id=chain_id)

        def block_number() -> int | None:
            from utils.rpc import rpc_request

            result = rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)
            if isinstance(result, str):
                return int(result, 16)
            return int(result) if isinstance(result, int) else None

        return _Seams(
            simulate=simulate,
            transcript_store=self._make_transcript_store(session, job),
            capability_store=self._capability_store,
            chain_id=chain_id,
            call_batch=call_batch,
            anvil_factory=self._anvil_factory(chain_id, rpc_url),
            block_number=block_number,
        )

    def _anvil_factory(self, chain_id: int, rpc_url: str):
        """Single-flight forking-anvil factory: ONE fork per job per
        chain, created lazily on the first Tier-2 plan and memoized. Returns
        ``None`` when the fork is disabled, which makes the pause class emit no
        plan at all.

        Never reached from the offline suite — tests inject ``seams=``, and
        ``PSAT_EFFECTS_FORK`` is a belt-and-braces kill switch on top of that (the
        stage's own ``PSAT_EFFECTS_STAGE`` flag already gates every job out).

        A spawn failure is memoized and re-raised per plan: ``_probe_one`` catches
        it, records degraded, and the behavior lands ``unknown``
        (``AnvilSpawnError`` is a transient kind in ``retry_policy``), so a fork
        that will not start degrades the stage instead of crashing it."""
        if not _fork_enabled():
            return None
        from services.effects.anvil import SubprocessAnvil
        from services.effects.exceptions import AnvilSpawnError
        from utils.rpc import rpc_headers

        hardfork = _CHAIN_HARDFORK.get(chain_id, "prague")
        port = _anvil_port()

        def factory():
            if self._anvil_error is not None:
                raise self._anvil_error
            if self._anvil is not None:
                return self._anvil
            try:
                # rpc_headers is the single source of truth for eRPC auth — a local
                # or explicit fork URL correctly gets no secret.
                self._anvil = SubprocessAnvil(
                    port=port,
                    hardfork_name=hardfork,
                    fork_url=rpc_url,
                    fork_headers=rpc_headers(rpc_url),
                    # Pin the fork to the SAME height Tier 1 simulated at.
                    # Unpinned, anvil forks at the upstream's head at spawn — a
                    # height nothing records, so a Tier-2 witness could not say
                    # what state it observed and could not be replayed.
                    fork_block_number=self._fork_block_pin,
                )
            except Exception as exc:
                self._anvil_error = exc if isinstance(exc, AnvilSpawnError) else AnvilSpawnError(str(exc))
                raise self._anvil_error from exc
            # ``fork_block`` is read back off the spawned fork, not off the pin
            # asked for: a rejected pin leaves it None, and that is the height the
            # Tier-2 witnesses will publish.
            fork_block = self._anvil.fork_block_number()
            logger.info(
                "effects fork ready: chain_id=%s hardfork=%s fork_block=%s port=%s",
                chain_id,
                hardfork,
                fork_block,
                port,
                extra={"chain_id": chain_id, "hardfork": hardfork, "fork_block": fork_block, "port": port},
            )
            return self._anvil

        return factory

    def _close_anvil(self) -> None:
        """Always run — an anvil subprocess outliving the job would hold the port
        and the fork's memory for every subsequent job."""
        anvil = self._anvil
        self._anvil = None
        self._anvil_error = None
        self._fork_block_pin = None
        self._rss_sample_failed = False
        if anvil is None:
            return
        try:
            anvil.close()
        except Exception:
            logger.warning("effects fork close failed", exc_info=True)

    def _make_transcript_store(self, session: Session, job: Job):
        """Persist each transcript as a job artifact and return a stable,
        backend-agnostic pointer resolvable via ``get_artifact(job_id, name)``.
        The pointer is the cache/verdict ``transcript_ptr`` — never an inline blob."""

        def store(transcript: dict[str, Any]) -> str:
            name = _transcript_artifact_name(transcript)
            store_artifact(session, job.id, name, data=transcript)
            return f"{job.id}::{name}"

        return store

    def _hash_resolver(self, chain_id: int) -> HashResolver:
        return self._injected_hash_resolver or make_bytecode_hash_resolver(chain_id)

    # -- main entry --------------------------------------------------------

    def process(self, session: Session, job: Job) -> None:
        try:
            self._process(session, job)
        finally:
            # Never leak a fork subprocess, on any exit path.
            self._close_anvil()

    def _process(self, session: Session, job: Job) -> None:
        logger.info(
            "Effects stage started for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )
        durations_ms: dict[str, int] = {}
        counters = _Counters()

        # Selection FIRST (before any wire): a zero-candidate job must touch no RPC.
        with log_timed_phase(logger, "selection", durations_ms=durations_ms) as ph:
            candidates = self._select(session, job, funnel=counters.selection_funnel)
            # ``selection_selected`` IS the candidate count — no second spelling.
            ph.update(counters.selection_fields())
        counters.candidates_in = len(candidates)

        if not candidates:
            # Inert, wire-free: emit the remaining phase spans for a complete
            # timeline and write zero metrics. No seam is ever constructed.
            for phase in _PHASES_AFTER_SELECTION:
                with log_timed_phase(logger, phase, durations_ms=durations_ms):
                    pass
            # A zero-candidate job still owns contracts whose claims the policy
            # stage wrote. Skipping distillation here would leave every such
            # contract absent from the fold's population — an omission the
            # score would read as "this contract has no capabilities".
            self._distill_score_signals(session, job)
            self._record_metrics(counters)
            logger.info(
                "Effects stage complete for job %s: 0 candidates (no-op)",
                job.id,
                extra={"durations_ms": durations_ms, **counters.selection_fields()},
            )
            return

        seams = self._make_seams(session, job)
        hash_resolver = self._hash_resolver(seams.chain_id)
        supported, block = self._preflight(seams, durations_ms)
        ctx = self._probe_context(seams, supported, block, counters)

        # cache_lookup → build the worklist, partition hits/misses/audits.
        with log_timed_phase(logger, "cache_lookup", durations_ms=durations_ms) as ph:
            items = self._plan(session, candidates, ctx, hash_resolver, counters, job=job)
            ph["planned"] = len(items)

        # tier1_probes / tier2_fork → run recipes for misses + audit re-runs.
        self._run_probes(items, durations_ms, counters, seams)

        # verdict_write → cache + state-plane persistence + discrepancy routing,
        # then mint proven verdicts into registry claims on the matching
        # effective_functions rows — same job, same rows, same phase span so the
        # /monitor timeline gains no new stage.
        with log_timed_phase(logger, "verdict_write", durations_ms=durations_ms) as ph:
            self._write_verdicts(session, job, items, seams, counters)
            ph["verdicts_written"] = counters.verdicts_written
            ph["labeled"] = self._bridge_claims(session, items)

        # Layer-1 distillation, after the bridge so it reads the
        # ``behavioral_observed`` claims this job just merged. Deliberately
        # outside the phase span: it writes no verdict and adds no stage to the
        # /monitor timeline.
        self._distill_score_signals(session, job)

        self._record_seed_metrics(counters)
        self._record_metrics(counters)
        logger.info(
            "Effects stage complete for job %s: %d candidates (%d skipped), %d verdicts, "
            "%d hits (%dk/%dp), %d misses, %d failed probes, %d withheld, "
            "%d discrepancies, %d new-idiom candidates",
            job.id,
            len(candidates),
            counters.skipped,
            counters.verdicts_written,
            counters.cache_hits_kernel + counters.cache_hits_projection,
            counters.cache_hits_kernel,
            counters.cache_hits_projection,
            counters.cache_misses,
            counters.probes_failed,
            counters.withheld,
            counters.discrepancies_filed,
            counters.new_idiom_candidates,
            extra={
                "durations_ms": durations_ms,
                "skipped": counters.skipped,
                "probes_failed": counters.probes_failed,
                "withheld": counters.withheld,
                **counters.selection_fields(),
            },
        )

    # -- phase helpers -----------------------------------------------------

    def _select(self, session: Session, job: Job, *, funnel: dict[str, Any] | None = None) -> list[Candidate]:
        protocol_id = getattr(job, "protocol_id", None)
        if not isinstance(protocol_id, int):
            # A contract job with no protocol has nothing to simulate against the
            # value cascade (it needs the protocol's balances/control graph). Not an
            # error — just an empty candidate set. The funnel still reports a
            # defined state: "no rows, because selection never ran" is a different
            # fact from "the cascade returned nothing", and an absent funnel would
            # leave the consumer unable to tell them apart.
            if funnel is not None:
                funnel.update(
                    {
                        "rows_in": 0,
                        "skipped_already_explained": 0,
                        "cap_dropped": 0,
                        "selected": 0,
                        "not_run_reason": "job_has_no_protocol",
                    }
                )
            return []
        address = getattr(job, "address", None)
        scope = (
            JobScope(
                address=address,
                chain_id=_chain_id_for_job(job),
                # Only an empty-planning marker at least as new as this job counts
                # as ownership — see ``_scope_predicate`` rule 4.
                planned_since=getattr(job, "created_at", None),
            )
            if isinstance(address, str) and address.strip()
            else None
        )
        # No address ⇒ a company/root job, which owns no contract of its own; it
        # falls back to protocol-wide selection so such a job still covers the
        # protocol rather than planning nothing.
        return select_candidates(session, protocol_id, resource_cap=_resource_cap(), scope=scope, funnel=funnel)

    def _preflight(self, seams: _Seams, durations_ms: dict[str, int]) -> tuple[bool, int]:
        """Capability probe + the ONE ``eth_blockNumber`` that pins every Tier-1
        simulation to the same real block. Without a pinned block a recipe would
        simulate at genesis, so an unpinnable head disables Tier 1 (the classes
        then declare their Tier-2 fallback) rather than probing a wrong state."""
        with log_timed_phase(logger, "preflight", durations_ms=durations_ms) as ph:
            try:
                supported = probe_simulate_support(seams.simulate, seams.chain_id, seams.capability_store)
            except Exception as exc:
                # A preflight flake is fail-closed: assume unsupported (route to
                # the declared Tier-2 fallback), degraded but never crashing the
                # stage over a capability probe.
                record_degraded(phase="effects_preflight", exc=exc, context={"chain_id": seams.chain_id})
                supported = False
            block = 0
            if seams.block_number is not None:
                try:
                    head = seams.block_number()
                    block = int(head) if isinstance(head, int) and head > 0 else 0
                except Exception as exc:
                    record_degraded(phase="effects_block_pin", exc=exc, context={"chain_id": seams.chain_id})
                if supported and block <= 0:
                    # The seam exists and could not pin a head: Tier 1 is off
                    # rather than simulating at genesis. (No seam at all is a
                    # test/stub bundle — nothing block-tagged is issued there.)
                    record_degraded(
                        phase="effects_block_pin",
                        exc=RuntimeError("no pinned block for Tier-1 simulation"),
                        context={"chain_id": seams.chain_id},
                    )
                    supported = False
            ph["simulate_supported"] = supported
            ph["block"] = block
        return supported, block

    def _probe_context(self, seams: _Seams, supported: bool, block: int, counters: _Counters) -> ProbeContext:
        try:
            hardfork = _CHAIN_HARDFORK.get(seams.chain_id) or chain_by_id(seams.chain_id).name
        except UnknownChainError:
            hardfork = "prague"

        def on_requests(n: int) -> None:
            counters.upstream_requests += max(0, n)

        # The input-asset seeder is built HERE rather than lazily inside
        # ``ProbeContext`` so the job owns its cost ceiling and can report what it
        # spent: the seeded retry runs on the common (reverted) path, and without
        # a budget its discovery blocks scale with the protocol's distinct
        # vaults/tokens. Same construction conditions the lazy path used, so an
        # unsupported simulate or the kill-valve still means no seeder at all.
        self._seeder = None
        if supported and input_seeding_enabled():
            self._seeder = SimulateSeeder(seams.simulate, chain_id=seams.chain_id)

        # A non-positive block is the preflight's failure sentinel (it would fork
        # at genesis), so the fork is left unpinned and publishes no height.
        self._fork_block_pin = block if block > 0 else None

        return ProbeContext(
            chain_id=seams.chain_id,
            block=block,
            hardfork=hardfork,
            simulate=seams.simulate,
            simulate_supported=supported,
            transcript_store=seams.transcript_store,
            call_batch=seams.call_batch,
            anvil_factory=seams.anvil_factory,
            on_requests=on_requests,
            seeder=self._seeder,
        )

    def _record_seed_metrics(self, counters: _Counters) -> None:
        """Fold the job's seeding spend into the stage metrics + one log line.

        Without this the retry path is invisible: the next live run could measure
        that effects got slower but not whether seeding was why, nor whether the
        spend bought any verdict."""
        seeder = getattr(self, "_seeder", None)
        budget = seeding_budget_of(seeder) if seeder is not None else None
        if budget is None:
            return
        counters.seed_metrics = budget.metrics()
        if budget.exhausted_any:
            logger.warning("effects input seeding hit its per-job budget: %s", budget.summary())
        elif budget.probe_retries:
            logger.info("effects input seeding: %s", budget.summary())

    def _plan(
        self,
        session: Session,
        candidates: list[Candidate],
        ctx: ProbeContext,
        hash_resolver: HashResolver,
        counters: _Counters,
        *,
        job: Job | None = None,
    ) -> list[_Item]:
        # Bulk-load every per-candidate keyed row up front (bytecode, proxy
        # Contract/UpgradeEvent, pause claim + principal maps) so the deep
        # DB-fetch helpers read a dict instead of issuing a serial round-trip.
        # The flag off falls the helpers back to their single-row queries (the
        # A/B seam the parity test drives).
        batched = _batch_plan_enabled()
        if batched:
            install_prefetch(session, ctx.chain_id, candidates)
        try:
            # Pass 1: resolve hashes + build plans, staging each plan's cache
            # identity. No verdict lookups yet — those are batched below.
            staged: list[tuple[Candidate, Any, str, str]] = []
            # Per-contract planning outcome, for the empty-planning marker. A
            # contract only qualifies when EVERY candidate of its was planned
            # cleanly: a missing hash or a raising prober is transient, and
            # marking it would suppress the retry rather than record a fact.
            planned_per_contract: dict[int, int] = {}
            unclean_contracts: set[int] = set()
            contracts_with_plans: set[int] = set()
            # Function ids of every candidate refused for want of a behavioral
            # hash; the per-candidate degraded records below are capped, this is
            # the exact count behind the one summary record.
            no_hash_candidates: list[int] = []
            for cand in candidates:
                try:
                    resolved = hash_resolver(session, cand)
                except Exception as exc:
                    record_degraded(phase="effects_hash", exc=exc, context={"function_id": cand.function_id})
                    counters.skipped += 1
                    unclean_contracts.add(cand.contract_id)
                    continue
                if resolved is None:
                    # No behavioral hash (no cached bytecode, or a proxy row whose
                    # implementation is unresolved) — withhold rather than guess
                    # (per-behavior fail-forward). Recorded like its two raising
                    # siblings: the candidate silently vanishing from the worklist
                    # is what makes a bytecode-cache outage read as "nothing to do".
                    context = {
                        "function_id": cand.function_id,
                        "contract_id": cand.contract_id,
                        "contract_address": cand.contract_address,
                    }
                    # Bounded: a cold bytecode cache would otherwise write one
                    # StageError per candidate into an artifact with no cap, which
                    # ``base._persist_stage_errors`` rewrites on every retry. The
                    # first few name concrete rows; the exact total is published
                    # below (and as the ``skipped`` metric).
                    if len(no_hash_candidates) < _NO_HASH_SAMPLE:
                        record_degraded(
                            phase="effects_hash",
                            exc=BehaviorHashUnavailable(
                                f"no behavioral hash for function {cand.function_id} on {cand.contract_address}"
                            ),
                            context=context,
                        )
                    no_hash_candidates.append(cand.function_id)
                    # DEBUG per candidate (a cold bytecode cache would flood the
                    # log at WARNING); the job-level total rides the summary INFO
                    # as ``skipped`` and the stage metric of the same name.
                    logger.debug("effects: candidate skipped, no behavioral hash resolved", extra=context)
                    counters.skipped += 1
                    unclean_contracts.add(cand.contract_id)
                    continue
                kernel_hash, surface_hash = resolved
                try:
                    plans = self.prober(session, cand, ctx)
                except Exception as exc:
                    record_degraded(phase="effects_plan", exc=exc, context={"function_id": cand.function_id})
                    counters.skipped += 1
                    unclean_contracts.add(cand.contract_id)
                    continue
                planned_per_contract[cand.contract_id] = planned_per_contract.get(cand.contract_id, 0) + 1
                if plans:
                    contracts_with_plans.add(cand.contract_id)
                for plan in plans:
                    behavior_hash = plan.behavior_hash or kernel_hash
                    surface = surface_hash if plan.scope != SCOPE_KERNEL else ""
                    staged.append((cand, plan, behavior_hash, surface))
            if len(no_hash_candidates) > _NO_HASH_SAMPLE:
                # The exact total, once, so the capped per-candidate records above
                # are never mistaken for the whole shortfall.
                record_degraded(
                    phase="effects_hash",
                    exc=BehaviorHashUnavailable(
                        f"{len(no_hash_candidates)} candidates had no behavioral hash; "
                        f"{_NO_HASH_SAMPLE} recorded individually"
                    ),
                    context={
                        "candidates_without_hash": len(no_hash_candidates),
                        "recorded_individually": _NO_HASH_SAMPLE,
                        "function_ids_sample": no_hash_candidates[:_NO_HASH_SAMPLE],
                    },
                )
            self._mark_empty_planning(
                session, job, planned_per_contract, unclean_contracts, contracts_with_plans, counters
            )

            # Pass 2: one composite verdict lookup for the whole plan set
            # (collapses the per-plan single-row SELECTs), then assemble items.
            if batched:
                verdicts = find_cached_verdicts_batch(
                    session,
                    ((bh, p.effect_class, p.scope, surf, p.gate_ref) for _c, p, bh, surf in staged),
                )
            items: list[_Item] = []
            for cand, plan, behavior_hash, surface in staged:
                if batched:
                    # ``surface`` is already kernel-normalized (== "" for kernel),
                    # matching the batch's stored key.
                    cached = verdicts.get((behavior_hash, plan.effect_class, plan.scope, surface, plan.gate_ref))
                else:
                    cached = find_cached_verdict(
                        session,
                        behavior_hash=behavior_hash,
                        effect_class=plan.effect_class,
                        scope=plan.scope,
                        contract_surface_hash=surface,
                        gate_ref=plan.gate_ref,
                    )
                # First re-encounter of a shared hash (writer left audit_status
                # None) triggers the self-audit re-simulation.
                needs_audit = cached is not None and cached.audit_status is None
                items.append(
                    _Item(
                        candidate=cand,
                        effect_class=plan.effect_class,
                        scope=plan.scope,
                        gate_ref=plan.gate_ref,
                        behavior_hash=behavior_hash,
                        surface_hash=surface,
                        run=plan.run,
                        cached=cached,
                        needs_audit=needs_audit,
                    )
                )
            self._mark_residue_gaps(session, items, ctx.chain_id)
            return items
        finally:
            if batched:
                clear_prefetch(session)

    def _mark_residue_gaps(self, session: Session, items: list[_Item], chain_id: int) -> None:
        """Flag the cache hits whose persisted verdict row still has no residue
        AND has attempts left.

        One batched read for the whole worklist, so the check that makes the
        re-observation cheap does not itself reintroduce an N+1."""
        if not _residue_probe_enabled():
            return
        wanted = [
            it
            for it in items
            if it.cached is not None
            and not it.needs_audit
            and it.effect_class in _RESIDUE_KEY
            and _residue_observable(it.cached, it.effect_class)
        ]
        if not wanted:
            return
        stored = find_verdict_residue_batch(
            session,
            chain_id=chain_id,
            identities=((it.candidate.probe_target, it.candidate.selector or "", it.effect_class) for it in wanted),
        )
        for it in wanted:
            row = stored.get((it.candidate.probe_target.lower(), it.candidate.selector or "", it.effect_class))
            if row is None:
                # No verdict row yet: the first sighting of this deployment.
                it.residue_probe = True
                continue
            destination, _current_check, residue = row
            it.residue_attempts = _residue_attempts(residue)
            it.residue_probe = destination is None and it.residue_attempts < _RESIDUE_PROBE_MAX_ATTEMPTS

    def _mark_empty_planning(
        self,
        session: Session,
        job: Job | None,
        planned_per_contract: dict[int, int],
        unclean_contracts: set[int],
        contracts_with_plans: set[int],
        counters: _Counters,
    ) -> None:
        """Record contracts this pass planned in full and that yielded no plans.

        Without this a swept contract with no job of its own leaves nothing
        behind — no verdict, no ``stage_timing_effects`` artifact — and every
        later job in the protocol sweeps it again.

        Two conditions gate the write, both in the direction of re-planning:
        a contract with ANY unplannable candidate is excluded (transient, must
        retry), and nothing is recorded at all while the Tier-2 fork is disabled,
        because that suppresses the pause plans and would make an artificially
        empty result look like a real one."""
        if job is None or not planned_per_contract or not _fork_enabled():
            return
        empty = {
            cid: n
            for cid, n in planned_per_contract.items()
            if cid not in contracts_with_plans and cid not in unclean_contracts
        }
        if not empty:
            return
        counters.contracts_planned_empty = record_empty_planning(session, job_id=job.id, candidates_by_contract=empty)

    def _run_probes(self, items: list[_Item], durations_ms: dict[str, int], counters: _Counters, seams: _Seams) -> None:
        """Run recipes for cache misses + audit re-runs. Tier-2 (fork/projection)
        and Tier-1 are timed under their own phases. A per-behavior probe failure
        is caught here, recorded degraded, and the loop continues — only
        a whole-stage infra failure escapes ``process()``."""
        tier1 = [it for it in items if it.scope == SCOPE_KERNEL and (it.cached is None or it.needs_audit)]
        tier2 = [it for it in items if it.scope != SCOPE_KERNEL and (it.cached is None or it.needs_audit)]
        # State-plane residue re-observation. Kernel-scope only by construction —
        # every class in ``_RESIDUE_KEY`` is Tier-0/Tier-1, so this can never
        # spawn the Tier-2 fork — and timed under Tier 1 with the probes it
        # resembles rather than as a phase of its own.
        residue = [it for it in items if it.residue_probe and it.scope == SCOPE_KERNEL]

        with log_timed_phase(logger, "tier1_probes", durations_ms=durations_ms) as ph:
            for it in tier1:
                self._probe_one(it, counters)
            for it in residue:
                self._probe_one(it, counters)
            ph["probed"] = len(tier1)
            ph["residue_reobserved"] = len(residue)

        with log_timed_phase(logger, "tier2_fork", durations_ms=durations_ms) as ph:
            for it in tier2:
                self._probe_one(it, counters)
                self._sample_anvil_rss(counters)
            ph["probed"] = len(tier2)
            ph["peak_anvil_rss_measured"] = counters.peak_anvil_rss_mb is not None
            if counters.peak_anvil_rss_mb is not None:
                ph["peak_anvil_rss_mb"] = counters.peak_anvil_rss_mb

    def _sample_anvil_rss(self, counters: _Counters) -> None:
        """Fold the memoized fork's current RSS into the job peak. The fork may be
        absent (fork disabled / never spawned / spawn failed) — guard for that and
        never raise into the probe loop: an RSS sample must not fail a behavior."""
        anvil = getattr(self, "_anvil", None)
        sample = getattr(anvil, "rss_mb", None)
        if sample is None:
            return
        try:
            measured = sample()
        except Exception as exc:
            self._note_rss_unmeasured(reason="sampler_raised", exc=exc)
            return
        # ``None`` is the transport saying it does not KNOW (fork exited, /proc
        # unreadable) — the case that used to arrive as a 0 and get published as
        # a measured "used no memory".
        if measured is None:
            self._note_rss_unmeasured(reason="read_did_not_answer", exc=AnvilRssUnmeasured("rss_mb returned None"))
            return
        current = counters.peak_anvil_rss_mb
        counters.peak_anvil_rss_mb = int(measured) if current is None else max(current, int(measured))

    def _note_rss_unmeasured(self, *, reason: str, exc: BaseException) -> None:
        """One line + one degraded record per job for an RSS read that did not
        answer. The peak stays ``None`` and the metric says so, so unmeasured is
        published as unmeasured rather than as a 0 MB peak nobody observed."""
        if self._rss_sample_failed:
            return
        self._rss_sample_failed = True
        context = {"reason": reason, "exc_type": type(exc).__name__}
        record_degraded(phase="effects_rss_sample", exc=exc, context=context)
        logger.warning(
            "effects: anvil RSS sampling did not answer; peak_anvil_rss_mb is unmeasured, not zero",
            extra=context,
        )

    def _probe_one(self, it: _Item, counters: _Counters) -> None:
        try:
            it.probed = it.run()
        except Exception as exc:
            record_degraded(
                phase="effects_probe",
                exc=exc,
                context={"function_id": it.candidate.function_id, "effect_class": it.effect_class},
            )
            it.probed = None

    def _write_verdicts(
        self, session: Session, job: Job, items: list[_Item], seams: _Seams, counters: _Counters
    ) -> None:
        for it in items:
            verdict, tier, transcript_ptr, details, concrete, discrepancy, witness_from_cache = self._resolve_item(
                session, it, counters
            )
            cand = it.candidate
            record_effect_verdict(
                session,
                chain_id=seams.chain_id,
                # The address whose behavior was actually observed (the
                # deployment for a proxy-backed function) — the state-plane
                # identity. The code-plane cache key stays on the behavioral
                # hash, which is derived from the code-bearing address.
                contract_address=cand.probe_target,
                selector=cand.selector,
                effect_class=it.effect_class,
                function_id=cand.function_id,
                behavior_hash=it.behavior_hash,
                verdict=verdict,
                tier=tier,
                concrete_destination=concrete.get("destination") if concrete else None,
                current_check_passed=concrete.get("current_check_passed") if concrete else None,
                observed_residue=_observed_residue(it, concrete),
                # CONTRACT for anything reading ``effect_verdicts.witness``: this
                # row is written for UNKNOWN verdicts too, so the payload alone is
                # not a claim. ``witness["observation"]`` is the discriminator —
                # ``executed`` means the probe call ran and the other keys describe
                # F; ``reverted``/``not_run`` mean nothing was measured and a
                # ``false`` in the payload (``value_moved``, ``upgradeable``) is
                # "unmeasured", never "F does not do this". A consumer that reads
                # ``witness`` without joining on ``verdict`` must at minimum join on
                # this key. See ``services.effects.recipes.OBSERVATION_*``.
                # ``witness["reason"]`` sub-divides it: several verdicts share one
                # ``observation`` and differ only there (a withheld contradictory
                # supply sign vs a plain non-observation), so a consumer counting
                # a specific outcome must read the reason, and must treat its
                # ABSENCE as "not recorded" — rows written before it existed, and
                # cache hits served from such a row, simply lack the key.
                witness=details or None,
                # The payload above was served from the code-plane cache without a
                # re-simulation: its missing deployment-plane keys are structural,
                # not measured, so the upsert keeps the stored row's own.
                witness_from_cache=witness_from_cache,
                transcript_ptr=transcript_ptr,
            )
            counters.verdicts_written += 1
            self._route_section9(it, verdict, tier, transcript_ptr, discrepancy, counters)

    def _bridge_claims(self, session: Session, items: list[_Item]) -> int:
        """Fold this job's *proven* verdicts into registry claims
        on the matching ``effective_functions`` rows. Reads the verdicts back from
        the DB (authoritative — includes cache-hit proven verdicts, not only fresh
        probes) and merges through the pure bridge. Fail-closed is the bridge's
        job; this only touches rows that actually mint. Returns the row count
        labeled."""
        fn_ids = {it.candidate.function_id for it in items if it.candidate.function_id is not None}
        if not fn_ids:
            return 0
        verdicts = (
            session.query(EffectVerdict)
            .filter(EffectVerdict.function_id.in_(fn_ids), EffectVerdict.verdict == VERDICT_PROVEN)
            .all()
        )
        by_fn: dict[int, list[EffectVerdict]] = {}
        for verdict in verdicts:
            if verdict.function_id is not None:
                by_fn.setdefault(verdict.function_id, []).append(verdict)
        if not by_fn:
            return 0
        rows = session.query(EffectiveFunction).filter(EffectiveFunction.id.in_(by_fn)).all()
        labeled = 0
        for ef in rows:
            merged = claims_bridge.merge_into_function(ef.claims, ef.effect_labels, by_fn.get(ef.id, ()))
            if merged is None:
                continue
            ef.claims, ef.effect_labels = merged
            labeled += 1
        return labeled

    def _distill_score_signals(self, session: Session, job: Job) -> None:
        """Distil this job's contracts into ``function_score_signals`` + mark the
        protocol's score dirty.

        **Fail-forward, and partial-free per contract.** The effects stage never
        emits ``failed_terminal``, so a distillation raise must not be the thing
        that kills a job whose verdicts are already written and correct — every
        failure here is caught, logged with protocol/job context, and dropped.
        What must NOT survive is a half-written contract: each contract is
        replaced inside its own SAVEPOINT, and ``replace_contract_signals``
        validates every signal before it deletes anything, so a contract either
        replaces wholesale or not at all. Contracts that succeeded before a
        failing one legitimately stand — each was a complete honest replace of a
        different contract, and discarding them would lose recall to prove
        nothing.

        The whole pass runs in the job's transaction rather than committing:
        the ``_bridge_claims`` writes above are uncommitted at this point, and a
        DB error outside a savepoint would abort the transaction carrying them —
        an abort the stage would not notice until its own commit silently became
        a rollback and the job advanced as a success with its verdicts gone.

        **The opening flush is deliberately OUTSIDE the caught envelope.**
        ``begin_nested`` flushes unconditionally, so leaving it inside would let
        a failure in the stage's OWN pending writes be caught here and reported
        as a distillation failure — while the job died at its real commit
        anyway. Hoisted, a host-work failure raises as itself and everything the
        handlers below report is genuinely this hook's.
        """
        # Timed as a stage METRIC only, never a ``log_timed_phase`` span: the
        # caller keeps this outside the timeline on purpose (it writes no verdict
        # and must add no /monitor stage), but its cost still has to be
        # attributable rather than hiding inside the job's residual elapsed time.
        started = time.monotonic()
        try:
            self._distill_score_signals_inner(session, job)
        finally:
            record_stage_metric("phase_ms_distill", int((time.monotonic() - started) * 1000))

    def _distill_score_signals_inner(self, session: Session, job: Job) -> None:
        """The distillation itself; see :meth:`_distill_score_signals`."""
        from services.scoring.dirty import SCORE_DIRTY_EFFECTS, mark_protocol_score_dirty
        from services.scoring.distill import distill_job_signals
        from services.scoring.population import replace_contract_signals

        protocol_id = getattr(job, "protocol_id", None)
        # Flushed OUTSIDE the guard. ``begin_nested`` flushes unconditionally,
        # so a failure in the STAGE's own pending writes would otherwise be
        # caught below and reported as a distillation failure it is not — while
        # the job died at commit anyway. Everything the ``except`` reports is
        # then genuinely this hook's.
        session.flush()
        try:
            with session.begin_nested():
                grouped = distill_job_signals(session, job)
        except Exception as exc:
            # A real degradation, not a side-effect: this job's contracts are
            # now absent from the fold's population, so the protocol's next
            # score is computed over less than the run produced.
            record_degraded(phase="score_distillation", exc=exc, context={"protocol_id": protocol_id})
            logger.warning(
                "Effects: score-signal distillation failed for job %s (protocol %s)",
                job.id,
                protocol_id,
                exc_info=True,
                extra={"job_id": str(job.id), "protocol_id": protocol_id, "phase": "score_distillation"},
            )
            return

        written = 0
        failed: list[int] = []
        for contract_id, signals in grouped.items():
            try:
                with session.begin_nested():
                    deleted = replace_contract_signals(
                        session,
                        contract_id=contract_id,
                        signals=signals,
                        job_id=job.id,
                    )
                written += 1
                if deleted and not signals:
                    # A wholesale replace by an EMPTY set retracts every
                    # capability the contract had. That is correct when its
                    # functions genuinely went away and fail-open when anything
                    # upstream merely failed to produce them, and the two are
                    # indistinguishable from the row count alone — so the
                    # retraction is named rather than left silent.
                    logger.warning(
                        "Effects: distillation retracted all %d score signals for contract %s (job %s)",
                        deleted,
                        contract_id,
                        job.id,
                        extra={
                            "job_id": str(job.id),
                            "protocol_id": protocol_id,
                            "contract_id": contract_id,
                            "signals_retracted": deleted,
                            "phase": "score_distillation",
                        },
                    )
            except Exception as exc:
                failed.append(contract_id)
                # Same degradation, one contract wide: this contract keeps the
                # signal set an earlier job derived, so the protocol's score is
                # folded over a stale view of it.
                record_degraded(
                    phase="score_distillation",
                    exc=exc,
                    context={"protocol_id": protocol_id, "contract_id": contract_id},
                )
                logger.warning(
                    "Effects: score-signal persist failed for contract %s on job %s (protocol %s)",
                    contract_id,
                    job.id,
                    protocol_id,
                    exc_info=True,
                    extra={
                        "job_id": str(job.id),
                        "protocol_id": protocol_id,
                        "contract_id": contract_id,
                        "phase": "score_distillation",
                    },
                )

        if not grouped:
            return
        # Mark on any successful replace: the protocol's signal set changed, and
        # the fold must see it. A pass where every contract failed changed
        # nothing, so it does not enqueue a fold that would read the same rows.
        if written and protocol_id is not None:
            mark_protocol_score_dirty(session, protocol_id, SCORE_DIRTY_EFFECTS)
        logger.info(
            "Effects: distilled score signals for job %s: %d contract(s) replaced, %d failed",
            job.id,
            written,
            len(failed),
            extra={
                "job_id": str(job.id),
                "protocol_id": protocol_id,
                "contracts_replaced": written,
                "contracts_failed": len(failed),
                "failed_contract_ids": failed,
                "signal_rows": sum(len(v) for v in grouped.values()),
            },
        )

    def _resolve_item(
        self, session: Session, it: _Item, counters: _Counters
    ) -> tuple[str, str, str | None, dict[str, Any] | None, dict[str, Any] | None, Discrepancy | None, bool]:
        """Turn one worklist item into its persisted verdict, applying the cache /
        self-audit rules.

        The trailing bool is ``witness_from_cache``: the details being persisted
        were served from the code-plane cache WITHOUT a fresh re-simulation, so
        ``DEPLOYMENT_PLANE_KEYS`` are structurally absent from them and the
        verdict upsert must not read that absence as a measurement (it would
        erase the producing write's own seeding qualifiers / blast-radius set —
        whose absence is a contractual claim — on every self-hit). The audited
        hit paths return ``False`` because they re-attach the fresh probe's own
        deployment-plane keys below: there, an absent key IS this run's
        measurement."""
        if it.cached is None:
            # MISS — the probe result is the verdict; write it to the code-plane cache.
            eff = it.probed
            if eff is None:
                # Probe failed (degraded already recorded) → fail-closed unknown,
                # NOT cached (a flake must not poison the shared cache). Counted
                # so this outcome is neither a hit nor a miss in the accounting.
                counters.probes_failed += 1
                return VERDICT_UNKNOWN, TIER_CALL, None, None, None, None, False
            counters.cache_misses += 1
            if _is_cacheable(eff):
                self._cache_miss_write(session, it, eff, audit_status=None)
            return (
                eff.verdict,
                eff.tier,
                eff.transcript_ptr,
                eff.witness_payload or None,
                eff.concrete,
                eff.discrepancy,
                False,
            )

        cached = it.cached
        if it.needs_audit:
            # Self-audit: compare the re-simulated kernel against the cached one.
            fresh = it.probed
            if fresh is None:
                # Could not re-simulate to audit → do not trust the unaudited hit.
                return self._withhold_collision(session, cached, it, counters, reason="audit_probe_failed")
            if not kernel_signature_is_comparable(cached.details) or not kernel_signature_is_comparable(
                fresh.witness_payload
            ):
                # THE AUDIT FLOOR. A signature with no structural key agrees with
                # itself unconditionally — 49 of 150 cache rows are ``authority_change``
                # with ``verdict='unknown'`` and none of the five allowlisted keys, so
                # their "audit" is the string ``unknown`` compared with itself, and a
                # collision between two behaviours that both answer ``unknown`` is
                # exactly what it would have to catch. Such a hit is NOT trusted on the
                # signature alone.
                #
                # What is compared instead is the only thing such a row asserts: its
                # verdict and its ``reason`` — which IS a claim about the twin
                # (``no_supply_delta`` says "the call ran and no supply moved"). On
                # agreement the row is stamped audited, because the assertion has been
                # corroborated against a fresh probe of THIS deployment — strictly more
                # evidence than the structural-key path collects. On disagreement this
                # deployment publishes the verdict it just re-simulated and the row is
                # left UNAUDITED rather than AUDIT_FAILED: a reason legitimately varies
                # between two sightings of one behaviour (a precondition revert here, a
                # clean non-observation there), so poisoning the key would withhold from
                # every future sighting on the strength of a difference that proves
                # nothing.
                cached_reason = (cached.details or {}).get("reason")
                fresh_reason = (fresh.witness_payload or {}).get("reason")
                if cached.verdict == fresh.verdict and cached_reason == fresh_reason:
                    mark_audited(session, cached, passed=True, peer_hash=it.surface_hash or it.behavior_hash)
                    bump_hit(session, cached)
                    self._count_hit(it, counters)
                    return (
                        cached.verdict,
                        cached.tier,
                        cached.transcript_ptr,
                        _details_with_fresh_deployment_plane(cached.details, fresh),
                        _residue_only(fresh.concrete, it.effect_class),
                        None,
                        False,
                    )
                record_degraded(
                    phase="effect_cache_audit_floor",
                    exc=RuntimeError("zero-key kernel signature and the fresh probe disagrees; hit not trusted"),
                    context={
                        "behavior_hash": it.behavior_hash,
                        "effect_class": it.effect_class,
                        "cached_verdict": cached.verdict,
                        "cached_reason": cached_reason,
                        "fresh_verdict": fresh.verdict,
                        "fresh_reason": fresh_reason,
                    },
                )
                counters.cache_misses += 1
                return (
                    fresh.verdict,
                    fresh.tier,
                    fresh.transcript_ptr,
                    fresh.witness_payload or None,
                    fresh.concrete,
                    fresh.discrepancy,
                    False,
                )
            agree = kernel_verdicts_agree(cached.verdict, cached.details, fresh.verdict, fresh.details)
            mark_audited(session, cached, passed=agree, peer_hash=it.surface_hash or it.behavior_hash)
            if not agree:
                return self._withhold_collision(session, cached, it, counters, reason="kernel_hash_collision")
            bump_hit(session, cached)
            self._count_hit(it, counters)
            # The audit already re-simulated THIS deployment, so its state-plane
            # residue is in hand at no extra cost — the verdict still comes from
            # the cache (the audit only confirmed they agree), while the
            # deployment-plane qualifiers come from the fresh probe: they are
            # THIS deployment's own observation, which the cache structurally
            # cannot carry.
            return (
                cached.verdict,
                cached.tier,
                cached.transcript_ptr,
                _details_with_fresh_deployment_plane(cached.details, fresh),
                _residue_only(fresh.concrete, it.effect_class),
                None,
                False,
            )

        if cached.audit_status == AUDIT_FAILED:
            # A previously-caught collision poisoned this key → never reuse it.
            return self._withhold_collision(session, cached, it, counters, reason="poisoned_cache_key")

        bump_hit(session, cached)
        self._count_hit(it, counters)
        # A plain hit carries no residue of its own. When this
        # deployment's stored row has none either, ``_mark_residue_gaps`` asked
        # for one observation; take its ``concrete`` and NOTHING else — the
        # verdict, tier, details and transcript stay the cache's, and nothing
        # observed here is written back to ``effect_behavior_cache``.
        concrete = None
        if it.residue_probe and it.probed is not None:
            concrete = _residue_only(it.probed.concrete, it.effect_class)
            if concrete is not None:
                counters.residue_observations += 1
        # ``code_plane_details`` is a no-op on a row written at the current
        # version; it launders any earlier same-version row that still carries a
        # newly-classified deployment-plane key (``pause_effective``), so a hit
        # can never republish one deployment's fork state as another's.
        # ``witness_from_cache=True``: no re-simulation happened here, so the
        # verdict upsert must keep the stored row's own deployment-plane keys.
        return (
            cached.verdict,
            cached.tier,
            cached.transcript_ptr,
            code_plane_details(cached.details),
            concrete,
            None,
            True,
        )

    def _cache_miss_write(self, session: Session, it: _Item, eff: ObservedEffect, *, audit_status: str | None) -> None:
        upsert_cached_verdict(
            session,
            behavior_hash=it.behavior_hash,
            effect_class=it.effect_class,
            scope=it.scope,
            contract_surface_hash=it.surface_hash,
            gate_ref=it.gate_ref,
            verdict=eff.verdict,
            tier=eff.tier,
            transcript_ptr=eff.transcript_ptr,
            details=eff.witness_payload or None,
            audit_status=audit_status,
        )

    def _withhold_collision(
        self, session: Session, cached: EffectBehaviorCache, it: _Item, counters: _Counters, *, reason: str
    ) -> tuple[str, str, str | None, dict[str, Any] | None, dict[str, Any] | None, Discrepancy | None, bool]:
        """A caught hash collision / poisoned key: withhold the cached verdict and
        file a discrepancy. The cached verdict is NEVER propagated to this
        deployment."""
        # Neither served as a hit nor re-counted as a miss — without this the item
        # is invisible to the worklist accounting (``_Counters``).
        counters.withheld += 1
        disc = Discrepancy(
            kind=reason,
            effect_class=it.effect_class,
            detail={"behavior_hash": it.behavior_hash, "cached_verdict": cached.verdict},
        )
        return VERDICT_UNKNOWN, TIER_CALL, None, None, None, disc, False

    def _count_hit(self, it: _Item, counters: _Counters) -> None:
        if it.scope == SCOPE_KERNEL:
            counters.cache_hits_kernel += 1
        else:
            counters.cache_hits_projection += 1

    def _route_section9(
        self,
        it: _Item,
        verdict: str,
        tier: str,
        transcript_ptr: str | None,
        discrepancy: Discrepancy | None,
        counters: _Counters,
    ) -> None:
        cand = it.candidate
        if discrepancy is not None:
            if discrepancy.transcript_ptr is None:
                discrepancy.transcript_ptr = transcript_ptr
            route_discrepancy(discrepancy, contract_address=cand.probe_target, selector=cand.selector, tier=tier)
            counters.discrepancies_filed += 1
        # Direction 3: an exact-finite_set principal rejected by a canonical
        # gate error falsifies the resolver's enumeration. Only on a FRESH probe
        # (miss) that actually executed the call — a cache hit ran nothing.
        if getattr(cand, "membership_exact", False) and it.cached is None and it.probed is not None:
            filed = authority_contradiction(
                effect_class=it.effect_class,
                transcript=it.probed.transcript,
                membership_exact=True,
                contract_address=cand.probe_target,
                selector=cand.selector,
                tier=tier,
                transcript_ptr=transcript_ptr,
            )
            if filed:
                counters.discrepancies_filed += 1
        # Direction 2: a freshly-witnessed effect on a static-silent (blank)
        # function is a candidate new static idiom — an INFORMATIONAL vocabulary-
        # growth signal, NOT a degradation (every proven verdict is one, so it
        # would flood a healthy job's stage_errors). Counted separately as a
        # benign metric; ``discrepancies_filed`` stays direction-1 only. Only on a
        # fresh probe (miss), not on cache reuse — witnessed once, when first seen.
        if verdict == VERDICT_PROVEN and it.cached is None and it.probed is not None:
            eff = it.probed
            eff.transcript_ptr = eff.transcript_ptr or transcript_ptr
            file_new_idiom_candidate(eff, contract_address=cand.probe_target, selector=cand.selector)
            counters.new_idiom_candidates += 1

    def _record_metrics(self, counters: _Counters) -> None:
        record_stage_metric("candidates_in", counters.candidates_in)
        record_stage_metric("cache_hits_kernel", counters.cache_hits_kernel)
        record_stage_metric("cache_hits_projection", counters.cache_hits_projection)
        record_stage_metric("cache_misses", counters.cache_misses)
        # Candidates that never became worklist items (candidate units).
        record_stage_metric("skipped", counters.skipped)
        # The two item-unit outcomes that are neither a hit nor a miss, so the
        # worklist adds up: items == hits + misses + probes_failed + withheld.
        record_stage_metric("probes_failed", counters.probes_failed)
        record_stage_metric("withheld", counters.withheld)
        record_stage_metric("verdicts_written", counters.verdicts_written)
        record_stage_metric("discrepancies_filed", counters.discrepancies_filed)
        record_stage_metric("new_idiom_candidates", counters.new_idiom_candidates)
        record_stage_metric("upstream_requests", counters.upstream_requests)
        # Published ONLY when a sample succeeded. An unmeasured fork leaves the
        # key absent (and says so) rather than publishing a 0 MB peak nothing
        # observed.
        record_stage_metric("peak_anvil_rss_measured", counters.peak_anvil_rss_mb is not None)
        if counters.peak_anvil_rss_mb is not None:
            record_stage_metric("peak_anvil_rss_mb", counters.peak_anvil_rss_mb)
        record_stage_metric("residue_observations", counters.residue_observations)
        record_stage_metric("contracts_planned_empty", counters.contracts_planned_empty)
        # The pre-candidate funnel: what the cascade returned and what selection
        # itself removed before any candidate existed.
        for name, value in counters.selection_fields().items():
            record_stage_metric(name, value)
        for name, value in counters.seed_metrics.items():
            record_stage_metric(name, value)

    def _finalize_terminal_failure(
        self,
        session: Session,
        job: Job,
        *,
        error: str,
        kind: str,
        retry_count: int | None,
        lease_id,
    ) -> None:
        """Fail-forward: the effects stage NEVER emits
        ``failed_terminal``. On retry exhaustion (or a terminal error) advance to
        ``coverage`` instead of killing a job whose upstream policy artifacts are
        already complete and correct — flag-off is otherwise strictly better than
        flag-on, which the whole stage must not be.

        Verdicts default to ``unknown`` (the fail-closed value; per-behavior
        probes wrote what they could before the escaping failure). The failing
        exception is already in the ``stage_errors`` artifact — ``BaseWorker``
        persisted the degraded accumulator before invoking this hook — so the
        degradation stays observable without a bespoke marker.
        """
        logger.warning(
            "Effects stage fail-forward: advancing job %s to %s after %s failure "
            "(retries exhausted); verdicts default to unknown",
            job.id,
            self.next_stage.value,
            kind,
            extra={"phase": "job", "outcome": "degraded_advance", "failure_kind": kind},
        )
        advance_job(
            session,
            job.id,
            self.next_stage,
            "effects degraded → coverage (fail-forward)",
            lease_id=lease_id,
        )


_TRANSCRIPT_CLASS_RE = re.compile(r"[^a-z0-9_]")


def _transcript_artifact_name(transcript: dict[str, Any]) -> str:
    """A content-addressed artifact name for one transcript.

    ``store_artifact`` upserts on ``(job_id, name)``, so a positional counter is
    only unique within a single pass over a job: a second pass (a stale-lease
    reclaim, a requeue) restarts at 0 against a DIFFERENT probe order — because
    the first pass's writes turned some misses into cache hits — and silently
    overwrites the artifacts that already-persisted ``transcript_ptr``s point at.
    ``effect_behavior_cache`` pointers outlive the job that wrote them, so that
    destroys the witness trail behind live verdicts.

    Naming on the content instead makes a rewrite either a no-op (identical
    transcript ⇒ identical bytes) or a NEW artifact (changed transcript ⇒ changed
    digest), so an existing pointer always still resolves to what it witnessed.
    The effect-class prefix keeps the name legible; the digest carries uniqueness.
    """
    raw_class = transcript.get("effect_class")
    effect_class = _TRANSCRIPT_CLASS_RE.sub("", str(raw_class or "").lower())[:40] or "unclassified"
    body = json.dumps(transcript, sort_keys=True, default=str)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
    return f"effect_transcript_{effect_class}_{digest}"


def _chain_id_for_job(job: Job) -> int:
    """The job's first-class ``chain_id`` (invariant 1), else derived from
    ``request['chain']``, else mainnet — mirrors ``policy_worker``."""
    from db.models import derive_job_chain_id

    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        return chain_id
    request = job.request if isinstance(job.request, dict) else {}
    return derive_job_chain_id(request.get("chain"), getattr(job, "address", None)) or 1


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    EffectsWorker().run_loop()


if __name__ == "__main__":
    main()
