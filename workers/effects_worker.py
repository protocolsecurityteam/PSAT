"""Effects worker: behavioural effect simulation, between ``policy`` and ``coverage``.

Determines what a gated function does by observing state transitions on a fork, backed by a behavioural-hash cache. The
transition is behind ``PSAT_EFFECTS_STAGE`` (default off, read in ``PolicyWorker.next_stage``).

Verdicts persist to ``effect_behavior_cache`` / ``effect_verdicts``; discrepancies go to ``record_degraded``; proven
verdicts become registry claims via ``services.effects.claims_bridge`` for the frontend. The score does not consume
verdicts yet (the frontend neutralises the ``behavioral_observed`` tier).

Probe wiring is the ``Prober`` seam (``services.effects.orchestrator``) and every wire is injectable, so tests run
against stubs and the zero-candidate path touches no wire.

``BaseWorker`` supplies leasing, heartbeat, SIGTERM, ``StageErrors`` and ``PSAT_EFFECTS_JOB_CONCURRENCY`` (default 1:
anvil snapshot/revert is process-global). This file overrides ``process()`` and the fail-forward finalizer.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, replace
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
from services.effects.balance_dependencies import (
    DEPENDENT_FAMILIES,
    finish_work,
    prepare_work,
    reconcile_pending_effects,
)
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

# Unknown reasons that are code-plane non-observations and safe to transfer on the behavioural hash: each is recorded
# only when the probe call executed and the transition wasn't there. Reverted counterparts (``value_probe_reverted``,
# ``upgrade_probe_reverted``, ``mint_call_reverted``, ``mutation_call_reverted``) are excluded: a revert on a
# precondition or guessed argument is not a fact about twins.
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
    """Whether a verdict may transfer on the behavioural hash: proven code-plane verdicts, and unknowns only when the
    non-observation is structural.

    Tier-0 historical verdicts never transfer: they depend on the indexed upgrade and a per-deployment current-state
    check, and EIP-1967 proxies of one type share bytecode, so a twin would inherit "upgradeable now" without its own
    check.
    """
    if eff.tier == TIER_HISTORICAL:
        return False
    if eff.state_dependent:
        # Depends on state this probe manufactured (a scheduled op, a time warp): state-plane like Tier 0, whatever the
        # verdict.
        return False
    if eff.verdict == VERDICT_PROVEN:
        return True
    return eff.reason in _CACHEABLE_UNKNOWN_REASONS


# Post-Cancun default recorded for Tier-1 probes; the Tier-2 recipe asserts against the live fork separately.
_CHAIN_HARDFORK = {1: "prague", 8453: "prague"}


def _fork_enabled() -> bool:
    """Tier-2 fork kill switch, default on (the stage itself is off by default).

    Disables forking alone without losing Tier 0/1.
    """
    return os.getenv("PSAT_EFFECTS_FORK", "1").strip().lower() in ("1", "true", "yes", "on")


# State-plane residue re-observation on a cache hit.
#
# Hits carry no concrete values, so a deployment whose first write is a hit gets NULL residue forever. This re-runs the
# plan for ``concrete`` only; verdict, tier, details and transcript still come from the cache, and nothing is written
# back.
#
# To keep the cache worthwhile (61% hit rate), it runs only when:
#   * the class has storable residue reachable from a hit (only ``value_out``'s destination; others emit no
# ``concrete``, and ``code_upgrade``'s is Tier-0 only, never cached);
#   * the cached verdict can carry residue;
#   * this deployment's row lacks the value and still has attempts left (one batched read), so an unreproducible
# behaviour doesn't re-probe every job forever.
#
# At most ``_RESIDUE_PROBE_MAX_ATTEMPTS`` Tier-1 probes per deployment and class. ``freeze_pause`` is excluded (needs
# the Tier-2 fork).
_RESIDUE_KEY = {
    EFFECT_CLASS_VALUE_OUT: "destination",
}

# Attempts spent on the destination; bookkeeping, not published (the claims bridge whitelists keys).
_RESIDUE_ATTEMPTS_KEY = "destination_probe_attempts"

# One retry for an RPC flake, then accept the gap.
_RESIDUE_PROBE_MAX_ATTEMPTS = 2

# Hash-less candidates that get their own ``StageError``; the artifact is uncapped and rewritten per retry, so the rest
# are summarised.
_NO_HASH_SAMPLE = 8

# Residue keys that ride ``observed_residue``. A strict whitelist: only these are per-deployment facts to publish.
_RESIDUE_JSON_KEYS = (
    "observed_reach_value_usd",
    "observed_reach_holders",
    "reach_indeterminate",
    # The discriminator and the floor under its own name; dropping either lets a consumer read a floor as measured
    # reach.
    "reach_determined",
    "observed_reach_floor_usd",
    # Assets measured over and unvalued (holder, asset) pairs; the pairs and priced holders keep the disclosure tied to
    # the figure.
    "observed_reach_assets",
    "observed_reach_unvalued_pairs",
    "observed_reach_unvalued_assets",
    "observed_reach_unvalued_reasons",
    "observed_reach_priced_usd",
    "observed_reach_priced_holders",
    # The ceiling outcome, including ``skipped_no_tvl``; a dropped result looks like no check.
    "reach_tvl_check",
    "observed_reach_rejected_usd",
    "protocol_tvl_usd",
    # Backing counts per execution; the booleans stay on ``details`` as the code-plane witness.
    "backing_inflow_transfers",
    "backing_mint_transfers",
    # The call that proved the figure (caller, target, selector, calldata, height, seeding); per-deployment, so state
    # plane only.
    PROVING_EXECUTION_KEY,
)


def _residue_observable(cached: EffectBehaviorCache, effect_class: str) -> bool:
    """Can re-probing this cached behaviour yield residue?

    ``value_out`` records a destination only when proven, so an unknown hit would waste two calls for a guaranteed NULL.
    ``code_upgrade`` is absent: its residue is Tier-0 only, which is never cached. ``caller_arbitrary`` is excluded
    because the recipe withholds that address.
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
    """The ``observed_residue`` payload: value-reach figures (state plane, never cached) and the hit-path attempt
    count.

    Merged key-wise on conflict.
    """
    payload: dict[str, Any] = {}
    if concrete:
        payload.update({k: concrete[k] for k in _RESIDUE_JSON_KEYS if k in concrete})
    if it.residue_probe:
        # Counted even when nothing was produced; that's what the bound is for.
        payload[_RESIDUE_ATTEMPTS_KEY] = it.residue_attempts + 1
    return payload or None


def _residue_only(concrete: dict[str, Any] | None, effect_class: str) -> dict[str, Any] | None:
    """The one residue key this class may contribute from a hit (a whitelist, not the raw ``concrete``)."""
    key = _RESIDUE_KEY.get(effect_class)
    if not concrete or key is None:
        return None
    value = concrete.get(key)
    return {key: value} if value is not None else None


def _details_with_fresh_deployment_plane(
    cached_details: dict[str, Any] | None, fresh: ObservedEffect
) -> dict[str, Any] | None:
    """The details an audited hit persists: the cache's code-plane facts plus the fresh re-simulation's
    deployment-plane keys.

    The cache strips those keys, and serving ``cached.details`` verbatim dropped seeding qualifiers whose absence is
    itself a claim (a proven burn once lost ``input_seeded: true``). The audit just re-ran this deployment, so its keys
    (or their absence) are current. ``code_plane_details`` launders older rows.
    """
    merged = dict(code_plane_details(cached_details) or {})
    merged.update(deployment_plane_details(fresh.witness_payload))
    return merged or None


def _residue_probe_enabled() -> bool:
    """Kill switch for hit-path residue re-observation; default on."""
    return os.getenv("PSAT_EFFECTS_RESIDUE_PROBE", "1").strip().lower() in ("1", "true", "yes", "on")


def _batch_plan_enabled() -> bool:
    """Batch the ``cache_lookup`` DB round-trips instead of N+1.

    Default on; the switch is the parity test's A/B seam.
    """
    return os.getenv("PSAT_EFFECTS_BATCH_PLAN", "1").strip().lower() in ("1", "true", "yes", "on")


def _anvil_port() -> int:
    try:
        return int(os.getenv("PSAT_EFFECTS_ANVIL_PORT", "8546"))
    except ValueError:
        return 8546


def _resource_cap() -> int | None:
    """Safety valve only (value orders, never gates).

    Unset means no cap; when exceeded, ``select_candidates`` logs what it dropped.
    """
    raw = os.getenv("PSAT_EFFECTS_RESOURCE_CAP")
    if not raw:
        return None
    try:
        return max(0, int(raw))
    except ValueError:
        return None


@dataclass
class _Seams:
    """The stage's real I/O bundle, built from ``job.request``; injectable for tests, and constructed lazily only
    when candidates exist.
    """

    simulate: Any
    transcript_store: Any
    capability_store: CapabilityStore
    chain_id: int
    call_batch: Any = None
    anvil_factory: Any = None
    # ``() -> int | None``: the head, pinned once at preflight for every Tier-1 probe. ``None`` in tests.
    block_number: Any = None


@dataclass
class _Item:
    """One (candidate, plan) unit through cache_lookup, probe and verdict_write."""

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
    # A hit whose persisted row has no residue yet: run the plan for ``concrete`` only (see ``_RESIDUE_KEY``).
    residue_probe: bool = False
    # Attempts already spent, read from the stored row so the bound holds across jobs.
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
    # ``None`` until a sample succeeds, never a fake 0 MB.
    peak_anvil_rss_mb: int | None = None
    # Candidate units: candidates that never reached the worklist.
    skipped: int = 0
    # Item units, exactly: items == cache_hits_kernel + cache_hits_projection + cache_misses + probes_failed + withheld.
    # ``probes_failed`` is a miss whose probe produced nothing; ``withheld`` is a hit refused by the audit.
    probes_failed: int = 0
    withheld: int = 0
    residue_observations: int = 0
    contracts_planned_empty: int = 0
    # The funnel from ``select_candidates``; ``selection_fields()`` adds the ``selection_`` prefix.
    selection_funnel: dict[str, Any] = field(default_factory=dict)
    seed_metrics: dict[str, int] = field(default_factory=dict)

    def selection_fields(self) -> dict[str, Any]:
        """The funnel under the key spelling every sink uses."""
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
        self.prober: Prober = prober or default_prober
        self._injected_hash_resolver = hash_resolver
        self._injected_seams = seams
        self._capability_store: CapabilityStore = capability_store or InMemoryCapabilityStore()
        # One anvil per job, created on the first Tier-2 plan and closed in ``process()``.
        self._anvil: Any = None
        self._anvil_error: Exception | None = None
        self._fork_gateway: Any = None
        # The preflight height the fork spawns at, set in ``_probe_context`` (the factory is built before the head is
        # pinned) and cleared with the fork.
        self._fork_block_pin: int | None = None
        # Rebuilt per job so budget counters start at zero.
        self._seeder: SimulateSeeder | None = None
        self._rss_sample_failed = False

    def _make_seams(self, session: Session, job: Job) -> _Seams:
        """Build the real I/O bundle from ``job.request``; only reached with candidates."""
        if self._injected_seams is not None:
            return self._injected_seams

        from services.clients.rpc import eth_call_batch, require_rpc_url
        from services.effects.simulate import eth_simulate_v1

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
            from services.clients.rpc import rpc_request

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
        """Single-flight forking-anvil factory: one fork per job per chain, created on the first Tier-2 plan.

        ``None`` when forking is disabled, so pause plans aren't emitted.

        Never reached in tests (they inject ``seams=``). A spawn failure is memoized and re-raised per plan;
        ``_probe_one`` records it and the behaviour lands ``unknown`` (``AnvilSpawnError`` is transient), so the stage
        degrades rather than crashes.
        """
        if not _fork_enabled():
            return None
        from services.clients.fork_gateway import ForkGateway
        from services.clients.rpc import rpc_headers
        from services.effects.anvil import SubprocessAnvil
        from services.effects.exceptions import AnvilSpawnError

        hardfork = _CHAIN_HARDFORK.get(chain_id, "prague")
        port = _anvil_port()

        def factory():
            if self._anvil_error is not None:
                raise self._anvil_error
            if self._anvil is not None:
                return self._anvil
            try:
                # ``rpc_headers`` is the source of eRPC auth; local/explicit fork URLs get no secret.
                self._fork_gateway = ForkGateway(rpc_url, rpc_headers(rpc_url))
                self._anvil = SubprocessAnvil(
                    port=port,
                    hardfork_name=hardfork,
                    fork_url=self._fork_gateway.url,
                    # Same height as Tier 1; unpinned forks observe an unrecorded, unreplayable state.
                    fork_block_number=self._fork_block_pin,
                )
            except Exception as exc:
                self._anvil_error = exc if isinstance(exc, AnvilSpawnError) else AnvilSpawnError(str(exc))
                raise self._anvil_error from exc
            # Read back from the fork: a rejected pin leaves None, which Tier-2 witnesses then publish.
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
        """Always run; a leftover anvil would hold the port and memory."""
        anvil = self._anvil
        self._anvil = None
        self._anvil_error = None
        self._fork_block_pin = None
        self._rss_sample_failed = False
        gateway = getattr(self, "_fork_gateway", None)
        self._fork_gateway = None
        if anvil is None:
            if gateway is not None:
                gateway.close()
            return
        try:
            anvil.close()
        except Exception:
            logger.warning("effects fork close failed", exc_info=True)
        finally:
            if gateway is not None:
                gateway.close()

    def _make_transcript_store(self, session: Session, job: Job):
        """Persist each transcript as a job artifact, returning a pointer resolvable via ``get_artifact(job_id,
        name)``.
        """

        def store(transcript: dict[str, Any]) -> str:
            name = _transcript_artifact_name(transcript)
            store_artifact(session, job.id, name, data=transcript)
            return f"{job.id}::{name}"

        return store

    def _hash_resolver(self, chain_id: int) -> HashResolver:
        return self._injected_hash_resolver or make_bytecode_hash_resolver(chain_id)

    def _claim_job(self, session: Session) -> Job | None:
        now = time.monotonic()
        if now - getattr(self, "_last_balance_reconcile", float("-inf")) >= 60:
            reconcile_pending_effects(session)
            session.commit()
            self._last_balance_reconcile = now
        return super()._claim_job(session)

    def process(self, session: Session, job: Job) -> None:
        try:
            self._process(session, job)
        finally:
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

        # Selection first so a zero-candidate job makes no RPC.
        with log_timed_phase(logger, "selection", durations_ms=durations_ms) as ph:
            candidates = self._select(session, job, funnel=counters.selection_funnel)
            ph.update(counters.selection_fields())
        self._balance_work = {}
        if candidates and isinstance(job.protocol_id, int):
            self._balance_work = prepare_work(
                session,
                candidates,
                protocol_id=job.protocol_id,
                chain_id=_chain_id_for_job(job),
                job_id=job.id,
            )
            if self._balance_work:
                session.commit()
        counters.candidates_in = len(candidates)

        if not candidates:
            resume_id = (job.request or {}).get("effects_resume_work_id")
            if resume_id:
                from db.models.balance_work import PendingEffectsWork

                work = session.get(PendingEffectsWork, resume_id)
                if work is not None and work.queued_job_id == job.id:
                    work.state = "complete"
                    work.reason = "not_applicable"
                    work.queued_job_id = None
            # Wire-free: emit the remaining phase spans for a complete timeline.
            for phase in _PHASES_AFTER_SELECTION:
                with log_timed_phase(logger, phase, durations_ms=durations_ms):
                    pass
            # These contracts' claims still need distilling, or the fold treats them as having no capabilities.
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

        with log_timed_phase(logger, "cache_lookup", durations_ms=durations_ms) as ph:
            items = self._plan(session, candidates, ctx, hash_resolver, counters, job=job)
            ph["planned"] = len(items)

        self._run_probes(items, durations_ms, counters, seams)
        # Persist verdicts, route discrepancies, and mint proven verdicts into claims in the same phase, so /monitor
        # gains no stage.
        with log_timed_phase(logger, "verdict_write", durations_ms=durations_ms) as ph:
            self._write_verdicts(session, job, items, seams, counters)
            ph["verdicts_written"] = counters.verdicts_written
            ph["labeled"] = self._bridge_claims(session, items)

        # After the bridge so it reads the new ``behavioral_observed`` claims; outside the phase span (no verdict, no
        # stage).
        self._distill_score_signals(session, job)
        finish_work(session, self._balance_work, job_id=job.id)

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

    def _select(self, session: Session, job: Job, *, funnel: dict[str, Any] | None = None) -> list[Candidate]:
        protocol_id = getattr(job, "protocol_id", None)
        if not isinstance(protocol_id, int):
            # No protocol means nothing to simulate against. The funnel still records "selection never ran", which
            # differs from an empty cascade.
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
                # Only markers at least as new as this job count (``_scope_predicate`` rule 4).
                planned_since=getattr(job, "created_at", None),
            )
            if isinstance(address, str) and address.strip()
            else None
        )
        # No address means a company/root job; it falls back to protocol-wide selection.
        resume_ids = (job.request or {}).get("effects_function_ids")
        if resume_ids:
            # Explicit recovery bypasses ownership and markers, narrowed to exactly the dependent functions on this
            # chain.
            candidates = select_candidates(
                session,
                protocol_id,
                scope=None,
                funnel=funnel,
                chain_id=_chain_id_for_job(job),
                function_ids=resume_ids,
            )
            from db.models.balance_work import PendingEffectsWork

            work = session.get(PendingEffectsWork, (job.request or {}).get("effects_resume_work_id"))
            if work is not None and work.effect_family in DEPENDENT_FAMILIES:
                candidates = [replace(c, restrict_families=frozenset({work.effect_family})) for c in candidates]
            return candidates
        return select_candidates(
            session,
            protocol_id,
            resource_cap=_resource_cap(),
            scope=scope,
            funnel=funnel,
        )

    def _preflight(self, seams: _Seams, durations_ms: dict[str, int]) -> tuple[bool, int]:
        """Capability probe plus the one ``eth_blockNumber`` pinning every Tier-1 simulation.

        Without a pin, Tier 1 is disabled rather than simulating at genesis.
        """
        with log_timed_phase(logger, "preflight", durations_ms=durations_ms) as ph:
            try:
                supported = probe_simulate_support(seams.simulate, seams.chain_id, seams.capability_store)
            except Exception as exc:
                # Fail closed: assume unsupported (Tier-2 fallback).
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
                    # Couldn't pin a head, so Tier 1 is off. (No seam at all is a stub bundle.)
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

        # Built here so the job owns its cost ceiling and can report spend; the same conditions as the lazy path.
        self._seeder = None
        if supported and input_seeding_enabled():
            self._seeder = SimulateSeeder(seams.simulate, chain_id=seams.chain_id)

        # A non-positive block is the preflight failure sentinel; leave the fork unpinned.
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
        """Fold the job's seeding spend into stage metrics and one log line, so a run can tell whether seeding cost
        time and bought verdicts.
        """
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
        # Bulk-load per-candidate rows up front; with the flag off the helpers use single-row queries (parity test
        # seam).
        batched = _batch_plan_enabled()
        if batched:
            install_prefetch(session, ctx.chain_id, candidates)
        try:
            # Pass 1: hashes and plans, staging cache identities.
            staged: list[tuple[Candidate, Any, str, str]] = []
            # A contract qualifies for the empty-planning marker only if every candidate planned cleanly; failures are
            # transient.
            planned_per_contract: dict[int, int] = {}
            unclean_contracts: set[int] = set()
            contracts_with_plans: set[int] = set()
            # Exact count behind the one summary record.
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
                    # No behavioural hash: withhold rather than guess, and record it so a bytecode-cache outage doesn't
                    # look like nothing to do.
                    context = {
                        "function_id": cand.function_id,
                        "contract_id": cand.contract_id,
                        "contract_address": cand.contract_address,
                    }
                    # Bounded: the artifact is uncapped and rewritten every retry.
                    if len(no_hash_candidates) < _NO_HASH_SAMPLE:
                        record_degraded(
                            phase="effects_hash",
                            exc=BehaviorHashUnavailable(
                                f"no behavioral hash for function {cand.function_id} on {cand.contract_address}"
                            ),
                            context=context,
                        )
                    no_hash_candidates.append(cand.function_id)
                    # DEBUG per candidate; the total is in the summary and the ``skipped`` metric.
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
                # The exact total, so the capped records aren't mistaken for all of it.
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
            unclean_contracts.update(
                c.contract_id
                for c in candidates
                if any(
                    fid == c.function_id and r.state != "complete"
                    for (fid, _), r in getattr(self, "_balance_work", {}).items()
                )
            )
            self._mark_empty_planning(
                session, job, planned_per_contract, unclean_contracts, contracts_with_plans, counters
            )

            # Pass 2: one composite verdict lookup, then assemble items.
            verdicts: dict[tuple[str, str, str, str, str], EffectBehaviorCache] = {}
            if batched:
                verdicts = find_cached_verdicts_batch(
                    session,
                    ((bh, p.effect_class, p.scope, surf, p.gate_ref) for _c, p, bh, surf in staged),
                )
            items: list[_Item] = []
            for cand, plan, behavior_hash, surface in staged:
                if batched:
                    # ``surface`` is already kernel-normalized.
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
                work = getattr(self, "_balance_work", {}).get((cand.function_id, plan.effect_class))
                if (
                    job is not None
                    and (job.request or {}).get("effects_resume_work_id")
                    and work is not None
                    and work.queued_job_id == job.id
                ):
                    # Replay only the selected dependency with its new inputs.
                    cached = None
                # First re-encounter of a shared hash triggers the self-audit.
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
        """Flag cache hits whose persisted row has no residue and attempts left, in one batched read."""
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
                # No row yet: first sighting.
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
        """Record contracts planned in full that yielded no plans, so later jobs don't sweep them again.

        Contracts with any unplannable candidate are excluded (transient), and nothing is recorded while the Tier-2 fork
        is disabled (pause plans would be artificially missing).
        """
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
        """Run recipes for misses and audit re-runs, timed by tier.

        Per-behaviour failures are recorded and skipped; only whole-stage failures escape ``process()``.
        """
        tier1 = [it for it in items if it.scope == SCOPE_KERNEL and (it.cached is None or it.needs_audit)]
        tier2 = [it for it in items if it.scope != SCOPE_KERNEL and (it.cached is None or it.needs_audit)]
        # Kernel scope only (every ``_RESIDUE_KEY`` class is Tier 0/1), timed with Tier 1.
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
        """Fold the fork's RSS into the job peak; tolerates a missing fork and never raises."""
        anvil = getattr(self, "_anvil", None)
        sample = getattr(anvil, "rss_mb", None)
        if sample is None:
            return
        try:
            measured = sample()
        except Exception as exc:
            self._note_rss_unmeasured(reason="sampler_raised", exc=exc)
            return
        # ``None`` means unknown (exited, /proc unreadable), not 0.
        if measured is None:
            self._note_rss_unmeasured(reason="read_did_not_answer", exc=AnvilRssUnmeasured("rss_mb returned None"))
            return
        current = counters.peak_anvil_rss_mb
        counters.peak_anvil_rss_mb = int(measured) if current is None else max(current, int(measured))

    def _note_rss_unmeasured(self, *, reason: str, exc: BaseException) -> None:
        """One log line and degraded record per job for an unanswered RSS read."""
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
                # The observed deployment (state-plane identity); the cache key uses the code-bearing address.
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
                # This row is written for unknowns too. ``witness["observation"]`` says whether the call ran; with
                # ``reverted``/``not_run`` a ``false`` means unmeasured. ``witness["reason"]`` distinguishes outcomes
                # within one observation; its absence means not recorded (older rows). See
                # ``services.effects.recipes.OBSERVATION_*``.
                witness=details or None,
                # Served from the cache without re-simulation: keep the stored row's deployment-plane keys.
                witness_from_cache=witness_from_cache,
                transcript_ptr=transcript_ptr,
            )
            counters.verdicts_written += 1
            self._route_section9(it, verdict, tier, transcript_ptr, discrepancy, counters)

    def _bridge_claims(self, session: Session, items: list[_Item]) -> int:
        """Fold this job's proven verdicts (read back from the DB, including cache hits) into claims on the matching
        ``effective_functions`` rows via the bridge. Returns the number of rows labelled.
        """
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
        """Distil this job's contracts into ``function_score_signals`` and mark the protocol's score dirty.

        Fail-forward: effects never fails terminally, so errors are logged and dropped. Each contract is replaced in its
        own SAVEPOINT and ``replace_contract_signals`` validates before deleting, so no contract is half-written;
        earlier successes stand.

        Runs in the job's transaction (the ``_bridge_claims`` writes are still uncommitted), so DB errors must stay
        inside savepoints. The opening flush is outside the error handling so the stage's own pending-write failures
        aren't misreported as distillation failures.
        """
        # A stage metric, not a phase span: it must not add a /monitor stage.
        started = time.monotonic()
        try:
            self._distill_score_signals_inner(session, job)
        finally:
            record_stage_metric("phase_ms_distill", int((time.monotonic() - started) * 1000))

    def _distill_score_signals_inner(self, session: Session, job: Job) -> None:
        from services.scoring.dirty import SCORE_DIRTY_EFFECTS, mark_protocol_score_dirty
        from services.scoring.distill import distill_job_signals
        from services.scoring.population import replace_contract_signals

        protocol_id = getattr(job, "protocol_id", None)
        # Outside the guard: ``begin_nested`` flushes, and the stage's own write failures shouldn't be reported as this
        # hook's.
        session.flush()
        try:
            with session.begin_nested():
                resume_id = (job.request or {}).get("effects_resume_work_id")
                if resume_id:
                    from db.models.balance_work import PendingEffectsWork

                    resumed_work = session.get(PendingEffectsWork, int(resume_id))
                    if resumed_work is None:
                        raise RuntimeError("effects recovery dependency disappeared")
                    grouped = distill_job_signals(session, job, contract_ids=[resumed_work.contract_id])
                else:
                    grouped = distill_job_signals(session, job)
        except Exception as exc:
            # These contracts are now missing from the fold's population.
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
                    # An empty replace retracts every capability, which is fail-open if something upstream merely
                    # failed; name it.
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
                # This contract keeps an older signal set, so the score uses a stale view.
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
        # Only mark when something changed.
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
        """Resolve one item to its persisted verdict under the cache and self-audit rules.

        The trailing bool is ``witness_from_cache``: details served without re-simulation lack ``DEPLOYMENT_PLANE_KEYS``
        structurally, so the upsert mustn't treat that as a measurement. Audited paths return ``False`` because they
        re-attach the fresh keys.
        """
        if it.cached is None:
            # Miss: cache the probe result.
            eff = it.probed
            if eff is None:
                # Probe failed: fail-closed unknown, not cached.
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
            fresh = it.probed
            if fresh is None:
                # Can't audit, so don't trust the hit.
                return self._withhold_collision(session, cached, it, counters, reason="audit_probe_failed")
            if not kernel_signature_is_comparable(cached.details) or not kernel_signature_is_comparable(
                fresh.witness_payload
            ):
                # Audit floor: a signature with no structural key trivially matches itself (e.g. every
                # ``authority_change`` unknown), so compare verdict and ``reason`` instead. Agreement stamps it audited.
                # Disagreement publishes this deployment's fresh verdict and leaves the row unaudited (not
                # AUDIT_FAILED), since reasons legitimately vary.
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
            # The audit already re-simulated this deployment, so take its deployment-plane keys; the verdict stays the
            # cache's.
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
            # A previously caught collision poisoned this key.
            return self._withhold_collision(session, cached, it, counters, reason="poisoned_cache_key")

        bump_hit(session, cached)
        self._count_hit(it, counters)
        # A plain hit's residue observation: take its ``concrete`` only; nothing is written back to the cache.
        concrete = None
        if it.residue_probe and it.probed is not None:
            concrete = _residue_only(it.probed.concrete, it.effect_class)
            if concrete is not None:
                counters.residue_observations += 1
        # ``code_plane_details`` launders older same-version rows; ``witness_from_cache=True`` keeps the stored
        # deployment-plane keys.
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
        """A caught collision or poisoned key: withhold the cached verdict and file a discrepancy."""
        # Otherwise the item is missing from the accounting.
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
        # Direction 3: an exact-set principal rejected by a canonical gate error, on a fresh probe that actually
        # executed.
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
        # Direction 2: a fresh proven effect on a blank function is an informational new-idiom signal, not a
        # degradation. Only on first sighting (a miss).
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
        record_stage_metric("skipped", counters.skipped)
        # So the worklist adds up.
        record_stage_metric("probes_failed", counters.probes_failed)
        record_stage_metric("withheld", counters.withheld)
        record_stage_metric("verdicts_written", counters.verdicts_written)
        record_stage_metric("discrepancies_filed", counters.discrepancies_filed)
        record_stage_metric("new_idiom_candidates", counters.new_idiom_candidates)
        record_stage_metric("upstream_requests", counters.upstream_requests)
        # Only when a sample succeeded.
        record_stage_metric("peak_anvil_rss_measured", counters.peak_anvil_rss_mb is not None)
        if counters.peak_anvil_rss_mb is not None:
            record_stage_metric("peak_anvil_rss_mb", counters.peak_anvil_rss_mb)
        record_stage_metric("residue_observations", counters.residue_observations)
        record_stage_metric("contracts_planned_empty", counters.contracts_planned_empty)
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
        """Fail-forward: effects never emits ``failed_terminal``.

        On exhaustion or a terminal error, advance to ``coverage`` so an enabled stage is never worse than a disabled
        one. Verdicts default to ``unknown``; the error is already in ``stage_errors``.
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
    """A content-addressed transcript artifact name.

    ``store_artifact`` upserts on ``(job_id, name)``, and a positional counter restarts on a second pass in a different
    order, overwriting artifacts that cached ``transcript_ptr``s (which outlive the job) point at. A content digest
    makes rewrites no-ops or new artifacts.
    """
    raw_class = transcript.get("effect_class")
    effect_class = _TRANSCRIPT_CLASS_RE.sub("", str(raw_class or "").lower())[:40] or "unclassified"
    body = json.dumps(transcript, sort_keys=True, default=str)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
    return f"effect_transcript_{effect_class}_{digest}"


def _chain_id_for_job(job: Job) -> int:
    """The job's ``chain_id``, else derived from ``request['chain']``, else mainnet; mirrors
    ``policy_worker``.
    """
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
