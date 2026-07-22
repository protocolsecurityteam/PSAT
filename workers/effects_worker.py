"""Effects worker — behavioral effect simulation (EFFECTS_RESOLUTION_SPEC §3a).

The sixth pipeline stage worker, inserted between ``policy`` and ``coverage``.
It determines what a gated function *does* by observing state transitions on a
fork (idiom-agnostic witnesses), backed by a persistent behavioral-hash cache.

The policy->effects transition is feature-flagged (``PSAT_EFFECTS_STAGE``,
default-off, read in ``PolicyWorker.next_stage``); with the flag off no job ever
enters this stage and the worker simply idles.

**Consumption boundary (§3a amended by §5.2): labels-observable, scoring-
deferred.** Verdicts persist to ``effect_behavior_cache`` / ``effect_verdicts``
and §9 discrepancies to the warning channel (``record_degraded``). Beyond that,
*proven* verdicts are minted into registry claims on the matching
``effective_functions`` rows through ``services.effects.claims_bridge`` (call
site 1, after ``verdict_write``), so the frontend renders them as labels through
the one shared claims vocabulary. The **score** still does not consume verdicts
(deferred to ``SCORING_INVARIANTS.md``); the frontend score path neutralises the
``behavioral_observed`` tier so it stays byte-identical.

Orchestration lives here; the per-candidate probe wiring is a ``Prober`` seam
(``services.effects.orchestrator``) and every wire (simulate / call-batch / anvil
/ transcript store / capability store / behavioral-hash resolver) is injectable,
so the offline suite drives the whole stage against stubs with recorded
transcripts (inv. 8) and the **zero-candidate path touches no wire at all**.

Inherited from ``BaseWorker`` (never reimplemented): lease claim, stale reclaim,
background heartbeat, SIGTERM release, the ``[BOOT]`` banner, ``StageErrors``,
and per-worker concurrency via ``PSAT_EFFECTS_JOB_CONCURRENCY`` (default 1,
single-flight per inv. 16 — anvil snapshot/revert is process-global). This file
overrides ``process()`` and the fail-forward finalizer only.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from db.effect_cache import (
    AUDIT_FAILED,
    bump_hit,
    find_cached_verdict,
    kernel_verdicts_agree,
    mark_audited,
    record_effect_verdict,
    upsert_cached_verdict,
)
from db.models import EffectBehaviorCache, EffectiveFunction, EffectVerdict, Job, JobStage
from db.queue import advance_job, store_artifact
from services.effects import claims_bridge
from services.effects.config import (
    SCOPE_KERNEL,
    TIER_CALL,
    TIER_HISTORICAL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.discrepancies import file_new_idiom_candidate, route_discrepancy
from services.effects.harness import Discrepancy, ObservedEffect
from services.effects.orchestrator import (
    HashResolver,
    ProbeContext,
    Prober,
    default_prober,
    make_bytecode_hash_resolver,
)
from services.effects.preflight import CapabilityStore, InMemoryCapabilityStore, probe_simulate_support
from services.effects.selection import Candidate, select_candidates
from utils.chains import UnknownChainError, chain_by_id
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker

logger = logging.getLogger("workers.effects_worker")

_PHASES_AFTER_SELECTION = ("preflight", "cache_lookup", "tier1_probes", "tier2_fork", "verdict_write")

# ``unknown`` reasons that are genuine CODE-PLANE non-observations — safe to
# transfer on the behavioral hash (a re-run/twin sees the same structural
# result). Every OTHER unknown (capability fallback, precondition/mint revert,
# malformed response) is chain-/state-/transient-dependent and must NEVER enter
# the code-plane cache (§7) — those re-probe instead of transferring.
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
    check, inv. 13), so they are state-plane and live only in ``effect_verdicts``
    (§7 "state-determined → never cached"). Caching one would let a present-tense
    "upgradeable now" mint for a bytecode twin whose own current-state check was
    never run — EIP-1967 proxies of the same type share runtime bytecode, so the
    kernel hash collides across many real twins."""
    if eff.tier == TIER_HISTORICAL:
        return False
    if eff.verdict == VERDICT_PROVEN:
        return True
    return eff.reason in _CACHEABLE_UNKNOWN_REASONS


# Post-Cancun default per chain for the Tier-1 SimContext hardfork stamp. The
# Tier-2 pause recipe asserts post-Cancun against the live fork separately (§8.7);
# this is only the recorded value for eth_call/eth_simulateV1 probes.
_CHAIN_HARDFORK = {1: "prague", 8453: "prague"}


def _fork_enabled() -> bool:
    """Tier-2 fork kill switch. Default ON in production — the stage itself is
    already behind ``PSAT_EFFECTS_STAGE`` (default off), so this exists to disable
    forking alone (a host without foundry, an incident) without losing Tier 0/1."""
    return os.getenv("PSAT_EFFECTS_FORK", "1").strip().lower() in ("1", "true", "yes", "on")


def _anvil_port() -> int:
    try:
        return int(os.getenv("PSAT_EFFECTS_ANVIL_PORT", "8546"))
    except ValueError:
        return 8546


def _resource_cap() -> int | None:
    """Hard safety-valve only (inv. 4) — value never gates. Unset ⇒ no cap; every
    distinct behavior is simulated. When set and exceeded, ``select_candidates``
    logs exactly what it dropped."""
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


@dataclass
class _Counters:
    candidates_in: int = 0
    candidates_after_cascade: int = 0
    cache_hits_kernel: int = 0
    cache_hits_projection: int = 0
    cache_misses: int = 0
    verdicts_written: int = 0
    discrepancies_filed: int = 0
    new_idiom_candidates: int = 0
    upstream_requests: int = 0
    peak_anvil_rss_mb: int = 0
    skipped: int = 0


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
        # Single-flight fork state (inv. 16): one anvil per job, memoized on first
        # Tier-2 plan and closed in ``process()``'s finally.
        self._anvil: Any = None
        self._anvil_error: Exception | None = None

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
        """Single-flight forking-anvil factory (inv. 16): ONE fork per job per
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

        def factory():
            if self._anvil_error is not None:
                raise self._anvil_error
            if self._anvil is not None:
                return self._anvil
            try:
                # rpc_headers is the single source of truth for eRPC auth — a local
                # or explicit fork URL correctly gets no secret.
                self._anvil = SubprocessAnvil(
                    port=_anvil_port(),
                    hardfork_name=hardfork,
                    fork_url=rpc_url,
                    fork_headers=rpc_headers(rpc_url),
                )
            except Exception as exc:
                self._anvil_error = exc if isinstance(exc, AnvilSpawnError) else AnvilSpawnError(str(exc))
                raise self._anvil_error from exc
            logger.info("effects fork ready: chain_id=%s hardfork=%s", chain_id, hardfork)
            return self._anvil

        return factory

    def _close_anvil(self) -> None:
        """Always run — an anvil subprocess outliving the job would hold the port
        and the fork's memory for every subsequent job."""
        anvil = self._anvil
        self._anvil = None
        self._anvil_error = None
        if anvil is None:
            return
        try:
            anvil.close()
        except Exception:
            logger.warning("effects fork close failed", exc_info=True)

    def _make_transcript_store(self, session: Session, job: Job):
        """Persist each transcript as a job artifact (§8.5) and return a stable,
        backend-agnostic pointer resolvable via ``get_artifact(job_id, name)``.
        The pointer is the cache/verdict ``transcript_ptr`` — never an inline blob."""
        seq = {"n": 0}

        def store(transcript: dict[str, Any]) -> str:
            name = f"effect_transcript_{seq['n']}"
            seq["n"] += 1
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
            # Never leak a fork subprocess, on any exit path (inv. 16).
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
            candidates = self._select(session, job)
            ph["candidate_count"] = len(candidates)
        counters.candidates_in = len(candidates)
        counters.candidates_after_cascade = len(candidates)

        if not candidates:
            # Inert, wire-free: emit the remaining phase spans for a complete
            # timeline and write zero metrics. No seam is ever constructed.
            for phase in _PHASES_AFTER_SELECTION:
                with log_timed_phase(logger, phase, durations_ms=durations_ms):
                    pass
            self._record_metrics(counters)
            logger.info(
                "Effects stage complete for job %s: 0 candidates (no-op)",
                job.id,
                extra={"durations_ms": durations_ms},
            )
            return

        seams = self._make_seams(session, job)
        hash_resolver = self._hash_resolver(seams.chain_id)
        supported, block = self._preflight(seams, durations_ms)
        ctx = self._probe_context(seams, supported, block, counters)

        # cache_lookup → build the worklist, partition hits/misses/audits.
        with log_timed_phase(logger, "cache_lookup", durations_ms=durations_ms) as ph:
            items = self._plan(session, candidates, ctx, hash_resolver, counters)
            ph["planned"] = len(items)

        # tier1_probes / tier2_fork → run recipes for misses + audit re-runs.
        self._run_probes(items, durations_ms, counters, seams)

        # verdict_write → cache + state-plane persistence + §9 routing, then mint
        # proven verdicts into registry claims on the matching effective_functions
        # rows (§5.2 call site 1) — same job, same rows, same phase span so the
        # /monitor timeline gains no new stage.
        with log_timed_phase(logger, "verdict_write", durations_ms=durations_ms) as ph:
            self._write_verdicts(session, job, items, seams, counters)
            ph["verdicts_written"] = counters.verdicts_written
            ph["labeled"] = self._bridge_claims(session, items)

        self._record_metrics(counters)
        logger.info(
            "Effects stage complete for job %s: %d candidates, %d verdicts, "
            "%d hits (%dk/%dp), %d misses, %d discrepancies, %d new-idiom candidates",
            job.id,
            len(candidates),
            counters.verdicts_written,
            counters.cache_hits_kernel + counters.cache_hits_projection,
            counters.cache_hits_kernel,
            counters.cache_hits_projection,
            counters.cache_misses,
            counters.discrepancies_filed,
            counters.new_idiom_candidates,
            extra={"durations_ms": durations_ms},
        )

    # -- phase helpers -----------------------------------------------------

    def _select(self, session: Session, job: Job) -> list[Candidate]:
        protocol_id = getattr(job, "protocol_id", None)
        if not isinstance(protocol_id, int):
            # A contract job with no protocol has nothing to simulate against the
            # §6 cascade (it needs the protocol's balances/control graph). Not an
            # error — just an empty candidate set.
            return []
        return select_candidates(session, protocol_id, resource_cap=_resource_cap())

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
        )

    def _plan(
        self,
        session: Session,
        candidates: list[Candidate],
        ctx: ProbeContext,
        hash_resolver: HashResolver,
        counters: _Counters,
    ) -> list[_Item]:
        items: list[_Item] = []
        for cand in candidates:
            try:
                resolved = hash_resolver(session, cand)
            except Exception as exc:
                record_degraded(phase="effects_hash", exc=exc, context={"function_id": cand.function_id})
                counters.skipped += 1
                continue
            if resolved is None:
                # No behavioral hash (no cached bytecode) — withhold rather than
                # guess (per-behavior fail-forward, inv. 15).
                counters.skipped += 1
                continue
            kernel_hash, surface_hash = resolved
            try:
                plans = self.prober(session, cand, ctx)
            except Exception as exc:
                record_degraded(phase="effects_plan", exc=exc, context={"function_id": cand.function_id})
                counters.skipped += 1
                continue
            for plan in plans:
                behavior_hash = plan.behavior_hash or kernel_hash
                surface = surface_hash if plan.scope != SCOPE_KERNEL else ""
                cached = find_cached_verdict(
                    session,
                    behavior_hash=behavior_hash,
                    effect_class=plan.effect_class,
                    scope=plan.scope,
                    contract_surface_hash=surface,
                    gate_ref=plan.gate_ref,
                )
                # First re-encounter of a shared hash (writer left audit_status
                # None) triggers the §7 self-audit re-simulation.
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
        return items

    def _run_probes(self, items: list[_Item], durations_ms: dict[str, int], counters: _Counters, seams: _Seams) -> None:
        """Run recipes for cache misses + audit re-runs. Tier-2 (fork/projection)
        and Tier-1 are timed under their own phases. A per-behavior probe failure
        is caught here, recorded degraded, and the loop continues (inv. 15) — only
        a whole-stage infra failure escapes ``process()``."""
        tier1 = [it for it in items if it.scope == SCOPE_KERNEL and (it.cached is None or it.needs_audit)]
        tier2 = [it for it in items if it.scope != SCOPE_KERNEL and (it.cached is None or it.needs_audit)]

        with log_timed_phase(logger, "tier1_probes", durations_ms=durations_ms) as ph:
            for it in tier1:
                self._probe_one(it, counters)
            ph["probed"] = len(tier1)

        with log_timed_phase(logger, "tier2_fork", durations_ms=durations_ms) as ph:
            for it in tier2:
                self._probe_one(it, counters)
            ph["probed"] = len(tier2)
            ph["peak_anvil_rss_mb"] = counters.peak_anvil_rss_mb

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
            verdict, tier, transcript_ptr, details, concrete, discrepancy = self._resolve_item(session, it, counters)
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
                witness=details or None,
                transcript_ptr=transcript_ptr,
            )
            counters.verdicts_written += 1
            self._route_section9(it, verdict, tier, transcript_ptr, discrepancy, counters)

    def _bridge_claims(self, session: Session, items: list[_Item]) -> int:
        """§5.2 call site 1: fold this job's *proven* verdicts into registry claims
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

    def _resolve_item(
        self, session: Session, it: _Item, counters: _Counters
    ) -> tuple[str, str, str | None, dict[str, Any] | None, dict[str, Any] | None, Discrepancy | None]:
        """Turn one worklist item into its persisted verdict, applying the cache /
        self-audit rules (inv. 3 / §7)."""
        if it.cached is None:
            # MISS — the probe result is the verdict; write it to the code-plane cache.
            eff = it.probed
            if eff is None:
                # Probe failed (degraded already recorded) → fail-closed unknown,
                # NOT cached (a flake must not poison the shared cache).
                return VERDICT_UNKNOWN, TIER_CALL, None, None, None, None
            counters.cache_misses += 1
            if _is_cacheable(eff):
                self._cache_miss_write(session, it, eff, audit_status=None)
            return eff.verdict, eff.tier, eff.transcript_ptr, eff.details, eff.concrete, eff.discrepancy

        cached = it.cached
        if it.needs_audit:
            # §7 self-audit: compare the re-simulated kernel against the cached one.
            fresh = it.probed
            if fresh is None:
                # Could not re-simulate to audit → do not trust the unaudited hit.
                return self._withhold_collision(session, cached, it, counters, reason="audit_probe_failed")
            agree = kernel_verdicts_agree(cached.verdict, cached.details, fresh.verdict, fresh.details)
            mark_audited(session, cached, passed=agree, peer_hash=it.surface_hash or it.behavior_hash)
            if not agree:
                return self._withhold_collision(session, cached, it, counters, reason="kernel_hash_collision")
            bump_hit(session, cached)
            self._count_hit(it, counters)
            return cached.verdict, cached.tier, cached.transcript_ptr, cached.details, None, None

        if cached.audit_status == AUDIT_FAILED:
            # A previously-caught collision poisoned this key → never reuse it.
            return self._withhold_collision(session, cached, it, counters, reason="poisoned_cache_key")

        bump_hit(session, cached)
        self._count_hit(it, counters)
        return cached.verdict, cached.tier, cached.transcript_ptr, cached.details, None, None

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
            details=eff.details or None,
            audit_status=audit_status,
        )

    def _withhold_collision(
        self, session: Session, cached: EffectBehaviorCache, it: _Item, counters: _Counters, *, reason: str
    ) -> tuple[str, str, str | None, dict[str, Any] | None, dict[str, Any] | None, Discrepancy | None]:
        """A caught hash collision / poisoned key: withhold the cached verdict and
        file a §9 discrepancy. The cached verdict is NEVER propagated to this
        deployment."""
        disc = Discrepancy(
            kind=reason,
            effect_class=it.effect_class,
            detail={"behavior_hash": it.behavior_hash, "cached_verdict": cached.verdict},
        )
        return VERDICT_UNKNOWN, TIER_CALL, None, None, None, disc

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
        # Direction 2 (§9): a freshly-witnessed effect on a static-silent (blank)
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
        record_stage_metric("candidates_after_cascade", counters.candidates_after_cascade)
        record_stage_metric("cache_hits_kernel", counters.cache_hits_kernel)
        record_stage_metric("cache_hits_projection", counters.cache_hits_projection)
        record_stage_metric("cache_misses", counters.cache_misses)
        record_stage_metric("verdicts_written", counters.verdicts_written)
        record_stage_metric("discrepancies_filed", counters.discrepancies_filed)
        record_stage_metric("new_idiom_candidates", counters.new_idiom_candidates)
        record_stage_metric("upstream_requests", counters.upstream_requests)
        record_stage_metric("peak_anvil_rss_mb", counters.peak_anvil_rss_mb)

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
        """Fail-forward (inv. 15): the effects stage NEVER emits
        ``failed_terminal``. On retry exhaustion (or a terminal error) advance to
        ``coverage`` instead of killing a job whose upstream policy artifacts are
        already complete and correct — flag-off is otherwise strictly better than
        flag-on, which the whole stage must not be.

        Verdicts default to ``unknown`` (the §8 fail-closed value; per-behavior
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
