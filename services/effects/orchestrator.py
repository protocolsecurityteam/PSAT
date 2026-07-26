"""Per-candidate probe planning — the seam between selection and the harness.

The effects worker owns the *orchestration* (cache lookup/write with kernel-vs-
projection scope, the §7 self-audit, verdict persistence, §9 routing, metrics,
fail-forward). It delegates *what to probe for each candidate* to a ``Prober``
seam so the orchestration is testable end-to-end against stubs with recorded
transcripts (inv. 8) and the production recipe wiring stays swappable.

A :class:`ProbePlan` is one (effect-class, scope) unit of work for a candidate:
a ``run`` closure that executes the applicable Tier-1/Tier-2 recipe against the
injected seams and returns a tiered, transcripted
:class:`~services.effects.harness.ObservedEffect`. The plan does NOT carry the
behavioral hash — the worker stamps that from the candidate's resolved hashes so
kernel/projection cache scoping (inv. 3) lives in one place.

The default prober drives **code-upgrade** (Tier 0 indexed history + a
current-state check, §4.3/inv. 13) for proxy candidates, plus every class whose
concrete probe inputs :mod:`services.effects.calldata` can synthesize from the
static facts — value-out (§4.2), supply (§4.5), authority-change (§4.4) at Tier
1, and freeze/pause (§4.1) at Tier 2 when a fork transport is available.

Where the synthesizer returns nothing the prober emits NO plan for that class:
the recipes already fail closed on thin inputs, but a probe on guessed calldata
burns a simulation to learn nothing. So the plan set is exactly the set of
classes with real inputs, and everything else stays ``unknown``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Contract, UpgradeEvent
from services.effects import calldata as calldata_synth
from services.effects import recipes
from services.effects.anvil import AnvilTransport, pause_recipe
from services.effects.config import (
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_CODE_UPGRADE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
    SCOPE_PROJECTION,
)
from services.effects.harness import (
    CallBatch,
    ObservedEffect,
    SimContext,
    TranscriptStore,
    select_identities,
)
from services.effects.seeding import Seeder, SimulateSeeder, input_seeding_enabled
from services.effects.selection import Candidate
from services.effects.simulate import Simulate

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProbeContext:
    """Injected seams + per-chain context a prober runs against. Every wire is
    behind one of these callables so the orchestration is hermetic under test."""

    chain_id: int
    block: int
    hardfork: str
    simulate: Simulate
    simulate_supported: bool
    transcript_store: TranscriptStore
    call_batch: CallBatch | None = None
    anvil_factory: Callable[[], AnvilTransport] | None = None
    # Called with the number of upstream requests a probe issued, for the
    # §3-preflight sizing metric (best-effort; recipes that don't report leave 0).
    on_requests: Callable[[int], None] | None = None
    # Input-asset seeding seam. Left unset in production: the default is built
    # from ``simulate`` on first use and memoizes token identity + storage layout
    # for the WHOLE context, so a job's candidates share one discovery.
    seeder: Seeder | None = None
    _seeder_cache: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def sim_context(self) -> SimContext:
        return SimContext(chain_id=self.chain_id, block=self.block, hardfork=self.hardfork)

    def effective_seeder(self) -> Seeder | None:
        """The seeder Tier-1 probes retry through, or ``None`` (⇒ no seeding, the
        pre-seeding probe verbatim). Requires ``eth_simulateV1``: seeding is a
        state-override retry of the same block, with no Tier-2 equivalent."""
        if self.seeder is not None:
            return self.seeder
        if not self.simulate_supported or not input_seeding_enabled():
            return None
        cached = self._seeder_cache.get("seeder")
        if cached is None:
            cached = SimulateSeeder(self.simulate, chain_id=self.chain_id)
            self._seeder_cache["seeder"] = cached
        return cached


@dataclass
class ProbePlan:
    """One (effect-class, scope) unit of probe work for a candidate. ``run``
    executes the recipe (touching the injected seams) and returns the verdict.
    ``gate_ref`` names the gate *structure* (never an address — inv. 12)."""

    effect_class: str
    scope: str
    run: Callable[[], ObservedEffect]
    gate_ref: str = ""
    # Optional per-class hash override; when None the worker uses the candidate's
    # resolved (kernel_hash, surface_hash). Lets a prober key a class on a
    # narrower behavioral identity if it ever computes one.
    behavior_hash: str | None = None


# A Prober maps a candidate to its probe plans. Injected into the worker
# (default below); tests substitute a stub returning canned plans.
Prober = Callable[[Session, Candidate, ProbeContext], list[ProbePlan]]

# Resolves (kernel_hash, surface_hash) for a candidate, or None to skip it.
# Injected so tests control cache scoping (inv. 3) without real bytecode.
HashResolver = Callable[[Session, Candidate], "tuple[str, str] | None"]


# ---------------------------------------------------------------------------
# Default hash resolver — §7 bytecode fallback (sound; under-dedups)
# ---------------------------------------------------------------------------


def make_bytecode_hash_resolver(chain_id: int) -> HashResolver:
    """Build the default (kernel_hash, surface_hash) resolver for a chain.

    Uses the §7 item-2 fallback (metadata-stripped whole-runtime-bytecode +
    selector for the kernel; selectorless for the surface). Sound by construction —
    it can only *under*-dedup (distinct surfaces sharing a mixin kernel hash apart,
    costing extra sims), never transfer a verdict wrongly. The resolved-IR primary
    hash (§7 item 1) is a dedup optimization requiring live Slither IR and is not
    on the worker's cheap path; the fallback is always safe. Returns ``None`` when
    no runtime bytecode is cached for the deployment (the worker skips it,
    degraded — never guesses)."""
    from services.effects.hashing import bytecode_fallback_hash, contract_surface_hash

    def _resolve(session: Session, candidate: Candidate) -> tuple[str, str] | None:
        code = _runtime_bytecode(session, chain_id, candidate.contract_address)
        if not code:
            return None
        return bytecode_fallback_hash(code, candidate.selector), contract_surface_hash(code)

    return _resolve


def _runtime_bytecode(session: Session, chain_id: int, address: str) -> str | None:
    """Fetch a deployment's runtime bytecode from the ``bytecode_cache`` table
    (keyed ``(chain_id, address)``). DB-only (no wire) so hashing stays off the RPC
    path; a miss returns ``None`` and the candidate is skipped rather than guessed."""
    from db.models import BytecodeCache
    from services.effects.prefetch import get_prefetch

    pf = get_prefetch(session)
    addr = address.lower()
    if pf is not None and pf.chain_id == chain_id and addr in pf.addresses:
        return pf.bytecode_by_addr.get(addr)

    row = session.execute(
        select(BytecodeCache.bytecode).where(
            BytecodeCache.chain_id == chain_id,
            BytecodeCache.address == address.lower(),
        )
    ).scalar_one_or_none()
    return row if isinstance(row, str) and row else None


# ---------------------------------------------------------------------------
# Default prober — conservative, code-upgrade Tier-0 (§4.3 / inv. 13)
# ---------------------------------------------------------------------------


def default_prober(session: Session, candidate: Candidate, ctx: ProbeContext) -> list[ProbePlan]:
    """Build probe plans for one candidate: the Tier-0 code-upgrade plan plus one
    plan per class the synthesizer produced concrete inputs for.

    §5c: a claim-enrolled candidate (``restrict_families`` set) is only re-probed
    for its value/supply families — the code-upgrade probe is skipped so an
    already-explained flow/supply function is not re-simulated for upgradeability."""
    allow = candidate.restrict_families
    plans: list[ProbePlan] = []
    if allow is None or EFFECT_CLASS_CODE_UPGRADE in allow:
        plans += _code_upgrade_plans(session, candidate, ctx)
    return plans + _synthesized_plans(session, candidate, ctx)


def _code_upgrade_plans(session: Session, candidate: Candidate, ctx: ProbeContext) -> list[ProbePlan]:
    """§4.3 code-upgrade for proxy candidates: an indexed upgrade (Tier 0 history)
    discharges a present-tense capability claim only in conjunction with a
    current-state check (inv. 13). That check is a static/DB read (off the wire)
    and, per inv. 13, requires the capability be present NOW — BOTH the impl slot
    still non-zero AND a resolved, non-renounced upgrade authority. Freezing
    upgradeability does not zero the impl slot, so impl-non-zero alone would mint a
    false "upgradeable now" for a proxy whose authority was renounced; requiring a
    resolved principal closes that. A renounced/unset authority resolves to the
    zero address / empty set here (predicate_evaluator / solmate_roles), so an
    empty resolved set WITHHOLDS (fail-closed §8), never over-claims."""
    from services.effects.prefetch import get_prefetch

    pf = get_prefetch(session)
    plans: list[ProbePlan] = []
    if pf is not None and candidate.contract_id in pf.contract_ids:
        contract = pf.contract_by_id.get(candidate.contract_id)
    else:
        contract = session.execute(
            select(Contract).where(Contract.id == candidate.contract_id).limit(1)
        ).scalar_one_or_none()
    if contract is None or not contract.is_proxy:
        return plans

    if pf is not None and candidate.contract_id in pf.contract_ids:
        has_indexed_upgrade = candidate.contract_id in pf.contract_ids_with_upgrade
    else:
        has_indexed_upgrade = (
            session.execute(
                select(UpgradeEvent.id).where(UpgradeEvent.contract_id == candidate.contract_id).limit(1)
            ).scalar_one_or_none()
            is not None
        )
    if not has_indexed_upgrade:
        return plans

    zero = "0x" + "0" * 40
    impl = (contract.implementation or "").strip().lower()
    current_impl_nonzero = bool(impl) and impl != zero and impl != "0x0"
    # inv. 13 current-state check: a resolved, non-renounced upgrade authority must
    # ALSO be present now. A renounced/unset authority is the zero address / empty
    # set, so drop those before deciding the capability is live.
    resolved_principals = [p for p in candidate.principal_addresses if p and p.strip().lower() != zero]
    current_capability_present = current_impl_nonzero and len(resolved_principals) > 0
    principal = resolved_principals[0] if resolved_principals else None

    def _run() -> ObservedEffect:
        return recipes.code_upgrade(
            simulate=ctx.simulate,
            store=ctx.transcript_store,
            ctx=ctx.sim_context(),
            proxy_address=candidate.probe_target,
            principal=principal,
            upgrade_calldata="0x",
            sentinel_address="0x" + "ee" * 20,
            sentinel_override=None,
            impl_before=impl or None,
            indexed_upgrade=True,
            current_impl_nonzero=current_capability_present,
            gate_ref=_upgrade_gate_ref(contract),
        )

    plans.append(
        ProbePlan(
            effect_class=EFFECT_CLASS_CODE_UPGRADE,
            scope=SCOPE_KERNEL,
            run=_run,
            gate_ref=_upgrade_gate_ref(contract),
        )
    )
    return plans


def _upgrade_gate_ref(contract: Contract) -> str:
    """A gate-STRUCTURE descriptor (inv. 12) — the proxy pattern, never the admin
    address. Principal binding happens at read time via ``function_principals``."""
    return f"proxy:{(contract.proxy_type or 'unknown').lower()}"


# ---------------------------------------------------------------------------
# Synthesized plans — §4.2 / §4.4 / §4.5 (Tier 1) and §4.1 (Tier 2)
# ---------------------------------------------------------------------------


def _synthesized_plans(session: Session, candidate: Candidate, ctx: ProbeContext) -> list[ProbePlan]:
    """One plan per class the synthesizer produced inputs for. A class with thin
    facts yields no plan at all rather than a probe on guessed calldata."""
    inputs = calldata_synth.synthesize(session, candidate)
    plans: list[ProbePlan] = []
    if inputs.value_out is not None:
        plans.append(_value_out_plan(ctx, inputs.value_out))
    if inputs.supply is not None:
        plans.append(_supply_plan(ctx, inputs.supply))
    if inputs.authority is not None:
        plans.append(_authority_plan(ctx, candidate, inputs.authority))
    # Tier 2 needs the fork; with no anvil factory the pause class stays unknown
    # rather than degrading into a Tier-1 approximation that cannot see sequencing.
    if inputs.pause is not None and ctx.anvil_factory is not None:
        plans.append(_pause_plan(ctx, inputs.pause))
    return plans


def _value_out_plan(ctx: ProbeContext, spec: calldata_synth.ValueOutPlanInputs) -> ProbePlan:
    def _run() -> ObservedEffect:
        return recipes.value_out(
            simulate=ctx.simulate,
            store=ctx.transcript_store,
            ctx=ctx.sim_context(),
            contract_address=spec.contract_address,
            principal=spec.principal,
            calldata=spec.calldata,
            simulate_supported=ctx.simulate_supported,
            taint_param_reaches_sink=spec.taint_param_reaches_sink,
            sentinel_address=spec.sentinel_address,
            sentinel_calldata=spec.sentinel_calldata,
            value_holders=spec.value_holders,
            acting_balance_usd=spec.acting_balance_usd,
            gate_ref=spec.gate_ref,
            seeder=ctx.effective_seeder(),
            input_token_hints=spec.input_token_hints,
            token_param_indexes=spec.token_param_indexes,
            seeded_calldata=spec.seeded_calldata,
            seeded_sentinel_calldata=spec.seeded_sentinel_calldata,
            target_payable=spec.target_payable,
            native_payout=spec.native_payout,
            static_shape=spec.static_shape,
        )

    return ProbePlan(effect_class=EFFECT_CLASS_VALUE_OUT, scope=SCOPE_KERNEL, run=_run, gate_ref=spec.gate_ref)


def _supply_plan(ctx: ProbeContext, spec: calldata_synth.SupplyPlanInputs) -> ProbePlan:
    def _run() -> ObservedEffect:
        return recipes.supply(
            simulate=ctx.simulate,
            store=ctx.transcript_store,
            ctx=ctx.sim_context(),
            token_address=spec.token_address,
            principal=spec.principal,
            mint_calldata=spec.mint_calldata,
            simulate_supported=ctx.simulate_supported,
            taint_param_reaches_sink=spec.taint_param_reaches_sink,
            sentinel_address=spec.sentinel_address,
            sentinel_calldata=spec.sentinel_calldata,
            gate_ref=spec.gate_ref,
            seeder=ctx.effective_seeder(),
            input_token_hints=spec.input_token_hints,
            token_param_indexes=spec.token_param_indexes,
            seeded_calldata=spec.seeded_calldata,
            seeded_sentinel_calldata=spec.seeded_sentinel_calldata,
            target_payable=spec.target_payable,
            native_payout=spec.native_payout,
        )

    return ProbePlan(effect_class=EFFECT_CLASS_SUPPLY, scope=SCOPE_KERNEL, run=_run, gate_ref=spec.gate_ref)


def _authority_plan(ctx: ProbeContext, candidate: Candidate, spec: calldata_synth.AuthorityPlanInputs) -> ProbePlan:
    # Randoms are derived deterministically from (selector, contract) exactly as
    # the differential probe derives them, so a replay reuses the same identities.
    randoms, _ = select_identities(candidate.selector or "0x00000000", spec.contract_address, principal=spec.principal)

    def _run() -> ObservedEffect:
        return recipes.authority_change(
            simulate=ctx.simulate,
            store=ctx.transcript_store,
            ctx=ctx.sim_context(),
            contract_address=spec.contract_address,
            principal=spec.principal,
            mutate_calldata=spec.mutate_calldata,
            probe_calldata=spec.probe_calldata,
            randoms=randoms,
            gate_ref=spec.gate_ref,
        )

    return ProbePlan(effect_class=EFFECT_CLASS_AUTHORITY_CHANGE, scope=SCOPE_KERNEL, run=_run, gate_ref=spec.gate_ref)


def _pause_plan(ctx: ProbeContext, spec: calldata_synth.PausePlanInputs) -> ProbePlan:
    def _run() -> ObservedEffect:
        factory = ctx.anvil_factory
        if factory is None:  # pragma: no cover - guarded at plan time
            raise RuntimeError("pause plan requires an anvil factory")
        return pause_recipe(
            transport=factory(),
            store=ctx.transcript_store,
            ctx=ctx.sim_context(),
            contract_address=spec.contract_address,
            principal=spec.principal,
            pause_calldata=spec.pause_calldata,
            entry_points=spec.entry_points,
            predicted_guard_set=spec.predicted_guard_set,
            max_pause_duration=spec.max_pause_duration,
            gate_ref=spec.gate_ref,
            fixtures=spec.fixtures,
        )

    return ProbePlan(effect_class=EFFECT_CLASS_FREEZE_PAUSE, scope=SCOPE_PROJECTION, run=_run, gate_ref=spec.gate_ref)


# ---------------------------------------------------------------------------
# Plan-level convenience for a prober that already holds an ObservedEffect
# (used by tests to inject canned verdicts as one-shot plans).
# ---------------------------------------------------------------------------


def static_plan(effect: ObservedEffect, *, gate_ref: str = "", behavior_hash: str | None = None) -> ProbePlan:
    """Wrap an already-computed :class:`ObservedEffect` as a ProbePlan whose
    ``run`` just returns it. Convenience for stub probers."""
    return ProbePlan(
        effect_class=effect.effect_class,
        scope=effect.scope,
        run=lambda: effect,
        gate_ref=gate_ref or effect.gate_ref,
        behavior_hash=behavior_hash,
    )


__all__ = [
    "ProbeContext",
    "ProbePlan",
    "Prober",
    "HashResolver",
    "make_bytecode_hash_resolver",
    "default_prober",
    "static_plan",
]
