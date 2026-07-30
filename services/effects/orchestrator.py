"""Per-candidate probe planning — the seam between selection and the harness.

The effects worker owns the *orchestration* (cache lookup/write with kernel-vs-
projection scope, the self-audit, verdict persistence, discrepancy routing,
metrics, fail-forward). It delegates *what to probe for each candidate* to a
``Prober`` seam so the orchestration is testable end-to-end against stubs with
recorded transcripts and the production recipe wiring stays swappable.

A :class:`ProbePlan` is one (effect-class, scope) unit of work for a candidate:
a ``run`` closure that executes the applicable Tier-1/Tier-2 recipe against the
injected seams and returns a tiered, transcripted
:class:`~services.effects.harness.ObservedEffect`. The plan does NOT carry the
behavioral hash — the worker stamps that from the candidate's resolved hashes so
kernel/projection cache scoping lives in one place.

The default prober drives **code-upgrade** (Tier 0 indexed history + a
current-state check) for proxy candidates, plus every class whose concrete probe
inputs :mod:`services.effects.calldata` can synthesize from the static facts —
value-out, supply, authority-change at Tier 1, and freeze/pause at Tier 2 when a
fork transport is available.

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
from services.effects.anvil import AnvilTransport, pause_recipe, timelock_execute_recipe
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
    # preflight sizing metric (best-effort; recipes that don't report leave 0).
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
    ``gate_ref`` names the gate *structure* (never an address)."""

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
# Injected so tests control cache scoping without real bytecode.
HashResolver = Callable[[Session, Candidate], "tuple[str, str] | None"]


# ---------------------------------------------------------------------------
# Default hash resolver — bytecode fallback (sound; under-dedups)
# ---------------------------------------------------------------------------


def make_bytecode_hash_resolver(chain_id: int) -> HashResolver:
    """Build the default (kernel_hash, surface_hash) resolver for a chain.

    Uses the bytecode fallback (metadata-stripped whole-runtime-bytecode +
    selector for the kernel; selectorless for the surface). Sound by construction —
    it can only *under*-dedup (distinct surfaces sharing a mixin kernel hash apart,
    costing extra sims), never transfer a verdict wrongly. The resolved-IR primary
    hash is a dedup optimization requiring live Slither IR and is not
    on the worker's cheap path; the fallback is always safe. Returns ``None`` when
    no runtime bytecode is cached for the deployment (the worker skips it,
    degraded — never guesses)."""
    from services.effects.hashing import bytecode_fallback_hash, contract_surface_hash

    def _resolve(session: Session, candidate: Candidate) -> tuple[str, str] | None:
        address = _hashable_code_address(session, candidate)
        if address is None:
            return None
        code = _runtime_bytecode(session, chain_id, address)
        if not code:
            return None
        return bytecode_fallback_hash(code, candidate.selector), contract_surface_hash(code)

    return _resolve


def _hashable_code_address(session: Session, candidate: Candidate) -> str | None:
    """The address whose runtime bytecode may key this candidate's verdict, or ``None``.

    What makes bytecode hashing safe is the unstated
    invariant *"a proxy row never carries ``effective_functions``"* — true today (39
    proxy rows, 0 functions) and asserted by nothing: no constraint, no test, no
    comment. When it breaks, ``candidate.contract_address`` is a PROXY address and the
    bytecode at it is the forwarding STUB. The collisions that invariant holds back are
    real and measured: 16 colliding surface-hash groups over 323 mainnet
    ``bytecode_cache`` rows, 149 addresses inside a collision, largest group **15
    distinct implementations behind ONE hash** (``UUPSProxy`` — LiquidityPool, eETH,
    EtherFiNodesManager, weETH …). A verdict keyed on that hash — a Tier-1 code-upgrade
    result, or any projection-scope class keyed on the selectorless surface hash — is
    served to every unrelated implementation behind the same proxy pattern.

    So a proxy row's OWN bytecode is never hashed. Where the row names an
    implementation whose bytecode is cached, the hash keys on THAT (the behavior belongs
    to the code — the same principle ``Candidate.probe_target`` states from the other
    side: probe the deployment, hash the code). Where it does not, the answer is
    ``None`` and the worker takes its existing "skip, degraded, never guess" path.

    Not a blanket ``None`` for every proxy row, because the code-upgrade class is
    planned ONLY for proxy contract rows (``_code_upgrade_plans``), so a blanket
    refusal would make that class unplannable by construction rather than merely
    uncached. The implementation redirect keeps the
    class reachable while still never keying on a stub; the refusal remains for every
    proxy row that cannot be resolved to cached implementation code. (Local corpus: 0
    ``code_upgrade`` verdicts exist today, so neither variant changes a realised row —
    a lower bound, not a proof of harmlessness.)
    """
    contract = _contract_row(session, candidate.contract_id)
    if contract is None or not contract.is_proxy:
        return candidate.contract_address
    implementation = (contract.implementation or "").strip().lower()
    if not implementation or implementation in ("0x", "0x" + "0" * 40):
        logger.warning(
            "effects hash: contract row %s (%s) is a proxy with function rows and no resolved "
            "implementation — refusing to hash the forwarding stub (it collides across every "
            "implementation behind it) and skipping the candidate",
            candidate.contract_id,
            candidate.contract_address,
        )
        return None
    logger.info(
        "effects hash: contract row %s (%s) is a proxy carrying function rows — hashing its "
        "implementation %s instead of the forwarding stub",
        candidate.contract_id,
        candidate.contract_address,
        implementation,
    )
    return implementation


def _contract_row(session: Session, contract_id: int) -> Contract | None:
    """The candidate's ``contracts`` row, from the batch store when installed (the same
    source ``_code_upgrade_plans`` reads, so batched and unbatched planning agree)."""
    from services.effects.prefetch import get_prefetch

    pf = get_prefetch(session)
    if pf is not None and contract_id in pf.contract_ids:
        return pf.contract_by_id.get(contract_id)
    return session.execute(select(Contract).where(Contract.id == contract_id).limit(1)).scalar_one_or_none()


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
# Default prober — conservative, code-upgrade Tier-0
# ---------------------------------------------------------------------------


def default_prober(session: Session, candidate: Candidate, ctx: ProbeContext) -> list[ProbePlan]:
    """Build probe plans for one candidate: the Tier-0 code-upgrade plan plus one
    plan per class the synthesizer produced concrete inputs for.

    A claim-enrolled candidate (``restrict_families`` set) is only re-probed
    for its value/supply families — the code-upgrade probe is skipped so an
    already-explained flow/supply function is not re-simulated for upgradeability."""
    allow = candidate.restrict_families
    plans: list[ProbePlan] = []
    if allow is None or EFFECT_CLASS_CODE_UPGRADE in allow:
        plans += _code_upgrade_plans(session, candidate, ctx)
    return plans + _synthesized_plans(session, candidate, ctx)


def _code_upgrade_plans(session: Session, candidate: Candidate, ctx: ProbeContext) -> list[ProbePlan]:
    """Code-upgrade for proxy candidates: an indexed upgrade (Tier 0 history)
    discharges a present-tense capability claim only in conjunction with a
    current-state check. That check is a static/DB read (off the wire)
    and requires the capability be present NOW — BOTH the impl slot
    still non-zero AND a resolved, non-renounced upgrade authority. Freezing
    upgradeability does not zero the impl slot, so impl-non-zero alone would mint a
    false "upgradeable now" for a proxy whose authority was renounced; requiring a
    resolved principal closes that. A renounced/unset authority resolves to the
    zero address / empty set here (predicate_evaluator / solmate_roles), so an
    empty resolved set WITHHOLDS (fail-closed), never over-claims."""
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
    # Current-state check: a resolved, non-renounced upgrade authority must
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
    """A gate-STRUCTURE descriptor — the proxy pattern, never the admin
    address. Principal binding happens at read time via ``function_principals``."""
    return f"proxy:{(contract.proxy_type or 'unknown').lower()}"


# ---------------------------------------------------------------------------
# Synthesized plans — value-out / authority-change / supply (Tier 1) and freeze/pause (Tier 2)
# ---------------------------------------------------------------------------


def _synthesized_plans(session: Session, candidate: Candidate, ctx: ProbeContext) -> list[ProbePlan]:
    """One plan per class the synthesizer produced inputs for. A class with thin
    facts yields no plan at all rather than a probe on guessed calldata."""
    inputs = calldata_synth.synthesize(session, candidate)
    plans: list[ProbePlan] = []
    # A delayed executor gets the Tier-2 sequence INSTEAD of the Tier-1 probe, not
    # alongside it. Tier 1 cannot satisfy a ``block.timestamp`` gate at all, so its
    # row is a revert that reads as "we called it and it failed" while saying
    # nothing about the function; and both plans carry the same effect class,
    # scope and gate, so they would stage under one cache key. With no fork
    # available the Tier-1 plan stands exactly as it does today.
    timelocked = inputs.timelock is not None and ctx.anvil_factory is not None
    if inputs.value_out is not None and not timelocked:
        plans.append(_value_out_plan(ctx, inputs.value_out))
    if inputs.timelock is not None and ctx.anvil_factory is not None:
        plans.append(_timelock_plan(ctx, inputs.timelock))
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
            protocol_tvl_usd=spec.protocol_tvl_usd,
            gate_ref=spec.gate_ref,
            seeder=ctx.effective_seeder(),
            input_token_hints=spec.input_token_hints,
            token_param_indexes=spec.token_param_indexes,
            seeded_calldata=spec.seeded_calldata,
            seeded_sentinel_calldata=spec.seeded_sentinel_calldata,
            target_payable=spec.target_payable,
            native_payout=spec.native_payout,
            static_shape=spec.static_shape,
            inputs_vacuous=spec.inputs_vacuous,
            contract_holdings=spec.contract_holdings,
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
            inputs_vacuous=spec.inputs_vacuous,
            contract_holdings=spec.contract_holdings,
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


def _timelock_plan(ctx: ProbeContext, spec: calldata_synth.TimelockPlanInputs) -> ProbePlan:
    def _run() -> ObservedEffect:
        factory = ctx.anvil_factory
        if factory is None:  # pragma: no cover - guarded at plan time
            raise RuntimeError("timelock plan requires an anvil factory")
        transport = factory()
        # The delay belongs to the CONTRACT: OZ rejects a schedule below
        # its own ``getMinDelay()``, and the value differs per deployment. An
        # unreadable delay is not guessed — zero goes to the contract, whose own
        # check rejects it and whose revert the recipe records verbatim.
        delay = _uint_call(transport, spec.contract_address, spec.delay_calldata)
        return timelock_execute_recipe(
            transport=transport,
            store=ctx.transcript_store,
            ctx=ctx.sim_context(),
            contract_address=spec.contract_address,
            principal=spec.principal,
            schedule_calldata=spec.schedule_calldata(delay),
            execute_calldata=spec.execute_calldata,
            delay_seconds=delay,
            gate_ref=spec.gate_ref,
            fixtures=spec.fixtures,
            sentinel_address=spec.sentinel_address,
            witness_token=spec.witness_token,
            witness_calldata=spec.witness_calldata,
        )

    return ProbePlan(effect_class=EFFECT_CLASS_VALUE_OUT, scope=SCOPE_KERNEL, run=_run, gate_ref=spec.gate_ref)


def _uint_call(transport: AnvilTransport, to: str, data: str) -> int:
    """A uint read off the fork, or 0 when the call fails or returns nothing.
    Zero is not a fallback VALUE here — it is an input the contract itself
    rejects, which is the honest outcome for a delay we could not read."""
    try:
        result = transport.call({"to": to, "data": data})
    except Exception:
        return 0
    if not result.success or not result.return_data:
        return 0
    try:
        return int(result.return_data, 16)
    except ValueError:
        return 0


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
            duration_bound_source=spec.duration_bound_source,
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
