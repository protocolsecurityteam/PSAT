"""Per-candidate probe planning: the seam between selection and the harness.

The effects worker owns orchestration (cache scoping, self-audit, persistence, discrepancy routing, metrics); it asks a
``Prober`` what to probe per candidate, so orchestration can be tested with stubs.

A :class:`ProbePlan` is one (effect class, scope) unit whose ``run`` executes a recipe and returns an
:class:`~services.effects.harness.ObservedEffect`. The worker stamps the behavioural hash so cache scoping lives in one
place.

The default prober plans code-upgrade (Tier 0 plus a current-state check) for proxies, plus every class
:mod:`services.effects.calldata` can synthesize inputs for (value-out, supply, authority-change at Tier 1; freeze/pause
at Tier 2 with a fork). Classes without real inputs get no plan and stay ``unknown``.
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
    BLOCK_SOURCE_INVOCATION_PIN,
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_CODE_UPGRADE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
    SCOPE_PROJECTION,
)
from services.effects.harness import (
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
    """Injected seams and per-chain context, so orchestration is hermetic under test."""

    chain_id: int
    block: int
    hardfork: str
    simulate: Simulate
    simulate_supported: bool
    transcript_store: TranscriptStore
    anvil_factory: Callable[[], AnvilTransport] | None = None
    # Unset in production: built from ``simulate`` on first use and memoized for the whole context.
    seeder: Seeder | None = None
    _seeder_cache: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def sim_context(self) -> SimContext:
        return SimContext(
            chain_id=self.chain_id,
            block=self.block,
            hardfork=self.hardfork,
            # The preflight pins one block per invocation and every Tier-1 probe uses it. An unpinnable head is ``0``
            # (Tier 1 disabled) and publishes nothing.
            block_source=BLOCK_SOURCE_INVOCATION_PIN if self.block > 0 else None,
        )

    def effective_seeder(self) -> Seeder | None:
        """The seeder Tier-1 probes retry through, or ``None`` (no seeding).

        Needs ``eth_simulateV1``; there's no Tier-2 equivalent.
        """
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
    """One (effect class, scope) unit of probe work. ``gate_ref`` names the gate structure, never an address."""

    effect_class: str
    scope: str
    run: Callable[[], ObservedEffect]
    gate_ref: str = ""
    # Per-class override; ``None`` uses the candidate's (kernel_hash, surface_hash).
    behavior_hash: str | None = None


Prober = Callable[[Session, Candidate, ProbeContext], list[ProbePlan]]

# (kernel_hash, surface_hash) for a candidate, or None to skip.
HashResolver = Callable[[Session, Candidate], "tuple[str, str] | None"]


def make_bytecode_hash_resolver(chain_id: int) -> HashResolver:
    """Default (kernel_hash, surface_hash) resolver for a chain.

    Uses metadata-stripped runtime bytecode (+ selector for the kernel). It can only under-dedup, never transfer a
    verdict wrongly; the resolved-IR hash needs live Slither and isn't on this path. ``None`` when no bytecode is cached
    (the worker skips, degraded).
    """
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
    """The address whose bytecode may key this candidate's verdict, or ``None``.

    Bytecode hashing is only safe while proxy rows carry no ``effective_functions`` (true today, but not enforced). If
    one did, the hashed code would be the forwarding stub, and stubs collide heavily (15 implementations behind one
    ``UUPSProxy`` hash), serving one verdict to unrelated implementations.

    So a proxy's own bytecode is never hashed: use its cached implementation's bytecode, else ``None`` (skip). Not a
    blanket ``None`` for proxies, since code-upgrade is only planned for proxy rows.
    """
    contract = _contract_row(session, candidate.contract_id)
    if contract is None or not contract.is_proxy:
        return candidate.contract_address
    implementation = (contract.implementation or "").strip().lower()
    if not implementation or implementation in ("0x", "0x" + "0" * 40):
        # No ``record_degraded`` here: the worker records the skip (capped); doing it here too would double entries.
        context = {
            "contract_id": candidate.contract_id,
            "contract_address": candidate.contract_address,
            "function_id": candidate.function_id,
        }
        logger.warning(
            "effects hash: proxy with function rows and no resolved implementation — refusing to hash the "
            "forwarding stub (it collides across every implementation behind it) and skipping the candidate",
            extra=context,
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
    """The candidate's ``contracts`` row, from the batch store when installed (same source as
    ``_code_upgrade_plans``).
    """
    from services.effects.prefetch import get_prefetch

    pf = get_prefetch(session)
    if pf is not None and contract_id in pf.contract_ids:
        return pf.contract_by_id.get(contract_id)
    return session.execute(select(Contract).where(Contract.id == contract_id).limit(1)).scalar_one_or_none()


def _runtime_bytecode(session: Session, chain_id: int, address: str) -> str | None:
    """Runtime bytecode from ``bytecode_cache`` (DB only, no wire); a miss skips the candidate."""
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


def default_prober(session: Session, candidate: Candidate, ctx: ProbeContext) -> list[ProbePlan]:
    """Probe plans for one candidate: Tier-0 code-upgrade plus one plan per synthesizable class.

    Claim-enrolled candidates (``restrict_families``) skip code-upgrade.
    """
    allow = candidate.restrict_families
    plans: list[ProbePlan] = []
    if allow is None or EFFECT_CLASS_CODE_UPGRADE in allow:
        plans += _code_upgrade_plans(session, candidate, ctx)
    return plans + _synthesized_plans(session, candidate, ctx)


def _code_upgrade_plans(session: Session, candidate: Candidate, ctx: ProbeContext) -> list[ProbePlan]:
    """Code-upgrade for proxies.

    Indexed history proves a present capability only with a current-state check (DB, off the wire): the impl slot is
    non-zero and a resolved, non-renounced upgrade authority exists. Freezing doesn't zero the slot, so the authority
    check prevents a false "upgradeable now"; renounced authorities resolve to zero/empty and withhold.
    """
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
    # Drop zero-address and empty principals before deciding the capability is live.
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
    """Gate structure (the proxy pattern), never the admin address."""
    return f"proxy:{(contract.proxy_type or 'unknown').lower()}"


def _synthesized_plans(session: Session, candidate: Candidate, ctx: ProbeContext) -> list[ProbePlan]:
    """One plan per class with synthesized inputs; thin facts get no plan."""
    inputs = calldata_synth.synthesize(session, candidate)
    plans: list[ProbePlan] = []
    # Delayed executors get the Tier-2 sequence instead of Tier 1: Tier 1 can't pass a timestamp gate (its revert says
    # nothing about F), and both plans would share a cache key. Without a fork, Tier 1 stands.
    timelocked = inputs.timelock is not None and ctx.anvil_factory is not None
    if inputs.value_out is not None and not timelocked:
        plans.append(_value_out_plan(ctx, inputs.value_out))
    if inputs.timelock is not None and ctx.anvil_factory is not None:
        plans.append(_timelock_plan(ctx, inputs.timelock))
    if inputs.supply is not None:
        plans.append(_supply_plan(ctx, inputs.supply))
    if inputs.authority is not None:
        plans.append(_authority_plan(ctx, candidate, inputs.authority))
    # Pause needs the fork; without it the class stays unknown.
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
            sentinel_param=spec.sentinel_param,
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
    # Deterministic randoms from (selector, contract), matching the differential probe, so replays reuse them.
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
        # The delay is the contract's own (OZ rejects below ``getMinDelay()``). Unreadable goes as zero, which the
        # contract rejects and the recipe records.
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
    """A uint read off the fork, or 0 on failure: an input the contract itself rejects, not a guessed value."""
    # The transcript doesn't exist yet, so only the log can record this.
    try:
        result = transport.call({"to": to, "data": data})
    except Exception as exc:
        logger.debug(
            "effects timelock: delay read failed, passing 0",
            extra={"contract_address": to, "reason": "call_raised", "exc_type": type(exc).__name__},
        )
        return 0
    if not result.success or not result.return_data:
        logger.debug(
            "effects timelock: delay read failed, passing 0",
            extra={"contract_address": to, "reason": "reverted" if not result.success else "empty_return"},
        )
        return 0
    try:
        return int(result.return_data, 16)
    except ValueError:
        logger.debug(
            "effects timelock: delay read failed, passing 0",
            extra={"contract_address": to, "reason": "unparseable_return"},
        )
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


# Convenience for injecting canned verdicts as one-shot plans (tests).


__all__ = [
    "ProbeContext",
    "ProbePlan",
    "Prober",
    "HashResolver",
    "make_bytecode_hash_resolver",
    "default_prober",
]
