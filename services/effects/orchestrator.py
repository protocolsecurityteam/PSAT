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

The default prober is deliberately conservative: it drives the one effect class
fully derivable from data the worker already holds — **code-upgrade** (Tier 0
indexed history + a current-state check, §4.3/inv. 13) — for proxy candidates.
The remaining classes need ABI-driven calldata / entry-point synthesis from the
effects-facts + predicate-tree artifacts; that derivation is the preview
follow-up (V1 is write-only, validated by the Appendix B preview cycle). Every
recipe fails closed on thin inputs, so a conservative prober is sound, never
wrong.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Contract, UpgradeEvent
from services.effects import recipes
from services.effects.anvil import AnvilTransport
from services.effects.config import (
    EFFECT_CLASS_CODE_UPGRADE,
    SCOPE_KERNEL,
)
from services.effects.harness import CallBatch, ObservedEffect, SimContext, TranscriptStore
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

    def sim_context(self) -> SimContext:
        return SimContext(chain_id=self.chain_id, block=self.block, hardfork=self.hardfork)


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
    """Build probe plans for one candidate.

    v1 drives the code-upgrade class for proxy candidates: an indexed upgrade
    (Tier 0 history) discharges a present-tense capability claim only in
    conjunction with a current-state check (inv. 13). The current check reads the
    statically-resolved implementation (non-zero ⇒ still upgradeable) — a DB read,
    keeping this off the wire. The other classes await ABI-driven calldata
    synthesis (documented preview follow-up)."""
    plans: list[ProbePlan] = []
    contract = session.execute(
        select(Contract).where(Contract.id == candidate.contract_id).limit(1)
    ).scalar_one_or_none()
    if contract is None or not contract.is_proxy:
        return plans

    has_indexed_upgrade = (
        session.execute(
            select(UpgradeEvent.id).where(UpgradeEvent.contract_id == candidate.contract_id).limit(1)
        ).scalar_one_or_none()
        is not None
    )
    if not has_indexed_upgrade:
        return plans

    impl = (contract.implementation or "").strip().lower()
    current_impl_nonzero = bool(impl) and impl != "0x" + "0" * 40 and impl != "0x0"
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None

    def _run() -> ObservedEffect:
        return recipes.code_upgrade(
            simulate=ctx.simulate,
            store=ctx.transcript_store,
            ctx=ctx.sim_context(),
            proxy_address=candidate.contract_address,
            principal=principal,
            upgrade_calldata="0x",
            sentinel_address="0x" + "ee" * 20,
            sentinel_override=None,
            impl_before=impl or None,
            indexed_upgrade=True,
            current_impl_nonzero=current_impl_nonzero,
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
