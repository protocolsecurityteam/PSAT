"""Tier-1 harness core.

The shared substrate every recipe (``services.effects.recipes`` Tier 1,
``services.effects.anvil`` Tier 2) builds on: the returned verdict/discrepancy
shapes, the identity-selection + raw-revert authorization discipline inherited
from ``differential_probe``, and transcript emission through an
INJECTED store seam (``transcript_ptr`` is an artifact key, never inline JSONB).

Everything here is PURE given its injected seams (``call_batch`` /
``Simulate`` / the transcript store), so it runs against stubbed wires with
recorded transcripts in the offline suite. No verdict is
DB-persisted here: ``workers.effects_worker`` owns selection, persistence, and
discrepancy routing; ``services.effects.orchestrator`` builds the probe plans.
The harness returns/emits :class:`ObservedEffect` objects.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from services.clients.rpc import EthCallResult
from services.effects.config import (
    BLOCK_SOURCES,
    SCOPE_KERNEL,
    TIER_CALL,
    TIER_HISTORICAL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.resolution.differential_probe import (
    CallBatch,
    attribute,
    decode_error,
    derive_random_identities,
)

__all__ = [
    "CallBatch",
    "SimContext",
    "ObservedEffect",
    "Discrepancy",
    "TranscriptStore",
    "select_identities",
    "authorization_opened",
    "new_transcript",
    "record_calls",
    "emit",
    "proven",
    "unknown",
]

# A transcript store persists a bounded transcript dict and returns its artifact
# KEY. Injected: the real impl wraps ``db.queue.store_artifact`` /
# nested-artifacts; the offline stub records the dict and hands back a fake key.
TranscriptStore = Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class SimContext:
    """Replay-minimum provenance stamped into every transcript.

    ``hardfork`` is asserted/recorded for both Tier 1 and Tier 2; the anvil /
    foundry versions are Tier-2-only (empty for Tier 1) so a fork witness is
    reproducible across Dockerfile ``foundryup`` rebuilds."""

    chain_id: int
    block: int
    hardfork: str
    anvil_version: str | None = None
    foundry_version: str | None = None
    # PROVENANCE of ``block`` — one of :data:`config.BLOCK_SOURCES`, or ``None``
    # when the recorded height is not provably the height the probe ran at (an
    # unpinnable head, a fork spawned without ``--fork-block-number``). Only a
    # named source publishes the height as a witness; ``None`` publishes nothing.
    block_source: str | None = None


@dataclass
class Discrepancy:
    """A plane-disagreement object attached to the verdict.

    ``workers.effects_worker`` routes it through
    ``services.effects.discrepancies``, which records the closing rule."""

    kind: str
    effect_class: str
    detail: dict[str, Any] = field(default_factory=dict)
    transcript_ptr: str | None = None


@dataclass
class ObservedEffect:
    """A tiered, transcripted effect verdict returned by a recipe.

    ``details`` is the code-plane structural witness (cacheable on the behavioral
    hash — supply-delta sign, destination *shape*, duration bound); ``concrete``
    is the state-plane residue (exact destination, exact impl, current-check
    result) that must never enter a cache key. Both are kept
    separate so the effects worker can persist each to its correct table.
    """

    effect_class: str
    verdict: str  # VERDICT_PROVEN | VERDICT_UNKNOWN
    tier: str
    scope: str = SCOPE_KERNEL
    gate_ref: str = ""
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    concrete: dict[str, Any] = field(default_factory=dict)
    transcript: dict[str, Any] | None = None
    transcript_ptr: str | None = None
    discrepancy: Discrepancy | None = None
    # A verdict whose truth depends on per-probe STATE MANIPULATION this recipe
    # performed on the fork — a scheduled operation landing, time advancing — is
    # not a code-plane structural fact and must never transfer to a bytecode twin
    # on the behavioural hash (the same reason ``TIER_HISTORICAL`` never caches).
    # ``_is_cacheable`` refuses any verdict carrying this flag,
    # whatever its tier, scope, verdict or reason.
    state_dependent: bool = False

    @property
    def is_proven(self) -> bool:
        return self.verdict == VERDICT_PROVEN

    @property
    def witness_payload(self) -> dict[str, Any]:
        """What gets PERSISTED as the witness — ``details`` plus the reason.

        ``details`` alone does not identify the verdict: every unknown supply
        verdict carries ``{"observation": "executed"}``, so a sign WITHHELD
        because the arithmetic and the zero-address ``Transfer`` logs contradicted
        each other is byte-identical on the row to "supply did not move". The
        reason is code-plane (it is what ``_is_cacheable`` already keys the
        transfer decision on), so it travels with the verdict into the behavioral
        cache too and a twin that free-hits can still say why.
        """
        if not self.reason:
            return dict(self.details)
        return {**self.details, "reason": self.reason}


# ---------------------------------------------------------------------------
# Identity selection + authorization discipline
# ---------------------------------------------------------------------------


def select_identities(
    selector: str,
    contract_address: str,
    *,
    principal: str | None,
    random_count: int = 2,
) -> tuple[list[str], str | None]:
    """The impersonation set: ``random_count`` (≥2) deterministic random controls
    + the resolved principal. Randoms are derived exactly as the
    differential probe derives them, so replays reuse the same addresses and a
    curated-allowlist collision is astronomically unlikely."""
    randoms = derive_random_identities(selector, contract_address, max(2, random_count))
    return randoms, principal


def authorization_opened(
    randoms_before: Sequence[EthCallResult],
    randoms_after: Sequence[EthCallResult],
) -> bool:
    """Did a state change OPEN a gate to random callers? True only when ≥2
    distinct random identities were consistently REJECTED before and ALL SUCCEED
    after. Uses the differential probe's :func:`attribute` on raw revert
    data in both directions; an ambiguous/split outcome is never "opened"
    (indeterminate ≠ public, fail-closed).

    This is the direction the authority-change kernel and any
    freeze-reversal check reads: a single-identity flip never opens anything.
    """
    if len(randoms_before) < 2 or len(randoms_after) < 2:
        return False
    before = attribute(randoms_before, None)
    after = attribute(randoms_after, None)
    # Before: consistently gated (all randoms rejected at the same gate).
    # After: open (every random succeeds). Anything else withholds.
    return before == "caller_rejected_consistent" and after == "not_caller_discriminating"


# ---------------------------------------------------------------------------
# Transcript emission
# ---------------------------------------------------------------------------


def new_transcript(ctx: SimContext, *, feature: str, tier: str, effect_class: str) -> dict[str, Any]:
    """A transcript bounded to the replay minimum: tier, forked block,
    hardfork, anvil/foundry version. ``calls``/``results`` are appended by
    :func:`record_calls` as the recipe issues them."""
    tr = {
        "feature": feature,
        "version": 1,
        "tier": tier,
        "effect_class": effect_class,
        "chain_id": ctx.chain_id,
        "block_number": ctx.block,
        "hardfork": ctx.hardfork,
        "anvil_version": ctx.anvil_version,
        "foundry_version": ctx.foundry_version,
        "calls": [],
        "results": [],
    }
    # Tier 0 is excluded on purpose: it decides from an INDEXED event history plus
    # a current-state check (``observation: not_run``), so no single height is the
    # height it observed and ``ctx.block`` would be a bystander. Tier 1 simulates
    # at ``hex(block_number)`` and Tier 2 forks at it, so for those the recorded
    # height IS the observation — where the source says it was pinned.
    if ctx.block_source in BLOCK_SOURCES and tier != TIER_HISTORICAL and ctx.block > 0:
        tr["block_source"] = ctx.block_source
    return tr


def record_calls(
    transcript: dict[str, Any],
    calls: Sequence[dict[str, Any]],
    results: Sequence[Any],
    *,
    label: str = "",
) -> None:
    """Append issued calls + their raw results to the transcript. Revert data is
    kept raw; a decoded label is added for human replay only (never a verdict
    input)."""
    for call in calls:
        transcript["calls"].append({"label": label, **{k: _jsonable(v) for k, v in call.items()}})
    for res in results:
        transcript["results"].append(_result_dict(label, res))


def _result_dict(label: str, res: Any) -> dict[str, Any]:
    if isinstance(res, EthCallResult):
        return {
            "label": label,
            "success": res.success,
            "return_or_revert": res.return_data if res.success else res.revert_data,
            "decoded": None if res.success else decode_error(res.revert_data),
        }
    # Simulate call result (duck-typed to avoid a hard import cycle).
    success = getattr(res, "success", None)
    revert = getattr(res, "revert_data", None)
    return {
        "label": label,
        "success": success,
        "return_or_revert": getattr(res, "return_data", None) if success else revert,
        "decoded": None if success else decode_error(revert),
    }


def _jsonable(v: Any) -> Any:
    return v if isinstance(v, (str, int, float, bool)) or v is None else str(v)


def emit(store: TranscriptStore, effect: ObservedEffect) -> ObservedEffect:
    """Store a present transcript and stamp the returned artifact key.

    The store must return a replayable key; storage exceptions propagate.
    This helper leaves an absent transcript alone and does not validate the
    returned key. Recipe tests in ``tests/effects/test_effects_harness.py``
    assert that emitted verdicts carry a transcript pointer."""
    if effect.transcript is not None:
        effect.transcript_ptr = store(effect.transcript)
        if effect.discrepancy is not None and effect.discrepancy.transcript_ptr is None:
            effect.discrepancy.transcript_ptr = effect.transcript_ptr
    _stamp_observation_height(effect)
    return effect


def _stamp_observation_height(effect: ObservedEffect) -> None:
    """Copy the transcript's PROVEN observation height onto the verdict's witness.

    Every verdict already travels with a transcript, so this is the one place the
    height reaches ``effect_verdicts.witness`` — no recipe restates it and none can
    forget to. It publishes only what :func:`new_transcript` certified: a positive
    height AND a named pin scope. A failed head pin (``block`` is ``0``, the
    sentinel that reads as genesis), an unpinned fork, and a Tier-0 index read all
    arrive here with no ``block_source`` and leave BOTH keys absent — the
    not_determined state, never a fabricated or zero height.

    The pair is state-plane (:data:`db.effect_cache.DEPLOYMENT_PLANE_KEYS`): one
    deployment's observation height is not a property of the bytecode, so it must
    not ride the behavioral cache onto a twin.
    """
    tr = effect.transcript or {}
    block = tr.get("block_number")
    source = tr.get("block_source")
    if source not in BLOCK_SOURCES:
        return
    if isinstance(block, bool) or not isinstance(block, int) or block <= 0:
        return
    effect.details["block_number"] = block
    effect.details["block_source"] = source


# ---------------------------------------------------------------------------
# Verdict constructors
# ---------------------------------------------------------------------------


def proven(
    effect_class: str,
    *,
    tier: str = TIER_CALL,
    scope: str = SCOPE_KERNEL,
    gate_ref: str = "",
    reason: str = "",
    details: dict[str, Any] | None = None,
    concrete: dict[str, Any] | None = None,
    transcript: dict[str, Any] | None = None,
) -> ObservedEffect:
    return ObservedEffect(
        effect_class=effect_class,
        verdict=VERDICT_PROVEN,
        tier=tier,
        scope=scope,
        gate_ref=gate_ref,
        reason=reason,
        details=details or {},
        concrete=concrete or {},
        transcript=transcript,
    )


def unknown(
    effect_class: str,
    *,
    tier: str = TIER_CALL,
    scope: str = SCOPE_KERNEL,
    gate_ref: str = "",
    reason: str = "",
    details: dict[str, Any] | None = None,
    concrete: dict[str, Any] | None = None,
    transcript: dict[str, Any] | None = None,
    discrepancy: Discrepancy | None = None,
) -> ObservedEffect:
    """The fail-closed verdict for every non-observation. Never carries a
    proven positive; may carry a discrepancy object (recorded, not routed)."""
    return ObservedEffect(
        effect_class=effect_class,
        verdict=VERDICT_UNKNOWN,
        tier=tier,
        scope=scope,
        gate_ref=gate_ref,
        reason=reason,
        details=details or {},
        concrete=concrete or {},
        transcript=transcript,
        discrepancy=discrepancy,
    )
