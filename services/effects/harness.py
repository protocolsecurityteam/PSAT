"""Tier-1 harness core (EFFECTS_RESOLUTION_SPEC §4 / §8).

The shared substrate every recipe (``services.effects.recipes`` Tier 1,
``services.effects.anvil`` Tier 2) builds on: the returned verdict/discrepancy
shapes, the identity-selection + raw-revert authorization discipline inherited
from ``differential_probe`` (§8.2/§8.3), and transcript emission through an
INJECTED store seam (§8.5 — ``transcript_ptr`` is an artifact key, never inline
JSONB).

Everything here is PURE given its injected seams (``call_batch`` /
``Simulate`` / the transcript store), so it runs against stubbed wires with
recorded transcripts in the offline suite (§8.6, inv. 8). No verdict is
DB-persisted here — Phase 3 wires selection → harness → persistence; the harness
only returns/emits :class:`ObservedEffect` objects.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from services.effects.config import (
    SCOPE_KERNEL,
    TIER_CALL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.resolution.differential_probe import (
    CallBatch,
    attribute,
    decode_error,
    derive_random_identities,
)
from utils.rpc import EthCallResult

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
# KEY (§8.5). Injected: the real impl wraps ``db.queue.store_artifact`` /
# nested-artifacts; the offline stub records the dict and hands back a fake key.
TranscriptStore = Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class SimContext:
    """Replay-minimum provenance stamped into every transcript (§8.5, inv. 14).

    ``hardfork`` is asserted/recorded for both Tier 1 and Tier 2; the anvil /
    foundry versions are Tier-2-only (empty for Tier 1) so a fork witness is
    reproducible across Dockerfile ``foundryup`` rebuilds (§8.7)."""

    chain_id: int
    block: int
    hardfork: str
    anvil_version: str | None = None
    foundry_version: str | None = None


@dataclass
class Discrepancy:
    """A §9 plane-disagreement object. Phase 2 RECORDS it on the verdict; it does
    NOT route it anywhere (Phase 3 owns the warning-channel routing + the
    closing-rule bookkeeping)."""

    kind: str
    effect_class: str
    detail: dict[str, Any] = field(default_factory=dict)
    transcript_ptr: str | None = None


@dataclass
class ObservedEffect:
    """A tiered, transcripted effect verdict returned by a recipe (§8.5, inv. 8).

    ``details`` is the code-plane structural witness (cacheable on the behavioral
    hash — supply-delta sign, destination *shape*, duration bound); ``concrete``
    is the state-plane residue (exact destination, exact impl, current-check
    result) that must never enter a cache key (inv. 3/12). Both are kept
    separate so Phase 3 can route each to its correct table.
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

    @property
    def is_proven(self) -> bool:
        return self.verdict == VERDICT_PROVEN


# ---------------------------------------------------------------------------
# Identity selection + authorization discipline (§8.2 / §8.3)
# ---------------------------------------------------------------------------


def select_identities(
    selector: str,
    contract_address: str,
    *,
    principal: str | None,
    random_count: int = 2,
) -> tuple[list[str], str | None]:
    """The impersonation set: ``random_count`` (≥2) deterministic random controls
    + the resolved principal (§8.2). Randoms are derived exactly as the
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
    after (§8.2). Uses the differential probe's :func:`attribute` on raw revert
    data (§8.3) in both directions; an ambiguous/split outcome is never "opened"
    (indeterminate ≠ public, fail-closed).

    This is the direction the authority-change kernel (§4.4) and any
    freeze-reversal check reads: a single-identity flip never opens anything.
    """
    if len(randoms_before) < 2 or len(randoms_after) < 2:
        return False
    before = attribute(randoms_before, None)
    after = attribute(randoms_after, None)
    # Before: consistently gated (all randoms rejected at the same gate).
    # After: open (every random succeeds). Anything else withholds.
    return before == "caller_rejected_consistent" and after == "not_caller_discriminating"


def same_gate(a: EthCallResult, b: EthCallResult) -> bool:
    """Two outcomes hit the SAME gate iff both revert with identical raw data
    (§8.3). Success≠revert are different; a node error (no revert data) is never
    "same" (unattributable → withhold)."""
    if a.success or b.success:
        return a.success and b.success
    if a.revert_data is None or b.revert_data is None:
        return False
    return a.revert_data == b.revert_data


# ---------------------------------------------------------------------------
# Transcript emission (§8.5)
# ---------------------------------------------------------------------------


def new_transcript(ctx: SimContext, *, feature: str, tier: str, effect_class: str) -> dict[str, Any]:
    """A transcript bounded to the replay minimum (§8.5): tier, forked block,
    hardfork, anvil/foundry version. ``calls``/``results`` are appended by
    :func:`record_calls` as the recipe issues them."""
    return {
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


def record_calls(
    transcript: dict[str, Any],
    calls: Sequence[dict[str, Any]],
    results: Sequence[Any],
    *,
    label: str = "",
) -> None:
    """Append issued calls + their raw results to the transcript. Revert data is
    kept raw; a decoded label is added for human replay only (never a verdict
    input — §8.3)."""
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
    """Persist the verdict's transcript through the injected store seam and stamp
    the artifact key (§8.5). No verdict ships without a replayable transcript
    (inv. 8) — a verdict whose transcript can't be stored keeps the in-memory
    ``transcript`` for the caller but a ``None`` ``transcript_ptr`` is a bug the
    §8-rule-5 test guards against."""
    if effect.transcript is not None:
        effect.transcript_ptr = store(effect.transcript)
        if effect.discrepancy is not None and effect.discrepancy.transcript_ptr is None:
            effect.discrepancy.transcript_ptr = effect.transcript_ptr
    return effect


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
    """The §8 fail-closed verdict for every non-observation. Never carries a
    proven positive; may carry a §9 discrepancy object (recorded, not routed)."""
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
