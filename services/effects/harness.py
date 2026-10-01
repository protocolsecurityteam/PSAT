"""Tier-1 harness core.

Shared by every recipe: verdict and discrepancy shapes, identity selection and raw-revert authorization from
``differential_probe``, and transcript emission through an injected store (``transcript_ptr`` is an
artifact key). Pure given its seams; nothing is persisted here.
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

# Persists a bounded transcript and returns its artifact key.
TranscriptStore = Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class SimContext:
    """Replay provenance stamped into every transcript. ``hardfork`` for both tiers; anvil/foundry versions only
    for Tier 2.
    """

    chain_id: int
    block: int
    hardfork: str
    anvil_version: str | None = None
    foundry_version: str | None = None
    # One of :data:`config.BLOCK_SOURCES`, or ``None`` when the height isn't provably the probe's (unpinnable head,
    # unpinned fork); only a named source publishes the height.
    block_source: str | None = None


@dataclass
class Discrepancy:
    """A plane-disagreement, recorded on the verdict but not routed here."""

    kind: str
    effect_class: str
    detail: dict[str, Any] = field(default_factory=dict)
    transcript_ptr: str | None = None


@dataclass
class ObservedEffect:
    """A tiered, transcripted verdict.

    ``details`` is the code-plane witness (cacheable on the behavioural hash); ``concrete`` is state-plane residue that
    must never enter a cache key.
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
    # Verdicts depending on state the recipe manufactured (a scheduled op, a time warp) must never transfer to a twin;
    # ``_is_cacheable`` refuses them.
    state_dependent: bool = False

    @property
    def is_proven(self) -> bool:
        return self.verdict == VERDICT_PROVEN

    @property
    def witness_payload(self) -> dict[str, Any]:
        """What's persisted as the witness: ``details`` plus the reason.

        The reason distinguishes otherwise identical unknowns (e.g. a withheld contradicted sign vs no supply movement)
        and is code-plane, so it travels into the cache too.
        """
        if not self.reason:
            return dict(self.details)
        return {**self.details, "reason": self.reason}


def select_identities(
    selector: str,
    contract_address: str,
    *,
    principal: str | None,
    random_count: int = 2,
) -> tuple[list[str], str | None]:
    """The impersonation set: two or more deterministic random controls plus the resolved principal, derived
    as in the differential probe.
    """
    randoms = derive_random_identities(selector, contract_address, max(2, random_count))
    return randoms, principal


def authorization_opened(
    randoms_before: Sequence[EthCallResult],
    randoms_after: Sequence[EthCallResult],
) -> bool:
    """Did a state change open a gate to random callers? Only when at least two randoms were consistently rejected
    before and all succeed after, via :func:`attribute` on raw reverts. A single-identity flip never
    opens anything.
    """
    if len(randoms_before) < 2 or len(randoms_after) < 2:
        return False
    before = attribute(randoms_before, None)
    after = attribute(randoms_after, None)
    return before == "caller_rejected_consistent" and after == "not_caller_discriminating"


def new_transcript(ctx: SimContext, *, feature: str, tier: str, effect_class: str) -> dict[str, Any]:
    """A transcript with the replay minimum: tier, block, hardfork, anvil/foundry versions.

    Calls are appended by :func:`record_calls`.
    """
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
    # Tier 0 decides from indexed history, so no single height is its observation. Tiers 1 and 2 run at ``block``, so
    # it's recorded when the source says it was pinned.
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
    """Append issued calls and raw results. Decoded labels are for humans only."""
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
    # Duck-typed to avoid an import cycle.
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
    """Persist the transcript through the store and stamp the key.

    A missing ``transcript_ptr`` is a bug (every probed verdict needs a transcript).
    """
    if effect.transcript is not None:
        effect.transcript_ptr = store(effect.transcript)
        if effect.discrepancy is not None and effect.discrepancy.transcript_ptr is None:
            effect.discrepancy.transcript_ptr = effect.transcript_ptr
    _stamp_observation_height(effect)
    return effect


def _stamp_observation_height(effect: ObservedEffect) -> None:
    """Copy the transcript's proven height onto the witness.

    Only a positive height with a named pin scope from :func:`new_transcript`; failed pins, unpinned forks and Tier 0
    leave both keys absent. The pair is state-plane (:data:`db.effect_cache.DEPLOYMENT_PLANE_KEYS`), so never cached.
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
    """The fail-closed verdict for every non-observation; may carry a recorded discrepancy."""
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
