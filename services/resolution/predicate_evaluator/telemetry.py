"""Telemetry counters and small context helpers for the predicate evaluator."""

from __future__ import annotations

import logging
from collections import Counter
from typing import TYPE_CHECKING, Any

from utils.logging import record_stage_metric

from ..capabilities import (
    CapabilityExpr,
    ExternalCheck,
)

if TYPE_CHECKING:
    from .core import EvaluationContext

logger = logging.getLogger("services.resolution.predicate_evaluator")

# Telemetry for the delegated-role-gate durability invariant (CONTROLLER_RESOLUTION_
# SPEC §5): the guard closing a fail-open, and the broader tripwire of a caller gate
# that settles unresolved. Both keyed by callee signature so a NOVEL role-store
# standard the adapter can't yet fold shows up as a new label spiking — the one
# human link (add it to role_store_standards.py). Running counts folded into the
# policy stage's timing artifact via record_stage_metric (a no-op off-worker).
_GUARD_FIRE_COUNTS: "Counter[str]" = Counter()
_DELEGATED_GATE_UNRESOLVED_COUNTS: "Counter[str]" = Counter()


def _record_guard_fire(descriptor: Any) -> None:
    """The refine-only guard fired — a delegated caller gate that would have
    fail-open-published is kept closed. metric + WARNING so a regression (or a
    novel un-foldable standard) is loud, not just a silent metric bump."""
    sig = descriptor.get("callee_signature") if isinstance(descriptor, dict) else None
    sig = sig if isinstance(sig, str) else "unknown"
    _GUARD_FIRE_COUNTS[sig] += 1
    record_stage_metric(f"inline_refine_only_guard::{sig}", _GUARD_FIRE_COUNTS[sig])
    logger.warning(
        "refine-only guard closed a delegated-gate fail-open",
        extra={"callee_signature": sig, "basis": "inline_refine_only_guard"},
    )


def _record_delegated_gate_unresolved(check: "ExternalCheck") -> None:
    """Durability tripwire: a caller gate settled ``external_check_only`` without a
    pending-index deferral — resolved-unknown for good (guard-fired, adapter
    decline, or a bare external check). A metric only; the guard's WARNING is the
    loud arm, this is the queryable count per callee signature."""
    extra = check.extra or {}
    sig = extra.get("callee_signature")
    if not isinstance(sig, str):
        sig = check.target_call_selector if isinstance(check.target_call_selector, str) else "unknown"
    _DELEGATED_GATE_UNRESOLVED_COUNTS[sig] += 1
    record_stage_metric(f"delegated_gate_unresolved::{sig}", _DELEGATED_GATE_UNRESOLVED_COUNTS[sig])


def _bump_resolve_counter(outer_ctx: Any, key: str, n: int = 1) -> None:
    """Increment a resolve-level work-volume counter on the outer
    EvaluationContext's ``meta['resolve_counters']`` (wired by the capability
    resolver). No-op when absent, so unit evaluations and the pure-week-4 path
    are untouched. Surfaces redundant work (live getter eth_calls, cross-contract
    inline recursions, HyperSync fallback scans) on the per-job
    ``capability_summary`` without per-RPC latency noise."""
    meta = getattr(outer_ctx, "meta", None)
    if not isinstance(meta, dict):
        return
    counters = meta.get("resolve_counters")
    if isinstance(counters, dict):
        counters[key] = counters.get(key, 0) + n


def _pass_live_read_memo(outer_ctx: Any) -> dict[Any, Any] | None:
    """The contract-scoped ``meta['live_read_memo']`` (wired by the capability resolver), or None when absent
    — leaving unit evaluations and the pure-week-4 path un-memoized. Scoped to the contract's resolution
    frame, so it is discarded when the pass ends; never a cross-run/persistent cache."""
    meta = getattr(outer_ctx, "meta", None)
    if not isinstance(meta, dict):
        return None
    memo = meta.get("live_read_memo")
    return memo if isinstance(memo, dict) else None


def _frame_is_inlined(ctx: "EvaluationContext") -> bool:
    """True when we're resolving inside an inlined cross-contract call — the frame's
    ``msg.sender`` has been bound to a concrete intermediate contract (the caller of
    the downstream call), so a caller-authorization leaf evaluated here constrains
    that intermediate, NOT the function's end-user caller. ``CallFrame.root`` leaves
    ``current_msg_sender`` None (symbolic root caller)."""
    frame = getattr(ctx, "call_frame", None)
    return frame is not None and getattr(frame, "current_msg_sender", None) is not None


def _tag_caller_subject(cap: "CapabilityExpr", ctx: "EvaluationContext") -> "CapabilityExpr":
    """Mark a freshly-resolved caller-authorization capability with the dimension it
    constrains: ``bound`` inside an inlined downstream call (subject = the frame-bound
    intermediate contract), else ``root`` (the end-user caller). The combinators in
    ``capabilities.py`` use this to keep a bound check as a side-condition rather than
    set-intersecting it into the end-user principal set (which would zero it)."""
    cap.subject = "bound" if _frame_is_inlined(ctx) else "root"
    return cap


def _adapter_declined_external_set(cap: "CapabilityExpr") -> bool:
    """True when an ``external_set`` adapter produced no concrete answer — unsupported,
    a query-only external check, or the empty non-exact placeholder of the null adapter.
    An *exact* empty set is a real ``nobody`` and is NOT a decline."""
    return cap.kind in {"unsupported", "external_check_only"} or (
        cap.kind == "finite_set" and not cap.members and cap.membership_quality != "exact"
    )


def _adapter_deferred_pending_index(cap: "CapabilityExpr") -> bool:
    """True when an adapter's decline is a *cold durable-index* deferral it has tagged
    for self-heal (``check.extra.deferred_pending_index``): the authority's events
    aren't backfilled yet, so the exact caller set becomes recoverable once they are.

    Distinct from a settled decline (``unsupported`` / a warm authority that emitted no
    role events). ``deferred_reconciler`` re-enqueues the owning job's policy stage once
    the cursor reaches head — but ONLY if this marker survives into the persisted
    ``capability_expr``. So the external_set path must preserve such a deferral verbatim
    and NOT overwrite it with the inline cross-contract probe / event-candidate
    materializer: that live probe is a non-self-healing heuristic that drops the marker
    and freezes the cold result (the Veda RolesAuthority cold-start race)."""
    return (
        cap.kind == "external_check_only"
        and cap.check is not None
        and bool((cap.check.extra or {}).get("deferred_pending_index"))
    )


def _state_var_lookup_key(operand: dict[str, Any]) -> str | None:
    name = operand.get("state_variable_name")
    if not isinstance(name, str) or not name:
        return None
    member_path = operand.get("member_path")
    if isinstance(member_path, list) and member_path:
        parts = [part for part in member_path if isinstance(part, str) and part]
        if parts:
            return ".".join([name, *parts])
    return name


def _is_zero_address(value: str) -> bool:
    return value.lower() == "0x" + "0" * 40
