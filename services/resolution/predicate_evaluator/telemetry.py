"""Telemetry counters and context helpers for the predicate evaluator."""

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

# Delegated-role-gate durability telemetry (CONTROLLER_RESOLUTION_SPEC §5), keyed by callee signature so a new
# un-foldable role-store standard shows up as a new label (then add it to role_store_standards.py).
_GUARD_FIRE_COUNTS: "Counter[str]" = Counter()
_DELEGATED_GATE_UNRESOLVED_COUNTS: "Counter[str]" = Counter()


def _record_guard_fire(descriptor: Any) -> None:
    """The refine-only guard kept a delegated caller gate closed. Metric plus WARNING."""
    sig = descriptor.get("callee_signature") if isinstance(descriptor, dict) else None
    sig = sig if isinstance(sig, str) else "unknown"
    _GUARD_FIRE_COUNTS[sig] += 1
    record_stage_metric(f"inline_refine_only_guard::{sig}", _GUARD_FIRE_COUNTS[sig])
    logger.warning(
        "refine-only guard closed a delegated-gate fail-open",
        extra={"callee_signature": sig, "basis": "inline_refine_only_guard"},
    )


def _record_delegated_gate_unresolved(check: "ExternalCheck") -> None:
    """Durability tripwire: a caller gate settled ``external_check_only`` without a deferral. Metric only."""
    extra = check.extra or {}
    sig = extra.get("callee_signature")
    if not isinstance(sig, str):
        sig = check.target_call_selector if isinstance(check.target_call_selector, str) else "unknown"
    _DELEGATED_GATE_UNRESOLVED_COUNTS[sig] += 1
    record_stage_metric(f"delegated_gate_unresolved::{sig}", _DELEGATED_GATE_UNRESOLVED_COUNTS[sig])


def _bump_resolve_counter(outer_ctx: Any, key: str, n: int = 1) -> None:
    """Increment ``meta['resolve_counters']`` on the outer context; no-op when absent."""
    meta = getattr(outer_ctx, "meta", None)
    if not isinstance(meta, dict):
        return
    counters = meta.get("resolve_counters")
    if isinstance(counters, dict):
        counters[key] = counters.get(key, 0) + n


def _pass_live_read_memo(outer_ctx: Any) -> dict[Any, Any] | None:
    """The per-pass ``meta['live_read_memo']``, or None. Never persisted."""
    meta = getattr(outer_ctx, "meta", None)
    if not isinstance(meta, dict):
        return None
    memo = meta.get("live_read_memo")
    return memo if isinstance(memo, dict) else None


def _frame_is_inlined(ctx: "EvaluationContext") -> bool:
    """Whether we're inside an inlined call, where ``msg.sender`` is bound to an intermediate contract
    (``CallFrame.root`` leaves it None).
    """
    frame = getattr(ctx, "call_frame", None)
    return frame is not None and getattr(frame, "current_msg_sender", None) is not None


def _tag_caller_subject(cap: "CapabilityExpr", ctx: "EvaluationContext") -> "CapabilityExpr":
    """Tag a caller-authorization capability ``bound`` inside an inlined call, else ``root``, so combinators keep
    bound checks as side conditions.
    """
    cap.subject = "bound" if _frame_is_inlined(ctx) else "root"
    return cap


def _adapter_declined_external_set(cap: "CapabilityExpr") -> bool:
    """Whether an ``external_set`` adapter gave no concrete answer.

    An exact empty set is a real "nobody", not a decline.
    """
    return cap.kind in {"unsupported", "external_check_only"} or (
        cap.kind == "finite_set" and not cap.members and cap.membership_quality != "exact"
    )


def _adapter_deferred_pending_index(cap: "CapabilityExpr") -> bool:
    """Whether the decline is a tagged cold-index deferral (``check.extra.deferred_pending_index``).

    ``deferred_reconciler`` re-runs policy once the cursor catches up, but only if the marker survives, so such
    deferrals must not be overwritten by the inline probe.
    """
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
