"""Per-resolution-pass memo of leaf evaluations.

An entry point and its effect-scope sites often hold the same leaf (``onlyRole(DEFAULT_ADMIN_ROLE)`` guards the
function and every site under it), and at one pinned block the same inputs give the same answer.
``resolve_contract_capabilities`` puts an empty dict under ``ctx.meta[PASS_MEMO]``; it is shared by every function,
site and inlined child context of that pass and discarded with it. Without it the helpers below just compute.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from typing import Any, Callable, TypeVar

PASS_MEMO = "leaf_memo"

T = TypeVar("T")


def _memo(ctx: Any) -> dict[Any, Any] | None:
    meta = getattr(ctx, "meta", None)
    memo = meta.get(PASS_MEMO) if isinstance(meta, dict) else None
    return memo if isinstance(memo, dict) else None


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def memoized(ctx: Any, key: tuple[Any, ...], compute: Callable[[], T], *, keep_alive: tuple[Any, ...] = ()) -> T:
    """``compute()`` once per pass for ``key``; every caller gets its own deep copy, since capabilities are mutable
    (``_tag_caller_subject`` rewrites ``subject`` in place).

    ``keep_alive`` holds objects whose ``id()`` is in ``key`` for the pass, so a later object can't reuse the id.
    """
    memo = _memo(ctx)
    if memo is None:
        return compute()
    if key in memo:
        _bump(ctx, "leaf_memo_hits")
        return copy.deepcopy(memo[key][0])
    value = compute()
    memo[key] = (copy.deepcopy(value), keep_alive)
    return value


def _bump(ctx: Any, name: str) -> None:
    meta = getattr(ctx, "meta", None)
    counters = meta.get("resolve_counters") if isinstance(meta, dict) else None
    if isinstance(counters, dict):
        counters[name] = counters.get(name, 0) + 1


def adapter_context_key(ctx: Any) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """``(key, keep_alive)`` covering everything an adapter reads from an ``adapters.EvaluationContext``.

    The call frame enters whole except ``current_function_signature``, so two functions share a leaf whose answer
    depends on no more than their selector; repos, session and RPC enter by identity (one per pass, also copied into
    inlined children); ``meta`` is the pass's configuration, copied into every child.
    """
    frame = getattr(ctx, "call_frame", None)
    frame_key: tuple[Any, ...] = ()
    if frame is not None:
        fields = [f.name for f in dataclasses.fields(frame) if f.name != "current_function_signature"]
        frame_key = tuple(canonical(getattr(frame, name)) for name in fields)
    shared = (
        getattr(ctx, "event_log_repo", None),
        getattr(ctx, "bytecode", None),
        getattr(ctx, "session", None),
        getattr(ctx, "recursive_resolver", None),
    )
    key = (
        getattr(ctx, "chain_id", None),
        getattr(ctx, "rpc_url", None),
        getattr(ctx, "block", None),
        getattr(ctx, "finality_depth", None),
        getattr(ctx, "contract_address", None),
        canonical(getattr(ctx, "state_var_values", None)),
        frame_key,
        tuple(id(obj) for obj in shared),
    )
    return key, shared
