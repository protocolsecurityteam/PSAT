"""Enumerable role-store adapter: resolves a delegated ``registry.onlyX(msg.sender)`` gate to its controllers without
parsing role names.

1. Fold the standard's grant/revoke events at the authority proxy into a candidate universe (every current role holder),
plus the registry's own owner/admin values for hybrid gates. The durable index drives cold/warm lifecycle.
2. Probe the gate at a pinned block: a negative control that must revert, then each candidate. The gate is its own
ground truth, so false positives are impossible.
3. Optionally cross-check the enumerable getter; a mismatch declines.

Probe transport failures are indeterminate and decline to ``probe_unavailable``. Cold index defers via
``deferred_reconciler``; warm with no events settles unconfirmed. New standards are recognized only in
``role_store_standards.py``.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Any, TypeGuard

from services.clients.rpc import encode_address_word, multicall3_aggregate3, rpc_request
from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from utils.logging import record_stage_metric
from utils.scoring_status import TRACE_STEP_ENUMERABLE_ROLE_STORE

from ..capabilities import CapabilityExpr, ExternalCheck
from ..event_tail import scan_event_tail
from ..repos.event_logs_pg import UNDECODABLE_EVENT_DATA, UndecodableEventRow, _cursor_covers_block
from ..role_store_standards import (
    GetterSpec,
    RoleStoreStandard,
    resolve_probe_code,
    resolve_standard,
    spec_by_topic0,
)
from . import EvaluationContext

logger = logging.getLogger(__name__)

_ZERO_ADDRESS = "0x" + "0" * 40
# A gate that passes this isn't an allowlist; never reported as a member.
_NEGATIVE_CONTROL_ADDR = "0x" + "de1e7e" + "00" * 17


_MATCH_SCORE = 90

# Cold, or warm but behind the pinned block with no complete tail.
_INDEX_WAIT_BASES = frozenset({"no_index_cursor", "cursor_behind_block"})


# Settled declines are only observable here (the persisted basis is superseded downstream), so count them per reason.
_ADAPTER_DECLINE_REASONS = {
    "negative_control_passed",
    "role_fold_getter_mismatch",
    "probe_unavailable",
    "no_candidate_passed_gate",
    "registry_context_error",
}
_DECLINE_COUNTS: "Counter[str]" = Counter()


def _getter_crosscheck_enabled() -> bool:
    return os.getenv("PSAT_ROLE_STORE_GETTER_CROSSCHECK", "0").lower() in {"1", "true", "yes", "on"}


class EnumerableRoleStoreAdapter:
    """Resolves a delegated single-address-param role gate by folding role events and confirming each candidate
    against the live gate.
    """

    @classmethod
    def matches(cls, descriptor: dict, ctx: EvaluationContext) -> int:
        # Structural check before any wire call.
        if not isinstance(descriptor, dict) or descriptor.get("kind") != "external_set":
            return 0
        if not _is_single_address_param_signature(descriptor.get("callee_signature")):
            return 0
        if not _has_caller_key_source(descriptor):
            return 0
        authority = _resolve_authority_address(descriptor, ctx)
        if authority is None:
            return 0
        standard = _detect_standard(authority, ctx)
        return _MATCH_SCORE if standard is not None else 0

    @classmethod
    def supports_external_check_only(cls) -> bool:
        return True

    def enumerate(self, descriptor: dict, ctx: EvaluationContext) -> CapabilityExpr:
        authority = _resolve_authority_address(descriptor, ctx)
        callee_selector = _resolve_callee_selector(descriptor)
        repo = ctx.event_log_repo
        iter_rows = getattr(repo, "iter_event_rows", None) if repo is not None else None
        min_indexed = getattr(repo, "min_indexed_block", None) if repo is not None else None

        basis: list[str] = []
        if authority is None:
            basis.append("authority_unresolved")
        if callee_selector is None:
            basis.append("selector_unresolved")
        if iter_rows is None or min_indexed is None:
            basis.append("no_event_log_repo")
        if authority is None or callee_selector is None or iter_rows is None or min_indexed is None:
            return _check_only(authority, callee_selector, basis)

        standard = _detect_standard(authority, ctx)
        if standard is None:
            return _check_only(authority, callee_selector, ["standard_undetected"])

        topic0s = list(standard.topic0s())
        # Cold index: defer so the reconciler re-resolves after backfill; a live probe now would freeze a lower bound.
        # Checked before pinning so it works without RPC.
        try:
            cursor_block = min_indexed(chain_id=ctx.chain_id, event_address=authority, topic0s=topic0s)
        except Exception:
            return _check_only(authority, callee_selector, ["event_log_backend_error"])
        if cursor_block is None:
            return _check_only(authority, callee_selector, ["no_index_cursor"])

        rpc_url = ctx.rpc_url
        if not rpc_url:
            return _check_only(authority, callee_selector, ["no_rpc_for_probe"])
        # One height for fold, probe and trace frontier, so the result is reproducible and drift detection has a fixed
        # frontier. An unpinned pass reads head once; failure settles to probe_unavailable.
        pinned_block = _pin_probe_block(ctx, rpc_url)
        if pinned_block is None:
            return _check_only(authority, callee_selector, ["probe_unavailable"])

        scan_window: dict[str, Any] | None = None
        try:
            if _cursor_covers_block(cursor_block, pinned_block):
                rows = list(
                    iter_rows(chain_id=ctx.chain_id, event_address=authority, topic0s=topic0s, block=pinned_block)
                )
            else:
                # A grant in (cursor, pin] would leave its holder out of the candidate universe the probe tests. An
                # unpinned pass's head read is not a confirmed height to complete a fold to.
                if not isinstance(ctx.block, int):
                    return _check_only(authority, callee_selector, ["cursor_behind_block"])
                memo = _pass_memo(ctx)
                tail_key = ("role_store_tail", ctx.chain_id, authority, tuple(topic0s), cursor_block, pinned_block)
                scan = memo.get(tail_key)
                if scan is None:
                    scan = scan_event_tail(
                        rpc_url=rpc_url,
                        chain_id=ctx.chain_id,
                        event_address=authority,
                        topic0s=topic0s,
                        frontier=cursor_block,
                        block=pinned_block,
                    )
                    if scan.complete:
                        memo[tail_key] = scan
                if not scan.complete:
                    return _check_only(authority, callee_selector, ["cursor_behind_block"])
                durable = iter_rows(chain_id=ctx.chain_id, event_address=authority, topic0s=topic0s, block=cursor_block)
                rows = [*durable, *scan.logs]
                scan_window = scan.trace_fields()
        except UndecodableEventRow:
            return _check_only(authority, callee_selector, [UNDECODABLE_EVENT_DATA])
        except Exception:
            return _check_only(authority, callee_selector, ["event_log_backend_error"])
        if not rows:
            # Warm with no role events: can't confirm the store speaks this standard, so exact-empty would be a false
            # "nobody".
            return _check_only(authority, callee_selector, ["authority_unconfirmed_no_role_events"])

        active_holders = _fold_active_holders(rows)
        registry_context = _registry_controller_context(ctx, authority)
        if registry_context is None:
            # A DB error isn't "no candidates" (R1): a shrunken universe would shrink the survivors.
            return _check_only(authority, callee_selector, ["registry_context_error"])
        controller_addrs, role_labels = registry_context
        candidates = sorted(active_holders | controller_addrs)

        probe = _probe_gate(
            rpc_url=rpc_url,
            authority=authority,
            callee_selector=callee_selector,
            candidates=candidates,
            block=pinned_block,
            memo=_pass_memo(ctx),
        )
        if probe.transport_failed:
            # Transport failure is indeterminate, not non-membership.
            return _check_only(authority, callee_selector, ["probe_unavailable"])
        if probe.control_passed:
            # The gate passed a random address: not an allowlist.
            return _check_only(authority, callee_selector, ["negative_control_passed"])

        members = sorted(probe.survivors)
        if not members and candidates:
            # Zero survivors over a non-empty universe means either an unheld role or a gate admitting non-role callers
            # (e.g. ``msg.sender == liquidityPool``); indistinguishable, so decline. An empty universe from a complete
            # fold stays exact-empty below.
            return _check_only(authority, callee_selector, ["no_candidate_passed_gate"])

        if _getter_crosscheck_enabled() and standard.enumerable_getter is not None:
            mismatch = _getter_crosscheck(
                rpc_url=rpc_url,
                authority=authority,
                getter=standard.enumerable_getter,
                roles=_active_roles(rows),
                fold_holders=active_holders,
                block=pinned_block,
            )
            if mismatch:
                return _check_only(authority, callee_selector, ["role_fold_getter_mismatch"])

        trace = [
            {
                "step": TRACE_STEP_ENUMERABLE_ROLE_STORE,
                "authority": authority,
                "standard": standard.name,
                "callee_selector": callee_selector,
                "probe_block": pinned_block,
                # The fold's coverage height, for re-resolving when a later grant/revoke is indexed: the least-advanced
                # cursor, or the pin when a tail completed the fold past it.
                "fold_frontier": max(cursor_block, pinned_block),
                "candidate_count": len(candidates),
                "candidates_from_events": sorted(active_holders),
                "candidates_from_controllers": sorted(controller_addrs),
                "role_labels": role_labels,
                **(scan_window or {}),
            }
        ]
        logger.debug(
            "enumerable_role_store decision",
            extra={
                "adapter": TRACE_STEP_ENUMERABLE_ROLE_STORE,
                "address": authority,
                "decision": "finite_set",
                "reason": "gate_probe_confirmed",
                "members": len(members),
                "candidates": len(candidates),
            },
        )
        return CapabilityExpr.finite_set(
            members,
            quality="exact",
            confidence="enumerable",
            last_indexed_block=max(cursor_block, pinned_block) if scan_window else cursor_block,
            trace=trace,
        )


class _ProbeResult:
    __slots__ = ("survivors", "control_passed", "transport_failed")

    def __init__(self, survivors: set[str], control_passed: bool, transport_failed: bool) -> None:
        self.survivors = survivors
        self.control_passed = control_passed
        self.transport_failed = transport_failed


def _probe_gate(
    *,
    rpc_url: str,
    authority: str,
    callee_selector: str,
    candidates: list[str],
    block: int | None,
    memo: dict[Any, Any],
) -> _ProbeResult:
    """Which candidates the gate passes at ``block``, plus the negative control, in one Multicall3 (the address is an
    argument, so sender rewriting is harmless). Memoized per ``(authority, selector, block)`` for the whole
    function family. A whole-call failure is ``transport_failed``, distinct from a per-candidate revert.
    """
    key = ("role_store_probe", authority, callee_selector, block)
    cached = memo.get(key)
    if isinstance(cached, _ProbeResult):
        # Stable per (authority, selector, block), and the candidate list is identical across the family.
        return cached

    calls: list[tuple[str, str]] = [(authority, callee_selector + encode_address_word(_NEGATIVE_CONTROL_ADDR))]
    calls += [(authority, callee_selector + encode_address_word(cand)) for cand in candidates]
    block_tag = hex(block) if isinstance(block, int) else "latest"
    try:
        results = multicall3_aggregate3(rpc_url, calls, block_tag=block_tag)
    except Exception:
        # Not memoized, so one blip doesn't settle the whole family.
        return _ProbeResult(set(), control_passed=False, transport_failed=True)
    if len(results) != len(calls):
        return _ProbeResult(set(), control_passed=False, transport_failed=True)

    control_passed = bool(results[0][0])
    survivors = {cand for cand, (ok, _data) in zip(candidates, results[1:]) if ok}
    result = _ProbeResult(survivors, control_passed=control_passed, transport_failed=False)
    memo[key] = result
    return result


def _getter_crosscheck(
    *,
    rpc_url: str,
    authority: str,
    getter: GetterSpec,
    roles: set[str],
    fold_holders: set[str],
    block: int | None,
) -> bool:
    """True when the event fold and the enumerable getter disagree (``count``/``at`` per active role).

    Transport failure counts as no alarm.
    """
    block_tag = hex(block) if isinstance(block, int) else "latest"
    getter_holders: set[str] = set()
    try:
        count_calls = [(authority, getter.count_selector + _role_word(role)) for role in sorted(roles)]
        if not count_calls:
            return False
        counts = multicall3_aggregate3(rpc_url, count_calls, block_tag=block_tag)
        at_calls: list[tuple[str, str]] = []
        for role, (ok, data) in zip(sorted(roles), counts):
            if not ok:
                continue
            n = _word_int(data)
            for i in range(min(n, 512)):
                at_calls.append((authority, getter.at_selector + _role_word(role) + _uint_word(i)))
        if at_calls:
            at_results = multicall3_aggregate3(rpc_url, at_calls, block_tag=block_tag)
            for ok, data in at_results:
                if not ok:
                    continue
                addr = _word_to_address(data)
                if addr is not None:
                    getter_holders.add(addr)
    except Exception:
        return False
    return getter_holders != fold_holders


def _fold_active_holders(rows: Any) -> set[str]:
    """Fold grant/revoke rows (log order) into the set of current holders of any role, last-write-wins per (holder,
    role).
    """
    specs = spec_by_topic0()
    state: dict[tuple[str, str], bool] = {}
    for row in rows:
        topics = list(getattr(row, "topics", None) or [])
        if not topics:
            continue
        spec = specs.get(str(topics[0]).lower())
        if spec is None:
            continue
        holder = _topic_address(topics, spec.holder_topic_index)
        role = _topic_word(topics, spec.role_topic_index)
        if holder is None or role is None:
            continue
        if spec.active_topic_index is not None:
            active = _topic_bool(topics, spec.active_topic_index)
        else:
            active = bool(spec.active_when)
        state[(holder, role)] = active
    return {holder for (holder, _role), active in state.items() if active}


def _active_roles(rows: Any) -> set[str]:
    specs = spec_by_topic0()
    roles: set[str] = set()
    for row in rows:
        topics = list(getattr(row, "topics", None) or [])
        if not topics:
            continue
        spec = specs.get(str(topics[0]).lower())
        if spec is None:
            continue
        role = _topic_word(topics, spec.role_topic_index)
        if role is not None:
            roles.add(role)
    return roles


def _registry_controller_context(ctx: EvaluationContext, authority: str) -> tuple[set[str], dict[str, str]] | None:
    """The registry's address-typed controller values (unioned into candidates for hybrid gates) plus a role-hash →
    name map for display only.

    Chain-scoped: a bare address lookup could resolve another chain's registry to the Ethereum row. NULL
    ``contracts.chain`` means mainnet (as in ``services.discovery.upgrade_history``).

    Returns ``None`` on any error (R1: not an empty set). A ctx with no session returns empties.
    """
    session = getattr(ctx, "session", None)
    if session is None:
        return set(), {}
    try:
        from sqlalchemy import func, or_, select

        from db.models import Contract, ControllerValue
        from utils.chains import chain_by_id

        chain_name = chain_by_id(ctx.chain_id).name

        def _chain_scoped(address_predicate: Any) -> Any:
            return address_predicate & (func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_name)

        # Values may sit on the proxy row or the impl row.
        impl_row = session.execute(
            select(Contract.implementation).where(_chain_scoped(func.lower(Contract.address) == authority)).limit(1)
        ).first()
        impl = impl_row[0].lower() if impl_row and _is_address(impl_row[0]) else None
        addresses = [authority] + ([impl] if impl else [])
        rows = session.execute(
            select(ControllerValue.controller_id, ControllerValue.value)
            .join(Contract, ControllerValue.contract_id == Contract.id)
            .where(_chain_scoped(or_(*[func.lower(Contract.address) == a for a in addresses])))
        ).all()
    except Exception:
        return None

    controller_addrs: set[str] = set()
    role_labels: dict[str, str] = {}
    for controller_id, value in rows:
        cid = str(controller_id or "")
        if cid.startswith("role_identifier:"):
            word = _role_word_from_value(value)
            if word is not None:
                role_labels[word] = cid.split(":", 1)[1]
        elif _is_address(value) and value.lower() != _ZERO_ADDRESS:
            controller_addrs.add(value.lower())
    return controller_addrs, role_labels


def _check_only(authority: str | None, callee_selector: str | None, basis: list[str]) -> CapabilityExpr:
    extra: dict[str, Any] = {"basis": basis, "adapter": TRACE_STEP_ENUMERABLE_ROLE_STORE}
    # Only the index-wait bases defer; marking settled answers would spin the reconciler forever.
    waits_on_index = bool(_INDEX_WAIT_BASES.intersection(basis))
    if waits_on_index:
        extra["deferred_pending_index"] = True
    for reason in basis:
        if reason in _ADAPTER_DECLINE_REASONS:
            _DECLINE_COUNTS[reason] += 1
            record_stage_metric(f"role_store_decline_{reason}", _DECLINE_COUNTS[reason])
    logger.debug(
        "enumerable_role_store decision",
        extra={
            "adapter": TRACE_STEP_ENUMERABLE_ROLE_STORE,
            "address": authority,
            "decision": "deferred" if waits_on_index else "external_check",
            "reason": ",".join(basis),
        },
    )
    return CapabilityExpr.external_check_only(
        ExternalCheck(target_address=authority, target_call_selector=callee_selector, extra=extra)
    )


def _detect_standard(authority: str, ctx: EvaluationContext) -> RoleStoreStandard | None:
    """The role-store standard behind ``authority`` (proxy-aware), memoized per pass."""
    memo = _pass_memo(ctx)
    key = ("role_store_standard", authority)
    if key in memo:
        return memo[key]
    try:
        code = resolve_probe_code(getattr(ctx, "session", None), authority, ctx.chain_id, rpc_url=ctx.rpc_url)
    except Exception:
        code = None
    standard = resolve_standard(code)
    memo[key] = standard
    return standard


def _pin_probe_block(ctx: EvaluationContext, rpc_url: str) -> int | None:
    """One height for the whole enumeration: ``ctx.block`` if pinned, else one memoized ``eth_blockNumber`` per
    chain.

    ``None`` settles to ``probe_unavailable``.
    """
    if isinstance(ctx.block, int):
        return ctx.block
    memo = _pass_memo(ctx)
    key = ("role_store_pin_block", ctx.chain_id)
    if key in memo:
        return memo[key]
    pinned: int | None = None
    try:
        raw = rpc_request(rpc_url, "eth_blockNumber", [], chain_id=ctx.chain_id)
        pinned = int(raw, 16) if isinstance(raw, str) else None
    except Exception:
        pinned = None
    memo[key] = pinned
    return pinned


def _pass_memo(ctx: EvaluationContext) -> dict[Any, Any]:
    """The pass-scoped ``live_read_memo``, or a throwaway dict for a bare ctx."""
    meta = getattr(ctx, "meta", None)
    if isinstance(meta, dict):
        memo = meta.get("live_read_memo")
        if isinstance(memo, dict):
            return memo
    return {}


def _resolve_authority_address(descriptor: dict, ctx: EvaluationContext) -> str | None:
    authority = descriptor.get("authority_contract") or {}
    raw = authority.get("address")
    if _is_nonzero_address(raw):
        return raw.lower()
    source = authority.get("address_source") or {}
    if source.get("source") == "state_variable":
        name = source.get("state_variable_name")
        value = (ctx.state_var_values or {}).get(name) if isinstance(name, str) else None
        if _is_nonzero_address(value):
            return value.lower()
    if source.get("source") == "self_address":
        # A1 Part A: self-gate descriptor (e.g. RoleRegistry.onlyUpgradeTimelock); probe the analysed deployment.
        value = ctx.contract_address
        if _is_nonzero_address(value):
            return value.lower()
    return None


def _resolve_callee_selector(descriptor: dict) -> str | None:
    from services.resolution.predicate_evaluator.binding import (
        _selector_for_canonical_signature,
        _stored_dispatch_selector,
    )

    signature = descriptor.get("callee_signature")
    signature = signature.replace(" ", "") if isinstance(signature, str) else None
    selector = _stored_dispatch_selector(descriptor.get("callee_selector"), signature)
    if _is_selector(selector):
        return selector.lower()
    return _selector_for_canonical_signature(signature)


def _is_single_address_param_signature(signature: Any) -> bool:
    if not isinstance(signature, str) or "(" not in signature or not signature.rstrip().endswith(")"):
        return False
    params = signature[signature.index("(") + 1 : signature.rindex(")")]
    return [p.strip() for p in params.split(",") if p.strip()] == ["address"]


def _has_caller_key_source(descriptor: dict) -> bool:
    keys = descriptor.get("key_sources") or []
    return any(isinstance(k, dict) and k.get("source") in _CALLER_SOURCES for k in keys)


def _topic_address(topics: list[Any], index: int) -> str | None:
    if not 0 <= index < len(topics):
        return None
    return _word_to_address(topics[index])


def _topic_word(topics: list[Any], index: int) -> str | None:
    if not 0 <= index < len(topics):
        return None
    return _role_word_from_value(topics[index])


def _topic_bool(topics: list[Any], index: int) -> bool:
    if not 0 <= index < len(topics):
        return False
    return _word_int(topics[index]) != 0


def _role_word(role_hex: str) -> str:
    body = role_hex.lower().removeprefix("0x")
    return body.rjust(64, "0")[-64:]


def _uint_word(value: int) -> str:
    return format(value, "064x")


def _role_word_from_value(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    body = value[2:]
    if len(body) > 64:
        return None
    return "0x" + body.rjust(64, "0").lower()


def _word_to_address(word: Any) -> str | None:
    if not isinstance(word, str) or len(word) < 40:
        return None
    addr = "0x" + word[-40:].lower()
    if addr == _ZERO_ADDRESS:
        return None
    return addr


def _word_int(word: Any) -> int:
    if not isinstance(word, str):
        return 0
    try:
        return int(word, 16)
    except ValueError:
        return 0


def _is_address(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and value.startswith("0x") and len(value) == 42


def _is_nonzero_address(value: Any) -> TypeGuard[str]:
    return _is_address(value) and value.lower() != _ZERO_ADDRESS


def _is_selector(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and value.startswith("0x") and len(value) == 10
