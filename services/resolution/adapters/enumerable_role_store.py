"""Enumerable role-store adapter — resolves a delegated ``registry.onlyX(msg.sender)``
gate to its real controllers.

The caller's outer leaf is an ``external_set`` check against a single-address-param
callee on a role registry (``roleRegistry.onlyOperatingMultisig(msg.sender)`` and
its 9 etherfi siblings). This adapter recovers the concrete controller set for that
gate by three cooperating reads, none of which parses a role name (dissolved role
identity, CONTROLLER_RESOLUTION_SPEC.md §3.2):

  1. **Fold** the standard's indexed grant/revoke events at the authority PROXY into
     a *candidate universe* — every address currently holding ANY role — union the
     registry's own address-typed controller values (owner/admin; the hybrid-gate
     mitigation). The durable index is primary and drives the cold/warm lifecycle.
  2. **Probe** the gate itself at the pinned block: a negative control
     (``onlyX(CONTROL)``) that MUST revert (else the gate is not an allowlist), then
     each candidate (``onlyX(candidate)``) — survivors are exactly who the on-chain
     gate passes. The gate is its own ground truth, so false positives are
     structurally impossible (§7.3); a candidate is asserted a member only if the
     real gate passes it.
  3. Optionally **cross-check** the standard's enumerable getter as a consistency
     alarm (default off): a mismatch DECLINES loudly rather than emitting a set the
     getter contradicts.

Every transport failure in the probe is treated as *indeterminate*, never as a
membership failure (§7.7): a wire error declines to a settled ``probe_unavailable``
external check, it never classifies a candidate. Cold index → deferral that
self-heals via ``deferred_reconciler`` (mirrors the Solmate adapter); warm-with-no-
events → settled unconfirmed (we can't confirm the store speaks the standard we
model). The single place a new standard is recognized is
``role_store_standards.py``.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Any, TypeGuard

from eth_utils.crypto import keccak

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from utils.logging import record_stage_metric
from utils.rpc import encode_address_word, multicall3_aggregate3, rpc_request
from utils.scoring_status import TRACE_STEP_ENUMERABLE_ROLE_STORE

from ..capabilities import CapabilityExpr, ExternalCheck
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
# A structurally-non-member address for the negative control: a gate that passes
# THIS is not an allowlist (it passes everyone), so the enumeration is declined. A
# fixed sentinel with no plausible role grant; never itself reported as a member.
_NEGATIVE_CONTROL_ADDR = "0x" + "de1e7e" + "00" * 17


_MATCH_SCORE = 90


# Settled (non-deferring) adapter declines worth a metric — the persisted row's
# basis is superseded by the :1976 guard downstream, so the adapter is the only
# site where these are observable. A running count per reason (record_stage_metric
# folds it into the policy stage's timing artifact) surfaces a store the adapter
# recognized-but-couldn't-fold (negative control), a fold/getter disagreement, or a
# probe-transport blip, distinct from an ordinary cold-index deferral.
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
    """Resolves a delegated single-address-param role gate into its concrete
    controller set by folding the role-store standard's events and confirming each
    candidate against the live gate."""

    @classmethod
    def matches(cls, descriptor: dict, ctx: EvaluationContext) -> int:
        # Cheap structural gate first — only touch the wire (standard detection)
        # once the descriptor is shaped like a delegated single-address role gate.
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
        # Cold durable index: no warm cursor yet. Defer (mirror Solmate) so the
        # reconciler re-resolves exactly once the RoleSet backfill reaches head —
        # a live probe now would freeze a non-self-healing lower bound. Checked
        # before pinning a height so a cold index self-heals even without an RPC.
        try:
            cursor_block = min_indexed(chain_id=ctx.chain_id, event_address=authority, topic0s=topic0s)
        except Exception:
            return _check_only(authority, callee_selector, ["event_log_backend_error"])
        if cursor_block is None:
            return _check_only(authority, callee_selector, ["no_index_cursor"])

        rpc_url = ctx.rpc_url
        if not rpc_url:
            return _check_only(authority, callee_selector, ["no_rpc_for_probe"])
        # Pin ONE height for the fold read, the gate probe, AND the trace frontier so
        # the enumeration is offline-reproducible and the drift arm (§6 Stage 4) has a
        # fixed frontier to compare a later indexed row against. The resolver usually
        # pins the whole pass (ctx.block); an unpinned pass (a transient blocknum-read
        # failure upstream) re-reads head once here, and a failed read settles to
        # probe_unavailable rather than reading the three consumers at three heights.
        pinned_block = _pin_probe_block(ctx, rpc_url)
        if pinned_block is None:
            return _check_only(authority, callee_selector, ["probe_unavailable"])

        try:
            rows = iter_rows(chain_id=ctx.chain_id, event_address=authority, topic0s=topic0s, block=pinned_block)
        except Exception:
            return _check_only(authority, callee_selector, ["event_log_backend_error"])
        if not rows:
            # Warm cursor, zero role events: we cannot confirm the store actually
            # speaks the standard we'd fold, so an exact-empty set would be a false
            # "nobody". Settle to a probe (mirror Solmate's unconfirmed arm).
            return _check_only(authority, callee_selector, ["authority_unconfirmed_no_role_events"])

        active_holders = _fold_active_holders(rows)
        registry_context = _registry_controller_context(ctx, authority)
        if registry_context is None:
            # A DB error while resolving the registry's own controllers is NOT
            # "no candidates" (R1): a shrunken candidate universe silently
            # shrinks the survivor set, which is the false-empty shape this
            # adapter must never produce. Settle to the gated probe.
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
            # A wire failure is indeterminate, NOT a membership failure (§7.7): never
            # classify a candidate on transport error — settle to a probe.
            return _check_only(authority, callee_selector, ["probe_unavailable"])
        if probe.control_passed:
            # The gate passed a random control address: it is not an allowlist
            # (open, or a shape this adapter mis-modeled). Decline to the guard.
            return _check_only(authority, callee_selector, ["negative_control_passed"])

        members = sorted(probe.survivors)
        if not members and candidates:
            # Every candidate failed the real gate. If this gate were the pure
            # role-allowlist the adapter models, its admitted set would be a
            # subset of the candidate universe — zero survivors over a
            # NON-empty universe means either the gate's one role is currently
            # unheld or the gate admits callers outside the model (a hybrid /
            # non-role gate, e.g. ``msg.sender == liquidityPool``). The two are
            # indistinguishable here (role identity is dissolved by design), so
            # an ``exact`` "provably nobody" would be unwitnessed — decline.
            # An empty CANDIDATE universe (complete fold, all holders revoked,
            # no registry controllers) stays the exact-empty arm below: there
            # the emptiness is witnessed by the complete durable fold.
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
                # The height the fold covers (the least-advanced backfilled cursor):
                # the role-drift arm re-resolves when a grant/revoke is later indexed
                # PAST this frontier. Not probe_block — a grant in (frontier, probe]
                # would otherwise be missed.
                "fold_frontier": cursor_block,
                "candidate_count": len(candidates),
                "candidates_from_events": sorted(active_holders),
                "candidates_from_controllers": sorted(controller_addrs),
                "role_labels": role_labels,
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
            last_indexed_block=cursor_block,
            trace=trace,
        )


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------


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
    """Confirm which candidates the gate passes at ``block``, plus the negative
    control. One Multicall3 ``aggregate3`` (the ``onlyX(addr)`` reads are
    caller-independent — the address is an argument, not ``msg.sender`` — so
    Multicall3 rewriting the sender is harmless). Memoized per
    ``(authority, selector, block)`` so the 92 same-family functions share one
    probe. A whole-call transport failure raises and is reported as
    ``transport_failed`` (indeterminate), distinct from a per-candidate revert
    (non-member)."""
    key = ("role_store_probe", authority, callee_selector, block)
    cached = memo.get(key)
    if isinstance(cached, _ProbeResult):
        # The control result is stable per (authority, selector, block); only the
        # survivor filter depends on the candidate list, which is authority-scoped
        # and identical across a family, so a cached probe applies verbatim.
        return cached

    calls: list[tuple[str, str]] = [(authority, callee_selector + encode_address_word(_NEGATIVE_CONTROL_ADDR))]
    calls += [(authority, callee_selector + encode_address_word(cand)) for cand in candidates]
    block_tag = hex(block) if isinstance(block, int) else "latest"
    try:
        results = multicall3_aggregate3(rpc_url, calls, block_tag=block_tag)
    except Exception:
        # Do NOT memoize a transport failure: a single blip would otherwise settle
        # the whole same-(authority, selector, block) family to probe_unavailable
        # for the pass. Successes are memoized below; a failure re-probes next time.
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
    """True on a mismatch between the event fold and the standard's enumerable
    getter (a consistency alarm). Walk ``count(role)`` then ``at(role, i)`` for each
    active role; compare the getter's holder set to the fold's. A transport failure
    is treated as NO alarm (indeterminate — the probe already confirmed members;
    the getter is only a secondary check)."""
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


# ---------------------------------------------------------------------------
# Fold
# ---------------------------------------------------------------------------


def _fold_active_holders(rows: Any) -> set[str]:
    """Fold indexed grant/revoke rows (in log order) into the set of addresses
    currently holding ANY role — the event-side candidate universe. Last-write-wins
    per (holder, role); OZ grant/revoke polarity and Solady's active topic are both
    read from the row's ``spec_by_topic0`` entry."""
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


# ---------------------------------------------------------------------------
# Registry controller-value context (hybrid-gate mitigation + display labels)
# ---------------------------------------------------------------------------


def _registry_controller_context(ctx: EvaluationContext, authority: str) -> tuple[set[str], dict[str, str]] | None:
    """The registry's own address-typed controller values (owner/admin — union'd
    into the candidate universe so a hybrid ``onlyX`` that also passes an owner is
    reachable), plus a role-hash → NAME map inverted from the registry's
    ``role_identifier`` rows for DISPLAY labels only (join on value; never a name
    transform).

    Chain-scoped: ``contracts`` rows are keyed ``(address, chain)`` and a bare
    lower(address) read would resolve a second-chain registry authority to the
    ETHEREUM contract's implementation and controller values — cross-chain twin
    aliasing inside the caller-set computation. ``ctx.chain_id`` resolves through
    the canonical registry; NULL ``contracts.chain`` is legacy-mainnet by
    convention (same coalesce as ``services.discovery.upgrade_history``).

    Returns ``None`` on any resolution error (unknown chain, DB failure): an
    error is NOT an empty candidate set (R1) — the caller declines instead of
    probing a silently-shrunken universe. A bare ctx with no session returns
    empties (structural: there is no registry context to read)."""
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

        # Controller values may sit on the proxy row or the impl row (with the
        # proxy as deployment_address); accept either address as the registry.
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


# ---------------------------------------------------------------------------
# Decline
# ---------------------------------------------------------------------------


def _check_only(authority: str | None, callee_selector: str | None, basis: list[str]) -> CapabilityExpr:
    extra: dict[str, Any] = {"basis": basis, "adapter": TRACE_STEP_ENUMERABLE_ROLE_STORE}
    # Only the cold-index basis is *waiting on the durable index*; mark it so the
    # deferred-resolution reconciler re-resolves once the RoleSet backfill reaches
    # head. Every other basis is a settled answer (unresolved context, a warm store
    # with no role events, a passed negative control, a wire failure), so it is NOT
    # marked — marking would spin the reconciler forever.
    if "no_index_cursor" in basis:
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
            "decision": "deferred" if "no_index_cursor" in basis else "external_check",
            "reason": ",".join(basis),
        },
    )
    return CapabilityExpr.external_check_only(
        ExternalCheck(target_address=authority, target_call_selector=callee_selector, extra=extra)
    )


# ---------------------------------------------------------------------------
# Descriptor / standard resolution
# ---------------------------------------------------------------------------


def _detect_standard(authority: str, ctx: EvaluationContext) -> RoleStoreStandard | None:
    """The role-store standard behind ``authority`` (proxy-hop aware), memoized per
    authority across the resolution pass so 250 gated functions share one detection."""
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
    """One concrete height for the whole enumeration. A resolver that already pinned
    the pass (``ctx.block`` is an int) is honored verbatim; an unpinned pass reads
    ``eth_blockNumber`` once, memoized per chain in ``live_read_memo`` so a family of
    gated functions shares the read. ``None`` (a failed read) makes the caller settle
    to ``probe_unavailable`` — the fail-closed direction (§7.7), never a fold/probe/
    trace read at three different heights."""
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
    """The pass-scoped memo the resolver threads onto every function's ctx
    (``live_read_memo``): a within-pass dedup, discarded with the frame, never a
    cross-run cache. Absent (a bare ctx) → a throwaway dict so callers are
    uniform."""
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
        # A1 Part A: a SELF-gate descriptor (the un-lowerable role gate lives
        # on the analyzed contract itself — RoleRegistry.onlyUpgradeTimelock).
        # Resolve to the analyzed deployment so the probe hits real storage.
        value = ctx.contract_address
        if _is_nonzero_address(value):
            return value.lower()
    return None


def _resolve_callee_selector(descriptor: dict) -> str | None:
    selector = descriptor.get("callee_selector")
    if _is_selector(selector):
        return selector.lower()
    signature = descriptor.get("callee_signature")
    if isinstance(signature, str) and "(" in signature:
        return "0x" + keccak(text=signature.replace(" ", "")).hex()[:8]
    return None


def _is_single_address_param_signature(signature: Any) -> bool:
    if not isinstance(signature, str) or "(" not in signature or not signature.rstrip().endswith(")"):
        return False
    params = signature[signature.index("(") + 1 : signature.rindex(")")]
    return [p.strip() for p in params.split(",") if p.strip()] == ["address"]


def _has_caller_key_source(descriptor: dict) -> bool:
    keys = descriptor.get("key_sources") or []
    return any(isinstance(k, dict) and k.get("source") in _CALLER_SOURCES for k in keys)


# ---------------------------------------------------------------------------
# Word helpers
# ---------------------------------------------------------------------------


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
