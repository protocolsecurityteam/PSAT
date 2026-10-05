"""Resolve a contract's semantic capabilities per externally-callable function.

Loads the persisted ``predicate_trees`` artifact, evaluates each tree via ``evaluate_tree_with_registry`` against the
Postgres event-log repo, and serializes each ``CapabilityExpr`` to a dict:

    with SessionLocal() as session:
        result = resolve_contract_capabilities(session, address="0x...", chain_id=1)
    # {"grantRole(bytes32,address)": {"kind": "finite_set", "members": [...], ...}, ...}

Returns ``None`` when there's no completed analysis or predicate-tree artifact; callers degrade explicitly.
"""

from __future__ import annotations

import logging
import math
import os
import time
from dataclasses import asdict, dataclass, is_dataclass, replace
from typing import Any, Mapping

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.deployment import deployment_scope, normalize_deployment
from db.models import Contract, ControllerValue, Job, JobStatus
from db.queue import get_artifact
from services.clients.rpc import ChainContext, chain_context, eth_call_batch, rpc_request
from utils.chains import UnknownChainError, chain_by_id, require_chain
from utils.logging import record_degraded, record_stage_metric

from . import indexer_settings
from .adapters import AdapterRegistry, CallFrame, EvaluationContext
from .adapters.authorization import AuthorizationAdapter
from .adapters.enumerable_role_store import EnumerableRoleStoreAdapter
from .adapters.event_indexed import EventIndexedAdapter
from .adapters.solmate_roles import SolmateRolesAuthorityAdapter
from .capabilities import CapabilityExpr, Condition
from .differential_probe import ProbeResult, differential_probe_enabled, run_differential_probe
from .one_shot_probe import (
    LatchReadResult,
    annotate_capability_one_shot,
    collect_one_shot_latches,
    latch_descriptor_digest,
    one_shot_probe_enabled,
    resolve_one_shot_state,
    tree_has_one_shot_role,
)
from .permissionless_shapes import CALLER_GATE_BASIS_TAGS
from .predicate_evaluator import evaluate_tree_with_registry
from .repos import PostgresEventLogRepo
from .repos.bytecode_rpc import BytecodeSelectorRepo

logger = logging.getLogger(__name__)

# Minimum blocks the resolver steps back from head when pinning the per-pass evaluation height (#119).
#
# A healthy cursor sits at ``indexer_head - confirmation_depth`` as of its last poll, so pinning at
# ``resolver_head - depth`` would race and demote everything. ``resolver_pin_margin`` deepens this floor per chain to
# the chain's depth plus two indexer poll intervals of blocks, so a keeping-up cursor covers the pin and a stalled one
# falls behind it. A larger value only delays stall detection.
RESOLVER_FINALITY_MARGIN = int(os.getenv("PSAT_RESOLVER_FINALITY_MARGIN", "64"))
INDEXER_INTERVAL_S = indexer_settings.INTERVAL_S


def resolver_pin_margin(chain_id: int | None) -> int:
    """``max(RESOLVER_FINALITY_MARGIN, confirmation_depth + 2·⌈INDEXER_INTERVAL_S / block_time_s⌉)`` for the chain; the
    floor alone when the chain is unknown.
    """
    if not isinstance(chain_id, int):
        return RESOLVER_FINALITY_MARGIN
    try:
        info = chain_by_id(chain_id)
    except UnknownChainError:
        return RESOLVER_FINALITY_MARGIN
    poll_blocks = math.ceil(INDEXER_INTERVAL_S / info.block_time_s)
    return max(RESOLVER_FINALITY_MARGIN, info.confirmation_depth + 2 * poll_blocks)


def _capability_function_slow_ms() -> int:
    """Per-function slow-log threshold (``PSAT_CAPABILITY_FUNCTION_SLOW_MS``, default 250), mirroring
    ``predicate_artifacts``.
    """
    try:
        return max(0, int(os.getenv("PSAT_CAPABILITY_FUNCTION_SLOW_MS", "250")))
    except ValueError:
        return 250


def _capability_summary_ms() -> int:
    """Per-contract summary threshold (``PSAT_CAPABILITY_SUMMARY_MS``, default 500), mirroring
    ``predicate_artifacts``.
    """
    try:
        return max(0, int(os.getenv("PSAT_CAPABILITY_SUMMARY_MS", "500")))
    except ValueError:
        return 500


def _capability_kind_label(cap: CapabilityExpr) -> str:
    """Bucket a capability for the per-job kind tally, the run-over-run regression signal.

    ``finite_set`` splits into ``resolved_empty`` and populated; a cold-index ``external_check_only`` becomes
    ``deferred_pending_index``.
    """
    kind = getattr(cap, "kind", "unknown")
    if kind == "finite_set":
        members = getattr(cap, "members", None) or []
        if not members and getattr(cap, "membership_quality", None) == "exact":
            return "resolved_empty"
        return "finite_set"
    if kind == "external_check_only":
        check = getattr(cap, "check", None)
        extra = (getattr(check, "extra", None) or {}) if check is not None else {}
        if extra.get("deferred_pending_index"):
            return "deferred_pending_index"
        return "external_check_only"
    # ``CapabilityExpr`` stores "OR"/"AND"; lowercase so metric keys don't split.
    return str(kind).lower()


def _emit_capability_summary(
    *,
    contract_address: str,
    total_ms: int,
    per_function_ms: list[tuple[str, int]],
    kind_counts: dict[str, int],
    resolve_counters: dict[str, Any],
) -> None:
    """Fold the capability-kind tally and work counters into stage_timing, and emit ``capability_summary`` when the
    contract was slow enough. No-op outside a worker job.
    """
    for label, count in kind_counts.items():
        record_stage_metric(f"cap_{label}", count)
    record_stage_metric("cap_total", sum(kind_counts.values()))
    adapter_match = resolve_counters.get("adapter_match") if isinstance(resolve_counters, dict) else None
    if isinstance(adapter_match, dict):
        for name, count in adapter_match.items():
            record_stage_metric(f"adapter_{str(name).replace('Adapter', '')}", count)
    for ckey in ("live_getter_calls", "live_getter_failures", "inline_recursions", "hypersync_fallback_scans"):
        if ckey in resolve_counters:
            record_stage_metric(ckey, resolve_counters[ckey])

    if total_ms < _capability_summary_ms():
        return
    top_slow = sorted(per_function_ms, key=lambda kv: kv[1], reverse=True)[:5]
    logger.info(
        "capability summary for %s: total=%dms fns=%d kinds=%s",
        contract_address,
        total_ms,
        len(per_function_ms),
        kind_counts,
        extra={
            "profile_kind": "capability_summary",
            "total_ms": total_ms,
            "function_count": len(per_function_ms),
            "kind_counts": dict(kind_counts),
            "resolve_counters": dict(resolve_counters),
            "top_slow_functions": [{"function": name, "duration_ms": ms} for name, ms in top_slow],
        },
    )


@dataclass(frozen=True)
class AnalysisJobLookup:
    runtime_job: Job
    analysis_job: Job


def find_analysis_job_for_address(
    session: Session,
    address: str,
    *,
    required_artifact: str = "predicate_trees",
    chain: str | None = None,
    completed_only: bool = True,
) -> AnalysisJobLookup | None:
    """Find the job whose artifacts apply to a runtime address: a direct artifact if present, else the proxy's
    implementation job.
    """
    for runtime_job in _jobs_for_address(session, address, chain=chain, completed_only=completed_only):
        lookup = _analysis_lookup_for_runtime_job(
            session,
            runtime_job,
            required_artifact=required_artifact,
            chain=chain,
            completed_only=completed_only,
        )
        if lookup is not None:
            return lookup
    return None


def find_dependency_provider_job_for_address(
    session: Session,
    address: str,
    *,
    chain: str | None = None,
) -> AnalysisJobLookup | None:
    """The job that should satisfy a policy dependency for *address*.

    For a proxy that's the implementation job, since the proxy job may be done without policy artifacts.
    """
    for runtime_job in _jobs_for_address(session, address, chain=chain, completed_only=False):
        impl_job = _implementation_child_job(session, runtime_job, chain=chain, completed_only=False)
        if impl_job is not None:
            return AnalysisJobLookup(runtime_job=runtime_job, analysis_job=impl_job)
        return AnalysisJobLookup(runtime_job=runtime_job, analysis_job=runtime_job)
    return None


def _resolve_chain_context(
    chain_id: int,
    explicit_rpc_url: str | None,
    chain: str | None,
) -> ChainContext:
    """Bind ``chain_id`` to its RPC URL via :func:`services.clients.rpc.chain_context`.

    Unregistered ids raise :class:`~utils.chains.UnsupportedChainError`; an explicit local ``explicit_rpc_url`` wins for
    fork tests.
    """
    require_chain(chain_id, chain=chain, context="capability resolution chain context")
    return chain_context(chain_id, explicit_rpc_url=explicit_rpc_url)


def resolve_contract_capabilities(
    session: Session,
    *,
    address: str,
    chain_id: int,
    block: int | None = None,
    job_id: Any = None,
    chain: str | None = None,
) -> dict[str, dict[str, Any]] | None:
    """``{function_signature: capability_dict}`` for the latest completed analysis of ``address``, or ``None``.

    ``session`` must stay open: adapters read repos lazily. ``chain_id`` binds the live reads. ``job_id`` targets an
    in-progress job (the default completed-job filter would skip it). ``chain`` plus ``job_id`` scope the
    ``ControllerValue`` lookup so other runs' rows don't leak in; without ``job_id`` it falls back to address-only with
    a warning.
    """
    addr = address.lower()
    runtime_addr = addr
    if job_id is not None:
        job = session.get(Job, job_id)
        if job is None or (job.address or "").lower() != addr:
            return None
        runtime_job = job
        analysis_job = job
        request = job.request if isinstance(job.request, dict) else {}
        proxy_address = request.get("proxy_address")
        if isinstance(proxy_address, str) and proxy_address.startswith("0x") and len(proxy_address) == 42:
            runtime_addr = proxy_address.lower()
    else:
        lookup = find_analysis_job_for_address(
            session,
            addr,
            required_artifact="predicate_trees",
            chain=chain,
            completed_only=True,
        )
        if lookup is None:
            return None
        runtime_job = lookup.runtime_job
        analysis_job = lookup.analysis_job
        runtime_addr = (runtime_job.address or addr).lower()

    artifact = get_artifact(session, analysis_job.id, "predicate_trees")
    if not isinstance(artifact, dict) or "trees" not in artifact:
        lookup = _analysis_lookup_for_runtime_job(
            session,
            runtime_job,
            required_artifact="predicate_trees",
            chain=chain,
            completed_only=True,
        )
        if lookup is None:
            return None
        runtime_job = lookup.runtime_job
        analysis_job = lookup.analysis_job
        artifact = get_artifact(session, analysis_job.id, "predicate_trees")
        if not isinstance(artifact, dict) or "trees" not in artifact:
            return None

    # Best-effort default from Job.request; without it the lookup is address-only.
    if chain is None and isinstance(analysis_job.request, dict):
        req_chain = analysis_job.request.get("chain")
        if isinstance(req_chain, str) and req_chain:
            chain = req_chain
    if chain is None and isinstance(runtime_job.request, dict):
        req_chain = runtime_job.request.get("chain")
        if isinstance(req_chain, str) and req_chain:
            chain = req_chain
    explicit_rpc_url: str | None = None
    for candidate_job in (analysis_job, runtime_job):
        if not isinstance(candidate_job.request, dict):
            continue
        if isinstance(candidate_job.request.get("rpc_url"), str):
            explicit_rpc_url = candidate_job.request["rpc_url"]
            break
    # Derive the RPC URL from ``chain_id`` so the pair can't disagree (they used to come from different sources).
    ctx_chain = _resolve_chain_context(chain_id, explicit_rpc_url, chain)
    rpc_url = ctx_chain.rpc_url
    chain_id = ctx_chain.chain_id

    registry = AdapterRegistry()
    registry.register(AuthorizationAdapter)
    # Named standard adapters first (higher matches() scores win); event-indexed is the fallback.
    registry.register(SolmateRolesAuthorityAdapter)
    registry.register(EnumerableRoleStoreAdapter)
    registry.register(EventIndexedAdapter)

    event_log_repo = PostgresEventLogRepo(session)
    # Lets adapters tell standards apart by bytecode, e.g. Solmate RolesAuthority vs OZ AccessManager (same canCall
    # selector).
    bytecode_repo = BytecodeSelectorRepo(rpc_url, chain_id)
    state_var_values = _load_state_var_values(
        session,
        analysis_job.address or addr,
        job_id=analysis_job.id,
        chain=chain,
    )
    if not state_var_values and runtime_job.id != analysis_job.id:
        state_var_values = _load_state_var_values(session, addr, job_id=runtime_job.id, chain=chain)
    canonical_signatures = artifact.get("canonical_signatures") if isinstance(artifact, dict) else None
    out: dict[str, dict[str, Any]] = {}
    # Resolver-side twin of ``build_predicate_artifacts``' profiling, so runaway functions in the policy stage are
    # visible. ``resolve_counters`` rides on ctx.meta for adapters and inlining to increment.
    started = time.monotonic()
    per_function_ms: list[tuple[str, int]] = []
    kind_counts: dict[str, int] = {}
    resolve_counters: dict[str, Any] = {}
    # Per-pass memo of live nullary getter reads, shared across functions; discarded with this frame, never persisted.
    live_read_memo: dict[Any, Any] = {}
    slow_threshold_ms = _capability_function_slow_ms()
    # Pin one finalized height for the whole pass (#119), stepped back ``resolver_pin_margin`` so healthy cursors stay
    # ``exact`` and stalled ones demote. ``None`` leaves it unpinned, which demotes (safe). The differential probe keeps
    # its own height.
    resolution_block: int | None = _resolve_resolution_block(rpc_url, block, chain_id=chain_id)
    probe_block: int | None = (
        _resolve_probe_block(rpc_url, block, chain_id=chain_id) if differential_probe_enabled() else None
    )
    # One-shot latch probe (default on). The runtime address is a proxy when the artifact came from an implementation
    # job or the job has ``proxy_address``, so an unset latch is genuinely live.
    one_shot_enabled = one_shot_probe_enabled()
    db_proxy_linked = (runtime_job.id != analysis_job.id) or (runtime_addr != addr)
    # Resolved lazily on the first one-shot row so passes without initializers make no extra calls.
    one_shot_block_cell: list[Any] = [probe_block if probe_block is not None else _UNRESOLVED_BLOCK]
    one_shot_pass_cache: dict[tuple[Any, ...], LatchReadResult] = {}
    function_trees = dict(artifact["trees"] or {})
    for signature in artifact.get("effect_scopes") or {}:
        function_trees.setdefault(signature, None)
    for fn_signature, tree in function_trees.items():
        ctx = EvaluationContext(
            chain_id=chain_id,
            contract_address=runtime_addr,
            block=resolution_block,
            event_log_repo=event_log_repo,
            bytecode=bytecode_repo,
            rpc_url=rpc_url,
            state_var_values=state_var_values,
            session=session,
            call_frame=CallFrame.root(
                contract_address=runtime_addr,
                function_signature=fn_signature if isinstance(fn_signature, str) else None,
                function_selector=_selector_for_signature(
                    fn_signature if isinstance(fn_signature, str) else None, canonical_signatures
                ),
            ),
            meta={"resolve_counters": resolve_counters, "live_read_memo": live_read_memo},
        )
        fn_started = time.monotonic()
        cap = evaluate_tree_with_registry(tree, registry, ctx)
        if probe_block is not None:
            cap = _maybe_differential_probe(
                cap,
                chain_id=chain_id,
                contract_address=runtime_addr,
                fn_signature=fn_signature if isinstance(fn_signature, str) else None,
                canonical_signatures=canonical_signatures,
                rpc_url=rpc_url,
                block=probe_block,
            )
        scoped = (artifact.get("effect_scopes") or {}).get(fn_signature)
        scope_records = []
        if scoped:
            from .effect_scopes import resolve_effect_scopes

            aggregate, scope_records = resolve_effect_scopes(
                scoped, registry, ctx, base_cap=cap, all_scopes=artifact.get("effect_scopes")
            )
            if aggregate is not None:
                cap = aggregate
        cap_dict = capability_to_dict(cap)
        if scope_records:
            cap_dict["effect_capabilities"] = scope_records
        if one_shot_enabled and rpc_url:
            _maybe_one_shot_probe(
                cap_dict,
                tree=tree,
                runtime_addr=runtime_addr,
                rpc_url=rpc_url,
                chain_id=chain_id,
                block=block,
                block_cell=one_shot_block_cell,
                db_proxy_linked=db_proxy_linked,
                pass_cache=one_shot_pass_cache,
            )
        fn_ms = int((time.monotonic() - fn_started) * 1000)
        out[fn_signature] = cap_dict
        per_function_ms.append((str(fn_signature), fn_ms))
        label = _capability_kind_label(cap)
        kind_counts[label] = kind_counts.get(label, 0) + 1
        if fn_ms >= slow_threshold_ms:
            logger.info(
                "capability function %s on %s took %dms (kind=%s)",
                fn_signature,
                runtime_addr,
                fn_ms,
                label,
                extra={
                    "profile_kind": "capability_function_slow",
                    "duration_ms": fn_ms,
                    "function": str(fn_signature),
                    "kind": label,
                },
            )
    _emit_capability_summary(
        contract_address=runtime_addr,
        total_ms=int((time.monotonic() - started) * 1000),
        per_function_ms=per_function_ms,
        kind_counts=kind_counts,
        resolve_counters=resolve_counters,
    )
    return out


def _selector_for_signature(
    signature: str | None,
    canonical_signatures: Mapping[str, str] | None = None,
) -> str | None:
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    from eth_utils.crypto import keccak

    # Tree keys are Slither ``full_name`` signatures with user-defined type names; prefer the static stage's canonical
    # ABI signature so the selector equals the real ``msg.sig``.
    canonical = (canonical_signatures or {}).get(signature)
    if isinstance(canonical, str) and "(" in canonical and canonical.endswith(")"):
        return "0x" + keccak(text=canonical).hex()[:8]

    from services.policy.effective_permissions import _abi_signature
    from services.static.contract_analysis_pipeline.predicate_artifacts import is_canonical_abi_signature

    # Name-based fallback handles contract params but not enums or structs; when lowering is incomplete, return no
    # selector, since a wrong one silently matches the wrong function.
    lowered = _abi_signature(signature)
    if not is_canonical_abi_signature(lowered):
        return None
    return "0x" + keccak(text=lowered).hex()[:8]


# Differential probe wiring, only used when ``PSAT_DIFFERENTIAL_PROBE`` is on.

# Deterministic per ``(chain, address, selector, block)``, so cached in-process on the real-wire path only (injected
# ``call_batch`` bypasses it). Keyed by exact block.
_PROBE_CACHE: dict[tuple[int, str, str, int], "ProbeResult"] = {}
_PROBE_CACHE_MAX = 4096


def clear_probe_cache() -> None:
    _PROBE_CACHE.clear()


def _probe_cache_put(key: tuple[int, str, str, int], result: "ProbeResult") -> None:
    if len(_PROBE_CACHE) >= _PROBE_CACHE_MAX:
        # FIFO-ish trim: drop a quarter at the bound.
        for stale in list(_PROBE_CACHE.keys())[: _PROBE_CACHE_MAX // 4]:
            _PROBE_CACHE.pop(stale, None)
    _PROBE_CACHE[key] = result


def _resolve_probe_block(rpc_url: str | None, block: int | None, *, chain_id: int | None = None) -> int | None:
    """Pin a probe height: the caller's ``block``, else head minus a finality margin. None on failure skips probing."""
    if isinstance(block, int) and block > 0:
        return block
    if not rpc_url:
        return None
    try:
        head = int(rpc_request(rpc_url, "eth_blockNumber", [], retries=1, chain_id=chain_id), 16)
    except Exception:
        return None
    return max(1, head - 12)


def _resolve_resolution_block(rpc_url: str | None, block: int | None, *, chain_id: int | None = None) -> int | None:
    """Pin the per-pass evaluation height for event-indexed coverage (#119): the caller's ``block``, else head minus
    ``resolver_pin_margin(chain_id)``. ``None`` leaves it unpinned, so no event fold can claim coverage.
    """
    if isinstance(block, int) and block > 0:
        return block
    if not rpc_url:
        return None
    try:
        head = int(rpc_request(rpc_url, "eth_blockNumber", [], retries=1, chain_id=chain_id), 16)
    except Exception:
        return None
    return max(1, head - resolver_pin_margin(chain_id))


def _should_differential_probe(cap: CapabilityExpr) -> bool:
    """True only for a top-level ``external_check_only`` with a caller-gate basis tag.

    Cold-index deferrals are never probed, so ``deferred_reconciler`` can converge them.
    """
    if cap.kind != "external_check_only" or cap.check is None:
        return False
    extra = cap.check.extra or {}
    if extra.get("deferred_pending_index"):
        return False
    basis = extra.get("basis") or []
    return any(tag in CALLER_GATE_BASIS_TAGS for tag in basis)


def _apply_probe_result(cap: CapabilityExpr, result: ProbeResult) -> CapabilityExpr:
    """Land a probe verdict.

    Only confirmed-public changes the verdict (to ``conditional_universal``); others keep ``external_check_only`` and
    attach the transcript.
    """
    transcript_step = {"step": "differential_probe", **result.transcript}
    if result.verdict == "public":
        opened = CapabilityExpr.conditional_universal(
            Condition(kind="business", description="differential probe: caller-independent (observed open)")
        )
        opened.trace = list(cap.trace) + [transcript_step]
        return opened
    if cap.check is not None:
        extra = dict(cap.check.extra or {})
        extra["differential_probe"] = result.transcript
        return replace(cap, check=replace(cap.check, extra=extra))
    out = replace(cap)
    out.trace = list(cap.trace) + [transcript_step]
    return out


def _maybe_differential_probe(
    cap: CapabilityExpr,
    *,
    chain_id: int,
    contract_address: str,
    fn_signature: str | None,
    canonical_signatures: Mapping[str, str] | None,
    rpc_url: str | None,
    block: int,
    call_batch: Any = None,
) -> CapabilityExpr:
    """Probe one gated-unknown capability.

    Any failure leaves the static verdict. ``call_batch`` is injectable for tests.
    """
    if not _should_differential_probe(cap):
        return cap
    selector = _selector_for_signature(fn_signature, canonical_signatures)
    if not selector:
        return cap
    use_cache = call_batch is None
    cache_key = (chain_id, contract_address.lower(), selector, block)
    if use_cache:
        cached = _PROBE_CACHE.get(cache_key)
        if cached is not None:
            return _apply_probe_result(cap, cached)
    canonical = (canonical_signatures or {}).get(fn_signature) if fn_signature else None
    canonical = canonical or fn_signature
    if call_batch is None:
        if not rpc_url:
            return cap

        def _wire_call_batch(calls: list[dict[str, str]], block_tag: str):  # noqa: ANN202
            return eth_call_batch(rpc_url, calls, block_tag, chain_id=chain_id)

        call_batch = _wire_call_batch

    try:
        result = run_differential_probe(
            call_batch=call_batch,
            chain_id=chain_id,
            contract_address=contract_address,
            selector=selector,
            canonical_signature=canonical,
            block=block,
            principal=None,
        )
    except Exception:
        logger.debug("differential probe failed for %s; keeping static verdict", fn_signature, exc_info=True)
        return cap
    if use_cache:
        _probe_cache_put(cache_key, result)
    return _apply_probe_result(cap, result)


# Deterministic per ``(chain, address, block, latch-slot signature)``; bounded FIFO like the probe cache.
_ONE_SHOT_CACHE: dict[tuple[Any, ...], LatchReadResult] = {}
_ONE_SHOT_CACHE_MAX = 4096

# Distinguishes "not yet resolved" from a real ``None`` (read at latest).
_UNRESOLVED_BLOCK = object()


def clear_one_shot_cache() -> None:
    _ONE_SHOT_CACHE.clear()


def _one_shot_cache_put(key: tuple[Any, ...], result: LatchReadResult) -> None:
    if len(_ONE_SHOT_CACHE) >= _ONE_SHOT_CACHE_MAX:
        for stale in list(_ONE_SHOT_CACHE.keys())[: _ONE_SHOT_CACHE_MAX // 4]:
            _ONE_SHOT_CACHE.pop(stale, None)
    _ONE_SHOT_CACHE[key] = result


def _maybe_one_shot_probe(
    cap_dict: dict[str, Any],
    *,
    tree: Any,
    runtime_addr: str,
    rpc_url: str,
    chain_id: int,
    block: int | None,
    block_cell: list[Any],
    db_proxy_linked: bool,
    pass_cache: dict[tuple[Any, ...], LatchReadResult],
) -> None:
    """Read the latch state for a one-shot row and annotate ``cap_dict`` in place; failures leave the badge
    unchanged.

    Standard one-shots always annotate. Structural candidates are promoted only when the read confirms a real latch.
    ``block_cell`` resolves the height lazily on first use.
    """
    try:
        latches = collect_one_shot_latches(tree)
    except Exception:
        return
    has_standard = bool(latches["standard"]) or tree_has_one_shot_role(tree)
    has_candidate = bool(latches["candidate"])
    if not has_standard and not has_candidate:
        return
    all_latches = list(latches["standard"]) + list(latches["candidate"])
    if not all_latches:
        return

    if block_cell[0] is _UNRESOLVED_BLOCK:
        block_cell[0] = _resolve_probe_block(rpc_url, block)
    probe_height = block_cell[0]

    cache_key = (
        chain_id,
        runtime_addr.lower(),
        probe_height,
        latch_descriptor_digest(all_latches),
    )
    result = pass_cache.get(cache_key)
    if result is None:
        result = _ONE_SHOT_CACHE.get(cache_key)
    if result is None:
        try:
            result = resolve_one_shot_state(
                rpc_url=rpc_url,
                address=runtime_addr,
                latches=all_latches,
                block=probe_height if isinstance(probe_height, int) else None,
                db_proxy_linked=db_proxy_linked,
            )
        except Exception:
            logger.debug("one-shot probe failed for %s; keeping static badge", runtime_addr, exc_info=True)
            return
        pass_cache[cache_key] = result
        _one_shot_cache_put(cache_key, result)

    annotate_capability_one_shot(cap_dict, result, confirmed_candidate=has_candidate and not has_standard)


def _analysis_lookup_for_runtime_job(
    session: Session,
    runtime_job: Job,
    *,
    required_artifact: str,
    chain: str | None,
    completed_only: bool,
) -> AnalysisJobLookup | None:
    # A proxy's own predicate_trees artifact exists but is empty; preferring it would shadow the implementation's trees
    # and break cross-contract inlining. Prefer a substantive artifact; fall back to an empty one only if neither has
    # content.
    runtime_artifact = get_artifact(session, runtime_job.id, required_artifact)
    if _artifact_is_substantive(required_artifact, runtime_artifact):
        return AnalysisJobLookup(runtime_job=runtime_job, analysis_job=runtime_job)

    impl_job = _implementation_child_job(session, runtime_job, chain=chain, completed_only=completed_only)
    impl_artifact = get_artifact(session, impl_job.id, required_artifact) if impl_job is not None else None
    if impl_job is not None and _artifact_is_substantive(required_artifact, impl_artifact):
        return AnalysisJobLookup(runtime_job=runtime_job, analysis_job=impl_job)

    if isinstance(runtime_artifact, dict):
        return AnalysisJobLookup(runtime_job=runtime_job, analysis_job=runtime_job)
    if impl_job is not None and isinstance(impl_artifact, dict):
        return AnalysisJobLookup(runtime_job=runtime_job, analysis_job=impl_job)
    return None


def _jobs_for_address(
    session: Session,
    address: str,
    *,
    chain: str | None = None,
    completed_only: bool = True,
) -> list[Job]:
    stmt = (
        select(Job)
        .where(func.lower(Job.address) == address.lower())
        .where(Job.request["effects_resume_work_id"].astext.is_(None))
        .where(~Job.status.in_((JobStatus.failed, JobStatus.failed_terminal)))
        .order_by(Job.updated_at.desc(), Job.created_at.desc())
    )
    if completed_only:
        stmt = stmt.where(Job.status == JobStatus.completed)
    candidates = list(session.execute(stmt).scalars().all())
    if chain is None:
        return candidates
    return [job for job in candidates if _job_chain(job) == chain]


def _implementation_child_job(
    session: Session,
    runtime_job: Job,
    *,
    chain: str | None,
    completed_only: bool,
) -> Job | None:
    contract = _contract_for_job(session, runtime_job, chain=chain)
    impl_addr = (contract.implementation if contract is not None else None) or None
    if not isinstance(impl_addr, str) or not impl_addr.startswith("0x") or len(impl_addr) != 42:
        return None

    candidates = _jobs_for_address(session, impl_addr, chain=chain, completed_only=completed_only)
    runtime_addr = (runtime_job.address or "").lower()
    parent_id = str(runtime_job.id)

    def is_linked(candidate: Job) -> bool:
        request = candidate.request if isinstance(candidate.request, dict) else {}
        proxy_addr = request.get("proxy_address")
        return request.get("parent_job_id") == parent_id or (
            isinstance(proxy_addr, str) and proxy_addr.lower() == runtime_addr
        )

    linked = [candidate for candidate in candidates if is_linked(candidate)]
    if linked:
        return linked[0]
    return candidates[0] if candidates else None


def _contract_for_job(session: Session, job: Job, *, chain: str | None) -> Contract | None:
    contract = session.execute(
        select(Contract).where(Contract.job_id == job.id).order_by(Contract.created_at.desc()).limit(1)
    ).scalar_one_or_none()
    if contract is not None:
        return contract

    address = (job.address or "").lower()
    if not address:
        return None
    stmt = select(Contract).where(func.lower(Contract.address) == address)
    effective_chain = chain or _job_chain(job)
    if effective_chain is not None:
        stmt = stmt.where(Contract.chain == effective_chain)
    return session.execute(stmt.order_by(Contract.created_at.desc()).limit(1)).scalar_one_or_none()


def _job_chain(job: Job) -> str | None:
    request = job.request if isinstance(job.request, dict) else {}
    chain = request.get("chain")
    return chain if isinstance(chain, str) and chain else None


def _artifact_is_substantive(artifact_name: str, artifact: Any) -> bool:
    """Whether an artifact has usable content: ``predicate_trees`` needs at least one ``trees``/``check_trees``
    entry; other kinds just need to be a dict.
    """
    if not isinstance(artifact, dict):
        return False
    if artifact_name == "predicate_trees":
        return bool(artifact.get("trees") or artifact.get("check_trees"))
    return True


def _load_state_var_values(
    session: Session,
    address: str,
    *,
    job_id: Any = None,
    chain: str | None = None,
) -> dict[str, str]:
    """Persisted ``controller_values`` for ``address``, keyed by bare state-variable name.

    Stored ids are ``"<kind>:<name>"``; the prefix is stripped and ``state_variable:`` rows win over others with the
    same name. Scoped to ``Contract.job_id`` when given, else the latest contract for the address (and ``chain`` if
    given). Empty dict when nothing matches.
    """
    if job_id is not None:
        stmt = select(Contract).where(Contract.job_id == job_id)
        if chain is not None:
            stmt = stmt.where(Contract.chain == chain)
        contract = session.execute(stmt.order_by(Contract.created_at.desc()).limit(1)).scalar_one_or_none()
        if contract is not None:
            # Scope to this deployment so a shared impl reads only its own proxy's values.
            job = session.get(Job, job_id)
            deployment = (
                normalize_deployment(job.request.get("proxy_address"))
                if job is not None and isinstance(job.request, dict)
                else None
            )
            return _controller_values_for_contract(session, contract, deployment, scope_deployment=True)
    else:
        # Address-only lookup can pick up another job's or chain's rows; record it.
        record_degraded(
            phase="state_var_values_no_job_id",
            exc=RuntimeError("_load_state_var_values called without job_id"),
            context={"address": address, "chain": chain},
        )
        logger.warning(
            "_load_state_var_values called without job_id; falling back to address-only lookup",
            extra={"address": address, "chain": chain},
        )

    stmt = select(Contract).where(func.lower(Contract.address) == address.lower())
    if chain is not None:
        stmt = stmt.where(Contract.chain == chain)
    stmt = stmt.order_by(Contract.created_at.desc()).limit(1)
    contract = session.execute(stmt).scalar_one_or_none()
    if contract is None:
        return {}
    return _controller_values_for_contract(session, contract)


def _controller_values_for_contract(
    session: Session,
    contract: Contract,
    deployment_address: str | None = None,
    *,
    scope_deployment: bool = False,
) -> dict[str, str]:
    stmt = select(ControllerValue).where(ControllerValue.contract_id == contract.id)
    if scope_deployment:
        # Only this deployment's rows (plus legacy NULL). No-op for 1:1.
        stmt = stmt.where(deployment_scope(ControllerValue.deployment_address, deployment_address))
    rows = session.execute(stmt).scalars()
    state_var: dict[str, str] = {}
    other: dict[str, str] = {}
    for row in rows:
        cid = row.controller_id or ""
        value = row.value
        if not cid or not value:
            continue
        if ":" in cid:
            kind, _, name = cid.partition(":")
        else:
            kind, name = "", cid
        if not name:
            continue
        if kind == "state_variable":
            state_var[name] = value
        else:
            other.setdefault(name, value)
    # state_variable rows win.
    return {**other, **state_var}


def capability_to_dict(cap: CapabilityExpr) -> dict[str, Any]:
    """Serialize a ``CapabilityExpr`` to a JSON-ready dict, recursing through ``children`` and ``signer`` and
    dropping default-valued keys.
    """
    if not is_dataclass(cap):
        return {}
    out: dict[str, Any] = {"kind": cap.kind}
    if cap.members is not None:
        out["members"] = list(cap.members)
    if cap.threshold is not None:
        m, signers = cap.threshold
        out["threshold"] = {"m": m, "signers": list(signers)}
    if cap.blacklist is not None:
        out["blacklist"] = list(cap.blacklist)
    if cap.signer is not None:
        out["signer"] = capability_to_dict(cap.signer)
    if cap.check is not None:
        out["check"] = asdict(cap.check)
    if cap.conditions:
        out["conditions"] = [asdict(c) if is_dataclass(c) else dict(c) for c in cap.conditions]
    if cap.unsupported_reason is not None:
        out["unsupported_reason"] = cap.unsupported_reason
    if cap.children:
        out["children"] = [capability_to_dict(c) for c in cap.children]
    out["membership_quality"] = cap.membership_quality
    out["confidence"] = cap.confidence
    if cap.last_indexed_block is not None:
        out["last_indexed_block"] = cap.last_indexed_block
    # Three states: int (exact at one height), ``"not_determined"`` (heterogeneous heights), or absent (never computed).
    # ``last_indexed_block`` is never a substitute.
    if cap.exact_as_of is not None:
        out["exact_as_of"] = cap.exact_as_of
    if cap.trace:
        out["trace"] = list(cap.trace)
    # Emitted only when non-default, so root capabilities keep their shape.
    if cap.subject != "root":
        out["subject"] = cap.subject
    # Always emitted on a cofinite: when it was omitted by default, absence read as a complete denylist (the strong
    # claim). Absence now just means "not a denylist".
    if cap.kind == "cofinite_blacklist":
        out["blacklist_quality"] = cap.blacklist_quality
    elif cap.blacklist_quality != "exact":
        # A non-cofinite with a non-default quality is a producer bug; emit it rather than hide it.
        out["blacklist_quality"] = cap.blacklist_quality
    # Only labelled empties carry a reason.
    if cap.empty_reason is not None:
        out["empty_reason"] = cap.empty_reason
    return out
