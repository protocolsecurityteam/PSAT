"""Resolver-side counterpart to ``predicate_artifacts``: given a
contract address, return semantic capabilities per externally-callable
function.

It loads the persisted ``predicate_trees``
artifact (written by the static stage's
``build_predicate_artifacts`` + ``store_artifact``), wires the
Postgres-backed generic event-log repo into an
``EvaluationContext``, evaluates each function's PredicateTree
through ``evaluate_tree_with_registry`` to a ``CapabilityExpr``,
and serializes the result to a JSON-ready dict per function.

The output is the structured per-function capability surface: every
external/public function appears when it has semantic predicate data,
with a typed capability shape the resolver/UI can reason about
uniformly.

Usage:

    with SessionLocal() as session:
        result = resolve_contract_capabilities(
            session, address="0x...", chain_id=1
        )
    # {
    #   "grantRole(bytes32,address)": {
    #       "kind": "finite_set",
    #       "members": ["0x..."],
    #       "membership_quality": "exact",
    #       "confidence": "enumerable",
    #       ...
    #   },
    #   ...
    # }

Returns ``None`` when the contract has no completed analysis or no
predicate-tree artifact yet. Callers degrade explicitly instead of
using the old static summary as an authority source.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import asdict, dataclass, is_dataclass, replace
from typing import Any, Mapping

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.deployment import deployment_scope, normalize_deployment
from db.models import Contract, ControllerValue, Job, JobStatus
from db.queue import get_artifact
from utils.chains import require_chain
from utils.logging import record_degraded, record_stage_metric
from utils.rpc import ChainContext, chain_context, eth_call_batch, rpc_request

from .adapters import AdapterRegistry, CallFrame, EvaluationContext
from .adapters.enumerable_role_store import EnumerableRoleStoreAdapter
from .adapters.event_indexed import EventIndexedAdapter
from .adapters.solmate_roles import SolmateRolesAuthorityAdapter
from .capabilities import CapabilityExpr, Condition
from .differential_probe import ProbeResult, differential_probe_enabled, run_differential_probe
from .one_shot_probe import (
    LatchReadResult,
    annotate_capability_one_shot,
    collect_one_shot_latches,
    one_shot_probe_enabled,
    resolve_one_shot_state,
    tree_has_one_shot_role,
)
from .permissionless_shapes import CALLER_GATE_BASIS_TAGS
from .predicate_evaluator import evaluate_tree_with_registry
from .repos import PostgresEventLogRepo
from .repos.bytecode_rpc import BytecodeSelectorRepo

logger = logging.getLogger(__name__)

# Finality margin (in blocks) the resolver steps back from live head when it pins
# the per-pass event-fold evaluation height (#119). It is INTENTIONALLY deeper than
# the event indexer's own confirmation depth (``PSAT_EVENT_INDEXER_FINALITY_DEPTH``,
# default 12): a keeping-up durable cursor sits at ``indexer_head - depth`` as of the
# indexer's last pass, while the resolver reads a fresher ``resolver_head >=
# indexer_head``. Pinning ``resolver_head - depth`` would race — a perfectly healthy
# cursor falls a few blocks short of it whenever any block arrived since the indexer's
# last pass — and degenerate to a blanket demotion. Stepping back a margin LARGER than
# ``depth + (blocks per indexer poll interval)`` makes the pinned height one the
# keeping-up cursor has provably already covered, so coverage is deterministic:
# ``cursor >= pin`` is stably TRUE for a healthy cursor (no flap), and a stalled cursor
# (frozen while head advances) falls below ``pin`` and demotes. Because ``pin <=
# cursor`` whenever it stays exact, the index is COMPLETE up to the read height — the
# ``exact`` label is truthful, never a fail-open. Default 64 comfortably covers the
# ~12s/2s-block chains (Ethereum/Base/Optimism/Polygon); raise it for sub-second chains
# (e.g. Arbitrum) where a healthy cursor lags further. Larger only delays stall
# detection; it never manufactures a false ``exact``.
RESOLVER_FINALITY_MARGIN = int(os.getenv("PSAT_RESOLVER_FINALITY_MARGIN", "64"))


def _capability_function_slow_ms() -> int:
    """Per-function log threshold for the resolver profiler — mirrors
    ``predicate_artifacts._slow_function_threshold_ms`` (env
    ``PSAT_CAPABILITY_FUNCTION_SLOW_MS``, default 250)."""
    try:
        return max(0, int(os.getenv("PSAT_CAPABILITY_FUNCTION_SLOW_MS", "250")))
    except ValueError:
        return 250


def _capability_summary_ms() -> int:
    """Aggregate threshold below which the per-contract capability summary is
    suppressed — mirrors ``predicate_artifacts._predicate_summary_threshold_ms``
    (env ``PSAT_CAPABILITY_SUMMARY_MS``, default 500)."""
    try:
        return max(0, int(os.getenv("PSAT_CAPABILITY_SUMMARY_MS", "500")))
    except ValueError:
        return 500


def _capability_kind_label(cap: CapabilityExpr) -> str:
    """Bucket a resolved capability for the per-job kind tally. ``finite_set``
    splits into ``resolved_empty`` (an exact "nobody") vs a populated set; an
    ``external_check_only`` carrying the cold-index marker becomes
    ``deferred_pending_index`` (flags self-heal-pending cold-event-index races).
    This tally is the run-over-run regression signal — e.g. the Veda OR-kind
    17→106 jump that was previously invisible because per-function outcomes were
    never recorded."""
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
    # Lowercase so the metric keys are uniform (cap_or / cap_and /
    # cap_cofinite_blacklist, matching the special-cased lowercase labels above)
    # — ``CapabilityExpr`` stores composite kinds as "OR"/"AND". Mixed casing
    # would split the run-over-run diff this tally exists for.
    return str(kind).lower()


def _emit_capability_summary(
    *,
    contract_address: str,
    total_ms: int,
    per_function_ms: list[tuple[str, int]],
    kind_counts: dict[str, int],
    resolve_counters: dict[str, Any],
) -> None:
    """Fold the per-job capability-kind tally + work-volume counters into the
    stage_timing artifact and, when the contract was expensive enough, emit a
    ``capability_summary`` line (mirrors ``predicate_artifacts``' predicate
    summary). ``record_stage_metric`` is a no-op outside a worker job context."""
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
    """Find the job whose artifacts should be used for a runtime address.

    Proxies are runtime addresses, but their semantic artifacts usually live
    on the implementation child job. Prefer a direct artifact when present;
    otherwise follow the proxy Contract row to the implementation job.
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
    """Return the job that should satisfy a policy dependency for address.

    If ``address`` is a proxy and its implementation child job exists, the
    policy edge must wait on the implementation job. The proxy job may already
    be ``done`` without policy artifacts, so depending on the proxy address can
    unblock too early or never satisfy the semantic inlining path.
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
    """Bind ``chain_id`` to its RPC URL (invariant 7). Registry-backed via
    :func:`utils.rpc.chain_context`. An unregistered ``chain_id`` (only reachable
    from a hand-built job request) now fails loud (invariant 6): ``require_chain``
    raises :class:`~utils.chains.UnsupportedChainError` with call context instead
    of silently building an eRPC route for an unknown chain. A local (Anvil/test)
    ``explicit_rpc_url`` still wins for fork tests."""
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
    """Return ``{function_signature: capability_dict}`` for the most
    recent completed analysis of ``address``, or ``None`` if there's
    no analysis / no semantic predicate artifact yet.

    The caller MUST keep ``session`` open for the duration of the
    call — adapters consume the repos lazily inside
    ``evaluate_tree_with_registry``.

    ``chain_id`` is required (invariant 6): it binds the live event/bytecode
    reads to the right chain via a single :class:`ChainContext`. Callers thread
    the job/contract chain — a chainless call can no longer run the predicate
    tree as mainnet.

    ``job_id`` lets in-pipeline callers (e.g. the policy worker's semantic
    enrichment pass) target the job they're currently processing. The
    default ``Job.status == completed`` filter would otherwise skip
    the in-progress job and return None or stale prior artifacts.

    ``chain`` is the string chain identifier (e.g. ``"ethereum"``,
    ``"optimism"``) matching ``Contract.chain``. Together with
    ``job_id`` it scopes the per-job ``ControllerValue`` lookup so a
    re-analysis on a different chain (or a follow-up run on the same
    address) doesn't leak rows back into a completed job's resolved
    capabilities. Falls back to address-only lookup with a warn-log when
    ``job_id`` is None.
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

    # Default chain from Job.request when caller didn't supply one. The
    # downstream ``_load_state_var_values`` only filters by chain when
    # it's non-None, so this is best-effort: a job whose request lacks
    # a 'chain' key falls back to address-only Contract lookup.
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
    # Resolve the RPC URL *from* ``chain_id`` via a single ChainContext so
    # the (chain_id, rpc_url) pair can never disagree. They used to come from
    # independent sources — the request's ``chain_id`` for the URL and the
    # caller's ``chain_id`` argument for the event/bytecode reads — which let the
    # URL point at one chain while the reads ran as another. A local (Anvil/test)
    # explicit rpc_url still wins for fork tests, exactly as before.
    ctx_chain = _resolve_chain_context(chain_id, explicit_rpc_url, chain)
    rpc_url = ctx_chain.rpc_url
    chain_id = ctx_chain.chain_id

    registry = AdapterRegistry()
    # Named standard adapters first (higher matches() scores win); the generic
    # event-indexed adapter is the fallback for non-standard authority.
    registry.register(SolmateRolesAuthorityAdapter)
    registry.register(EnumerableRoleStoreAdapter)
    registry.register(EventIndexedAdapter)

    event_log_repo = PostgresEventLogRepo(session)
    # Lets adapters confirm a contract's standard from its bytecode — e.g. tell a
    # Solmate RolesAuthority from an OZ AccessManager, which share canCall's selector.
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
    # Per-function profiling + per-job capability-kind tally + work-volume
    # counters. This loop is the resolver-side twin of the static stage's
    # ``build_predicate_artifacts`` loop, which has predicate_function_slow /
    # predicate_summary lines; this one had none, so a function (or a cold
    # HyperSync fallback) that ran away inside the policy stage was invisible.
    # ``resolve_counters`` rides on each EvaluationContext.meta so the adapter
    # dispatch and the cross-contract inline path increment it (adapter matches,
    # live getter eth_calls, inline recursions, HyperSync scans) — surfacing
    # redundant work without per-RPC latency noise.
    started = time.monotonic()
    per_function_ms: list[tuple[str, int]] = []
    kind_counts: dict[str, int] = {}
    resolve_counters: dict[str, Any] = {}
    # Contract-scoped memo (shared into every function's ctx.meta below, like resolve_counters) of live
    # nullary getter reads. Lets owner()/governor()/external-getter values that miss the persisted feed be
    # read once per resolution pass instead of once per gated function. Discarded with this frame — it is a
    # within-pass dedup, never a cross-run/persistent cache, so it cannot serve stale data across runs.
    live_read_memo: dict[Any, Any] = {}
    slow_threshold_ms = _capability_function_slow_ms()
    # Differential probe (default OFF). Pin ONE block for the whole pass so every
    # probed function is observed at the same height (replay + caching
    # consistency). A None block (non-archive node / blocknum read failure)
    # disables probing for the pass — the probe is strictly additive, so its
    # absence is exactly the current behavior.
    # Pin a finalized head for the WHOLE pass (#119). An unpinned ``block=None``
    # evaluates "at live head", which a durable event index structurally lags, so
    # every event-indexed allowlist would demote to ``lower_bound``. Pin a height
    # stepped back ``RESOLVER_FINALITY_MARGIN`` from head — deeper than the indexer's
    # confirmation depth — so a keeping-up cursor DETERMINISTICALLY covers it (no
    # resolver-vs-indexer head race) and stays ``exact``, while a stalled cursor falls
    # below it and demotes. Reads every function at one replayable height. ``None``
    # (no RPC / blocknum read failure) leaves ``block`` unpinned -> the fold's
    # coverage gate demotes, the safe direction. The differential probe keeps its own
    # shallower head-12 height (default OFF), independent of this coverage pin.
    resolution_block: int | None = _resolve_resolution_block(rpc_url, block, chain_id=chain_id)
    probe_block: int | None = (
        _resolve_probe_block(rpc_url, block, chain_id=chain_id) if differential_probe_enabled() else None
    )
    # One-shot consumed/live probe (default ON). The runtime address IS a proxy
    # when the analysis artifact came from an implementation child job, or the
    # job carried an explicit ``proxy_address`` — so an unset latch on it is a
    # confirmed live one-shot, not a bare-template false-open. Block is pinned
    # once per pass (reuses the differential-probe block when set) for a
    # consistent read height; lazily resolved only if a one-shot row exists.
    one_shot_enabled = one_shot_probe_enabled()
    db_proxy_linked = (runtime_job.id != analysis_job.id) or (runtime_addr != addr)
    # Pinned one-shot read height, resolved lazily on the FIRST one-shot row so a
    # pass with no initializers makes zero extra wire calls. ``[sentinel]`` marks
    # "not yet resolved"; reuses the differential-probe block when that is set.
    one_shot_block_cell: list[Any] = [probe_block if probe_block is not None else _UNRESOLVED_BLOCK]
    one_shot_pass_cache: dict[tuple[Any, ...], LatchReadResult] = {}
    for fn_signature, tree in (artifact["trees"] or {}).items():
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
        cap_dict = capability_to_dict(cap)
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

    # ``trees`` keys are Slither ``full_name`` signatures, which keep user-defined
    # parameter type names (``addAsset(ERC20)``, ``executeTasks(IFoo.Report)``).
    # The real EVM selector — and ``effective_functions.selector`` — is keyed on
    # the canonical ABI signature. The static stage precomputes that per function
    # (contract→address, enum→uint8, struct→tuple); prefer it so the selector the
    # Solmate ``canCall`` fold keys on equals the true ``msg.sig``.
    canonical = (canonical_signatures or {}).get(signature)
    if isinstance(canonical, str) and "(" in canonical and canonical.endswith(")"):
        return "0x" + keccak(text=canonical).hex()[:8]

    from services.policy.effective_permissions import _abi_signature
    from services.static.contract_analysis_pipeline.predicate_artifacts import is_canonical_abi_signature

    # Fallback: string normalization of full_name. Correct for contract/interface
    # params (→ ``address``); enum/struct params can't be recovered from the name
    # alone (no tuple layout, no uint width), which is why the map above exists.
    # When the lowering is provably incomplete we return no selector rather than
    # one the chain will never dispatch on — a wrong selector silently matches
    # the wrong function, while a missing one only fails to match.
    lowered = _abi_signature(signature)
    if not is_canonical_abi_signature(lowered):
        return None
    return "0x" + keccak(text=lowered).hex()[:8]


# ---------------------------------------------------------------------------
# Differential probe wiring. Gated behind
# ``PSAT_DIFFERENTIAL_PROBE`` (default OFF) in the resolution loop above; these
# helpers run only when the flag is on, so flag-off resolution is byte-identical.
# ---------------------------------------------------------------------------

# Process-level probe cache: a probe is deterministic given
# ``(chain, address, selector, block)`` — the random identities are derived from
# (selector, address) and the block is pinned — so cache the result and skip the
# wire when the same gated-unknown function is re-resolved in-process. Bounded;
# only used on the real-wire production path (a stubbed ``call_batch`` bypasses it
# so tests stay hermetic). Keyed by exact block, never bucketed — a different
# block may see different allowlist state, so re-probing then is correct.
_PROBE_CACHE: dict[tuple[int, str, str, int], "ProbeResult"] = {}
_PROBE_CACHE_MAX = 4096


def clear_probe_cache() -> None:
    """Clear the process-level differential-probe cache (tests / manual reset)."""
    _PROBE_CACHE.clear()


def _probe_cache_put(key: tuple[int, str, str, int], result: "ProbeResult") -> None:
    if len(_PROBE_CACHE) >= _PROBE_CACHE_MAX:
        # Cheap FIFO-ish trim: drop an arbitrary quarter when the bound is hit.
        for stale in list(_PROBE_CACHE.keys())[: _PROBE_CACHE_MAX // 4]:
            _PROBE_CACHE.pop(stale, None)
    _PROBE_CACHE[key] = result


def _resolve_probe_block(rpc_url: str | None, block: int | None, *, chain_id: int | None = None) -> int | None:
    """Pin a concrete probe height. Prefer the caller's ``block``; else read the
    head and step back a finality margin. None on any failure (no RPC, blocknum
    read fails) → probing is skipped for the pass (strictly additive)."""
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
    """Pin the per-pass evaluation height for event-indexed coverage (#119).

    Prefer the caller's explicit ``block`` (a deliberate as-of height). Otherwise
    read live head and step back ``RESOLVER_FINALITY_MARGIN`` — deeper than the
    indexer's confirmation depth so a keeping-up durable cursor provably COVERS the
    pinned height (``cursor >= pin``) despite the poll-interval gap between the
    indexer's last pass and this read, making the fold-coverage gate deterministic.
    ``None`` on no-RPC / blocknum-read-failure leaves the height unpinned, so the
    fold's coverage gate demotes event-indexed sets to ``lower_bound`` — the safe
    (never-fabricates) direction, and exactly the offline/non-archive behavior."""
    if isinstance(block, int) and block > 0:
        return block
    if not rpc_url:
        return None
    try:
        head = int(rpc_request(rpc_url, "eth_blockNumber", [], retries=1, chain_id=chain_id), 16)
    except Exception:
        return None
    return max(1, head - RESOLVER_FINALITY_MARGIN)


def _should_differential_probe(cap: CapabilityExpr) -> bool:
    """True only for the gated-unknown population the probe targets: a
    top-level ``external_check_only`` carrying a caller-gate basis tag — exactly
    ``_is_root_authority_blocker``'s external-check arm. A cold-index self-heal
    deferral is NEVER probed: overwriting its marker would freeze the cold result
    (the Veda RolesAuthority race) instead of letting ``deferred_reconciler``
    converge it once the authority's events backfill."""
    if cap.kind != "external_check_only" or cap.check is None:
        return False
    extra = cap.check.extra or {}
    if extra.get("deferred_pending_index"):
        return False
    basis = extra.get("basis") or []
    return any(tag in CALLER_GATE_BASIS_TAGS for tag in basis)


def _apply_probe_result(cap: CapabilityExpr, result: ProbeResult) -> CapabilityExpr:
    """Land a probe verdict on the capability. Only a confirmed-public
    verdict CHANGES the static verdict (→ ``conditional_universal``); a gated
    confirmation/observation and an inconclusive/indeterminate probe keep the
    static ``external_check_only`` and merely attach the transcript so the verdict
    is reproducible."""
    transcript_step = {"step": "differential_probe", **result.transcript}
    if result.verdict == "public":
        opened = CapabilityExpr.conditional_universal(
            Condition(kind="business", description="differential probe: caller-independent (observed open)")
        )
        opened.trace = list(cap.trace) + [transcript_step]
        return opened
    # Keep the gated verdict; attach the transcript to the check's extra.
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
    """Probe one resolved capability when it is gated-unknown.
    Wrapped in a blanket try/except: a probe failure must never break resolution
    (strictly additive) — on any error the static verdict stands. ``call_batch`` is
    injectable for hermetic tests; defaults to the real ``eth_call_batch`` wire."""
    if not _should_differential_probe(cap):
        return cap
    selector = _selector_for_signature(fn_signature, canonical_signatures)
    if not selector:
        return cap
    # Cache only on the real-wire path; an injected (test) batch bypasses it.
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


# Process-level one-shot latch cache: a read is deterministic given
# ``(chain, address, block, latch-slot signature)`` — the proxy topology and
# init slot don't change at a fixed height — so re-resolving the same contract
# in-process skips the wire. Bounded with a cheap FIFO trim, like the
# differential-probe cache.
_ONE_SHOT_CACHE: dict[tuple[Any, ...], LatchReadResult] = {}
_ONE_SHOT_CACHE_MAX = 4096

# Sentinel for the lazily-resolved one-shot block cell: distinguishes "not yet
# resolved" from a real ``None`` (block read failed → read at latest).
_UNRESOLVED_BLOCK = object()


def clear_one_shot_cache() -> None:
    """Clear the process-level one-shot latch cache (tests / manual reset)."""
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
    """Read the on-chain latch state for a one-shot row and annotate ``cap_dict``
    in place. Strictly additive: any failure leaves the static badge untouched.

    A standard (A-spine) one-shot always annotates its ``one_shot`` condition. A
    structural candidate is promoted to a one_shot condition ONLY when the read
    confirms a real latch (consumed/live) — an indeterminate read leaves the
    generic badge, so the candidate's false-positive class costs one wasted read,
    never a wrong badge.

    ``block_cell`` is a 1-element mutable holder for the pass-pinned read height,
    resolved lazily here so a function with NO one-shot row triggers zero wire
    calls (the ``eth_blockNumber`` head read fires only once a latch is found).
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
        tuple(sorted(str(latch.get("slot") or latch.get("getter_selector") or "") for latch in all_latches)),
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
    # A proxy's own predicate_trees artifact is present but *empty* — it has no
    # logic of its own, so the analyzable functions live on the implementation
    # child job. Treating that empty artifact as "present" (the old
    # ``_job_has_artifact`` check) returns the proxy job and shadows the
    # implementation's real trees, which strands cross-contract authority
    # inlining with an empty tree set and drops the true controller (e.g. an
    # upgrade gate delegating to RoleRegistry.onlyProtocolUpgrader never
    # resolves its owner/timelock). Prefer whichever job carries a *substantive*
    # artifact; only fall back to a present-but-empty one when neither does (a
    # contract that genuinely has no gated functions).
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
    """Whether an artifact carries usable content — not merely that a row exists.

    A proxy contract's ``predicate_trees`` artifact is present but empty (no
    logic of its own), so ``predicate_trees`` counts as substantive only when it
    carries at least one ``trees``/``check_trees`` entry. Other artifact kinds
    count as substantive whenever the row is a dict.
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
    """Read persisted ``controller_values`` rows for ``address`` and key
    them by the bare state-variable name the predicate evaluator looks
    up (e.g. ``"_owner"``, ``"roleRegistry"``).

    The static pipeline writes ``controller_id`` with a
    ``"<kind>:<name>"`` prefix (e.g. ``"state_variable:_owner"``,
    ``"external_contract:roleRegistry"``). The predicate evaluator
    queries ``ctx.state_var_values[<name>]`` without the prefix, so we
    strip it on read and prefer ``state_variable:`` rows when both
    a state-variable and an external-contract row exist for the same
    name.

    Scoping rules:
      - ``Contract.job_id == :job_id`` when ``job_id`` is non-None. Static
        writes a fresh Contract row per analysis job, and resolution writes
        the snapshot's ControllerValue rows under that exact row.
      - ``Contract.chain == :chain`` when ``chain`` is non-None for fallback
        address lookups.

    Picks the exact job Contract when available. Falls back to the latest
    address/chain Contract only when callers do not provide job context or
    rows do not have job_id populated.

    Returns an empty dict when no contract row matches — the evaluator
    falls back to the lower_bound/partial placeholder."""
    if job_id is not None:
        stmt = select(Contract).where(Contract.job_id == job_id)
        if chain is not None:
            stmt = stmt.where(Contract.chain == chain)
        contract = session.execute(stmt.order_by(Contract.created_at.desc()).limit(1)).scalar_one_or_none()
        if contract is not None:
            # Scope to this job's deployment so a shared impl (N proxies → 1 impl
            # row) reads only its own proxy's controller values, not a sibling's.
            job = session.get(Job, job_id)
            deployment = (
                normalize_deployment(job.request.get("proxy_address"))
                if job is not None and isinstance(job.request, dict)
                else None
            )
            return _controller_values_for_contract(session, contract, deployment, scope_deployment=True)
    else:
        # No job context → address-only lookup can surface controller rows from a
        # different job/chain (cross-tenant leakage). Degrade + breadcrumb.
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
        # One impl row can hold N per-proxy controller sets; read only this
        # deployment's (plus legacy untagged NULL) rows. No-op for 1:1.
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
    # state_variable rows win; external_contract / role_identifier rows
    # fill in only when there's no direct state-variable value.
    return {**other, **state_var}


def capability_to_dict(cap: CapabilityExpr) -> dict[str, Any]:
    """Serialize a ``CapabilityExpr`` to a JSON-ready dict.

    Recurses through ``children`` (AND / OR composition) and
    ``signer`` (signature_witness wraps another CapabilityExpr).
    Drops keys whose value is the dataclass default (None / empty
    list) so the wire shape is compact.
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
    if cap.trace:
        out["trace"] = list(cap.trace)
    # Only emit when non-default so root-caller capabilities (the vast majority) keep
    # their existing wire shape; ``bound`` marks an inlined downstream-call subject.
    if cap.subject != "root":
        out["subject"] = cap.subject
    # ALWAYS emitted on a cofinite, never elsewhere. The old
    # emit-when-non-default rule made ABSENCE mean ``exact``: a consumer that has
    # never heard of this key read every cofinite denylist as a COMPLETE
    # exclusion, which is the strong claim — the one place where a hedge's
    # default was the assertion rather than the caution. Absence
    # now means "this capability is not a denylist", so the question of denylist
    # completeness simply does not arise; a present ``lower_bound`` says at least
    # these are excluded, so the complement is an upper bound on who may call.
    if cap.kind == "cofinite_blacklist":
        out["blacklist_quality"] = cap.blacklist_quality
    elif cap.blacklist_quality != "exact":
        # A non-cofinite carrying a non-default blacklist quality would be a
        # producer bug; emit it rather than silently dropping the anomaly.
        out["blacklist_quality"] = cap.blacklist_quality
    # Emit-when-non-default: only labeled empties carry a reason, so populated
    # sets and pre-existing empties keep their wire shape. Carries the
    # empty-by-design ceiling / read-failure flavor to the persisted
    # ``capability_expr`` the policy + surface layers read.
    if cap.empty_reason is not None:
        out["empty_reason"] = cap.empty_reason
    return out
