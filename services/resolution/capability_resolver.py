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
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Contract, ControllerValue, Job, JobStatus
from db.queue import get_artifact
from utils.rpc import PUBLIC_ETH_RPC_URL, default_rpc_url

from .adapters import AdapterRegistry, CallFrame, EvaluationContext
from .adapters.event_indexed import EventIndexedAdapter
from .capabilities import CapabilityExpr
from .predicate_evaluator import evaluate_tree_with_registry
from .repos import PostgresEventLogRepo

logger = logging.getLogger(__name__)
DEFAULT_RPC_URL = os.getenv("ETH_RPC", PUBLIC_ETH_RPC_URL)


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


def resolve_contract_capabilities(
    session: Session,
    *,
    address: str,
    chain_id: int = 1,
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
    rpc_url: str | None = None
    rpc_chain_id: int | str | None = None
    for candidate_job in (analysis_job, runtime_job):
        if not isinstance(candidate_job.request, dict):
            continue
        if rpc_chain_id is None:
            rpc_chain_id = candidate_job.request.get("chain_id")
        if isinstance(candidate_job.request.get("rpc_url"), str):
            rpc_url = candidate_job.request["rpc_url"]
            break
    rpc_url = (
        default_rpc_url(
            explicit_rpc_url=rpc_url,
            chain_id=rpc_chain_id,
            chain=chain,
            fallback_url=os.getenv("ETH_RPC") or DEFAULT_RPC_URL,
        )
        or DEFAULT_RPC_URL
    )

    registry = AdapterRegistry()
    registry.register(EventIndexedAdapter)

    event_log_repo = PostgresEventLogRepo(session)
    state_var_values = _load_state_var_values(
        session,
        analysis_job.address or addr,
        job_id=analysis_job.id,
        chain=chain,
    )
    if not state_var_values and runtime_job.id != analysis_job.id:
        state_var_values = _load_state_var_values(session, addr, job_id=runtime_job.id, chain=chain)
    out: dict[str, dict[str, Any]] = {}
    for fn_signature, tree in (artifact["trees"] or {}).items():
        ctx = EvaluationContext(
            chain_id=chain_id,
            contract_address=runtime_addr,
            block=block,
            event_log_repo=event_log_repo,
            rpc_url=rpc_url,
            state_var_values=state_var_values,
            session=session,
            call_frame=CallFrame.root(
                contract_address=runtime_addr,
                function_signature=fn_signature if isinstance(fn_signature, str) else None,
                function_selector=_selector_for_signature(fn_signature if isinstance(fn_signature, str) else None),
            ),
        )
        cap = evaluate_tree_with_registry(tree, registry, ctx)
        out[fn_signature] = capability_to_dict(cap)
    return out


def _selector_for_signature(signature: str | None) -> str | None:
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    from eth_utils.crypto import keccak

    return "0x" + keccak(text=signature).hex()[:8]


def _analysis_lookup_for_runtime_job(
    session: Session,
    runtime_job: Job,
    *,
    required_artifact: str,
    chain: str | None,
    completed_only: bool,
) -> AnalysisJobLookup | None:
    if _job_has_artifact(session, runtime_job, required_artifact):
        return AnalysisJobLookup(runtime_job=runtime_job, analysis_job=runtime_job)

    impl_job = _implementation_child_job(session, runtime_job, chain=chain, completed_only=completed_only)
    if impl_job is None:
        return None
    if not _job_has_artifact(session, impl_job, required_artifact):
        return None
    return AnalysisJobLookup(runtime_job=runtime_job, analysis_job=impl_job)


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


def _job_has_artifact(session: Session, job: Job, artifact_name: str) -> bool:
    artifact = get_artifact(session, job.id, artifact_name)
    return isinstance(artifact, dict)


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
            return _controller_values_for_contract(session, contract)
    else:
        logger.warning(
            "_load_state_var_values called without job_id for address=%s; "
            "falling back to address-only Contract lookup. "
            "Capability resolution may surface controller rows from a "
            "different job/chain.",
            address,
        )

    stmt = select(Contract).where(func.lower(Contract.address) == address.lower())
    if chain is not None:
        stmt = stmt.where(Contract.chain == chain)
    stmt = stmt.order_by(Contract.created_at.desc()).limit(1)
    contract = session.execute(stmt).scalar_one_or_none()
    if contract is None:
        return {}
    return _controller_values_for_contract(session, contract)


def _controller_values_for_contract(session: Session, contract: Contract) -> dict[str, str]:
    rows = session.execute(select(ControllerValue).where(ControllerValue.contract_id == contract.id)).scalars()
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
    return out
