"""Predicate capability + probe endpoints.

Hosts the read path that consumes the semantic ``predicate_trees`` artifact:
 - per-contract / per-company capability resolution
 - membership and signature probes against individual leaves
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from db.models import Job, JobStatus, Protocol
from utils.chains import require_chain

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Probe rate limiter
# ---------------------------------------------------------------------------
# v4 plan §15 spec is "10/min/key/contract" — sliding-window per
# (admin_key, address). PSAT_PROBE_RATE_LIMIT and PSAT_PROBE_RATE_WINDOW_S
# override. Each worker has its own state so a multi-worker deployment
# allows up to N×limit requests in aggregate; that's an acceptable first
# cut. Long-term: shared store (Redis) for fleet-wide accounting.

_PROBE_RATE_LIMIT = int(os.environ.get("PSAT_PROBE_RATE_LIMIT", "10"))
_PROBE_RATE_WINDOW_S = float(os.environ.get("PSAT_PROBE_RATE_WINDOW_S", "60"))
_probe_rate_state: dict[tuple[str, str, int], Any] = {}


def _prune_probe_rate_state(now: float) -> None:
    for key, state in list(_probe_rate_state.items()):
        while state and state[0] + _PROBE_RATE_WINDOW_S < now:
            state.popleft()
        if not state:
            _probe_rate_state.pop(key, None)


def _probe_rate_check(admin_key: str | None, address: str, chain_id: int) -> None:
    """Raise HTTPException(429) when the (admin_key, address, chain_id) sliding
    window has hit its limit. No-op when the limit is 0 (env override
    for testing / disabled-by-default flag use).

    The chain is part of the bucket key (inv. 12): the same address on two chains
    is two distinct contracts, so probing one must not consume the other's budget.
    Defaults to mainnet so a caller that omits it keeps the mainnet bucket."""
    if _PROBE_RATE_LIMIT <= 0:
        return
    import collections as _collections
    import time as _time

    now = _time.time()
    _prune_probe_rate_state(now)
    key = (admin_key or "<no-key>", address.lower(), chain_id)
    state = _probe_rate_state.get(key)
    if state is None:
        state = _collections.deque()
        _probe_rate_state[key] = state
    if len(state) >= _PROBE_RATE_LIMIT:
        retry_after = max(0, int(state[0] + _PROBE_RATE_WINDOW_S - now)) + 1
        raise HTTPException(
            status_code=429,
            detail=(
                f"Probe rate limit exceeded for this admin key + contract "
                f"({_PROBE_RATE_LIMIT} requests / "
                f"{int(_PROBE_RATE_WINDOW_S)}s). Retry in ~{retry_after}s."
            ),
            headers={"Retry-After": str(retry_after)},
        )
    state.append(now)


# ---------------------------------------------------------------------------
# Capabilities response cache
# ---------------------------------------------------------------------------
# In-process TTL cache for /api/contract/{addr}/capabilities. Per the v4
# plan §15 ("Response cache 60 blocks") — at 12s/block on mainnet that's
# ~12 minutes; we accept seconds for chain-agnostic simplicity.
# PSAT_CAPABILITIES_CACHE_TTL_S overrides; 0 disables. Each worker process
# has its own cache; that's fine — the resolver is read-only and the cache
# is best-effort.
_CAPABILITIES_CACHE_TTL_S = float(os.environ.get("PSAT_CAPABILITIES_CACHE_TTL_S", "60"))
_capabilities_cache: dict[tuple[str, int, int | None], tuple[float, dict[str, Any]]] = {}


def _capabilities_cache_get(key: tuple[str, int, int | None]) -> dict[str, Any] | None:
    if _CAPABILITIES_CACHE_TTL_S <= 0:
        return None
    import time as _time

    entry = _capabilities_cache.get(key)
    if entry is None:
        return None
    expires_at, value = entry
    if expires_at < _time.time():
        _capabilities_cache.pop(key, None)
        return None
    return value


def _capabilities_cache_put(key: tuple[str, int, int | None], value: dict[str, Any]) -> None:
    if _CAPABILITIES_CACHE_TTL_S <= 0:
        return
    import time as _time

    _capabilities_cache[key] = (_time.time() + _CAPABILITIES_CACHE_TTL_S, value)


# ---------------------------------------------------------------------------
# Probe request models
# ---------------------------------------------------------------------------


class _ProbeMembershipRequest(BaseModel):
    function_signature: str = Field(..., description="Full signature, e.g. 'grantRole(bytes32,address)'")
    predicate_index: int = Field(..., ge=0, description="DFS-order leaf index in the function's predicate tree")
    member: str = Field(..., description="Address being tested for membership in the leaf's set")
    chain_id: int = Field(default=1, description="Chain id for repo lookups (defaults to ethereum mainnet)")
    block: int | None = Field(default=None, description="Optional block number for point-in-time probes")

    @field_validator("member")
    @classmethod
    def _check_member_address(cls, v: str) -> str:
        if not isinstance(v, str) or not v.startswith("0x") or len(v) != 42:
            raise ValueError("member must be a 0x-prefixed 20-byte address")
        return v.lower()


class _ProbeSignatureRequest(BaseModel):
    function_signature: str = Field(..., description="Full signature, e.g. 'execute(bytes32,bytes)'")
    predicate_index: int = Field(..., ge=0, description="DFS-order leaf index for the signature_auth leaf")
    recovered_signer: str = Field(
        ...,
        description=(
            "Address ECDSA-recovered from (hash, sig) by the caller, OR the address "
            "approving the signature via EIP-1271 isValidSignature. The route checks "
            "whether this address is in the leaf's allowed-signer set."
        ),
    )
    chain_id: int = Field(default=1)
    block: int | None = Field(default=None)

    @field_validator("recovered_signer")
    @classmethod
    def _check_signer_address(cls, v: str) -> str:
        if not isinstance(v, str) or not v.startswith("0x") or len(v) != 42:
            raise ValueError("recovered_signer must be a 0x-prefixed 20-byte address")
        return v.lower()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compute_data_freshness(session, address: str, chain_id: int) -> dict[str, Any]:
    """Return generic indexed-event freshness for ``address``."""
    from db.models import IndexedEventCursor

    row = session.execute(
        select(
            func.count(IndexedEventCursor.topic0),
            func.max(IndexedEventCursor.last_indexed_block),
            func.max(IndexedEventCursor.last_run_at),
        ).where(
            IndexedEventCursor.chain_id == chain_id,
            func.lower(IndexedEventCursor.event_address) == address.lower(),
        )
    ).first()
    if row is None or not row[0]:
        return {"event_logs": None}
    return {
        "event_logs": {
            "cursor_count": int(row[0]),
            "last_indexed_block": row[1],
            "last_run_at": row[2].isoformat() if row[2] else None,
        }
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/api/contract/{address}/probe/membership",
    dependencies=[Depends(deps.require_admin_key)],
)
def probe_contract_membership(
    address: str,
    req: _ProbeMembershipRequest,
    x_psat_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    """Semantic predicate probe: is ``member`` allowed by leaf ``predicate_index``
    of ``function_signature`` on ``address``?'

    Resolves the predicate_trees artifact server-side from the most
    recent successful job for ``address``; the descriptor is NEVER
    client-supplied — clients only carry the leaf index they received
    from the semantic capability rendering.
    """
    addr = deps._normalize_address_or_400(address)
    if "chain_id" not in req.model_fields_set:
        # Admin API edge (inv. 6): chain_id defaults to mainnet; log when taken.
        logger.info("probe_membership: chain_id defaulted to mainnet (chain_id=1) for %s", addr)
    _probe_rate_check(x_psat_admin_key, addr, req.chain_id)

    # Lazy-import the resolver bits so the probe route doesn't impose
    # its dependency surface on the rest of the API.
    from services.resolution.adapters import AdapterRegistry, EvaluationContext
    from services.resolution.adapters.event_indexed import EventIndexedAdapter
    from services.resolution.probe import probe_membership
    from services.resolution.repos import PostgresEventLogRepo

    with deps.SessionLocal() as session:
        job_stmt = (
            select(Job)
            .where(func.lower(Job.address) == addr)
            .where(Job.status == JobStatus.completed)
            .order_by(Job.updated_at.desc(), Job.created_at.desc())
            .limit(1)
        )
        # An explicit chain_id scopes to that chain's job (inv. 12): a CREATE2
        # twin's trees must not cross-load. Absent, the mainnet-default edge
        # (logged above) keeps the address-only most-recent pick.
        if "chain_id" in req.model_fields_set:
            job_stmt = job_stmt.where(Job.chain_id == req.chain_id)
        job = session.execute(job_stmt).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail=f"No completed analysis job found for {addr}")

        artifact = deps.get_artifact(session, job.id, "predicate_trees")
        if artifact is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    "predicate_trees artifact missing for the latest analysis "
                    "(semantic predicate-tree emit did not run or failed)"
                ),
            )

        if not isinstance(artifact, dict) or "trees" not in artifact:
            # Either an error-path placeholder ({"error": "..."}) or a
            # malformed payload — surface the reason rather than silently
            # treating as no-tree.
            reason = artifact.get("error") if isinstance(artifact, dict) else "predicate_trees payload was not a dict"
            return {
                "result": "unknown",
                "reason": "predicate_trees_unavailable",
                "detail": reason,
            }

        tree = artifact["trees"].get(req.function_signature)
        if tree is None:
            # Resolver convention: absent function = unguarded (publicly
            # callable). For probe semantics, that means anyone is in
            # the set.
            return {
                "result": "yes",
                "reason": "function_unguarded",
                "function_signature": req.function_signature,
            }

        registry = AdapterRegistry()
        registry.register(EventIndexedAdapter)
        ctx = EvaluationContext(
            chain_id=req.chain_id,
            contract_address=addr,
            block=req.block,
            event_log_repo=PostgresEventLogRepo(session),
        )

        return probe_membership(
            tree,
            predicate_index=req.predicate_index,
            member=req.member,
            registry=registry,
            ctx=ctx,
        )


@router.post(
    "/api/contract/{address}/probe/signature",
    dependencies=[Depends(deps.require_admin_key)],
)
def probe_contract_signature(
    address: str,
    req: _ProbeSignatureRequest,
    x_psat_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    """Counterpart to /probe/membership for signature_auth leaves.
    Caller already did ECDSA recovery (or EIP-1271 verification); we
    check whether the recovered signer is in the leaf's allowed-signer
    set."""
    from services.resolution.adapters import AdapterRegistry, EvaluationContext
    from services.resolution.adapters.event_indexed import EventIndexedAdapter
    from services.resolution.probe import probe_signature
    from services.resolution.repos import PostgresEventLogRepo

    addr = deps._normalize_address_or_400(address)
    if "chain_id" not in req.model_fields_set:
        # Admin API edge (inv. 6): chain_id defaults to mainnet; log when taken.
        logger.info("probe_signature: chain_id defaulted to mainnet (chain_id=1) for %s", addr)
    _probe_rate_check(x_psat_admin_key, addr, req.chain_id)
    with deps.SessionLocal() as session:
        job_stmt = (
            select(Job)
            .where(func.lower(Job.address) == addr)
            .where(Job.status == JobStatus.completed)
            .order_by(Job.updated_at.desc(), Job.created_at.desc())
            .limit(1)
        )
        # An explicit chain_id scopes to that chain's job (inv. 12); absent,
        # the mainnet-default edge (logged above) keeps the most-recent pick.
        if "chain_id" in req.model_fields_set:
            job_stmt = job_stmt.where(Job.chain_id == req.chain_id)
        job = session.execute(job_stmt).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail=f"No completed analysis job found for {addr}")
        artifact = deps.get_artifact(session, job.id, "predicate_trees")
        if artifact is None:
            raise HTTPException(
                status_code=404,
                detail="predicate_trees artifact missing for the latest analysis",
            )
        if not isinstance(artifact, dict) or "trees" not in artifact:
            return {
                "result": "unknown",
                "reason": "predicate_trees_unavailable",
                "detail": (artifact.get("error") if isinstance(artifact, dict) else "malformed"),
            }
        tree = artifact["trees"].get(req.function_signature)
        if tree is None:
            return {
                "result": "yes",
                "reason": "function_unguarded",
                "function_signature": req.function_signature,
            }

        registry = AdapterRegistry()
        registry.register(EventIndexedAdapter)
        ctx = EvaluationContext(
            chain_id=req.chain_id,
            contract_address=addr,
            block=req.block,
            event_log_repo=PostgresEventLogRepo(session),
        )

        return probe_signature(
            tree,
            predicate_index=req.predicate_index,
            recovered_signer=req.recovered_signer,
            registry=registry,
            ctx=ctx,
        )


@router.get("/api/contract/{address}/capabilities")
def get_contract_capabilities(
    address: str,
    chain_id: int = 1,
    block: int | None = None,
) -> dict[str, Any]:
    """Return semantic capabilities per externally-callable function on
    ``address``.

    Response shape::

        {
          "contract_address": "0x...",
          "chain_id": 1,
          "block": null,
          "capabilities": {
            "grantRole(bytes32,address)": {
              "kind": "finite_set",
              "members": ["0x..."],
              "membership_quality": "exact",
              "confidence": "enumerable",
              ...
            },
            ...
          }
        }

    Empty ``capabilities`` dict means every function on the contract is
    unguarded (publicly callable) per the resolver convention.

    Returns 404 if no completed analysis Job exists for the address, or
    no predicate_trees artifact has been written for the latest analysis.
    """
    from services.resolution.capability_resolver import resolve_contract_capabilities

    addr = deps._normalize_address_or_400(address)
    # Admin API edge (inv. 6): chain_id query param defaults to mainnet. Logged so
    # the mainnet assumption is visible for a chainless admin query.
    logger.info("get_contract_capabilities: resolving %s on chain_id=%s (default mainnet=1)", addr, chain_id)
    cache_key = (addr, chain_id, block)
    cached = _capabilities_cache_get(cache_key)
    if cached is not None:
        return cached

    with deps.SessionLocal() as session:
        # Resolve the chain string from the most recent completed Job's
        # request so ``_load_state_var_values`` can scope ``Contract``
        # by (address, chain). The resolver itself defaults from the
        # job's request when chain is None, but doing it here too keeps
        # cache and direct resolver lookups aligned.
        chain_str: str | None = None
        # Hard-filter the job pick to the requested chain (inv. 12): a CREATE2
        # twin's trees must never cross-load. Ordering-by-preference used to fall
        # back to another chain's job when the requested chain had none, serving
        # that chain's trees under the requested chain_id. No job on this chain
        # falls through to the 404 below. Address-scoped jobs always carry a
        # chain_id (Job CHECK constraint), so no legacy NULL-chain row is lost.
        latest_job = session.execute(
            select(Job)
            .where(func.lower(Job.address) == addr)
            .where(Job.status == JobStatus.completed)
            .where(Job.chain_id == chain_id)
            .order_by(
                Job.updated_at.desc(),
                Job.created_at.desc(),
            )
            .limit(1)
        ).scalar_one_or_none()
        no_capabilities_detail = (
            "No semantic capabilities for this address — either no completed "
            "analysis exists or the predicate-tree artifact is missing. Fall "
            "back to /api/company/* or /api/jobs?address=..."
        )
        # No job on the requested chain: 404 directly rather than calling the
        # resolver, whose ``job_id=None`` fallback re-looks-up the job by address
        # alone and would cross-load a twin's trees from another chain.
        if latest_job is None:
            raise HTTPException(status_code=404, detail=no_capabilities_detail)
        if isinstance(latest_job.request, dict):
            req_chain = latest_job.request.get("chain")
            if isinstance(req_chain, str) and req_chain:
                chain_str = req_chain
        capabilities = resolve_contract_capabilities(
            session,
            address=addr,
            chain_id=chain_id,
            block=block,
            job_id=latest_job.id,
            chain=chain_str,
        )
        if capabilities is None:
            raise HTTPException(status_code=404, detail=no_capabilities_detail)
        freshness = _compute_data_freshness(session, addr, chain_id)
    response = {
        "contract_address": addr,
        "chain_id": chain_id,
        "block": block,
        "capabilities": capabilities,
        "data_freshness": freshness,
    }
    _capabilities_cache_put(cache_key, response)
    return response


@router.get("/api/company/{company_name}/semantic_capabilities")
def company_semantic_capabilities(company_name: str) -> dict[str, Any]:
    """Semantic capability map for every analyzed contract in a company.

    Returned as a separate endpoint (not embedded in the company-
    overview payload) because resolving capabilities requires running
    the AdapterRegistry over each contract's predicate trees + repo
    lookups — adds tens of milliseconds per contract, not free to
    include in the already-1-3MB overview response. UI consumers fetch
    this when they want to render resolved guard details without
    inflating the overview response.

    Response shape::

        {
          "company": "<name>",
          "contracts": {
            "0xab...": {
              "guardedFn()": {
                "kind": "finite_set", "members": [...],
                "membership_quality": "exact",
                "confidence": "enumerable", ...
              },
              ...
            },
            "0xcd...": {...},
            "0xef...": null
          },
          "missing_semantic_count": <int>
        }

    A contract with no predicate-tree artifact maps to ``null`` so consumers can
    distinguish "not yet semantically analyzed" from "semantically analyzed and has no
    guarded functions" (the latter maps to ``{}``).

    NOT admin-gated — read-only / idempotent, the same shape contract
    as ``/api/contract/{addr}/capabilities``.
    """
    from services.aggregations.company_overview import _entity_addr, _entity_key, _job_chain_name
    from services.resolution.capability_resolver import resolve_contract_capabilities

    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            raise HTTPException(status_code=404, detail="Company not found")

        # Group completed jobs by composite (chain, address) entity (inv. 13): a
        # CREATE2 twin analyzed on two chains is two entities, resolved against
        # its OWN chain's job. Resolving per bare address collapsed the twin and
        # dropped one chain's capability set. Jobs newest-first within each entity
        # so the per-entity pick and the bare-map winner are deterministic.
        jobs_by_entity: dict[str, list[Job]] = {}
        for job in session.execute(
            select(Job).where(
                Job.protocol_id == protocol_row.id,
                Job.status == JobStatus.completed,
                Job.address.isnot(None),
            )
        ).scalars():
            if not job.address:
                continue
            jobs_by_entity.setdefault(_entity_key(_job_chain_name(job), job.address), []).append(job)

        def _job_recency(job: Job) -> tuple[Any, Any]:
            return (job.updated_at, job.created_at)

        for entity_jobs in jobs_by_entity.values():
            entity_jobs.sort(key=_job_recency, reverse=True)

        # ``contracts_by_entity`` carries one entry per (chain, address); the bare
        # ``contracts`` map keeps one deterministic entry per address (newest
        # completed job across chains wins), preserving the pre-multichain shape
        # for single-chain consumers. ``missing_semantic_count`` counts per entity.
        contracts_by_entity: dict[str, Any] = {}
        missing = 0
        bare_winner: dict[str, tuple[tuple[Any, Any], str]] = {}
        for entity in sorted(jobs_by_entity):
            latest_job = jobs_by_entity[entity][0]
            addr = _entity_addr(entity)
            chain_str: str | None = None
            if isinstance(latest_job.request, dict):
                req_chain = latest_job.request.get("chain")
                if isinstance(req_chain, str) and req_chain:
                    chain_str = req_chain
            try:
                # Job.chain_id is guaranteed for address-scoped jobs (Phase-0
                # dual-write + backfill); a job that still can't resolve raises
                # UnsupportedChainError and lands in the warn-and-count-missing
                # path below rather than 500ing the whole company map.
                chain_info = require_chain(
                    latest_job.chain_id,
                    chain=chain_str,
                    context=f"semantic capabilities for {entity}",
                )
                caps = resolve_contract_capabilities(
                    session,
                    address=addr,
                    chain_id=chain_info.chain_id,
                    job_id=latest_job.id,
                    chain=chain_str,
                )
            except Exception as exc:
                logger.warning(
                    "semantic capability resolution failed for %s in company %s: %s",
                    entity,
                    company_name,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                caps = None
            if caps is None:
                missing += 1
            contracts_by_entity[entity] = caps
            recency = _job_recency(latest_job)
            prior = bare_winner.get(addr)
            if prior is None or recency > prior[0]:
                bare_winner[addr] = (recency, entity)

        contracts = {addr: contracts_by_entity[entity] for addr, (_, entity) in sorted(bare_winner.items())}

        return {
            "company": company_name,
            "contracts": contracts,
            "contracts_by_entity": contracts_by_entity,
            "missing_semantic_count": missing,
        }
