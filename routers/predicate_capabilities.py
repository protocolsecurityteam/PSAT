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
from services.artifacts import get_artifact_field
from utils.rpc import default_rpc_url, require_supported_chain_id

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
_probe_rate_state: dict[tuple[str, str], Any] = {}


def _prune_probe_rate_state(now: float) -> None:
    for key, state in list(_probe_rate_state.items()):
        while state and state[0] + _PROBE_RATE_WINDOW_S < now:
            state.popleft()
        if not state:
            _probe_rate_state.pop(key, None)


def _probe_rate_check(admin_key: str | None, address: str, chain_id: int) -> None:
    """Raise HTTPException(429) when the (admin_key, chain_id, address) sliding
    window has hit its limit. No-op when the limit is 0 (env override
    for testing / disabled-by-default flag use)."""
    if _PROBE_RATE_LIMIT <= 0:
        return
    import collections as _collections
    import time as _time

    now = _time.time()
    _prune_probe_rate_state(now)
    key = (admin_key or "<no-key>", f"{chain_id}:{address.lower()}")
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
    chain_id: int = Field(..., ge=1, description="Chain id for repo lookups")
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
    chain_id: int = Field(..., ge=1)
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


def _supported_chain_id_or_400(chain_id: int, *, context: str) -> int:
    try:
        return require_supported_chain_id(chain_id=chain_id, context=context)
    except RuntimeError as exc:
        logger.error("%s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
    chain_id = _supported_chain_id_or_400(req.chain_id, context=f"membership probe for {addr}")
    _probe_rate_check(x_psat_admin_key, addr, chain_id)

    # Lazy-import the resolver bits so the probe route doesn't impose
    # its dependency surface on the rest of the API.
    from services.resolution.adapters import AdapterRegistry, EvaluationContext
    from services.resolution.adapters.event_indexed import EventIndexedAdapter
    from services.resolution.probe import probe_membership
    from services.resolution.repos import PostgresEventLogRepo

    with deps.SessionLocal() as session:
        job = session.execute(
            select(Job)
            .where(func.lower(Job.address) == addr)
            .where(Job.chain_id == chain_id)
            .where(Job.status == JobStatus.completed)
            .order_by(Job.updated_at.desc(), Job.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail=f"No completed analysis job found for {chain_id}:{addr}")

        artifact = get_artifact_field(session, job.id, "predicate_trees")
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
        rpc_url = default_rpc_url(chain_id=chain_id)
        ctx = EvaluationContext(
            chain_id=chain_id,
            rpc_url=rpc_url,
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
    chain_id = _supported_chain_id_or_400(req.chain_id, context=f"signature probe for {addr}")
    _probe_rate_check(x_psat_admin_key, addr, chain_id)
    with deps.SessionLocal() as session:
        job = session.execute(
            select(Job)
            .where(func.lower(Job.address) == addr)
            .where(Job.chain_id == chain_id)
            .where(Job.status == JobStatus.completed)
            .order_by(Job.updated_at.desc(), Job.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail=f"No completed analysis job found for {chain_id}:{addr}")
        artifact = get_artifact_field(session, job.id, "predicate_trees")
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
        rpc_url = default_rpc_url(chain_id=chain_id)
        ctx = EvaluationContext(
            chain_id=chain_id,
            rpc_url=rpc_url,
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
    chain_id: int,
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
    chain_id = _supported_chain_id_or_400(chain_id, context=f"contract capabilities for {addr}")
    cache_key = (addr, chain_id, block)
    cached = _capabilities_cache_get(cache_key)
    if cached is not None:
        return cached

    with deps.SessionLocal() as session:
        latest_job = session.execute(
            select(Job)
            .where(func.lower(Job.address) == addr)
            .where(Job.chain_id == chain_id)
            .where(Job.status == JobStatus.completed)
            .order_by(Job.updated_at.desc(), Job.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        capabilities = resolve_contract_capabilities(
            session,
            address=addr,
            chain_id=chain_id,
            block=block,
            job_id=latest_job.id if latest_job is not None else None,
        )
        if capabilities is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    "No semantic capabilities for this address — either no completed "
                    "analysis exists or the predicate-tree artifact is missing."
                ),
            )
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
            "1:0xab...": {
              "address": "0xab...",
              "chain_id": 1,
              "capabilities": {
                "guardedFn()": {
                  "kind": "finite_set", "members": [...],
                  "membership_quality": "exact",
                  "confidence": "enumerable", ...
                },
                ...
              }
            },
            "8453:0xab...": {
              "address": "0xab...",
              "chain_id": 8453,
              "capabilities": null
            }
          },
          "missing_semantic_count": <int>
        }

    A contract with no predicate-tree artifact has ``capabilities: null`` so
    consumers can distinguish "not yet semantically analyzed" from
    "semantically analyzed and has no guarded functions" (the latter maps
    ``capabilities`` to ``{}``).
    """
    from services.resolution.capability_resolver import resolve_contract_capabilities

    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            raise HTTPException(status_code=404, detail="Company not found")

        jobs = session.execute(
            select(Job).where(
                Job.protocol_id == protocol_row.id,
                Job.status == JobStatus.completed,
                Job.address.isnot(None),
                Job.chain_id.isnot(None),
            )
            .order_by(Job.updated_at.desc(), Job.created_at.desc(), Job.id.desc())
        ).scalars()
        latest_by_identity: dict[tuple[int, str], Job] = {}
        for job in jobs:
            if not job.address or job.chain_id is None:
                continue
            addr = job.address.lower()
            chain_id = _supported_chain_id_or_400(
                job.chain_id,
                context=f"company semantic capabilities for {company_name} job {job.id}",
            )
            key = (chain_id, addr)
            if key not in latest_by_identity:
                latest_by_identity[key] = job

        contracts: dict[str, Any] = {}
        missing = 0
        for (chain_id, addr), latest_job in sorted(latest_by_identity.items()):
            try:
                caps = resolve_contract_capabilities(
                    session,
                    address=addr,
                    job_id=latest_job.id,
                    chain_id=chain_id,
                )
            except Exception as exc:
                logger.error(
                    "semantic capability resolution failed for chain_id=%s address=%s in company %s: %s",
                    chain_id,
                    addr,
                    company_name,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                raise HTTPException(
                    status_code=502,
                    detail=f"semantic capability resolution failed for {chain_id}:{addr}",
                ) from exc
            if caps is None:
                missing += 1
            contracts[f"{chain_id}:{addr}"] = {
                "address": addr,
                "chain_id": chain_id,
                "capabilities": caps,
            }

        return {
            "company": company_name,
            "contracts": contracts,
            "missing_semantic_count": missing,
        }
