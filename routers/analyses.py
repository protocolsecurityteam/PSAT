"""Analysis listing, detail, and artifact endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select

from db.models import Artifact, Contract, Job, JobStatus
from services.aggregations import build_analysis_detail
from services.governance.proxies import _merge_proxy_impl_entries

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()

# Artifact names the consumer frontend fetches via ``/artifact/``. Any other
# name is operator/internal and gated behind a valid admin key. Compared
# against the requested name after extension-stripping and lower-casing.
_CONSUMER_SAFE_ARTIFACTS = frozenset({"upgrade_history", "dependencies", "dependency_graph_viz", "policy_state"})

# Internal/operator artifacts excluded from the public ``/api/analyses``
# listing so their existence isn't enumerable to anonymous callers.
_INTERNAL_ARTIFACT_NAMES = frozenset({"stage_errors", "stage_timings", "predicate_trees", "control_tracking_plan"})


def _is_internal_artifact_name(name: str) -> bool:
    n = name.lower()
    return n in _INTERNAL_ARTIFACT_NAMES or n.startswith("stage_timing_") or n.endswith("error") or n.endswith("plan")


@router.get("/api/analyses")
def analyses(response: Response) -> list[dict]:
    """List completed analyses with their available artifacts."""
    # Read-mostly listing — let the browser reuse it across navigations.
    # Short max-age + SWR keeps freshness while letting back/forward and
    # rapid re-renders avoid a network round-trip for the multi-MB payload.
    response.headers["Cache-Control"] = "private, max-age=15, stale-while-revalidate=60"
    with deps.SessionLocal() as session:
        stmt = select(Job).where(Job.status == JobStatus.completed).order_by(Job.updated_at.desc())
        jobs = session.execute(stmt).scalars().all()

        jobs_by_id = {str(job.id): job for job in jobs}
        jobs_by_address: dict[str, Job] = {}
        for job in jobs:
            if job.address:
                jobs_by_address.setdefault(job.address.lower(), job)

        # Rank scores, chains, name, proxy_type, implementation come from
        # the ``contracts`` table. is_proxy comes from Job (denormalized via
        # store_artifact). Pulling all of these from columns lets us skip
        # the per-job ``contract_flags`` storage GET entirely — at 25ms
        # production RTT × N jobs, that GET batch was the dominant cost
        # of this endpoint after the parallel-fanout commit.
        contracts_by_address: dict[str, Contract] = {}
        addresses_from_jobs = list(jobs_by_address.keys())
        if addresses_from_jobs:
            for c in session.execute(select(Contract).where(Contract.address.in_(addresses_from_jobs))).scalars():
                addr_lower = (c.address or "").lower()
                if addr_lower:
                    contracts_by_address.setdefault(addr_lower, c)

        job_ids = [job.id for job in jobs]
        # Earlier code fetched every job's ``contract_analysis`` artifact body
        # from object storage just to read ``subject.name`` and ``summary``.
        # Both were redundant: ``contract_name`` is on the prefetched
        # ``Contract`` row and ``summary`` is never consumed by the frontend
        # listing (it's a detail-page field). Reading just artifact NAMES
        # (no body) keeps the available_artifacts list populated without
        # the per-job HTTP round-trip — the dominant cost of this endpoint
        # at production scale.
        artifact_names_by_job: dict[Any, list[str]] = {}
        if job_ids:
            for row in session.execute(
                select(Artifact.job_id, Artifact.name).where(Artifact.job_id.in_(job_ids))
            ).all():
                artifact_names_by_job.setdefault(row[0], []).append(row[1])

    def company_for_job(job: Job) -> str | None:
        seen: set[str] = set()
        current: Job | None = job
        while current is not None:
            if current.company:
                return current.company
            request = current.request if isinstance(current.request, dict) else {}
            parent_job_id = request.get("parent_job_id")
            if not isinstance(parent_job_id, str) or parent_job_id in seen:
                return None
            seen.add(parent_job_id)
            current = jobs_by_id.get(parent_job_id)
        return None

    results = []
    for job in jobs:
        run_name = job.name or str(job.id)
        request = job.request if isinstance(job.request, dict) else {}
        parent_job_id = request.get("parent_job_id")
        company = company_for_job(job)
        addr_lower = (job.address or "").lower()
        contract = contracts_by_address.get(addr_lower)
        entry: dict[str, Any] = {
            "run_name": run_name,
            "job_id": str(job.id),
            "address": job.address,
            "chain": request.get("chain") or (contract.chain if contract else None),
            "company": company,
            "parent_job_id": parent_job_id,
            "rank_score": (float(contract.rank_score) if contract and contract.rank_score is not None else None),
            "is_proxy": bool(job.is_proxy),
            "proxy_type": contract.proxy_type if contract else None,
            "implementation_address": contract.implementation if contract else None,
            "proxy_address": request.get("proxy_address"),
        }
        entry["available_artifacts"] = sorted(
            n for n in artifact_names_by_job.get(job.id, []) if not _is_internal_artifact_name(n)
        )

        # Hide proxy entries until the impl is completed — otherwise the
        # listing renders a half-populated card that mutates once the impl
        # lands. ``jobs_by_address`` only carries completed jobs.
        contract_name_source = contract
        if entry["is_proxy"] and entry["implementation_address"]:
            impl_job = jobs_by_address.get(entry["implementation_address"].lower())
            if impl_job is None:
                continue
            # Always prefer the impl's name over the proxy shell's. Proxy
            # rows usually carry a generic name like "UUPSProxy" or
            # "TransparentUpgradeableProxy"; the impl's name is the one
            # the user actually recognises (e.g. "WithdrawRequestNFT").
            # Fall back to the proxy's name if the impl Contract row is
            # missing or unnamed.
            impl_contract = contracts_by_address.get(entry["implementation_address"].lower())
            if impl_contract is not None and impl_contract.contract_name:
                contract_name_source = impl_contract

        if contract_name_source and contract_name_source.contract_name:
            entry["contract_name"] = contract_name_source.contract_name
        results.append(entry)
    return _merge_proxy_impl_entries(results)


@router.get("/api/analyses/{run_name:path}/artifact/{artifact_name:path}")
def analysis_artifact(
    run_name: str,
    artifact_name: str,
    request: Request,
    x_psat_admin_key: str | None = Header(default=None),
):
    """Get a specific artifact for an analysis.

    Storage-backed artifacts are fetched from object storage transparently;
    inline (legacy) artifacts are served from Postgres. Either way, the body
    is returned directly to the client.

    Only the consumer-safe artifacts are public; any other name requires a
    valid admin key, enforced before any lookup so an unauthorized name yields
    no existence signal and no storage I/O.
    """
    # Strip .json/.txt extension for artifact lookup.
    lookup_name = artifact_name
    if artifact_name.endswith(".json"):
        lookup_name = artifact_name[:-5]
    elif artifact_name.endswith(".txt"):
        lookup_name = artifact_name[:-4]

    if lookup_name.lower() not in _CONSUMER_SAFE_ARTIFACTS:
        deps.require_admin_key(request, x_psat_admin_key)

    with deps.SessionLocal() as session:
        # Find job by name or id or address
        stmt = select(Job).where(Job.name == run_name).order_by(Job.updated_at.desc()).limit(1)
        job = session.execute(stmt).scalar_one_or_none()
        if job is None:
            try:
                job = session.get(Job, run_name)
            except Exception:
                session.rollback()
        if job is None:
            job = session.execute(
                select(Job)
                .where(Job.address == run_name, Job.status == JobStatus.completed)
                .order_by(Job.updated_at.desc())
                .limit(1)
            ).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail="Analysis not found")

        artifact: Any = None
        try:
            artifact = deps.get_artifact(session, job.id, lookup_name)
            if artifact is None:
                artifact = deps.get_artifact(session, job.id, artifact_name)
        except Exception as exc:
            # Storage backend can be transiently unreachable (MinIO/Tigris
            # outage, expired credentials, missing object). Don't 500 — log
            # and fall through to the per-artifact synthesis fallback.
            logger.warning("artifact %s for job %s unreadable: %s", lookup_name, job.id, exc)

        # upgrade_history is reproducible from UpgradeEvent rows. When the
        # stored artifact is gone or storage is down, regenerate from the
        # relational source so the per-proxy detail view stays usable.
        if artifact is None and lookup_name == "upgrade_history":
            from services.discovery.upgrade_history import synthesize_from_events

            contract = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
            if contract is not None:
                artifact = synthesize_from_events(session, contract)

        if artifact is None:
            raise HTTPException(status_code=404, detail="Artifact not found")

        if isinstance(artifact, (dict, list)):
            return JSONResponse(content=artifact)
        return PlainTextResponse(str(artifact))


@router.get("/api/analyses/{run_name:path}")
def analysis_detail(run_name: str) -> dict:
    """Get analysis detail by job name (run_name) or job_id."""
    with deps.SessionLocal() as session:
        payload = build_analysis_detail(session, run_name)
        if payload is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return payload
