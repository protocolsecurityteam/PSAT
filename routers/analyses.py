"""Analysis listing, detail, and artifact endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import func, select

from db.models import Artifact, Contract, Job, JobStatus
from schemas.common import make_contract
from schemas.governance_schemas import AnalysisListEntry
from services.aggregations import build_analysis_detail
from services.aggregations.analysis_detail import AmbiguousAnalysisLookup
from services.artifacts import expand_available_artifact_names, get_artifact_or_stage_field
from services.governance.proxies import _merge_proxy_impl_entries
from utils.rpc import require_supported_chain_id

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/analyses")
def analyses(response: Response) -> list[AnalysisListEntry]:
    """List completed analyses with their available artifacts."""
    # Read-mostly listing — let the browser reuse it across navigations.
    # Short max-age + SWR keeps freshness while letting back/forward and
    # rapid re-renders avoid a network round-trip for the multi-MB payload.
    response.headers["Cache-Control"] = "private, max-age=15, stale-while-revalidate=60"
    with deps.SessionLocal() as session:
        stmt = select(Job).where(Job.status == JobStatus.completed).order_by(Job.updated_at.desc())
        jobs = session.execute(stmt).scalars().all()

        jobs_by_id = {str(job.id): job for job in jobs}
        jobs_by_identity: dict[tuple[str, int | None], Job] = {}
        for job in jobs:
            if job.address:
                jobs_by_identity.setdefault((job.address.lower(), job.chain_id), job)

        # Rank scores, chains, name, proxy_type, implementation come from
        # the ``contracts`` table. is_proxy comes from Job (denormalized via
        # store_artifact). Pulling all of these from columns lets us skip
        # the per-job ``contract_flags`` storage GET entirely — at 25ms
        # production RTT × N jobs, that GET batch was the dominant cost
        # of this endpoint after the parallel-fanout commit.
        contracts_by_key: dict[tuple[str, int | None], Contract] = {}
        addresses_from_jobs = list({address for address, _chain_id in jobs_by_identity})
        if addresses_from_jobs:
            for c in session.execute(select(Contract).where(Contract.address.in_(addresses_from_jobs))).scalars():
                addr_lower = (c.address or "").lower()
                if addr_lower:
                    contracts_by_key.setdefault((addr_lower, c.chain_id), c)

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

    results: list[AnalysisListEntry] = []
    for job in jobs:
        run_name = job.name or str(job.id)
        request = job.request if isinstance(job.request, dict) else {}
        parent_job_id = request.get("parent_job_id")
        company = company_for_job(job)
        contract = contracts_by_key.get((job.address.lower(), job.chain_id)) if job.address else None
        chain_id = job.chain_id
        if chain_id is None:
            raise RuntimeError(f"analysis job {job.id} requires chain_id")
        entry: AnalysisListEntry = {
            "run_name": run_name,
            "job_id": str(job.id),
            "address": job.address,
            "chain_id": chain_id,
            "company": company,
            "parent_job_id": parent_job_id,
            "rank_score": (float(contract.rank_score) if contract and contract.rank_score is not None else None),
            "is_proxy": bool(job.is_proxy),
            "proxy_type": contract.proxy_type if contract else None,
            "implementation_address": contract.implementation if contract else None,
            "proxy_address": request.get("proxy_address"),
        }
        if contract is not None:
            if contract.chain_id is None:
                raise RuntimeError(f"contract {contract.id} requires chain_id for analyses list")
            entry["contract"] = make_contract(
                address=contract.address,
                chain_id=contract.chain_id,
                name=contract.contract_name,
                label=run_name,
                is_proxy=bool(contract.is_proxy),
                proxy_address=contract.address if contract.is_proxy else None,
                implementation_addresses=[
                    item for item in [contract.implementation, *(contract.secondary_implementations or [])] if item
                ],
                admin_addresses=[contract.admin] if contract.admin else [],
                beacon_addresses=[contract.beacon] if contract.beacon else [],
                deployer_address=contract.deployer,
                proxy_type=contract.proxy_type,
            )
        entry["available_artifacts"] = sorted(expand_available_artifact_names(artifact_names_by_job.get(job.id, [])))

        # Hide proxy entries until the impl is completed — otherwise the
        # listing renders a half-populated card that mutates once the impl
        # lands. ``jobs_by_identity`` only carries completed jobs.
        contract_name_source = contract
        if entry["is_proxy"] and entry["implementation_address"]:
            impl_job = jobs_by_identity.get((entry["implementation_address"].lower(), chain_id))
            if impl_job is None:
                continue
            # Always prefer the impl's name over the proxy shell's. Proxy
            # rows usually carry a generic name like "UUPSProxy" or
            # "TransparentUpgradeableProxy"; the impl's name is the one
            # the user actually recognises (e.g. "WithdrawRequestNFT").
            # Fall back to the proxy's name if the impl Contract row is
            # missing or unnamed.
            impl_address = entry["implementation_address"].lower()
            impl_contract = contracts_by_key.get((impl_address, chain_id))
            if impl_contract is not None and impl_contract.contract_name:
                contract_name_source = impl_contract

        if contract_name_source and contract_name_source.contract_name:
            entry["contract_name"] = contract_name_source.contract_name
        results.append(entry)
    return _merge_proxy_impl_entries(results)


def _looks_like_address(value: str) -> bool:
    return isinstance(value, str) and value.startswith("0x") and len(value) == 42


def _job_by_name(session, run_name: str, *, chain_id: int | None) -> Job | None:
    if chain_id is not None:
        return session.execute(
            select(Job)
            .where(Job.name == run_name, Job.chain_id == chain_id)
            .order_by(Job.updated_at.desc())
            .limit(1)
        ).scalar_one_or_none()

    rows = list(
        session.execute(select(Job).where(Job.name == run_name).order_by(Job.updated_at.desc())).scalars()
    )
    if not rows:
        return None

    chain_ids: set[int | None] = set()
    for row in rows:
        if row.chain_id is None:
            chain_ids.add(None)
            continue
        chain_ids.add(
            require_supported_chain_id(
                chain_id=row.chain_id,
                context=f"analysis artifact name lookup {run_name}",
            )
        )
    if len(chain_ids) > 1:
        logger.error(
            "analysis artifact lookup for name=%r is ambiguous across chain_ids=%s",
            run_name,
            sorted(chain_ids, key=lambda item: -1 if item is None else item),
        )
        raise HTTPException(status_code=409, detail=f"Analysis name {run_name!r} is ambiguous; provide chain_id")
    return rows[0]


@router.get("/api/analyses/{run_name:path}/artifact/{artifact_name:path}")
def analysis_artifact(run_name: str, artifact_name: str, chain_id: int | None = None):
    """Get a specific artifact for an analysis.

    Storage-backed artifacts are fetched from object storage transparently;
    inline (legacy) artifacts are served from Postgres. Either way, the body
    is returned directly to the client.
    """
    with deps.SessionLocal() as session:
        # Find job by name or id or address
        effective_chain_id = (
            require_supported_chain_id(chain_id=chain_id, context=f"analysis artifact lookup for {run_name}")
            if chain_id is not None
            else None
        )
        job = None
        if not _looks_like_address(run_name):
            job = _job_by_name(session, run_name, chain_id=effective_chain_id)
        if job is None:
            try:
                job = session.get(Job, run_name)
            except Exception:
                session.rollback()
        if job is None:
            if effective_chain_id is None:
                effective_chain_id = require_supported_chain_id(
                    chain_id=chain_id,
                    context=f"analysis artifact address lookup for {run_name}",
                )
            job = session.execute(
                select(Job)
                .where(
                    func.lower(Job.address) == run_name.lower(),
                    Job.chain_id == effective_chain_id,
                    Job.status == JobStatus.completed,
                )
                .order_by(Job.updated_at.desc())
                .limit(1)
            ).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail="Analysis not found")

        # Strip .json/.txt extension for artifact lookup
        lookup_name = artifact_name
        if artifact_name.endswith(".json"):
            lookup_name = artifact_name[:-5]
        elif artifact_name.endswith(".txt"):
            lookup_name = artifact_name[:-4]

        artifact: Any = None
        try:
            artifact = get_artifact_or_stage_field(session, job.id, lookup_name)
            if artifact is None:
                artifact = get_artifact_or_stage_field(session, job.id, artifact_name)
        except Exception as exc:
            logger.error(
                "artifact %s for job %s unreadable; failing request: %s",
                lookup_name,
                job.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            raise HTTPException(status_code=502, detail="Artifact storage read failed") from exc

        if artifact is None:
            raise HTTPException(status_code=404, detail="Artifact not found")

        if isinstance(artifact, (dict, list)):
            return JSONResponse(content=artifact)
        return PlainTextResponse(str(artifact))


@router.get("/api/analyses/{run_name:path}")
def analysis_detail(run_name: str, chain_id: int | None = None) -> dict:
    """Get analysis detail by job name (run_name) or job_id."""
    with deps.SessionLocal() as session:
        try:
            payload = build_analysis_detail(session, run_name, chain_id=chain_id)
        except AmbiguousAnalysisLookup as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if payload is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return payload
