from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select, text

from db.models import Artifact, Contract, Job, JobStage, JobStatus, Protocol, derive_job_chain_id
from db.queue import store_artifact
from schemas.api_requests import AnalyzeRequest
from schemas.api_responses import (
    AnalyzeRemainingResponse,
    CancelQueuedJobsResponse,
    DeleteCompanyAddressResponse,
    JobDict,
    JobStageTimingsResponse,
    QueuedJobRef,
)
from schemas.stage_errors import StageError, StageErrors
from services.discovery.membership_gate import (
    HUMAN_ASSERTION_REQUEST_KEY,
    HumanAssertion,
    human_assertion_request_payload,
)
from services.discovery.ranking import not_superseded_impl_clause
from utils.chains import (
    UnknownChainError,
    UnsupportedChainError,
    chain_by_name,
    chain_enabled,
    require_supported_chain,
)

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()

# Admin auth is one shared key, so it's the only provable actor.
W5_ADMIN_ACTOR = "admin_api_key"


@router.get("/api/jobs", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def list_jobs() -> list[JobDict]:
    with deps.SessionLocal() as session:
        stmt = select(Job).order_by(Job.created_at.desc())
        jobs = session.execute(stmt).scalars().all()
        return [job.to_dict() for job in jobs]


@router.post("/api/analyze", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def analyze_address(request: AnalyzeRequest) -> JobDict:
    # Allowlist on the resolved chain, so chainless and company/dapp submissions are unaffected. An address
    # submission naming a chain must name a registered one: the string is stored verbatim.
    if request.address and request.chain and request.chain.strip():
        try:
            chain_by_name(request.chain)
        except UnknownChainError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    resolved_chain_id = derive_job_chain_id(request.chain, request.address)
    if resolved_chain_id is not None:
        try:
            require_supported_chain(resolved_chain_id, context="/api/analyze")
        except UnsupportedChainError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    with deps.SessionLocal() as session:
        # ``rpc_url`` is honored only as a local-node override, so a hosted URL can't shadow eRPC. Sanitized on output.
        req_dict = request.model_dump()
        # Lookup-only, so a typo 404s instead of minting a protocol. The membership claim rides as an attributed W5
        # assertion for the gate, never a source tag.
        if request.address and request.company:
            protocol_row = session.execute(
                select(Protocol).where(func.lower(Protocol.name) == request.company.lower()).limit(1)
            ).scalar_one_or_none()
            if protocol_row is None:
                raise HTTPException(status_code=404, detail="Company not found")
            req_dict["protocol_id"] = protocol_row.id
            req_dict[HUMAN_ASSERTION_REQUEST_KEY] = human_assertion_request_payload(
                HumanAssertion(actor=W5_ADMIN_ACTOR, asserted_at=datetime.now(timezone.utc))
            )
        if request.dapp_urls:
            job = deps.create_job(session, req_dict, initial_stage=JobStage.dapp_crawl)
        elif request.defillama_protocol:
            job = deps.create_job(session, req_dict, initial_stage=JobStage.defillama_scan)
        else:
            job = deps.create_job(session, req_dict)
        deps.log_admin_mutation("analyze_create", id=str(job.id), stage=job.stage.value)
        return job.to_dict()


@router.post(
    "/api/company/{company_name}/analyze-remaining",
    dependencies=[Depends(deps.require_admin_key)],
    response_model=None,
)
def analyze_remaining(company_name: str) -> AnalyzeRemainingResponse:
    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            raise HTTPException(status_code=404, detail="Company not found")

        # Superseded historical impls only anchor audit coverage; single predicate in services/discovery/ranking.
        unanalyzed = (
            session.execute(
                select(Contract).where(
                    Contract.protocol_id == protocol_row.id,
                    Contract.job_id.is_(None),
                    not_superseded_impl_clause(Contract.discovery_sources),
                )
            )
            .scalars()
            .all()
        )

        queued: list[QueuedJobRef] = []
        for contract in unanalyzed:
            # Guards against double-clicks creating duplicate jobs.
            session.refresh(contract, attribute_names=["job_id"])
            if contract.job_id is not None:
                continue
            # Allowlist gate, mirroring the selection worker.
            if not chain_enabled(contract.chain):
                logger.info(
                    "analyze-remaining: skipping stub on non-enabled chain",
                    extra={"address": contract.address, "chain": contract.chain, "reason": "chain_not_enabled"},
                )
                continue
            # Coalesce NULL to ethereum so dedup stays within mainnet (F8).
            existing = deps.find_existing_job_for_address(session, contract.address, chain=contract.chain or "ethereum")
            if existing is not None:
                contract.job_id = existing.id
                session.commit()
                continue
            req_dict = {
                "address": contract.address,
                "name": contract.contract_name or f"{company_name}_{contract.address[2:10]}",
                "chain": contract.chain,
                "protocol_id": protocol_row.id,
                "company": company_name,
            }
            job = deps.create_job(session, req_dict)
            contract.job_id = job.id
            session.commit()
            queued.append({"job_id": str(job.id), "address": contract.address})

        deps.log_admin_mutation("analyze_remaining", id=company_name, count=len(queued))
        return {"queued": len(queued), "jobs": queued}


@router.delete(
    "/api/company/{company_name}/queued-jobs",
    dependencies=[Depends(deps.require_admin_key)],
    response_model=None,
)
def cancel_queued_company_jobs(company_name: str) -> CancelQueuedJobsResponse:
    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            raise HTTPException(status_code=404, detail="Company not found")
        result = session.execute(
            text(
                """
                DELETE FROM jobs
                WHERE company = :company AND status = 'queued'
                RETURNING id
                """
            ),
            {"company": company_name},
        )
        deleted = [str(row_id) for (row_id,) in result]
        session.commit()
    deps.log_admin_mutation("cancel_queued_jobs", id=company_name, count=len(deleted))
    return {"company": company_name, "cancelled": len(deleted), "job_ids": deleted}


@router.delete(
    "/api/company/{company_name}/addresses/{address}",
    dependencies=[Depends(deps.require_admin_key)],
    response_model=None,
)
def delete_company_address(
    company_name: str,
    address: str,
    chain: str = Query(default="ethereum"),
) -> DeleteCompanyAddressResponse:
    """Remove a Contract row.

    Scoped by chain (defaults to mainnet): address alone raised ``MultipleResultsFound``. FK cascades clean up
    coverage and upgrade attribution.
    """
    if not deps._ADDRESS_RE.match(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    try:
        chain_name = chain_by_name(chain).name
    except UnknownChainError:
        raise HTTPException(status_code=400, detail=f"Unknown chain: {chain}") from None
    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            raise HTTPException(status_code=404, detail="Company not found")
        contract = session.execute(
            select(Contract).where(
                Contract.protocol_id == protocol_row.id,
                Contract.address == address,
                func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_name,
            )
        ).scalar_one_or_none()
        if contract is None:
            raise HTTPException(status_code=404, detail="Address not found for this protocol")
        session.delete(contract)
        session.commit()
    deps.log_admin_mutation("delete_company_address", id=address, company=company_name)
    return {"company": company_name, "address": address, "chain": chain_name, "deleted": True}


@router.get("/api/jobs/{job_id}", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def get_job(job_id: str) -> JobDict:
    with deps.SessionLocal() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        return job.to_dict()


class JobErrorsResponse(BaseModel):
    job_id: str
    trace_id: str | None
    status: str
    stage: str
    errors: list[StageError]


@router.get(
    "/api/jobs/{job_id}/errors",
    response_model=JobErrorsResponse,
    dependencies=[Depends(deps.require_admin_key)],
)
def get_job_errors(job_id: str) -> JobErrorsResponse:
    """Empty list when the artifact is missing; 404 means no such job."""
    # A non-UUID would raise ``DataError``; 404 like the other job routes.
    import uuid as _uuid

    try:
        parsed = _uuid.UUID(job_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc
    with deps.SessionLocal() as session:
        job = session.get(Job, parsed)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        raw = deps.get_artifact(session, job.id, "stage_errors")
        errors: list[StageError] = []
        if isinstance(raw, dict):
            try:
                errors = StageErrors.model_validate(raw).errors
            except Exception as exc:
                logger.warning(
                    "stage_errors artifact for job %s did not validate: %s",
                    job.id,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                errors = []
        from utils.secrets import sanitize_obj, sanitize_string

        scrubbed: list[StageError] = []
        for e in errors:
            scrubbed.append(
                e.model_copy(
                    update={
                        "message": sanitize_string(e.message),
                        "traceback": sanitize_string(e.traceback) if e.traceback else e.traceback,
                        "context": sanitize_obj(e.context) if e.context is not None else None,
                    }
                )
            )
        return JobErrorsResponse(
            job_id=str(job.id),
            trace_id=job.trace_id,
            status=job.status.value,
            stage=job.stage.value,
            errors=scrubbed,
        )


@router.post("/api/jobs/{job_id}/retry", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def retry_job(job_id: str) -> JobDict:
    """Operator retry of a ``failed_terminal`` job: reset to a fresh-looking queued row and append a degraded
    ``manual_retry`` StageError so the log doesn't show a silent recovery. 409 for any other state.
    """
    import uuid as _uuid

    try:
        parsed = _uuid.UUID(job_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc
    with deps.SessionLocal() as session:
        # Serializes concurrent retries; otherwise both flip to queued and race on the artifact upsert. Held until the
        # final commit.
        job = session.execute(select(Job).where(Job.id == parsed).with_for_update()).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != JobStatus.failed_terminal:
            raise HTTPException(
                status_code=409,
                detail=f"Job status is {job.status.value}; only failed_terminal jobs can be retried",
            )
        job.status = JobStatus.queued
        job.retry_count = 0
        job.next_attempt_at = None
        job.last_failure_kind = None
        job.detail = "Manual retry requested by operator"
        job.worker_id = None
        job.error = None
        # Same transaction as the status flip, under the row lock. ``degraded`` so consumers don't read it as a failed
        # attempt.
        existing = deps.get_artifact(session, job.id, "stage_errors")
        prior: list[StageError] = []
        corrupt_prior: dict[str, Any] | None = None
        if isinstance(existing, dict):
            try:
                prior = list(StageErrors.model_validate(existing).errors)
            except Exception as exc:
                logger.warning(
                    "stage_errors artifact for job %s did not validate during manual retry: %s",
                    job.id,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                # Keep the unparseable prior body as a breadcrumb so the log isn't lossy.
                prior = []
                corrupt_prior = existing
        if corrupt_prior is not None:
            prior.append(
                StageError(
                    stage=job.stage.value,
                    severity="degraded",
                    exc_type="schema.CorruptPriorArtifact",
                    message="Prior stage_errors body did not validate; raw payload preserved in context.",
                    phase="corrupt_prior",
                    trace_id=job.trace_id,
                    job_id=str(job.id),
                    worker_id="api",
                    failed_at=datetime.now(timezone.utc),
                    retry_count=0,
                    context={"raw": corrupt_prior},
                )
            )
        prior.append(
            StageError(
                stage=job.stage.value,
                severity="degraded",
                exc_type="manual.OperatorRetry",
                message="Operator-initiated retry of failed_terminal job",
                phase="manual_retry",
                trace_id=job.trace_id,
                job_id=str(job.id),
                worker_id="api",
                failed_at=datetime.now(timezone.utc),
                retry_count=0,
                context={"reason": "operator-initiated retry of failed_terminal job"},
            )
        )
        store_artifact(
            session,
            job.id,
            "stage_errors",
            data=StageErrors(errors=prior).model_dump(mode="json"),
        )
        session.refresh(job)
        deps.log_admin_mutation("job_retry", id=str(job.id))
        return job.to_dict()


@router.get("/api/jobs/{job_id}/stage_timings", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def get_job_stage_timings(job_id: str) -> JobStageTimingsResponse:
    """Per-stage timing artifacts keyed by stage, for the bench harness. Admin-gated operator telemetry."""
    with deps.SessionLocal() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        rows = (
            session.execute(
                select(Artifact).where(
                    Artifact.job_id == job.id,
                    Artifact.name.like(r"stage\_timing\_%", escape="\\"),
                )
            )
            .scalars()
            .all()
        )
        # Release the session before slow storage I/O.
        resolved_job_id = str(job.id)
        inline_values: dict[str, Any] = {}
        storage_lookups: dict[str, tuple[str, str | None]] = {}
        for row in rows:
            stage = row.name[len("stage_timing_") :]
            if row.storage_key:
                storage_lookups[stage] = (row.storage_key, row.content_type)
            elif row.data is not None:
                inline_values[stage] = row.data
            elif row.text_data is not None:
                inline_values[stage] = row.text_data

    timings: dict[str, Any] = {stage: v for stage, v in inline_values.items() if isinstance(v, dict)}
    if storage_lookups:
        client = deps.get_storage_client()
        if client is None:
            logger.warning(
                "stage_timings on job %s reference storage_key but storage is not configured; "
                "returning inline timings only",
                resolved_job_id,
            )
        else:
            bodies = client.get_many([key for key, _ in storage_lookups.values()])
            for stage, (key, content_type) in storage_lookups.items():
                body = bodies.get(key)
                if body is None:
                    # Distinct from a stage that never ran.
                    logger.warning(
                        "stage_timing body missing from storage for job %s stage %s",
                        resolved_job_id,
                        stage,
                        extra={"job_id": resolved_job_id, "stage": stage, "storage_key": key},
                    )
                    continue
                value = deps.deserialize_artifact(body, content_type)
                if isinstance(value, dict):
                    timings[stage] = value

    return {"job_id": resolved_job_id, "stage_timings": timings}
