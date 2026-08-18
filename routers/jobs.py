"""Job lifecycle: list, create, fetch, cancel, stage timings."""

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


@router.get("/api/jobs", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def list_jobs() -> list[JobDict]:
    with deps.SessionLocal() as session:
        stmt = select(Job).order_by(Job.created_at.desc())
        jobs = session.execute(stmt).scalars().all()
        return [job.to_dict() for job in jobs]


@router.post("/api/analyze", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def analyze_address(request: AnalyzeRequest) -> JobDict:
    if request.address and not request.address.startswith("0x"):
        raise HTTPException(status_code=400, detail="Address must start with 0x")
    # Allowlist enforcement (inv. 14): the edge keeps its mainnet default, but a
    # submission that resolves to a chain this deployment has not enabled is
    # rejected before a job is spawned. Enforce on the *resolved* chain — the same
    # ``derive_job_chain_id`` value the job carries — so a chainless/mainnet
    # default is unaffected and an address-less company/dapp/defillama submission
    # (no chain identity; it fans out to the protocol's declared chains during
    # discovery, an internal derivation not gated here) is left alone.
    # An address-scoped submission that *names* a chain must name a registered
    # one. ``derive_job_chain_id``'s unknown-chain fallback (warn + mainnet) is
    # an internal-writer edge, not an ingress contract — the string is stored
    # verbatim on the job, so it must resolve here or be rejected.
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
        # Workers honor ``request["rpc_url"]`` only as a local-node override
        # (Anvil / test fork) via ``default_rpc_url``; a hosted URL here is
        # ignored in favor of eRPC, so a pinned provider can't shadow the
        # proxy. Stored verbatim and sanitized by ``Job.to_dict`` at output.
        req_dict = request.model_dump()
        # Optional protocol context: an address submission that also names a
        # company links to the EXISTING protocol row — lookup-only, so a typo'd
        # name 404s instead of minting a duplicate protocol (company-only
        # submissions keep resolving/creating theirs during discovery). The
        # ``"inventory"`` source records the admin's explicit membership
        # assertion so the fetched contract row passes the ownership gate and
        # adopts the protocol. Address-only submissions stay standalone.
        if request.address and request.company:
            protocol_row = session.execute(
                select(Protocol).where(func.lower(Protocol.name) == request.company.lower()).limit(1)
            ).scalar_one_or_none()
            if protocol_row is None:
                raise HTTPException(status_code=404, detail="Company not found")
            req_dict["protocol_id"] = protocol_row.id
            sources = list(req_dict.get("discovery_sources") or [])
            if "inventory" not in sources:
                sources.append("inventory")
            req_dict["discovery_sources"] = sources
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
    """Queue analysis jobs for all discovered-but-not-analyzed contracts in a company."""
    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            raise HTTPException(status_code=404, detail="Company not found")

        # Exclude backfilled *superseded* historical impls — those rows exist
        # only to anchor audit-coverage matching, not to be re-analyzed. The
        # proxy's CURRENT impl is kept (it carries the live marker), since that
        # is where the real functions live. Single source of truth for the
        # anchor predicate: services/discovery/ranking.not_superseded_impl_clause.
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
            # Re-check inside the loop so concurrent calls (double-click or
            # duplicate request) don't each create a job for the same contract.
            session.refresh(contract, attribute_names=["job_id"])
            if contract.job_id is not None:
                continue
            # Allowlist gate (inv. 14), mirroring the selection worker: a stub
            # on a chain this deployment has not enabled is skipped — its
            # discovery evidence stays for a future widened scan, no job spawns.
            if not chain_enabled(contract.chain):
                logger.info(
                    "analyze-remaining: skipping stub on non-enabled chain",
                    extra={"address": contract.address, "chain": contract.chain, "reason": "chain_not_enabled"},
                )
                continue
            # Coalesce NULL→"ethereum" (legacy convention): a NULL-chain contract
            # must still dedup within mainnet, not skip chain filtering entirely
            # and match a job on any chain at the same address (F8).
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
    """Cancel queued jobs for a company; leaves processing/completed/failed untouched."""
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
    """Remove a Contract row from a protocol.

    Scoped to the protocol AND chain: the same address can host a contract on
    two chains within one protocol, so keying by address alone used to raise
    ``MultipleResultsFound`` (a 500). ``chain`` disambiguates and defaults to
    mainnet at this admin edge (inv. 12) so existing single-chain callers are
    unchanged. FK cascades on ``contracts.id`` clean up the audit coverage rows
    and any upgrade-event attribution.
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
                # ``Contract.chain`` is nullable; a legacy NULL row is mainnet, so
                # coalesce keeps the mainnet default matching those rows exactly.
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
    """Response shape for ``GET /api/jobs/{job_id}/errors``."""

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
    """Return the deserialized ``stage_errors`` artifact for a job.

    Returns an empty list when the artifact is missing — every job either
    has zero degraded events and zero failures, or it has the artifact
    documenting them. A 404 is reserved for "no such job".
    """
    # Job.id is a UUID column; a non-UUID string would otherwise raise
    # ``DataError`` at the dialect level — surface as 404 instead so the
    # endpoint matches the rest of the job-routes' behaviour for bad ids.
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
                # Legacy/corrupt payloads shouldn't 500 the endpoint —
                # return them empty and let the operator inspect the
                # underlying artifact directly.
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
    """Operator-initiated retry of a ``failed_terminal`` job.

    Resets ``status`` to ``queued``, ``retry_count`` to 0, ``next_attempt_at``
    to NULL, and ``last_failure_kind`` to NULL so the row looks like a fresh
    submission to the worker fleet. Appends a ``severity="degraded"``
    ``StageError`` to the per-job ``stage_errors`` artifact tagging the manual
    retry — without it the audit log would silently show the job recovering
    on its own.

    409 (not 400) for non-``failed_terminal`` jobs because the request itself
    is well-formed; the conflict is with the job's current state. Done jobs,
    queued jobs, and processing jobs are all rejected so an operator can't
    accidentally clobber an in-flight run.
    """
    import uuid as _uuid

    try:
        parsed = _uuid.UUID(job_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc
    with deps.SessionLocal() as session:
        # ``with_for_update`` serializes concurrent admin retries against the
        # same row: without it, two operators hitting this endpoint at once
        # both observe ``failed_terminal``, both flip to ``queued``, and the
        # artifact-append below would see them race on ``store_artifact``'s
        # upsert (last writer clobbers the first writer's manual_retry entry).
        # The lock is held until the outer ``session.commit()`` below.
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
        # Drop the prior ``error`` text — it referred to the now-superseded
        # terminal failure. The audit log preserves it via the manual_retry
        # entry below + the prior failure entries already in stage_errors.
        job.error = None
        # Read + append + upsert the audit-log artifact in the same
        # transaction as the status flip. The FOR UPDATE row lock above
        # covers everything until the final commit, so a concurrent admin
        # retry blocks here and observes ``queued`` (→ 409) instead of
        # racing on the upsert.
        #
        # Append the manual retry entry so /api/jobs/{id}/errors shows
        # operator intervention as part of the per-job history. Severity
        # ``degraded`` (not ``error``) so consumers don't treat it as a
        # failed attempt — it's a recovery signal.
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
                # Preserve the raw bytes via a degraded breadcrumb so the
                # audit log isn't lossy when an operator retries a job whose
                # prior body fell out of schema (legacy/partial-write/etc.).
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
    """Return all per-stage timing artifacts the worker fleet wrote for
    this job, keyed by stage name. Schema-v2 layout (one
    ``stage_timing_<stage>`` artifact per stage). Used by the bench
    harness to populate ``worker_elapsed_seconds`` reliably without
    scraping Fly logs.

    Admin-gated: the payload is operator execution telemetry (per-stage
    durations, status, metric counts, worker_id) served only to the monitor
    dashboard, not part of the public consumer surface.
    """
    with deps.SessionLocal() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        # Escape `_` so the legacy `stage_timings` artifact doesn't match this prefix scan.
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
        # Read everything we need off the rows before releasing the session
        # so the storage fan-out below doesn't pin a DB connection during
        # slow HTTP I/O.
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
            # Storage env stripped after rows were written. Degrade to inline-only
            # rather than 500 — the SPA copes with a partial timings map.
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
                    # A stage_timing row points at a storage key whose object
                    # is gone — distinct from a stage that never ran. Surface it
                    # so a lost artifact doesn't silently read as "no timing".
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
