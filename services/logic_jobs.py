"""Durable references and lease-fenced checkpoints for the three logic operations."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Job, JobStage, JobStatus
from db.queue import LeaseLost, create_job, get_artifact, store_artifact
from services.clients.jev import JevBudgetExceeded
from services.logic.source_context import digest

RESULT = "logic_result"
OPERATIONS = {"generate": "formulas", "assess": "expansion_selection", "enumerate": "address_expansions"}


class LogicJobNotFound(ValueError):
    pass


class LogicJobNotReady(ValueError):
    pass


def request_of(job: Job) -> dict[str, Any]:
    request = job.request
    if not isinstance(request, dict) or request.get("logic_operation") not in OPERATIONS:
        raise LogicJobNotFound("Logic job not found")
    return request


def logic_job(session: Session, job_id: UUID) -> Job:
    job = session.get(Job, job_id)
    if job is None or (job.request or {}).get("logic_operation") not in OPERATIONS:
        raise LogicJobNotFound("Logic job not found")
    return job


def completed_result(session: Session, job_id: UUID, operation: str | None = None) -> tuple[Job, dict]:
    job = logic_job(session, job_id)
    if operation is not None and request_of(job)["logic_operation"] != operation:
        raise LogicJobNotReady(f"Input must be a {operation} job")
    if job.status != JobStatus.completed:
        raise LogicJobNotReady("Input job has not completed")
    result = get_artifact(session, job.id, RESULT)
    if not isinstance(result, dict) or result.get("kind") != OPERATIONS[request_of(job)["logic_operation"]]:
        raise LogicJobNotReady("Completed job has no valid result artifact")
    if request_of(job).get("result_hash") != digest(result):
        raise LogicJobNotReady("Stored artifact changed after completion")
    return job, result


def enqueue(
    session: Session,
    operation: str,
    params: dict,
    *,
    chain: str,
    chain_id: int,
    address: str,
    actor: str,
    input_hash: str | None = None,
) -> Job:
    # Keep address/protocol_id unset: these auxiliary jobs must never replace a completed production analysis
    # in address-based lookup queries or trigger production enrollment/scoring.
    return create_job(
        session,
        {
            "name": f"logic:{operation}",
            "logic_operation": operation,
            "target_address": address,
            "chain_id": chain_id,
            "chain": chain,
            "actor": actor,
            "params": params,
            "input_hash": input_hash,
            "jev_requests_reserved": 0,
        },
        initial_stage=JobStage.logic,
    )


def _locked(session: Session, job_id: UUID, lease_id: UUID) -> Job:
    job = session.execute(
        select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if job is None or job.status != JobStatus.processing or not lease_id or job.lease_id != lease_id:
        raise LeaseLost("logic job lease moved")
    return job


def pin_block(session: Session, job_id: UUID, lease_id: UUID, block: int) -> int:
    job = _locked(session, job_id, lease_id)
    request = dict(request_of(job))
    params = dict(request["params"])
    if params.get("block") is None:
        params["block"] = block
        request["params"] = params
        job.request = request
    session.commit()
    return params["block"]


def reserve_inference(session: Session, job_id: UUID, lease_id: UUID) -> None:
    """Reserve before sending. Crashes/timeouts consume a reservation; retries cannot reset the cap."""
    job = _locked(session, job_id, lease_id)
    request = dict(request_of(job))
    if request["jev_requests_reserved"] >= request["params"]["max_requests"]:
        session.rollback()
        raise JevBudgetExceeded("durable Jev request budget exhausted")
    request["jev_requests_reserved"] += 1
    job.request = request
    session.commit()


def publish(session: Session, job_id: UUID, lease_id: UUID, result: dict) -> None:
    job = _locked(session, job_id, lease_id)
    if result.get("kind") != OPERATIONS[request_of(job)["logic_operation"]]:
        raise ValueError("Unexpected logic output kind")
    state = (result.get("assessment") or {}).get("status", result.get("status", "available"))
    job.request = {
        **request_of(job),
        "result_state": state,
        "result_hash": digest(result),
        "result_block": result.get("block"),
    }
    # store_artifact commits the metadata with the payload while holding the job-row lock. A stale worker
    # cannot overwrite an artifact after another lease has claimed the job.
    store_artifact(session, job.id, RESULT, result)


def status(job: Job) -> dict:
    request = request_of(job)
    return {
        "job_id": str(job.id),
        "operation": request["logic_operation"],
        "status": job.status.value,
        "stage": job.stage.value,
        "chain_id": request["chain_id"],
        "address": request["target_address"],
        "block": request.get("result_block", request["params"].get("block")),
        "result_state": request.get("result_state"),
        "jev_requests_reserved": request.get("jev_requests_reserved", 0),
        "retry_count": job.retry_count,
        "detail": job.detail,
        "error": job.error,
        "status_url": f"/api/logic/jobs/{job.id}",
        "result_url": f"/api/logic/jobs/{job.id}/result",
    }
