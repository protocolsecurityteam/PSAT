"""Authenticated submission/status/result endpoints; no compilation or inference in HTTP handlers."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from db.storage import StorageError
from schemas.logic_jobs import AssessRequest, EnumerateRequest, GenerateRequest
from services.logic.source_context import digest
from services.logic_jobs import (
    LogicJobNotFound,
    LogicJobNotReady,
    completed_result,
    enqueue,
    logic_job,
    request_of,
    status,
)
from services.resolution.logic_selection import selections_from_report
from utils.chains import UnsupportedChainError, require_supported_chain

from . import deps

router = APIRouter(prefix="/api/logic", tags=["logic"], dependencies=[Depends(deps.require_admin)])


def _result(session, job_id, operation=None):
    try:
        return completed_result(session, job_id, operation)
    except LogicJobNotFound as exc:
        raise HTTPException(404, str(exc)) from exc
    except LogicJobNotReady as exc:
        raise HTTPException(409, str(exc)) from exc
    except StorageError as exc:
        raise HTTPException(503, "Input artifact storage is unavailable") from exc


def _supported(chain_id: int):
    try:
        return require_supported_chain(chain_id, context="logic submission")
    except UnsupportedChainError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/generate", status_code=202)
def generate(body: GenerateRequest, actor: str = Depends(deps.admin_actor)) -> dict:
    chain = _supported(body.chain_id)
    with deps.SessionLocal() as session:
        params = body.model_dump(mode="json")
        input_hash = None
        if body.resume_job_id is not None:
            _, previous = _result(session, body.resume_job_id, "generate")
            if (previous["address"].lower(), previous["chain_id"]) != (body.address, body.chain_id):
                raise HTTPException(409, "Resume target does not match generation")
            if body.block is not None and body.block != previous["block"]:
                raise HTTPException(409, "Resume must use the original block")
            if not previous.get("pending_functions"):
                raise HTTPException(409, "Generation has no pending functions")
            scope = previous.get("generation_scope", {})
            for key in ("related_addresses", "context_chars"):
                if key in scope:
                    if key in body.model_fields_set and params[key] != scope[key]:
                        raise HTTPException(409, "Resume must preserve the generation scope")
                    params[key] = scope[key]
            params["block"] = previous["block"]
            input_hash = digest(previous)
        job = enqueue(
            session,
            "generate",
            params,
            chain=chain.name,
            chain_id=chain.chain_id,
            address=body.address,
            actor=actor,
            input_hash=input_hash,
        )
        deps.log_admin_mutation("logic_generate", actor=actor, job_id=str(job.id))
        return status(job)


@router.post("/assess", status_code=202)
def assess(body: AssessRequest, actor: str = Depends(deps.admin_actor)) -> dict:
    with deps.SessionLocal() as session:
        parent, formulas = _result(session, body.formula_job_id, "generate")
        _supported(formulas["chain_id"])
        job = enqueue(
            session,
            "assess",
            body.model_dump(mode="json"),
            chain=request_of(parent)["chain"],
            chain_id=formulas["chain_id"],
            address=formulas["address"],
            actor=actor,
            input_hash=digest(formulas),
        )
        deps.log_admin_mutation("logic_assess", actor=actor, job_id=str(job.id))
        return status(job)


@router.post("/enumerate", status_code=202)
def enumerate_addresses(body: EnumerateRequest, actor: str = Depends(deps.admin_actor)) -> dict:
    with deps.SessionLocal() as session:
        parent, assessment = _result(session, body.assessment_job_id, "assess")
        _, formulas = _result(session, UUID(request_of(parent)["params"]["formula_job_id"]), "generate")
        _supported(formulas["chain_id"])
        try:
            selections = selections_from_report(formulas, assessment)
            if set(body.functions) - selections.keys():
                raise ValueError("Requested function has no assessed expansion recommendation")
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        job = enqueue(
            session,
            "enumerate",
            body.model_dump(mode="json"),
            chain=request_of(parent)["chain"],
            chain_id=formulas["chain_id"],
            address=formulas["address"],
            actor=actor,
            input_hash=digest({"formulas": formulas, "assessment": assessment}),
        )
        deps.log_admin_mutation("logic_enumerate", actor=actor, job_id=str(job.id))
        return status(job)


@router.get("/jobs/{job_id}")
def get_status(job_id: UUID) -> dict:
    with deps.SessionLocal() as session:
        try:
            return status(logic_job(session, job_id))
        except LogicJobNotFound as exc:
            raise HTTPException(404, str(exc)) from exc


@router.get("/jobs/{job_id}/result")
def get_result(job_id: UUID) -> dict:
    with deps.SessionLocal() as session:
        _, result = _result(session, job_id)
        return result
