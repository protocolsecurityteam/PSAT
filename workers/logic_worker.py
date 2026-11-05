"""Execute one explicit logic operation per durable job; never schedule the next operation."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

from sqlalchemy.orm import Session

from db.models import Job, JobStage, SessionLocal
from db.queue import LeaseLost
from services.clients.jev import JevClient
from services.clients.rpc import require_rpc_url, rpc_request
from services.compute_isolation import run_isolated, static_budget
from services.logic.deployment import _deployment_inputs, deployment_expansions, deployment_formulas
from services.logic.model import Limits, ReadError
from services.logic.source_context import digest
from services.logic_jobs import completed_result, pin_block, publish, request_of, reserve_inference
from services.resolution.logic_assessment import assess_formulas
from services.resolution.logic_impact import JudgmentCache
from services.resolution.logic_selection import ReportLimits, selections_from_report
from utils.chains import require_supported_chain
from workers.base import BaseWorker


class JobJev(JevClient):
    def __init__(self, job_id: UUID, lease_id: UUID, api_key: str, **kwargs):
        super().__init__(api_key, **kwargs)
        self.job_id, self.lease_id = job_id, lease_id

    def ask(self, state: dict, questions: dict) -> dict:
        with SessionLocal() as session:
            reserve_inference(session, self.job_id, self.lease_id)
        return super().ask(state, questions)


def execute_operation(job_id: UUID, lease_id: UUID, request: dict, rpc_url: str) -> dict:
    """Isolated compute entrypoint: its own DB/HTTP clients, no inherited session."""
    params, operation = request["params"], request["logic_operation"]
    with SessionLocal() as session:
        if operation == "generate":
            previous = None
            if params.get("resume_job_id"):
                _, previous = completed_result(session, UUID(params["resume_job_id"]), "generate")
                if digest(previous) != request["input_hash"]:
                    raise ValueError("Input checkpoint artifact changed after submission")
            return deployment_formulas(
                session,
                params["address"],
                params["chain_id"],
                rpc_url,
                block=params["block"],
                related_addresses=tuple(params["related_addresses"]),
                context_chars=params["context_chars"],
                expansion_steps=params.get("expansion_steps", 5000),
                loop_iterations=params.get("loop_iterations", 32),
                callee_depth=params.get("callee_depth", 8),
                value_steps=params.get("value_steps", 50_000),
                resume=previous,
            )
        if operation == "assess":
            _, formulas = completed_result(session, UUID(params["formula_job_id"]), "generate")
            if digest(formulas) != request["input_hash"]:
                raise ValueError("Input formula artifact changed after submission")
            key = os.environ.get("TYPESAFE_API_KEY") or os.environ.get("JEV_API_KEY", "")
            client = (
                JobJev(
                    job_id,
                    lease_id,
                    key,
                    max_requests=params["max_requests"],
                    long_context=params.get("long_context", False),
                )
                if key and not params["cache_only"]
                else None
            )
            cache = JudgmentCache(Path(os.environ.get("PSAT_LOGIC_JEV_CACHE", ".cache/logic-jev")))
            with _deployment_inputs(session, formulas["chain_id"], rpc_url, formulas["block"]) as (reads, contracts):
                return assess_formulas(
                    formulas,
                    cache=cache,
                    client=client,
                    reads=reads,
                    contracts=contracts,
                    limits=ReportLimits(
                        direct_reads=params["direct_reads"],
                        solver_ms=params["solver_ms"],
                        solver_queries=params["solver_queries"],
                    ),
                )
        if operation == "enumerate":
            parent, assessment = completed_result(session, UUID(params["assessment_job_id"]), "assess")
            _, formulas = completed_result(session, UUID(request_of(parent)["params"]["formula_job_id"]), "generate")
            if digest({"formulas": formulas, "assessment": assessment}) != request["input_hash"]:
                raise ValueError("Input artifacts changed after submission")
            plan = selections_from_report(formulas, assessment)
            if set(params["functions"]) - plan.keys():
                raise ValueError("Function has no assessed expansion recommendation")
            return deployment_expansions(
                session,
                formulas,
                rpc_url,
                {name: plan[name] for name in params["functions"]},
                limits=Limits(
                    members=params["members"],
                    solver_ms=params["solver_ms"],
                    storage_steps=params.get("storage_steps", Limits().storage_steps),
                ),
            )
        raise ValueError("Unknown logic operation")


class LogicWorker(BaseWorker):
    stage = JobStage.logic
    next_stage = JobStage.done

    def process(self, session: Session, job: Job) -> None:
        request = request_of(job)
        lease_id = job.lease_id
        if lease_id is None:
            raise LeaseLost("logic job has no claim lease")
        chain_id = request["chain_id"]
        require_supported_chain(chain_id, context="logic job")
        rpc_url = require_rpc_url(chain_id=chain_id, context="logic job")
        remote_chain = rpc_request(rpc_url, "eth_chainId", [], retries=0, chain_id=chain_id)
        if not isinstance(remote_chain, str):
            raise ReadError("RPC chain identity unanswered")
        if int(remote_chain, 16) != chain_id:
            raise ValueError("Configured RPC returned a different chain")
        if request["logic_operation"] == "generate" and request["params"].get("block") is None:
            raw = rpc_request(rpc_url, "eth_blockNumber", [], retries=0, chain_id=chain_id)
            if not isinstance(raw, str):
                raise ReadError("Block number unanswered")
            pin_block(session, job.id, lease_id, int(raw, 16))
            session.refresh(job)
            request = request_of(job)
        result = run_isolated(
            execute_operation,
            job.id,
            lease_id,
            request,
            rpc_url,
            budget=static_budget(),
            label=f"logic:{request['logic_operation']}",
        )
        publish(session, job.id, lease_id, result)


def main():
    LogicWorker().run_loop()


if __name__ == "__main__":
    main()
