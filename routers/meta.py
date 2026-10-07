from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy import distinct, func, select, text, tuple_

from db.models import Job, JobStatus
from schemas.api_responses import PipelineStatsResponse

from . import deps
from .spa import _site_index_response

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/")
def index():
    return _site_index_response()


@router.get("/api/health")
def health(request: Request, x_psat_admin_key: str | None = Header(default=None)):
    """Liveness probe for DB and storage. ``pool`` stats only for admins."""
    from db.models import engine as _engine

    body: dict[str, Any] = {"status": "ok", "db": "ok", "storage": "inline"}
    failures: list[str] = []

    try:
        with deps.SessionLocal() as session:
            # So a hung Postgres can't hang the probe.
            session.execute(text("SET LOCAL statement_timeout = 2000"))
            session.execute(select(1))
    except Exception as exc:
        logger.warning("Health check: db unreachable: %s", exc, extra={"exc_type": type(exc).__name__})
        body["db"] = "unavailable"
        failures.append("db")

    # NullPool lacks these counters.
    from sqlalchemy.pool import QueuePool

    if deps.is_admin_request(request, x_psat_admin_key) and isinstance(_engine.pool, QueuePool):
        pool = _engine.pool
        body["pool"] = {
            "size": pool.size(),
            "checked_in": pool.checkedin(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
        }

    storage_client = deps.get_storage_client()
    if storage_client is not None:
        try:
            storage_client.health_check()
            body["storage"] = "ok"
        except deps.StorageUnavailable as exc:
            logger.warning("Health check: storage unreachable: %s", exc, extra={"exc_type": type(exc).__name__})
            body["storage"] = "unavailable"
            failures.append("storage")

    if failures:
        body["status"] = "unavailable"
        return JSONResponse(body, status_code=503)
    return body


@router.get("/api/health/monitoring", dependencies=[Depends(deps.require_admin)])
def monitoring_health() -> Any:
    """Monitoring-fleet liveness for an uptime checker: 503 when any daemon is stale or erroring, with per-chain
    detail. Operator-only.
    """
    from services.monitoring.ops_alerts import collect_chain_health, collect_stale_processes

    with deps.SessionLocal() as session:
        stale = collect_stale_processes(session)
        chains = collect_chain_health(session)
    stale_chains = [c for c in chains if c["stale"]]
    ok = not stale and not stale_chains
    body: dict[str, Any] = {
        "status": "ok" if ok else "unavailable",
        "stale": stale,
        "chains": chains,
    }
    if not ok:
        return JSONResponse(body, status_code=503)
    return body


@router.get("/api/version")
def version() -> dict[str, str]:
    """Deployed git SHA, for post-deploy smoke checks."""
    return {"sha": os.environ.get("GIT_SHA", "unknown")}


@router.get("/api/config", dependencies=[Depends(deps.require_admin)])
def config() -> dict[str, str]:
    from utils.secrets import sanitize_url

    return {"default_rpc_url": sanitize_url(deps.DEFAULT_RPC_URL)}


@router.get("/api/stats", dependencies=[Depends(deps.require_admin)], response_model=None)
def pipeline_stats() -> PipelineStatsResponse:
    with deps.SessionLocal() as session:
        # A CREATE2 twin is two entities.
        unique_addresses = (
            session.execute(
                select(func.count(distinct(tuple_(Job.chain_id, Job.address)))).where(Job.address.isnot(None))
            ).scalar()
            or 0
        )
        total_jobs = session.execute(select(func.count(Job.id))).scalar() or 0
        completed_jobs = (
            session.execute(select(func.count(Job.id)).where(Job.status == JobStatus.completed)).scalar() or 0
        )
        failed_jobs = session.execute(select(func.count(Job.id)).where(Job.status == JobStatus.failed)).scalar() or 0
        return {
            "unique_addresses": unique_addresses,
            "total_jobs": total_jobs,
            "completed_jobs": completed_jobs,
            "failed_jobs": failed_jobs,
        }
