"""Liveness, version, config, and pipeline-stats endpoints."""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import distinct, func, select, text

from db.models import Job, JobStatus
from utils.rpc import supported_chain_ids

from . import deps
from .spa import _site_index_response

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/")
def index():
    return _site_index_response()


@router.get("/api/health")
def health():
    """Liveness/readiness probe — verifies the database and object storage are reachable."""
    from db.models import engine as _engine

    body: dict[str, Any] = {"status": "ok", "db": "ok", "storage": "inline"}
    failures: list[str] = []

    try:
        with deps.SessionLocal() as session:
            # Cap the probe at 2s so a hung Postgres can't hang the health endpoint.
            # SET LOCAL statement_timeout is Postgres-specific syntax.
            session.execute(text("SET LOCAL statement_timeout = 2000"))
            session.execute(select(1))
    except Exception as exc:
        logger.warning("Health check: db unreachable: %s", exc, extra={"exc_type": type(exc).__name__})
        body["db"] = "unavailable"
        failures.append("db")

    # NullPool (used in some test setups) lacks these counters.
    from sqlalchemy.pool import QueuePool

    if isinstance(_engine.pool, QueuePool):
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


@router.get("/api/version")
def version() -> dict[str, str]:
    """Returns the deployed git SHA. Used by post-deploy smoke checks to confirm
    the running image matches the commit that triggered the deploy."""
    return {"sha": os.environ.get("GIT_SHA", "unknown")}


@router.get("/api/config")
def config() -> dict[str, Any]:
    return {
        "rpc_provider": "erpc",
        "erpc_configured": bool(os.getenv("ERPC_BASE_URL")),
        "supported_chain_ids": sorted(supported_chain_ids()),
    }


@router.get("/api/stats")
def pipeline_stats() -> dict[str, Any]:
    """Quick stats: unique addresses stored, total jobs, etc."""
    with deps.SessionLocal() as session:
        unique_addresses = (
            session.execute(
                select(func.count(distinct(func.concat(Job.chain_id, ":", func.lower(Job.address))))).where(
                    Job.address.isnot(None),
                    Job.chain_id.isnot(None),
                )
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
