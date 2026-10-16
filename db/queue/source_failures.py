"""Bounded source-absence observations, separate from successful analysis cache identity."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from db.models import Job, JobStatus

SOURCE_ABSENCE = "verified_source_unavailable"
SOURCE_RECHECK_SECONDS = 3600


def root_id(job: Job) -> str:
    request = job.request if isinstance(job.request, dict) else {}
    return str(request.get("root_job_id") or job.id)


def record_source_absence(session, job: Job, chain_id: int) -> None:
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

    now = datetime.now(timezone.utc)
    job.request = {
        **(job.request or {}),
        SOURCE_ABSENCE: {
            "address": (job.address or "").lower(),
            "chain_id": chain_id,
            "provider": "etherscan",
            "observed_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=SOURCE_RECHECK_SECONDS)).isoformat(),
            "analyzer_version": ANALYSIS_SCHEMA_VERSION,
        },
    }
    session.commit()


def source_failure_active(job: Job) -> bool:
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

    marker = (job.request or {}).get(SOURCE_ABSENCE)
    if not isinstance(marker, dict):
        return False
    try:
        expiry = datetime.fromisoformat(marker["expires_at"])
        return bool(
            job.status == JobStatus.failed_terminal
            and expiry > datetime.now(timezone.utc)
            and marker.get("analyzer_version") == ANALYSIS_SCHEMA_VERSION
            and marker.get("chain_id") == job.chain_id
            and marker.get("address") == (job.address or "").lower()
        )
    except (KeyError, TypeError, ValueError):
        return False


def unstructured_source_failure(job: Job) -> bool:
    """Old free-text failures are not fresh absence evidence; allow a structured recheck."""
    return bool(
        job.status == JobStatus.failed_terminal
        and job.address
        and SOURCE_ABSENCE not in (job.request or {})
        and f"no verified source code for {job.address.lower()}" in (job.error or "").lower()
    )


def source_failure_in_scope(job: Job, parent: Job | None, proxy_address: str | None = None) -> bool:
    """Other terminal errors retain existing policy; source absence never substitutes another scope's job.

    Source can become verified without code changing. A new scope, expiry, or explicit
    retry can fetch again; this observation does not claim source is absent forever.
    """
    if unstructured_source_failure(job):
        return False
    if job.status != JobStatus.failed_terminal or SOURCE_ABSENCE not in (job.request or {}):
        return True
    if parent is None or not source_failure_active(job) or (parent.request or {}).get("force"):
        return False
    return (
        root_id(job) == root_id(parent)
        and job.protocol_id == parent.protocol_id
        and str((job.request or {}).get("proxy_address") or "").lower() == str(proxy_address or "").lower()
    )
