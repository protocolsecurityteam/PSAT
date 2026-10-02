from __future__ import annotations

import pytest

from db.models import Job, JobStatus
from db.queue import create_job, fail_job_terminal
from tests.cache_helpers import requires_postgres
from tests.support.db_fixtures import (
    _read_stage_errors,
    clean_jobs,  # noqa: F401  (fixture, registered by import)
)


@requires_postgres
def test_retry_endpoint_resets_failed_terminal_to_queued(api_client, clean_jobs):
    db_session = clean_jobs
    job = create_job(db_session, {"address": "0xabc", "name": "manual-retry"})
    fail_job_terminal(db_session, job.id, "boom", kind="terminal")

    response = api_client.post(f"/api/jobs/{job.id}/retry")
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "queued"
    assert body["retry_count"] == 0
    assert body["next_attempt_at"] is None
    assert body["last_failure_kind"] is None

    db_session.expire_all()
    refreshed = db_session.get(Job, job.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.queued
    assert refreshed.retry_count == 0

    payload = _read_stage_errors(db_session, job.id)
    assert payload is not None
    errors = payload["errors"]
    assert len(errors) >= 1
    last = errors[-1]
    assert last["severity"] == "degraded"
    assert last["phase"] == "manual_retry"
    assert "perator-initiated" in last["message"]  # case-insensitive match


# done: a real outcome must not be clobbered. queued: a retry would only reset retry_count and mask
# failures. processing: clobbering could double-execute. legacy failed: must be promoted first.
@requires_postgres
@pytest.mark.parametrize(
    ("status", "detail_fragment"),
    [
        pytest.param(JobStatus.completed, "completed", id="done"),
        pytest.param(None, "queued", id="queued"),
        pytest.param(JobStatus.processing, None, id="processing"),
        pytest.param(JobStatus.failed, None, id="legacy_failed"),
    ],
)
def test_retry_endpoint_rejects_non_retryable_status(api_client, clean_jobs, status, detail_fragment):
    db_session = clean_jobs
    job = create_job(db_session, {"address": "0xabc", "name": "non-retryable"})
    if status is not None:
        job.status = status
        db_session.commit()

    response = api_client.post(f"/api/jobs/{job.id}/retry")
    assert response.status_code == 409
    if detail_fragment is not None:
        assert detail_fragment in response.json()["detail"]


@requires_postgres
@pytest.mark.parametrize(
    "job_id",
    [
        pytest.param("00000000-0000-0000-0000-000000000000", id="missing_job"),
        pytest.param("not-a-uuid", id="malformed_uuid"),
    ],
)
def test_retry_endpoint_returns_404(api_client, clean_jobs, job_id):
    response = api_client.post(f"/api/jobs/{job_id}/retry")
    assert response.status_code == 404
