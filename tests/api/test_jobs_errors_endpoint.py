"""Integration tests for ``GET /api/jobs/{job_id}/errors``."""

from __future__ import annotations

from datetime import datetime, timezone

from db.queue import create_job, store_artifact
from schemas.stage_errors import StageError, StageErrors
from tests.cache_helpers import requires_postgres


@requires_postgres
def test_get_errors_unknown_job_id_returns_404(api_client):
    fake_id = "00000000-0000-0000-0000-000000000000"
    response = api_client.get(f"/api/jobs/{fake_id}/errors")
    assert response.status_code == 404, response.text


@requires_postgres
def test_get_errors_for_job_without_artifact_returns_empty_list(db_session, api_client):
    job = create_job(db_session, {"address": "0xabc", "name": "endpoint-empty"})
    db_session.commit()

    response = api_client.get(f"/api/jobs/{job.id}/errors")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["job_id"] == str(job.id)
    assert body["trace_id"] == job.trace_id
    assert body["status"] == job.status.value
    assert body["stage"] == job.stage.value
    assert body["errors"] == []


@requires_postgres
def test_get_errors_returns_deserialized_artifact(db_session, api_client):
    job = create_job(db_session, {"address": "0xabc", "name": "endpoint-full"})
    db_session.commit()

    payload = StageErrors(
        errors=[
            StageError(
                stage="static",
                severity="error",
                exc_type="builtins.RuntimeError",
                message="dependency_static failed",
                traceback="Traceback...",
                phase="dependency_static",
                trace_id=job.trace_id,
                job_id=str(job.id),
                worker_id="StaticWorker-pid-zzzz",
                failed_at=datetime(2026, 5, 2, 12, 0, tzinfo=timezone.utc),
            ),
            StageError(
                stage="static",
                severity="degraded",
                exc_type="requests.exceptions.HTTPError",
                message="GitHub 403",
                phase="audit_report_html_fetch",
                trace_id=job.trace_id,
                job_id=str(job.id),
                worker_id="StaticWorker-pid-zzzz",
                failed_at=datetime(2026, 5, 2, 12, 1, tzinfo=timezone.utc),
            ),
        ]
    )
    store_artifact(db_session, job.id, "stage_errors", data=payload.model_dump(mode="json"))

    response = api_client.get(f"/api/jobs/{job.id}/errors")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["job_id"] == str(job.id)
    assert body["trace_id"] == job.trace_id
    assert len(body["errors"]) == 2
    assert body["errors"][0]["severity"] == "error"
    assert body["errors"][0]["phase"] == "dependency_static"
    assert body["errors"][1]["severity"] == "degraded"
    assert body["errors"][1]["phase"] == "audit_report_html_fetch"


@requires_postgres
def test_get_errors_corrupt_artifact_does_not_500(db_session, api_client):
    job = create_job(db_session, {"address": "0xabc", "name": "endpoint-corrupt"})
    db_session.commit()

    store_artifact(db_session, job.id, "stage_errors", data={"not": "valid", "shape": [1, 2, 3]})

    response = api_client.get(f"/api/jobs/{job.id}/errors")
    assert response.status_code == 200, response.text
    assert response.json()["errors"] == []


@requires_postgres
def test_get_errors_non_uuid_job_id_is_404(api_client):
    response = api_client.get("/api/jobs/not-a-uuid/errors")
    assert response.status_code == 404, response.text
    assert response.json()["detail"] == "Job not found"
