"""Storage is unconfigured so artifacts stay inline and offline-safe."""

from __future__ import annotations

import requests

from db.models import Job, JobStage, JobStatus
from db.queue import create_job
from tests.cache_helpers import requires_postgres
from tests.support.db_fixtures import (
    _read_stage_errors,
    clean_jobs,  # noqa: F401  (fixture, registered by import)
    test_session_local,  # noqa: F401  (fixture, registered by import)
)
from workers.base import BaseWorker


class _ConfigurableWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0.0

    def __init__(self, side_effect):
        super().__init__()
        self.side_effect = side_effect
        self.calls = 0

    def process(self, session, job):
        self.calls += 1
        outcome = self.side_effect(self.calls)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _transient_exc():
    return requests.exceptions.ConnectionError("upstream blip")


@requires_postgres
def test_transient_retries_exhausted_to_terminal(clean_jobs, test_session_local, monkeypatch):
    monkeypatch.setenv("PSAT_JOB_RETRY_BASE_S", "1")
    monkeypatch.setenv("PSAT_JOB_MAX_RETRIES", "5")

    job = clean_jobs
    job_row = create_job(job, {"address": "0xabc", "name": "exhaustion"})

    worker = _ConfigurableWorker(side_effect=lambda _n: _transient_exc())
    for _ in range(5):
        job.expire_all()
        current = job.get(Job, job_row.id)
        worker._execute_job(job, current)

    job.expire_all()
    refreshed = job.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.failed_terminal
    # Counting the final attempt keeps its existence on the row.
    assert refreshed.retry_count == 5
    assert refreshed.last_failure_kind == "transient"

    payload = _read_stage_errors(job, job_row.id)
    assert payload is not None
    errors = payload["errors"]
    assert len(errors) == 5
    assert [e["retry_count"] for e in errors] == [0, 1, 2, 3, 4]


# A corrupt ``stage_errors`` body is kept as a ``corrupt_prior`` breadcrumb, since operators read /api/jobs/{id}/errors.


@requires_postgres
def test_persist_stage_errors_preserves_corrupt_prior_as_breadcrumb(clean_jobs, test_session_local):
    from db.queue import store_artifact
    from schemas.stage_errors import StageError

    db_session = clean_jobs
    job_row = create_job(db_session, {"address": "0xabc", "name": "corrupt-prior"})

    # Pydantic accepts unknown fields, so ``errors`` must be present but malformed.
    corrupt_body = {
        "schema_version": "v0-legacy",
        "errors": [
            {"when": "2026-01-01T00:00:00Z", "what": "pre-migration entry the operator may still need"},
        ],
    }
    store_artifact(db_session, job_row.id, "stage_errors", data=corrupt_body)
    db_session.commit()

    worker = _ConfigurableWorker(side_effect=lambda _n: ValueError("bad input"))
    worker._execute_job(db_session, job_row)

    db_session.expire_all()
    payload = _read_stage_errors(db_session, job_row.id)
    assert payload is not None
    assert "errors" in payload

    entries = payload["errors"]
    assert len(entries) == 2, f"expected breadcrumb + new error, got {entries}"

    breadcrumb = entries[0]
    assert breadcrumb["phase"] == "corrupt_prior"
    assert breadcrumb["severity"] == "degraded"
    assert breadcrumb["exc_type"] == "schema.CorruptPriorArtifact"
    assert breadcrumb["context"]["raw"] == corrupt_body

    new_error = entries[1]
    assert new_error["severity"] == "error"
    assert "ValueError" in new_error["exc_type"]

    StageError.model_validate(breadcrumb)
    StageError.model_validate(new_error)
