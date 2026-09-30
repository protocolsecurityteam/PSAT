from __future__ import annotations

import pytest

from db.models import Artifact, Job, JobStatus
from db.queue import create_job, fail_job_terminal
from tests.cache_helpers import requires_postgres


@pytest.fixture()
def clean_jobs(db_session):
    db_session.query(Artifact).delete()
    db_session.query(Job).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.query(Artifact).delete()
    db_session.query(Job).delete()
    db_session.commit()


def _read_stage_errors(session, job_id):
    art = session.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == "stage_errors").one_or_none()
    if art is None or art.data is None:
        return None
    return art.data


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


@requires_postgres
def test_retry_endpoint_concurrent_operators_serialize_via_row_lock(clean_jobs, monkeypatch):
    """Without FOR UPDATE both see ``failed_terminal`` and the second upsert clobbers the first's audit entry.

    ``api_client`` shares one session, so each request gets its own.
    """
    import os
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    import api as api_module
    from routers import deps

    db_session = clean_jobs
    job = create_job(db_session, {"address": "0xabc", "name": "race"})
    fail_job_terminal(db_session, job.id, "boom", kind="terminal")
    job_id = job.id
    db_session.commit()

    test_engine = create_engine(os.environ["TEST_DATABASE_URL"])
    real_factory = sessionmaker(bind=test_engine, class_=Session, expire_on_commit=False)

    # The barrier proves both calls reached the locking SELECT, so contention really happened.
    started = threading.Barrier(2)

    class _CoordinatedFactory:
        def __call__(self):
            return _CoordinatedSession(real_factory())

    class _CoordinatedSession:
        def __init__(self, inner):
            self._inner = inner
            self._first_execute = True

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *exc):
            return self._inner.__exit__(*exc)

        def execute(self, *args, **kwargs):
            if self._first_execute:
                self._first_execute = False
                started.wait(timeout=10)
            return self._inner.execute(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    monkeypatch.setattr(deps, "SessionLocal", _CoordinatedFactory())

    client = TestClient(api_module.app)

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(client.post, f"/api/jobs/{job_id}/retry") for _ in range(2)]
        responses = [f.result(timeout=15) for f in futures]

    statuses = sorted(r.status_code for r in responses)

    assert statuses == [200, 409], f"expected serialized [200, 409] — got {statuses}"

    body_409 = next(r.json() for r in responses if r.status_code == 409)
    assert "queued" in body_409["detail"]

    with real_factory() as verify:
        from db.models import Artifact

        art = verify.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == "stage_errors").one_or_none()
        assert art is not None and isinstance(art.data, dict)
        manual_retries = [e for e in art.data["errors"] if e.get("phase") == "manual_retry"]

    assert len(manual_retries) == 1, (
        f"lock should have ensured exactly one manual_retry entry — got {len(manual_retries)}"
    )

    test_engine.dispose()
