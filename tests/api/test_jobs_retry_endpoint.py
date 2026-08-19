"""Integration tests for ``POST /api/jobs/{id}/retry``.

Hits the FastAPI app with the test DB wired through ``api_client`` so
admin-key, status checks, and the artifact append are exercised end to end.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Artifact, Job, JobStatus  # noqa: E402
from db.queue import create_job, fail_job_terminal  # noqa: E402
from tests.cache_helpers import requires_postgres  # noqa: E402


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


# ---------------------------------------------------------------------------
# Happy path: failed_terminal → queued
# ---------------------------------------------------------------------------


@requires_postgres
def test_retry_endpoint_resets_failed_terminal_to_queued(api_client, clean_jobs):
    """A failed_terminal job is reset to queued with retry_count=0 and a
    manual_retry artifact entry appended."""
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


# ---------------------------------------------------------------------------
# 409 for the wrong status
# ---------------------------------------------------------------------------


@requires_postgres
def test_retry_endpoint_rejects_done_job(api_client, clean_jobs):
    """A done/completed job must not be retried — that would clobber a real outcome."""
    db_session = clean_jobs
    job = create_job(db_session, {"address": "0xabc", "name": "completed"})
    job.status = JobStatus.completed
    db_session.commit()

    response = api_client.post(f"/api/jobs/{job.id}/retry")
    assert response.status_code == 409
    assert "completed" in response.json()["detail"]


@requires_postgres
def test_retry_endpoint_rejects_queued_job(api_client, clean_jobs):
    """A queued job is already eligible to run — retrying it would be a no-op
    that resets its retry_count, masking earlier failures."""
    db_session = clean_jobs
    job = create_job(db_session, {"address": "0xabc", "name": "queued"})

    response = api_client.post(f"/api/jobs/{job.id}/retry")
    assert response.status_code == 409
    assert "queued" in response.json()["detail"]


@requires_postgres
def test_retry_endpoint_rejects_processing_job(api_client, clean_jobs):
    """A processing job is in flight — clobbering it could double-execute work."""
    db_session = clean_jobs
    job = create_job(db_session, {"address": "0xabc", "name": "processing"})
    job.status = JobStatus.processing
    db_session.commit()

    response = api_client.post(f"/api/jobs/{job.id}/retry")
    assert response.status_code == 409


@requires_postgres
def test_retry_endpoint_rejects_legacy_failed_job(api_client, clean_jobs):
    """``status='failed'`` (the legacy state) is not retryable via this
    endpoint — the operator must promote to ``failed_terminal`` first or
    use a different mechanism. Avoids accidental retries of pre-migration
    rows that may have been transient and stayed flapping."""
    db_session = clean_jobs
    job = create_job(db_session, {"address": "0xabc", "name": "legacy-failed"})
    job.status = JobStatus.failed
    db_session.commit()

    response = api_client.post(f"/api/jobs/{job.id}/retry")
    assert response.status_code == 409


# ---------------------------------------------------------------------------
# 404 for missing / malformed
# ---------------------------------------------------------------------------


@requires_postgres
def test_retry_endpoint_returns_404_for_missing_job(api_client, clean_jobs):
    response = api_client.post("/api/jobs/00000000-0000-0000-0000-000000000000/retry")
    assert response.status_code == 404


@requires_postgres
def test_retry_endpoint_returns_404_for_malformed_uuid(api_client, clean_jobs):
    response = api_client.post("/api/jobs/not-a-uuid/retry")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Concurrency: two operators hitting /retry simultaneously
# ---------------------------------------------------------------------------
#
# Asserts that ``routers/jobs.py:retry_job`` serializes concurrent admin
# retries via ``SELECT … FOR UPDATE`` on the row read. Without the lock, two
# near-simultaneous POSTs both observe ``failed_terminal``, both flip the row
# to ``queued``, and the second writer's ``store_artifact`` upsert clobbers
# the first writer's manual_retry entry — losing audit history.
#
# With the lock, the second caller blocks until the first commits and then
# observes ``queued`` status, returning 409.


@requires_postgres
def test_retry_endpoint_concurrent_operators_serialize_via_row_lock(clean_jobs, monkeypatch):
    """Two concurrent /retry calls: exactly one returns 200, the other 409.
    The audit log gets exactly one manual_retry entry — no clobber.

    Bypasses the shared-session ``api_client`` fixture because that wires
    every request through one ``Session``, which would serialize at the
    SQLAlchemy layer and never exercise the DB-level lock. Real production
    traffic gives each request its own session — replicated here via a real
    sessionmaker bound to the test DB.
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

    # Hand each request its own session and coordinate them at the post-lock
    # observation point so we can assert both calls reached the SELECT … FOR
    # UPDATE site — proving the test actually exercised contention rather
    # than running them serially. The barrier waits on the first ``execute``
    # of the request: thread A's ``execute`` (the locking SELECT) returns
    # immediately; thread B's ``execute`` blocks at the DB until A commits.
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
                # Sync both threads at the row-lock attempt so the test
                # genuinely contends on the lock instead of running serially.
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

    # FOR UPDATE serializes the two callers: first one flips to queued and
    # commits, second one wakes up holding the lock, sees queued, returns 409.
    assert statuses == [200, 409], f"expected serialized [200, 409] — got {statuses}"

    # Verify the 409 response carries the post-flip status.
    body_409 = next(r.json() for r in responses if r.status_code == 409)
    assert "queued" in body_409["detail"]

    # Read artifact via a fresh session so we see committed state.
    with real_factory() as verify:
        from db.models import Artifact

        art = verify.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == "stage_errors").one_or_none()
        assert art is not None and isinstance(art.data, dict)
        manual_retries = [e for e in art.data["errors"] if e.get("phase") == "manual_retry"]

    # Exactly one writer ever ran the artifact append, so exactly one entry.
    assert len(manual_retries) == 1, (
        f"lock should have ensured exactly one manual_retry entry — got {len(manual_retries)}"
    )

    test_engine.dispose()
