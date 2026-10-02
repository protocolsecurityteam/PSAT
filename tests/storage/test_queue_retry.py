from __future__ import annotations

from datetime import datetime, timedelta, timezone

from db.models import Job, JobStage, JobStatus
from db.queue import (
    claim_job,
    create_job,
    fail_job_terminal,
    requeue_job,
)
from tests.cache_helpers import requires_postgres
from tests.support.db_fixtures import clean_jobs  # noqa: F401  (fixture, registered by import)


@requires_postgres
def test_claim_job_skips_future_next_attempt_at(clean_jobs):
    db_session = clean_jobs
    """A queued job with next_attempt_at in the future is invisible to claim_job."""
    job = create_job(db_session, {"address": "0x" + "a" * 40, "name": "future-retry"})
    future = datetime.now(timezone.utc) + timedelta(minutes=10)
    requeue_job(db_session, job.id, "transient blip", retry_count=1, next_attempt_at=future)

    claimed = claim_job(db_session, JobStage.discovery, "test-worker")
    assert claimed is None


@requires_postgres
def test_claim_job_claims_past_next_attempt_at(clean_jobs):
    db_session = clean_jobs
    """Once next_attempt_at <= NOW(), the job is claimable again."""
    job = create_job(db_session, {"address": "0x" + "b" * 40, "name": "past-retry"})
    past = datetime.now(timezone.utc) - timedelta(seconds=5)
    requeue_job(db_session, job.id, "transient blip", retry_count=1, next_attempt_at=past)

    claimed = claim_job(db_session, JobStage.discovery, "test-worker")
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.status == JobStatus.processing


@requires_postgres
def test_claim_job_claims_null_next_attempt_at(clean_jobs):
    db_session = clean_jobs
    """Brand-new jobs (never retried) have next_attempt_at NULL — must be claimable."""
    job = create_job(db_session, {"address": "0x" + "c" * 40, "name": "fresh"})
    db_session.commit()

    claimed = claim_job(db_session, JobStage.discovery, "test-worker")
    assert claimed is not None
    assert claimed.id == job.id


@requires_postgres
def test_requeue_job_sets_retry_state(clean_jobs):
    db_session = clean_jobs
    job = create_job(db_session, {"address": "0x" + "d" * 40, "name": "requeue"})
    next_at = datetime.now(timezone.utc) + timedelta(seconds=30)

    requeue_job(db_session, job.id, "boom traceback", retry_count=1, next_attempt_at=next_at)

    db_session.expire_all()
    refreshed = db_session.get(Job, job.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.queued
    assert refreshed.retry_count == 1
    assert refreshed.next_attempt_at is not None
    assert refreshed.last_failure_kind == "transient"
    assert refreshed.error == "boom traceback"
    assert refreshed.worker_id is None


@requires_postgres
def test_fail_job_terminal_preserves_retry_count(clean_jobs):
    db_session = clean_jobs
    """retries-exhausted path: requeue 4 times, then fail_job_terminal — retry_count stays."""
    job = create_job(db_session, {"address": "0x" + "f" * 40, "name": "exhausted"})
    requeue_job(
        db_session,
        job.id,
        "blip",
        retry_count=4,
        next_attempt_at=datetime.now(timezone.utc) + timedelta(seconds=1),
    )

    fail_job_terminal(db_session, job.id, "exhausted", kind="transient")

    db_session.expire_all()
    refreshed = db_session.get(Job, job.id)
    assert refreshed is not None
    assert refreshed.retry_count == 4  # unchanged by the terminal call
    assert refreshed.last_failure_kind == "transient"
    assert refreshed.status == JobStatus.failed_terminal
