"""Integration tests for retry-related queue operations.

Covers:
- ``claim_job`` honours ``next_attempt_at`` (skips future, claims past).
- ``requeue_job`` sets retry_count + next_attempt_at + queued + transient.
- ``fail_job_terminal`` sets failed_terminal + last_failure_kind, no requeue.
- ``reclaim_stuck_jobs`` does not touch ``failed_terminal`` rows even if
  their ``updated_at`` is ancient.

Postgres-gated via the standard ``requires_postgres`` mark in
``tests/cache_helpers.py``; skips cleanly when ``TEST_DATABASE_URL`` is
unset.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Artifact, Job, JobStage, JobStatus  # noqa: E402
from db.queue import (  # noqa: E402
    claim_job,
    create_job,
    fail_job_terminal,
    reclaim_stuck_jobs,
    requeue_job,
)
from tests.cache_helpers import requires_postgres  # noqa: E402


@pytest.fixture()
def clean_jobs(db_session):
    """Drop any leftover jobs/artifacts so the global queue-level queries
    (``claim_job``, ``reclaim_stuck_jobs``) only see this test's rows.

    The shared ``db_session`` fixture only sweeps monitoring tables on
    teardown — anything older than this test session can otherwise leak
    into our assertions.
    """
    db_session.query(Artifact).delete()
    db_session.query(Job).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.query(Artifact).delete()
    db_session.query(Job).delete()
    db_session.commit()


def _backdate(session, job_id, *, seconds_ago: int) -> None:
    """Force ``updated_at`` into the past so the stale sweep predicate fires."""
    session.execute(
        text("UPDATE jobs SET updated_at = NOW() - (:s * INTERVAL '1 second') WHERE id = :id"),
        {"s": seconds_ago, "id": str(job_id)},
    )
    session.commit()


# ---------------------------------------------------------------------------
# claim_job honours next_attempt_at
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# requeue_job
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# fail_job_terminal
# ---------------------------------------------------------------------------


@requires_postgres
def test_fail_job_terminal_sets_terminal_state(clean_jobs):
    db_session = clean_jobs
    job = create_job(db_session, {"address": "0x" + "e" * 40, "name": "terminal"})

    fail_job_terminal(db_session, job.id, "deterministic boom", kind="terminal")

    db_session.expire_all()
    refreshed = db_session.get(Job, job.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.failed_terminal
    assert refreshed.error == "deterministic boom"
    assert refreshed.last_failure_kind == "terminal"
    assert refreshed.next_attempt_at is None
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


# ---------------------------------------------------------------------------
# reclaim_stuck_jobs ignores failed_terminal
# ---------------------------------------------------------------------------


@requires_postgres
def test_reclaim_stuck_jobs_ignores_failed_terminal(clean_jobs):
    db_session = clean_jobs
    """An ancient ``failed_terminal`` row must NEVER be resurrected by the sweep."""
    job = create_job(db_session, {"address": "0x" + "1" * 40, "name": "terminal-old"})
    fail_job_terminal(db_session, job.id, "terminal", kind="terminal")
    _backdate(db_session, job.id, seconds_ago=10_000)

    rescued = reclaim_stuck_jobs(db_session, stale_timeout_seconds=1)

    assert rescued == []
    db_session.expire_all()
    refreshed = db_session.get(Job, job.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.failed_terminal
