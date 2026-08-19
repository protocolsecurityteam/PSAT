"""Integration tests for ``BaseWorker._execute_job`` retry behaviour.

Hits real Postgres so the full claim → process → requeue/terminal cycle
(including the stage_errors artifact) is exercised against the live schema.
Object storage is intentionally NOT configured; the artifact stays inline
JSONB which keeps these tests offline-safe.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Artifact, Job, JobStage, JobStatus  # noqa: E402
from db.queue import create_job  # noqa: E402
from tests.cache_helpers import requires_postgres  # noqa: E402
from workers.base import BaseWorker  # noqa: E402


@pytest.fixture()
def test_session_local(monkeypatch):
    """Point ``workers.base.SessionLocal`` at the test database.

    ``BaseWorker._persist_stage_errors``/``_run_one_job`` open fresh
    ``SessionLocal()`` instances; without this monkeypatch they'd hit the
    prod DATABASE_URL even though the test holds a session against
    TEST_DATABASE_URL.
    """
    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")
    test_engine = create_engine(test_url)
    test_factory = sessionmaker(bind=test_engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("workers.base.SessionLocal", test_factory)
    yield test_factory
    test_engine.dispose()


@pytest.fixture()
def clean_jobs(db_session):
    """Drop any leftover jobs/artifacts so the retry-state assertions are
    deterministic. The shared db_session fixture only sweeps monitoring
    tables on teardown.
    """
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


class _ConfigurableWorker(BaseWorker):
    """Worker whose ``process()`` executes a caller-supplied side effect.

    Lets each test express the failure shape it wants (which exception, on
    which attempt) without subclassing per scenario.
    """

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


# ---------------------------------------------------------------------------
# Transient → requeued
# ---------------------------------------------------------------------------


@requires_postgres
def test_transient_exception_requeues(clean_jobs, test_session_local, monkeypatch):
    """A transient (ConnectionError) failure leaves the job queued with
    retry_count=1 and next_attempt_at set. Stage_errors artifact has one
    entry tagged retry_count=0."""
    monkeypatch.setenv("PSAT_JOB_RETRY_BASE_S", "30")
    monkeypatch.setenv("PSAT_JOB_MAX_RETRIES", "5")

    job = clean_jobs
    job_row = create_job(job, {"address": "0xabc", "name": "transient-1"})

    worker = _ConfigurableWorker(side_effect=lambda _n: _transient_exc())
    worker._execute_job(job, job_row)

    job.expire_all()
    refreshed = job.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.queued
    assert refreshed.retry_count == 1
    assert refreshed.next_attempt_at is not None
    assert refreshed.last_failure_kind == "transient"

    payload = _read_stage_errors(job, job_row.id)
    assert payload is not None
    errors = payload["errors"]
    assert len(errors) == 1
    assert errors[0]["severity"] == "error"
    assert errors[0]["retry_count"] == 0
    assert "ConnectionError" in errors[0]["exc_type"]


# ---------------------------------------------------------------------------
# Retries exhausted → failed_terminal
# ---------------------------------------------------------------------------


@requires_postgres
def test_transient_retries_exhausted_to_terminal(clean_jobs, test_session_local, monkeypatch):
    """Five transient failures → status=failed_terminal, retry_count=5,
    artifact has 5 entries tagged 0..4. ``last_failure_kind="transient"``
    so an operator can tell exhaustion apart from deterministic-from-the-start.
    """
    monkeypatch.setenv("PSAT_JOB_RETRY_BASE_S", "1")
    monkeypatch.setenv("PSAT_JOB_MAX_RETRIES", "5")

    job = clean_jobs
    job_row = create_job(job, {"address": "0xabc", "name": "exhaustion"})

    worker = _ConfigurableWorker(side_effect=lambda _n: _transient_exc())
    # Drive the job through 5 attempts; bump retry_count on the row each
    # iteration to mimic what the worker fleet would observe across claims.
    for _ in range(5):
        # Re-fetch the job each iteration so retry_count is current.
        job.expire_all()
        current = job.get(Job, job_row.id)
        worker._execute_job(job, current)

    job.expire_all()
    refreshed = job.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.failed_terminal
    # Retries-exhausted bumps retry_count to the full attempt count so the row
    # records "5 total attempts before giving up" rather than "4 retries
    # scheduled" — the latter would lose the final attempt's existence.
    assert refreshed.retry_count == 5
    assert refreshed.last_failure_kind == "transient"

    payload = _read_stage_errors(job, job_row.id)
    assert payload is not None
    errors = payload["errors"]
    assert len(errors) == 5
    # Chronological retry_count tagging: 0, 1, 2, 3, 4.
    assert [e["retry_count"] for e in errors] == [0, 1, 2, 3, 4]


# ---------------------------------------------------------------------------
# Terminal short-circuit
# ---------------------------------------------------------------------------


@requires_postgres
def test_terminal_exception_skips_retries(clean_jobs, test_session_local):
    """``ValueError`` is classified terminal — the row jumps straight to
    ``failed_terminal`` on attempt one, no requeue ever scheduled."""
    job = clean_jobs
    job_row = create_job(job, {"address": "0xabc", "name": "terminal-1"})

    worker = _ConfigurableWorker(side_effect=lambda _n: ValueError("bad input"))
    worker._execute_job(job, job_row)

    job.expire_all()
    refreshed = job.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.failed_terminal
    assert refreshed.retry_count == 0  # never bumped
    assert refreshed.last_failure_kind == "terminal"
    assert refreshed.next_attempt_at is None

    payload = _read_stage_errors(job, job_row.id)
    assert payload is not None
    errors = payload["errors"]
    assert len(errors) == 1
    assert errors[0]["severity"] == "error"
    assert errors[0]["retry_count"] == 0


# ---------------------------------------------------------------------------
# Eventual success after transient failures
# ---------------------------------------------------------------------------


@requires_postgres
def test_transient_then_success(clean_jobs, test_session_local, monkeypatch):
    """Two transient failures + one success → status=done (or queued for
    next stage), retry_count=2 (bumped twice), artifact has two transient
    error entries. The success path doesn't append a new error entry."""
    monkeypatch.setenv("PSAT_JOB_RETRY_BASE_S", "1")
    monkeypatch.setenv("PSAT_JOB_MAX_RETRIES", "5")

    job = clean_jobs
    job_row = create_job(job, {"address": "0xabc", "name": "flaky-then-ok"})

    def _side_effect(call_n):
        if call_n <= 2:
            return _transient_exc()
        return None  # success

    worker = _ConfigurableWorker(side_effect=_side_effect)

    # Patch the success advance so we don't need a real next-stage row.
    import workers.base as base

    advances: list = []
    monkey_advance = base.advance_job
    base.advance_job = lambda _s, jid, ns, _d, **_kw: advances.append((jid, ns))
    try:
        for _ in range(3):
            job.expire_all()
            current = job.get(Job, job_row.id)
            worker._execute_job(job, current)
    finally:
        base.advance_job = monkey_advance

    job.expire_all()
    refreshed = job.get(Job, job_row.id)
    assert refreshed is not None
    # The third attempt succeeded → advance_job was called (via the patch),
    # so the row stays in the same DB state advance_job would have left it
    # unchanged: still queued because we didn't actually run advance_job's
    # commit. The interesting assertion is the retry_count and the artifact.
    assert refreshed.retry_count == 2

    payload = _read_stage_errors(job, job_row.id)
    assert payload is not None
    errors = payload["errors"]
    # Two transient failure entries, no entry from the third (successful) attempt.
    assert len(errors) == 2
    assert [e["retry_count"] for e in errors] == [0, 1]
    assert all(e["severity"] == "error" for e in errors)
    # advance_job was called once after the third attempt's success.
    assert len(advances) == 1


# ---------------------------------------------------------------------------
# Corrupt prior artifact body is preserved as a degraded breadcrumb
# ---------------------------------------------------------------------------
#
# When ``BaseWorker._persist_stage_errors`` finds an existing ``stage_errors``
# body that fails ``StageErrors.model_validate`` (legacy schema, partial
# write, manual tampering), it must not silently drop the prior payload —
# operators reading /api/jobs/{id}/errors after a manual triage need to be
# able to see what was there.
#
# The contract: prepend a ``severity="degraded"``, ``phase="corrupt_prior"``
# entry whose ``context.raw`` carries the original payload, then continue
# with the new entries the current attempt produced.


@requires_postgres
def test_persist_stage_errors_preserves_corrupt_prior_as_breadcrumb(clean_jobs, test_session_local):
    """A corrupt prior body becomes a ``corrupt_prior`` breadcrumb entry
    rather than being silently dropped."""
    from db.queue import store_artifact
    from schemas.stage_errors import StageError

    db_session = clean_jobs
    job_row = create_job(db_session, {"address": "0xabc", "name": "corrupt-prior"})

    # Pre-seed a body that fails ``StageErrors.model_validate``. Pydantic
    # accepts unknown fields by default, so "shape mismatch" alone isn't
    # enough — we need ``errors`` to be present-but-malformed (here: a list
    # whose entries lack required fields like ``stage``/``severity``/...).
    corrupt_body = {
        "schema_version": "v0-legacy",
        "errors": [
            {"when": "2026-01-01T00:00:00Z", "what": "pre-migration entry the operator may still need"},
        ],
    }
    store_artifact(db_session, job_row.id, "stage_errors", data=corrupt_body)
    db_session.commit()

    # Run a worker attempt that triggers _persist_stage_errors via the
    # normal failure path. Use a terminal exception so the path executes once.
    worker = _ConfigurableWorker(side_effect=lambda _n: ValueError("bad input"))
    worker._execute_job(db_session, job_row)

    db_session.expire_all()
    payload = _read_stage_errors(db_session, job_row.id)
    assert payload is not None
    assert "errors" in payload

    entries = payload["errors"]
    # Two entries: the corrupt-prior breadcrumb (first), and the just-failed
    # attempt's error entry.
    assert len(entries) == 2, f"expected breadcrumb + new error, got {entries}"

    breadcrumb = entries[0]
    assert breadcrumb["phase"] == "corrupt_prior"
    assert breadcrumb["severity"] == "degraded"
    assert breadcrumb["exc_type"] == "schema.CorruptPriorArtifact"
    # Raw prior payload is preserved verbatim under context.raw so an
    # operator can still read it via /api/jobs/{id}/errors.
    assert breadcrumb["context"]["raw"] == corrupt_body

    new_error = entries[1]
    assert new_error["severity"] == "error"
    assert "ValueError" in new_error["exc_type"]

    # Round-trip: the artifact still validates as StageErrors.
    StageError.model_validate(breadcrumb)
    StageError.model_validate(new_error)
