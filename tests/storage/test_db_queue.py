"""Unit tests for db/queue/ helpers."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from db.models import Protocol
from db.queue import get_or_create_protocol
from tests.conftest import requires_postgres

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


@pytest.fixture()
def session():
    """PostgreSQL session scoped to one test, cleans Job rows on teardown."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Artifact, Base, Job, SourceFile

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        s.query(SourceFile).delete()
        s.query(Artifact).delete()
        s.query(Job).delete()
        s.commit()
        s.close()
        engine.dispose()


def _backdate_job(s, job_id, seconds_ago: int) -> None:
    """Force ``updated_at`` *and* ``lease_expires_at`` into the past.

    ``updated_at`` auto-stamps NOW() on every write and ``claim_job`` sets ``lease_expires_at`` to
    NOW()+ttl, either of which would defeat a stuck-job assertion."""
    from sqlalchemy import update as sa_update

    from db.models import Job

    past = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    s.execute(sa_update(Job).where(Job.id == job_id).values(updated_at=past, lease_expires_at=past))
    s.commit()


class TestGetOrCreateProtocol:
    @pytest.mark.parametrize(
        "name,kwargs,expected_domain",
        [
            pytest.param("ether.fi", {"official_domain": "ether.fi"}, "ether.fi", id="with_domain"),
            pytest.param("some-slug", {}, None, id="no_domain_leaves_null"),
        ],
    )
    def test_creates_when_missing(self, name, kwargs, expected_domain):
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None

        row = get_or_create_protocol(session, name, **kwargs)

        assert isinstance(row, Protocol)
        assert row.name == name
        assert row.official_domain == expected_domain
        session.add.assert_called_once()
        session.flush.assert_called_once()

    def test_returns_existing_without_modifying(self):
        existing = Protocol(name="uniswap", official_domain="uniswap.org")
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = existing

        row = get_or_create_protocol(session, "uniswap", official_domain="uniswap.org")

        assert row is existing
        assert row.official_domain == "uniswap.org"
        session.add.assert_not_called()
        session.flush.assert_not_called()

    def test_backfills_official_domain_when_null(self):
        existing = Protocol(name="aave", official_domain=None)
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = existing

        row = get_or_create_protocol(session, "aave", official_domain="aave.com")

        assert row is existing
        assert row.official_domain == "aave.com"
        session.add.assert_not_called()
        session.flush.assert_called_once()

    def test_does_not_overwrite_existing_official_domain(self):
        existing = Protocol(name="aave", official_domain="aave-v3.com")
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = existing

        row = get_or_create_protocol(session, "aave", official_domain="different.com")

        assert row.official_domain == "aave-v3.com"
        session.flush.assert_not_called()


# ---------------------------------------------------------------------------
# reclaim_stuck_jobs — cross-stage worker-crash recovery
# ---------------------------------------------------------------------------


@requires_postgres
def test_reclaim_stuck_jobs_resets_long_running_processing_to_queued(session):
    from db.models import JobStage, JobStatus
    from db.queue import claim_job, create_job, reclaim_stuck_jobs

    job = create_job(session, {"address": "0x" + "1" * 40})
    claimed = claim_job(session, JobStage.discovery, "crashed-worker")
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.status == JobStatus.processing
    _backdate_job(session, job.id, seconds_ago=10)

    reclaimed_ids = reclaim_stuck_jobs(session, stale_timeout_seconds=1)

    assert str(job.id) in [str(i) for i in reclaimed_ids]
    assert len(reclaimed_ids) == 1
    session.expire_all()
    refreshed = session.get(type(job), job.id)
    assert refreshed.status == JobStatus.queued
    assert refreshed.worker_id is None
    assert reclaim_stuck_jobs(session, stale_timeout_seconds=1) == []  # idempotent: second sweep finds nothing


@requires_postgres
def test_reclaim_stuck_jobs_leaves_recent_processing_alone(session):
    """A freshly-claimed job within the threshold must NOT be swept (that would steal work from a live worker)."""
    from db.models import JobStage, JobStatus
    from db.queue import claim_job, create_job, reclaim_stuck_jobs

    job = create_job(session, {"address": "0x" + "2" * 40})
    claimed = claim_job(session, JobStage.discovery, "live-worker")
    assert claimed is not None

    reclaimed_ids = reclaim_stuck_jobs(session, stale_timeout_seconds=900)

    assert reclaimed_ids == []
    session.expire_all()
    refreshed = session.get(type(job), job.id)
    assert refreshed.status == JobStatus.processing
    assert refreshed.worker_id == "live-worker"


@requires_postgres
def test_reclaim_stuck_jobs_ignores_terminal_states(session):
    """Completed and failed jobs are never touched, however old their updated_at."""
    from db.models import JobStage, JobStatus
    from db.queue import claim_job, complete_job, create_job, fail_job, reclaim_stuck_jobs

    completed = create_job(session, {"address": "0x" + "4" * 40})
    claim_job(session, JobStage.discovery, "w1")
    complete_job(session, completed.id)
    _backdate_job(session, completed.id, seconds_ago=10)

    failed = create_job(session, {"address": "0x" + "5" * 40})
    claim_job(session, JobStage.discovery, "w2")
    fail_job(session, failed.id, "boom")
    _backdate_job(session, failed.id, seconds_ago=10)

    reclaimed_ids = reclaim_stuck_jobs(session, stale_timeout_seconds=1)

    assert reclaimed_ids == []
    session.expire_all()
    assert session.get(type(completed), completed.id).status == JobStatus.completed
    assert session.get(type(failed), failed.id).status == JobStatus.failed


# ---------------------------------------------------------------------------
# Lease-based claim: duplicate-claim race POC
#
# claim_job filters only on status='queued', and reclaim_stuck_jobs fires when updated_at is stale.
# The heartbeat keeping updated_at fresh runs inside parallel_map's per-task callback
# (services/concurrency.py:82-86, 122-126), so a nested forge build longer than
# PSAT_JOB_STALE_TIMEOUT (900s in prod) silently expires the lease and a sibling claims the same
# job. These tests pin the fix: (1) the original holder's writes detect the lost lease and refuse
# to commit; (2) claim takes the lease atomically with the status flip.
# ---------------------------------------------------------------------------


def _complete(session, job_id, lease):
    from db.queue import complete_job

    complete_job(session, job_id, lease_id=lease)


def _advance(session, job_id, lease):
    from db.models import JobStage
    from db.queue import advance_job

    advance_job(session, job_id, JobStage.static, lease_id=lease)


@requires_postgres
@pytest.mark.parametrize(
    "op",
    [
        pytest.param(_complete, id="complete"),
        # CRITICAL: a reclaimed job must not be silently advanced by the original holder either.
        pytest.param(_advance, id="advance"),
    ],
)
def test_reclaimed_job_cannot_be_silently_written_by_original_holder(session, op):
    """Worker A claims, lags past stale_timeout, is reclaimed; B claims; A's completion/advance must be rejected
    (lease lost)."""
    from db.models import JobStage
    from db.queue import LeaseLost, claim_job, create_job, reclaim_stuck_jobs

    job = create_job(session, {"address": "0x" + "a" * 40, "name": "long-running"})
    a = claim_job(session, JobStage.discovery, "worker-A")
    assert a is not None
    a_lease = getattr(a, "lease_id", None)
    assert a_lease is not None, "claim_job must mint a lease id for the holder"

    _backdate_job(session, job.id, seconds_ago=1000)
    reclaim_stuck_jobs(session, stale_timeout_seconds=1)

    b = claim_job(session, JobStage.discovery, "worker-B")
    assert b is not None
    assert b.id == job.id
    assert b.worker_id == "worker-B"
    assert getattr(b, "lease_id", None) != a_lease, "B's claim must produce a fresh lease id"

    with pytest.raises(LeaseLost):
        op(session, a.id, a_lease)


@requires_postgres
def test_heartbeat_extends_lease_and_blocks_reclaim(session, monkeypatch):
    """A worker heartbeating inside a long task must not be reclaimed: the sweep keys on
    lease_expires_at, which the heartbeat extends regardless of updated_at.

    ``_heartbeat`` opens a fresh ``SessionLocal()`` (see ``test_heartbeat_fresh_session.py``),
    bound to the dev ``DATABASE_URL``, so it is routed to ``TEST_DATABASE_URL`` here."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session as _Session
    from sqlalchemy.orm import sessionmaker

    from db.models import JobStage, JobStatus
    from db.queue import claim_job, create_job, reclaim_stuck_jobs
    from workers.base import BaseWorker

    test_engine = create_engine(DATABASE_URL)
    monkeypatch.setattr(
        "workers.base.SessionLocal", sessionmaker(bind=test_engine, class_=_Session, expire_on_commit=False)
    )

    class _Probe(BaseWorker):
        stage = JobStage.discovery
        next_stage = JobStage.static
        poll_interval = 0.0

    job = create_job(session, {"address": "0x" + "c" * 40, "name": "heartbeating"})
    claimed = claim_job(session, JobStage.discovery, "worker-A")
    assert claimed is not None

    _backdate_job(session, job.id, seconds_ago=1000)

    probe = _Probe()
    probe._heartbeat(session, claimed)

    # Refresh test session to see the heartbeat's commit (different connection).
    session.expire_all()

    rescued = reclaim_stuck_jobs(session, stale_timeout_seconds=1)
    assert rescued == [], "heartbeat must keep the lease alive — sweep should leave the row"

    session.expire_all()
    refreshed = session.get(type(job), job.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.processing
    assert refreshed.worker_id == "worker-A"

    test_engine.dispose()


@requires_postgres
def test_concurrent_claims_cannot_both_acquire_lease(session):
    """A live lease must block any sibling claim, even when an unrelated write stamps updated_at."""
    from db.models import JobStage
    from db.queue import claim_job, create_job, reclaim_stuck_jobs

    create_job(session, {"address": "0x" + "d" * 40, "name": "live"})
    a = claim_job(session, JobStage.discovery, "worker-A")
    assert a is not None

    rescued = reclaim_stuck_jobs(session, stale_timeout_seconds=900)
    assert rescued == []

    other = claim_job(session, JobStage.discovery, "worker-B")
    assert other is None
