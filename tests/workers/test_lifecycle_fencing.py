"""Paused old owners must not commit after their 900-second lease expires."""

import uuid
from functools import partial

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from db.models import Job, JobStage, JobStatus, Protocol
from services.commit_fence import fenced_commits
from services.monitoring import reconciler
from services.monitoring.enrollment import mark_enrollment_dirty
from services.process_singleton import ProcessSingleton
from services.resolution import indexer_scheduler
from services.resolution.indexer_work import WorkPending, claim_one, mark_dirty, renew_claim
from tests.conftest import DATABASE_URL, requires_postgres

pytestmark = requires_postgres


def test_session_singleton_cannot_expire_or_overlap():
    first = ProcessSingleton("workers", DATABASE_URL)
    second = ProcessSingleton("workers", DATABASE_URL)
    try:
        assert first.acquire()
        first.check()
        assert not second.acquire()
        first.close()
        assert second.acquire()
        second.check()
    finally:
        first.close()
        second.close()


def test_singleton_loss_is_detected_without_reconnect():
    first = ProcessSingleton("monitor", DATABASE_URL)
    try:
        assert first.acquire()
        with first.connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock_all()")
        with pytest.raises(RuntimeError, match="ownership lost"):
            first.check()
    finally:
        first.close()


def test_transaction_pool_endpoint_rejected():
    with pytest.raises(ValueError, match="direct PostgreSQL"):
        ProcessSingleton("workers", "postgresql://user:password@ep-test-pooler.neon.tech/db")


def test_indexer_lost_lease_rolls_back_business_writes(db_session):
    db_session.execute(text("DELETE FROM indexer_work"))
    mark_dirty(db_session, "reconcile", "1")
    db_session.commit()
    claim = claim_one(db_session, ("reconcile",))
    assert claim is not None
    with Session(db_session.bind) as other:
        other.execute(text("UPDATE indexer_work SET lease_id=:lease"), {"lease": uuid.uuid4()})
        other.commit()
    with pytest.raises(WorkPending):
        with fenced_commits(db_session, partial(renew_claim, claim=claim)):
            db_session.add(
                Job(
                    id=uuid.uuid4(), name="stale-indexer", stage=JobStage.discovery, status=JobStatus.queued, request={}
                )
            )
            db_session.commit()
    db_session.rollback()
    assert db_session.query(Job).filter_by(name="stale-indexer").count() == 0


def test_real_reconciliation_internal_commit_is_fenced(db_session, monkeypatch):
    db_session.execute(text("DELETE FROM indexer_work"))
    mark_dirty(db_session, "reconcile", "1")
    db_session.commit()

    def takeover_then_commit(session, **_):
        with Session(session.bind) as other:
            other.execute(text("UPDATE indexer_work SET lease_id=:lease"), {"lease": uuid.uuid4()})
            other.commit()
        session.add(
            Job(id=uuid.uuid4(), name="stale-reconcile", stage=JobStage.discovery, status=JobStatus.queued, request={})
        )
        session.commit()
        return 1

    monkeypatch.setattr(indexer_scheduler, "reconcile_deferred_resolutions", takeover_then_commit)
    assert indexer_scheduler.drain_reconciliation(db_session) == (0, 0)
    assert db_session.query(Job).filter_by(name="stale-reconcile").count() == 0


def test_enrollment_takeover_cannot_stamp_success(db_session):
    protocol = Protocol(name="fenced-enrollment")
    db_session.add(protocol)
    db_session.commit()
    mark_enrollment_dirty(db_session, protocol.id, "test")
    db_session.commit()
    claim = reconciler.claim_due_enrollments(db_session, lease_ttl_s=900, limit=1)[0]
    with Session(db_session.bind) as other:
        other.execute(text("UPDATE monitoring_enrollment_queue SET lease_id=:lease"), {"lease": uuid.uuid4()})
        other.commit()
    with pytest.raises(RuntimeError, match="lease lost"):
        reconciler._finish_success(db_session, claim)
    db_session.rollback()
    db_session.refresh(protocol)
    assert protocol.last_enrollment_reconcile_at is None


def test_enrollment_internal_commit_is_fenced(db_session):
    protocol = Protocol(name="fenced-enrollment-commit")
    db_session.add(protocol)
    db_session.commit()
    mark_enrollment_dirty(db_session, protocol.id, "test")
    db_session.commit()
    claim = reconciler.claim_due_enrollments(db_session, lease_ttl_s=900, limit=1)[0]
    with Session(db_session.bind) as other:
        other.execute(text("UPDATE monitoring_enrollment_queue SET lease_expires_at=now()-interval '1 second'"))
        other.commit()
    with pytest.raises(RuntimeError, match="lease lost"):
        with fenced_commits(db_session, lambda s: reconciler.renew_claim(s, claim)):
            protocol.name = "must-rollback"
            db_session.commit()
    db_session.rollback()
    db_session.refresh(protocol)
    assert protocol.name == "fenced-enrollment-commit"
