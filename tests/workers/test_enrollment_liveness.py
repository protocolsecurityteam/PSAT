"""Long enrollment builds retain ownership without weakening takeover fencing."""

import threading
import time
from datetime import datetime, timezone

import pytest
from sqlalchemy import text, update
from sqlalchemy.orm import sessionmaker

from db.models import MonitoringEnrollmentQueue, Protocol
from services.monitoring import reconciler
from services.monitoring.enrollment import mark_enrollment_dirty
from tests.conftest import requires_postgres

pytestmark = requires_postgres


@pytest.fixture
def enrollment(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_WORKER_LIFECYCLE_MODE", "off")
    monkeypatch.delenv("PSAT_WORKER_BOOT_ID", raising=False)
    factory = sessionmaker(bind=db_session.bind, expire_on_commit=False)
    monkeypatch.setattr(reconciler, "SessionLocal", factory)
    monkeypatch.setattr(reconciler, "rpc_for_chain", lambda *_: "offline")
    protocol = Protocol(name="long-enrollment")
    db_session.add(protocol)
    db_session.commit()
    mark_enrollment_dirty(db_session, protocol.id, "test")
    db_session.commit()
    yield protocol.id, factory
    assert not any(t.name == "enrollment-lease-keepalive" for t in threading.enumerate())


def run_drain(**kwargs):
    return reconciler.drain_enrollment_queue("offline", "ethereum", lease_ttl_s=1, **kwargs)


def test_long_build_renews_between_commits_even_when_lifecycle_off(enrollment, monkeypatch):
    protocol_id, factory = enrollment

    def build(session, *_args, **_kwargs):
        time.sleep(1.35)
        with factory() as observer:
            row = observer.get(MonitoringEnrollmentQueue, protocol_id)
            assert row is not None and row.lease_expires_at is not None
            assert row.lease_expires_at > datetime.now(timezone.utc)
        protocol = session.get(Protocol, protocol_id)
        assert protocol is not None
        protocol.name = "completed-long-build"
        session.commit()
        return []

    monkeypatch.setattr(reconciler, "enroll_protocol_contracts", build)
    assert run_drain() == {"drained": 1, "failed": 0}
    with factory() as observer:
        protocol = observer.get(Protocol, protocol_id)
        assert protocol is not None and protocol.name == "completed-long-build"
        assert protocol.last_enrollment_reconcile_at is not None
        assert observer.get(MonitoringEnrollmentQueue, protocol_id) is None


def test_own_queue_lock_can_outlive_ttl_without_deadlock_or_false_loss(enrollment, monkeypatch):
    protocol_id, factory = enrollment

    def build(session, *_args, **_kwargs):
        session.execute(
            update(MonitoringEnrollmentQueue)
            .where(MonitoringEnrollmentQueue.protocol_id == protocol_id)
            .values(reason="business-write")
        )
        time.sleep(1.35)  # Keepalive must skip our locked row rather than block.
        with factory() as other:
            assert reconciler.claim_due_enrollments(other, lease_ttl_s=1, limit=1) == []
        protocol = session.get(Protocol, protocol_id)
        assert protocol is not None
        protocol.name = "lock-holder-completed"
        session.commit()
        return []

    monkeypatch.setattr(reconciler, "enroll_protocol_contracts", build)
    assert run_drain() == {"drained": 1, "failed": 0}
    with factory() as observer:
        protocol = observer.get(Protocol, protocol_id)
        assert protocol is not None and protocol.name == "lock-holder-completed"


def test_actual_takeover_fences_all_stale_commits_and_heartbeat(enrollment, monkeypatch):
    protocol_id, factory = enrollment
    successor = []

    def build(session, *_args, **_kwargs):
        with factory() as other:
            other.execute(text("UPDATE monitoring_enrollment_queue SET lease_expires_at=now()-interval '1 second'"))
            # This real claimant locks/replaces the expired token atomically.
            successor.extend(reconciler.claim_due_enrollments(other, lease_ttl_s=10, limit=1))
        assert len(successor) == 1
        time.sleep(0.75)  # At least two old-owner keepalive attempts.
        for _ in range(2):
            protocol = session.get(Protocol, protocol_id)
            assert protocol is not None
            protocol.name = "stale-must-never-commit"
            with pytest.raises(RuntimeError, match="lease lost"):
                session.commit()
            session.rollback()
        raise RuntimeError("ownership was lost")

    monkeypatch.setattr(reconciler, "enroll_protocol_contracts", build)
    assert run_drain() == {"drained": 0, "failed": 1}
    with factory() as observer:
        protocol = observer.get(Protocol, protocol_id)
        assert protocol is not None and protocol.name == "long-enrollment"
        assert protocol.last_enrollment_reconcile_at is None
        row = observer.get(MonitoringEnrollmentQueue, protocol_id)
        assert row is not None and row.lease_id == successor[0].lease_id and row.attempts == 0


def test_heartbeat_error_does_not_poison_unchanged_owner(enrollment, monkeypatch):
    protocol_id, factory = enrollment
    attempted = threading.Event()

    def unavailable(*_args):
        attempted.set()
        raise OSError("temporary local DB connection failure")

    monkeypatch.setattr(reconciler, "_keepalive_once", unavailable)

    def build(session, *_args, **_kwargs):
        time.sleep(1.35)  # Lease expires, but no successor claims it.
        assert attempted.is_set()
        protocol = session.get(Protocol, protocol_id)
        assert protocol is not None
        protocol.name = "recovered-connectivity"
        session.commit()
        return []

    monkeypatch.setattr(reconciler, "enroll_protocol_contracts", build)
    assert run_drain() == {"drained": 1, "failed": 0}
    with factory() as observer:
        protocol = observer.get(Protocol, protocol_id)
        assert protocol is not None and protocol.name == "recovered-connectivity"


def test_later_protocol_is_not_preclaimed_while_long_build_runs(enrollment, monkeypatch):
    first_id, factory = enrollment
    with factory() as session:
        second = Protocol(name="second-enrollment")
        session.add(second)
        session.commit()
        second_id = second.id
        mark_enrollment_dirty(session, second_id, "test")
        session.commit()
    order = []

    def build(session, protocol_id, *_args, **_kwargs):
        order.append(protocol_id)
        if protocol_id == first_id:
            time.sleep(1.35)
            with factory() as observer:
                row = observer.get(MonitoringEnrollmentQueue, second_id)
                assert row is not None and row.lease_id is None and row.lease_expires_at is None
        session.commit()
        return []

    monkeypatch.setattr(reconciler, "enroll_protocol_contracts", build)
    assert run_drain(max_claims=2) == {"drained": 2, "failed": 0}
    assert order == [first_id, second_id]


def test_redirtied_protocol_is_not_rebuilt_twice_in_one_pass(enrollment, monkeypatch):
    protocol_id, factory = enrollment
    calls = []

    def build(session, *_args, **_kwargs):
        calls.append(protocol_id)
        mark_enrollment_dirty(session, protocol_id, "changed-during-build")
        session.commit()
        return []

    monkeypatch.setattr(reconciler, "enroll_protocol_contracts", build)
    assert run_drain(max_claims=8) == {"drained": 1, "failed": 0}
    assert calls == [protocol_id]
    with factory() as observer:
        row = observer.get(MonitoringEnrollmentQueue, protocol_id)
        assert row is not None and row.lease_id is None


@pytest.mark.parametrize("fail", [False, True])
def test_shutdown_finishes_current_build_and_joins_keepalive(enrollment, monkeypatch, fail):
    protocol_id, factory = enrollment
    stopped = threading.Event()
    with factory() as session:
        second = Protocol(name="waiting-for-next-owner")
        session.add(second)
        session.commit()
        second_id = second.id
        mark_enrollment_dirty(session, second_id, "test")
        session.commit()

    def build(session, current_id, *_args, **_kwargs):
        assert current_id == protocol_id
        stopped.set()
        time.sleep(1.35)  # Signal cannot terminate keepalive while build drains.
        with factory() as observer:
            row = observer.get(MonitoringEnrollmentQueue, protocol_id)
            assert row is not None and row.lease_expires_at is not None
            assert row.lease_expires_at > datetime.now(timezone.utc)
        if fail:
            raise RuntimeError("build failure")
        session.commit()
        return []

    monkeypatch.setattr(reconciler, "enroll_protocol_contracts", build)
    assert run_drain(stop_event=stopped) == {"drained": int(not fail), "failed": int(fail)}
    with factory() as observer:
        row = observer.get(MonitoringEnrollmentQueue, second_id)
        assert row is not None and row.lease_id is None
