"""Daemon-lease primitive (design §2.4 Layer 1) against the real test Postgres.

No fakes: these drive ``db.queue.try_acquire_daemon_lease`` /
``renew_daemon_lease`` / ``release_daemon_lease`` over the real
``daemon_leases`` table. The exclusivity guarantee lives in the
``INSERT ... ON CONFLICT (name) DO UPDATE ... WHERE`` statement, so the
contention case exercises it through two independent connections.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.queue import (
    release_daemon_lease,
    renew_daemon_lease,
    try_acquire_daemon_lease,
)

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

requires_postgres = pytest.mark.skipif(not DATABASE_URL, reason="TEST_DATABASE_URL not set")

pytestmark = requires_postgres


def _lease_name() -> str:
    # Unique per test so rows never collide across the shared test DB.
    return f"test_lease:{uuid.uuid4().hex[:12]}"


def _expires_at(session: Session, name: str):
    return session.execute(
        text("SELECT expires_at FROM daemon_leases WHERE name = :n"), {"n": name}
    ).scalar_one_or_none()


def _holder(session: Session, name: str):
    return session.execute(text("SELECT holder FROM daemon_leases WHERE name = :n"), {"n": name}).scalar_one_or_none()


@pytest.fixture()
def lease_session():
    engine = create_engine(DATABASE_URL)
    session = Session(engine, expire_on_commit=False)
    created: list[str] = []
    try:
        yield session, created
    finally:
        session.rollback()
        for name in created:
            session.execute(text("DELETE FROM daemon_leases WHERE name = :n"), {"n": name})
        session.commit()
        session.close()
        engine.dispose()


def test_fresh_acquire_wins(lease_session):
    session, created = lease_session
    name = _lease_name()
    created.append(name)
    holder = uuid.uuid4()

    assert try_acquire_daemon_lease(session, name, holder, ttl_seconds=60) is True
    assert _holder(session, name) == holder


def test_distinct_holder_loses_while_unexpired(lease_session):
    session, created = lease_session
    name = _lease_name()
    created.append(name)
    holder_a = uuid.uuid4()
    holder_b = uuid.uuid4()

    assert try_acquire_daemon_lease(session, name, holder_a, ttl_seconds=60) is True
    # Live lease, different holder: the WHERE fails, nothing is updated.
    assert try_acquire_daemon_lease(session, name, holder_b, ttl_seconds=60) is False
    assert _holder(session, name) == holder_a


def test_expired_lease_is_stolen(lease_session):
    session, created = lease_session
    name = _lease_name()
    created.append(name)
    holder_a = uuid.uuid4()
    holder_b = uuid.uuid4()

    # Negative TTL seeds an already-expired lease (expires_at = NOW() - 5s).
    assert try_acquire_daemon_lease(session, name, holder_a, ttl_seconds=-5) is True
    assert try_acquire_daemon_lease(session, name, holder_b, ttl_seconds=60) is True
    assert _holder(session, name) == holder_b


def test_holder_reacquire_extends_expiry(lease_session):
    session, created = lease_session
    name = _lease_name()
    created.append(name)
    holder = uuid.uuid4()

    assert try_acquire_daemon_lease(session, name, holder, ttl_seconds=60) is True
    before = _expires_at(session, name)

    # Re-acquire (renewal) always wins for the current holder and pushes
    # expires_at forward; a longer TTL makes the forward move unambiguous.
    assert renew_daemon_lease(session, name, holder, ttl_seconds=120) is True
    after = _expires_at(session, name)

    assert before is not None and after is not None
    assert after > before
    assert _holder(session, name) == holder


def test_release_removes_own_row(lease_session):
    session, created = lease_session
    name = _lease_name()
    created.append(name)
    holder = uuid.uuid4()

    assert try_acquire_daemon_lease(session, name, holder, ttl_seconds=60) is True
    release_daemon_lease(session, name, holder)
    assert _holder(session, name) is None


def test_release_wrong_holder_noops(lease_session):
    session, created = lease_session
    name = _lease_name()
    created.append(name)
    holder = uuid.uuid4()
    other = uuid.uuid4()

    assert try_acquire_daemon_lease(session, name, holder, ttl_seconds=60) is True
    # Someone who doesn't hold the lease can't delete the real holder's row.
    release_daemon_lease(session, name, other)
    assert _holder(session, name) == holder


def test_contention_two_connections(lease_session):
    """Two independent sessions prove the ON CONFLICT WHERE is the exclusivity
    guarantee — not any in-process coordination."""
    session_a, created = lease_session
    name = _lease_name()
    created.append(name)
    holder_a = uuid.uuid4()
    holder_b = uuid.uuid4()

    engine_b = create_engine(DATABASE_URL)
    session_b = Session(engine_b, expire_on_commit=False)
    try:
        assert try_acquire_daemon_lease(session_a, name, holder_a, ttl_seconds=60) is True
        # Second connection, live lease held elsewhere → loses.
        assert try_acquire_daemon_lease(session_b, name, holder_b, ttl_seconds=60) is False
        assert _holder(session_b, name) == holder_a

        # Once A releases, B can take it from its own connection.
        release_daemon_lease(session_a, name, holder_a)
        assert try_acquire_daemon_lease(session_b, name, holder_b, ttl_seconds=60) is True
        assert _holder(session_a, name) == holder_b
    finally:
        session_b.close()
        engine_b.dispose()


def test_daemon_leases_table_reachable(lease_session):
    """The conftest migration created the table; a plain SELECT must succeed."""
    session, _ = lease_session
    session.execute(text("SELECT name, holder, expires_at FROM daemon_leases LIMIT 1")).all()
