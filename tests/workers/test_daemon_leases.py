"""Daemon-lease primitive against the real test Postgres.

Exclusivity lives in the ``ON CONFLICT ... WHERE`` statement, so contention uses two connections.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.queue import (
    renew_daemon_lease,
    try_acquire_daemon_lease,
)

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

requires_postgres = pytest.mark.skipif(not DATABASE_URL, reason="TEST_DATABASE_URL not set")

pytestmark = requires_postgres


def _lease_name() -> str:
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


# The other two branches are covered by ``test_contention_two_connections``.


def test_expired_lease_is_stolen(lease_session):
    session, created = lease_session
    name = _lease_name()
    created.append(name)
    holder_a = uuid.uuid4()
    holder_b = uuid.uuid4()

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

    # A longer TTL makes the forward move unambiguous.
    assert renew_daemon_lease(session, name, holder, ttl_seconds=120) is True
    after = _expires_at(session, name)

    assert before is not None and after is not None
    assert after > before
    assert _holder(session, name) == holder


def test_contention_two_connections(lease_session):
    session_a, created = lease_session
    name = _lease_name()
    created.append(name)
    holder_a = uuid.uuid4()
    holder_b = uuid.uuid4()

    engine_b = create_engine(DATABASE_URL)
    session_b = Session(engine_b, expire_on_commit=False)
    try:
        assert try_acquire_daemon_lease(session_a, name, holder_a, ttl_seconds=60) is True
        assert try_acquire_daemon_lease(session_b, name, holder_b, ttl_seconds=60) is False
        assert _holder(session_b, name) == holder_a

        assert try_acquire_daemon_lease(session_a, name, holder_a, ttl_seconds=-5) is True
        assert try_acquire_daemon_lease(session_b, name, holder_b, ttl_seconds=60) is True
        assert _holder(session_a, name) == holder_b
    finally:
        session_b.close()
        engine_b.dispose()
