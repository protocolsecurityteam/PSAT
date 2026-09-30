"""Architectural invariant: ``BaseWorker._heartbeat`` must open a fresh
``SessionLocal()`` rather than reuse the long-lived worker session.

During ``parallel_map`` the main session does no SQL for 2-10 minutes and Neon's
pooler closes the idle SSL connection. The heartbeat's UPDATE then raises
``OperationalError``, is swallowed, ``updated_at`` never refreshes, and the
stale-job sweep requeues live work to a sibling. Seen in ``psat-pr-73``
(2026-05-08 06:43-06:55): ``ResolutionWorker-657-2655967e`` was requeued despite
four heartbeat callbacks. ``pool_pre_ping=True`` replaces stale pooled connections
on the fresh session's checkout.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

from db.models import JobStage, JobStatus
from workers.base import BaseWorker


class _TestWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0

    def process(self, session, job):
        pass


def _make_job(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        address="0x" + "a" * 40,
        name="test-job",
        status=JobStatus.processing,
        stage=JobStage.discovery,
        updated_at=datetime.now(timezone.utc),
        worker_id="some-worker",
        detail=None,
        retry_count=0,
        lease_id=uuid.uuid4(),
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _ctx_session(stand_in: MagicMock) -> MagicMock:
    """Wrap *stand_in* so it works as a context manager (``with SessionLocal() as s``)."""
    stand_in.__enter__ = MagicMock(return_value=stand_in)
    stand_in.__exit__ = MagicMock(return_value=False)
    return stand_in


@patch("workers.base.signal.signal")
@patch("workers.base.heartbeat_job")
def test_heartbeat_does_not_reuse_passed_session_on_lease_path(
    mock_heartbeat_job: MagicMock,
    _mock_signal: MagicMock,
) -> None:
    """``heartbeat_job`` must get a session opened *inside* ``_heartbeat``, since the
    main session can be silently dead (Neon SSL idle close)."""
    w = _TestWorker()
    job = _make_job()  # has lease_id by default

    # Stand-in for the worker's main session. Any execute on it would
    # raise like a Neon-killed connection — the heartbeat must not touch it.
    worker_session = MagicMock()
    worker_session.execute.side_effect = AssertionError(
        "_heartbeat must NOT issue the UPDATE through the worker's main session"
    )

    fresh_session = _ctx_session(MagicMock())
    SessionLocalMock = MagicMock(return_value=fresh_session)

    with patch("workers.base.SessionLocal", SessionLocalMock):
        w._heartbeat(worker_session, cast(Any, job))

    # SessionLocal was opened.
    assert SessionLocalMock.called, "_heartbeat must open a fresh SessionLocal()"
    # heartbeat_job was called with the FRESH session, not the worker's.
    assert mock_heartbeat_job.called, "heartbeat_job should be invoked on the lease path"
    used_session = mock_heartbeat_job.call_args.args[0]
    assert used_session is fresh_session, (
        "heartbeat_job must be called with the fresh SessionLocal session, not the worker's main session"
    )
    assert used_session is not worker_session
