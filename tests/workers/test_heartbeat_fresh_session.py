"""Architectural invariant: ``BaseWorker._heartbeat`` must open a fresh
``SessionLocal()`` rather than reuse the long-lived worker session that
parallel sections leave idle for minutes.

The worker's main ORM session sits idle through ``resolve_control_graph``
— the worker thread blocks in ``parallel_map`` (semaphore + ``as_completed``)
while forge builds run in the executor pool, doing zero SQL on its own
session for 2-10 minutes. Neon's pooler-side SSL idle timeout closes
that connection during the wait. When ``_heartbeat`` finally fires per
parallel_map completion, ``session.execute(UPDATE jobs ...)`` raises
``OperationalError``; the except-clause swallows, ``updated_at`` never
refreshes, and the stale-job sweep requeues live work to a sibling
worker that redoes the whole recursion chain.

Confirmed in ``psat-pr-73`` logs (2026-05-08 06:43-06:55):
``ResolutionWorker-657-2655967e`` claimed LiquidityPool: (impl) at
06:43:52, ran four parallel forge builds (heartbeat opportunities at
~06:46:22, 06:46:23, ~06:50, ~06:54), and was requeued by
``ResolutionWorker-657-8778bce0`` at 06:54:46 with
``stuck since 2026-05-08T06:43:58.048516+00:00`` — i.e. ``updated_at``
hadn't moved off the value set by the initial ``update_detail`` commit
despite four heartbeat callbacks firing.

Fix: open a fresh session inside ``_heartbeat``. Pool's
``pool_pre_ping=True`` validates the new connection on checkout, so any
stale connection in the pool is replaced transparently — the heartbeat
write doesn't share a session lifecycle with the long-running worker
flow.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import JobStage, JobStatus  # noqa: E402
from workers.base import BaseWorker  # noqa: E402


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
    """The lease path must invoke ``heartbeat_job`` with a session opened
    *inside* ``_heartbeat`` — not the worker's main session passed in.

    Justification: the worker's main session can be silently dead (Neon
    SSL idle close) by the time the heartbeat fires. Heartbeat writes
    must not share its lifecycle.
    """
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


@patch("workers.base.signal.signal")
def test_heartbeat_does_not_reuse_passed_session_on_legacy_path(
    _mock_signal: MagicMock,
) -> None:
    """Same invariant for the legacy (``lease_id is None``) path: the
    fallback ``UPDATE jobs SET updated_at=...`` must run on a fresh
    session, not the worker's main session.
    """
    w = _TestWorker()
    job = _make_job(lease_id=None)

    worker_session = MagicMock()
    worker_session.execute.side_effect = AssertionError(
        "_heartbeat legacy path must NOT issue the UPDATE through the worker's main session"
    )

    fresh_session = _ctx_session(MagicMock())
    SessionLocalMock = MagicMock(return_value=fresh_session)

    with patch("workers.base.SessionLocal", SessionLocalMock):
        w._heartbeat(worker_session, cast(Any, job))

    assert SessionLocalMock.called, "_heartbeat (legacy path) must open a fresh SessionLocal()"
    assert fresh_session.execute.called, "fresh session must receive the UPDATE"
    assert fresh_session.commit.called, "fresh session must commit"
