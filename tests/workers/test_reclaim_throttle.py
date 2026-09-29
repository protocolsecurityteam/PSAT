"""Regression tests for the stuck-job sweep throttle in ``workers.base.BaseWorker._claim_job``.

Unthrottled, 10 workers polling every 2s issued ~5 cross-stage ``UPDATE … FOR UPDATE
SKIP LOCKED`` sweeps per second, mostly returning zero rows. Each worker is now bounded
to one sweep per ``RECLAIM_INTERVAL_S`` (30s vs the 900s stale_timeout), while
``claim_job`` must never be starved by the throttle.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from db.models import JobStage
from workers import base
from workers.base import BaseWorker


class _FakeWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0.0


def test_first_claim_sweeps():
    """The ``-inf`` sentinel makes the first poll sweep; otherwise a fresh fleet waits
    RECLAIM_INTERVAL_S."""
    w = _FakeWorker()
    session = MagicMock()
    with (
        patch("workers.base.reclaim_stuck_jobs") as mocked_reclaim,
        patch("workers.base.claim_job", return_value=None) as mocked_claim,
        patch("workers.base.time.monotonic", return_value=1000.0),
    ):
        w._claim_job(session)
    assert mocked_reclaim.call_count == 1
    assert mocked_claim.call_count == 1


def test_repeat_claim_within_window_does_not_sweep():
    w = _FakeWorker()
    session = MagicMock()
    with (
        patch("workers.base.reclaim_stuck_jobs") as mocked_reclaim,
        patch("workers.base.claim_job", return_value=None) as mocked_claim,
        patch("workers.base.time.monotonic", side_effect=[1000.0, 1001.0]),
    ):
        w._claim_job(session)
        w._claim_job(session)
    assert mocked_reclaim.call_count == 1, "second claim within window must NOT sweep"
    assert mocked_claim.call_count == 2, "claim_job must always run"


def test_claim_after_window_expires_sweeps_again():
    """The cadence guarantee the fleet relies on."""
    w = _FakeWorker()
    session = MagicMock()
    interval = base.RECLAIM_INTERVAL_S
    with (
        patch("workers.base.reclaim_stuck_jobs") as mocked_reclaim,
        patch("workers.base.claim_job", return_value=None),
        patch(
            "workers.base.time.monotonic",
            side_effect=[1000.0, 1000.0 + interval + 0.1],
        ),
    ):
        w._claim_job(session)
        w._claim_job(session)
    assert mocked_reclaim.call_count == 2


def test_each_worker_throttle_is_independent():
    """Per-worker, not global: otherwise an unlucky boot order could starve one stage's recovery."""
    w1 = _FakeWorker()
    w2 = _FakeWorker()
    session = MagicMock()
    with (
        patch("workers.base.reclaim_stuck_jobs") as mocked_reclaim,
        patch("workers.base.claim_job", return_value=None),
        patch("workers.base.time.monotonic", return_value=1000.0),
    ):
        w1._claim_job(session)
        w2._claim_job(session)
    assert mocked_reclaim.call_count == 2
