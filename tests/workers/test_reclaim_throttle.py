"""Unthrottled, 10 workers polling every 2s issued ~5 cross-stage sweeps per second.

Each worker now sweeps at most once per ``RECLAIM_INTERVAL_S``, and ``claim_job`` must never be starved.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from db.models import JobStage
from workers.base import BaseWorker


class _FakeWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0.0


def test_each_worker_throttle_is_independent():
    """A global throttle could starve one stage's recovery by boot order."""
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
