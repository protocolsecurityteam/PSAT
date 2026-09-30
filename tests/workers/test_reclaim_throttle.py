"""Regression tests for the stuck-job sweep throttle in ``workers.base.BaseWorker._claim_job``.

Unthrottled, 10 workers polling every 2s issued ~5 cross-stage ``UPDATE … FOR UPDATE
SKIP LOCKED`` sweeps per second, mostly returning zero rows. Each worker is now bounded
to one sweep per ``RECLAIM_INTERVAL_S`` (30s vs the 900s stale_timeout), while
``claim_job`` must never be starved by the throttle.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from db.models import JobStage
from workers import base
from workers.base import BaseWorker


class _FakeWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0.0


@pytest.mark.parametrize(
    ("ticks", "expected_sweeps"),
    [
        # The ``-inf`` sentinel makes the first poll sweep; otherwise a fresh fleet waits RECLAIM_INTERVAL_S.
        pytest.param([1000.0], 1, id="first_claim_sweeps"),
        pytest.param([1000.0, 1001.0], 1, id="repeat_claim_within_window_does_not_sweep"),
        # The cadence guarantee the fleet relies on.
        pytest.param([1000.0, 1000.0 + base.RECLAIM_INTERVAL_S + 0.1], 2, id="claim_after_window_expires_sweeps_again"),
    ],
)
def test_reclaim_sweep_throttle_timeline(ticks, expected_sweeps):
    w = _FakeWorker()
    session = MagicMock()
    with (
        patch("workers.base.reclaim_stuck_jobs") as mocked_reclaim,
        patch("workers.base.claim_job", return_value=None) as mocked_claim,
        patch("workers.base.time.monotonic", side_effect=ticks),
    ):
        for _ in ticks:
            w._claim_job(session)
    assert mocked_reclaim.call_count == expected_sweeps
    assert mocked_claim.call_count == len(ticks), "claim_job must always run"


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
