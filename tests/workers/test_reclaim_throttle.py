"""Regression tests for the stuck-job sweep throttle in
``workers.base.BaseWorker._claim_job``.

Before this throttle every worker called ``reclaim_stuck_jobs`` on every
poll: with 10 worker procs polling every 2s, that's 5 cross-stage
``UPDATE … WHERE status='processing' … FOR UPDATE SKIP LOCKED`` queries
per second, 24/7. Most of those return zero rows — pure DB noise.

The throttle bounds each worker to one sweep per ``RECLAIM_INTERVAL_S``
seconds. Recovery is still global (any worker can sweep) and still timely
(stale_timeout is 900s; sweep cadence is 30s). What we pin:

1. The first claim sweeps (sentinel ``-inf`` initial timestamp).
2. A second claim within the throttle window does NOT sweep.
3. A claim after the throttle window expires sweeps again.
4. ``claim_job`` is always called regardless of sweep state — the
   throttle must NOT starve the happy path.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import JobStage
from workers import base
from workers.base import BaseWorker


class _FakeWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0.0


def test_first_claim_sweeps():
    """Sentinel float('-inf') guarantees the first poll always sweeps —
    otherwise a freshly-started fleet would wait RECLAIM_INTERVAL_S
    before doing the first cross-stage sweep."""
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
    """Two claims 1s apart with a 30s window must produce only one sweep."""
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
    """A claim after RECLAIM_INTERVAL_S elapses re-arms the sweep — this
    is the cadence guarantee the fleet relies on."""
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


def test_claim_job_called_every_time_regardless_of_throttle():
    """Critical safety property: throttling the SWEEP must never throttle
    the CLAIM. A bug that conflated the two would silently halve worker
    throughput."""
    w = _FakeWorker()
    session = MagicMock()
    with (
        patch("workers.base.reclaim_stuck_jobs"),
        patch("workers.base.claim_job", return_value=None) as mocked_claim,
        patch("workers.base.time.monotonic", side_effect=[1000.0, 1001.0, 1002.0]),
    ):
        w._claim_job(session)
        w._claim_job(session)
        w._claim_job(session)
    assert mocked_claim.call_count == 3


def test_each_worker_throttle_is_independent():
    """The throttle is per-worker, not global. Two workers in the same
    process must each be allowed a sweep — otherwise an unlucky boot
    order could starve one stage's recovery."""
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
