"""The ``chain`` logging contextvar is bound per job.

``BaseWorker._execute_job`` binds ``chain`` so every job-scoped log line can be
filtered per chain in Loki. It prefers the human-readable chain name in
``request['chain']`` and falls back to the canonical name of the job's
first-class ``chain_id`` when the request omits chain.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from db.models import JobStage, JobStatus
from utils.logging import chain_var
from workers.base import BaseWorker, _job_chain_log_value


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
        worker_id="some-worker",
        detail=None,
        retry_count=0,
        lease_id=None,  # skip the background heartbeat thread
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# _job_chain_log_value — pure label resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("chain_id", "req", "expected"),
    [
        pytest.param(1, {"chain": "base"}, "base", id="request_chain_name_beats_chain_id"),
        pytest.param(8453, {}, "base", id="falls_back_to_chain_id_name"),
        pytest.param(None, {}, None, id="none_when_no_chain_signal"),
        pytest.param(999999, {}, None, id="none_for_unknown_chain_id"),
    ],
)
def test_job_chain_log_value(chain_id, req, expected):
    job = _make_job(chain_id=chain_id)
    assert _job_chain_log_value(job, req) == expected


# ---------------------------------------------------------------------------
# _execute_job — the bind actually happens at the worker entry point
# ---------------------------------------------------------------------------


@patch("workers.base.signal.signal")
@patch("workers.base.advance_job")
def test_execute_job_binds_chain_from_request(_mock_advance, _mock_signal):
    captured: dict[str, str | None] = {}
    job = _make_job(request={"address": "0x" + "a" * 40, "chain": "base"}, chain_id=8453)

    w = _TestWorker()
    w._record_stage_timing = MagicMock()
    w._satisfy_dependencies = MagicMock(return_value=0)
    w.process = MagicMock(side_effect=lambda _s, _j: captured.__setitem__("chain", chain_var.get()))

    w._execute_job(MagicMock(), cast(Any, job))
    assert captured["chain"] == "base"
    # Contextvar is reset on exit — no leak into the next job.
    assert chain_var.get() is None
