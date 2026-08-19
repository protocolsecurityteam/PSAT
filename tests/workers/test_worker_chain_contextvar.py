"""M0.2 item 2 — the ``chain`` logging contextvar is bound per job (invariant 4).

``BaseWorker._execute_job`` binds ``chain`` so every job-scoped log line can be
filtered per chain in Loki. It prefers the human-readable chain name in
``request['chain']`` and falls back to the canonical name of the job's
first-class ``chain_id`` (M0.2) when the request omits chain.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

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


def test_label_prefers_request_chain_name():
    job = _make_job(chain_id=1)
    assert _job_chain_log_value(job, {"chain": "base"}) == "base"


def test_label_falls_back_to_chain_id_name():
    """No request chain but a chain_id → canonical name for that id."""
    job = _make_job(chain_id=8453)
    assert _job_chain_log_value(job, {}) == "base"


def test_label_none_when_no_chain_signal():
    job = _make_job(chain_id=None)
    assert _job_chain_log_value(job, {}) is None


def test_label_none_for_unknown_chain_id():
    job = _make_job(chain_id=999999)
    assert _job_chain_log_value(job, {}) is None


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


@patch("workers.base.signal.signal")
@patch("workers.base.advance_job")
def test_execute_job_binds_chain_from_chain_id_when_request_omits_it(_mock_advance, _mock_signal):
    captured: dict[str, str | None] = {}
    job = _make_job(request={"address": "0x" + "a" * 40}, chain_id=8453)

    w = _TestWorker()
    w._record_stage_timing = MagicMock()
    w._satisfy_dependencies = MagicMock(return_value=0)
    w.process = MagicMock(side_effect=lambda _s, _j: captured.__setitem__("chain", chain_var.get()))

    w._execute_job(MagicMock(), cast(Any, job))
    assert captured["chain"] == "base"
