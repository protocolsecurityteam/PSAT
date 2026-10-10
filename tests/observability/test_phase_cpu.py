"""Per-phase CPU on ``log_timed_phase`` records, beside the wall-time fields it already carried."""

from __future__ import annotations

import logging
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from tests.support.worker_stubs import _make_job, _TestWorker
from utils.logging import job_in_flight, log_timed_phase

_LOGGER = logging.getLogger("test.phase_cpu")


def _burn(seconds: float) -> None:
    deadline = time.thread_time() + seconds
    while time.thread_time() < deadline:
        pass


def _phase_record(caplog, prefix: str = "phase complete") -> logging.LogRecord:
    return next(r for r in caplog.records if r.name == _LOGGER.name and r.message.startswith(prefix))


def test_phase_record_keeps_wall_fields_and_adds_cpu(caplog):
    durations: dict[str, int] = {}
    with caplog.at_level(logging.INFO, logger=_LOGGER.name):
        with log_timed_phase(_LOGGER, "burn", durations_ms=durations, extra_field="kept") as extra:
            _burn(0.05)
            extra["items"] = 3

    record = _phase_record(caplog)
    fields = cast(Any, record)
    assert fields.phase == "burn"
    assert isinstance(fields.duration_ms, int) and durations == {"burn": fields.duration_ms}
    assert fields.extra_field == "kept" and fields.items == 3
    assert fields.cpu_s >= 0.04
    assert fields.process_cpu_s >= fields.cpu_s - 0.005
    assert fields.children_cpu_s >= 0.0
    assert fields.job_concurrency == 0


def test_work_on_another_thread_is_process_cpu_not_thread_cpu(caplog):
    with caplog.at_level(logging.INFO, logger=_LOGGER.name):
        with log_timed_phase(_LOGGER, "fan_out"):
            worker = threading.Thread(target=_burn, args=(0.1,))
            worker.start()
            worker.join()

    fields = cast(Any, _phase_record(caplog))
    assert fields.cpu_s < 0.05
    assert fields.process_cpu_s >= 0.09


def test_reaped_subprocess_cpu_is_attributed_to_the_phase(caplog):
    burn = "import time\nd = time.process_time() + 0.2\nwhile time.process_time() < d: pass\n"
    with caplog.at_level(logging.INFO, logger=_LOGGER.name):
        with log_timed_phase(_LOGGER, "forge_build"):
            subprocess.run([sys.executable, "-c", burn], check=True)

    fields = cast(Any, _phase_record(caplog))
    assert fields.children_cpu_s >= 0.15
    assert fields.cpu_s < fields.children_cpu_s


def test_failed_phase_carries_cpu_when_failure_logging_is_on(caplog):
    with caplog.at_level(logging.INFO, logger=_LOGGER.name):
        with pytest.raises(RuntimeError):
            with log_timed_phase(_LOGGER, "boom", log_failure=True):
                _burn(0.02)
                raise RuntimeError("boom")

    fields = cast(Any, _phase_record(caplog, "phase ended with error"))
    assert fields.outcome == "failed" and isinstance(fields.duration_ms, int)
    assert fields.cpu_s >= 0.015


def test_job_concurrency_counts_jobs_in_flight_across_threads(caplog):
    entered = threading.Barrier(2)
    release = threading.Event()

    def other_job() -> None:
        with job_in_flight():
            entered.wait()
            release.wait(timeout=5)

    other = threading.Thread(target=other_job)
    other.start()
    try:
        with caplog.at_level(logging.INFO, logger=_LOGGER.name):
            with job_in_flight():
                entered.wait()
                with log_timed_phase(_LOGGER, "shared"):
                    pass
    finally:
        release.set()
        other.join()

    assert cast(Any, _phase_record(caplog)).job_concurrency == 2
    with caplog.at_level(logging.INFO, logger=_LOGGER.name):
        caplog.clear()
        with log_timed_phase(_LOGGER, "after"):
            pass
    assert cast(Any, _phase_record(caplog)).job_concurrency == 0


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@patch("workers.base.signal.signal")
@patch("workers.base.advance_job")
def test_execute_job_marks_its_job_in_flight_for_phase_records(_advance, _signal):
    job = _make_job(lease_id=uuid.uuid4())
    # Worker construction reconfigures root logging, which drops caplog's handler.
    worker = _TestWorker()
    worker._record_stage_timing = MagicMock()
    worker._satisfy_dependencies = MagicMock(return_value=0)

    def process(_session, _job):
        with log_timed_phase(_LOGGER, "inside_job"):
            pass

    worker.process = MagicMock(side_effect=process)
    handler = _ListHandler()
    _LOGGER.addHandler(handler)
    previous_level = _LOGGER.level
    _LOGGER.setLevel(logging.INFO)
    try:
        worker._execute_job(MagicMock(), cast(Any, job))
    finally:
        _LOGGER.removeHandler(handler)
        _LOGGER.setLevel(previous_level)

    (record,) = [r for r in handler.records if r.getMessage().startswith("phase complete")]
    assert cast(Any, record).job_concurrency == 1
