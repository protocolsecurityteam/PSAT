"""Offline: a fake session and a raising head fetcher exercise the per-group swallow and degraded-heartbeat decision."""

from __future__ import annotations

import logging
import os
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

import pytest

from services.resolution.repos import event_logs_pg
from utils.logging import stage_metrics_var, worker_id_var

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
from workers.event_log_indexer import (
    ScanSummary,
    _heartbeat_status_for_pass,
    scan_enrolled_events,
)

_ADDR = "0x" + "ab" * 20
_TOPIC = "0x" + "cd" * 32
_RUN = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeSession:
    def __init__(self, rows):
        self._rows = rows
        self.rollbacks = 0
        self.commits = 0

    def execute(self, *_a, **_k):
        return _FakeResult(self._rows)

    def rollback(self):
        self.rollbacks += 1

    def commit(self):
        self.commits += 1

    def in_transaction(self):
        return False


class _BoomHead:
    def head_block(self) -> int:
        raise RuntimeError("rpc down")


# A prod outage once emitted 2,172 ERROR tracebacks.
@pytest.mark.parametrize(
    ("rows", "scan_kwargs", "expected_failed_groups", "expected_rollbacks", "expected_address"),
    [
        pytest.param([(1, _ADDR, _TOPIC, _RUN, 0, False, None, None)], {}, 1, 1, _ADDR, id="default-mode"),
        pytest.param(
            [
                (1, _ADDR, _TOPIC, _RUN, 100, True, _RUN, None),
                (1, "0x" + "12" * 20, _TOPIC, _RUN, 100, True, _RUN, None),
            ],
            {"scan_mode": "warm"},
            2,
            0,  # warm mode fails the whole chain's head read, not one address group
            None,
            id="warm-mode",
        ),
    ],
)
def test_group_scan_failure_is_swallowed_warning_not_exception(
    caplog, rows, scan_kwargs, expected_failed_groups, expected_rollbacks, expected_address
):
    session = _FakeSession(rows)
    sentinel = object()
    with caplog.at_level(logging.WARNING, logger="workers.event_log_indexer"):
        summary = scan_enrolled_events(
            session,  # pyright: ignore[reportArgumentType]
            fetchers={1: sentinel},  # pyright: ignore[reportArgumentType]
            head_fetchers={1: _BoomHead()},
            block_hash_fetchers={1: sentinel},  # pyright: ignore[reportArgumentType]
            **scan_kwargs,
        )

    assert summary.failed_groups == expected_failed_groups
    assert summary.windows_scanned == 0
    assert summary.total_cursors == len(rows)
    assert session.rollbacks == expected_rollbacks

    recs = [r for r in caplog.records if r.name == "workers.event_log_indexer"]
    assert len(recs) == 1
    assert len(caplog.records) == 1
    rec = recs[0]
    assert rec.levelno == logging.WARNING  # not ERROR
    assert rec.exc_info is None  # no traceback attached
    assert getattr(rec, "exc_type", None) == "RuntimeError"
    assert getattr(rec, "event_address", None) == expected_address


def test_total_outage_pass_degrades_the_heartbeat():
    all_failed = ScanSummary(windows_scanned=0, failed_groups=2, total_cursors=2)
    assert _heartbeat_status_for_pass("running", all_failed) == "degraded"

    partial = ScanSummary(windows_scanned=5, failed_groups=1, total_cursors=3)
    assert _heartbeat_status_for_pass("running", partial) == "running"

    healthy = ScanSummary(windows_scanned=5, failed_groups=0, total_cursors=3)
    assert _heartbeat_status_for_pass("running", healthy) == "running"

    assert _heartbeat_status_for_pass("error", all_failed) == "error"


def test_main_installs_json_logging(monkeypatch):
    """So ``extra={}`` fields ship as queryable JSON."""
    import signal as signal_mod

    import workers.event_log_indexer as indexer
    from utils.logging import JsonFormatter

    root = logging.getLogger()
    if hasattr(root, "_psat_json_logging_configured"):
        delattr(root, "_psat_json_logging_configured")
    for h in list(root.handlers):
        root.removeHandler(h)

    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    monkeypatch.setattr(signal_mod, "signal", lambda *_a, **_k: None)
    called: dict[str, bool] = {}
    monkeypatch.setattr(indexer, "run_event_log_indexer_loop", lambda **_k: called.setdefault("ran", True))

    indexer.main()

    assert called.get("ran") is True
    assert getattr(root, "_psat_json_logging_configured", False) is True
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)


def test_note_partial_reason_counts_and_levels(caplog):
    """Only genuine upstream degradation warns; benign defers are DEBUG."""
    event_logs_pg._PARTIAL_REASON_COUNTS.clear()

    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        with caplog.at_level(logging.DEBUG, logger=event_logs_pg.__name__):
            n1 = event_logs_pg._note_partial_reason("no_index_cursor", event_address=_ADDR, repo="postgres")
            n2 = event_logs_pg._note_partial_reason("no_index_cursor", event_address=_ADDR, repo="postgres")
            event_logs_pg._note_partial_reason("hypersync_timeout", event_address=_ADDR, repo="hypersync")
    finally:
        stage_metrics_var.reset(token)

    assert (n1, n2) == (1, 2)
    assert metrics["event_fold_partial_no_index_cursor"] == 2
    assert metrics["event_fold_partial_hypersync_timeout"] == 1

    by_reason = {(r.partial_reason, r.levelno) for r in caplog.records if r.name == event_logs_pg.__name__}
    assert ("no_index_cursor", logging.DEBUG) in by_reason
    assert ("hypersync_timeout", logging.WARNING) in by_reason

    before = len(caplog.records)
    assert event_logs_pg._note_partial_reason(None, event_address=_ADDR, repo="postgres") == 0
    assert len(caplog.records) == before


def test_indexer_loop_binds_worker_id_on_both_threads(monkeypatch):
    """The daemon isn't a BaseWorker and a new thread starts with an empty context, so both threads must bind
    ``worker_id``.
    """
    import time
    from threading import Event

    import workers.event_log_indexer as indexer

    seen: dict[str, str | None] = {}
    stop = Event()

    def _fake_enroll_from_completed_jobs(_session, **_kwargs):
        seen["backfill"] = worker_id_var.get()
        return 0

    def _fake_heartbeat(*_a, **_k):
        seen.setdefault("reconcile", worker_id_var.get())
        deadline = time.monotonic() + 5
        while "backfill" not in seen and time.monotonic() < deadline:
            time.sleep(0.01)
        stop.set()

    monkeypatch.setattr(indexer, "SessionLocal", lambda: nullcontext(object()))
    from services.resolution import indexer_scheduler

    monkeypatch.setattr(indexer_scheduler, "drain_enrollment", _fake_enroll_from_completed_jobs)
    monkeypatch.setattr(indexer, "scan_enrolled_events", lambda *_a, **_k: ScanSummary())
    monkeypatch.setattr(indexer_scheduler, "drain_reconciliation", lambda *_a, **_k: (0, 0))
    monkeypatch.setattr(indexer, "_cursor_progress", lambda _s: (0, 0))
    monkeypatch.setattr(indexer, "record_heartbeat", _fake_heartbeat)

    indexer.run_event_log_indexer_loop(
        fetchers={}, head_fetchers={}, block_hash_fetchers={}, interval=0.01, stop_event=stop
    )

    assert seen.get("backfill") == indexer.WORKER_ID
    assert seen.get("reconcile") == indexer.WORKER_ID
    assert worker_id_var.get() is None


def test_shutdown_line_names_the_process(monkeypatch, caplog):
    import signal as signal_mod

    import workers.event_log_indexer as indexer

    handlers: dict[int, object] = {}
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    monkeypatch.setattr(signal_mod, "signal", lambda num, fn: handlers.setdefault(num, fn))
    monkeypatch.setattr(indexer, "run_event_log_indexer_loop", lambda **_k: None)
    # ``configure_logging()`` clears caplog's handler on first call, so this would pass only if an earlier test
    # configured logging.
    monkeypatch.setattr(indexer, "configure_logging", lambda *_a, **_k: None)

    indexer.main()
    with caplog.at_level(logging.INFO, logger="workers.event_log_indexer"):
        handlers[signal_mod.SIGTERM](signal_mod.SIGTERM, None)  # pyright: ignore[reportCallIssue]

    record = next(r for r in caplog.records if "shutting down" in r.getMessage())
    assert indexer.WORKER_ID in record.getMessage()
    assert record.worker_id == indexer.WORKER_ID
    assert record.pid == os.getpid()


def test_probe_code_failure_is_visible_and_still_over_enrolls(monkeypatch, caplog):
    """Over-enrolling is the fail-safe direction, but it used to look like a contract declaring no standard."""
    import workers.event_log_indexer as indexer

    def _boom(*_a, **_k):
        raise RuntimeError("rpc down")

    monkeypatch.setattr(indexer, "resolve_probe_code", _boom)

    with caplog.at_level(logging.WARNING, logger="workers.event_log_indexer"):
        topics = indexer._role_store_topic0s(cast("Session", object()), _ADDR, 1, {})

    assert topics == indexer.all_topic0s()
    record = next(r for r in caplog.records if r.levelno == logging.WARNING)
    assert record.exc_type == "RuntimeError"
    assert record.decision == "enroll_all_standards"
    assert record.chain_id == 1
