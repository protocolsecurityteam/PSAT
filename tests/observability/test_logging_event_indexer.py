"""Logging locks for the event_log_indexer daemon + repos. Offline.

The scan path runs against a fake session (only the cursor listing) and a head fetcher that
raises, exercising the per-group swallow, the ``failed_groups`` tally and the degraded-heartbeat
decision without Postgres or RPC.
"""

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
    """Answers only the initial cursor listing; records rollback/commit calls."""

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


# A group whose head fetch raises is counted in ``failed_groups`` and logged as a WARNING with
# ``exc_type``, never a traceback storm (a prod outage emitted 2,172 ERROR tracebacks).
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
    """Every attempted group failed (0 windows) -> degraded; partial failure stays running;
    an errored pass stays error."""
    all_failed = ScanSummary(windows_scanned=0, failed_groups=2, total_cursors=2)
    assert _heartbeat_status_for_pass("running", all_failed) == "degraded"

    partial = ScanSummary(windows_scanned=5, failed_groups=1, total_cursors=3)
    assert _heartbeat_status_for_pass("running", partial) == "running"

    healthy = ScanSummary(windows_scanned=5, failed_groups=0, total_cursors=3)
    assert _heartbeat_status_for_pass("running", healthy) == "running"

    # A pass that raised wholesale must not be downgraded to merely "degraded".
    assert _heartbeat_status_for_pass("error", all_failed) == "error"


def test_main_installs_json_logging(monkeypatch):
    """main() routes through configure_logging() (JsonFormatter) instead of basicConfig, so
    ``extra={}`` fields ship as queryable JSON."""
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
    """The counter tallies per reason, folds the running count into a stage metric under a worker
    job, and WARNs only on genuine upstream degradation (timeout/max_pages); benign defers are DEBUG."""
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

    # None (a complete fold) is a no-op: no count, no metric, no log.
    before = len(caplog.records)
    assert event_logs_pg._note_partial_reason(None, event_address=_ADDR, repo="postgres") == 0
    assert len(caplog.records) == before


@pytest.mark.parametrize("reason", ["no_index_cursor", "hypersync_max_pages"])
def test_note_partial_reason_noop_without_job_context(reason):
    """Outside a worker job the metric write is a no-op and must not raise (repos call it unconditionally)."""
    event_logs_pg._PARTIAL_REASON_COUNTS.clear()
    assert event_logs_pg._note_partial_reason(reason, event_address=_ADDR, repo="postgres") == 1


def test_indexer_loop_binds_worker_id_on_both_threads(monkeypatch):
    """The daemon is not a BaseWorker, so nothing binds ``worker_id``; its stream was the one
    fleet worker output with no identity to filter by. Both the reconcile loop AND the backfill
    thread must carry it (a new thread starts with an empty context)."""
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
        # Stop only once the backfill thread has been observed too; its bind is easiest to lose.
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
    # And the bind is scoped: it must not leak into the caller's context.
    assert worker_id_var.get() is None


def test_shutdown_line_names_the_process(monkeypatch, caplog):
    """Every daemon logs shutdown within the same second when the fleet stops; identical lines
    make it impossible to tell which process got the signal."""
    import signal as signal_mod

    import workers.event_log_indexer as indexer

    handlers: dict[int, object] = {}
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    monkeypatch.setattr(signal_mod, "signal", lambda num, fn: handlers.setdefault(num, fn))
    monkeypatch.setattr(indexer, "run_event_log_indexer_loop", lambda **_k: None)
    # ``main()`` calls ``configure_logging()``, whose first call clears every root handler,
    # including caplog's. Left in, this passes only if an earlier test configured logging, so
    # it fails under xdist's fresh processes. ``test_main_installs_json_logging`` covers the real call.
    monkeypatch.setattr(indexer, "configure_logging", lambda *_a, **_k: None)

    indexer.main()
    with caplog.at_level(logging.INFO, logger="workers.event_log_indexer"):
        handlers[signal_mod.SIGTERM](signal_mod.SIGTERM, None)  # pyright: ignore[reportCallIssue]

    record = next(r for r in caplog.records if "shutting down" in r.getMessage())
    assert indexer.WORKER_ID in record.getMessage()
    assert record.worker_id == indexer.WORKER_ID
    assert record.pid == os.getpid()


def test_probe_code_failure_is_visible_and_still_over_enrolls(monkeypatch, caplog):
    """An unreadable probe keeps the fail-safe direction (enroll the union of every standard's
    topic0s) but used to read like a contract declaring no known standard."""
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
