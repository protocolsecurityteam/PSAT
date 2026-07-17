"""Logging/observability locks for the event_log_indexer daemon + repos.

Offline: no DB, no network. The scan path is driven with a fake session whose
only DB interaction is the initial cursor listing, and a head fetcher that
raises — so the per-group swallow, the ``failed_groups`` tally, and the
degraded-heartbeat decision are exercised without Postgres or an RPC.
"""

from __future__ import annotations

import logging

import pytest

from services.resolution.repos import event_logs_pg
from utils.logging import stage_metrics_var
from workers.event_log_indexer import (
    ScanSummary,
    _heartbeat_status_for_pass,
    scan_enrolled_events,
)

_ADDR = "0x" + "ab" * 20
_TOPIC = "0x" + "cd" * 32


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


class _BoomHead:
    def head_block(self) -> int:
        raise RuntimeError("rpc down")


def test_group_scan_failure_is_swallowed_warning_not_exception(caplog):
    """A group whose head fetch raises is counted in ``failed_groups`` and logged
    as a WARNING carrying ``exc_type`` — never a ``logger.exception`` traceback
    storm (the prod outage once emitted 2,172 ERROR tracebacks here)."""
    session = _FakeSession([(1, _ADDR, _TOPIC, None)])
    sentinel = object()
    with caplog.at_level(logging.WARNING, logger="workers.event_log_indexer"):
        summary = scan_enrolled_events(
            session,  # type: ignore[arg-type]
            fetchers={1: sentinel},  # type: ignore[arg-type]
            head_fetchers={1: _BoomHead()},
            block_hash_fetchers={1: sentinel},  # type: ignore[arg-type]
        )

    assert summary.failed_groups == 1
    assert summary.windows_scanned == 0
    assert summary.total_cursors == 1
    assert session.rollbacks == 1

    recs = [r for r in caplog.records if r.name == "workers.event_log_indexer"]
    assert len(recs) == 1
    rec = recs[0]
    assert rec.levelno == logging.WARNING  # not ERROR
    assert rec.exc_info is None  # no traceback attached
    assert getattr(rec, "exc_type", None) == "RuntimeError"
    assert getattr(rec, "event_address", None) == _ADDR


def test_total_outage_pass_degrades_the_heartbeat():
    """Every attempted group failed (0 windows) → degraded; a partial failure
    (some windows scanned) stays running; an errored pass stays error."""
    all_failed = ScanSummary(windows_scanned=0, failed_groups=2, total_cursors=2)
    assert _heartbeat_status_for_pass("running", all_failed) == "degraded"

    partial = ScanSummary(windows_scanned=5, failed_groups=1, total_cursors=3)
    assert _heartbeat_status_for_pass("running", partial) == "running"

    healthy = ScanSummary(windows_scanned=5, failed_groups=0, total_cursors=3)
    assert _heartbeat_status_for_pass("running", healthy) == "running"

    # A pass that raised wholesale must not be downgraded to merely "degraded".
    assert _heartbeat_status_for_pass("error", all_failed) == "error"


def test_main_installs_json_logging(monkeypatch):
    """main() routes the daemon through configure_logging() (JsonFormatter on the
    root logger) instead of logging.basicConfig — so its ``extra={}`` fields ship
    as queryable JSON rather than plaintext."""
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
    """The repo partial-reason counter tallies per reason, folds the running
    count into a stage metric under a worker job, and WARNs only on a genuine
    upstream degradation (timeout/max_pages); benign defers log at DEBUG."""
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
    """Outside a worker job (no stage-metrics accumulator) the metric write is a
    no-op and must not raise — repos call this unconditionally."""
    event_logs_pg._PARTIAL_REASON_COUNTS.clear()
    assert event_logs_pg._note_partial_reason(reason, event_address=_ADDR, repo="postgres") == 1
