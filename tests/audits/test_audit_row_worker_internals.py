"""``SessionLocal`` is patched with a dummy exposing only ``close()``."""

from __future__ import annotations

import logging
import signal as _signal
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from workers import audit_row_worker as arw_module
from workers.audit_row_worker import AuditRowWorker


class _Outcome:
    def __init__(self, *, status: str = "success", error: str | None = None) -> None:
        self.status = status
        self.error = error


class _FakeRow:
    def __init__(self, row_id: int) -> None:
        self.id = row_id


class _TestWorker(AuditRowWorker):
    """Each ``_next_batch`` call returns the next queued batch, then stops the loop."""

    worker_name = "TestWorker"
    batch_size = 2
    max_concurrent = 2
    idle_poll_interval = 0.0  # No sleep — test must not stall.
    stale_processing_seconds = 600
    stale_recovery_every_n_polls = 1  # Recover on every iteration.
    thread_name_prefix = "test-audit-row"

    def __init__(self, batches: list[list[_FakeRow]] | None = None) -> None:
        super().__init__()
        self._batches = list(batches or [])
        self._claim_calls = 0
        self._recover_calls = 0
        self.processed: list[int] = []
        self.persisted: list[tuple[int, Any]] = []
        self.log = logging.getLogger("tests.test_audit_row_worker_internals")

    def _pending_rows_query(self):
        raise AssertionError("_pending_rows_query should not be called when _claim_batch is overridden")

    def _mark_processing(self, row, now) -> None:
        raise AssertionError("_mark_processing should not be called when _claim_batch is overridden")

    def _stale_recovery_query(self, cutoff):
        raise AssertionError("_stale_recovery_query should not be called when _recover_stale_rows is overridden")

    def _claim_batch(self, session) -> list[Any]:
        self._claim_calls += 1
        if self._batches:
            return self._batches.pop(0)
        return []

    def _recover_stale_rows(self, session) -> None:
        self._recover_calls += 1

    def _process_row(self, audit) -> tuple[int, Any]:
        self.processed.append(audit.id)
        return audit.id, _Outcome(status="success")

    def _persist_outcome(self, audit_id: int, result) -> None:
        self.persisted.append((audit_id, result))


@pytest.fixture(autouse=True)
def _patch_session_local(monkeypatch):

    class _DummySession:
        def close(self) -> None:
            pass

    monkeypatch.setattr(arw_module, "SessionLocal", _DummySession)
    yield


def test_handle_signal_flips_running_false(caplog):
    # configure_logging would wipe pytest's LogCaptureHandler; pre-marking the root keeps caplog attached.
    import logging as _stdlib_logging

    from utils import logging as _psat_logging

    setattr(_stdlib_logging.getLogger(), _psat_logging._CONFIGURED_FLAG, True)
    worker = _TestWorker()
    assert worker._running is True
    with caplog.at_level(logging.INFO, logger=worker.log.name):
        worker._handle_signal(_signal.SIGTERM, None)
    assert worker._running is False
    # Ops relies on this line to know why a worker died.
    assert any("received signal" in r.message for r in caplog.records)


class TestLogOutcomeDefault:
    @pytest.mark.parametrize(
        ("audit_id", "outcome", "expected", "has_parens"),
        [
            pytest.param(42, _Outcome(status="success"), "Audit 42 → success", False, id="success-status-only"),
            pytest.param(
                7, _Outcome(status="failed", error="boom"), "Audit 7 → failed (boom)", True, id="failed-error-in-parens"
            ),
            # A subclass returning something without ``status`` must not crash.
            pytest.param(9, object(), "Audit 9 → ?", False, id="non-outcome-question-mark"),
        ],
    )
    def test_log_outcome_format(self, caplog, audit_id, outcome, expected, has_parens):
        worker = _TestWorker()
        with caplog.at_level(logging.INFO, logger=worker.log.name):
            worker._log_outcome(audit_id, outcome)
        messages = [r.getMessage() for r in caplog.records]
        assert any(expected in m for m in messages)
        assert any("(" in m and ")" in m for m in messages) is has_parens


class _RecoveryWorker(AuditRowWorker):
    worker_name = "RecoveryTest"
    log = logging.getLogger("tests.test_audit_row_worker_internals.recovery")

    def _pending_rows_query(self):  # pragma: no cover - unused in the recovery test
        raise NotImplementedError

    def _mark_processing(self, row, now) -> None:  # pragma: no cover
        raise NotImplementedError

    def _stale_recovery_query(self, cutoff):
        return MagicMock()  # placeholder — session.execute is mocked

    def _process_row(self, audit):  # pragma: no cover
        raise NotImplementedError

    def _persist_outcome(self, audit_id, result) -> None:  # pragma: no cover
        raise NotImplementedError


class TestRecoverStaleRows:
    def test_no_stale_rows_rolls_back(self):
        """Otherwise the idle transaction sits between polls until Postgres kills it."""
        worker = _RecoveryWorker()
        session = MagicMock()
        session.execute.return_value = iter([])  # zero rows returned
        worker._recover_stale_rows(session)
        session.rollback.assert_called_once()
        session.commit.assert_not_called()

    def test_stale_rows_commits_and_logs(self, caplog):
        worker = _RecoveryWorker()
        session = MagicMock()
        row1 = MagicMock()
        row1.id = 10
        row2 = MagicMock()
        row2.id = 11
        session.execute.return_value = iter([row1, row2])
        with caplog.at_level(logging.WARNING, logger=worker.log.name):
            worker._recover_stale_rows(session)
        session.commit.assert_called_once()
        session.rollback.assert_not_called()
        assert any("reset 2 stale row" in r.getMessage() for r in caplog.records)


class TestRunLoop:
    def test_processes_claimed_batch_and_exits_on_signal(self, caplog):
        rows = [_FakeRow(100), _FakeRow(101)]

        class _ExitAfterOneBatchWorker(_TestWorker):
            def _persist_outcome(self, audit_id, result):
                super()._persist_outcome(audit_id, result)
                self._running = False

        worker = _ExitAfterOneBatchWorker(batches=[rows])
        with caplog.at_level(logging.INFO, logger=worker.log.name):
            worker.run_loop()

        assert sorted(worker.processed) == [100, 101]
        assert sorted(pid for pid, _ in worker.persisted) == [100, 101]
        assert worker._claim_calls >= 1
        assert worker._recover_calls >= 1
        messages = [r.getMessage() for r in caplog.records]
        assert any("starting" in m for m in messages)
        assert any("claimed 2 audit" in m for m in messages)

    def test_no_work_sleeps_and_polls_again(self, monkeypatch):
        sleeps: list[float] = []

        def fake_sleep(secs: float) -> None:
            sleeps.append(secs)

        monkeypatch.setattr(arw_module.time, "sleep", fake_sleep)

        class _ExitAfterIdleWorker(_TestWorker):
            def _claim_batch(self, session):
                self._claim_calls += 1
                self._running = False
                return []

        worker = _ExitAfterIdleWorker()
        worker.run_loop()

        assert worker.processed == []
        assert worker.persisted == []
        assert sleeps == [0.0]

    def test_unexpected_process_row_exception_is_swallowed(self, caplog):
        """The loop must keep draining instead of leaving the row in 'processing' until stale recovery."""
        rows = [_FakeRow(200), _FakeRow(201)]

        class _RaisingWorker(_TestWorker):
            def _process_row(self, audit):
                if audit.id == 200:
                    raise RuntimeError("simulated failure")
                return super()._process_row(audit)

            def _persist_outcome(self, audit_id, result):
                super()._persist_outcome(audit_id, result)
                if audit_id == 201:
                    self._running = False

        worker = _RaisingWorker(batches=[rows])
        with caplog.at_level(logging.ERROR, logger=worker.log.name):
            worker.run_loop()

        assert [pid for pid, _ in worker.persisted] == [201]
        assert any("Unexpected error" in r.getMessage() for r in caplog.records)

    def test_stale_recovery_runs_on_poll_cadence(self):
        """Stale recovery is the only way to detect a stuck worker from another process."""

        class _ExitAfterTwoPolls(_TestWorker):
            stale_recovery_every_n_polls = 1

            def _claim_batch(self, session):
                self._claim_calls += 1
                if self._claim_calls >= 2:
                    self._running = False
                return []

        worker = _ExitAfterTwoPolls()
        worker.run_loop()

        assert worker._claim_calls == 2
        assert worker._recover_calls == 2


def test_recovery_cutoff_is_configured_seconds_in_past():
    """Otherwise a subclass could reset rows still in flight."""
    captured: dict[str, datetime] = {}

    class _CaptureCutoffWorker(_RecoveryWorker):
        stale_processing_seconds = 300

        def _stale_recovery_query(self, cutoff):
            captured["cutoff"] = cutoff
            return MagicMock()

    session = MagicMock()
    session.execute.return_value = iter([])
    worker = _CaptureCutoffWorker()
    before = datetime.now(timezone.utc) - timedelta(seconds=301)
    worker._recover_stale_rows(session)
    after = datetime.now(timezone.utc) - timedelta(seconds=299)
    assert before <= captured["cutoff"] <= after


@pytest.fixture()
def _restore_audit_worker_modules():
    """``importlib.reload`` rebinds ``max_concurrent`` on the class, which outlives the test."""
    yield
    import importlib
    import os

    import workers.audit_scope_extraction as scope_mod
    import workers.audit_text_extraction as text_mod

    # Finalizer order between same-scope fixtures is not guaranteed.
    os.environ.pop("PSAT_AUDIT_TEXT_CONCURRENCY", None)
    os.environ.pop("PSAT_AUDIT_SCOPE_CONCURRENCY", None)
    importlib.reload(text_mod)
    importlib.reload(scope_mod)


def test_audit_concurrency_overridable_via_env(_restore_audit_worker_modules, monkeypatch):
    monkeypatch.setenv("PSAT_AUDIT_TEXT_CONCURRENCY", "3")
    monkeypatch.setenv("PSAT_AUDIT_SCOPE_CONCURRENCY", "5")
    import importlib

    import workers.audit_scope_extraction as scope_mod
    import workers.audit_text_extraction as text_mod

    importlib.reload(text_mod)
    importlib.reload(scope_mod)

    assert text_mod.AuditTextExtractionWorker.max_concurrent == 3
    assert scope_mod.AuditScopeExtractionWorker.max_concurrent == 5
