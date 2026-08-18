"""Unit tests for ``workers.audit_row_worker.AuditRowWorker``.

The two concrete subclasses (``AuditTextExtractionWorker`` and
``AuditScopeExtractionWorker``) drive ``_claim_batch``, ``_process_row``
and ``_persist_outcome`` through their integration suites. What lives
here are the *base-class* behaviours those integration tests skip:

    - ``_handle_signal`` flipping ``_running`` to False
    - ``_log_outcome`` formatting (with and without ``error``)
    - ``_recover_stale_rows`` when no rows are stuck (the rollback branch)
    - ``run_loop`` end-to-end with mocked DB + batch dispatch, including:
        * no-work idle sleep path
        * periodic stale recovery
        * successful row processing (persist + log called)
        * ``_process_row`` raising an unexpected exception

No real Postgres, no external services — ``SessionLocal`` is patched at
the module level with a dummy that exposes only ``close()``.
"""

from __future__ import annotations

import logging
import signal as _signal
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workers import audit_row_worker as arw_module  # noqa: E402
from workers.audit_row_worker import AuditRowWorker  # noqa: E402

# ---------------------------------------------------------------------------
# Minimal concrete subclass driving only what the tests need.
# ---------------------------------------------------------------------------


class _Outcome:
    """Outcome shape matching what ``_log_outcome`` reads."""

    def __init__(self, *, status: str = "success", error: str | None = None) -> None:
        self.status = status
        self.error = error


class _FakeRow:
    """Stand-in for a SQLAlchemy AuditReport row — only id is read."""

    def __init__(self, row_id: int) -> None:
        self.id = row_id


class _TestWorker(AuditRowWorker):
    """Concrete subclass that records every method call.

    The ``run_loop`` tests below drive this via ``_next_batch`` — each call
    returns the next pre-queued batch, then sets ``_running = False`` so
    the loop exits after N iterations. That is cleaner than relying on a
    separate timer thread."""

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

    # Hooks — only what the base class requires.
    def _pending_rows_query(self):  # noqa: ANN201
        raise AssertionError("_pending_rows_query should not be called when _claim_batch is overridden")

    def _mark_processing(self, row, now) -> None:  # noqa: ARG002
        raise AssertionError("_mark_processing should not be called when _claim_batch is overridden")

    def _stale_recovery_query(self, cutoff):  # noqa: ANN201, ARG002
        raise AssertionError("_stale_recovery_query should not be called when _recover_stale_rows is overridden")

    def _claim_batch(self, session) -> list[Any]:  # noqa: ARG002
        self._claim_calls += 1
        if self._batches:
            return self._batches.pop(0)
        # Out of batches — let the caller decide when to stop. Default: no work.
        return []

    def _recover_stale_rows(self, session) -> None:  # noqa: ARG002
        self._recover_calls += 1

    def _process_row(self, audit) -> tuple[int, Any]:
        self.processed.append(audit.id)
        return audit.id, _Outcome(status="success")

    def _persist_outcome(self, audit_id: int, result) -> None:
        self.persisted.append((audit_id, result))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _patch_session_local(monkeypatch):
    """``run_loop`` instantiates ``SessionLocal()`` every poll. Replace it
    with a context-managerless dummy that only needs ``close()``."""

    class _DummySession:
        def close(self) -> None:
            pass

    monkeypatch.setattr(arw_module, "SessionLocal", _DummySession)
    yield


# ---------------------------------------------------------------------------
# _handle_signal — flips _running to False and logs once.
# ---------------------------------------------------------------------------


def test_handle_signal_flips_running_false(caplog):
    """SIGTERM / SIGINT arrives → the loop should drain, then exit."""
    # ``utils.logging.configure_logging`` runs in ``AuditRowWorker.__init__``
    # and on its first call wipes the root logger's pre-existing handlers
    # — including pytest's ``LogCaptureHandler``. Pre-mark the root as
    # configured so the call short-circuits and caplog stays attached.
    import logging as _stdlib_logging

    from utils import logging as _psat_logging

    setattr(_stdlib_logging.getLogger(), _psat_logging._CONFIGURED_FLAG, True)
    worker = _TestWorker()
    assert worker._running is True
    with caplog.at_level(logging.INFO, logger=worker.log.name):
        worker._handle_signal(_signal.SIGTERM, None)
    assert worker._running is False
    # Make sure we logged the signal — ops relies on this line to know why
    # a worker died.
    assert any("received signal" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# _log_outcome — default formatting (with / without error).
# ---------------------------------------------------------------------------


class TestLogOutcomeDefault:
    def test_success_outcome_logs_status_only(self, caplog):
        worker = _TestWorker()
        with caplog.at_level(logging.INFO, logger=worker.log.name):
            worker._log_outcome(42, _Outcome(status="success"))
        messages = [r.getMessage() for r in caplog.records]
        assert any("Audit 42 → success" in m for m in messages)
        assert not any("(" in m and ")" in m for m in messages)

    def test_failed_outcome_logs_error_in_parens(self, caplog):
        worker = _TestWorker()
        with caplog.at_level(logging.INFO, logger=worker.log.name):
            worker._log_outcome(7, _Outcome(status="failed", error="boom"))
        messages = [r.getMessage() for r in caplog.records]
        assert any("Audit 7 → failed (boom)" in m for m in messages)

    def test_non_outcome_uses_question_mark(self, caplog):
        """If a subclass hands back something without ``status``, don't
        crash — log a ``?`` so the operator can still see the row moved."""
        worker = _TestWorker()
        with caplog.at_level(logging.INFO, logger=worker.log.name):
            worker._log_outcome(9, object())
        messages = [r.getMessage() for r in caplog.records]
        assert any("Audit 9 → ?" in m for m in messages)


# ---------------------------------------------------------------------------
# _recover_stale_rows — no-stale-rows path (rollback, not commit).
#
# Covered through a minimal concrete subclass; the DB behaviour is driven
# by a MagicMock session that reports an empty result set.
# ---------------------------------------------------------------------------


class _RecoveryWorker(AuditRowWorker):
    worker_name = "RecoveryTest"
    log = logging.getLogger("tests.test_audit_row_worker_internals.recovery")

    def _pending_rows_query(self):  # pragma: no cover - unused in the recovery test
        raise NotImplementedError

    def _mark_processing(self, row, now) -> None:  # pragma: no cover
        raise NotImplementedError

    def _stale_recovery_query(self, cutoff):  # noqa: ANN201, ARG002
        return MagicMock()  # placeholder — session.execute is mocked

    def _process_row(self, audit):  # pragma: no cover
        raise NotImplementedError

    def _persist_outcome(self, audit_id, result) -> None:  # pragma: no cover
        raise NotImplementedError


class TestRecoverStaleRows:
    def test_no_stale_rows_rolls_back(self):
        """When the RETURNING-less UPDATE finds nothing, the session must
        roll back the implicit transaction so we don't sit on an idle
        txn between polls — Postgres will eventually kill it as stuck."""
        worker = _RecoveryWorker()
        session = MagicMock()
        session.execute.return_value = iter([])  # zero rows returned
        worker._recover_stale_rows(session)
        session.rollback.assert_called_once()
        session.commit.assert_not_called()

    def test_stale_rows_commits_and_logs(self, caplog):
        """Rows returned → log a warning and commit the reset. We only
        need a shape that behaves like SQLAlchemy's result iterator."""
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


# ---------------------------------------------------------------------------
# run_loop — the glue that the integration tests never call directly
# ---------------------------------------------------------------------------


class TestRunLoop:
    def test_processes_claimed_batch_and_exits_on_signal(self, caplog):
        """One batch of rows is claimed, processed in the thread pool,
        persisted, and logged. After the batch drains we flip
        ``_running = False`` to exit. This is the smoke test for the
        whole loop — without it, everything below 185 in
        ``audit_row_worker.py`` stays uncovered."""
        rows = [_FakeRow(100), _FakeRow(101)]

        class _ExitAfterOneBatchWorker(_TestWorker):
            def _persist_outcome(self, audit_id, result):
                super()._persist_outcome(audit_id, result)
                # Signal the loop to stop after the first persist completes.
                self._running = False

        worker = _ExitAfterOneBatchWorker(batches=[rows])
        with caplog.at_level(logging.INFO, logger=worker.log.name):
            worker.run_loop()

        assert sorted(worker.processed) == [100, 101]
        assert sorted(pid for pid, _ in worker.persisted) == [100, 101]
        assert worker._claim_calls >= 1
        # Stale recovery must run on the first poll with _every_n_polls=1.
        assert worker._recover_calls >= 1
        # The startup + claim info lines make up the operator's breadcrumb.
        messages = [r.getMessage() for r in caplog.records]
        assert any("starting" in m for m in messages)
        assert any("claimed 2 audit" in m for m in messages)

    def test_no_work_sleeps_and_polls_again(self, monkeypatch):
        """Empty claim → idle sleep. Exit after one idle sleep so we don't
        loop forever. The sleep-branch is the common-case hot path when
        the pipeline is caught up."""
        sleeps: list[float] = []

        def fake_sleep(secs: float) -> None:
            sleeps.append(secs)

        monkeypatch.setattr(arw_module.time, "sleep", fake_sleep)

        class _ExitAfterIdleWorker(_TestWorker):
            def _claim_batch(self, session):
                # Register the call then stop — nothing to claim.
                self._claim_calls += 1
                self._running = False
                return []

        worker = _ExitAfterIdleWorker()
        worker.run_loop()

        # Either the sleep ran (we patched it to no-op) or the loop exited
        # before hitting the sleep line. The contract matters: no rows
        # were processed.
        assert worker.processed == []
        assert worker.persisted == []
        # sleeps captured the idle_poll_interval (0.0) at least once when
        # the empty-claim branch was taken.
        assert sleeps == [0.0]

    def test_unexpected_process_row_exception_is_swallowed(self, caplog):
        """``_process_row`` is contracted to never raise. The one here does
        anyway — the loop must log the exception and keep draining rather
        than leaving the row in 'processing' until stale recovery."""
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

        # Row 200 raised → not persisted. Row 201 persisted normally.
        assert [pid for pid, _ in worker.persisted] == [201]
        # The exception was logged (not re-raised) so ops can spot it.
        assert any("Unexpected error" in r.getMessage() for r in caplog.records)

    def test_stale_recovery_runs_on_poll_cadence(self):
        """With ``stale_recovery_every_n_polls=1``, every poll invokes the
        recovery pass. The counter is the only way to detect a stuck worker
        from another process — it must not be skipped on idle polls."""

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
        # Every poll triggers recovery when _every_n_polls is 1.
        assert worker._recover_calls == 2


# ---------------------------------------------------------------------------
# Constructor sanity — worker_id has the right shape.
# ---------------------------------------------------------------------------


def test_worker_id_contains_worker_name_and_pid():
    """Operators grep the logs for a worker_id to trace a row through the
    pipeline; a garbled prefix would break that workflow."""
    worker = _TestWorker()
    assert worker.worker_id.startswith("TestWorker-")
    # Shape: <name>-<pid>-<8hex>
    parts = worker.worker_id.split("-")
    assert len(parts) == 3
    assert parts[1].isdigit()
    assert len(parts[2]) == 8


# ---------------------------------------------------------------------------
# Timestamp shape sanity on the cutoff passed to stale recovery.
# ---------------------------------------------------------------------------


def test_recovery_cutoff_is_configured_seconds_in_past():
    """The ``cutoff`` passed to ``_stale_recovery_query`` must be exactly
    ``stale_processing_seconds`` before ``now``. Without this guarantee,
    a subclass could unintentionally reset rows that are still in flight."""
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


# ---------------------------------------------------------------------------
# Step 4: max_concurrent=8 tunable. Both AuditTextExtractionWorker and
# AuditScopeExtractionWorker default to 8 LLM/network-bound threads.
# ---------------------------------------------------------------------------


def test_audit_text_and_scope_default_to_max_concurrent_8(monkeypatch):
    """Both audit row workers default to max_concurrent=8 — bumped in Step 4
    so a single worker can saturate LLM/network bandwidth without oversizing
    the fleet."""
    # Clear the env so we read the in-code defaults, not whatever the dev box has.
    monkeypatch.delenv("PSAT_AUDIT_TEXT_CONCURRENCY", raising=False)
    monkeypatch.delenv("PSAT_AUDIT_SCOPE_CONCURRENCY", raising=False)
    import importlib

    import workers.audit_scope_extraction as scope_mod
    import workers.audit_text_extraction as text_mod

    importlib.reload(text_mod)
    importlib.reload(scope_mod)

    assert text_mod.AuditTextExtractionWorker.max_concurrent == 8
    assert scope_mod.AuditScopeExtractionWorker.max_concurrent == 8


def test_audit_concurrency_overridable_via_env(monkeypatch):
    """The ``PSAT_AUDIT_*_CONCURRENCY`` env vars override the in-code defaults
    so an operator can dial down a saturated pool without code changes."""
    monkeypatch.setenv("PSAT_AUDIT_TEXT_CONCURRENCY", "3")
    monkeypatch.setenv("PSAT_AUDIT_SCOPE_CONCURRENCY", "5")
    import importlib

    import workers.audit_scope_extraction as scope_mod
    import workers.audit_text_extraction as text_mod

    importlib.reload(text_mod)
    importlib.reload(scope_mod)

    assert text_mod.AuditTextExtractionWorker.max_concurrent == 3
    assert scope_mod.AuditScopeExtractionWorker.max_concurrent == 5
