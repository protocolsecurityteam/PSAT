"""Observability locks for the policy stage.

Covers the logging/observability behaviour added to ``workers/policy_worker.py``:

* The explicit zero-write path — when no ``Contract`` row exists for the job,
  the stage emits a WARNING, ``record_degraded(phase='policy_db_write')``, and
  ``record_stage_metric('rows_written', False)`` instead of silently writing
  nothing (DB and artifacts disagreeing with a green job).
* The authority-resolution line puts ``authority_status`` / ``authority_reason``
  into ``extra={}`` and folds an ``authority_status`` stage metric.
* The phase timers (formerly the bespoke ``_log_policy_phase``) fold
  ``phase_ms_<phase>`` metrics via the canonical ``log_timed_phase``.
* Materialization hydration tells a DB error apart from a row miss: the error
  path rolls the session back, warns, and records degraded; the miss stays
  silent.

Offline: ``process()`` is driven with all DB/RPC collaborators stubbed; the
``MagicMock`` session's ``scalar_one_or_none`` returns ``None`` so ``contract_row``
is missing, which is exactly the zero-write scenario.
"""

from __future__ import annotations

import logging
import uuid
from types import SimpleNamespace
from typing import Any, cast

import pytest

from tests.support.policy_builders import (
    TARGET_ADDRESS,
    _graph_with_nodes,
    _minimal_contract_analysis,
    _minimal_snapshot,
    _tracking_plan,
)
from utils.logging import (
    bind_trace_context,
    degraded_errors_var,
    stage_metrics_var,
)
from workers.policy_worker import PolicyWorker


class _RecordCollector(logging.Handler):
    """Collect emitted records directly off the module logger.

    The worker calls ``configure_logging()`` at BOOT, which reconfigures the
    root logger and can drop pytest's ``caplog`` handler. Attaching our own
    handler to ``workers.policy_worker`` is immune to that reconfiguration.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _job(**overrides: Any) -> SimpleNamespace:
    payload: dict[str, Any] = {
        "id": uuid.uuid4(),
        "address": TARGET_ADDRESS,
        "name": "TestContract",
        "company": None,
        "protocol_id": None,
        "request": {"rpc_url": "https://rpc.example", "chain_id": 1},
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def _drive_process_with_missing_contract_row(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Run ``PolicyWorker.process`` with every collaborator stubbed and no
    ``Contract`` row, returning the (mock) session for assertions."""
    from unittest.mock import MagicMock

    worker = PolicyWorker()
    session = MagicMock()
    # No Contract row for this job -> the zero-write path.
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    contract_analysis = _minimal_contract_analysis()
    # A non-empty controller_values + dict graph drives _resolve_authority.
    control_snapshot = _minimal_snapshot({"some_key:admin": {"value": "0xbbb"}})
    resolved_graph = _graph_with_nodes([])
    tracking_plan = _tracking_plan()

    def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
        return {
            "contract_analysis": contract_analysis,
            "control_snapshot": control_snapshot,
            "resolved_control_graph": resolved_graph,
            "control_tracking_plan": tracking_plan,
        }.get(name)

    monkeypatch.setattr("workers.policy_worker.get_artifact", fake_get_artifact)
    monkeypatch.setattr("workers.policy_worker.store_artifact", lambda *a, **kw: None)
    monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *_a, **_kw: {})
    monkeypatch.setattr(
        "workers.policy_worker.build_effective_permissions",
        lambda *a, **kw: {"schema_version": "1", "functions": []},
    )
    monkeypatch.setattr(
        "workers.policy_worker.resolve_control_graph",
        lambda **kw: ({"nodes": [], "edges": []}, {}),
    )
    monkeypatch.setattr(
        "workers.policy_worker.build_principal_labels",
        lambda *a, **kw: {"principals": []},
    )
    monkeypatch.setattr(
        PolicyWorker,
        "_enrich_cross_contract",
        lambda self, session, job, contract_analysis, control_snapshot, **kw: {},
    )

    worker.process(session, cast(Any, job))
    return session


def _run_capturing(monkeypatch: pytest.MonkeyPatch) -> tuple[list, dict[str, Any], list[logging.LogRecord]]:
    degraded: list = []
    metrics: dict[str, Any] = {}
    collector = _RecordCollector()
    module_logger = logging.getLogger("workers.policy_worker")
    module_logger.addHandler(collector)

    dtoken = degraded_errors_var.set(degraded)
    mtoken = stage_metrics_var.set(metrics)
    try:
        with bind_trace_context(
            trace_id="trace-policy",
            job_id="job-policy",
            stage="policy",
            worker_id="PolicyWorker-1",
        ):
            _drive_process_with_missing_contract_row(monkeypatch)
    finally:
        stage_metrics_var.reset(mtoken)
        degraded_errors_var.reset(dtoken)
        module_logger.removeHandler(collector)
    return degraded, metrics, collector.records


def test_zero_write_path_degrades_and_records_metric(monkeypatch: pytest.MonkeyPatch) -> None:
    degraded, metrics, records = _run_capturing(monkeypatch)

    # #5: the missing-Contract-row zero-write path is now explicit.
    assert metrics["rows_written"] is False
    db_write_degraded = [e for e in degraded if e.phase == "policy_db_write"]
    assert len(db_write_degraded) == 1
    assert db_write_degraded[0].severity == "degraded"

    warnings = [r for r in records if r.levelno == logging.WARNING and "wrote zero DB rows" in r.getMessage()]
    assert len(warnings) == 1
    # The address is a queryable field, not only in the message text.
    assert getattr(warnings[0], "address", None) == TARGET_ADDRESS


def test_authority_status_in_extra_and_metric(monkeypatch: pytest.MonkeyPatch) -> None:
    _degraded, metrics, records = _run_capturing(monkeypatch)

    # #16-policy: authority status is a metric + an extra field, not %s text.
    assert metrics["authority_status"] == "no_authority"

    auth_lines = [r for r in records if "authority resolution complete" in r.getMessage()]
    assert len(auth_lines) == 1
    assert getattr(auth_lines[0], "authority_status", None) == "no_authority"
    assert getattr(auth_lines[0], "authority_reason", None)

    # #16-policy: phase timers fold phase_ms_<phase> via log_timed_phase.
    assert "phase_ms_effective_permissions" in metrics
    assert "phase_ms_principal_labels" in metrics


def _drive_hydration(monkeypatch: pytest.MonkeyPatch, *, raises: bool) -> tuple[Any, list, list[logging.LogRecord]]:
    """Drive ``_load_nested_artifacts`` over one nested bundle whose
    ``contract_materializations`` lookup either raises or misses."""
    from unittest.mock import MagicMock

    from db.nested_artifacts import artifact_key
    from workers import policy_worker

    row = SimpleNamespace(name=artifact_key(TARGET_ADDRESS, "snapshot"))
    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = [row]

    monkeypatch.setattr(policy_worker, "get_artifact", lambda *_a, **_kw: {"contract_address": TARGET_ADDRESS})

    def _lookup(_session: Any, *, chain: str, address: str) -> Any:
        if raises:
            raise RuntimeError("connection reset")
        return None

    monkeypatch.setattr("db.contract_materializations.find_by_address", _lookup)

    collector = _RecordCollector()
    module_logger = logging.getLogger("workers.policy_worker")
    module_logger.addHandler(collector)
    degraded: list = []
    dtoken = degraded_errors_var.set(degraded)
    try:
        with bind_trace_context(trace_id="t", job_id="j", stage="policy", worker_id="PolicyWorker-1"):
            policy_worker._load_nested_artifacts(session, "job-1", chain="ethereum")
    finally:
        degraded_errors_var.reset(dtoken)
        module_logger.removeHandler(collector)
    return session, degraded, collector.records


def test_hydration_db_error_warns_and_rolls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    session, degraded, records = _drive_hydration(monkeypatch, raises=True)

    warnings = [
        r for r in records if r.levelno == logging.WARNING and "Materialization hydration failed" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert getattr(warnings[0], "exc_type", None) == "RuntimeError"
    # ``bundle_address``, not ``address``: JsonFormatter drops an extra whose
    # key collides with a bound context field (the job's own address).
    assert getattr(warnings[0], "bundle_address", None) == TARGET_ADDRESS
    assert getattr(warnings[0], "bundle_chain", None) == "ethereum"

    hydration = [e for e in degraded if e.phase == "nested_artifact_hydration"]
    assert len(hydration) == 1
    assert hydration[0].severity == "degraded"

    # A failed query leaves the session pending-rollback; the handler clears it.
    assert session.rollback.called


def test_hydration_row_miss_stays_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    session, degraded, records = _drive_hydration(monkeypatch, raises=False)

    assert [r for r in records if r.levelno >= logging.WARNING] == []
    assert degraded == []
    assert not session.rollback.called


def test_principal_classification_failures_collect_per_contract() -> None:
    """D5: resolver crashes are collected so the writer can report them once
    per contract rather than once per principal."""
    from services.policy import effective_permissions_writer as writer

    memo: dict[str, Any] = {}
    failures: list[BaseException] = []

    def _boom(_address: str) -> Any:
        raise RuntimeError("classifier down")

    for addr in ("0xaaa", "0xbbb", "0xAAA"):
        assert writer._classify_principal(addr, _boom, memo, failures=failures) == (None, None)

    # The memo collapses the repeat: two distinct addresses, two failures.
    assert len(failures) == 2
