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

from utils.logging import (
    bind_trace_context,
    degraded_errors_var,
    stage_metrics_var,
)
from workers.policy_worker import PolicyWorker

TARGET_ADDRESS = "0x1111111111111111111111111111111111111111"


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

    contract_analysis = {
        "contract_address": TARGET_ADDRESS,
        "contract_name": "TestContract",
        "functions": [],
    }
    # A non-empty controller_values + dict graph drives _resolve_authority.
    control_snapshot = {
        "contract_address": TARGET_ADDRESS,
        "controller_values": {"some_key:admin": {"value": "0xbbb"}},
    }
    resolved_graph = {"nodes": [], "edges": []}
    tracking_plan = {
        "schema_version": "0.1",
        "contract_address": TARGET_ADDRESS,
        "contract_name": "TestContract",
    }

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
        lambda self, session, job, contract_analysis, control_snapshot: {},
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
