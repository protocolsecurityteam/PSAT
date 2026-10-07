"""Semantic-emit swallows are WARNING + ``record_degraded``, and ``predicate_fns_attempted`` vs
``predicate_trees_built`` makes an empty semantic artifact chartable.
"""

from __future__ import annotations

from types import SimpleNamespace

import services.static.contract_analysis_pipeline.core as core
from services.static.contract_analysis_pipeline.core import (
    collect_contract_analysis_with_artifacts,
)
from utils.logging import (
    bind_trace_context,
    degraded_errors_var,
    stage_metrics_var,
)


def _stub_analysis_phases(monkeypatch):
    subject = SimpleNamespace(name="C", functions=[])
    monkeypatch.setattr(core, "Slither", lambda _target: object())
    monkeypatch.setattr(core, "_select_subject_contract", lambda *_a, **_k: subject)
    monkeypatch.setattr(core, "build_effects", lambda *_a, **_k: {})
    monkeypatch.setattr(
        core,
        "_detect_contract_classification",
        lambda *_a, **_k: {
            "standards": [],
            "is_factory": False,
            "is_nft": False,
        },
    )
    monkeypatch.setattr(core, "_build_semantic_control_summary", lambda *_a, **_k: {"role_definitions": []})
    monkeypatch.setattr(core, "build_controller_tracking", lambda *_a, **_k: {})
    monkeypatch.setattr(core, "_detect_upgradeability", lambda *_a, **_k: {"is_upgradeable": False})
    monkeypatch.setattr(core, "_detect_pausability", lambda *_a, **_k: {"is_pausable": False})
    monkeypatch.setattr(core, "_detect_timelock", lambda *_a, **_k: {"has_timelock": False})
    monkeypatch.setattr(core, "_determine_control_model", lambda *_a, **_k: "unknown")
    monkeypatch.setattr(core, "_build_tracking_hints", lambda *_a, **_k: {})
    return subject


def test_core_predicate_emit_failure_records_degraded_not_exception(monkeypatch, tmp_path, caplog):
    _stub_analysis_phases(monkeypatch)

    def _boom(_contract):
        raise RuntimeError("predicate IR-gen exploded")

    monkeypatch.setattr(core, "build_predicate_artifacts_with_pause_info", _boom)
    monkeypatch.setattr(core, "detect_secondary_impl_pointers", lambda *_a, **_k: [])

    accumulator: list = []
    metrics: dict = {}
    deg_token = degraded_errors_var.set(accumulator)
    met_token = stage_metrics_var.set(metrics)
    try:
        with bind_trace_context(trace_id="t", job_id="j", stage="static", worker_id="StaticWorker-1"):
            with caplog.at_level("WARNING"):
                analysis, trees, _effects = collect_contract_analysis_with_artifacts(tmp_path)
    finally:
        stage_metrics_var.reset(met_token)
        degraded_errors_var.reset(deg_token)

    phases = [e.phase for e in accumulator]
    assert "predicate_trees_emit" in phases
    emit = next(e for e in accumulator if e.phase == "predicate_trees_emit")
    assert emit.severity == "degraded"
    assert emit.stage == "static"
    assert emit.exc_type == "builtins.RuntimeError"

    rec = next(r for r in caplog.records if r.getMessage().startswith("semantic predicate_trees emit failed"))
    assert rec.levelname == "WARNING"
    assert getattr(rec, "exc_type", None) == "RuntimeError"

    assert trees is not None and trees["error"]
    # The failure is recorded on the analysis too, so it is never reused as a complete one (#113).
    assert analysis["analysis_status"]["static_analysis_completed"] is False
    assert analysis["analysis_status"]["errors"] == ["predicate_trees_emit: RuntimeError: predicate IR-gen exploded"]
    assert metrics["secondary_impl_pointers"] == 0
    assert any(k.startswith("phase_ms_") for k in metrics)


def test_unknown_parent_chain_reports_once_per_job(caplog):
    """The ``"ethereum"`` fallback is a wrong answer, reported once per job though ``process()`` asks ~10 times."""
    import logging
    from typing import Any, cast

    from workers import static_worker

    def _job(job_id: str) -> Any:
        return cast(Any, SimpleNamespace(id=job_id, chain_id=987654, address="0x" + "11" * 20, request={}))

    def _warnings() -> list:
        return [r for r in caplog.records if r.levelno == logging.WARNING and "Unknown chain_id" in r.getMessage()]

    first, second = _job("job-1"), _job("job-2")
    accumulator: list = []
    deg_token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(trace_id="t", job_id="job-1", stage="static", worker_id="StaticWorker-1"):
            with caplog.at_level(logging.WARNING, logger="workers.static_worker"):
                names = [static_worker._parent_chain_name(first) for _ in range(3)]
    finally:
        degraded_errors_var.reset(deg_token)

    assert names == ["ethereum", "ethereum", "ethereum"]
    assert len(_warnings()) == 1
    assert getattr(_warnings()[0], "chain_id", None) == 987654

    entries = [e for e in accumulator if e.phase == "parent_chain_name"]
    assert len(entries) == 1
    assert entries[0].severity == "degraded"

    # The K=1 worker loop reuses one context, so the dedup keys on the job row.
    deg_token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(trace_id="t", job_id="job-2", stage="static", worker_id="StaticWorker-1"):
            with caplog.at_level(logging.WARNING, logger="workers.static_worker"):
                static_worker._parent_chain_name(second)
    finally:
        degraded_errors_var.reset(deg_token)

    assert len(_warnings()) == 2
    assert len([e for e in accumulator if e.phase == "parent_chain_name"]) == 2
