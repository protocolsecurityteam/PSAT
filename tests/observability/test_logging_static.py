"""Logging/observability locks for the static stage.

Covers the Wave-1 static instrumentation:

* the ``core.py`` semantic-emit swallows now WARNING + ``record_degraded``
  (no more ``logger.exception`` on a continue path), plus the
  ``secondary_impl_pointers`` count and the ``phase_ms_<phase>`` stage metrics;
* ``predicate_artifacts`` emits ``predicate_fns_attempted`` vs
  ``predicate_trees_built`` so a degraded/empty semantic artifact is chartable.

All offline: Slither and the per-phase analysis helpers are stubbed so nothing
touches the network or a real Foundry project.
"""

from __future__ import annotations

from types import SimpleNamespace

import services.static.static_analysis.core as core
from services.static.static_analysis.core import (
    _emit_pipeline_profile,
    collect_static_inputs,
)
from services.static.static_analysis.predicate_artifacts import (
    build_predicate_artifacts_with_pause_info,
)
from utils.logging import (
    bind_trace_context,
    degraded_errors_var,
    stage_metrics_var,
)


def test_emit_pipeline_profile_folds_phase_ms_metrics():
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        _emit_pipeline_profile(
            contract_name="C",
            external_fn_count=3,
            durations_ms={"slither_parse": 50, "predicate_trees": 200},
            total_ms=300,
        )
    finally:
        stage_metrics_var.reset(token)

    assert metrics["phase_ms_slither_parse"] == 50
    assert metrics["phase_ms_predicate_trees"] == 200
    assert metrics["static_facts_total_ms"] == 300


def test_predicate_artifacts_emits_attempted_and_built_metrics():
    # An empty contract: zero entry points -> zero attempted, zero trees built.
    # The metric pair must still be emitted so divergence is chartable.
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        artifact, _pause = build_predicate_artifacts_with_pause_info(
            SimpleNamespace(name="Empty", functions_entry_points=[])
        )
    finally:
        stage_metrics_var.reset(token)

    assert artifact["trees"] == {}
    assert metrics["predicate_fns_attempted"] == 0
    assert metrics["predicate_trees_built"] == 0


def _stub_analysis_phases(monkeypatch):
    """Stub everything past the Slither parse so the pipeline reaches the
    semantic-emit swallows without a real Foundry project."""
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
    """A raising semantic predicate build is swallowed as a degraded WARNING +
    ``record_degraded`` — never a ``logger.exception`` (ERROR) on the continue
    path — and the pipeline still produces an analysis dict with the
    ``secondary_impl_pointers`` + ``phase_ms`` stage metrics."""
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
                analysis, trees, _effects = collect_static_inputs(tmp_path)
    finally:
        stage_metrics_var.reset(met_token)
        degraded_errors_var.reset(deg_token)

    # Degraded recorded under the right phase, with the right severity/stage.
    phases = [e.phase for e in accumulator]
    assert "predicate_trees_emit" in phases
    emit = next(e for e in accumulator if e.phase == "predicate_trees_emit")
    assert emit.severity == "degraded"
    assert emit.stage == "static"
    assert emit.exc_type == "builtins.RuntimeError"

    # The swallow logged at WARNING (degraded-but-continuing), not ERROR.
    rec = next(r for r in caplog.records if r.getMessage().startswith("semantic predicate_trees emit failed"))
    assert rec.levelname == "WARNING"
    assert getattr(rec, "exc_type", None) == "RuntimeError"

    # Pipeline continued: degraded artifact + stage metrics still emitted.
    assert trees is not None and trees["error"]
    assert analysis["static_status"]["static_analysis_completed"] is True
    assert metrics["secondary_impl_pointers"] == 0
    assert any(k.startswith("phase_ms_") for k in metrics)


def test_unknown_parent_chain_reports_once_per_job(caplog):
    """The ``"ethereum"`` fallback is a wrong answer, not a missing one, so it
    warns + records degraded — once per job, though ``process()`` asks for the
    parent chain name from ~10 places."""
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

    # The next job reports again. The K=1 worker loop runs every job on the same
    # context, so the dedup has to key on the job row, not on contextvar state.
    deg_token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(trace_id="t", job_id="job-2", stage="static", worker_id="StaticWorker-1"):
            with caplog.at_level(logging.WARNING, logger="workers.static_worker"):
                static_worker._parent_chain_name(second)
    finally:
        degraded_errors_var.reset(deg_token)

    assert len(_warnings()) == 2
    assert len([e for e in accumulator if e.phase == "parent_chain_name"]) == 2
