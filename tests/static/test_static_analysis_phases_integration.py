"""Integration tests for StaticWorker._run_analysis_phase.

The Slither CLI subprocess + its slither_results / analysis_report
artifacts were removed when vulnerability-detector triage was split
out of PSAT's cascade pipeline. The structured ``contract_analysis``
artifact (built from Slither's Python IR) is what every downstream
stage reads, so its phase is the only one with integration coverage
here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workers.static_worker import StaticWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _job(**overrides):
    payload = {
        "id": "job-1",
        "address": "0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
        "name": "TestContract",
        "request": {"rpc_url": "https://rpc.example"},
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def _capture_store_artifact(monkeypatch):
    """Patch store_artifact and return a list that collects all calls."""
    calls: list[dict] = []

    def _fake_store(_session, _job_id, name, data=None, text_data=None):
        calls.append({"name": name, "data": data, "text_data": text_data})

    monkeypatch.setattr("workers.static_worker.store_artifact", _fake_store)
    return calls


# ---------------------------------------------------------------------------
# _run_analysis_phase
# ---------------------------------------------------------------------------


class TestAnalysisPhaseSuccess:
    """Mock collect_contract_analysis() to return a dict; verify artifact is stored."""

    def test_stores_contract_analysis_artifact(self, monkeypatch, tmp_path):
        worker = StaticWorker()
        monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
        monkeypatch.setattr(worker, "_write_analysis_tables", lambda *a, **kw: None)
        session = MagicMock()
        job = _job()

        analysis_data = {
            "schema_version": "0.1",
            "subject": {"name": "TestContract"},
            "summary": {"control_model": "ownable"},
        }
        predicate_trees = {"schema_version": "semantic", "trees": {}}
        effects = {"schema_version": "semantic", "functions": {}}

        monkeypatch.setattr(
            "workers.static_worker.collect_contract_analysis_with_artifacts",
            lambda project_dir: (analysis_data, predicate_trees, effects),
        )
        calls = _capture_store_artifact(monkeypatch)

        result = worker._run_analysis_phase(session, job, tmp_path, "TestContract", job.address)

        assert result == analysis_data
        names = [call["name"] for call in calls]
        assert names == ["contract_analysis", "predicate_trees", "effects"]
        assert calls[0]["data"] == analysis_data
        assert calls[1]["data"] == predicate_trees
        assert calls[2]["data"] == effects

    def test_stores_predicate_trees_and_effects_side_artifacts(self, monkeypatch, tmp_path):
        worker = StaticWorker()
        monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
        monkeypatch.setattr(worker, "_write_analysis_tables", lambda *a, **kw: None)
        session = MagicMock()
        job = _job()

        analysis_data = {
            "schema_version": "0.1",
            "subject": {"name": "TestContract"},
            "summary": {"control_model": "ownable"},
        }
        predicate_trees = {"schema_version": "semantic", "trees": {}}
        effects = {"schema_version": "semantic", "functions": {}}
        analysis_path = tmp_path / "contract_analysis.json"
        analysis_path.write_text(json.dumps(analysis_data))

        monkeypatch.setattr(
            "workers.static_worker.collect_contract_analysis_with_artifacts",
            lambda project_dir: (analysis_data, predicate_trees, effects),
        )
        calls = _capture_store_artifact(monkeypatch)

        result = worker._run_analysis_phase(session, job, tmp_path, "TestContract", job.address)

        assert result == analysis_data
        assert [call["name"] for call in calls] == ["contract_analysis", "predicate_trees", "effects"]

    def test_skips_predicate_trees_for_vyper(self, monkeypatch, tmp_path):
        """Vyper projects return ``None`` for predicate_trees + effects;
        only contract_analysis is stored."""
        worker = StaticWorker()
        monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
        monkeypatch.setattr(worker, "_write_analysis_tables", lambda *a, **kw: None)
        session = MagicMock()
        job = _job()

        monkeypatch.setattr(
            "workers.static_worker.collect_contract_analysis_with_artifacts",
            lambda project_dir: ({"schema_version": "0.1"}, None, None),
        )
        calls = _capture_store_artifact(monkeypatch)

        result = worker._run_analysis_phase(session, job, tmp_path, "TestContract", job.address)

        assert result == {"schema_version": "0.1"}
        assert [call["name"] for call in calls] == ["contract_analysis"]


class TestAnalysisPhaseFailure:
    """Mock ``collect_contract_analysis_with_artifacts()`` to raise;
    verify error artifact and return value."""

    def test_stores_analysis_error_on_exception(self, monkeypatch, tmp_path):
        worker = StaticWorker()
        monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
        session = MagicMock()
        job = _job()

        def _raise(project_dir):
            raise RuntimeError("LLM analysis timed out")

        monkeypatch.setattr("workers.static_worker.collect_contract_analysis_with_artifacts", _raise)
        calls = _capture_store_artifact(monkeypatch)

        result = worker._run_analysis_phase(session, job, tmp_path, "TestContract", job.address)

        assert result is None
        assert len(calls) == 1
        assert calls[0]["name"] == "analysis_error"
        assert "LLM analysis timed out" in calls[0]["data"]["error"]

    def test_stores_analysis_error_on_generic_exception(self, monkeypatch, tmp_path):
        worker = StaticWorker()
        monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
        session = MagicMock()
        job = _job()

        def _raise(project_dir):
            raise ValueError("bad json from model")

        monkeypatch.setattr("workers.static_worker.collect_contract_analysis_with_artifacts", _raise)
        calls = _capture_store_artifact(monkeypatch)

        result = worker._run_analysis_phase(session, job, tmp_path, "TestContract", job.address)

        assert result is None
        assert calls[0]["name"] == "analysis_error"
        assert "bad json from model" in calls[0]["data"]["error"]
