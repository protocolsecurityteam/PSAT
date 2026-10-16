"""The Slither CLI artifacts are gone; ``contract_analysis`` is what every downstream stage reads."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from workers.static_worker import StaticWorker


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
    calls: list[dict] = []

    def _fake_store(_session, _job_id, name, data=None, text_data=None):
        calls.append({"name": name, "data": data, "text_data": text_data})

    monkeypatch.setattr("workers.static_worker.store_artifact", _fake_store)
    return calls


class TestAnalysisPhaseSuccess:
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


class TestAnalysisPhaseFailure:
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


class TestAnalysisPhaseBudget:
    def test_runs_the_pipeline_in_a_child_under_the_static_budget(self, monkeypatch, tmp_path):
        from services.compute_isolation import static_budget

        worker = StaticWorker()
        monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
        monkeypatch.setattr(worker, "_write_analysis_tables", lambda *a, **kw: None)
        _capture_store_artifact(monkeypatch)
        seen: dict = {}

        def fake_run_isolated(fn, *args, budget, label, **kwargs):
            seen.update(fn=fn, args=args, budget=budget, label=label)
            return {"schema_version": "0.1", "subject": {"name": "T"}}, None, None

        monkeypatch.setattr("workers.static_worker.run_isolated", fake_run_isolated)
        worker._run_analysis_phase(MagicMock(), _job(), tmp_path, "TestContract", "0xabc")
        from workers import static_worker

        assert seen["fn"] is static_worker.collect_contract_analysis_with_artifacts
        assert seen["args"] == (tmp_path,)
        assert seen["budget"] == static_budget()
        assert seen["label"] == "static_analysis"

    def test_an_overrun_is_the_jobs_outcome_not_an_analysis_error(self, monkeypatch, tmp_path):
        import pytest

        from services.compute_isolation import ResourceExhausted

        worker = StaticWorker()
        monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
        calls = _capture_store_artifact(monkeypatch)

        def overrun(*_args, **_kwargs):
            raise ResourceExhausted("static_analysis", "memory", 5e9, 3e9)

        monkeypatch.setattr("workers.static_worker.run_isolated", overrun)
        with pytest.raises(ResourceExhausted):
            worker._run_analysis_phase(MagicMock(), _job(), tmp_path, "TestContract", "0xabc")
        assert calls == []
