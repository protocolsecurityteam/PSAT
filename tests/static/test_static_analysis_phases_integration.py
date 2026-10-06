"""The Slither CLI artifacts are gone; ``contract_analysis`` is what every downstream stage reads."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

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
    @pytest.mark.parametrize(
        "artifact_name, invalid",
        [(None, None)]
        + [
            (name, invalid)
            for name in ("predicate_trees", "effects")
            for invalid in (None, {}, {"error": "extraction failed"}, {"trees": [], "functions": []})
        ],
    )
    def test_stores_analysis_error_on_failure(self, monkeypatch, tmp_path, artifact_name, invalid):
        worker = StaticWorker()
        monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
        session = MagicMock()
        job = _job()

        def _raise(project_dir):
            if artifact_name is None:
                raise RuntimeError("extraction failed")
            trees = invalid if artifact_name == "predicate_trees" else {"trees": {}}
            effects = invalid if artifact_name == "effects" else {"functions": {}}
            return {"summary": {}}, trees, effects

        monkeypatch.setattr("workers.static_worker.collect_contract_analysis_with_artifacts", _raise)
        calls = _capture_store_artifact(monkeypatch)

        result = worker._run_analysis_phase(session, job, tmp_path, "TestContract", job.address)

        assert result is None
        assert len(calls) == 1
        assert calls[0]["name"] == "analysis_error"
        expected_error = (
            "extraction failed" if artifact_name is None else f"Incomplete static artifact: {artifact_name}"
        )
        assert expected_error in calls[0]["data"]["error"]
        assert not list(tmp_path.glob("*.json"))
