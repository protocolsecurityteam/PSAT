from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from tests.conftest import requires_postgres
from workers.static_worker import StaticWorker


def _job(**overrides):
    payload = {
        "id": "job-1",
        "address": "0x1111111111111111111111111111111111111111",
        "name": "HiddenThing",
        "request": {"rpc_url": "http://127.0.0.1:8545"},
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def test_resolve_proxy_queues_hidden_proxy_impl(monkeypatch):
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    store_calls = []
    created_jobs = []

    monkeypatch.setattr(
        "workers.static_worker.store_artifact",
        lambda _session, _job_id, name, data=None, text_data=None: store_calls.append((name, data, text_data)),
    )
    monkeypatch.setattr(
        "workers.static_worker.create_job",
        lambda _session, request: created_jobs.append(request) or SimpleNamespace(id="child-1"),
    )
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "address": address,
            "type": "proxy",
            "proxy_type": "unknown",
            "implementation": "0x2222222222222222222222222222222222222222",
        },
    )

    worker._resolve_proxy(session, job, job.address, job.name)

    assert store_calls[0][0] == "contract_flags"
    assert store_calls[0][1]["is_proxy"] is True
    assert store_calls[0][1]["implementation"] == "0x2222222222222222222222222222222222222222"

    assert len(created_jobs) == 1
    child = created_jobs[0]
    assert child["address"] == "0x2222222222222222222222222222222222222222"
    assert child["proxy_address"] == "0x1111111111111111111111111111111111111111"
    assert child["parent_job_id"] == "job-1"
    # Keeps within-cascade dedup for top-level calls.
    assert child["root_job_id"] == "job-1"
    assert child["discovery_relationship"] == "implementation"
    # No parent Contract row in this mock.
    assert child["parent_is_member"] is False
    assert child["chain"] == "ethereum"


@pytest.mark.parametrize("subject_kind", [None, "library", "interface"])
def test_process_attempts_semantic_proxy_classification_for_non_obvious_names(monkeypatch, tmp_path, subject_kind):
    monkeypatch.setattr("workers.static_worker.get_artifact", lambda *_args: None)
    worker = StaticWorker()
    session = MagicMock()
    mock_contract = MagicMock()
    mock_contract.contract_name = "OssifiableProxy"
    mock_contract.address = "0x1111111111111111111111111111111111111111"
    mock_contract.compiler_version = "v0.8.0"
    mock_contract.language = "solidity"
    mock_contract.evm_version = "shanghai"
    mock_contract.source_format = "flat"
    mock_contract.source_file_count = 1
    mock_contract.remappings = []
    mock_contract.optimization = False
    mock_contract.optimization_runs = 200
    mock_contract.is_proxy = False
    session.execute.return_value.scalar_one_or_none.return_value = mock_contract

    job = _job(name="OssifiableProxy", lease_id=None)
    called = []

    monkeypatch.setattr(
        "workers.static_worker.get_source_files",
        lambda _session, _job_id: {"contracts/OssifiableProxy.sol": "contract OssifiableProxy {}"},
    )
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *_args: called.append("resolve"))
    monkeypatch.setattr(worker, "_scaffold_project", lambda *args, **kwargs: None)
    monkeypatch.setattr(worker, "_run_dependency_phase", lambda *args, **kwargs: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *args, **kwargs: {"subject": {"kind": subject_kind}})
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *args, **kwargs: None)
    monkeypatch.setattr(worker, "update_detail", lambda *args, **kwargs: None)

    if subject_kind:
        from db.models import JobStage
        from workers.base import JobHandledDirectly

        monkeypatch.setattr(worker, "_satisfy_dependencies", lambda *a, **k: called.append("static-ready"))
        monkeypatch.setattr(worker, "_degrade_dependencies", lambda *a, **k: called.append("policy-unavailable"))
        monkeypatch.setattr(
            "services.policy.effective_permissions_writer.write_effective_function_rows",
            lambda *a, **k: called.append("clear-policy") if k["function_records"] == [] else None,
        )
        monkeypatch.setattr("db.queue.advance_job", lambda s, jid, stage, *a, **k: called.append(stage))
        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))
        assert called == ["resolve", "clear-policy", "static-ready", "policy-unavailable", JobStage.coverage]
        return
    worker.process(session, cast(Any, job))

    assert called == ["resolve"]


def test_force_dedupes_impl_jobs_within_same_root_cascade(monkeypatch):
    worker = StaticWorker()
    session = MagicMock()

    # Calls 1+2 are the first proxy, 3+4 the second; only call 4 hits a prior job.
    existing_in_cascade = SimpleNamespace(id="prior-impl-in-same-cascade")
    call_count = {"n": 0}

    def _fake_execute(query, *params):
        if params:
            return MagicMock()
        call_count["n"] += 1
        result = MagicMock()
        result.scalar_one_or_none.return_value = existing_in_cascade if call_count["n"] >= 4 else None
        return result

    session.execute.side_effect = _fake_execute

    created_jobs: list[dict] = []
    monkeypatch.setattr(
        "workers.static_worker.create_job",
        lambda _session, request: created_jobs.append(request) or SimpleNamespace(id=f"child-{len(created_jobs)}"),
    )
    monkeypatch.setattr(
        "workers.static_worker.store_artifact",
        lambda *_a, **_kw: None,
    )
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "address": address,
            "type": "proxy",
            "proxy_type": "uups",
            "implementation": "0x" + "33" * 20,
        },
    )

    job1 = _job(
        id="proxy-job-A",
        request={"rpc_url": "https://rpc", "force": True, "root_job_id": "root-1", "chain_id": 1},
    )
    job2 = _job(
        id="proxy-job-B",
        request={"rpc_url": "https://rpc", "force": True, "root_job_id": "root-1", "chain_id": 1},
    )

    worker._resolve_proxy(session, job1, job1.address, job1.name)
    worker._resolve_proxy(session, job2, job2.address, job2.name)

    assert len(created_jobs) == 1, f"second proxy in same cascade must dedupe its impl; got {len(created_jobs)} jobs"
    assert created_jobs[0]["root_job_id"] == "root-1"


def test_force_does_not_dedupe_across_different_root_cascades(monkeypatch):
    """Bench A/B runs need cold-path measurements per root."""
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None

    created_jobs: list[dict] = []
    monkeypatch.setattr(
        "workers.static_worker.create_job",
        lambda _session, request: created_jobs.append(request) or SimpleNamespace(id=f"child-{len(created_jobs)}"),
    )
    monkeypatch.setattr(
        "workers.static_worker.store_artifact",
        lambda *_a, **_kw: None,
    )
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "address": address,
            "type": "proxy",
            "proxy_type": "uups",
            "implementation": "0x" + "44" * 20,
        },
    )

    job_root_a = _job(
        id="proxy-A",
        request={"rpc_url": "https://rpc", "force": True, "root_job_id": "root-A", "chain_id": 1},
    )
    job_root_b = _job(
        id="proxy-B",
        request={"rpc_url": "https://rpc", "force": True, "root_job_id": "root-B", "chain_id": 1},
    )

    worker._resolve_proxy(session, job_root_a, job_root_a.address, job_root_a.name)
    worker._resolve_proxy(session, job_root_b, job_root_b.address, job_root_b.name)

    assert len(created_jobs) == 2, "fresh cascades must each get their own impl job"
    assert {j["root_job_id"] for j in created_jobs} == {"root-A", "root-B"}


def test_no_force_uses_global_dedupe(monkeypatch):
    worker = StaticWorker()
    session = MagicMock()
    prior = SimpleNamespace(id="prior-impl-from-other-cascade")
    session.execute.return_value.scalar_one_or_none.return_value = prior

    created_jobs: list[dict] = []
    monkeypatch.setattr(
        "workers.static_worker.create_job",
        lambda _session, request: created_jobs.append(request) or SimpleNamespace(id="should-not-be-created"),
    )
    monkeypatch.setattr(
        "workers.static_worker.store_artifact",
        lambda *_a, **_kw: None,
    )
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "address": address,
            "type": "proxy",
            "proxy_type": "uups",
            "implementation": "0x" + "55" * 20,
        },
    )

    job = _job(request={"rpc_url": "https://rpc"})  # no force
    worker._resolve_proxy(session, job, job.address, job.name)

    assert created_jobs == [], "global dedupe must reject this impl when prior job exists"


@requires_postgres
def test_load_contract_row_falls_back_to_address_when_job_id_rebound(db_session):
    """Live-tests USDC failure (run #25828735277): concurrent cascades rebind the Contract row's ``job_id``
    (``workers/discovery.py:402``).
    """
    from db.models import Contract, Job, JobStage, JobStatus

    chain = "ethereum"
    addr = "0x" + uuid.uuid4().hex[:40]
    now = datetime.now(timezone.utc)

    job_a = Job(
        id=uuid.uuid4(),
        address=addr,
        status=JobStatus.queued,
        stage=JobStage.static,
        request={"address": addr, "chain": chain},
        created_at=now,
        updated_at=now,
    )
    job_b = Job(
        id=uuid.uuid4(),
        address=addr,
        status=JobStatus.queued,
        stage=JobStage.static,
        request={"address": addr, "chain": chain},
        created_at=now,
        updated_at=now,
    )
    db_session.add_all([job_a, job_b])
    db_session.commit()

    contract = Contract(address=addr, chain=chain, job_id=job_a.id, contract_name="Vault")
    db_session.add(contract)
    db_session.commit()
    contract.job_id = job_b.id
    db_session.commit()

    row_for_a = StaticWorker._load_contract_row(db_session, job_a)
    assert row_for_a is not None, "address fallback must locate the orphaned Contract row"
    assert row_for_a.id == contract.id

    row_for_b = StaticWorker._load_contract_row(db_session, job_b)
    assert row_for_b is not None
    assert row_for_b.id == contract.id
