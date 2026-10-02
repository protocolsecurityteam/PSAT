from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

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
