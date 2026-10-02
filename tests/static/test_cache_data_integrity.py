from __future__ import annotations

import pytest

from tests.cache_helpers import (
    ADDR_A,
    IMPL_ADDR,
    _sqlite_compatible_store_artifact,
    db_session,  # noqa: F401
    requires_postgres,
)

pytestmark = requires_postgres


@pytest.fixture()
def api_client(db_session, monkeypatch):

    class _FakeSessionCtx:
        def __init__(self):
            pass

        def __enter__(self):
            return db_session

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("routers.deps.SessionLocal", _FakeSessionCtx)

    from fastapi.testclient import TestClient

    import api as api_module

    return TestClient(api_module.app)


def _setup_company_with_proxy(db_session, monkeypatch):
    from db.models import (
        Contract,
        ContractSummary,
        ControllerValue,
        JobStage,
        JobStatus,
        Protocol,
    )
    from db.queue import copy_static_cache, create_job

    store = _sqlite_compatible_store_artifact

    protocol = Protocol(name="TestProtocol")
    db_session.add(protocol)
    db_session.flush()

    old_job = create_job(
        db_session,
        {
            "address": ADDR_A,
            "name": "OldProxy",
            "chain": "ethereum",
            "company": "TestProtocol",
        },
    )
    old_job.status = JobStatus.completed
    old_job.stage = JobStage.done
    old_job.protocol_id = protocol.id
    old_job.company = "TestProtocol"
    db_session.commit()

    contract = Contract(
        job_id=old_job.id,
        address=ADDR_A.lower(),
        chain="ethereum",
        protocol_id=protocol.id,
        contract_name="ProxyContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
    )
    db_session.add(contract)
    db_session.flush()

    db_session.add(
        ContractSummary(
            contract_id=contract.id,
            control_model="proxy",
            is_upgradeable=True,
        )
    )

    db_session.add(
        ControllerValue(
            contract_id=contract.id,
            controller_id="owner",
            value="0x0000000000000000000000000000000000000001",
            resolved_type="eoa",
        )
    )
    db_session.commit()

    from db.queue import store_source_files

    store_source_files(
        db_session,
        old_job.id,
        {
            "src/Proxy.sol": "contract Proxy {}",
        },
    )
    store(
        db_session,
        old_job.id,
        "contract_analysis",
        data={
            "subject": {"name": "ProxyContract", "address": ADDR_A},
            "summary": {"control_model": "proxy"},
        },
    )
    store(db_session, old_job.id, "slither_results", data={"results": {}})
    store(db_session, old_job.id, "analysis_report", text_data="report")
    store(db_session, old_job.id, "control_tracking_plan", data={"controllers": []})
    store(
        db_session,
        old_job.id,
        "contract_flags",
        data={
            "is_proxy": True,
            "proxy_type": "eip1967",
            "implementation": IMPL_ADDR,
        },
    )

    new_job = create_job(
        db_session,
        {
            "address": ADDR_A,
            "name": "NewProxy",
            "chain": "ethereum",
            "static_cached": True,
            "cache_source_job_id": str(old_job.id),
        },
    )
    new_job.protocol_id = protocol.id
    db_session.commit()

    copy_static_cache(db_session, old_job.id, new_job.id)

    return old_job, new_job, protocol


def test_api_company_returns_data_for_old_proxy_job(db_session, api_client, monkeypatch):
    old_job, new_job, protocol = _setup_company_with_proxy(db_session, monkeypatch)

    from db.models import JobStage, JobStatus

    new_job.status = JobStatus.completed
    new_job.stage = JobStage.done
    new_job.company = "TestProtocol"
    db_session.commit()

    resp = api_client.get(f"/api/company/{protocol.name}")
    assert resp.status_code == 200
    data = resp.json()
    contracts = data.get("contracts", [])

    proxy_contract = next(
        (c for c in contracts if (c.get("address") or "").lower() == ADDR_A.lower()),
        None,
    )
    assert proxy_contract is not None, (
        f"Expected contract {ADDR_A} in company response, got addresses: {[c.get('address') for c in contracts]}"
    )
    assert proxy_contract.get("control_model") is not None, "control_model should not be None — Contract data was lost"
    assert proxy_contract.get("summary_evidence") == "present", "the ContractSummary row was lost"
