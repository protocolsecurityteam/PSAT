from __future__ import annotations

import pytest

from tests.cache_helpers import (
    ADDR_A,
    IMPL_ADDR,
    _create_source_job_with_proxy,
    _sqlite_compatible_store_artifact,
    db_session,  # noqa: F401
    requires_postgres,
)

pytestmark = requires_postgres


def test_copy_static_cache_preserves_proxy_fields(db_session):
    from db.models import Contract
    from db.queue import copy_static_cache, create_job

    source_job = _create_source_job_with_proxy(
        db_session,
        address=ADDR_A,
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
        beacon="0xbeac000000000000000000000000000000000000",
        admin="0xad0000000000000000000000000000000000000f",
    )

    target_job = create_job(db_session, {"address": ADDR_A})

    copy_static_cache(db_session, source_job.id, target_job.id)

    contract = (
        db_session.query(Contract)
        .filter(
            Contract.address == ADDR_A,
        )
        .first()
    )
    assert contract is not None, "Contract row should exist"
    assert contract.is_proxy is True, "is_proxy should be preserved, not zeroed"
    assert contract.proxy_type == "eip1967", "proxy_type should be preserved"
    assert contract.implementation == IMPL_ADDR, "implementation should be preserved"
    assert contract.beacon == "0xbeac000000000000000000000000000000000000"
    assert contract.admin == "0xad0000000000000000000000000000000000000f"


def test_copy_static_cache_preserves_non_proxy_contract(db_session):
    from db.models import Contract
    from db.queue import copy_static_cache, create_job

    source_job = _create_source_job_with_proxy(
        db_session,
        address=ADDR_A,
        is_proxy=False,
    )

    target_job = create_job(db_session, {"address": ADDR_A})

    copy_static_cache(db_session, source_job.id, target_job.id)

    contract = (
        db_session.query(Contract)
        .filter(
            Contract.address == ADDR_A,
        )
        .first()
    )
    assert contract is not None
    assert contract.is_proxy is False
    assert contract.proxy_type is None
    assert contract.implementation is None


def test_old_job_contract_accessible_by_address_after_copy(db_session):
    """copy_static_cache reassigns job_id, so the old job must find its row by address."""
    from db.models import Contract, ContractSummary
    from db.queue import copy_static_cache, create_job

    source_job = _create_source_job_with_proxy(
        db_session,
        address=ADDR_A,
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
    )

    contract_before = (
        db_session.query(Contract)
        .filter(
            Contract.job_id == source_job.id,
        )
        .first()
    )
    assert contract_before is not None
    assert contract_before.is_proxy is True

    target_job = create_job(db_session, {"address": ADDR_A})
    copy_static_cache(db_session, source_job.id, target_job.id)

    contract_by_addr = (
        db_session.query(Contract)
        .filter(
            Contract.address == ADDR_A,
        )
        .first()
    )
    assert contract_by_addr is not None, "Contract must be findable by address"
    assert contract_by_addr.is_proxy is True, "Contract found by address should retain is_proxy"
    assert contract_by_addr.proxy_type == "eip1967"

    summary = (
        db_session.query(ContractSummary)
        .filter(
            ContractSummary.contract_id == contract_by_addr.id,
        )
        .first()
    )
    assert summary is not None, "ContractSummary should still be linked"


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


def test_api_analysis_detail_returns_data_for_old_job(db_session, api_client, monkeypatch):
    old_job, new_job, protocol = _setup_company_with_proxy(db_session, monkeypatch)

    resp = api_client.get(f"/api/analyses/{old_job.id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data.get("contract_analysis") is not None or data.get("address") is not None, (
        "Old job analysis detail should have data, not be empty"
    )


def test_repeated_copy_static_cache_preserves_proxy_fields(db_session):
    from db.models import Contract
    from db.queue import copy_static_cache, create_job

    source_job = _create_source_job_with_proxy(
        db_session,
        address=ADDR_A,
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
    )

    target1 = create_job(db_session, {"address": ADDR_A})
    copy_static_cache(db_session, source_job.id, target1.id)

    target2 = create_job(db_session, {"address": ADDR_A})
    copy_static_cache(db_session, target1.id, target2.id)

    contract = (
        db_session.query(Contract)
        .filter(
            Contract.address == ADDR_A,
        )
        .first()
    )
    assert contract is not None
    assert contract.is_proxy is True, "is_proxy lost after second copy"
    assert contract.proxy_type == "eip1967", "proxy_type lost after second copy"
    assert contract.implementation == IMPL_ADDR, "implementation lost after second copy"
