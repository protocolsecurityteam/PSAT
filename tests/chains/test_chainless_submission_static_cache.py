"""A chain-less submission reuses static data only from its own chain.

The same address is deployed on mainnet and Base. A submission without a chain is a mainnet job; Base's completed
analysis must not be served to it, and Base's contract row (with its functions and principals) must stay Base's.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlalchemy import func, select

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import (
    Contract,
    ContractSummary,
    EffectiveFunction,
    FunctionPrincipal,
    JobStage,
    JobStatus,
)
from db.queue import copy_static_cache, create_job, store_artifact, store_source_files
from tests.cache_helpers import db_session, requires_postgres, store_semantic_artifacts  # noqa: F401

pytestmark = requires_postgres

ADDR = "0x" + "e2" * 20
BASE_SAFE = "0x" + "18" * 20

_ETHERSCAN_RESULT = {
    "ContractName": "Teller",
    "SourceCode": "pragma solidity ^0.8.24;\ncontract Teller { /* mainnet build */ }",
    "CompilerVersion": "v0.8.24",
    "OptimizationUsed": "1",
    "Runs": "200",
    "EVMVersion": "shanghai",
    "LicenseType": "MIT",
}


@pytest.fixture(autouse=True)
def _stub_membership_probe(monkeypatch):
    monkeypatch.setattr("services.discovery.membership_gate.probe", lambda session, contract: None)


def _analysed_on_base(session):
    job = create_job(session, {"address": ADDR, "chain": "base", "name": "Teller"})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    job.analysis_schema_version = ANALYSIS_SCHEMA_VERSION
    session.commit()

    contract = Contract(
        job_id=job.id,
        address=ADDR,
        chain="base",
        contract_name="Teller",
        compiler_version="v0.8.24",
        language="solidity",
        source_format="flat",
        source_file_count=1,
    )
    session.add(contract)
    session.flush()
    session.add(ContractSummary(contract_id=contract.id, control_model="roles", is_upgradeable=False))
    fn = EffectiveFunction(contract_id=contract.id, function_name="deposit(address,uint256)", selector="0x47e7ef24")
    session.add(fn)
    session.flush()
    session.add(FunctionPrincipal(function_id=fn.id, address=BASE_SAFE, resolved_type="safe"))
    session.commit()

    store_source_files(session, job.id, {"src/Teller.sol": "pragma solidity ^0.8.24;\ncontract Teller {}"})
    store_artifact(session, job.id, "contract_analysis", data={"summary": {"control_model": "roles"}})
    store_semantic_artifacts(session, job.id)
    session.commit()
    return job, contract


def _base_rows(session, contract_id):
    fns = session.execute(select(EffectiveFunction).where(EffectiveFunction.contract_id == contract_id)).scalars().all()
    principals = (
        session.execute(select(FunctionPrincipal.address).where(FunctionPrincipal.function_id.in_([f.id for f in fns])))
        .scalars()
        .all()
    )
    return [f.function_name for f in fns], list(principals)


def test_a_chainless_submission_never_takes_over_the_base_row(db_session, monkeypatch):
    from workers.discovery import DiscoveryWorker

    base_job, base_contract = _analysed_on_base(db_session)

    job = create_job(db_session, {"address": ADDR, "name": "Teller"})
    assert job.chain_id == 1
    monkeypatch.setattr(
        "workers.discovery.etherscan.parallel_get",
        lambda thunks: {"fetch": dict(_ETHERSCAN_RESULT), "creators": {ADDR: None}},
    )
    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    worker._process_address(db_session, job)

    db_session.expire_all()
    base_row = db_session.get(Contract, base_contract.id)
    assert base_row is not None
    assert (base_row.job_id, base_row.chain) == (base_job.id, "base")
    assert _base_rows(db_session, base_contract.id) == (["deposit(address,uint256)"], [BASE_SAFE])

    mainnet_rows = (
        db_session.execute(
            select(Contract).where(Contract.address == ADDR, func.coalesce(Contract.chain, "ethereum") == "ethereum")
        )
        .scalars()
        .all()
    )
    assert [(row.job_id, row.id != base_contract.id) for row in mainnet_rows] == [(job.id, True)]
    request = job.request if isinstance(job.request, dict) else {}
    assert "cache_source_job_id" not in request
    assert "cross_chain_cache_source_job_id" not in request


def test_copy_static_cache_refuses_a_donor_on_another_chain(db_session):
    base_job, base_contract = _analysed_on_base(db_session)
    target = create_job(db_session, {"address": ADDR, "name": "Teller"})

    assert copy_static_cache(db_session, base_job.id, target.id) is None

    db_session.expire_all()
    base_row = db_session.get(Contract, base_contract.id)
    assert base_row is not None and base_row.job_id == base_job.id
    assert _base_rows(db_session, base_contract.id) == (["deposit(address,uint256)"], [BASE_SAFE])


def test_analysis_detail_of_a_legacy_chainless_job_never_shows_the_base_row(db_session):
    from services.aggregations.analysis_detail import build_analysis_detail

    _base_job, base_contract = _analysed_on_base(db_session)
    legacy = create_job(db_session, {"address": ADDR, "name": "legacy-teller"})
    legacy.request = {"address": ADDR, "name": "legacy-teller"}
    legacy.status = JobStatus.completed
    legacy.stage = JobStage.done
    db_session.commit()

    payload = build_analysis_detail(db_session, "legacy-teller")

    assert payload is not None
    assert payload["contract_id"] != base_contract.id
    assert "effective_permissions" not in payload
