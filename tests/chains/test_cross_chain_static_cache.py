"""Cross-chain job-level static-cache reuse.

``find_completed_static_cache`` + copy reuses a completed job's CODE plane for a new ``(chain, address)``
deployment of the same verified source. The source-hash path is a fallback on primary miss only; the copy
re-stamps the contract address and leaves chain-derived artifacts to be re-derived per chain.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import Contract, ContractSummary, JobStage, JobStatus, RoleDefinition
from db.queue import (
    copy_static_cache_cross_chain,
    create_job,
    find_completed_static_cache,
    get_artifact,
    store_artifact,
    store_source_files,
)
from tests.cache_helpers import db_session, requires_postgres  # noqa: F401

pytestmark = requires_postgres

ADDR_MAINNET = "0x" + "a1" * 20
ADDR_BASE = "0x" + "b2" * 20
ADDR_OTHER = "0x" + "c3" * 20
HASH = "0x" + "de" * 32

_SOURCES = {
    "src/Vault.sol": "pragma solidity ^0.8.24;\ncontract Vault {}",
    "src/Lib.sol": "pragma solidity ^0.8.24;\nlibrary Lib {}",
}


def _analysis(address: str) -> dict:
    return {
        "schema_version": "1",
        "subject": {"address": address, "name": "Vault", "compiler_version": "v0.8.24", "source_verified": True},
        "summary": {"control_model": "ownable", "standards": ["ERC20"]},
        "semantic_control": {"role_definitions": [{"role": "ADMIN_ROLE", "declared_in": "Vault.sol"}]},
    }


def _tracking_plan(address: str) -> dict:
    return {"contract_address": address, "controllers": [{"id": "owner", "getter": "owner()"}]}


_PREDICATE_TREES = {"schema_version": "semantic", "trees": {"pause()": {"node_type": "caller"}}}
_EFFECTS = {"schema_version": "semantic", "effects": {"transfer()": [{"kind": "value_flow"}]}}


def _make_donor(
    session,
    *,
    address: str = ADDR_MAINNET,
    chain: str = "ethereum",
    source_content_hash: str | None = HASH,
    schema_version: int | None = ANALYSIS_SCHEMA_VERSION,
    with_analysis: bool = True,
    extra_artifacts: dict | None = None,
):
    job = create_job(session, {"address": address, "chain": chain, "name": "Vault"})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    job.source_content_hash = source_content_hash
    job.analysis_schema_version = schema_version
    session.commit()

    contract = Contract(
        job_id=job.id,
        address=address.lower(),
        chain=chain,
        contract_name="Vault",
        compiler_version="v0.8.24",
        language="solidity",
        source_format="flat",
        source_file_count=len(_SOURCES),
    )
    session.add(contract)
    session.flush()
    session.add(
        ContractSummary(
            contract_id=contract.id,
            control_model="ownable",
            is_upgradeable=False,
            is_pausable=True,
            standards=["ERC20"],
        )
    )
    session.add(RoleDefinition(contract_id=contract.id, role_name="ADMIN_ROLE", declared_in="Vault.sol"))
    session.commit()

    store_source_files(session, job.id, dict(_SOURCES))
    if with_analysis:
        store_artifact(session, job.id, "contract_analysis", data=_analysis(address.lower()))
        store_artifact(session, job.id, "control_tracking_plan", data=_tracking_plan(address.lower()))
        store_artifact(session, job.id, "predicate_trees", data=dict(_PREDICATE_TREES))
        store_artifact(session, job.id, "effects", data=dict(_EFFECTS))
    else:
        store_artifact(session, job.id, "contract_flags", data={"is_proxy": True, "proxy_type": "eip1967"})
    for name, data in (extra_artifacts or {}).items():
        store_artifact(session, job.id, name, data=data)
    return job, contract


def _make_target(session, *, address: str = ADDR_BASE, chain: str = "base"):
    job = create_job(session, {"address": address, "chain": chain, "name": "Vault"})
    session.commit()
    contract = Contract(
        job_id=job.id,
        address=address.lower(),
        chain=chain,
        contract_name="Vault",
        compiler_version="v0.8.24",
        language="solidity",
        source_format="flat",
        source_file_count=len(_SOURCES),
    )
    session.add(contract)
    session.commit()
    return job, contract


def test_copy_restamps_address_scopes_artifacts_and_leaves_donor_untouched(db_session):
    donor_job, donor_contract = _make_donor(
        db_session,
        extra_artifacts={
            "static_dependencies": {"address": ADDR_MAINNET.lower(), "dependencies": ["0x" + "42" * 20]},
            "enrichment_cache": {"0x" + "42" * 20: {"name": "MainnetDep"}},
            "upgrade_history": {"target_address": ADDR_MAINNET.lower(), "total_upgrades": 3},
        },
    )
    target_job, target_contract = _make_target(db_session)

    cid = copy_static_cache_cross_chain(db_session, donor_job.id, target_job.id, target_address=ADDR_BASE)
    assert cid == target_contract.id

    ca = get_artifact(db_session, target_job.id, "contract_analysis")
    assert isinstance(ca, dict)
    assert ca["subject"]["address"] == ADDR_BASE.lower()
    tp = get_artifact(db_session, target_job.id, "control_tracking_plan")
    assert isinstance(tp, dict)
    assert tp["contract_address"] == ADDR_BASE.lower()

    assert get_artifact(db_session, target_job.id, "predicate_trees") == _PREDICATE_TREES
    assert get_artifact(db_session, target_job.id, "effects") == _EFFECTS

    assert get_artifact(db_session, target_job.id, "static_dependencies") is None
    assert get_artifact(db_session, target_job.id, "enrichment_cache") is None
    assert get_artifact(db_session, target_job.id, "upgrade_history") is None

    summary = db_session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == target_contract.id)
    ).scalar_one()
    assert summary.control_model == "ownable"
    assert summary.standards == ["ERC20"]
    roles = (
        db_session.execute(select(RoleDefinition).where(RoleDefinition.contract_id == target_contract.id))
        .scalars()
        .all()
    )
    assert [r.role_name for r in roles] == ["ADMIN_ROLE"]

    # Unlike same-chain copy, the donor keeps its contract.
    donor_ca = get_artifact(db_session, donor_job.id, "contract_analysis")
    assert isinstance(donor_ca, dict)
    assert donor_ca["subject"]["address"] == ADDR_MAINNET.lower()
    db_session.refresh(donor_contract)
    assert donor_contract.job_id == donor_job.id


def test_fallback_fires_only_on_primary_miss(db_session):
    primary_job, _ = _make_donor(db_session, address=ADDR_MAINNET, chain="ethereum", source_content_hash=HASH)
    hash_donor, _ = _make_donor(db_session, address=ADDR_OTHER, chain="base", source_content_hash=HASH)

    hit = find_completed_static_cache(db_session, ADDR_MAINNET, chain="ethereum", source_content_hash=HASH)
    assert hit is not None and hit.id == primary_job.id

    fb = find_completed_static_cache(db_session, ADDR_BASE, chain="base", source_content_hash=HASH)
    assert fb is not None and fb.id == hash_donor.id


@pytest.mark.parametrize(
    ("donor_kwargs", "lookup_hashes"),
    [
        pytest.param({"schema_version": ANALYSIS_SCHEMA_VERSION + 1000}, [HASH], id="version_mismatch"),
        pytest.param({"source_content_hash": None, "schema_version": None}, [HASH, None], id="legacy_null_hash"),
        # A proxy donor (contract_flags only) is not a code-plane reuse source.
        pytest.param({"with_analysis": False}, [HASH], id="proxy_donor"),
    ],
)
def test_ineligible_cross_chain_donor_is_not_reused(db_session, donor_kwargs, lookup_hashes):
    _make_donor(db_session, address=ADDR_OTHER, chain="base", **{"source_content_hash": HASH, **donor_kwargs})
    for lookup_hash in lookup_hashes:
        assert find_completed_static_cache(db_session, ADDR_BASE, chain="base", source_content_hash=lookup_hash) is None


def test_discovery_reuses_cross_chain_donor(db_session, monkeypatch):
    from unittest.mock import MagicMock

    from services.discovery.fetch import source_content_hash
    from workers.discovery import DiscoveryWorker

    stub_result = {
        "ContractName": "Vault",
        "SourceCode": "pragma solidity ^0.8.24;\ncontract Vault {}",
        "CompilerVersion": "v0.8.24",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": "shanghai",
        "LicenseType": "MIT",
    }
    donor_hash = source_content_hash(stub_result)

    donor_job, _ = _make_donor(db_session, address=ADDR_MAINNET, chain="ethereum", source_content_hash=donor_hash)

    target_job = create_job(db_session, {"address": ADDR_BASE, "chain": "base"})
    db_session.commit()

    monkeypatch.setattr(
        "workers.discovery.etherscan.parallel_get",
        lambda thunks: {"fetch": stub_result, "creators": {ADDR_BASE.lower(): None}},
    )
    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    worker._process_address(db_session, target_job)

    db_session.refresh(target_job)
    req = target_job.request
    assert isinstance(req, dict)
    assert req.get("static_cached") is True
    assert req.get("cross_chain_cache_source_job_id") == str(donor_job.id)
    # Proxy state must re-resolve on Base.
    assert "cache_source_job_id" not in req
    assert target_job.source_content_hash == donor_hash

    ca = get_artifact(db_session, target_job.id, "contract_analysis")
    assert isinstance(ca, dict)
    assert ca["subject"]["address"] == ADDR_BASE.lower()
    base_contract = db_session.execute(select(Contract).where(Contract.job_id == target_job.id)).scalar_one()
    assert base_contract.chain == "base"
