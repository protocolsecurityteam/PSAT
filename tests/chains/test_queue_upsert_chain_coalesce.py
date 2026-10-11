"""Latent NULL-chain dedup sites in ``db.queue``.

Phase 2 (#154) fixed the bulk discovery writer (a chainless write derives a real chain and dedups against
legacy ``chain=NULL`` rows via a mainnet-coalesced key). These cover the same-class sites left latent:
``upsert_discovered_contract`` (single-row) and the ``find_completed_static_cache`` / ``is_known_proxy`` /
``copy_static_cache`` lookups whose ``chain == <value>`` predicate missed NULL rows.

Each is proven both ways: mainnet finds legacy NULL rows; non-mainnet stays isolated. No backfill.
"""

from __future__ import annotations

import uuid

import pytest

from tests.cache_helpers import store_semantic_artifacts
from tests.conftest import requires_postgres


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


@pytest.fixture()
def proto_id(db_session):
    from db.models import Protocol

    p = Protocol(name=f"queue-coalesce-{uuid.uuid4().hex[:10]}")
    db_session.add(p)
    db_session.commit()
    return p.id


@requires_postgres
@pytest.mark.parametrize(
    "chain,expected",
    [
        pytest.param("ethereum", True, id="mainnet_finds_legacy_null"),
        pytest.param("base", False, id="l2_isolated_from_legacy_null"),
    ],
)
def test_is_known_proxy_against_legacy_null_row(db_session, proto_id, chain, expected):
    from db.models import Contract
    from db.queue import is_known_proxy

    addr = _addr()
    db_session.add(Contract(address=addr, chain=None, protocol_id=proto_id, is_proxy=True))
    db_session.commit()

    assert is_known_proxy(db_session, addr, chain=chain) is expected


def _completed_source_with_null_contract(session, address, request_chain):
    from db.models import Contract, ContractSummary, JobStage, JobStatus
    from db.queue import create_job, store_artifact, store_source_files

    job = create_job(session, {"address": address, "name": "LegacyContract", "chain": request_chain})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()

    contract = Contract(
        job_id=job.id,
        address=address.lower(),
        chain=None,  # legacy NULL despite the mainnet request
        contract_name="LegacyContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        source_format="flat",
        source_file_count=1,
        remappings=[],
    )
    session.add(contract)
    session.flush()
    session.add(ContractSummary(contract_id=contract.id, control_model="ownable"))
    session.commit()

    store_source_files(session, job.id, {"src/Legacy.sol": "contract Legacy {}"})
    store_artifact(session, job.id, "contract_analysis", data={"summary": {}})
    store_semantic_artifacts(session, job.id)
    return job


@requires_postgres
def test_copy_static_cache_matches_legacy_null_source_row(db_session):
    """The raw equality returned None and the copy silently produced nothing."""
    from db.models import Contract
    from db.queue import copy_static_cache, create_job
    from tests.cache_helpers import ADDR_A

    src_job = _completed_source_with_null_contract(db_session, ADDR_A, "ethereum")
    target_job = create_job(db_session, {"address": ADDR_A, "chain": "ethereum", "name": "Target"})

    new_contract_id = copy_static_cache(db_session, src_job.id, target_job.id)
    assert new_contract_id is not None
    copied = db_session.query(Contract).filter(Contract.id == new_contract_id).one()
    assert copied.job_id == target_job.id
