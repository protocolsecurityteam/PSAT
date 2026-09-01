"""Tests proving chain-awareness bugs in the caching layer.

Each test demonstrates a real cross-chain contamination or data-loss
scenario. They should FAIL against the old code and PASS after fixes.
"""

from __future__ import annotations

import uuid

from tests.cache_helpers import (
    ADDR_A,
    _sqlite_compatible_store_artifact,
    db_session,  # noqa: F401
    requires_postgres,
)

pytestmark = requires_postgres

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_completed_job_with_chain(session, address, chain, name="TestContract"):
    """Create a completed job with all static data, on a specific chain."""
    from db.models import (
        Contract,
        ContractSummary,
        JobStage,
        JobStatus,
        RoleDefinition,
    )
    from db.queue import create_job, store_source_files

    store_artifact = _sqlite_compatible_store_artifact

    job = create_job(session, {"address": address, "name": name, "chain": chain})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    from db.contract_materializations import STATIC_FACTS_SCHEMA_VERSION

    job.static_facts_schema_version = STATIC_FACTS_SCHEMA_VERSION
    session.commit()

    contract = Contract(
        job_id=job.id,
        address=address.lower(),
        chain=chain,
        contract_name=name,
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=2,
        license="MIT",
        deployer="0x0000000000000000000000000000000000000001",
        remappings=[],
    )
    session.add(contract)
    session.flush()

    session.add(
        ContractSummary(
            contract_id=contract.id,
            control_model="ownable",
            is_upgradeable=False,
            is_pausable=True,
            has_timelock=False,
        )
    )
    session.add(
        RoleDefinition(
            contract_id=contract.id,
            role_name="ADMIN_ROLE",
            declared_in="TestContract.sol",
        )
    )
    session.commit()

    store_source_files(
        session,
        job.id,
        {
            "src/TestContract.sol": "pragma solidity ^0.8.24;\ncontract TestContract {}",
            "src/Utils.sol": "pragma solidity ^0.8.24;\nlibrary Utils {}",
        },
    )

    from tests.support.policy_builders import _assessment, _minimal_static_facts

    facts = _minimal_static_facts(address=address, name="TestContract")
    store_artifact(session, job.id, "assessment", data=_assessment(static_facts=facts, chain_id=job.chain_id or 1))
    store_artifact(session, job.id, "slither_results", data={"results": {"detectors": []}})
    store_artifact(session, job.id, "static_facts_report", text_data="Test analysis report")

    return job


def _create_completed_company_job_with_inventory(session, company, chain, inventory_data):
    """Create a completed company job with a contract_inventory artifact."""
    from db.models import JobStage, JobStatus
    from db.queue import create_job

    store_artifact = _sqlite_compatible_store_artifact

    job = create_job(session, {"company": company, "chain": chain, "name": company})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()

    store_artifact(session, job.id, "contract_inventory", data=inventory_data)
    return job


# ---------------------------------------------------------------------------
# P1: find_completed_static_cache must respect chain
# ---------------------------------------------------------------------------


class TestStaticCacheChainFiltering:
    def test_cache_hit_same_chain(self, db_session):
        """Cache hit when address AND chain match."""
        from db.queue import find_completed_static_cache

        job_eth = _create_completed_job_with_chain(db_session, ADDR_A, "ethereum")
        found = find_completed_static_cache(db_session, ADDR_A, chain="ethereum")
        assert found is not None
        assert found.id == job_eth.id

    def test_cache_miss_different_chain(self, db_session):
        """Same address on Ethereum must NOT be returned for a Base lookup."""
        from db.queue import find_completed_static_cache

        _create_completed_job_with_chain(db_session, ADDR_A, "ethereum")

        found = find_completed_static_cache(db_session, ADDR_A, chain="base")
        assert found is None, "Ethereum cache was returned for a Base request — cross-chain contamination"


# ---------------------------------------------------------------------------
# P2: find_previous_company_inventory must respect chain
# ---------------------------------------------------------------------------


class TestCompanyInventoryChainFiltering:
    def test_previous_inventory_same_chain(self, db_session):
        """Previous inventory on the same chain is returned."""
        from db.queue import find_previous_company_inventory

        inv = {"contracts": [{"address": ADDR_A, "chain": "ethereum"}]}
        job = _create_completed_company_job_with_inventory(
            db_session,
            "Aave",
            "ethereum",
            inv,
        )

        new_job_id = uuid.uuid4()  # dummy exclude
        found = find_previous_company_inventory(
            db_session,
            "Aave",
            exclude_job_id=new_job_id,
            chain="ethereum",
        )
        assert found is not None
        assert found.id == job.id

    def test_previous_inventory_different_chain_excluded(self, db_session):
        """Ethereum inventory must NOT be returned for a Base lookup."""
        from db.queue import find_previous_company_inventory

        inv = {"contracts": [{"address": ADDR_A, "chain": "ethereum"}]}
        _create_completed_company_job_with_inventory(db_session, "Aave", "ethereum", inv)

        found = find_previous_company_inventory(
            db_session,
            "Aave",
            chain="base",
        )
        assert found is None, "Ethereum inventory was returned for Base request — cross-chain contamination"


# ---------------------------------------------------------------------------
# P2: find_existing_job_for_address and is_known_proxy must respect chain
# ---------------------------------------------------------------------------


class TestDedupChainFiltering:
    def test_existing_job_different_chain_not_found(self, db_session):
        """An Ethereum job must NOT suppress a Base job for the same address."""
        from db.queue import create_job, find_existing_job_for_address

        create_job(db_session, {"address": ADDR_A, "chain": "ethereum"})
        found = find_existing_job_for_address(db_session, ADDR_A, chain="base")
        assert found is None, "Ethereum job suppressed Base job creation — cross-chain dedup error"

    def test_is_known_proxy_same_chain(self, db_session):
        """Proxy on Ethereum is detected for Ethereum queries."""
        from db.models import Contract
        from db.queue import create_job, is_known_proxy

        job = create_job(db_session, {"address": ADDR_A, "chain": "ethereum"})
        contract = Contract(
            job_id=job.id,
            address=ADDR_A.lower(),
            chain="ethereum",
            contract_name="Proxy",
            is_proxy=True,
            proxy_type="eip1967",
            implementation="0x1111111111111111111111111111111111111111",
        )
        db_session.add(contract)
        db_session.commit()

        assert is_known_proxy(db_session, ADDR_A, chain="ethereum") is True

    def test_is_known_proxy_different_chain_not_found(self, db_session):
        """A proxy on Ethereum must NOT be treated as proxy on Base."""
        from db.models import Contract
        from db.queue import create_job, is_known_proxy

        job = create_job(db_session, {"address": ADDR_A, "chain": "ethereum"})
        contract = Contract(
            job_id=job.id,
            address=ADDR_A.lower(),
            chain="ethereum",
            contract_name="Proxy",
            is_proxy=True,
            proxy_type="eip1967",
            implementation="0x1111111111111111111111111111111111111111",
        )
        db_session.add(contract)
        db_session.commit()

        assert is_known_proxy(db_session, ADDR_A, chain="base") is False, (
            "Ethereum proxy was reported as proxy on Base — cross-chain contamination"
        )


# ---------------------------------------------------------------------------
# P2: copy_static_cache must not steal the source job's contract row
# ---------------------------------------------------------------------------


class TestCopyCachePreservesSource:
    def test_source_job_still_valid_cache_after_copy(self, db_session):
        """After one cache copy, the source job must still be usable as a
        cache source for subsequent copies."""
        from db.queue import (
            copy_static_cache,
            create_job,
            find_completed_static_cache,
        )

        source = _create_completed_job_with_chain(db_session, ADDR_A, "ethereum")

        # First cache copy
        target1 = create_job(db_session, {"address": ADDR_A, "chain": "ethereum"})
        result1 = copy_static_cache(db_session, source.id, target1.id)
        assert result1 is not None

        # Source must still be a valid cache hit
        found = find_completed_static_cache(db_session, ADDR_A, chain="ethereum")
        assert found is not None, (
            "Source job is no longer a valid cache after first copy — contract row was moved instead of cloned"
        )
        assert found.id == source.id

    def test_second_cache_copy_succeeds(self, db_session):
        """A second cache copy from the same source must succeed."""
        from db.queue import copy_static_cache, create_job

        source = _create_completed_job_with_chain(db_session, ADDR_A, "ethereum")

        target1 = create_job(db_session, {"address": ADDR_A, "chain": "ethereum"})
        copy_static_cache(db_session, source.id, target1.id)

        target2 = create_job(db_session, {"address": ADDR_A, "chain": "ethereum"})
        result2 = copy_static_cache(db_session, source.id, target2.id)
        assert result2 is not None, "Second cache copy failed — source contract row was consumed by the first"
