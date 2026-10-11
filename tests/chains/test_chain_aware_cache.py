from __future__ import annotations

from tests.cache_helpers import (
    ADDR_A,
    _sqlite_compatible_store_artifact,
    db_session,  # noqa: F401
    requires_postgres,
    store_semantic_artifacts,
)

pytestmark = requires_postgres


def _create_completed_job_with_chain(session, address, chain, name="TestContract"):
    from db.models import (
        Contract,
        ContractSummary,
        JobStage,
        JobStatus,
        RoleDefinition,
    )
    from db.queue import create_job, store_source_files

    store_artifact = _sqlite_compatible_store_artifact

    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

    job = create_job(session, {"address": address, "name": name, "chain": chain})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    job.analysis_schema_version = ANALYSIS_SCHEMA_VERSION
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

    store_artifact(session, job.id, "contract_analysis", data={"summary": {"control_model": "ownable"}})
    store_semantic_artifacts(session, job.id)
    store_artifact(session, job.id, "slither_results", data={"results": {"detectors": []}})
    store_artifact(session, job.id, "analysis_report", text_data="Test analysis report")
    store_artifact(session, job.id, "control_tracking_plan", data={"controllers": []})

    return job


def _create_completed_company_job_with_inventory(session, company, chain, inventory_data):
    from db.models import JobStage, JobStatus
    from db.queue import create_job

    store_artifact = _sqlite_compatible_store_artifact

    job = create_job(session, {"company": company, "chain": chain, "name": company})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()

    store_artifact(session, job.id, "contract_inventory", data=inventory_data)
    return job


class TestCompanyInventoryChainFiltering:
    def test_previous_inventory_different_chain_excluded(self, db_session):
        from db.queue import find_previous_company_inventory

        inv = {"contracts": [{"address": ADDR_A, "chain": "ethereum"}]}
        _create_completed_company_job_with_inventory(db_session, "Aave", "ethereum", inv)

        found = find_previous_company_inventory(
            db_session,
            "Aave",
            chain="base",
        )
        assert found is None, "Ethereum inventory was returned for Base request — cross-chain contamination"


class TestCopyCachePreservesSource:
    def test_source_job_still_valid_cache_after_copy(self, db_session):
        from db.queue import (
            copy_static_cache,
            create_job,
            find_completed_static_cache,
        )

        source = _create_completed_job_with_chain(db_session, ADDR_A, "ethereum")

        target1 = create_job(db_session, {"address": ADDR_A, "chain": "ethereum"})
        result1 = copy_static_cache(db_session, source.id, target1.id)
        assert result1 is not None

        found = find_completed_static_cache(db_session, ADDR_A, chain="ethereum")
        assert found is not None, (
            "Source job is no longer a valid cache after first copy — contract row was moved instead of cloned"
        )
        assert found.id == source.id
