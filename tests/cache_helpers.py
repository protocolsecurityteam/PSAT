"""Shared fixtures, helpers, and constants for static cache tests.

Provides a PostgreSQL database session with the full PSAT schema.
Test modules import the ``db_session`` fixture and helper functions
from this module.

Requires TEST_DATABASE_URL env var pointing to a PostgreSQL test database.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Re-exported: modules import the gate from here alongside the fixtures below.
from tests.conftest import requires_postgres as requires_postgres

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


# ---------------------------------------------------------------------------
# Address / data constants
# ---------------------------------------------------------------------------

ADDR_A = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ADDR_B = "0x0000000000000000000000000000000000000099"

IMPL_ADDR = "0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f"
IMPL_ADDR_NEW = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

FAKE_STATIC_DEPS = {
    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "dependencies": [
        "0x0000000000000000000000000000000000000042",
        "0x0000000000000000000000000000000000000043",
    ],
    "rpc": "https://rpc.example",
}

FAKE_DYN_DEPS_OLD = {
    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "rpc": "https://rpc.example",
    "transactions_analyzed": [
        {"tx_hash": "0xaaa", "block_number": 100, "method_selector": "0x12345678"},
        {"tx_hash": "0xbbb", "block_number": 200, "method_selector": "0xabcdef01"},
    ],
    "trace_methods": ["debug_traceTransaction"],
    "dependencies": [
        "0x0000000000000000000000000000000000000042",
    ],
    "provenance": {
        "0x0000000000000000000000000000000000000042": [
            {
                "tx_hash": "0xaaa",
                "block_number": 100,
                "from": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "op": "CALL",
            },
        ],
    },
    "dependency_graph": [
        {
            "from": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "to": "0x0000000000000000000000000000000000000042",
            "op": "CALL",
            "provenance": [{"tx_hash": "0xaaa", "block_number": 100}],
        },
    ],
    "trace_errors": [],
}

FAKE_DYN_DEPS_NEW = {
    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "rpc": "https://rpc.example",
    "transactions_analyzed": [
        {"tx_hash": "0xccc", "block_number": 300, "method_selector": "0x99999999"},
    ],
    "trace_methods": ["debug_traceTransaction"],
    "dependencies": [
        "0x0000000000000000000000000000000000000042",
        "0x0000000000000000000000000000000000000099",
    ],
    "provenance": {
        "0x0000000000000000000000000000000000000042": [
            {
                "tx_hash": "0xccc",
                "block_number": 300,
                "from": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "op": "STATICCALL",
            },
        ],
        "0x0000000000000000000000000000000000000099": [
            {
                "tx_hash": "0xccc",
                "block_number": 300,
                "from": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "op": "CALL",
            },
        ],
    },
    "dependency_graph": [
        {
            "from": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "to": "0x0000000000000000000000000000000000000042",
            "op": "STATICCALL",
            "provenance": [{"tx_hash": "0xccc", "block_number": 300}],
        },
        {
            "from": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "to": "0x0000000000000000000000000000000000000099",
            "op": "CALL",
            "provenance": [{"tx_hash": "0xccc", "block_number": 300}],
        },
    ],
    "trace_errors": [],
}

FAKE_CLS_OUTPUT = {
    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "rpc": "https://rpc.example",
    "classifications": {
        "0x0000000000000000000000000000000000000042": {"type": "regular"},
        "0x0000000000000000000000000000000000000043": {"type": "proxy", "proxy_type": "eip1967"},
    },
    "discovered_addresses": [],
}

FAKE_UH_PREV = {
    "schema_version": "0.1",
    "target_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "proxies": {
        "0xdac17f958d2ee523a2206206994597c13d831ec7": {
            "proxy_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "proxy_type": "eip1967",
            "current_implementation": "0x0000000000000000000000000000000000000042",
            "upgrade_count": 1,
            "first_upgrade_block": 50,
            "last_upgrade_block": 50,
            "implementations": [
                {"address": "0x0000000000000000000000000000000000000042", "block_introduced": 50, "tx_hash": "0xaaa"},
            ],
            "events": [
                {
                    "event_type": "upgraded",
                    "block_number": 50,
                    "tx_hash": "0xaaa",
                    "log_index": 0,
                    "implementation": "0x0000000000000000000000000000000000000042",
                },
            ],
        },
    },
    "total_upgrades": 1,
}

FAKE_UH_NEW = {
    "schema_version": "0.1",
    "target_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "proxies": {
        "0xdac17f958d2ee523a2206206994597c13d831ec7": {
            "proxy_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "proxy_type": "eip1967",
            "current_implementation": "0x0000000000000000000000000000000000000099",
            "upgrade_count": 1,
            "first_upgrade_block": 100,
            "last_upgrade_block": 100,
            "implementations": [
                {"address": "0x0000000000000000000000000000000000000099", "block_introduced": 100, "tx_hash": "0xbbb"},
            ],
            "events": [
                {
                    "event_type": "upgraded",
                    "block_number": 100,
                    "tx_hash": "0xbbb",
                    "log_index": 0,
                    "implementation": "0x0000000000000000000000000000000000000099",
                },
            ],
        },
    },
    "total_upgrades": 1,
}


# Keep this export for test files that still import it
def _sqlite_compatible_store_artifact(session, job_id, name, data=None, text_data=None):
    """ORM-based store_artifact (works with both SQLite and PostgreSQL)."""
    from db.models import Artifact

    existing = session.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == name).first()
    if existing:
        existing.data = data
        existing.text_data = text_data
    else:
        session.add(Artifact(job_id=job_id, name=name, data=data, text_data=text_data))
    session.commit()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_session():
    """PostgreSQL database session with full PSAT schema.

    Creates all tables, yields a session, cleans up test data on teardown.
    """
    from db.models import (
        Artifact,
        Contract,
        ContractBalance,
        ContractDependency,
        ContractSummary,
        ControlGraphEdge,
        ControlGraphNode,
        ControllerValue,
        EffectiveFunction,
        FunctionPrincipal,
        Job,
        MonitoredContract,
        MonitoredEvent,
        PrincipalLabel,
        Protocol,
        ProtocolSubscription,
        ProxySubscription,
        ProxyUpgradeEvent,
        RoleDefinition,
        SourceFile,
        UpgradeEvent,
        UpgradeTransaction,
        WatchedProxy,
    )

    engine = create_engine(DATABASE_URL)
    session = Session(engine, expire_on_commit=False)

    try:
        yield session
    finally:
        session.rollback()
        # Delete in FK-safe order
        for model in [
            FunctionPrincipal,
            EffectiveFunction,
            PrincipalLabel,
            ControlGraphEdge,
            ControlGraphNode,
            ControllerValue,
            UpgradeEvent,
            ContractDependency,
            ContractBalance,
            RoleDefinition,
            ContractSummary,
            MonitoredEvent,
            MonitoredContract,
            ProxyUpgradeEvent,
            ProxySubscription,
            WatchedProxy,
            ProtocolSubscription,
            SourceFile,
            Artifact,
            Contract,
            Job,
            Protocol,
            # After Contract: upgrade_events cascade from it and hold the FK.
            UpgradeTransaction,
        ]:
            try:
                session.query(model).delete()
            except Exception:
                session.rollback()
        session.commit()
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _create_completed_job_with_static_data(session, address=ADDR_A):
    """Helper: create a completed job with all static data populated."""
    from db.models import (
        Contract,
        ContractSummary,
        JobStage,
        JobStatus,
        RoleDefinition,
    )
    from db.queue import create_job, store_artifact, store_source_files

    job = create_job(session, {"address": address, "name": "TestContract"})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()

    # Contract row
    contract = Contract(
        job_id=job.id,
        address=address,
        contract_name="TestContract",
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

    # Contract summary
    session.add(
        ContractSummary(
            contract_id=contract.id,
            control_model="ownable",
            is_upgradeable=False,
            is_pausable=True,
            has_timelock=False,
        )
    )

    # Role definitions
    session.add(
        RoleDefinition(
            contract_id=contract.id,
            role_name="ADMIN_ROLE",
            declared_in="TestContract.sol",
        )
    )

    session.commit()

    # Source files
    store_source_files(
        session,
        job.id,
        {
            "src/TestContract.sol": "pragma solidity ^0.8.24;\ncontract TestContract {}",
            "src/Utils.sol": "pragma solidity ^0.8.24;\nlibrary Utils {}",
        },
    )

    # Artifacts
    from tests.support.policy_builders import _assessment, _minimal_static_facts

    facts = _minimal_static_facts(address=address, name="TestContract")
    store_artifact(session, job.id, "assessment", data=_assessment(static_facts=facts))
    store_artifact(session, job.id, "slither_results", data={"results": {"detectors": []}})
    store_artifact(session, job.id, "static_facts_report", text_data="Test analysis report")
    store_artifact(session, job.id, "contract_flags", data={"is_proxy": False})

    return job


def _create_source_job_with_proxy(
    session,
    address=ADDR_A,
    is_proxy=True,
    proxy_type: str | None = "eip1967",
    implementation: str | None = IMPL_ADDR,
    beacon=None,
    admin=None,
):
    """Helper: create a completed source job with proxy fields set."""
    from db.models import Contract, ContractSummary, JobStage, JobStatus
    from db.queue import create_job, store_artifact, store_source_files

    job = create_job(session, {"address": address, "name": "ProxyContract"})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()

    contract = Contract(
        job_id=job.id,
        address=address,
        contract_name="ProxyContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
        is_proxy=is_proxy,
        proxy_type=proxy_type if is_proxy else None,
        implementation=implementation if is_proxy else None,
        beacon=beacon,
        admin=admin,
    )
    session.add(contract)
    session.flush()

    session.add(ContractSummary(contract_id=contract.id, control_model="proxy"))
    session.commit()

    store_source_files(session, job.id, {"src/Proxy.sol": "contract Proxy {}"})
    from tests.support.policy_builders import _assessment, _minimal_static_facts

    facts = _minimal_static_facts(address=address, name="ProxyContract")
    store_artifact(session, job.id, "assessment", data=_assessment(static_facts=facts))
    store_artifact(session, job.id, "slither_results", data={"results": {"detectors": []}})
    store_artifact(session, job.id, "static_facts_report", text_data="proxy report")

    return job


def _create_target_job_with_contract(session, source_job_id, address=ADDR_A, rpc_url="https://rpc.example"):
    """Helper: create a new job with static_cached flag and a contract row."""
    from db.queue import copy_static_cache, create_job, store_source_files

    job = create_job(
        session,
        {
            "address": address,
            "rpc_url": rpc_url,
            "static_cached": True,
            "cache_source_job_id": str(source_job_id),
        },
    )

    copy_static_cache(session, source_job_id, job.id)

    store_source_files(session, job.id, {"src/Proxy.sol": "contract Proxy {}"})

    return job


def _make_dep_phase_job(session, address=ADDR_A, extra_request=None):
    """Helper: create a job suitable for _run_dependency_phase testing."""
    from db.models import Contract
    from db.queue import create_job, store_source_files

    req = {"address": address, "rpc_url": "https://rpc.example"}
    if extra_request:
        req.update(extra_request)
    job = create_job(session, req)
    contract = Contract(
        job_id=job.id,
        address=address,
        contract_name="TestContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
    )
    session.add(contract)
    session.commit()
    store_source_files(session, job.id, {"src/Test.sol": "contract Test {}"})
    return job


def _patch_dep_phase_helpers(monkeypatch, find_dyn_fn):
    """Patch all helpers used by _run_dependency_phase except find_dynamic_dependencies."""
    monkeypatch.setattr("workers.static_worker.find_dependencies", lambda *a, **kw: FAKE_STATIC_DEPS)
    monkeypatch.setattr("workers.static_worker.find_dynamic_dependencies", find_dyn_fn)
    monkeypatch.setattr("workers.static_worker.classify_contracts", lambda *a, **kw: None)
    monkeypatch.setattr(
        "workers.static_worker.build_unified_dependencies",
        lambda *a, **kw: {"target_address": ADDR_A, "dependencies": {}},
    )
    monkeypatch.setattr("workers.static_worker.enrich_dependency_metadata", lambda *a, **kw: None)
    monkeypatch.setattr(
        "workers.static_worker.build_dependency_visualization",
        lambda *a, **kw: {"nodes": [], "edges": [], "metadata": {}},
    )


def _patch_static_worker_phases(monkeypatch, worker):
    """Apply common monkeypatches for StaticWorker phase methods."""
    phases_run = []
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: phases_run.append("resolve_proxy"))
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_dependency_phase", lambda *a, **kw: phases_run.append("dependency"))
    monkeypatch.setattr(worker, "_run_static_facts_phase", lambda *a, **kw: phases_run.append("analysis") or True)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    return phases_run


def _patch_static_worker_non_dep_phases(monkeypatch, worker):
    """Patch StaticWorker phases that are NOT the dependency phase."""
    phases_run = []
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: phases_run.append("resolve_proxy"))
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_static_facts_phase", lambda *a, **kw: phases_run.append("analysis") or True)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    return phases_run
