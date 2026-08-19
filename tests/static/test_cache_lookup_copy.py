"""Tests for cache lookup (find_completed_static_cache), copy_static_cache,
copy_row, data isolation, idempotency, and no-duplicate guarantees."""

from __future__ import annotations

from unittest.mock import MagicMock

from cache_helpers import (
    ADDR_A,
    ADDR_B,
    _create_completed_job_with_static_data,
    db_session,  # noqa: F401
    requires_postgres,
)

pytestmark = requires_postgres

# ---------------------------------------------------------------------------
# 1. Cache lookup tests
# ---------------------------------------------------------------------------


def test_find_completed_static_cache_hit(db_session):
    """Completed job with all static data is found."""
    from db.queue import find_completed_static_cache

    completed = _create_completed_job_with_static_data(db_session)
    found = find_completed_static_cache(db_session, ADDR_A)
    assert found is not None
    assert found.id == completed.id


def test_find_completed_static_cache_case_insensitive(db_session):
    """Cache lookup matches regardless of address casing."""
    from db.queue import find_completed_static_cache

    checksummed = ADDR_A
    completed = _create_completed_job_with_static_data(db_session, address=checksummed)
    found = find_completed_static_cache(db_session, checksummed.lower())
    assert found is not None
    assert found.id == completed.id


def test_find_completed_static_cache_miss_no_job(db_session):
    """No prior jobs for this address returns None."""
    from db.queue import find_completed_static_cache

    assert find_completed_static_cache(db_session, ADDR_B) is None


def test_find_completed_static_cache_miss_failed_job(db_session):
    """Failed job is not returned as cache."""
    from db.models import JobStatus
    from db.queue import create_job, find_completed_static_cache

    job = create_job(db_session, {"address": ADDR_A})
    job.status = JobStatus.failed
    db_session.commit()

    assert find_completed_static_cache(db_session, ADDR_A) is None


def test_find_completed_static_cache_miss_no_analysis(db_session):
    """Completed job without contract_analysis artifact is not returned."""
    from db.models import Contract, ContractSummary, JobStage, JobStatus
    from db.queue import create_job, find_completed_static_cache, store_source_files

    job = create_job(db_session, {"address": ADDR_A})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    db_session.commit()

    contract = Contract(job_id=job.id, address=ADDR_A, contract_name="X")
    db_session.add(contract)
    db_session.flush()
    db_session.add(ContractSummary(contract_id=contract.id))
    db_session.commit()
    store_source_files(db_session, job.id, {"src/X.sol": "contract X {}"})

    assert find_completed_static_cache(db_session, ADDR_A) is None


def test_find_completed_static_cache_hit_for_proxy_without_contract_analysis(db_session):
    """Regression: proxies never produce ``contract_analysis`` on their
    own job — that artifact only shows up on the impl child. The cache
    lookup must still return the proxy's completed job so the next
    company-discovery run can reuse its static data instead of re-
    fetching source from Etherscan and re-running slither for every
    proxy it sees.

    Before the fix, proxies required ``contract_analysis`` to be served
    from cache; none of them met that bar, so every re-discovery of a
    protocol did a full fresh fetch for every proxy row.
    """
    from db.models import Contract, ContractSummary, JobStage, JobStatus
    from db.queue import create_job, find_completed_static_cache, store_artifact, store_source_files

    job = create_job(db_session, {"address": ADDR_A})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    db_session.commit()

    contract = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="UUPSProxy",
        is_proxy=True,
        proxy_type="eip1967",
        implementation="0x" + "b" * 40,
    )
    db_session.add(contract)
    db_session.flush()
    db_session.add(ContractSummary(contract_id=contract.id))
    db_session.commit()
    store_source_files(db_session, job.id, {"src/Proxy.sol": "contract P {}"})
    # Proxy jobs write contract_flags (is_proxy=True + proxy_type) instead
    # of contract_analysis — the latter lives on the impl child's job.
    store_artifact(db_session, job.id, "contract_flags", data={"is_proxy": True, "proxy_type": "eip1967"})

    found = find_completed_static_cache(db_session, ADDR_A)
    assert found is not None
    assert found.id == job.id


def test_find_completed_static_cache_miss_no_summary(db_session):
    """Completed job without contract_summaries row is not returned."""
    from db.models import Contract, JobStage, JobStatus
    from db.queue import create_job, find_completed_static_cache, store_artifact, store_source_files

    job = create_job(db_session, {"address": ADDR_A})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    db_session.commit()

    db_session.add(Contract(job_id=job.id, address=ADDR_A, contract_name="X"))
    db_session.commit()
    store_source_files(db_session, job.id, {"src/X.sol": "contract X {}"})
    store_artifact(db_session, job.id, "contract_analysis", data={"summary": {}})

    assert find_completed_static_cache(db_session, ADDR_A) is None


def test_find_completed_static_cache_picks_most_recent(db_session):
    """When multiple completed jobs exist for the same address, the most
    recently updated one is returned."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import update

    from db.models import Contract, ContractSummary, Job, JobStage, JobStatus
    from db.queue import create_job, find_completed_static_cache, store_artifact, store_source_files

    _create_completed_job_with_static_data(db_session, address=ADDR_A)

    new_job = create_job(db_session, {"address": ADDR_A, "name": "TestContract2"})
    new_job.status = JobStatus.completed
    new_job.stage = JobStage.done
    db_session.commit()

    contract = Contract(job_id=new_job.id, address=ADDR_A, chain="ethereum", contract_name="TestContract2")
    db_session.add(contract)
    db_session.flush()
    db_session.add(ContractSummary(contract_id=contract.id))
    db_session.commit()
    store_source_files(db_session, new_job.id, {"src/T.sol": "contract T {}"})
    store_artifact(db_session, new_job.id, "contract_analysis", data={"summary": {}})

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    db_session.execute(update(Job).where(Job.id == new_job.id).values(updated_at=future))
    db_session.commit()

    found = find_completed_static_cache(db_session, ADDR_A)
    assert found is not None
    assert found.id == new_job.id


# ---------------------------------------------------------------------------
# 2. Cache copy tests
# ---------------------------------------------------------------------------


def test_copy_static_cache(db_session):
    """copy_static_cache duplicates all static data into a new job."""
    from sqlalchemy import select

    from db.models import Contract, ContractSummary, RoleDefinition
    from db.queue import copy_static_cache, create_job, get_artifact, get_source_files, store_artifact

    source_job = _create_completed_job_with_static_data(db_session)
    predicate_trees = {"schema_version": "semantic", "trees": {"pause()": {"node_type": "caller"}}}
    effects = {"schema_version": "semantic", "effects": {"pause()": [{"kind": "external_call"}]}}
    store_artifact(db_session, source_job.id, "predicate_trees", data=predicate_trees)
    store_artifact(db_session, source_job.id, "effects", data=effects)
    target_job = create_job(db_session, {"address": ADDR_A})

    new_contract_id = copy_static_cache(db_session, source_job.id, target_job.id)
    assert new_contract_id is not None

    target_contract = db_session.execute(select(Contract).where(Contract.job_id == target_job.id)).scalar_one_or_none()
    assert target_contract is not None
    assert target_contract.contract_name == "TestContract"
    assert target_contract.compiler_version == "v0.8.24"
    assert target_contract.is_proxy is False
    assert target_contract.proxy_type is None
    assert target_contract.implementation is None

    sources = get_source_files(db_session, target_job.id)
    assert len(sources) == 2
    assert "src/TestContract.sol" in sources

    summary = db_session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == new_contract_id)
    ).scalar_one_or_none()
    assert summary is not None
    assert summary.control_model == "ownable"

    rds = (
        db_session.execute(select(RoleDefinition).where(RoleDefinition.contract_id == new_contract_id)).scalars().all()
    )
    assert len(rds) == 1
    assert rds[0].role_name == "ADMIN_ROLE"

    assert get_artifact(db_session, target_job.id, "contract_analysis") is not None
    assert get_artifact(db_session, target_job.id, "predicate_trees") == predicate_trees
    assert get_artifact(db_session, target_job.id, "effects") == effects
    # slither_results / analysis_report were removed from the static-artifact
    # cache copy set when the Slither CLI subprocess was excised — they no
    # longer participate in caching since they're no longer produced.
    assert get_artifact(db_session, target_job.id, "control_tracking_plan") is not None
    assert get_artifact(db_session, target_job.id, "contract_flags") is None


# ---------------------------------------------------------------------------
# Data isolation
# ---------------------------------------------------------------------------


def test_data_isolation_after_cache_copy(db_session):
    """Deleting the source job does not affect the copied data."""
    from sqlalchemy import select

    from db.models import Contract, ContractSummary, Job
    from db.queue import copy_static_cache, create_job, get_artifact, get_source_files

    source_job = _create_completed_job_with_static_data(db_session)
    target_job = create_job(db_session, {"address": ADDR_A})

    new_contract_id = copy_static_cache(db_session, source_job.id, target_job.id)
    assert new_contract_id is not None

    db_session.delete(db_session.get(Job, source_job.id))
    db_session.commit()

    target_contract = db_session.execute(select(Contract).where(Contract.job_id == target_job.id)).scalar_one_or_none()
    assert target_contract is not None
    assert target_contract.contract_name == "TestContract"

    sources = get_source_files(db_session, target_job.id)
    assert len(sources) == 2

    summary = db_session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == new_contract_id)
    ).scalar_one_or_none()
    assert summary is not None

    assert get_artifact(db_session, target_job.id, "contract_analysis") is not None


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_copy_returns_early_if_target_already_populated(db_session):
    """Second call to copy_static_cache returns existing ID without duplicating."""
    from sqlalchemy import func, select

    from db.models import Contract, ContractSummary
    from db.queue import copy_static_cache, create_job

    source_job = _create_completed_job_with_static_data(db_session)
    target_job = create_job(db_session, {"address": ADDR_A})

    id1 = copy_static_cache(db_session, source_job.id, target_job.id)
    assert id1 is not None

    id2 = copy_static_cache(db_session, source_job.id, target_job.id)
    assert id2 == id1

    count = db_session.execute(
        select(func.count()).select_from(Contract).where(Contract.job_id == target_job.id)
    ).scalar()
    assert count == 1, f"Expected 1 contract row after double copy, got {count}"

    summary_count = db_session.execute(
        select(func.count()).select_from(ContractSummary).where(ContractSummary.contract_id == id1)
    ).scalar()
    assert summary_count == 1, f"Expected 1 summary after double copy, got {summary_count}"


# ---------------------------------------------------------------------------
# No duplicate rows
# ---------------------------------------------------------------------------


def test_no_duplicate_rows_after_two_runs(db_session, monkeypatch):
    """Running discovery twice for the same address produces exactly one set of
    static rows per job -- no duplicates within either job."""
    from sqlalchemy import func, select

    from db.models import Contract, ContractSummary, RoleDefinition, SourceFile
    from db.queue import create_job, get_artifact
    from workers.discovery import DiscoveryWorker

    _create_completed_job_with_static_data(db_session)

    new_job = create_job(db_session, {"address": ADDR_A})
    monkeypatch.setattr(
        "workers.discovery.fetch",
        lambda addr: (_ for _ in ()).throw(AssertionError("fetch should not be called")),
    )

    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    worker._process_address(db_session, new_job)

    new_contract = db_session.execute(select(Contract).where(Contract.job_id == new_job.id)).scalar_one()

    summary_count = db_session.execute(
        select(func.count()).select_from(ContractSummary).where(ContractSummary.contract_id == new_contract.id)
    ).scalar()
    assert summary_count == 1, f"Expected 1 summary, got {summary_count}"

    rd_count = db_session.execute(
        select(func.count()).select_from(RoleDefinition).where(RoleDefinition.contract_id == new_contract.id)
    ).scalar()
    assert rd_count == 1, f"Expected 1 role definition, got {rd_count}"

    src_count = db_session.execute(
        select(func.count()).select_from(SourceFile).where(SourceFile.job_id == new_job.id)
    ).scalar()
    assert src_count == 2, f"Expected 2 source files, got {src_count}"

    for artifact_name in ["contract_analysis", "control_tracking_plan"]:
        art = get_artifact(db_session, new_job.id, artifact_name)
        assert isinstance(art, dict), f"Missing artifact {artifact_name}"


# ---------------------------------------------------------------------------
# copy_row unit tests
# ---------------------------------------------------------------------------


def test_copy_row_skips_primary_key(db_session):
    """copy_row does not copy the primary key column."""
    from db.models import Contract
    from db.queue import copy_row, create_job

    job = create_job(db_session, {"address": ADDR_A})
    original = Contract(
        job_id=job.id,
        address=ADDR_A,
        chain="ethereum",
        contract_name="Original",
        compiler_version="v0.8.24",
        language="solidity",
    )
    db_session.add(original)
    db_session.flush()

    cloned = copy_row(db_session, original, job_id=job.id, address=ADDR_A, chain="base")
    assert isinstance(cloned, Contract)
    db_session.flush()

    assert cloned.id != original.id
    assert cloned.contract_name == "Original"


def test_copy_row_skips_server_defaults(db_session):
    """copy_row does not copy columns with server_default (e.g. created_at)."""
    from db.models import Contract
    from db.queue import copy_row, create_job

    job = create_job(db_session, {"address": ADDR_A})
    original = Contract(
        job_id=job.id,
        address=ADDR_A,
        chain="ethereum",
        contract_name="Original",
    )
    db_session.add(original)
    db_session.flush()

    cloned = copy_row(db_session, original, job_id=job.id, address=ADDR_A, chain="base")
    assert isinstance(cloned, Contract)
    db_session.flush()

    assert cloned.is_proxy is not None


def test_copy_row_applies_overrides(db_session):
    """copy_row applies keyword overrides instead of copying from source."""
    from db.models import Contract
    from db.queue import copy_row, create_job

    job1 = create_job(db_session, {"address": ADDR_A})
    job2 = create_job(db_session, {"address": ADDR_A})
    original = Contract(
        job_id=job1.id,
        address=ADDR_A,
        chain="ethereum",
        contract_name="Original",
    )
    db_session.add(original)
    db_session.flush()

    cloned = copy_row(db_session, original, job_id=job2.id, contract_name="Cloned", address=ADDR_A, chain="base")
    assert isinstance(cloned, Contract)
    db_session.flush()

    assert cloned.job_id == job2.id
    assert cloned.contract_name == "Cloned"


def test_copy_row_respects_exclude(db_session):
    """copy_row excludes specified columns."""
    from db.models import Contract
    from db.queue import copy_row, create_job

    job = create_job(db_session, {"address": ADDR_A})
    original = Contract(
        job_id=job.id,
        address=ADDR_A,
        chain="ethereum",
        contract_name="Original",
        compiler_version="v0.8.24",
        language="solidity",
    )
    db_session.add(original)
    db_session.flush()

    cloned = copy_row(
        db_session,
        original,
        job_id=job.id,
        address=ADDR_A,
        chain="base",
        exclude=frozenset({"compiler_version", "language"}),
    )
    assert isinstance(cloned, Contract)
    db_session.flush()

    assert cloned.compiler_version is None
    assert cloned.language is None
    assert cloned.contract_name == "Original"


def test_copy_row_shallow_copies_lists(db_session):
    """copy_row shallow-copies list values so mutations are independent."""
    from db.models import Contract
    from db.queue import copy_row, create_job

    job = create_job(db_session, {"address": ADDR_A})
    original = Contract(
        job_id=job.id,
        address=ADDR_A,
        chain="ethereum",
        contract_name="Original",
        remappings=["a=b", "c=d"],
    )
    db_session.add(original)
    db_session.flush()

    cloned = copy_row(db_session, original, job_id=job.id, address=ADDR_A, chain="base")
    assert isinstance(cloned, Contract)
    db_session.flush()

    assert cloned.remappings is not None
    assert cloned.remappings == ["a=b", "c=d"]
    cloned.remappings.append("e=f")
    assert original.remappings == ["a=b", "c=d"]
