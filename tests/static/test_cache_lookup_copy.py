from __future__ import annotations

from tests.cache_helpers import (
    ADDR_A,
    _create_completed_job_with_static_data,
    db_session,  # noqa: F401
    requires_postgres,
)

pytestmark = requires_postgres


def test_find_completed_static_cache_picks_most_recent(db_session):
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


def test_copy_returns_early_if_target_already_populated(db_session):
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


def test_copy_row_shallow_copies_lists(db_session):
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
