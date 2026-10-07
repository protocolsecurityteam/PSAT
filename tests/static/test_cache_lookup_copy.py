from __future__ import annotations

import pytest

from tests.cache_helpers import (
    ADDR_A,
    _create_completed_job_with_static_data,
    db_session,  # noqa: F401
    requires_postgres,
)

pytestmark = requires_postgres


@pytest.mark.parametrize("artifact_name", ["predicate_trees", "effects"])
@pytest.mark.parametrize(
    "invalid",
    [
        None,
        {},
        {"error": "extraction failed"},
        {"trees": [], "functions": []},
        "outdated",
        "unwitnessed",
        "incomplete_claims",
    ],
)
def test_find_completed_static_cache_picks_most_recent(db_session, artifact_name, invalid):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import delete, update

    from db.models import Artifact, Job
    from db.queue import find_completed_static_cache, store_artifact

    old_job = _create_completed_job_with_static_data(db_session, address=ADDR_A)
    new_job = _create_completed_job_with_static_data(db_session, address=ADDR_A)

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    db_session.execute(update(Job).where(Job.id == new_job.id).values(updated_at=future))
    db_session.commit()

    found = find_completed_static_cache(db_session, ADDR_A)
    assert found is not None
    assert found.id == new_job.id

    for bad, expected in [(new_job, old_job), (old_job, None)]:
        if invalid == "incomplete_claims":
            store_artifact(
                db_session,
                bad.id,
                "contract_analysis",
                data={"analysis_status": {"static_analysis_completed": True, "errors": ["claim matcher failed"]}},
            )
        elif isinstance(invalid, str):
            bad.analysis_schema_version = 0 if invalid == "outdated" else None
            db_session.commit()
        elif invalid is None:
            db_session.execute(delete(Artifact).where(Artifact.job_id == bad.id, Artifact.name == artifact_name))
            db_session.commit()
        else:
            store_artifact(db_session, bad.id, artifact_name, data=invalid)
        found = find_completed_static_cache(db_session, ADDR_A)
        assert (found.id if found else None) == (expected.id if expected else None)


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
