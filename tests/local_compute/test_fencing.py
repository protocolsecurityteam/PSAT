"""Real Postgres fencing and group races; never mocks the transaction boundary."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from db.attempts import JobAttempt, LeaseLost, bind_job_attempt
from db.compute import ComputeGroupBusy, move_group_to_cloud, reactivate_terminal_job
from db.models import Artifact, Contract, Job, JobDependency, JobStage, JobStatus
from db.queue import (
    advance_job,
    claim_job,
    complete_job,
    create_job,
    get_artifact,
    reclaim_stuck_jobs,
    requeue_job,
    store_artifact,
    store_source_files,
)


@pytest.fixture(autouse=True)
def routing(monkeypatch):
    monkeypatch.setenv("PSAT_LOCAL_COMPUTE_ROUTING_ENABLED", "1")
    monkeypatch.setenv("PSAT_COMPUTE_TARGET", "cloud")


def claim(session, *, stage=JobStage.static, target="cloud"):
    job = create_job(
        session,
        {"address": "0x" + uuid.uuid4().hex + "12345678", "chain": "ethereum"},
        initial_stage=stage,
        compute_target=target,
    )
    if target == "local":
        # Scope the worker target to one call, never race process environment.
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("PSAT_COMPUTE_TARGET", "local")
            claimed = claim_job(session, stage, "test-local")
    else:
        claimed = claim_job(session, stage, "test-cloud")
    assert claimed is not None and job.lease_id is not None
    assert claimed.id == job.id
    return job, JobAttempt(job.id, job.lease_id)


@pytest.mark.parametrize("stage", [JobStage.static, JobStage.resolution, JobStage.policy, JobStage.effects])
def test_target_isolation_and_skip_locked(db_session, stage, monkeypatch):
    cloud = create_job(db_session, {}, initial_stage=stage)
    local = create_job(db_session, {}, initial_stage=stage, compute_target="local")
    claimed = claim_job(db_session, stage, "cloud")
    assert claimed is not None and claimed.id == cloud.id
    assert claim_job(db_session, stage, "cloud") is None
    monkeypatch.setenv("PSAT_COMPUTE_TARGET", "local")
    claimed = claim_job(db_session, stage, "local")
    assert claimed is not None and claimed.id == local.id
    assert claim_job(db_session, stage, "local") is None


def test_competing_claims_have_one_winner(db_session):
    job = create_job(db_session, {}, initial_stage=JobStage.static)
    barrier = Barrier(2)

    def take(_):
        with Session(db_session.get_bind()) as session:
            barrier.wait(timeout=5)
            row = claim_job(session, JobStage.static, str(uuid.uuid4()))
            return row.id if row else None

    with ThreadPoolExecutor(2) as pool:
        result = list(pool.map(take, range(2)))
    assert result.count(job.id) == 1
    assert result.count(None) == 1


@pytest.mark.parametrize("kind", ["artifact", "source", "normalized", "dependency", "child", "timing", "errors"])
def test_stale_output_transaction_cannot_publish(db_session, kind):
    job, attempt = claim(db_session)
    with Session(db_session.get_bind()) as stale:
        stale_job = stale.get(Job, job.id)  # deliberately cached old lease
        db_session.execute(update(Job).where(Job.id == job.id).values(lease_id=uuid.uuid4()))
        db_session.commit()
        with bind_job_attempt(attempt), pytest.raises(LeaseLost):
            if kind in {"artifact", "timing", "errors"}:
                name = {"artifact": "test", "timing": "stage_timing_static", "errors": "stage_errors"}[kind]
                store_artifact(stale, job.id, name, data={"stale": True})
            elif kind == "source":
                store_source_files(stale, job.id, {"Test.sol": "stale"})
            elif kind == "normalized":
                stale.add(Contract(address=job.address, chain="ethereum", job_id=job.id))
                stale.commit()
            elif kind == "dependency":
                stale.add(
                    JobDependency(
                        depender_job_id=job.id,
                        provider_chain="ethereum",
                        provider_address=job.address,
                        required_stage=JobStage.policy,
                    )
                )
                stale.commit()
            else:
                create_job(stale, {}, routing_from=stale_job)
        stale.rollback()
    assert db_session.execute(select(Artifact).where(Artifact.job_id == job.id)).first() is None
    assert db_session.execute(select(Contract).where(Contract.job_id == job.id)).first() is None
    assert db_session.execute(select(JobDependency).where(JobDependency.depender_job_id == job.id)).first() is None


@pytest.mark.parametrize("operation", ["advance", "complete", "retry"])
def test_cached_orm_and_cleared_lease_cannot_change_lifecycle(db_session, operation):
    job, attempt = claim(db_session)
    with Session(db_session.get_bind()) as stale:
        stale.get(Job, job.id)
        db_session.execute(update(Job).where(Job.id == job.id).values(status=JobStatus.completed, lease_id=None))
        db_session.commit()
        with pytest.raises(LeaseLost):
            if operation == "advance":
                advance_job(stale, job.id, JobStage.policy, lease_id=attempt.lease_id)
            elif operation == "complete":
                complete_job(stale, job.id, lease_id=attempt.lease_id)
            else:
                requeue_job(
                    stale,
                    job.id,
                    "stale",
                    retry_count=1,
                    next_attempt_at=datetime.now(timezone.utc),
                    lease_id=attempt.lease_id,
                )


@pytest.mark.parametrize("stage", [JobStage.policy, JobStage.effects])
def test_handoff_is_atomic_and_clears_local_affinity(db_session, stage):
    job, attempt = claim(db_session, stage=stage, target="local")
    with bind_job_attempt(attempt):
        store_artifact(db_session, job.id, "test", data={"ok": True})
        advance_job(db_session, job.id, JobStage.coverage, lease_id=attempt.lease_id)
        with pytest.raises(LeaseLost):
            store_artifact(db_session, job.id, "late", data={"bad": True})
        db_session.rollback()
    db_session.info.pop("job_attempt", None)
    db_session.refresh(job)
    assert job.stage == JobStage.coverage and job.compute_target == "cloud" and job.lease_id is None
    claimed = claim_job(db_session, JobStage.coverage, "coverage")
    assert claimed is not None and claimed.id == job.id


def test_group_recovery_refuses_active_and_preserves_stage_retry_dependencies(db_session):
    job, attempt = claim(db_session, target="local")
    with bind_job_attempt(attempt):
        child = create_job(db_session, {}, routing_from=job)
    db_session.info.pop("job_attempt", None)
    assert child.compute_group_id == job.compute_group_id and child.compute_target == "local"
    with pytest.raises(ComputeGroupBusy):
        move_group_to_cloud(db_session, job.id)
    db_session.rollback()
    db_session.execute(
        update(Job).where(Job.id == job.id).values(lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    db_session.commit()
    assert str(job.id) in reclaim_stuck_jobs(db_session)
    db_session.refresh(job)
    assert job.compute_target == "local"
    assert move_group_to_cloud(db_session, job.id) == 2
    db_session.commit()
    db_session.refresh(child)
    assert child.compute_target == "cloud" and child.stage == JobStage.discovery
    with bind_job_attempt(attempt), pytest.raises(LeaseLost):
        create_job(db_session, {}, routing_from=job)
    db_session.rollback()
    db_session.info.pop("job_attempt", None)


def test_system_reactivation_rechecks_terminal_state(db_session):
    job, attempt = claim(db_session)
    complete_job(db_session, job.id, lease_id=attempt.lease_id)
    with Session(db_session.get_bind()) as other:
        old = other.get(Job, job.id)
        assert reactivate_terminal_job(
            db_session, job.id, expected_stage=JobStage.done, next_stage=JobStage.static, detail="winner"
        )
        db_session.commit()
        assert old is not None and old.stage == JobStage.done
        assert not reactivate_terminal_job(
            other, job.id, expected_stage=JobStage.done, next_stage=JobStage.policy, detail="loser"
        )
        other.commit()
    db_session.refresh(job)
    assert job.stage == JobStage.static and job.detail == "winner"


def test_commit_fence_locks_until_transaction_finishes(db_session):
    job, attempt = claim(db_session)
    entered, release = Event(), Event()

    def writer():
        with Session(db_session.get_bind()) as session, bind_job_attempt(attempt):
            from db.attempts import assert_current_job_attempt

            assert_current_job_attempt(session, job.id, attempt.lease_id)
            session.add(Artifact(job_id=job.id, name="winner", data={"ok": True}))
            entered.set()
            assert release.wait(5)
            session.commit()

    def rollover():
        with Session(db_session.get_bind()) as session:
            session.execute(text("SET LOCAL lock_timeout = '300ms'"))
            session.execute(update(Job).where(Job.id == job.id).values(lease_id=uuid.uuid4()))
            session.commit()

    with ThreadPoolExecutor(2) as pool:
        future = pool.submit(writer)
        assert entered.wait(5)
        from sqlalchemy.exc import OperationalError

        with pytest.raises(OperationalError, match="lock timeout"):
            rollover()
        release.set()
        future.result(5)
    assert get_artifact(db_session, job.id, "winner") == {"ok": True}


def test_group_move_races_claim_without_stealing(db_session, monkeypatch):
    job = create_job(db_session, {}, initial_stage=JobStage.static, compute_target="local")
    monkeypatch.setenv("PSAT_COMPUTE_TARGET", "local")
    barrier = Barrier(2)

    def take():
        with Session(db_session.get_bind()) as session:
            barrier.wait(5)
            result = claim_job(session, JobStage.static, "local")
            return result.id if result else None

    def move():
        with Session(db_session.get_bind()) as session:
            barrier.wait(5)
            try:
                result = move_group_to_cloud(session, job.id)
                session.commit()
                return result
            except ComputeGroupBusy:
                session.rollback()
                return None

    with ThreadPoolExecutor(2) as pool:
        taken, moved = pool.submit(take), pool.submit(move)
        taken, moved = taken.result(5), moved.result(5)
    assert (taken, moved) in {(job.id, None), (None, 1)}


def test_new_child_cannot_escape_recovered_group(db_session, monkeypatch):
    import db.compute as compute

    job, attempt = claim(db_session, target="local")
    before_lock, resume = Event(), Event()
    original = compute.lock_compute_groups

    def paused_lock(session, *groups):
        if session.info.get("pause_group"):
            before_lock.set()
            assert resume.wait(5)
        return original(session, *groups)

    monkeypatch.setattr(compute, "lock_compute_groups", paused_lock)

    def child():
        with Session(db_session.get_bind()) as session, bind_job_attempt(attempt):
            session.info["pause_group"] = True
            parent = session.get(Job, job.id)
            with pytest.raises(LeaseLost):
                create_job(session, {}, routing_from=parent)

    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(child)
        assert before_lock.wait(5)
        db_session.execute(
            update(Job)
            .where(Job.id == job.id)
            .values(lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        )
        db_session.commit()
        reclaim_stuck_jobs(db_session)
        assert move_group_to_cloud(db_session, job.id) == 1
        db_session.commit()
        resume.set()
        future.result(5)
    rows = db_session.execute(select(Job).where(Job.compute_group_id == job.compute_group_id)).scalars().all()
    assert len(rows) == 1
    db_session.refresh(rows[0])
    assert rows[0].compute_target == "cloud"


def test_child_cannot_borrow_unrelated_attempt(db_session):
    first, attempt = claim(db_session)
    other = create_job(db_session, {})
    with bind_job_attempt(attempt), pytest.raises(LeaseLost):
        create_job(db_session, {}, routing_from=other)
    db_session.rollback()


def test_stale_destructive_replacement_rolls_back_and_preserves_winner(db_session):
    from sqlalchemy import delete

    job, attempt = claim(db_session)
    row = Contract(address=job.address, chain="ethereum", job_id=job.id, contract_name="winner")
    db_session.add(row)
    db_session.commit()
    row_id = row.id
    db_session.execute(update(Job).where(Job.id == job.id).values(lease_id=uuid.uuid4()))
    db_session.commit()
    with Session(db_session.get_bind()) as stale, bind_job_attempt(attempt):
        stale.execute(delete(Contract).where(Contract.id == row_id))
        stale.add(Contract(address=job.address, chain="ethereum", job_id=job.id, contract_name="stale"))
        with pytest.raises(LeaseLost):
            stale.commit()
        stale.rollback()
    db_session.expire_all()
    preserved = db_session.get(Contract, row_id)
    assert preserved is not None and preserved.contract_name == "winner"


def test_competing_proxy_contexts_preserve_winner_and_spawn_other_deployment(db_session, monkeypatch):
    import db.compute as compute
    from db.queue import reconcile_impl_job_for_proxy

    first, first_attempt = claim(db_session)
    second, second_attempt = claim(db_session, target="local")
    candidate = create_job(db_session, {"address": "0x" + uuid.uuid4().hex + "12345678", "chain": "ethereum"})
    candidate.status = JobStatus.completed
    candidate.stage = JobStage.done
    db_session.commit()
    barrier = Barrier(2)
    original = compute.reactivate_terminal_job

    def competing(*args, **kwargs):
        barrier.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(compute, "reactivate_terminal_job", competing)

    def adopt(attempt):
        with Session(db_session.get_bind()) as session, bind_job_attempt(attempt):
            parent = session.get(Job, attempt.job_id)
            assert parent is not None and parent.address is not None and candidate.address is not None
            result = reconcile_impl_job_for_proxy(
                session, impl_addr=candidate.address, proxy_addr=parent.address, chain="ethereum", routing_from=parent
            )
            session.commit()
            return parent.id, result

    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(adopt, [first_attempt, second_attempt]))
    assert sorted(result for _, result in outcomes) == ["backpatched", "spawn"]
    winner_id = next(id for id, result in outcomes if result == "backpatched")
    db_session.expire_all()
    winner = db_session.get(Job, winner_id)
    assert winner is not None
    assert candidate.compute_group_id == winner.compute_group_id
    assert candidate.compute_target == winner.compute_target
    assert candidate.request is not None and candidate.request["proxy_address"] == winner.address
