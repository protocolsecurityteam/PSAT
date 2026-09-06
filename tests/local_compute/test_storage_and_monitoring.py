import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from db.attempts import JobAttempt, LeaseLost, bind_job_attempt
from db.models import Job, JobStage, MonitoredContract, MonitoringReanalysis, MonitoringReanalysisReceipt
from db.queue import claim_job, complete_job, create_job, get_artifact, store_artifact
from services.monitoring.reanalysis import maybe_queue_reanalysis, reconcile_pending_reanalysis


@pytest.mark.parametrize("source", [False, True])
def test_losing_object_cleanup_cannot_delete_winner(db_session, storage_bucket, monkeypatch, source):
    job = create_job(db_session, {}, initial_stage=JobStage.static)
    claimed = claim_job(db_session, JobStage.static, "first")
    assert claimed and claimed.lease_id
    from db.queue import get_source_files, store_source_files

    def publish(session, writer):
        if source:
            store_source_files(session, job.id, {"Test.sol": writer})
        else:
            store_artifact(session, job.id, "result", data={"writer": writer})

    old = JobAttempt(job.id, claimed.lease_id)
    put_done, resume = Event(), Event()
    actual_put = storage_bucket.put
    keys = []

    def paused_put(key, body, content_type, metadata=None):
        actual_put(key, body, content_type, metadata)
        keys.append(key)
        if b"stale" in body:
            put_done.set()
            assert resume.wait(5)

    monkeypatch.setattr(storage_bucket, "put", paused_put)

    def stale_writer():
        with Session(db_session.get_bind()) as session, bind_job_attempt(old):
            with pytest.raises(LeaseLost):
                publish(session, "stale")

    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(stale_writer)
        assert put_done.wait(5)
        winning_lease = uuid.uuid4()
        db_session.execute(update(Job).where(Job.id == job.id).values(lease_id=winning_lease))
        db_session.commit()
        with Session(db_session.get_bind()) as winner, bind_job_attempt(JobAttempt(job.id, winning_lease)):
            publish(winner, "winner")
        resume.set()
        future.result(5)
    assert len(set(keys)) == 2
    assert str(old.lease_id) in keys[0] and str(winning_lease) in keys[1]
    if source:
        assert get_source_files(db_session, job.id) == {"Test.sol": "winner"}
    else:
        assert get_artifact(db_session, job.id, "result") == {"writer": "winner"}
    assert b"winner" in storage_bucket.get(keys[1])
    from db.storage import StorageKeyMissing

    with pytest.raises(StorageKeyMissing):
        storage_bucket.get(keys[0])


def monitored():
    return MonitoredContract(
        address="0x" + uuid.uuid4().hex + "12345678", chain="ethereum", protocol_id=None, contract_id=None
    )


def test_parked_work_retains_coalesced_trigger(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_LOCAL_COMPUTE_ROUTING_ENABLED", "1")
    mc = monitored()
    parked = create_job(db_session, {"address": mc.address, "chain": mc.chain}, compute_target="local")
    assert maybe_queue_reanalysis(db_session, mc, "upgraded") is None
    assert maybe_queue_reanalysis(db_session, mc, "upgraded") is None
    db_session.commit()
    marker = db_session.get(MonitoringReanalysis, (1, mc.address))
    assert marker and marker.generation == 2 and marker.acknowledged_generation == 0
    claimed = claim_job(db_session, JobStage.discovery, "cloud-discovery")
    assert claimed and claimed.id == parked.id and claimed.lease_id
    complete_job(db_session, parked.id, lease_id=claimed.lease_id)
    created = reconcile_pending_reanalysis(db_session)
    assert len(created) == 1 and created[0].compute_target == "cloud"
    db_session.commit()
    assert reconcile_pending_reanalysis(db_session) == []
    assert db_session.get(MonitoringReanalysisReceipt, (1, mc.address, 2)).job_id == created[0].id


@pytest.mark.parametrize("crash", ["before_commit", "after_commit"])
def test_monitoring_generation_is_atomic_under_crash(db_session, crash):
    mc = monitored()
    job = maybe_queue_reanalysis(db_session, mc, "upgraded")
    assert job is not None
    if crash == "before_commit":
        db_session.rollback()
        assert db_session.get(Job, job.id) is None
        # The event transaction is replayed after rollback.
        job = maybe_queue_reanalysis(db_session, mc, "upgraded")
    db_session.commit()
    assert reconcile_pending_reanalysis(db_session) == []
    assert len(db_session.execute(select(Job).where(Job.address == mc.address)).scalars().all()) == 1
    assert (
        len(
            db_session.execute(
                select(MonitoringReanalysisReceipt).where(MonitoringReanalysisReceipt.address == mc.address)
            )
            .scalars()
            .all()
        )
        == 1
    )


def test_two_reconcilers_and_new_generation(db_session):
    mc = monitored()
    # A durable pending generation exists independently of an event publisher.
    db_session.add(
        MonitoringReanalysis(chain_id=1, address=mc.address, request={"address": mc.address, "chain": mc.chain})
    )
    db_session.commit()
    barrier = Barrier(2)

    def reconcile(_):
        with Session(db_session.get_bind()) as session:
            barrier.wait(5)
            jobs = reconcile_pending_reanalysis(session)
            session.commit()
            return len(jobs)

    with ThreadPoolExecutor(2) as pool:
        assert sum(pool.map(reconcile, range(2))) == 1
    assert maybe_queue_reanalysis(db_session, mc, "upgraded") is None
    db_session.commit()
    db_session.expire_all()
    marker = db_session.get(MonitoringReanalysis, (1, mc.address))
    assert marker and marker.generation == 2 and marker.acknowledged_generation == 1


def test_trigger_arriving_during_acknowledgment_survives(db_session):
    mc = monitored()
    db_session.add(
        MonitoringReanalysis(chain_id=1, address=mc.address, request={"address": mc.address, "chain": mc.chain})
    )
    db_session.commit()
    inserted, commit = Event(), Event()

    def consume():
        with Session(db_session.get_bind()) as session:
            assert len(reconcile_pending_reanalysis(session)) == 1
            inserted.set()
            assert commit.wait(5)
            session.commit()

    def trigger():
        with Session(db_session.get_bind()) as session:
            maybe_queue_reanalysis(session, mc, "upgraded")
            session.commit()

    with ThreadPoolExecutor(2) as pool:
        consumer = pool.submit(consume)
        assert inserted.wait(5)
        producer = pool.submit(trigger)
        assert not producer.done()
        commit.set()
        consumer.result(5)
        producer.result(5)
    marker = db_session.get(MonitoringReanalysis, (1, mc.address))
    assert marker and (marker.generation, marker.acknowledged_generation) == (2, 1)
