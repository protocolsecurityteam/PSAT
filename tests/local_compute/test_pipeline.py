"""Cross-host lifecycle simulation with real queue/DB/storage and stub analysis."""

import uuid

import pytest
from sqlalchemy.orm import Session, sessionmaker

from db.models import Artifact, JobStage, JobStatus, MonitoredContract
from db.queue import claim_job, create_job, store_artifact
from services.monitoring.reanalysis import maybe_queue_reanalysis, reconcile_pending_reanalysis
from workers.coverage_worker import CoverageWorker
from workers.effects_worker import EffectsWorker
from workers.policy_worker import PolicyWorker
from workers.resolution_worker import ResolutionWorker
from workers.static_worker import StaticWorker


@pytest.mark.parametrize("effects", [False, True])
def test_local_pipeline_returns_to_cloud_and_reconciles_pending_trigger(
    db_session, storage_bucket, monkeypatch, effects
):
    monkeypatch.setenv("PSAT_LOCAL_COMPUTE_ROUTING_ENABLED", "1")
    monkeypatch.setenv("PSAT_EFFECTS_STAGE", "1" if effects else "0")
    address = "0x" + uuid.uuid4().hex + "12345678"
    job = create_job(
        db_session, {"address": address, "chain": "ethereum"}, initial_stage=JobStage.static, compute_target="local"
    )
    monitored = MonitoredContract(address=address, chain="ethereum")
    assert maybe_queue_reanalysis(db_session, monitored, "upgraded") is None
    db_session.commit()
    classes = [StaticWorker, ResolutionWorker, PolicyWorker] + ([EffectsWorker] if effects else [])
    for worker_class in classes:
        monkeypatch.setenv("PSAT_COMPUTE_TARGET", "cloud")
        assert claim_job(db_session, worker_class.stage, "cloud") is None
        monkeypatch.setenv("PSAT_COMPUTE_TARGET", "local")
        with Session(db_session.get_bind()) as local_session:
            claimed = claim_job(local_session, worker_class.stage, "local")
            assert claimed is not None and claimed.id == job.id and claimed.lease_id is not None
            worker = worker_class()

            # Only the expensive analyzer is stubbed. BaseWorker output,
            # timing, dependency satisfaction, transitions and release are real.
            def analyze(session, current_job):
                store_artifact(session, current_job.id, "simulation_" + current_job.stage.value, data={"ok": True})

            monkeypatch.setattr(worker, "process", analyze)
            worker._execute_job(local_session, claimed)
        db_session.expire_all()
        assert job.status == JobStatus.queued
    db_session.refresh(job)
    assert job.stage == JobStage.coverage and job.compute_target == "cloud"
    monkeypatch.setenv("PSAT_COMPUTE_TARGET", "cloud")
    with Session(db_session.get_bind()) as production:
        coverage = CoverageWorker()
        claimed = coverage._claim_job(production)
        assert claimed is not None and claimed.id == job.id and claimed.lease_id is not None
        monkeypatch.setattr(coverage, "process", lambda session, current_job: None)
        coverage._execute_job(production, claimed)
    db_session.expire_all()
    assert job.status == JobStatus.completed and job.compute_target == "cloud"
    assert (
        db_session.query(Artifact).filter(Artifact.job_id == job.id, Artifact.name.like("stage_timing_%")).count()
        == len(classes) + 1
    )
    followups = reconcile_pending_reanalysis(db_session)
    db_session.commit()
    assert len(followups) == 1 and followups[0].compute_target == "cloud"
    assert followups[0].compute_group_id != job.compute_group_id
    assert reconcile_pending_reanalysis(db_session) == []


def test_direct_completion_publishes_diagnostics_before_clearing_lease(db_session, storage_bucket, monkeypatch):
    from db.queue import complete_job, get_artifact
    from utils.logging import record_degraded
    from workers.base import JobHandledDirectly

    # Diagnostic writes use an independent session against the same test DB.
    monkeypatch.setattr("workers.base.SessionLocal", sessionmaker(bind=db_session.get_bind()))
    job = create_job(db_session, {}, initial_stage=JobStage.static)
    claimed = claim_job(db_session, JobStage.static, "direct")
    assert claimed is not None
    worker = StaticWorker()

    def process(session, current_job):
        record_degraded(phase="test_direct", exc=RuntimeError("expected degradation"))
        worker._prepare_direct_transition(session, current_job)
        complete_job(session, current_job.id, lease_id=worker.claim_lease(current_job))
        raise JobHandledDirectly()

    monkeypatch.setattr(worker, "process", process)
    worker._execute_job(db_session, claimed)
    db_session.info.pop("job_attempt", None)
    timing = get_artifact(db_session, job.id, "stage_timing_static")
    errors = get_artifact(db_session, job.id, "stage_errors")
    assert isinstance(timing, dict) and timing["status"] == "handled_directly"
    assert isinstance(errors, dict) and errors["errors"][0]["phase"] == "test_direct"
    db_session.refresh(job)
    assert job.status == JobStatus.completed and job.lease_id is None
