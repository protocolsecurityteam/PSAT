"""Real PostgreSQL gates, late arrivals, wake recovery and readiness parity."""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from db.models import Job, JobDependency, JobStage, JobStatus, Protocol
from db.queue import LeaseLost, advance_job, claim_job, complete_job, requeue_job
from services.worker_lifecycle import claim_allowed, register_boot
from services.worker_workload import snapshot
from tests.conftest import requires_postgres
from workers.lifecycle_controller import tick

pytestmark = requires_postgres


@pytest.fixture
def lifecycle(db_session, monkeypatch):
    boot = uuid.uuid4()
    db_session.execute(text("UPDATE worker_lifecycle SET paused=false, next_start_at=NULL WHERE id=1"))
    register_boot(db_session, boot, "abc123")
    monkeypatch.setenv("PSAT_WORKER_BOOT_ID", str(boot))
    yield db_session
    db_session.rollback()
    db_session.execute(text("UPDATE worker_lifecycle SET boot_id=NULL, phase='stopped', paused=true WHERE id=1"))
    db_session.commit()


def add_job(session, stage=JobStage.discovery, **kwargs):
    job = Job(id=uuid.uuid4(), stage=stage, status=JobStatus.queued, request={}, **kwargs)
    session.add(job)
    session.commit()
    return job


def age_idle(session):
    session.execute(
        text("""UPDATE worker_lifecycle SET idle_since=now()-interval '10 minutes',
        last_work_at=now()-interval '10 minutes', started_at=now()-interval '10 minutes' WHERE id=1""")
    )
    session.commit()


def decide(session, state="started", mode="enforce"):
    return tick(session, {"id": "abc123", "state": state}, mode=mode, grace=300)


@pytest.mark.parametrize("stage", [s for s in JobStage if s not in (JobStage.done, JobStage.dapp_crawl)])
def test_all_analysis_stages_wake_and_claim(lifecycle, stage, monkeypatch):
    session = lifecycle
    job = add_job(session, stage)
    assert "jobs" in snapshot(session).ready
    monkeypatch.setattr("signal.signal", lambda *_: None)
    if stage == JobStage.coverage:
        from workers.coverage_worker import CoverageWorker

        claimed = CoverageWorker()._claim_job(session)
    elif stage == JobStage.selection:
        from workers.selection_worker import SelectionWorker

        claimed = SelectionWorker()._claim_job(session)
    else:
        claimed = claim_job(session, stage, "test")
        assert claimed is not None
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.lease_id is not None
    assert snapshot(session).active
    complete_job(session, job.id, lease_id=claimed.lease_id)
    assert not snapshot(session).busy


def test_browser_does_not_wake_analysis(lifecycle):
    job = add_job(lifecycle, JobStage.dapp_crawl)
    assert not snapshot(lifecycle).busy
    job.status = JobStatus.processing
    lifecycle.commit()
    assert not snapshot(lifecycle).busy


def test_delayed_retry_sleeps_then_wakes_without_producer_ping(lifecycle):
    job = add_job(lifecycle)
    claimed = claim_job(lifecycle, job.stage, "test")
    assert claimed is not None
    requeue_job(
        lifecycle,
        job.id,
        "retry",
        retry_count=1,
        next_attempt_at=datetime.now(timezone.utc) + timedelta(hours=1),
        lease_id=claimed.lease_id,
    )
    age_idle(lifecycle)
    assert decide(lifecycle)["action"] == "drain"
    assert decide(lifecycle, "stopped")["action"] != "start"
    lifecycle.execute(text("UPDATE jobs SET next_attempt_at=now()-interval '1 second' WHERE id=:id"), {"id": job.id})
    lifecycle.commit()
    assert decide(lifecycle, "stopped")["action"] == "start"


def test_dependency_completion_wakes_without_notification(lifecycle):
    job = add_job(lifecycle)
    dep = JobDependency(
        depender_job_id=job.id, provider_address="0x" + "a" * 40, required_stage=JobStage.static, status="pending"
    )
    lifecycle.add(dep)
    lifecycle.commit()
    assert not snapshot(lifecycle).busy
    assert claim_job(lifecycle, job.stage, "test") is None
    dep.status = "satisfied"
    lifecycle.commit()
    assert decide(lifecycle, "stopped")["action"] == "start"


def test_enqueue_during_shutdown_waits_for_actual_stop(lifecycle):
    age_idle(lifecycle)
    assert decide(lifecycle)["action"] == "drain"
    add_job(lifecycle)
    assert claim_job(lifecycle, JobStage.discovery, "late") is None
    assert decide(lifecycle, "stopping")["action"] == "busy"
    assert decide(lifecycle, "started")["action"] == "busy"
    assert decide(lifecycle, "stopped")["action"] == "start"


def test_missed_start_or_controller_restart_retries_after_durable_cooldown(lifecycle):
    add_job(lifecycle)
    assert decide(lifecycle, "stopped")["action"] == "start"
    assert decide(lifecycle, "stopped")["action"] == "busy"
    lifecycle.execute(text("UPDATE worker_lifecycle SET next_start_at=now()-interval '1 second' WHERE id=1"))
    lifecycle.commit()
    assert decide(lifecycle, "stopped")["action"] == "start"


def test_stale_boot_cannot_claim(lifecycle):
    add_job(lifecycle)
    register_boot(lifecycle, uuid.uuid4(), "abc123")
    assert claim_job(lifecycle, JobStage.discovery, "old-boot") is None


@pytest.mark.parametrize("mode,paused", [("observe", False), ("enforce", True)])
def test_observation_and_pause_never_drain_or_start(lifecycle, mode, paused):
    lifecycle.execute(text("UPDATE worker_lifecycle SET paused=:paused WHERE id=1"), {"paused": paused})
    lifecycle.commit()
    age_idle(lifecycle)
    assert decide(lifecycle, mode=mode)["action"] == "would_drain"
    assert lifecycle.execute(text("SELECT phase FROM worker_lifecycle")).scalar_one() == "running"
    add_job(lifecycle)
    assert decide(lifecycle, "stopped", mode)["action"] == "would_start"


def test_claim_and_drain_serialized_in_postgres(lifecycle):
    age_idle(lifecycle)
    # Hold gate before inserting work, exactly as a claimer does. The
    # controller must wait, then observe the committed processing row.
    assert claim_allowed(lifecycle)
    result = []
    started = threading.Event()

    def controller():
        with Session(lifecycle.bind) as other:
            started.set()
            result.append(decide(other))

    thread = threading.Thread(target=controller)
    thread.start()
    assert started.wait(2)
    thread.join(0.05)
    assert thread.is_alive()
    job = Job(id=uuid.uuid4(), stage=JobStage.static, status=JobStatus.processing, request={})
    lifecycle.add(job)
    lifecycle.commit()
    thread.join(3)
    assert not thread.is_alive()
    assert result[0]["action"] == "busy"


def test_short_claim_resets_grace_even_between_samples(lifecycle):
    job = add_job(lifecycle)
    age_idle(lifecycle)
    claimed = claim_job(lifecycle, job.stage, "short")
    assert claimed is not None
    complete_job(lifecycle, job.id, lease_id=claimed.lease_id)
    assert decide(lifecycle)["action"] == "idle"


@pytest.mark.parametrize(
    "action,paused,phase",
    [
        ("status", False, "running"),
        ("pause", True, "running"),
        ("drain", True, "draining"),
        ("resume", False, "running"),
    ],
)
def test_operator_controls_preserve_boot_and_change_only_requested_state(
    lifecycle, monkeypatch, capsys, action, paused, phase
):
    import json

    from sqlalchemy.orm import sessionmaker

    from workers import lifecycle_admin

    boot = lifecycle.execute(text("SELECT boot_id FROM worker_lifecycle WHERE id=1")).scalar_one()
    lifecycle.commit()
    monkeypatch.setattr(lifecycle_admin, "SessionLocal", sessionmaker(lifecycle.bind))
    monkeypatch.setattr("sys.argv", ["lifecycle_admin", action])
    lifecycle_admin.main()
    state = json.loads(capsys.readouterr().out)
    assert state["boot_id"] == str(boot)
    assert state["paused"] is paused
    assert state["phase"] == phase
    assert claim_allowed(lifecycle) is (phase == "running")


def test_controller_recovers_failed_machine_read_and_starts_durable_work(lifecycle, monkeypatch):
    from unittest.mock import Mock

    from sqlalchemy.orm import sessionmaker

    from workers import lifecycle_controller

    add_job(lifecycle)
    monkeypatch.setenv("PSAT_WORKER_LIFECYCLE_MODE", "enforce")
    monkeypatch.setenv("PSAT_WORKER_LIFECYCLE_TOKEN", "test-token")
    monkeypatch.setattr(lifecycle_controller, "SessionLocal", sessionmaker(lifecycle.bind))
    fly = Mock()
    fly.target.side_effect = [TimeoutError(), {"id": "abc123", "state": "stopped"}]
    monkeypatch.setattr(lifecycle_controller, "FlyMachines", lambda: fly)
    heartbeat = Mock()
    monkeypatch.setattr(lifecycle_controller, "record_heartbeat", heartbeat)
    sweep = Mock()
    monkeypatch.setattr("services.monitoring.enrollment_schedule.sweep_enqueue_stale", sweep)
    stop = Mock()
    stop.is_set.side_effect = [False, False, True]
    lifecycle_controller.run(stop)
    assert [call.kwargs["status"] for call in heartbeat.call_args_list] == ["error", "running"]
    fly.start.assert_called_once_with("abc123")
    sweep.assert_called_once()
    assert lifecycle.execute(text("SELECT phase FROM worker_lifecycle WHERE id=1")).scalar_one() == "running"


def test_null_or_replaced_lease_rejects_cached_finalizer(lifecycle):
    job = add_job(lifecycle)
    claimed = claim_job(lifecycle, job.stage, "old")
    assert claimed is not None
    lease = claimed.lease_id
    with Session(lifecycle.bind) as other:
        other.execute(text("UPDATE jobs SET lease_id=NULL, status='queued' WHERE id=:id"), {"id": job.id})
        other.commit()
    with pytest.raises(LeaseLost):
        advance_job(lifecycle, job.id, JobStage.static, lease_id=lease)
    lifecycle.rollback()


def test_finalizer_preserves_pending_business_fields(lifecycle):
    job = add_job(lifecycle)
    claimed = claim_job(lifecycle, job.stage, "owner")
    assert claimed is not None
    claimed.request = {"durable_result": True}
    advance_job(lifecycle, job.id, JobStage.static, lease_id=claimed.lease_id)
    lifecycle.expire_all()
    assert lifecycle.get(Job, job.id).request == {"durable_result": True}


def test_enrollment_backoff_and_daily_repair(lifecycle):
    from services.monitoring.enrollment import mark_enrollment_dirty
    from services.monitoring.reconciler import sweep_enqueue_stale

    p = Protocol(name="lifecycle-repair")
    lifecycle.add(p)
    lifecycle.commit()
    assert sweep_enqueue_stale(lifecycle) == [p.id]
    assert "enrollment" in snapshot(lifecycle).ready

    lifecycle.execute(text("UPDATE monitoring_enrollment_queue SET dirty_at=now()+interval '1 hour'"))
    lifecycle.commit()
    assert sweep_enqueue_stale(lifecycle) == []
    assert not snapshot(lifecycle).busy
    mark_enrollment_dirty(lifecycle, p.id, "manual")
    lifecycle.commit()
    assert "enrollment" in snapshot(lifecycle).ready


@pytest.mark.parametrize("phase", ["text", "scope"])
def test_audit_sources_and_gate(lifecycle, monkeypatch, phase):
    from db.models import AuditReport
    from workers.audit_scope_extraction import AuditScopeExtractionWorker
    from workers.audit_text_extraction import AuditTextExtractionWorker

    monkeypatch.setattr("signal.signal", lambda *_: None)
    protocol = Protocol(name="audit-lifecycle")
    lifecycle.add(protocol)
    lifecycle.commit()
    audit = AuditReport(
        protocol_id=protocol.id,
        url="https://example.invalid/audit.pdf",
        title="test",
        auditor="test",
        text_extraction_status="success" if phase == "scope" else None,
    )
    lifecycle.add(audit)
    lifecycle.commit()
    worker = AuditScopeExtractionWorker() if phase == "scope" else AuditTextExtractionWorker()
    assert "audit_" + phase in snapshot(lifecycle).ready
    lifecycle.execute(text("UPDATE worker_lifecycle SET phase='draining'"))
    lifecycle.commit()
    assert worker._claim_batch(lifecycle) == []
    lifecycle.rollback()
    lifecycle.execute(text("UPDATE worker_lifecycle SET phase='running'"))
    lifecycle.commit()
    assert len(worker._claim_batch(lifecycle)) == 1
    assert snapshot(lifecycle).active


def test_verification_source_and_orphan_exclusion(lifecycle, monkeypatch):
    from db.models import AuditContractCoverage, AuditReport, Contract
    from workers.coverage_verify import CoverageVerifyWorker

    monkeypatch.setattr("signal.signal", lambda *_: None)
    protocol = Protocol(name="verify-lifecycle")
    lifecycle.add(protocol)
    lifecycle.commit()
    contract = Contract(protocol_id=protocol.id, address="0x" + "a" * 40, chain="ethereum", is_proxy=False)
    audit = AuditReport(
        protocol_id=protocol.id,
        url="https://example.invalid/audit.pdf",
        title="test",
        auditor="test",
        text_extraction_status="success",
        scope_extraction_status="success",
    )
    lifecycle.add_all([contract, audit])
    lifecycle.commit()
    coverage = AuditContractCoverage(
        protocol_id=protocol.id,
        contract_id=contract.id,
        audit_report_id=audit.id,
        matched_name="test",
        match_type="name",
        match_confidence="high",
        equivalence_status="pending",
    )
    lifecycle.add(coverage)
    lifecycle.commit()
    assert snapshot(lifecycle).ready == ("coverage_verify",)
    worker = CoverageVerifyWorker()
    lifecycle.execute(text("UPDATE worker_lifecycle SET phase='draining'"))
    lifecycle.commit()
    assert worker._claim_batch(lifecycle) == []
    lifecycle.rollback()
    lifecycle.execute(text("UPDATE worker_lifecycle SET phase='running'"))
    lifecycle.commit()
    assert worker._claim_batch(lifecycle) == [coverage.id]
    assert snapshot(lifecycle).active
    # Reset while still an implementation, then reclassify it as a proxy:
    # existing coverage becomes unclaimable and must not keep the VM awake.
    lifecycle.execute(text("UPDATE audit_contract_coverage SET equivalence_status='pending'"))
    lifecycle.commit()
    contract.is_proxy = True
    lifecycle.commit()
    assert not snapshot(lifecycle).busy
    assert worker._claim_batch(lifecycle) == []


@pytest.mark.parametrize("stage", [JobStage.coverage, JobStage.selection])
def test_custom_readiness_and_stuck_fallback_match_consumer(lifecycle, monkeypatch, stage):
    from db.models import AuditReport
    from workers.coverage_worker import CoverageWorker
    from workers.selection_worker import SelectionWorker

    monkeypatch.setattr("signal.signal", lambda *_: None)
    protocol = Protocol(name="custom-readiness")
    lifecycle.add(protocol)
    lifecycle.commit()
    job = add_job(lifecycle, stage, protocol_id=protocol.id)
    if stage == JobStage.coverage:
        lifecycle.add(
            AuditReport(protocol_id=protocol.id, url="https://example.invalid/a.pdf", title="test", auditor="test")
        )
        # Audit text is independently runnable. Only test jobs readiness below.
        worker = CoverageWorker()
    else:
        sibling = add_job(lifecycle, JobStage.dapp_crawl)
        sibling.request = {"root_job_id": str(job.id)}
        worker = SelectionWorker()
    lifecycle.commit()
    assert "jobs" not in snapshot(lifecycle).ready
    assert worker._claim_job(lifecycle) is None
    lifecycle.execute(text("UPDATE jobs SET updated_at=now()-interval '2 hours' WHERE id=:id"), {"id": job.id})
    lifecycle.commit()
    assert "jobs" in snapshot(lifecycle).ready
    claimed = worker._claim_job(lifecycle)
    assert claimed is not None
    assert claimed.id == job.id


def test_existing_processing_work_wakes_for_recovery(lifecycle):
    job = add_job(lifecycle)
    claim_job(lifecycle, job.stage, "crashed")
    lifecycle.execute(text("UPDATE jobs SET lease_expires_at=now()-interval '1 second'"))
    lifecycle.commit()
    assert decide(lifecycle, "stopped")["action"] == "start"


def test_stopped_machine_waits_for_unexpired_orphan_lease(lifecycle):
    job = add_job(lifecycle)
    claim_job(lifecycle, job.stage, "crashed")
    assert decide(lifecycle, "stopped")["action"] != "start"


def test_indexer_dirty_work_does_not_wake_analysis(lifecycle):
    from services.resolution.indexer_work import mark_dirty

    mark_dirty(lifecycle, "reconcile", "1")
    mark_dirty(lifecycle, "job", str(uuid.uuid4()))
    lifecycle.commit()
    age_idle(lifecycle)
    assert decide(lifecycle)["action"] == "drain"


@pytest.mark.parametrize("managed", [False, True])
def test_pipeline_queue_state_and_artifacts_equivalent(lifecycle, monkeypatch, managed):
    """Run real transitions/lease checks/artifact writes with fixed stage outputs.

    External analyses remain covered by their existing deterministic suites.
    This verifies the lifecycle wrapper doesn't alter their persisted payloads.
    """
    from db.queue import get_artifact, store_artifact

    if not managed:
        monkeypatch.delenv("PSAT_WORKER_BOOT_ID")
    job = add_job(lifecycle)
    stages = [
        JobStage.discovery,
        JobStage.static,
        JobStage.resolution,
        JobStage.policy,
        JobStage.effects,
        JobStage.coverage,
    ]
    for index, stage in enumerate(stages):
        claimed = claim_job(lifecycle, stage, "same-capacity")
        assert claimed is not None
        assert claimed.id == job.id
        payload = {"stage": stage.value, "facts": ["fixed-input", 42]}
        store_artifact(lifecycle, job.id, "parity_" + stage.value, data=payload)
        if index + 1 < len(stages):
            advance_job(lifecycle, job.id, stages[index + 1], lease_id=claimed.lease_id)
        else:
            complete_job(lifecycle, job.id, lease_id=claimed.lease_id)
        assert get_artifact(lifecycle, job.id, "parity_" + stage.value) == payload
    lifecycle.refresh(job)
    assert (job.status, job.stage, job.retry_count, job.lease_id) == (JobStatus.completed, JobStage.done, 0, None)
