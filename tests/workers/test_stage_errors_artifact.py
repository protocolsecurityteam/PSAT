"""Storage is unconfigured, so artifacts stay inline JSONB."""

from __future__ import annotations

from db.models import Artifact, JobStage
from db.queue import create_job
from tests.cache_helpers import requires_postgres
from tests.support.db_fixtures import test_session_local  # noqa: F401  (fixture, registered by import)
from utils.logging import record_degraded
from workers.base import BaseWorker


class _FailingWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0.0

    def __init__(self, *, raise_after_degraded: bool = False, n_degraded: int = 0) -> None:
        super().__init__()
        self.raise_after_degraded = raise_after_degraded
        self.n_degraded = n_degraded

    def process(self, session, job):
        for i in range(self.n_degraded):
            try:
                raise RuntimeError(f"degraded {i}")
            except RuntimeError as exc:
                record_degraded(phase=f"sub_{i}", exc=exc)
        if self.raise_after_degraded:
            raise RuntimeError("boom")


def _read_stage_errors(session, job_id):
    art = session.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == "stage_errors").one_or_none()
    if art is None:
        return None
    if art.data is not None:
        return art.data
    return None


@requires_postgres
def test_failing_process_writes_stage_errors_with_severity_error(db_session, test_session_local):
    job = create_job(db_session, {"address": "0xabc", "name": "stage-err-1"})
    db_session.commit()

    worker = _FailingWorker(raise_after_degraded=True, n_degraded=0)
    worker._execute_job(db_session, job)

    db_session.expire_all()
    payload = _read_stage_errors(db_session, job.id)
    assert payload is not None, "stage_errors artifact must be written"
    errors = payload["errors"]
    assert len(errors) == 1
    err = errors[0]
    assert err["severity"] == "error"
    assert err["stage"] == "discovery"
    assert err["exc_type"] == "builtins.RuntimeError"
    assert "boom" in err["message"]
    assert err["traceback"] is not None
    assert err["job_id"] == str(job.id)
    assert err["trace_id"] == job.trace_id
    assert err["worker_id"] == worker.worker_id


@requires_postgres
def test_successful_process_with_degraded_records_writes_artifact(db_session, test_session_local):
    job = create_job(db_session, {"address": "0xabc", "name": "stage-err-2"})
    db_session.commit()

    worker = _FailingWorker(raise_after_degraded=False, n_degraded=2)
    import workers.base as base

    advances: list = []
    completes: list = []
    monkey_advance = base.advance_job
    monkey_complete = None
    base.advance_job = lambda _s, jid, ns, _d, **_kw: advances.append((jid, ns))
    import db.queue as db_queue

    monkey_complete = db_queue.complete_job
    db_queue.complete_job = lambda _s, jid: completes.append(jid)
    try:
        worker._execute_job(db_session, job)
    finally:
        base.advance_job = monkey_advance
        db_queue.complete_job = monkey_complete

    db_session.expire_all()
    payload = _read_stage_errors(db_session, job.id)
    assert payload is not None
    errors = payload["errors"]
    assert len(errors) == 2
    assert all(e["severity"] == "degraded" for e in errors)
    assert errors[0]["phase"] == "sub_0"
    assert errors[1]["phase"] == "sub_1"
    assert errors[0]["message"] == "degraded 0"
    assert errors[1]["message"] == "degraded 1"


@requires_postgres
def test_combined_degraded_and_error_produce_one_artifact(db_session, test_session_local):
    job = create_job(db_session, {"address": "0xabc", "name": "stage-err-3"})
    db_session.commit()

    worker = _FailingWorker(raise_after_degraded=True, n_degraded=2)
    worker._execute_job(db_session, job)

    db_session.expire_all()
    payload = _read_stage_errors(db_session, job.id)
    assert payload is not None
    errors = payload["errors"]
    assert len(errors) == 3
    severities = [e["severity"] for e in errors]
    assert severities == ["degraded", "degraded", "error"]
    assert errors[-1]["traceback"] is not None
    assert "boom" in errors[-1]["message"]


@requires_postgres
def test_fresh_session_fail_path_persists_artifact(db_session, test_session_local):
    job = create_job(db_session, {"address": "0xabc", "name": "stage-err-4"})
    db_session.commit()
    job_id = job.id  # capture before close

    class _BrokenSessionWorker(BaseWorker):
        stage = JobStage.discovery
        next_stage = JobStage.static
        poll_interval = 0.0

        def process(self, session, job):
            session.close()
            raise RuntimeError("session-poisoned")

    worker = _BrokenSessionWorker()
    worker._execute_job(db_session, job)

    fresh = test_session_local()
    try:
        payload = _read_stage_errors(fresh, job_id)
        assert payload is not None
        errors = payload["errors"]
        assert any(e["severity"] == "error" for e in errors)
        assert any("session-poisoned" in e["message"] for e in errors)
    finally:
        fresh.close()


@requires_postgres
def test_successful_process_without_degraded_writes_no_artifact(db_session, test_session_local):
    job = create_job(db_session, {"address": "0xabc", "name": "stage-err-5"})
    db_session.commit()

    worker = _FailingWorker(raise_after_degraded=False, n_degraded=0)
    import workers.base as base

    monkey_advance = base.advance_job
    base.advance_job = lambda *_a, **_kw: None
    try:
        worker._execute_job(db_session, job)
    finally:
        base.advance_job = monkey_advance

    db_session.expire_all()
    payload = _read_stage_errors(db_session, job.id)
    assert payload is None
