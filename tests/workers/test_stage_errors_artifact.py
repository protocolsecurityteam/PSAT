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
