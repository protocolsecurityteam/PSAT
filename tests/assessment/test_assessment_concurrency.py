from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.orm import Session

from db.assessment import load_assessment, store_assessment_section
from db.models import Job
from db.queue.artifacts import store_artifact
from tests.conftest import requires_postgres


@requires_postgres
def test_concurrent_stage_updates_serialize_without_losing_sections(db_session: Session) -> None:
    job = Job(request={})
    db_session.add(job)
    db_session.commit()
    job_id = job.id
    engine = db_session.get_bind()

    first_has_lock = threading.Event()
    release_first = threading.Event()

    def delayed_writer(session: Session, target_job_id: object, name: str, data: object) -> None:
        first_has_lock.set()
        assert release_first.wait(timeout=10)
        store_artifact(session, target_job_id, name, data)

    def write_effects() -> None:
        with Session(engine) as session:
            store_assessment_section(
                session,
                job_id,
                "effects",
                {"schema_version": "semantic-2", "functions": {}},
                writer=delayed_writer,
            )

    def write_labels() -> None:
        with Session(engine) as session:
            store_assessment_section(
                session,
                job_id,
                "principal_labels",
                {"schema_version": "principal-labels.v1", "principals": []},
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(write_effects)
        assert first_has_lock.wait(timeout=10)
        second = pool.submit(write_labels)
        # The second update has started while the first transaction owns the
        # job lock. Releasing the first allows the second to read its committed
        # Assessment and merge rather than overwrite it.
        release_first.set()
        first.result(timeout=10)
        second.result(timeout=10)

    db_session.expire_all()
    assessment = load_assessment(db_session, job_id)
    assert assessment is not None
    assert assessment.get("effects") == {"schema_version": "semantic-2", "functions": {}}
    assert assessment.get("principal_labels") == {
        "schema_version": "principal-labels.v1",
        "principals": [],
    }
