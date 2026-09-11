"""Public consumers receive only the row-shaped canonical Assessment."""

import uuid

import pytest

from db.models import Artifact, Job, JobStage, JobStatus
from tests.conftest import requires_postgres


@pytest.mark.parametrize("body", [{"schema_version": "assessment/5"}, {"schema_version": "assessment/4"}, []])
@requires_postgres
def test_public_detail_never_embeds_a_legacy_assessment(api_client, db_session, body):
    job = Job(
        id=uuid.uuid4(),
        address="0x" + "13" * 20,
        chain_id=1,
        name=f"legacy-{uuid.uuid4()}",
        request={"chain": "ethereum"},
        status=JobStatus.completed,
        stage=JobStage.done,
    )
    db_session.add(job)
    db_session.flush()
    db_session.add(Artifact(job_id=job.id, name="assessment", data=body))
    db_session.commit()

    response = api_client.get(f"/api/analyses/{job.name}")
    assert response.status_code == 200
    assert "assessment" not in response.json()
    assert "assessment_url" not in response.json()


def test_public_assessment_is_row_shaped_and_has_no_schema_version(api_client, db_session):
    from tests.support.assessment_artifacts import store_test_assessment

    address = "0x" + "12" * 20
    job = Job(
        address=address,
        chain_id=1,
        name="temporal-view",
        request={"address": address, "chain": "ethereum"},
        status=JobStatus.completed,
        stage=JobStage.done,
    )
    db_session.add(job)
    db_session.flush()
    store_test_assessment(db_session, job.id, address=address)

    response = api_client.get("/api/analyses/temporal-view/artifact/assessment.json")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "view",
        "subjects",
        "evidence",
        "claims",
        "analyses",
        "corrections",
        "contexts",
        "implementations",
        "payloads",
    }
    assert "schema_version" not in body
    assert all("id" in row for row in body["subjects"] + body["evidence"] + body["claims"])
