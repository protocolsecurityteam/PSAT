"""Public consumers receive validated Assessment or a structured failure."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import api
from routers import deps


@pytest.mark.parametrize("body", [{"schema_version": "assessment/5"}, {"schema_version": "assessment/4"}, []])
def test_public_detail_rejects_invalid_internal_projection(monkeypatch, body):
    session = MagicMock()
    job = MagicMock()
    job.name = "test"
    session.execute.return_value.scalar_one_or_none.return_value = job
    factory = MagicMock()
    factory.return_value.__enter__.return_value = session
    monkeypatch.setattr(deps, "SessionLocal", factory)
    monkeypatch.setattr(deps, "get_artifact", lambda *_: body)
    monkeypatch.setattr(deps, "get_all_artifacts", lambda *_: {"assessment": body})
    response = TestClient(api.app).get("/api/analyses/test")
    assert response.status_code == 500
    assert response.headers["X-PSAT-Artifact-State"] == "invalid"
    assert response.json()["detail"] == {"code": "invalid_assessment", "artifact": "assessment"}


def test_public_assessment_is_row_shaped_and_has_no_schema_version(api_client, db_session):
    from db.models import Job, JobStage, JobStatus
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
