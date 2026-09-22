"""Canonical Assessment API boundary preserves legacy section views exactly."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from db.assessment import store_assessment
from db.models import JobStage, JobStatus
from db.queue import create_job
from tests.conftest import requires_postgres

ADMIN_KEY = "assessment-boundary-key"


def _client(monkeypatch) -> TestClient:
    import api
    from routers.deps import require_admin_key

    api.app.dependency_overrides.pop(require_admin_key, None)
    monkeypatch.setattr("routers.deps.ADMIN_KEY", ADMIN_KEY)
    return TestClient(api.app)


def _session(job_id: uuid.UUID) -> MagicMock:
    job = MagicMock()
    job.id = job_id
    result = MagicMock()
    result.scalar_one_or_none.return_value = job
    session = MagicMock()
    session.execute.return_value = result
    cm = MagicMock()
    cm.__enter__.return_value = session
    cm.__exit__.return_value = False
    return cm


def test_assessment_and_each_section_are_byte_equal_views(monkeypatch) -> None:
    client = _client(monkeypatch)
    job_id = uuid.uuid4()
    effects = {"schema_version": "semantic-2", "functions": {}, "opaque": [None, {"order": [2, 1]}]}
    labels = {"schema_version": "principal-labels.v1", "principals": []}
    assessment = {"schema_version": "assessment/1", "effects": effects, "principal_labels": labels}
    getter = MagicMock(return_value=assessment)

    with patch("routers.deps.SessionLocal", return_value=_session(job_id)), patch("routers.deps.get_artifact", getter):
        headers = {"X-PSAT-Admin-Key": ADMIN_KEY}
        whole = client.get(f"/api/analyses/{job_id}/artifact/assessment", headers=headers)
        effects_view = client.get(f"/api/analyses/{job_id}/artifact/effects", headers=headers)
        labels_view = client.get(f"/api/analyses/{job_id}/artifact/principal_labels.json", headers=headers)

    assert whole.status_code == 200 and whole.json() == assessment
    assert effects_view.status_code == 200 and effects_view.json() == effects
    assert labels_view.status_code == 200 and labels_view.json() == labels
    assert all(call.args[2] == "assessment" for call in getter.call_args_list)


def test_malformed_canonical_body_is_not_served_as_absence(monkeypatch) -> None:
    client = _client(monkeypatch)
    job_id = uuid.uuid4()
    malformed = {"schema_version": "assessment/2", "effects": {}}
    with (
        patch("routers.deps.SessionLocal", return_value=_session(job_id)),
        patch("routers.deps.get_artifact", return_value=malformed),
    ):
        response = client.get(
            f"/api/analyses/{job_id}/artifact/effects",
            headers={"X-PSAT-Admin-Key": ADMIN_KEY},
        )
    assert response.status_code == 503
    assert response.headers["X-PSAT-Artifact-State"] == "not_determined"
    assert response.json()["artifact"] == "effects"


def test_assessment_views_require_admin_before_storage_read(monkeypatch) -> None:
    client = _client(monkeypatch)
    job_id = uuid.uuid4()
    getter = MagicMock(return_value={"schema_version": "assessment/1", "effects": {}})
    session_local = MagicMock(return_value=_session(job_id))
    with patch("routers.deps.SessionLocal", session_local), patch("routers.deps.get_artifact", getter):
        for name in ("assessment", "effects", "principal_labels.json"):
            response = client.get(f"/api/analyses/{job_id}/artifact/{name}")
            assert response.status_code == 401
    session_local.assert_not_called()
    getter.assert_not_called()


@requires_postgres
def test_analysis_listing_inventories_the_physical_assessment_artifact(db_session) -> None:
    import api

    job = create_job(db_session, {"address": "0x" + "7" * 40, "name": "assessment-listing"})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    db_session.commit()
    store_assessment(db_session, job.id, {"schema_version": "assessment/1", "effects": {}})

    response = TestClient(api.app).get("/api/analyses")
    assert response.status_code == 200
    entry = next(item for item in response.json() if item["job_id"] == str(job.id))
    assert entry["available_artifacts"] == ["assessment"]
