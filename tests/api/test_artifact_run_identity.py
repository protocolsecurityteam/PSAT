
from datetime import datetime, timedelta, timezone

from db.models import Artifact, Job, JobStage, JobStatus
from tests.conftest import requires_postgres
from tests.live.conftest import LiveClient
from tests.live.test_pipeline_stages import test_unconditionally_emitted_artifacts as check_fixture_artifact

pytestmark = requires_postgres


def test_live_fixture_reads_keep_job_identity_as_same_name_run_progresses(api_client, db_session, monkeypatch):
    monkeypatch.setattr("routers.deps.ADMIN_KEY", "fixture-artifact-test-key")
    api_client.headers["X-PSAT-Admin-Key"] = "fixture-artifact-test-key"
    now = datetime.now(timezone.utc)
    fixture = Job(
        name="WETH9_reused",
        address="0x" + "12" * 20,
        chain_id=1,
        request={},
        stage=JobStage.done,
        status=JobStatus.completed,
        updated_at=now - timedelta(minutes=5),
    )
    newer = Job(
        name=fixture.name,
        address=fixture.address,
        chain_id=1,
        request={},
        stage=JobStage.discovery,
        status=JobStatus.processing,
        updated_at=now,
    )
    db_session.add_all([fixture, newer])
    db_session.flush()
    names = ("control_snapshot", "effective_permissions", "principal_labels")
    for name in names:
        db_session.add(Artifact(job_id=fixture.id, name=name, data={"run": "fixture", "artifact": name}))
    db_session.commit()

    client = LiveClient("http://testserver", "")
    client._session.close()
    monkeypatch.setattr(client, "_session", api_client)
    fixture_job = {"job_id": str(fixture.id), "name": fixture.name}
    for name in names:
        # The old name lookup selected the unfinished job and failed here.
        check_fixture_artifact(fixture_job, client, name)
        assert client.artifact(str(fixture.id), name) == {"run": "fixture", "artifact": name}
        assert api_client.get(f"/api/analyses/{fixture.name}/artifact/{name}.json").status_code == 404
        assert client.artifact(str(newer.id), name) is None

    newer.updated_at = now + timedelta(seconds=10)
    db_session.commit()
    check_fixture_artifact(fixture_job, client, "control_snapshot")
    newer.status = JobStatus.completed
    newer.stage = JobStage.done
    for name in names:
        db_session.add(Artifact(job_id=newer.id, name=name, data={"run": "newer", "artifact": name}))
    db_session.commit()
    for name in names:
        assert client.artifact(str(fixture.id), name) == {"run": "fixture", "artifact": name}
        assert client.artifact(str(newer.id), name) == {"run": "newer", "artifact": name}
        alias = api_client.get(f"/api/analyses/{fixture.name}/artifact/{name}.json")
        assert alias.status_code == 200 and alias.json()["run"] == "newer"
