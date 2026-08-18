"""Admin gating of ops/internal reads + two enumeration/leak guards.

Drives the real FastAPI app via TestClient and stubs only the wire
(``routers.deps.SessionLocal`` and the aggregation builders). The conftest
``_bypass_admin_key`` autouse fixture stubs the auth dependency for every test,
so the 401 cases here pop that override and set a known key first.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ADMIN_KEY = "real-admin-key"


def _client_without_bypass(monkeypatch) -> TestClient:
    """Real app with the conftest admin-key bypass removed and a known key set."""
    import api
    from routers.deps import require_admin_key

    api.app.dependency_overrides.pop(require_admin_key, None)
    monkeypatch.setattr("routers.deps.ADMIN_KEY", ADMIN_KEY)
    return TestClient(api.app)


def _fake_job(job_id: str) -> MagicMock:
    job = MagicMock()
    job.id = uuid.UUID(job_id)
    job.trace_id = None
    job.status = MagicMock(value="completed")
    job.stage = MagicMock(value="done")
    job.to_dict.return_value = {"job_id": job_id, "status": "completed"}
    return job


def _session_cm(fake_job: MagicMock) -> MagicMock:
    """A SessionLocal() context manager whose session answers every read shape
    these endpoints use (get → a job; execute → empty scalars / zero counts)."""
    exec_result = MagicMock()
    exec_result.scalars.return_value.all.return_value = []
    exec_result.scalar.return_value = 0
    exec_result.scalar_one_or_none.return_value = None
    session = MagicMock()
    session.get.return_value = fake_job
    session.execute.return_value = exec_result
    cm = MagicMock()
    cm.__enter__.return_value = session
    cm.__exit__.return_value = False
    return cm


def test_ops_reads_require_admin_key(monkeypatch) -> None:
    """Each ops/internal read is 401 without the key and 200 with it."""
    client = _client_without_bypass(monkeypatch)
    job_id = str(uuid.uuid4())
    cm = _session_cm(_fake_job(job_id))

    reads = [
        "/api/jobs",
        f"/api/jobs/{job_id}",
        f"/api/jobs/{job_id}/errors",
        f"/api/jobs/{job_id}/stage_timings",
        "/api/fleet",
        "/api/stats",
        "/api/audits/pipeline",
    ]

    with (
        patch("routers.deps.SessionLocal", return_value=cm),
        patch("routers.deps.get_artifact", return_value=None),
        patch("routers.fleet.build_fleet_status", return_value={}),
        patch("routers.audits.build_audits_pipeline", return_value={}),
    ):
        for path in reads:
            anon = client.get(path)
            assert anon.status_code == 401, f"{path} must 401 without key, got {anon.status_code}"
            authed = client.get(path, headers={"X-PSAT-Admin-Key": ADMIN_KEY})
            assert authed.status_code == 200, f"{path} must 200 with key, got {authed.status_code}: {authed.text}"


def test_artifact_allowlist_gates_internal_names(monkeypatch) -> None:
    """Internal artifact names are admin-gated before any lookup; the four
    consumer-safe names stay reachable without a key."""
    client = _client_without_bypass(monkeypatch)
    cm = _session_cm(_fake_job(str(uuid.uuid4())))

    with (
        patch("routers.deps.SessionLocal", return_value=cm),
        patch("routers.deps.get_artifact", return_value=None),
    ):
        # Not on the allowlist → 401 with no key, before any DB/storage I/O.
        gated = client.get("/api/analyses/demo_run/artifact/stage_errors")
        assert gated.status_code == 401

        # An admin reaches it (404 here only because the stub has no body).
        admin = client.get(
            "/api/analyses/demo_run/artifact/stage_errors",
            headers={"X-PSAT-Admin-Key": ADMIN_KEY},
        )
        assert admin.status_code != 401

        # Consumer-safe names (incl. the .json the graph fetches with no key).
        for name in ("upgrade_history", "dependencies", "dependency_graph_viz.json", "policy_state.json"):
            resp = client.get(f"/api/analyses/demo_run/artifact/{name}")
            assert resp.status_code != 401, f"{name} must be reachable without a key (got {resp.status_code})"


def test_analyses_list_does_not_enumerate_internal_artifacts(monkeypatch) -> None:
    """The public listing strips internal artifact names from available_artifacts."""
    import api
    from routers import deps

    job = _fake_job(str(uuid.uuid4()))
    job.name = "demo_run"
    job.address = None
    job.company = "acme"
    job.is_proxy = False
    job.request = {}

    artifact_rows = [
        SimpleNamespace(job_id=job.id, name=n)
        for n in (
            "dependencies",
            "policy_state",
            "stage_errors",
            "stage_timing_discovery",
            "predicate_trees",
            "control_tracking_plan",
            "classification_error",
            "polling_plan",
        )
    ]

    def _execute(stmt, *a, **k):
        res = MagicMock()
        text = str(stmt).lower()
        if "artifact" in text:
            res.all.return_value = [(r.job_id, r.name) for r in artifact_rows]
        else:
            res.scalars.return_value.all.return_value = [job]
        return res

    session = MagicMock()
    session.execute.side_effect = _execute
    cm = MagicMock()
    cm.__enter__.return_value = session
    cm.__exit__.return_value = False

    monkeypatch.setattr(deps, "SessionLocal", lambda: cm)
    client = TestClient(api.app)
    resp = client.get("/api/analyses")
    assert resp.status_code == 200
    entries = {e["run_name"]: e for e in resp.json()}
    artifacts = entries["demo_run"]["available_artifacts"]
    assert artifacts == ["dependencies", "policy_state"], artifacts


def test_health_pool_only_for_admin(monkeypatch) -> None:
    """The status/db/storage booleans are public; the pool sub-object is admin-only."""
    from sqlalchemy.pool import QueuePool

    import api
    import db.models as dbm

    # The pool's connection counters (size/checkedin/...) read by /api/health
    # never call the creator, so a no-op creator is enough for this stub.
    monkeypatch.setattr(dbm, "engine", SimpleNamespace(pool=QueuePool(lambda: None)))  # pyright: ignore[reportArgumentType]
    monkeypatch.setattr("routers.deps.ADMIN_KEY", ADMIN_KEY)

    session = MagicMock()
    cm = MagicMock()
    cm.__enter__.return_value = session
    cm.__exit__.return_value = False

    client = TestClient(api.app)
    with (
        patch("routers.deps.SessionLocal", return_value=cm),
        patch("routers.deps.get_storage_client", return_value=None),
    ):
        anon = client.get("/api/health")
        authed = client.get("/api/health", headers={"X-PSAT-Admin-Key": ADMIN_KEY})

    assert anon.status_code == 200
    assert "pool" not in anon.json()
    assert authed.status_code == 200
    assert "pool" in authed.json()


def test_admin_key_valid_helper(monkeypatch) -> None:
    from routers import deps

    monkeypatch.setattr(deps, "ADMIN_KEY", ADMIN_KEY)
    assert deps.admin_key_valid(ADMIN_KEY) is True
    assert deps.admin_key_valid("wrong") is False
    assert deps.admin_key_valid(None) is False
    monkeypatch.setattr(deps, "ADMIN_KEY", None)
    assert deps.admin_key_valid(ADMIN_KEY) is False


def test_subscriptions_redacts_webhook_token() -> None:
    """The discord webhook token is never returned un-redacted."""
    import api

    sub = SimpleNamespace(
        id=uuid.uuid4(),
        protocol_id=1,
        discord_webhook_url="https://discord.com/api/webhooks/123456789012345678/SUPERSECRETtoken_abcdef",
        label="ops",
        event_filter=None,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    exec_result = MagicMock()
    exec_result.scalars.return_value.all.return_value = [sub]
    session = MagicMock()
    session.execute.return_value = exec_result
    cm = MagicMock()
    cm.__enter__.return_value = session
    cm.__exit__.return_value = False

    client = TestClient(api.app)
    with patch("routers.deps.SessionLocal", return_value=cm):
        resp = client.get("/api/protocols/1/subscriptions")

    assert resp.status_code == 200
    assert "SUPERSECRETtoken_abcdef" not in resp.text
    payload = resp.json()
    assert payload[0]["discord_webhook_url"] == "https://discord.com/api/webhooks/123456789012345678/<redacted>"
