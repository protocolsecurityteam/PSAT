"""Integration tests for object-storage-backed artifacts.

Requires:
- TEST_DATABASE_URL pointing at a Postgres test DB.
- TEST_ARTIFACT_STORAGE_* pointing at a running S3-compatible service
  (minio in docker-compose, real Tigris bucket in CI).

These tests exercise the production storage code path end to end:
write → row metadata → read → presigned URL → API redirect.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.cache_helpers import requires_postgres  # noqa: E402
from tests.conftest import SessionFactory, requires_storage  # noqa: E402

pytestmark = [requires_postgres, requires_storage]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _admin_headers() -> dict[str, str]:
    """Header carrying the configured admin key, for now-gated internal reads."""
    from routers import deps

    return {"X-PSAT-Admin-Key": deps.ADMIN_KEY or ""}


@pytest.fixture()
def api_with(monkeypatch, db_session, storage_bucket):
    """Wire the FastAPI app to the test DB session and storage bucket."""
    import api as api_module
    from routers import deps
    from routers.deps import require_admin_key

    monkeypatch.setattr(deps, "SessionLocal", SessionFactory(db_session))
    api_module.app.dependency_overrides[require_admin_key] = lambda: None
    return api_module


def _completed_job(session, name: str, address: str = "0xabcdef0000000000000000000000000000000001"):
    from db.models import JobStage, JobStatus
    from db.queue import create_job

    job = create_job(session, {"address": address, "name": name})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()
    return job


# ---------------------------------------------------------------------------
# 1. Full lifecycle — small + large artifacts both go to storage
# ---------------------------------------------------------------------------


def test_full_lifecycle_artifacts_round_trip(db_session, storage_bucket):
    """Every store_artifact write goes to storage; rows hold only metadata."""
    from db.models import Artifact
    from db.queue import create_job, get_all_artifacts, get_artifact, store_artifact

    job = create_job(db_session, {"address": "0xab", "name": "lifecycle"})

    small = {"is_proxy": True, "proxy_type": "eip1967"}
    large = {"detectors": [{"id": i, "data": "x" * 100} for i in range(2_000)]}
    text = "report body " * 5_000

    store_artifact(db_session, job.id, "contract_flags", data=small)
    store_artifact(db_session, job.id, "slither_results", data=large)
    store_artifact(db_session, job.id, "analysis_report", text_data=text)

    rows = db_session.execute(select(Artifact).where(Artifact.job_id == job.id)).scalars().all()
    by_name = {r.name: r for r in rows}

    for name in ("contract_flags", "slither_results", "analysis_report"):
        row = by_name[name]
        assert row.storage_key, f"{name} should have a storage_key"
        assert row.data is None, f"{name} should not be inline JSONB"
        assert row.text_data is None, f"{name} should not be inline text"
        assert row.stored_object_size_bytes and row.stored_object_size_bytes > 0
        assert row.content_type

    assert by_name["contract_flags"].content_type == "application/json"
    assert by_name["analysis_report"].content_type.startswith("text/plain")
    assert by_name["slither_results"].stored_object_size_bytes > 100_000

    assert get_artifact(db_session, job.id, "contract_flags") == small
    assert get_artifact(db_session, job.id, "slither_results") == large
    assert get_artifact(db_session, job.id, "analysis_report") == text

    all_arts = get_all_artifacts(db_session, job.id)
    assert all_arts["contract_flags"] == small
    assert all_arts["slither_results"] == large
    assert all_arts["analysis_report"] == text


# ---------------------------------------------------------------------------
# 2. Source files round-trip via storage
# ---------------------------------------------------------------------------


def test_source_files_round_trip_via_storage(db_session, storage_bucket):
    from db.models import SourceFile
    from db.queue import create_job, get_source_files, store_source_files

    job = create_job(db_session, {"address": "0xab", "name": "sf-test"})
    files = {
        "src/Big.sol": "pragma solidity ^0.8.24;\n" + ("// big line\n" * 10_000),
        "src/Small.sol": "pragma solidity ^0.8.24;\ncontract X {}",
        "src/sub/Nested.sol": "// nested",
    }
    store_source_files(db_session, job.id, files)

    rows = db_session.execute(select(SourceFile).where(SourceFile.job_id == job.id)).scalars().all()
    assert len(rows) == 3
    for r in rows:
        assert r.storage_key, f"{r.path} should have a storage_key"
        assert r.content is None

    assert get_source_files(db_session, job.id) == files


# ---------------------------------------------------------------------------
# 3. Legacy inline rows still read (no storage_key)
# ---------------------------------------------------------------------------


def test_legacy_inline_artifact_still_reads(db_session, storage_bucket):
    """An old row written before the migration (storage_key NULL) still works."""
    from db.models import Artifact
    from db.queue import create_job, get_artifact

    job = create_job(db_session, {"address": "0xab", "name": "legacy"})
    db_session.add(Artifact(job_id=job.id, name="legacy_blob", data={"v": 1}))
    db_session.commit()

    assert get_artifact(db_session, job.id, "legacy_blob") == {"v": 1}


# ---------------------------------------------------------------------------
# 4. Idempotent overwrite (deterministic key)
# ---------------------------------------------------------------------------


def test_nested_artifact_keys_round_trip_through_storage(db_session, storage_bucket):
    """Regression: nested recursive.* artifact names must pass ``_safe_name``.

    The storage layer's name validator rejects colons. A prior key format
    used ``recursive:<addr>:<kind>`` which passed unit tests (those stub
    ``store_artifact``) but failed at runtime whenever S3-compatible storage
    was active. This test hits the real client to make sure the current
    naming stays compatible.
    """
    from db.nested_artifacts import ARTIFACT_KINDS, artifact_key, parse_key, store_bundle
    from db.queue import create_job, get_artifact

    job = create_job(db_session, {"address": "0xab", "name": "nested-keys"})
    address = "0x3994741a5b29c60d0ab318de1024f9256fe959dc"
    bundle = {
        "analysis": {"subject": {"address": address, "name": "ETHFIStaking"}},
        "tracking_plan": {"contract_address": address, "tracked_controllers": []},
        "snapshot": {"contract_address": address, "controller_values": {}},
        "effective_permissions": {"contract_address": address, "functions": []},
    }

    store_bundle(db_session, job.id, {address: bundle})

    # Round-trip each kind back.
    for kind in ARTIFACT_KINDS:
        name = artifact_key(address, kind)
        assert parse_key(name) == (address, kind)
        assert get_artifact(db_session, job.id, name) == bundle[kind]


def test_repeat_store_overwrites_same_key(db_session, storage_bucket):
    from db.models import Artifact
    from db.queue import create_job, get_artifact, store_artifact

    job = create_job(db_session, {"address": "0xab", "name": "overwrite"})
    store_artifact(db_session, job.id, "x", data={"v": 1})
    first_row = db_session.execute(select(Artifact).where(Artifact.job_id == job.id, Artifact.name == "x")).scalar_one()
    first_key = first_row.storage_key

    store_artifact(db_session, job.id, "x", data={"v": 2})
    db_session.expire_all()
    second_row = db_session.execute(
        select(Artifact).where(Artifact.job_id == job.id, Artifact.name == "x")
    ).scalar_one()

    assert first_key == second_row.storage_key, "second write should reuse the deterministic key"
    assert get_artifact(db_session, job.id, "x") == {"v": 2}


# ---------------------------------------------------------------------------
# 5. /api/analyses/.../artifact endpoint serves storage-backed bodies
# ---------------------------------------------------------------------------


def test_artifact_endpoint_serves_storage_backed_json(api_with, db_session, storage_bucket):
    """Storage-backed JSON artifact is fetched from Tigris and served as JSON."""
    from db.queue import store_artifact

    job = _completed_job(db_session, "json-test")
    payload = {"summary": {"control_model": "ownable"}, "tag": "v1"}
    store_artifact(db_session, job.id, "contract_analysis", data=payload)

    client = TestClient(api_with.app)
    resp = client.get("/api/analyses/json-test/artifact/contract_analysis.json", headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.json() == payload


def test_artifact_endpoint_serves_storage_backed_text(api_with, db_session, storage_bucket):
    """Storage-backed text artifact is fetched and served as text."""
    from db.queue import store_artifact

    job = _completed_job(db_session, "text-test")
    body = "analysis report line " * 50
    store_artifact(db_session, job.id, "analysis_report", text_data=body)

    client = TestClient(api_with.app)
    resp = client.get("/api/analyses/text-test/artifact/analysis_report.txt", headers=_admin_headers())
    assert resp.status_code == 200
    assert body in resp.text


def test_artifact_endpoint_publishes_three_answers_not_two(api_with, db_session, storage_bucket):
    """The SPA's artifact boundary must not answer a storage outage with the
    same bytes as an artifact the job never produced.

    This is the altitude the fix is *for*: ``site/src/surface/sidebar/activity/
    EntityActivity.jsx`` fetches ``…/artifact/upgrade_history`` here and draws a
    proxy with no history as a proxy that was never upgraded, and
    ``site/src/surface/layout/dependencies.js`` fetches
    ``…/artifact/dependency_graph_viz``. Measured before this commit: readable
    200, outage 404 ``{"detail":"Artifact not found"}``, never-produced 404
    ``{"detail":"Artifact not found"}`` — byte-identical.

    ``slither_results`` is used rather than ``upgrade_history`` deliberately:
    upgrade_history has a synthesis fallback that answers from UpgradeEvent rows,
    so it exercises a different (also correct) branch.
    """
    from db.models import Artifact
    from db.queue import store_artifact
    from db.storage import StorageClient, StorageUnavailable

    job = _completed_job(db_session, "three-answers")
    store_artifact(db_session, job.id, "slither_results", data={"results": {}})
    client = TestClient(api_with.app)
    url = "/api/analyses/three-answers/artifact/slither_results.json"

    # A — proven present.
    readable = client.get(url, headers=_admin_headers())
    assert readable.status_code == 200
    assert readable.json() == {"results": {}}

    # B — not determined. Its own status, its own header, and the reason kept.
    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        outage = client.get(url, headers=_admin_headers())
    assert outage.status_code == 503
    assert outage.headers.get("X-PSAT-Artifact-State") == "not_determined"
    assert outage.json()["artifact"] == "slither_results"
    assert "bucket unreachable" in outage.json()["reason"]

    # C — proven absent: the job never produced this artifact.
    never = client.get("/api/analyses/three-answers/artifact/no_such_artifact.json", headers=_admin_headers())
    assert never.status_code == 404
    assert never.json() == {"detail": "Artifact not found"}

    # D — proven absent the other way: the row exists, the bucket says it holds
    # no such object. Same answer as C on purpose — both are determined — and
    # distinct from B, which is the distinction that was missing.
    row = db_session.execute(
        select(Artifact).where(Artifact.job_id == job.id, Artifact.name == "slither_results")
    ).scalar_one()
    storage_bucket.delete(row.storage_key)
    body_gone = client.get(url, headers=_admin_headers())
    assert body_gone.status_code == 404
    assert body_gone.json() == {"detail": "Artifact not found"}

    assert (outage.status_code, outage.text) != (never.status_code, never.text)
    assert (outage.status_code, outage.text) != (body_gone.status_code, body_gone.text)


def test_artifact_endpoint_publishes_a_keyless_row_as_the_third_state(api_with, db_session, storage_bucket):
    """R1/R2. ``StorageKeyAbsent`` is the class that names the third state, so
    the boundary must publish it as the third state.

    Reachable by construction on the *real* write path, which is how this test
    builds the row rather than hand-inserting one: ``store_artifact`` with an
    unconfigured backend and no payload writes ``storage_key`` NULL beside a
    NULL inline body (``db/queue.py``), and ``_artifact_row_to_value`` raises
    ``StorageKeyAbsent`` for exactly that row. It answered 404
    ``{"detail":"Artifact not found"}`` with no state header — byte-identical to
    the never-produced artifact asserted below as the negative control, which is
    the substitution W0-1 exists to remove.
    """
    import db.queue as queue_mod
    from db.models import Artifact
    from db.queue import store_artifact

    job = _completed_job(db_session, "keyless-third-state")

    # The real inline path: backend unconfigured, nothing to serialise.
    # Scoped with ``patch.object`` rather than monkeypatch: pytest hands the
    # same function-scoped monkeypatch to ``api_with`` and to the test, so a
    # ``monkeypatch.undo()`` here also reverted the fixture's
    # ``deps.SessionLocal`` override and pointed the TestClient at
    # ``DATABASE_URL``. The request then 404'd at the job lookup, and the
    # assertions below passed only in environments where DATABASE_URL and
    # TEST_DATABASE_URL happen to coincide.
    with patch.object(queue_mod, "get_storage_client", lambda: None):
        store_artifact(db_session, job.id, "dependencies")

    row = db_session.execute(
        select(Artifact).where(Artifact.job_id == job.id, Artifact.name == "dependencies")
    ).scalar_one()
    assert row.storage_key is None and row.data is None and row.text_data is None

    client = TestClient(api_with.app)
    unknown = client.get("/api/analyses/keyless-third-state/artifact/dependencies", headers=_admin_headers())
    assert unknown.status_code == 503
    assert unknown.headers.get("X-PSAT-Artifact-State") == "not_determined"
    assert unknown.json()["artifact"] == "dependencies"
    assert "StorageKeyAbsent" in unknown.json()["reason"]

    # Negative control — the job never produced this one. Determined, and it
    # must stay a silent 404 with no state header.
    never = client.get("/api/analyses/keyless-third-state/artifact/no_such_artifact", headers=_admin_headers())
    assert never.status_code == 404
    assert never.json() == {"detail": "Artifact not found"}
    assert never.headers.get("X-PSAT-Artifact-State") is None
    assert (unknown.status_code, unknown.text) != (never.status_code, never.text)


def test_artifact_endpoint_not_determined_still_prefers_a_real_synthesised_body(api_with, db_session, storage_bucket):
    """The 503 is the *last* answer, not the first: if a body can be rebuilt from
    another source (upgrade_history from UpgradeEvent rows) that real payload
    still wins over reporting an unknown. Negative control for the branch above —
    a fix that returned 503 on the first storage error would break this."""
    from db.models import Contract, UpgradeEvent
    from db.storage import StorageClient, StorageUnavailable

    job = _completed_job(db_session, "synth-wins")
    proxy = Contract(job_id=job.id, address="0x" + "ab" * 20, chain="ethereum", is_proxy=True)
    db_session.add(proxy)
    db_session.flush()
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl="0x" + "cd" * 20,
            block_number=1234,
            tx_hash="0x" + "ee" * 32,
        )
    )
    db_session.commit()

    client = TestClient(api_with.app)
    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        resp = client.get("/api/analyses/synth-wins/artifact/upgrade_history")
    assert resp.status_code == 200
    assert resp.json()["synthesized"] is True


def test_storage_client_can_presign(storage_bucket):
    """presign() returns a working URL — important for any future direct-from-storage download path."""
    storage_bucket.put("artifacts/test/presign.json", b'{"ok": true}', "application/json")
    url = storage_bucket.presign("artifacts/test/presign.json", expires_in=60)
    body = urllib.request.urlopen(url).read()
    assert json.loads(body.decode("utf-8")) == {"ok": True}


# ---------------------------------------------------------------------------
# 6. /api/jobs proxy detection works through storage
# ---------------------------------------------------------------------------


def test_list_jobs_detects_proxy_via_storage(api_with, db_session, storage_bucket):
    from db.queue import store_artifact

    proxy_job = _completed_job(db_session, "proxy-job")
    plain_job = _completed_job(db_session, "plain-job", address="0xabcdef0000000000000000000000000000000002")
    store_artifact(db_session, proxy_job.id, "contract_flags", data={"is_proxy": True})
    store_artifact(db_session, plain_job.id, "contract_flags", data={"is_proxy": False})

    client = TestClient(api_with.app)
    resp = client.get("/api/jobs")
    assert resp.status_code == 200
    by_id = {j["job_id"]: j for j in resp.json()}
    assert by_id[str(proxy_job.id)]["is_proxy"] is True
    assert by_id[str(plain_job.id)]["is_proxy"] is False


# ---------------------------------------------------------------------------
# 7. /api/health probes both the DB and storage
# ---------------------------------------------------------------------------


def test_health_endpoint_reports_db_and_storage(api_with):
    client = TestClient(api_with.app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    payload = resp.json()
    payload.pop("pool", None)  # only present under QueuePool
    assert payload == {"status": "ok", "db": "ok", "storage": "ok"}


def test_health_endpoint_503_when_storage_unreachable(api_with, monkeypatch):
    """If storage is configured but the bucket can't be reached, return 503."""
    from db import storage as storage_module

    def _boom(self):
        raise storage_module.StorageUnavailable("bucket gone")

    monkeypatch.setattr(storage_module.StorageClient, "health_check", _boom)

    client = TestClient(api_with.app)
    resp = client.get("/api/health")
    assert resp.status_code == 503
    payload = resp.json()
    payload.pop("pool", None)
    assert payload == {"status": "unavailable", "db": "ok", "storage": "unavailable"}


# ---------------------------------------------------------------------------
# 8. End-to-end stub: simulated worker writes a full job, API reads it back
# ---------------------------------------------------------------------------


def test_end_to_end_stubbed_worker(api_with, db_session, storage_bucket):
    """Simulate a worker writing all the artifacts a real job would."""
    from db.queue import store_artifact, store_source_files

    job = _completed_job(db_session, "e2e-test", address="0xabcdef0000000000000000000000000000000003")

    store_source_files(
        db_session,
        job.id,
        {
            "src/Main.sol": "pragma solidity ^0.8.24;\ncontract Main { function f() public {} }",
            "src/Lib.sol": "pragma solidity ^0.8.24;\nlibrary L {}",
        },
    )
    store_artifact(db_session, job.id, "contract_flags", data={"is_proxy": False})
    store_artifact(
        db_session,
        job.id,
        "contract_analysis",
        data={"subject": {"name": "Main"}, "summary": {"control_model": "ownable"}},
    )
    store_artifact(db_session, job.id, "slither_results", data={"results": {"detectors": []}})
    store_artifact(db_session, job.id, "analysis_report", text_data="Test analysis report content")

    client = TestClient(api_with.app)

    detail = client.get("/api/analyses/e2e-test")
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    assert payload["run_name"] == "e2e-test"
    assert "contract_analysis" in payload["available_artifacts"]
    assert payload["contract_analysis"]["subject"]["name"] == "Main"

    artifact = client.get(
        "/api/analyses/e2e-test/artifact/slither_results.json",
        headers=_admin_headers(),
        follow_redirects=True,
    )
    assert artifact.status_code == 200
    assert artifact.json() == {"results": {"detectors": []}}


# ---------------------------------------------------------------------------
# 9. Object storage outage during read surfaces as a graceful skip in lists
# ---------------------------------------------------------------------------


def test_get_all_artifacts_names_a_missing_storage_object_instead_of_skipping_it(db_session, storage_bucket):
    """INVERTED (was ``test_get_all_artifacts_skips_missing_storage_objects``,
    which asserted ``all_arts == {"good": {"v": 1}}``).

    That assertion pinned the defect: a short dict is byte-identical to "this
    job only ever produced ``good``", so a lost body and an absent artifact
    reached ``/api/analyses/{run_name}`` as the same answer. The read now fails
    closed and names what it could not read; the caller that may legitimately
    render a partial page opts in by catching it.

    The raised class also changed: a deleted object is ``StorageContentAbsent``
    (the bucket answered), not ``StorageContentNotDetermined``.
    """
    from db.models import Artifact
    from db.queue import create_job, get_all_artifacts, store_artifact
    from db.storage import StorageContentAbsent
    from workers.retry_policy import classify

    job = create_job(db_session, {"address": "0xab", "name": "missing-obj"})
    store_artifact(db_session, job.id, "good", data={"v": 1})
    store_artifact(db_session, job.id, "broken", data={"v": 2})

    broken_row = db_session.execute(
        select(Artifact).where(Artifact.job_id == job.id, Artifact.name == "broken")
    ).scalar_one()
    storage_bucket.delete(broken_row.storage_key)

    with pytest.raises(StorageContentAbsent) as excinfo:
        get_all_artifacts(db_session, job.id)
    assert excinfo.value.values == {"good": {"v": 1}}
    assert set(excinfo.value.proven_absent) == {"broken"}
    assert excinfo.value.not_determined == {}
    assert classify(excinfo.value) == "terminal"


# ---------------------------------------------------------------------------
# 10. Inline-fallback path (no storage configured) still works
# ---------------------------------------------------------------------------


def test_inline_fallback_when_storage_unconfigured(db_session, monkeypatch):
    """With no storage env, store_artifact writes inline like the legacy code."""
    from db.models import Artifact
    from db.queue import create_job, get_artifact, store_artifact
    from db.storage import reset_client_cache

    for k in (
        "ARTIFACT_STORAGE_ENDPOINT",
        "ARTIFACT_STORAGE_BUCKET",
        "ARTIFACT_STORAGE_ACCESS_KEY",
        "ARTIFACT_STORAGE_SECRET_KEY",
    ):
        monkeypatch.delenv(k, raising=False)
    reset_client_cache()

    job = create_job(db_session, {"address": "0xab", "name": "inline-only"})
    store_artifact(db_session, job.id, "x", data={"v": 1})

    row = db_session.execute(select(Artifact).where(Artifact.job_id == job.id, Artifact.name == "x")).scalar_one()
    assert row.storage_key is None
    assert row.data == {"v": 1}
    assert get_artifact(db_session, job.id, "x") == {"v": 1}


# ---------------------------------------------------------------------------
# 11. store_artifact cleans up the storage object when the DB write fails
# ---------------------------------------------------------------------------


def test_store_artifact_deletes_orphan_on_db_failure(db_session, storage_bucket):
    """Storage object is deleted if the INSERT raises — no dangling orphans in the bucket."""
    from db.queue import artifact_key, create_job, store_artifact
    from db.storage import StorageKeyMissing

    job = create_job(db_session, {"address": "0xab", "name": "orphan-1"})
    key = artifact_key(job.id, "will_orphan")

    real_execute = db_session.execute

    def failing_execute(stmt, *a, **kw):
        stmt_text = str(stmt).lower()
        if "insert into artifacts" in stmt_text:
            raise OperationalError("simulated DB outage", {}, Exception())
        return real_execute(stmt, *a, **kw)

    with patch.object(db_session, "execute", side_effect=failing_execute):
        with pytest.raises(OperationalError):
            store_artifact(db_session, job.id, "will_orphan", data={"v": 1})
    db_session.rollback()

    with pytest.raises(StorageKeyMissing):
        storage_bucket.get(key)


# ---------------------------------------------------------------------------
# 12. store_source_files deletes partial uploads when a later put fails
# ---------------------------------------------------------------------------


def test_store_source_files_cleans_up_orphans_on_midbatch_failure(db_session, storage_bucket):
    """Uploads from earlier iterations are deleted when a later iteration raises."""
    from db.models import SourceFile
    from db.queue import create_job, source_file_key, store_source_files
    from db.storage import StorageClient, StorageKeyMissing

    job = create_job(db_session, {"address": "0xab", "name": "orphan-2"})

    real_put = StorageClient.put
    calls = {"n": 0}

    def flaky_put(self, key, body, content_type, metadata=None):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated Tigris outage mid-batch")
        return real_put(self, key, body, content_type, metadata=metadata)

    files_in_order = {
        "src/First.sol": "first content",
        "src/Second.sol": "second content",
        "src/Third.sol": "third content",
    }

    with patch.object(StorageClient, "put", flaky_put):
        with pytest.raises(RuntimeError, match="simulated Tigris outage"):
            store_source_files(db_session, job.id, files_in_order)

    db_session.rollback()

    rows = db_session.execute(select(SourceFile).where(SourceFile.job_id == job.id)).scalars().all()
    assert rows == []

    first_key = source_file_key(job.id, "src/First.sol")
    with pytest.raises(StorageKeyMissing):
        storage_bucket.get(first_key)


# ---------------------------------------------------------------------------
# 13. Source file path is recoverable from S3 user-metadata
# ---------------------------------------------------------------------------


def test_source_file_path_recoverable_from_storage_metadata(db_session, storage_bucket):
    """Even if the DB row is lost, head_object returns the original path in user-metadata."""
    from db.models import SourceFile
    from db.queue import create_job, store_source_files

    job = create_job(db_session, {"address": "0xab", "name": "recovery"})
    store_source_files(db_session, job.id, {"src/Important.sol": "contract Important {}"})

    row = db_session.execute(select(SourceFile).where(SourceFile.job_id == job.id)).scalar_one()
    storage_key = row.storage_key

    # Simulate losing the row (backup restore, cascade delete, etc).
    db_session.delete(row)
    db_session.commit()

    head = storage_bucket._client.head_object(Bucket=storage_bucket.bucket, Key=storage_key)
    user_metadata = {k.lower(): v for k, v in (head.get("Metadata") or {}).items()}
    assert user_metadata.get("path") == "src/Important.sol"
    assert user_metadata.get("job_id") == str(job.id)


# ---------------------------------------------------------------------------
# 14. ARTIFACT_STORAGE_PREFIX scopes every storage key for multi-tenant buckets
# ---------------------------------------------------------------------------


def test_artifact_storage_prefix_scopes_keys_and_round_trips(monkeypatch, db_session, storage_bucket):
    """With ARTIFACT_STORAGE_PREFIX set, artifact + source-file keys are prefixed and still read/write cleanly.

    This is how PR-preview environments share a single Tigris bucket safely —
    each preview sets prefix=pr-<N>/ and teardown deletes that prefix.
    """
    from db.queue import (
        artifact_key,
        create_job,
        get_artifact,
        source_file_key,
        store_artifact,
        store_source_files,
    )

    monkeypatch.setenv("ARTIFACT_STORAGE_PREFIX", "pr-123")

    job = create_job(db_session, {"address": "0xab", "name": "prefix-ok"})
    store_artifact(db_session, job.id, "flagged", data={"ok": True})
    store_source_files(db_session, job.id, {"src/A.sol": "contract A {}"})

    art_k = artifact_key(job.id, "flagged")
    src_k = source_file_key(job.id, "src/A.sol")
    assert art_k.startswith("pr-123/artifacts/")
    assert src_k.startswith("pr-123/source_files/")

    # Round-trip through the prefixed key.
    assert get_artifact(db_session, job.id, "flagged") == {"ok": True}
    assert storage_bucket.get(art_k) == b'{"ok": true}'
    assert storage_bucket.get(src_k) == b"contract A {}"

    # Trailing / in env is idempotent.
    monkeypatch.setenv("ARTIFACT_STORAGE_PREFIX", "pr-123/")
    assert artifact_key(job.id, "flagged") == art_k

    # Unset → original unprefixed shape.
    monkeypatch.delenv("ARTIFACT_STORAGE_PREFIX")
    assert artifact_key(job.id, "flagged") == f"artifacts/{job.id}/flagged"


# /api/jobs no longer goes through ``_resolve_artifact_value`` — it reads
# ``Job.is_proxy`` directly, mirrored from the ``contract_flags`` artifact
# at write time. The "resolver bug surfaces as 500" guarantee still applies
# to /api/analyses and /api/analyses/{run_name}, which is where the catch
# blocks for storage errors actually live now.


# ---------------------------------------------------------------------------
# 15. Rows written under a foreign environment prefix stay readable (W0-1)
#
# Every storage key is recorded in Postgres verbatim, including the writing
# environment's ARTIFACT_STORAGE_PREFIX. Reading such a row from an environment
# with a different prefix addressed an object that was never written there:
# 8,256 rows across 5 columns in 3 tables were unreadable in the working
# database while the bytes sat at the same path, prefix-stripped.
#
# THE SHAPE MATTERS. Measured on the working DB, 8256/8256 rows are served by
# candidate index **1** and 0/8256 by index 0 — the recorded key never resolves.
# A test that writes the object *and* records the key under ``pr-160/`` passes
# with the fallback deleted, because candidate 0 answers; it exercises nothing.
# ``_divergent_key`` below constructs the production shape instead: the bytes
# exist only at the stripped path, so candidate 0 is a proven 404 and only the
# fallback can serve the row.
# ---------------------------------------------------------------------------


@pytest.fixture()
def preview_prefix(monkeypatch):
    """Write as a preview environment would, then read as this one does."""
    from db import storage as storage_module

    monkeypatch.setenv("ARTIFACT_STORAGE_PREFIX", "pr-160/")
    yield
    monkeypatch.delenv("ARTIFACT_STORAGE_PREFIX", raising=False)
    assert storage_module._key_prefix() == ""


def _divergent_key(bucket, prefixed_key: str) -> str:
    """Move the object written at *prefixed_key* to its prefix-stripped path.

    Leaves the exact production divergence: the DB row still records the
    prefixed key, and the only object lives at the stripped one. Asserts the
    prefixed object is really gone, so a test built on this cannot pass through
    candidate 0.
    """
    from db.storage import StorageKeyMissing

    assert prefixed_key.startswith("pr-160/")
    stripped = prefixed_key[len("pr-160/") :]
    bucket.put(stripped, bucket._get_one(prefixed_key), "application/json")
    bucket.delete(prefixed_key)
    with pytest.raises(StorageKeyMissing):
        bucket._get_one(prefixed_key)
    return stripped


def test_artifact_written_under_a_foreign_prefix_is_still_readable(db_session, storage_bucket, preview_prefix):
    """Column 1/5 — artifacts.storage_key (5,770 rows)."""
    import os

    from db.models import Artifact
    from db.queue import create_job, get_all_artifacts, get_artifact, store_artifact

    job = create_job(db_session, {"address": "0xab", "name": "prefix-artifacts"})
    payload = {"witness": "present", "n": 7}
    store_artifact(db_session, job.id, "effects", data=payload)

    row = db_session.execute(select(Artifact).where(Artifact.job_id == job.id)).scalars().one()
    assert row.storage_key.startswith("pr-160/artifacts/")
    _divergent_key(storage_bucket, row.storage_key)

    # Leave the preview environment. The row keeps its recorded key, which now
    # addresses nothing; only the stripped candidate can answer.
    os.environ.pop("ARTIFACT_STORAGE_PREFIX", None)
    assert get_artifact(db_session, job.id, "effects") == payload
    assert get_all_artifacts(db_session, job.id)["effects"] == payload


def test_source_files_written_under_a_foreign_prefix_are_still_readable(db_session, storage_bucket, preview_prefix):
    """Column 2/5 — source_files.storage_key (2,261 rows). This is the population
    behind ``search_source`` returning total_matches: 0 for every contract."""
    import os

    from db.models import SourceFile
    from db.queue import create_job, get_source_files, store_source_files

    job = create_job(db_session, {"address": "0xab", "name": "prefix-sources"})
    files = {"src/A.sol": "contract A { function pauseContract() external {} }", "src/B.sol": "contract B {}"}
    store_source_files(db_session, job.id, files)

    rows = db_session.execute(select(SourceFile).where(SourceFile.job_id == job.id)).scalars().all()
    assert all(r.storage_key.startswith("pr-160/source_files/") for r in rows)
    for row in rows:
        _divergent_key(storage_bucket, row.storage_key)

    os.environ.pop("ARTIFACT_STORAGE_PREFIX", None)
    assert get_source_files(db_session, job.id) == files


def test_materialization_blobs_written_under_a_foreign_prefix_are_still_readable(
    db_session, storage_bucket, preview_prefix
):
    """Columns 3-5/5 — contract_materializations.{analysis,tracking_plan,predicate_trees}_blob_key.

    ``hydrate_*`` swallowed an unreadable blob into ``None``, so this defect was
    invisible: the 75 rows read as "this materialization has no analysis".
    """
    import os

    from db import contract_materializations as cm
    from db.models import ContractMaterialization

    chain, keccak = "1", "0x" + "ab" * 32
    payloads = {
        "analysis": {"functions": ["pauseContract()"]},
        "tracking_plan": {"events": ["Paused"]},
        "predicate_trees": {"trees": {"pauseContract()": {"kind": "role"}}},
    }
    row = ContractMaterialization(
        chain=chain,
        address="0x" + "cd" * 20,
        bytecode_keccak=keccak,
        status="ready",
        analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION,
    )
    for kind, payload in payloads.items():
        key = cm._blob_key(chain, keccak, kind)
        assert key.startswith("pr-160/contract_materializations/")
        cm._put_blob(storage_bucket, key, payload)
        _divergent_key(storage_bucket, key)
        setattr(row, f"{kind}_blob_key", key)
    db_session.add(row)
    db_session.commit()

    os.environ.pop("ARTIFACT_STORAGE_PREFIX", None)
    assert cm.hydrate_analysis(row) == payloads["analysis"]
    assert cm.hydrate_tracking_plan(row) == payloads["tracking_plan"]
    assert cm.hydrate_predicate_trees(row) == payloads["predicate_trees"]


def test_a_genuinely_absent_object_is_still_reported_absent(db_session, storage_bucket):
    """POSITIVE CONTROL. The fallback must not explain away a real absence.

    Mirrors ``audit_reports`` id 183 in the working database — the one row whose
    object is gone at every candidate key. It resolved to a loud failure before
    this change and must keep doing so, now naming what it tried.
    """
    from db.storage import StorageKeyMissing

    with pytest.raises(StorageKeyMissing) as excinfo:
        storage_bucket.get("audits/text/183.txt")
    assert excinfo.value.tried == ["audits/text/183.txt"]

    with pytest.raises(StorageKeyMissing) as excinfo:
        storage_bucket.get("pr-160/artifacts/no-such-job/no-such-name")
    assert excinfo.value.tried == [
        "pr-160/artifacts/no-such-job/no-such-name",
        "artifacts/no-such-job/no-such-name",
    ]


def test_artifact_row_with_no_key_and_no_body_is_not_reported_as_no_artifact(db_session, storage_bucket):
    """R1. Three states must stay apart: a row that never recorded a key and
    holds no inline body means *not determined*, not ``None`` — which
    ``get_artifact`` also returns when the artifact does not exist at all."""
    from db.models import Artifact
    from db.queue import create_job, get_artifact
    from db.storage import StorageKeyAbsent

    job = create_job(db_session, {"address": "0xab", "name": "keyless"})
    db_session.add(Artifact(job_id=job.id, name="keyless", data=None, text_data=None, storage_key=None))
    db_session.commit()

    assert get_artifact(db_session, job.id, "never_stored") is None
    with pytest.raises(StorageKeyAbsent):
        get_artifact(db_session, job.id, "keyless")


def test_copy_resolves_a_foreign_prefixed_source_key(db_session, storage_bucket, preview_prefix):
    """``copy_artifacts_to_job`` server-side-copies from the row's recorded key;
    an unresolved prefix turned every reuse into a storage failure."""
    import os

    from db.queue import artifact_key

    src = artifact_key("job-src", "effects")
    assert src.startswith("pr-160/")
    storage_bucket.put(src, b'{"v":1}', "application/json")
    _divergent_key(storage_bucket, src)

    os.environ.pop("ARTIFACT_STORAGE_PREFIX", None)
    storage_bucket.copy(src, "artifacts/job-dst/effects")
    assert storage_bucket._get_one("artifacts/job-dst/effects") == b'{"v":1}'


# ---------------------------------------------------------------------------
# 16. R1 at the consumer boundary — an outage is not an empty job (W0-1)
#
# Measured on the working DB before this change: get_all_artifacts on the
# largest job returned 130 artifacts healthy, 0 under a patched bucket outage,
# and 0 for a job id that does not exist. Two of those three are the same
# number for opposite reasons, and the caller building /api/analyses/{run_name}
# had nothing to tell them apart with.
# ---------------------------------------------------------------------------


def test_a_bucket_outage_is_not_the_same_answer_as_a_job_with_no_artifacts(db_session, storage_bucket):
    """The four states, through the production entry point, in one test."""
    import uuid as _uuid

    from db.models import Artifact
    from db.queue import create_job, get_all_artifacts, store_artifact
    from db.storage import StorageClient, StorageContentAbsent, StorageContentNotDetermined, StorageUnavailable
    from workers.retry_policy import classify

    job = create_job(db_session, {"address": "0xab", "name": "outage-vs-empty"})
    store_artifact(db_session, job.id, "effects", data={"v": 1})
    store_artifact(db_session, job.id, "contract_analysis", data={"v": 2})
    empty_job = create_job(db_session, {"address": "0xcd", "name": "outage-vs-empty-2"})

    # A — healthy.
    assert set(get_all_artifacts(db_session, job.id)) == {"effects", "contract_analysis"}

    # B — bucket unreachable. Not determined, and it says so.
    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        with pytest.raises(StorageContentNotDetermined) as excinfo:
            get_all_artifacts(db_session, job.id)
    assert set(excinfo.value.not_determined) == {"effects", "contract_analysis"}
    assert excinfo.value.proven_absent == {}
    assert classify(excinfo.value) == "transient"

    # C — the bucket answered: the row asserts a key nothing is stored under.
    # A different class from B, because a retry cannot change this answer.
    gone = db_session.execute(
        select(Artifact).where(Artifact.job_id == job.id, Artifact.name == "effects")
    ).scalar_one()
    storage_bucket.delete(gone.storage_key)
    with pytest.raises(StorageContentAbsent) as absent:
        get_all_artifacts(db_session, job.id)
    assert set(absent.value.proven_absent) == {"effects"}
    assert absent.value.not_determined == {}
    assert set(absent.value.values) == {"contract_analysis"}
    assert classify(absent.value) == "terminal"
    assert not isinstance(absent.value, StorageContentNotDetermined)

    # D — proven absent: a real job that stored nothing, and an id with no rows.
    assert get_all_artifacts(db_session, empty_job.id) == {}
    assert get_all_artifacts(db_session, _uuid.uuid4()) == {}


def test_source_files_outage_is_not_the_same_answer_as_a_job_with_no_source(db_session, storage_bucket):
    """``workers.static_worker`` compiles whatever ``get_source_files`` hands
    it. A short dict there is a static analysis over a partial contract with
    nothing recording that anything was missing.

    INVERTED on one arm: this used to assert ``StorageContentNotDetermined``
    for a *deleted object*, i.e. it pinned "the bucket answered 'no such key'"
    and "the bucket could not be asked" as one class — which
    ``workers.retry_policy`` then classified transient while the identical
    single-key read (``StorageClient.get`` -> ``StorageKeyMissing``) classified
    terminal. The exception type is the only discriminator the worker gets, so
    the two now differ by type, and this test pins both verdicts.
    """
    from db.models import SourceFile
    from db.queue import create_job, get_source_files, store_source_files
    from db.storage import (
        StorageClient,
        StorageContentAbsent,
        StorageContentNotDetermined,
        StorageKeyMissing,
        StorageUnavailable,
    )
    from workers.retry_policy import classify

    job = create_job(db_session, {"address": "0xab", "name": "src-outage"})
    store_source_files(db_session, job.id, {"src/A.sol": "contract A {}", "src/B.sol": "contract B {}"})
    empty_job = create_job(db_session, {"address": "0xcd", "name": "src-empty"})

    assert len(get_source_files(db_session, job.id)) == 2

    # A — the bucket could not be asked. Not determined; a retry can still
    # turn it into a fact.
    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        with pytest.raises(StorageContentNotDetermined) as outage:
            get_source_files(db_session, job.id)
    assert set(outage.value.not_determined) == {"src/A.sol", "src/B.sol"}
    assert outage.value.proven_absent == {}
    assert classify(outage.value) == "transient"

    gone = db_session.execute(
        select(SourceFile).where(SourceFile.job_id == job.id, SourceFile.path == "src/B.sol")
    ).scalar_one()
    storage_bucket.delete(gone.storage_key)

    # B — the bucket answered. Determined, and terminal for the same reason the
    # single-key read is: re-asking cannot change the answer.
    with pytest.raises(StorageContentAbsent) as excinfo:
        get_source_files(db_session, job.id)
    assert set(excinfo.value.proven_absent) == {"src/B.sol"}
    assert excinfo.value.not_determined == {}
    assert set(excinfo.value.values) == {"src/A.sol"}
    assert classify(excinfo.value) == "terminal"
    # The verdict the collection read gives must match the one the single-key
    # read gives for the same key — the contradiction this test now guards.
    with pytest.raises(StorageKeyMissing) as direct:
        storage_bucket.get(gone.storage_key)
    assert classify(direct.value) == classify(excinfo.value) == "terminal"

    # C — proven absent because the job has no source rows at all. Still the
    # empty dict: nothing fell short, so nothing is claimed to have.
    assert get_source_files(db_session, empty_job.id) == {}


def test_collection_reads_publish_a_keyless_row_as_not_determined(db_session, storage_bucket):
    """The third state through the two *collection* entry points.

    ``_artifact_row_to_value`` raises ``StorageKeyAbsent`` for a row that
    records no key and holds no inline body, and ``routers.analyses`` publishes
    that as a 503. ``get_all_artifacts`` re-implemented the row resolution
    inline with no ``else`` and dropped the same row from the returned dict —
    no exception, no shortfall entry, one call away from
    ``services/aggregations/analysis_detail``, which publishes exactly the two
    maps this row was missing from. ``get_source_files`` had the identical gap.

    The negative controls are in the same test on purpose: a job that stored
    nothing must still be the empty dict, and a row that did read must not be
    dragged into the shortfall.
    """
    from db.models import Artifact, SourceFile
    from db.queue import create_job, get_all_artifacts, get_source_files, store_artifact, store_source_files
    from db.storage import StorageContentNotDetermined
    from workers.retry_policy import classify

    job = create_job(db_session, {"address": "0xab", "name": "keyless-collection"})
    store_artifact(db_session, job.id, "effects", data={"v": 1})
    # Exactly what ``store_artifact`` writes when the backend is unconfigured
    # and the stage passed no payload.
    db_session.add(Artifact(job_id=job.id, name="dependencies", data=None, text_data=None, storage_key=None))
    db_session.commit()

    with pytest.raises(StorageContentNotDetermined) as arts:
        get_all_artifacts(db_session, job.id)
    assert set(arts.value.not_determined) == {"dependencies"}
    assert arts.value.proven_absent == {}
    # The readable row is still carried, so a page that may degrade renders it.
    assert set(arts.value.values) == {"effects"}
    assert classify(arts.value) == "transient"

    src_job = create_job(db_session, {"address": "0xcd", "name": "keyless-source"})
    store_source_files(db_session, src_job.id, {"src/A.sol": "contract A {}"})
    db_session.add(SourceFile(job_id=src_job.id, path="src/B.sol", content=None, storage_key=None))
    db_session.commit()

    with pytest.raises(StorageContentNotDetermined) as srcs:
        get_source_files(db_session, src_job.id)
    assert set(srcs.value.not_determined) == {"src/B.sol"}
    assert srcs.value.proven_absent == {}
    assert set(srcs.value.values) == {"src/A.sol"}
    assert classify(srcs.value) == "transient"

    # Negative control — a keyless row with no storage sibling is still the only
    # thing short, and a job with no rows at all stays a silent empty dict.
    bare = create_job(db_session, {"address": "0xef", "name": "keyless-only"})
    db_session.add(SourceFile(job_id=bare.id, path="src/C.sol", content=None, storage_key=None))
    db_session.commit()
    with pytest.raises(StorageContentNotDetermined) as bare_exc:
        get_source_files(db_session, bare.id)
    assert set(bare_exc.value.not_determined) == {"src/C.sol"}
    assert bare_exc.value.values == {}

    empty = create_job(db_session, {"address": "0x00", "name": "keyless-none"})
    assert get_all_artifacts(db_session, empty.id) == {}
    assert get_source_files(db_session, empty.id) == {}


def test_hydrate_keeps_outage_absence_and_payload_apart(db_session, storage_bucket):
    """R1 for ``contract_materializations``. ``_hydrate`` returned ``None`` for
    all three, and ``services/resolution/recursive`` writes ``or {}`` over it —
    so a bucket outage rendered as "this contract has no analysis, no plan and
    no predicate trees" and that verdict seeded the effects probe."""
    from db import contract_materializations as cm
    from db.models import ContractMaterialization
    from db.storage import StorageClient, StorageContentAbsent, StorageContentNotDetermined, StorageUnavailable
    from workers.retry_policy import classify

    chain, keccak = "1", "0x" + "ef" * 32
    key = cm._blob_key(chain, keccak, "analysis")
    cm._put_blob(storage_bucket, key, {"functions": ["pauseContract()"]})
    row = ContractMaterialization(
        chain=chain,
        address="0x" + "12" * 20,
        bytecode_keccak=keccak,
        status="ready",
        analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION,
        analysis_blob_key=key,
    )
    keyless = ContractMaterialization(
        chain=chain,
        address="0x" + "34" * 20,
        bytecode_keccak="0x" + "cc" * 32,
        status="failed",
        analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION,
    )
    db_session.add_all([row, keyless])
    db_session.commit()

    # A — proven present.
    assert cm.hydrate_analysis(row) == {"functions": ["pauseContract()"]}

    # B — not determined. The row asserts a key; the bucket could not answer.
    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        with pytest.raises(StorageContentNotDetermined):
            cm.hydrate_analysis(row)

    # C — proven absent: nothing was ever stored. This is the shape of the 6
    # status='failed' rows in the working DB.
    assert cm.hydrate_analysis(keyless) is None

    # And the inline copy still wins over an unreadable blob — serving a
    # possibly-stale real payload is not the same as inventing an absence.
    keyless.analysis_blob_key = key
    keyless.analysis = {"functions": ["inline"]}
    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        assert cm.hydrate_analysis(keyless) == {"functions": ["inline"]}

    # D — the row asserts a key and the bucket answers "no such object", with no
    # inline copy. A different class from B: this one is terminal, so the stage
    # fails instead of re-asking a question the bucket already answered.
    storage_bucket.delete(key)
    with pytest.raises(StorageContentAbsent) as absent:
        cm.hydrate_analysis(row)
    assert set(absent.value.proven_absent) == {"analysis_blob_key"}
    assert absent.value.not_determined == {}
    assert classify(absent.value) == "terminal"
