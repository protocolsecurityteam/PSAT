"""Requires TEST_DATABASE_URL and TEST_ARTIFACT_STORAGE_* (minio locally, Tigris in CI)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from tests.cache_helpers import requires_postgres
from tests.conftest import SessionFactory, requires_storage

pytestmark = [requires_postgres, requires_storage]


def _admin_headers() -> dict[str, str]:
    from routers import deps

    return {"X-PSAT-Admin-Key": deps.ADMIN_KEY or ""}


@pytest.fixture()
def api_with(monkeypatch, db_session, storage_bucket):
    import api as api_module
    from routers import deps
    from routers.deps import require_admin_key

    monkeypatch.setattr(deps, "SessionLocal", SessionFactory(db_session))
    api_module.app.dependency_overrides[require_admin_key] = lambda: None
    return api_module


@pytest.fixture()
def materialization_key(db_session):
    """Fixed keys because blob keys derive from the keccak.

    Cleanup runs before and after, since a crashed run left rows that broke the composite primary key.
    """
    from db.models import ContractMaterialization

    claimed: list[tuple[str, str]] = []

    def purge() -> None:
        for chain, keccak in claimed:
            db_session.query(ContractMaterialization).filter_by(chain=chain, bytecode_keccak=keccak).delete()
        db_session.commit()

    def claim(chain: str, *keccaks: str) -> None:
        claimed.extend((chain, keccak) for keccak in keccaks)
        purge()

    yield claim
    purge()


def _completed_job(session, name: str, address: str = "0xabcdef0000000000000000000000000000000001"):
    from db.models import JobStage, JobStatus
    from db.queue import create_job

    job = create_job(session, {"address": address, "name": name})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()
    return job


def test_full_lifecycle_artifacts_round_trip(db_session, storage_bucket):
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


def test_legacy_inline_artifact_still_reads(db_session, storage_bucket):
    from db.models import Artifact
    from db.queue import create_job, get_artifact

    job = create_job(db_session, {"address": "0xab", "name": "legacy"})
    db_session.add(Artifact(job_id=job.id, name="legacy_blob", data={"v": 1}))
    db_session.commit()

    assert get_artifact(db_session, job.id, "legacy_blob") == {"v": 1}


def test_nested_artifact_keys_round_trip_through_storage(db_session, storage_bucket):
    """Unit tests stub ``store_artifact``, so a colon-bearing key only failed with real storage."""
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


def test_artifact_endpoint_serves_storage_backed_json(api_with, db_session, storage_bucket):
    from db.queue import store_artifact

    job = _completed_job(db_session, "json-test")
    payload = {"summary": {"control_model": "ownable"}, "tag": "v1"}
    store_artifact(db_session, job.id, "contract_analysis", data=payload)

    client = TestClient(api_with.app)
    resp = client.get("/api/analyses/json-test/artifact/contract_analysis.json", headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.json() == payload


def test_artifact_endpoint_serves_storage_backed_text(api_with, db_session, storage_bucket):
    from db.queue import store_artifact

    job = _completed_job(db_session, "text-test")
    body = "analysis report line " * 50
    store_artifact(db_session, job.id, "analysis_report", text_data=body)

    client = TestClient(api_with.app)
    resp = client.get("/api/analyses/text-test/artifact/analysis_report.txt", headers=_admin_headers())
    assert resp.status_code == 200
    assert body in resp.text


def test_artifact_endpoint_publishes_three_answers_not_two(api_with, db_session, storage_bucket):
    """``EntityActivity.jsx`` draws a proxy with no history as never upgraded, and an outage was a 404 byte-identical
    to never-produced. ``slither_results`` avoids upgrade_history's UpgradeEvent fallback.
    """
    from db.models import Artifact
    from db.queue import store_artifact
    from db.storage import StorageClient, StorageUnavailable

    job = _completed_job(db_session, "three-answers")
    store_artifact(db_session, job.id, "slither_results", data={"results": {}})
    client = TestClient(api_with.app)
    url = "/api/analyses/three-answers/artifact/slither_results.json"

    readable = client.get(url, headers=_admin_headers())
    assert readable.status_code == 200
    assert readable.json() == {"results": {}}

    # The raw exception is logged server-side only, never echoed to the caller.
    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        outage = client.get(url, headers=_admin_headers())
    assert outage.status_code == 503
    assert outage.headers.get("X-PSAT-Artifact-State") == "not_determined"
    assert outage.json()["artifact"] == "slither_results"
    assert outage.json()["reason"] == "Artifact read did not complete"
    assert "bucket unreachable" not in outage.text

    never = client.get("/api/analyses/three-answers/artifact/no_such_artifact.json", headers=_admin_headers())
    assert never.status_code == 404
    assert never.json() == {"detail": "Artifact not found"}

    # Same answer as C on purpose; both are determined.
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
    """Built through the real write path; it used to 404 byte-identically to the never-produced control."""
    import db.queue.artifacts as queue_mod
    from db.models import Artifact
    from db.queue import store_artifact

    job = _completed_job(db_session, "keyless-third-state")

    # ``monkeypatch.undo()`` would also revert ``api_with``'s ``SessionLocal`` override.
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
    assert unknown.json()["reason"] == "Artifact key not recorded"
    assert "StorageKeyAbsent" not in unknown.text

    never = client.get("/api/analyses/keyless-third-state/artifact/no_such_artifact", headers=_admin_headers())
    assert never.status_code == 404
    assert never.json() == {"detail": "Artifact not found"}
    assert never.headers.get("X-PSAT-Artifact-State") is None
    assert (unknown.status_code, unknown.text) != (never.status_code, never.text)


def test_artifact_endpoint_not_determined_still_prefers_a_real_synthesised_body(api_with, db_session, storage_bucket):
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


def test_missing_upgrade_history_404s_only_for_a_proven_non_proxy(api_with, db_session, storage_bucket):
    """The SPA reads the 404 as proven absence, but the stage writes nothing both when there are no proxies and when
    it raised. ``0x3c55986c…`` (``is_proxy=False``, ``proxy_type='beacon'``) had 14 ``Upgraded`` logs.
    """
    from db.models import Contract

    client = TestClient(api_with.app)

    # A self-consistent non-proxy has no history by construction; without this control the marker would land on every
    # Safe and EOA.
    plain_job = _completed_job(db_session, "uh-plain", address="0x" + "a1" * 20)
    db_session.add(Contract(job_id=plain_job.id, address="0x" + "a1" * 20, chain="ethereum", is_proxy=False))
    db_session.commit()
    plain = client.get("/api/analyses/uh-plain/artifact/upgrade_history")
    assert plain.status_code == 404
    assert plain.headers.get("X-PSAT-Artifact-State") is None

    # The row contradicts itself, so its non-proxy status can't carry an absence.
    beacon_job = _completed_job(db_session, "uh-beacon", address="0x" + "a2" * 20)
    db_session.add(
        Contract(
            job_id=beacon_job.id,
            address="0x" + "a2" * 20,
            chain="ethereum",
            is_proxy=False,
            proxy_type="beacon",
        )
    )
    db_session.commit()
    beacon = client.get("/api/analyses/uh-beacon/artifact/upgrade_history")
    assert beacon.status_code == 503
    assert beacon.headers.get("X-PSAT-Artifact-State") == "not_determined"
    assert "inconsistent about proxyhood" in beacon.json()["reason"]

    proxy_job = _completed_job(db_session, "uh-proxy", address="0x" + "a3" * 20)
    db_session.add(Contract(job_id=proxy_job.id, address="0x" + "a3" * 20, chain="ethereum", is_proxy=True))
    db_session.commit()
    proxy = client.get("/api/analyses/uh-proxy/artifact/upgrade_history")
    assert proxy.status_code == 503
    assert proxy.headers.get("X-PSAT-Artifact-State") == "not_determined"

    _completed_job(db_session, "uh-bare", address="0x" + "a4" * 20)
    bare = client.get("/api/analyses/uh-bare/artifact/upgrade_history")
    assert bare.status_code == 503
    assert "no contract row" in bare.json()["reason"]

    assert (plain.status_code, plain.text) != (beacon.status_code, beacon.text)


def test_a_degraded_upgrade_history_stage_blocks_the_404(api_with, db_session, storage_bucket):
    """0 of 123 local ``stage_errors`` carry this phase, so it has no realised rows yet."""
    from datetime import datetime, timezone

    from db.models import Contract
    from db.queue import store_artifact

    job = _completed_job(db_session, "uh-degraded", address="0x" + "a5" * 20)
    db_session.add(Contract(job_id=job.id, address="0x" + "a5" * 20, chain="ethereum", is_proxy=False))
    store_artifact(
        db_session,
        job.id,
        "stage_errors",
        data={
            "job_id": str(job.id),
            "errors": [
                {
                    "stage": "static",
                    "severity": "degraded",
                    "exc_type": "builtins.RuntimeError",
                    "message": "etherscan 429",
                    "phase": "dependency_upgrade_history",
                    "job_id": str(job.id),
                    "worker_id": "w1",
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        },
    )
    db_session.commit()

    client = TestClient(api_with.app)
    resp = client.get("/api/analyses/uh-degraded/artifact/upgrade_history")
    assert resp.status_code == 503
    assert resp.headers.get("X-PSAT-Artifact-State") == "not_determined"
    assert "degraded failure" in resp.json()["reason"]

    other = _completed_job(db_session, "uh-other-phase", address="0x" + "a6" * 20)
    db_session.add(Contract(job_id=other.id, address="0x" + "a6" * 20, chain="ethereum", is_proxy=False))
    store_artifact(
        db_session,
        other.id,
        "stage_errors",
        data={
            "job_id": str(other.id),
            "errors": [
                {
                    "stage": "static",
                    "severity": "degraded",
                    "exc_type": "builtins.RuntimeError",
                    "message": "unrelated",
                    "phase": "dependency_dynamic",
                    "job_id": str(other.id),
                    "worker_id": "w1",
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        },
    )
    db_session.commit()
    assert client.get("/api/analyses/uh-other-phase/artifact/upgrade_history").status_code == 404


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


def test_health_endpoint_reports_db_and_storage(api_with):
    client = TestClient(api_with.app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    payload = resp.json()
    payload.pop("pool", None)  # only present under QueuePool
    assert payload == {"status": "ok", "db": "ok", "storage": "ok"}


def test_health_endpoint_503_when_storage_unreachable(api_with, monkeypatch):
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


def test_end_to_end_stubbed_worker(api_with, db_session, storage_bucket):
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


def test_inline_fallback_when_storage_unconfigured(db_session, monkeypatch):
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


def test_store_artifact_deletes_orphan_on_db_failure(db_session, storage_bucket):
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


def test_store_source_files_cleans_up_orphans_on_midbatch_failure(db_session, storage_bucket):
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


def test_source_file_path_recoverable_from_storage_metadata(db_session, storage_bucket):
    from db.models import SourceFile
    from db.queue import create_job, store_source_files

    job = create_job(db_session, {"address": "0xab", "name": "recovery"})
    store_source_files(db_session, job.id, {"src/Important.sol": "contract Important {}"})

    row = db_session.execute(select(SourceFile).where(SourceFile.job_id == job.id)).scalar_one()
    storage_key = row.storage_key

    db_session.delete(row)
    db_session.commit()

    head = storage_bucket._client.head_object(Bucket=storage_bucket.bucket, Key=storage_key)
    user_metadata = {k.lower(): v for k, v in (head.get("Metadata") or {}).items()}
    assert user_metadata.get("path") == "src/Important.sol"
    assert user_metadata.get("job_id") == str(job.id)


def test_artifact_storage_prefix_scopes_keys_and_round_trips(monkeypatch, db_session, storage_bucket):
    """PR previews share one Tigris bucket via prefix=pr-<N>/."""
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

    assert get_artifact(db_session, job.id, "flagged") == {"ok": True}
    assert storage_bucket.get(art_k) == b'{"ok": true}'
    assert storage_bucket.get(src_k) == b"contract A {}"

    monkeypatch.setenv("ARTIFACT_STORAGE_PREFIX", "pr-123/")
    assert artifact_key(job.id, "flagged") == art_k

    monkeypatch.delenv("ARTIFACT_STORAGE_PREFIX")
    assert artifact_key(job.id, "flagged") == f"artifacts/{job.id}/flagged"


# Rows written under a foreign environment prefix stay readable. Keys include the writer's prefix, which left
# 8,256 rows unreadable elsewhere. In production every row is served by candidate index 1 (the stripped path), so
# ``_divergent_key`` puts bytes only there; writing and recording under ``pr-160/`` would pass with the fallback
# deleted.


@pytest.fixture()
def preview_prefix(monkeypatch):
    from db import storage as storage_module

    monkeypatch.setenv("ARTIFACT_STORAGE_PREFIX", "pr-160/")
    yield
    monkeypatch.delenv("ARTIFACT_STORAGE_PREFIX", raising=False)
    assert storage_module._key_prefix() == ""


def _divergent_key(bucket, prefixed_key: str) -> str:
    from db.storage import StorageKeyMissing

    assert prefixed_key.startswith("pr-160/")
    stripped = prefixed_key[len("pr-160/") :]
    bucket.put(stripped, bucket._get_one(prefixed_key), "application/json")
    bucket.delete(prefixed_key)
    with pytest.raises(StorageKeyMissing):
        bucket._get_one(prefixed_key)
    return stripped


def test_artifact_written_under_a_foreign_prefix_is_still_readable(db_session, storage_bucket, preview_prefix):
    import os

    from db.models import Artifact
    from db.queue import create_job, get_all_artifacts, get_artifact, store_artifact

    job = create_job(db_session, {"address": "0xab", "name": "prefix-artifacts"})
    payload = {"witness": "present", "n": 7}
    store_artifact(db_session, job.id, "effects", data=payload)

    row = db_session.execute(select(Artifact).where(Artifact.job_id == job.id)).scalars().one()
    assert row.storage_key.startswith("pr-160/artifacts/")
    _divergent_key(storage_bucket, row.storage_key)

    os.environ.pop("ARTIFACT_STORAGE_PREFIX", None)
    assert get_artifact(db_session, job.id, "effects") == payload
    assert get_all_artifacts(db_session, job.id)["effects"] == payload


def test_source_files_written_under_a_foreign_prefix_are_still_readable(db_session, storage_bucket, preview_prefix):
    """The population behind ``search_source`` returning 0 matches for every contract."""
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
    db_session, storage_bucket, preview_prefix, materialization_key
):
    """``hydrate_*`` swallowed unreadable blobs into ``None``, hiding this (75 rows)."""
    import os

    from db import contract_materializations as cm
    from db.models import ContractMaterialization

    chain, keccak = "1", "0x" + "ab" * 32
    materialization_key(chain, keccak)
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
    """Mirrors ``audit_reports`` id 183, which must keep failing loudly."""
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
    """``get_artifact`` also returns ``None`` for a nonexistent artifact."""
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
    import os

    from db.queue import artifact_key

    src = artifact_key("job-src", "effects")
    assert src.startswith("pr-160/")
    storage_bucket.put(src, b'{"v":1}', "application/json")
    _divergent_key(storage_bucket, src)

    os.environ.pop("ARTIFACT_STORAGE_PREFIX", None)
    storage_bucket.copy(src, "artifacts/job-dst/effects")
    assert storage_bucket._get_one("artifacts/job-dst/effects") == b'{"v":1}'


# ``get_all_artifacts`` returned 0 both under an outage and for a nonexistent job.


def test_a_bucket_outage_is_not_the_same_answer_as_a_job_with_no_artifacts(db_session, storage_bucket):
    import uuid as _uuid

    from db.models import Artifact
    from db.queue import create_job, get_all_artifacts, store_artifact
    from db.storage import StorageClient, StorageContentAbsent, StorageContentNotDetermined, StorageUnavailable
    from workers.retry_policy import classify

    job = create_job(db_session, {"address": "0xab", "name": "outage-vs-empty"})
    store_artifact(db_session, job.id, "effects", data={"v": 1})
    store_artifact(db_session, job.id, "contract_analysis", data={"v": 2})
    empty_job = create_job(db_session, {"address": "0xcd", "name": "outage-vs-empty-2"})

    assert set(get_all_artifacts(db_session, job.id)) == {"effects", "contract_analysis"}

    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        with pytest.raises(StorageContentNotDetermined) as excinfo:
            get_all_artifacts(db_session, job.id)
    assert set(excinfo.value.not_determined) == {"effects", "contract_analysis"}
    assert excinfo.value.proven_absent == {}
    assert classify(excinfo.value) == "transient"

    # A retry can't change this answer.
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

    assert get_all_artifacts(db_session, empty_job.id) == {}
    assert get_all_artifacts(db_session, _uuid.uuid4()) == {}


def test_source_files_outage_is_not_the_same_answer_as_a_job_with_no_source(db_session, storage_bucket):
    """A short dict means static analysis over a partial contract.

    Inverted on one arm: a deleted object was ``StorageContentNotDetermined`` (transient) while the single-key read was
    terminal; the exception type is the worker's only discriminator.
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

    with pytest.raises(StorageContentAbsent) as excinfo:
        get_source_files(db_session, job.id)
    assert set(excinfo.value.proven_absent) == {"src/B.sol"}
    assert excinfo.value.not_determined == {}
    assert set(excinfo.value.values) == {"src/A.sol"}
    assert classify(excinfo.value) == "terminal"
    with pytest.raises(StorageKeyMissing) as direct:
        storage_bucket.get(gone.storage_key)
    assert classify(direct.value) == classify(excinfo.value) == "terminal"

    assert get_source_files(db_session, empty_job.id) == {}


def test_collection_reads_publish_a_keyless_row_as_not_determined(db_session, storage_bucket):
    """``get_all_artifacts`` and ``get_source_files`` re-implemented resolution with no ``else`` and silently dropped
    the keyless row.
    """
    from db.models import Artifact, SourceFile
    from db.queue import create_job, get_all_artifacts, get_source_files, store_artifact, store_source_files
    from db.storage import StorageContentNotDetermined
    from workers.retry_policy import classify

    job = create_job(db_session, {"address": "0xab", "name": "keyless-collection"})
    store_artifact(db_session, job.id, "effects", data={"v": 1})
    db_session.add(Artifact(job_id=job.id, name="dependencies", data=None, text_data=None, storage_key=None))
    db_session.commit()

    with pytest.raises(StorageContentNotDetermined) as arts:
        get_all_artifacts(db_session, job.id)
    assert set(arts.value.not_determined) == {"dependencies"}
    assert arts.value.proven_absent == {}
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


def test_hydrate_keeps_outage_absence_and_payload_apart(db_session, storage_bucket, materialization_key):
    """``services/resolution/recursive`` writes ``or {}`` over ``None``, so an outage rendered as no analysis and
    seeded the effects probe.
    """
    from db import contract_materializations as cm
    from db.models import ContractMaterialization
    from db.storage import StorageClient, StorageContentAbsent, StorageContentNotDetermined, StorageUnavailable
    from workers.retry_policy import classify

    chain, keccak = "1", "0x" + "ef" * 32
    keyless_keccak = "0x" + "cc" * 32
    materialization_key(chain, keccak, keyless_keccak)
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
        bytecode_keccak=keyless_keccak,
        status="failed",
        analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION,
    )
    db_session.add_all([row, keyless])
    db_session.commit()

    assert cm.hydrate_analysis(row) == {"functions": ["pauseContract()"]}

    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        with pytest.raises(StorageContentNotDetermined):
            cm.hydrate_analysis(row)

    # The shape of the 6 status='failed' rows in the working DB.
    assert cm.hydrate_analysis(keyless) is None

    # A possibly stale real payload beats an invented absence.
    keyless.analysis_blob_key = key
    keyless.analysis = {"functions": ["inline"]}
    with patch.object(StorageClient, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        assert cm.hydrate_analysis(keyless) == {"functions": ["inline"]}

    # Terminal, unlike B: the bucket already answered.
    storage_bucket.delete(key)
    with pytest.raises(StorageContentAbsent) as absent:
        cm.hydrate_analysis(row)
    assert set(absent.value.proven_absent) == {"analysis_blob_key"}
    assert absent.value.not_determined == {}
    assert classify(absent.value) == "terminal"


# ---------------------------------------------------------------------------
# Job lifecycle
# ---------------------------------------------------------------------------


def test_create_job_extracts_the_address_from_the_request(db_session):
    from db.queue import create_job

    job = create_job(db_session, {"address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "name": "test"})
    assert job.id is not None
    assert job.address == "0xdAC17F958D2ee523a2206206994597C13D831ec7"


def test_claim_and_advance_job(db_session):
    from db.models import JobStage, JobStatus
    from db.queue import advance_job, claim_job, create_job

    create_job(db_session, {"address": "0x0000000000000000000000000000000000000001"})

    claimed = claim_job(db_session, JobStage.discovery, "test-worker")
    assert claimed is not None
    assert claimed.status == JobStatus.processing
    assert claimed.worker_id == "test-worker"

    assert claim_job(db_session, JobStage.discovery, "test-worker-2") is None

    advance_job(db_session, claimed.id, JobStage.static)
    db_session.refresh(claimed)
    assert claimed.stage == JobStage.static
    assert claimed.status == JobStatus.queued


def test_fail_job(db_session):
    from db.models import JobStage, JobStatus
    from db.queue import claim_job, create_job, fail_job

    create_job(db_session, {"address": "0x0000000000000000000000000000000000000002"})
    claimed = claim_job(db_session, JobStage.discovery, "test-worker")
    assert claimed is not None

    fail_job(db_session, claimed.id, "something went wrong")
    db_session.refresh(claimed)
    assert claimed.status == JobStatus.failed
    assert claimed.error == "something went wrong"


def test_complete_job(db_session):
    from db.models import JobStage, JobStatus
    from db.queue import claim_job, complete_job, create_job

    create_job(db_session, {"address": "0x0000000000000000000000000000000000000003"})
    claimed = claim_job(db_session, JobStage.discovery, "test-worker")
    assert claimed is not None

    complete_job(db_session, claimed.id)
    db_session.refresh(claimed)
    assert claimed.status == JobStatus.completed
    assert claimed.stage == JobStage.done
