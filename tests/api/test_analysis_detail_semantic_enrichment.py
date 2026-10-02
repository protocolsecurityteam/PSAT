from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.usefixtures("_stub_live_authority")


from tests.conftest import requires_postgres  # noqa: E402


def _seed_completed_job(db_session, *, address: str):
    from db.models import Job, JobStage, JobStatus

    job = Job(
        address=address,
        request={"address": address},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    db_session.flush()
    return job


def _semantic_artifact() -> dict:
    return {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "f()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "eq",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "msg_sender"},
                        {"source": "state_variable", "state_variable_name": "owner"},
                    ],
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "msg.sender == owner",
                    "basis": [],
                },
            }
        },
    }


@requires_postgres
def test_endpoint_includes_semantic_keys_when_artifact_present(api_client, db_session):
    from db.queue import store_artifact

    address = "0x" + uuid.uuid4().hex[:8] + "11" * 16
    job = _seed_completed_job(db_session, address=address)
    store_artifact(db_session, job.id, "predicate_trees", data=_semantic_artifact())
    db_session.commit()

    resp = api_client.get(f"/api/analyses/{address}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "predicate_trees" in body
    assert body["predicate_trees"]["schema_version"] == "semantic"
    assert "semantic_capabilities" in body
    assert "f()" in body["semantic_capabilities"]
    cap = body["semantic_capabilities"]["f()"]
    assert "kind" in cap
    assert "confidence" in cap
    assert "predicate_trees" in body["available_artifacts"]


@requires_postgres
def test_endpoint_omits_semantic_keys_when_artifact_missing(api_client, db_session):
    address = "0x" + uuid.uuid4().hex[:8] + "22" * 16
    _seed_completed_job(db_session, address=address)
    db_session.commit()

    resp = api_client.get(f"/api/analyses/{address}")
    assert resp.status_code == 200
    body = resp.json()
    assert "predicate_trees" not in body
    assert "semantic_capabilities" not in body
    assert "predicate_trees" not in body["available_artifacts"]


@requires_postgres
def test_endpoint_includes_predicate_trees_even_when_resolver_fails(api_client, db_session, monkeypatch):
    from db.queue import store_artifact

    address = "0x" + uuid.uuid4().hex[:8] + "33" * 16
    job = _seed_completed_job(db_session, address=address)
    store_artifact(db_session, job.id, "predicate_trees", data=_semantic_artifact())
    db_session.commit()

    def _boom(*a, **kw):
        raise RuntimeError("simulated resolver failure")

    import services.resolution.capability_resolver as cr_mod

    monkeypatch.setattr(cr_mod, "resolve_contract_capabilities", _boom)

    resp = api_client.get(f"/api/analyses/{address}")
    assert resp.status_code == 200
    body = resp.json()
    assert "predicate_trees" in body
    assert "semantic_capabilities" not in body


@requires_postgres
def test_endpoint_handles_unguarded_only_contract_with_empty_caps(api_client, db_session):
    """Both keys present but empty means analyzed, every function public."""
    from db.queue import store_artifact

    address = "0x" + uuid.uuid4().hex[:8] + "44" * 16
    job = _seed_completed_job(db_session, address=address)
    store_artifact(
        db_session,
        job.id,
        "predicate_trees",
        data={"schema_version": "semantic", "contract_name": "T", "trees": {}},
    )
    db_session.commit()

    resp = api_client.get(f"/api/analyses/{address}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["predicate_trees"]["trees"] == {}
    assert body["semantic_capabilities"] == {}


@requires_postgres
def test_endpoint_names_artifacts_it_could_not_read_instead_of_omitting_them(api_client, db_session, monkeypatch):
    """The SPA reads a missing artifact name as "never produced", so unreadable ones must be published, not only
    logged.
    """
    from db.storage import StorageContentNotDetermined
    from routers import deps

    address = "0x" + uuid.uuid4().hex[:8] + "33" * 16
    _seed_completed_job(db_session, address=address)
    db_session.commit()

    def _partial(_session, _job_id):
        raise StorageContentNotDetermined(
            "bucket unreachable",
            values={"predicate_trees": _semantic_artifact()},
            not_determined={"effective_permissions": "could not read artifacts/j/effective_permissions"},
        )

    monkeypatch.setattr(deps, "get_all_artifacts", _partial)

    resp = api_client.get(f"/api/analyses/{address}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["predicate_trees"]["schema_version"] == "semantic"
    assert "effective_permissions" in body["artifacts_not_determined"]
    assert "effective_permissions" not in body["available_artifacts"]


@requires_postgres
def test_endpoint_keeps_a_lost_body_apart_from_one_it_could_not_ask_about(api_client, db_session, monkeypatch):
    """``artifacts_not_determined`` is worth re-asking; ``artifacts_body_absent`` needs the artifact rebuilt."""
    from db.storage import StorageContentAbsent
    from routers import deps

    address = "0x" + uuid.uuid4().hex[:8] + "44" * 16
    _seed_completed_job(db_session, address=address)
    db_session.commit()

    def _partial(_session, _job_id):
        raise StorageContentAbsent(
            "1/2 artifact bodies proven absent",
            values={"predicate_trees": _semantic_artifact()},
            proven_absent={"effective_permissions": "no object at any candidate for artifacts/j/eff"},
        )

    monkeypatch.setattr(deps, "get_all_artifacts", _partial)

    resp = api_client.get(f"/api/analyses/{address}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["predicate_trees"]["schema_version"] == "semantic"
    assert "effective_permissions" in body["artifacts_body_absent"]
    assert "artifacts_not_determined" not in body
    assert "effective_permissions" not in body["available_artifacts"]


@requires_postgres
def test_address_lookup_keeps_full_analysis_after_effects_recovery(api_client, db_session):
    from datetime import timedelta

    from db.queue import store_artifact

    address = "0x" + uuid.uuid4().hex + "11" * 4
    original = _seed_completed_job(db_session, address=address)
    store_artifact(db_session, original.id, "predicate_trees", data=_semantic_artifact())
    retry = _seed_completed_job(db_session, address=address)
    assert retry.request is not None
    retry.request = dict(retry.request, effects_resume_work_id=42)
    retry.updated_at = original.updated_at + timedelta(minutes=1)
    db_session.commit()
    response = api_client.get(f"/api/analyses/{address}")
    assert response.status_code == 200
    assert response.json()["predicate_trees"]["schema_version"] == "semantic"
