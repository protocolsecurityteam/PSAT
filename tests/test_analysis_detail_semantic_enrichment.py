"""Pin semantic enrichment of ``GET /api/analyses/{run_name}``.

The endpoint adds two keys when a predicate-tree artifact exists:

  - ``predicate_trees`` — raw trees-by-function dict
  - ``semantic_capabilities`` — resolved CapabilityExpr per function
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

# offline: no live owner()/governor() eth_call during predicate evaluation
pytestmark = pytest.mark.usefixtures("_stub_live_authority")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


def _can_connect() -> bool:
    if not DATABASE_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


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
    # Both semantic enrichment keys present.
    assert "predicate_trees" in body
    assert body["predicate_trees"]["schema_version"] == "semantic"
    assert "semantic_capabilities" in body
    assert "f()" in body["semantic_capabilities"]
    cap = body["semantic_capabilities"]["f()"]
    assert "kind" in cap
    assert "confidence" in cap
    # available_artifacts surface lists the artifact name too.
    assert "predicate_trees" in body["available_artifacts"]


@requires_postgres
def test_endpoint_omits_semantic_keys_when_artifact_missing(api_client, db_session):
    """No predicate_trees stored means no semantic enrichment keys appear."""
    address = "0x" + uuid.uuid4().hex[:8] + "22" * 16
    _seed_completed_job(db_session, address=address)
    db_session.commit()

    resp = api_client.get(f"/api/analyses/{address}")
    assert resp.status_code == 200
    body = resp.json()
    assert "predicate_trees" not in body
    assert "semantic_capabilities" not in body
    # available_artifacts doesn't list it either.
    assert "predicate_trees" not in body["available_artifacts"]


@requires_postgres
def test_endpoint_includes_predicate_trees_even_when_resolver_fails(api_client, db_session, monkeypatch):
    """A semantic resolution failure must not break the endpoint. The
    raw ``predicate_trees`` artifact stays inlined; only the
    resolved ``semantic_capabilities`` is dropped."""
    from db.queue import store_artifact

    address = "0x" + uuid.uuid4().hex[:8] + "33" * 16
    job = _seed_completed_job(db_session, address=address)
    store_artifact(db_session, job.id, "predicate_trees", data=_semantic_artifact())
    db_session.commit()

    # Force the resolver import to raise.
    def _boom(*a, **kw):
        raise RuntimeError("simulated resolver failure")

    import services.resolution.capability_resolver as cr_mod

    monkeypatch.setattr(cr_mod, "resolve_contract_capabilities", _boom)

    resp = api_client.get(f"/api/analyses/{address}")
    assert resp.status_code == 200
    body = resp.json()
    # Raw trees still present.
    assert "predicate_trees" in body
    # Resolved capabilities dropped because resolution exploded.
    assert "semantic_capabilities" not in body


@requires_postgres
def test_endpoint_handles_unguarded_only_contract_with_empty_caps(api_client, db_session):
    """Contract with only public functions: predicate_trees has
    trees={}. semantic_capabilities resolves to {} — both keys present
    but empty, signaling 'analyzed, every function public'."""
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
