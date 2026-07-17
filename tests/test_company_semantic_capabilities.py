"""End-to-end tests for ``GET /api/company/{name}/semantic_capabilities``.

Read-only, not admin-gated. Returns the per-contract semantic
capability map for every analyzed contract in the company,
distinguishing "no predicate-tree artifact" (``null``) from "semantically analyzed
with no guarded functions" (``{}``).
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


def _seed_protocol_with_jobs(db_session, *, name: str, addresses_with_artifacts):
    """``addresses_with_artifacts`` is a list of
    ``(address, predicate_trees_or_None)``."""
    from db.models import Job, JobStage, JobStatus, Protocol
    from db.queue import store_artifact

    proto = Protocol(name=name)
    db_session.add(proto)
    db_session.flush()
    for address, artifact in addresses_with_artifacts:
        job = Job(
            address=address,
            protocol_id=proto.id,
            chain_id=1,
            request={"address": address},
            status=JobStatus.completed,
            stage=JobStage.done,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(job)
        db_session.flush()
        if artifact is not None:
            store_artifact(db_session, job.id, "predicate_trees", data=artifact)
    db_session.commit()
    return proto


def _semantic_artifact_with_guard() -> dict:
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


def _semantic_artifact_unguarded_only() -> dict:
    return {"schema_version": "semantic", "contract_name": "T", "trees": {}}


@requires_postgres
def test_company_semantic_capabilities_per_contract_map(api_client, db_session):
    """Three contracts in the company: one with semantic guards, one
    semantically analyzed but unguarded, one legacy pre-semantic. Each maps
    distinguishably."""
    name = f"company_semantic_{uuid.uuid4().hex[:6]}"
    addr_guarded = "0x" + uuid.uuid4().hex[:8] + "11" * 16
    addr_unguarded = "0x" + uuid.uuid4().hex[:8] + "22" * 16
    addr_legacy = "0x" + uuid.uuid4().hex[:8] + "33" * 16
    _seed_protocol_with_jobs(
        db_session,
        name=name,
        addresses_with_artifacts=[
            (addr_guarded, _semantic_artifact_with_guard()),
            (addr_unguarded, _semantic_artifact_unguarded_only()),
            (addr_legacy, None),  # no predicate_trees artifact
        ],
    )

    resp = api_client.get(f"/api/company/{name}/semantic_capabilities")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["company"] == name
    assert body["missing_semantic_count"] == 1
    contracts = body["contracts"]
    assert addr_guarded in contracts
    assert "f()" in contracts[addr_guarded]
    assert "kind" in contracts[addr_guarded]["f()"]
    assert addr_unguarded in contracts
    assert contracts[addr_unguarded] == {}
    assert addr_legacy in contracts
    assert contracts[addr_legacy] is None


@requires_postgres
def test_company_semantic_capabilities_unknown_company_404(api_client, db_session):
    resp = api_client.get(f"/api/company/no_such_{uuid.uuid4().hex[:6]}/semantic_capabilities")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Company not found"


@requires_postgres
def test_company_semantic_capabilities_empty_when_no_completed_jobs(api_client, db_session):
    """A company with no completed analyses returns an empty
    contracts map — distinct from the 404 unknown-company case."""
    from db.models import Protocol

    name = f"empty_company_{uuid.uuid4().hex[:6]}"
    proto = Protocol(name=name)
    db_session.add(proto)
    db_session.commit()

    resp = api_client.get(f"/api/company/{name}/semantic_capabilities")
    assert resp.status_code == 200
    body = resp.json()
    assert body["company"] == name
    assert body["contracts"] == {}
    assert body["missing_semantic_count"] == 0


@requires_postgres
def test_company_semantic_capabilities_resolver_failure_treated_as_missing(api_client, db_session, monkeypatch):
    """If the resolver raises for a contract, that contract is
    counted as missing rather than 500ing the whole endpoint."""
    name = f"company_failsafe_{uuid.uuid4().hex[:6]}"
    addr = "0x" + uuid.uuid4().hex[:8] + "44" * 16
    _seed_protocol_with_jobs(
        db_session,
        name=name,
        addresses_with_artifacts=[(addr, _semantic_artifact_with_guard())],
    )

    def _boom(*a, **kw):
        raise RuntimeError("simulated resolver failure")

    monkeypatch.setattr("services.resolution.capability_resolver.resolve_contract_capabilities", _boom)
    # The api module imported the function lazily inside the
    # handler, so monkeypatching the module-level export is enough.
    # Ensure the api module also picks up the patch on the next call.
    import services.resolution.capability_resolver as cr_mod

    monkeypatch.setattr(cr_mod, "resolve_contract_capabilities", _boom)

    resp = api_client.get(f"/api/company/{name}/semantic_capabilities")
    assert resp.status_code == 200
    body = resp.json()
    assert body["contracts"][addr] is None
    assert body["missing_semantic_count"] == 1


@requires_postgres
def test_company_semantic_capabilities_route_not_admin_gated(api_client, db_session):
    """Mirror of the /api/contract/{addr}/capabilities pin: this
    endpoint is read-only and external consumers need it without
    credentials."""
    import api as api_module
    from routers.deps import require_admin_key

    api_module.app.dependency_overrides.pop(require_admin_key, None)

    name = f"company_unauth_{uuid.uuid4().hex[:6]}"
    addr = "0x" + uuid.uuid4().hex[:8] + "55" * 16
    _seed_protocol_with_jobs(
        db_session,
        name=name,
        addresses_with_artifacts=[(addr, _semantic_artifact_with_guard())],
    )

    resp = api_client.get(f"/api/company/{name}/semantic_capabilities")
    assert resp.status_code == 200
