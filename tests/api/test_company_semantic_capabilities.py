"""``null`` means no predicate-tree artifact; ``{}`` means analyzed with no guarded functions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

# offline: no live owner()/governor() eth_call during predicate evaluation
pytestmark = pytest.mark.usefixtures("_stub_live_authority")


from tests.conftest import requires_postgres  # noqa: E402


def _seed_protocol_with_jobs(db_session, *, name: str, addresses_with_artifacts):
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


def _guard_tree(fn: str) -> dict:
    art = _semantic_artifact_with_guard()
    art["trees"] = {fn: art["trees"]["f()"]}
    return art


@requires_postgres
def test_company_semantic_capabilities_twin_keeps_both_chains(api_client, db_session):
    """Invariant 13: resolving per bare address used to drop the older chain's set."""
    from db.models import Job, JobStage, JobStatus, Protocol
    from db.queue import store_artifact

    name = f"twin_semcaps_{uuid.uuid4().hex[:6]}"
    addr = "0x" + uuid.uuid4().hex[:8] + "77" * 16
    proto = Protocol(name=name)
    db_session.add(proto)
    db_session.flush()
    for chain_id, chain_name, fn in ((1, "ethereum", "eth_fn()"), (8453, "base", "base_fn()")):
        job = Job(
            address=addr,
            protocol_id=proto.id,
            chain_id=chain_id,
            request={"address": addr, "chain": chain_name},
            status=JobStatus.completed,
            stage=JobStage.done,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(job)
        db_session.flush()
        store_artifact(db_session, job.id, "predicate_trees", data=_guard_tree(fn))
    db_session.commit()

    resp = api_client.get(f"/api/company/{name}/semantic_capabilities")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    by_entity = body["contracts_by_entity"]
    eth_key = f"ethereum::{addr.lower()}"
    base_key = f"base::{addr.lower()}"
    assert eth_key in by_entity and base_key in by_entity, sorted(by_entity)
    assert "eth_fn()" in by_entity[eth_key] and "base_fn()" not in by_entity[eth_key], by_entity[eth_key]
    assert "base_fn()" in by_entity[base_key] and "eth_fn()" not in by_entity[base_key], by_entity[base_key]

    # The bare map keeps the newest completed job per address.
    assert body["contracts"][addr.lower()] is not None
    assert body["missing_semantic_count"] == 0


@requires_postgres
def test_company_semantic_capabilities_unknown_company_404(api_client, db_session):
    resp = api_client.get(f"/api/company/no_such_{uuid.uuid4().hex[:6]}/semantic_capabilities")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Company not found"


@requires_postgres
def test_company_semantic_capabilities_resolver_failure_treated_as_missing(api_client, db_session, monkeypatch):
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
    # The handler imports the function lazily, so patching the module export is enough.
    import services.resolution.capability_resolver as cr_mod

    monkeypatch.setattr(cr_mod, "resolve_contract_capabilities", _boom)

    resp = api_client.get(f"/api/company/{name}/semantic_capabilities")
    assert resp.status_code == 200
    body = resp.json()
    assert body["contracts"][addr] is None
    assert body["missing_semantic_count"] == 1
