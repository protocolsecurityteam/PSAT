from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from tests.conftest import requires_postgres


def _no_auth(api_module):
    from routers.deps import require_admin

    api_module.app.dependency_overrides[require_admin] = lambda: None


def _seed_completed_job_with_artifact(
    db_session,
    *,
    address: str,
    predicate_trees: dict | None,
    chain_id: int | None = None,
    updated_at: datetime | None = None,
):
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact

    ts = updated_at or datetime.now(timezone.utc)
    job = Job(
        address=address,
        chain_id=chain_id,
        request={"address": address, "name": "T"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=ts,
        updated_at=ts,
    )
    db_session.add(job)
    db_session.flush()
    if predicate_trees is not None:
        store_artifact(db_session, job.id, "predicate_trees", data=predicate_trees)
    db_session.commit()
    return job


def _address_topic(address: str) -> str:
    return "0x" + address.lower()[2:].rjust(64, "0")


_MEMBERSHIP_TREE = {
    "op": "LEAF",
    "leaf": {
        "kind": "membership",
        "operator": "truthy",
        "authority_role": "caller_authority",
        "operands": [{"source": "msg_sender"}],
        "set_descriptor": {
            "kind": "mapping_membership",
            "key_sources": [
                {"source": "constant", "constant_value": "0x" + "01" * 32},
                {"source": "msg_sender"},
            ],
            "storage_var": "_roles",
        },
        "references_msg_sender": True,
        "parameter_indices": [],
        "expression": "_roles[ROLE][msg.sender]",
        "basis": [],
    },
}


@requires_postgres
def test_probe_membership_uses_explicit_chain_id_job(api_client, db_session):
    """A CREATE2 twin has one completed job per chain, each with its own
    predicate_trees. An explicit ``chain_id`` must load *that* chain's trees,
    not the most-recently-updated job's."""
    import api as api_module

    _no_auth(api_module)
    address = "0x" + "ab" * 20
    now = datetime.now(timezone.utc)
    # The ethereum job is newest and guards f(); the base job leaves f() unguarded, so the responses differ.
    _seed_completed_job_with_artifact(
        db_session,
        address=address,
        chain_id=1,
        updated_at=now,
        predicate_trees={"schema_version": "semantic", "contract_name": "EthC", "trees": {"f()": _MEMBERSHIP_TREE}},
    )
    _seed_completed_job_with_artifact(
        db_session,
        address=address,
        chain_id=8453,
        updated_at=now - timedelta(hours=1),
        predicate_trees={"schema_version": "semantic", "contract_name": "BaseC", "trees": {}},
    )

    resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json={
            "function_signature": "f()",
            "predicate_index": 0,
            "member": "0x" + "11" * 20,
            "chain_id": 8453,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("reason") == "function_unguarded", body


@requires_postgres
def test_probe_membership_no_completed_job_returns_404(api_client, db_session):
    import api as api_module

    _no_auth(api_module)
    resp = api_client.post(
        f"/api/contract/0x{'ee' * 20}/probe/membership",
        json={
            "function_signature": "f()",
            "predicate_index": 0,
            "member": "0x" + "11" * 20,
        },
    )
    assert resp.status_code == 404
    assert "No completed analysis job" in resp.json()["detail"]


@requires_postgres
def test_probe_membership_no_artifact_returns_404(api_client, db_session):
    import api as api_module

    _no_auth(api_module)
    address = "0x" + "f1" * 20
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=None)

    resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json={
            "function_signature": "f()",
            "predicate_index": 0,
            "member": "0x" + "11" * 20,
        },
    )
    assert resp.status_code == 404
    assert "predicate_trees artifact missing" in resp.json()["detail"]


@requires_postgres
def test_probe_membership_semantic_error_payload_returns_unknown(api_client, db_session):
    """A failed semantic emit degrades to unknown instead of a 500."""
    import api as api_module

    _no_auth(api_module)
    address = "0x" + "f2" * 20
    artifact = {"schema_version": "semantic", "error": "semantic_emit_blew_up"}
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=artifact)

    resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json={
            "function_signature": "f()",
            "predicate_index": 0,
            "member": "0x" + "11" * 20,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"] == "unknown"
    assert body["reason"] == "predicate_trees_unavailable"
    assert body["detail"] == "semantic_emit_blew_up"


@requires_postgres
def test_probe_membership_rejects_malformed_address_payload(api_client, db_session):
    import api as api_module

    _no_auth(api_module)
    address = "0x" + "1f" * 20
    _seed_completed_job_with_artifact(
        db_session,
        address=address,
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )

    resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json={
            "function_signature": "f()",
            "predicate_index": 0,
            "member": "not-an-address",
        },
    )
    assert resp.status_code == 422


@requires_postgres
def test_probe_membership_returns_yes_via_postgres_event_log_repo(api_client, db_session):
    """Proves the Postgres event repo wiring does real work instead of falling through."""
    import api as api_module
    from db.models import Contract, IndexedEventCursor, IndexedEventLog, Protocol

    _no_auth(api_module)

    # A uuid-derived address keeps reruns from colliding on ``contracts.address+chain``.
    import uuid as _uuid

    suffix = _uuid.uuid4().hex[:8]
    address = "0x" + suffix + "00" * 16
    role_const_hex = "0x" + "01" * 32
    member = "0x" + "44" * 20
    topic0 = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"

    proto = Protocol(name=f"probe_route_test_{suffix}")
    db_session.add(proto)
    db_session.flush()
    contract = Contract(
        address=address,
        chain="ethereum",
        protocol_id=proto.id,
    )
    db_session.add(contract)
    db_session.flush()
    db_session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=address,
            topic0=topic0,
            tx_hash=b"\xaa" * 32,
            log_index=0,
            block_number=100,
            block_hash=b"\xbb" * 32,
            transaction_index=0,
            topics=[topic0, role_const_hex, _address_topic(member)],
            data_words=[],
        )
    )
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=address,
            topic0=topic0,
            last_indexed_block=18_500_000,
            last_indexed_block_hash=b"\xcc" * 32,
            backfill_complete=True,
            first_indexed_block=0,
            first_indexed_block_basis="creation_block_minus_one",
        )
    )
    db_session.flush()

    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "guardedFn()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "key_sources": [
                            {"source": "constant", "constant_value": role_const_hex},
                            {"source": "msg_sender"},
                        ],
                        "storage_var": "_roles",
                        "enumeration_hint": [
                            {
                                "event_address": address,
                                "topic0": topic0,
                                "topics_to_keys": {1: 0, 2: 1},
                                "data_to_keys": {},
                                "direction": "add",
                            }
                        ],
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "_roles[ROLE][msg.sender]",
                    "basis": [],
                },
            }
        },
    }
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=artifact)

    # block=None is live head, which the cursor lags (#119), so a non-member would read "unknown". A covering finalized
    # block keeps the set exact, as the resolver's head pin does in prod.
    covering_block = 18_000_000

    granted_resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json={
            "function_signature": "guardedFn()",
            "predicate_index": 0,
            "member": member,
            "block": covering_block,
        },
    )
    assert granted_resp.status_code == 200, granted_resp.text
    granted_body = granted_resp.json()
    assert granted_body["result"] == "yes", granted_body
    assert granted_body["leaf_kind"] == "membership"

    unknown_member = "0x" + "55" * 20
    no_resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json={
            "function_signature": "guardedFn()",
            "predicate_index": 0,
            "member": unknown_member,
            "block": covering_block,
        },
    )
    assert no_resp.status_code == 200, no_resp.text
    no_body = no_resp.json()
    assert no_body["result"] == "no", no_body


@requires_postgres
def test_probe_signature_route_for_signature_auth_leaf(api_client, db_session):
    """With no adapter resolving the signer, the witness wraps a lower-bound placeholder; the response still names
    capability_kind.
    """
    import api as api_module

    _no_auth(api_module)
    address = "0x" + uuid.uuid4().hex[:8] + "8b" * 16
    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "execute()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "signature_auth",
                    "operator": "eq",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "signature_recovery"},
                        {"source": "state_variable", "state_variable_name": "trustedSigner"},
                    ],
                    "references_msg_sender": False,
                    "parameter_indices": [],
                    "expression": "ecrecover(...) == trustedSigner",
                    "basis": [],
                },
            }
        },
    }
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=artifact)

    resp = api_client.post(
        f"/api/contract/{address}/probe/signature",
        json={
            "function_signature": "execute()",
            "predicate_index": 0,
            "recovered_signer": "0x" + "ee" * 20,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["leaf_kind"] == "signature_auth"
    assert body.get("capability_kind") == "signature_witness"
    assert body["result"] in ("yes", "no", "unknown")


@requires_postgres
def test_probe_signature_rejects_malformed_signer(api_client, db_session):
    import api as api_module

    _no_auth(api_module)
    address = "0x" + uuid.uuid4().hex[:8] + "8c" * 16
    _seed_completed_job_with_artifact(
        db_session,
        address=address,
        predicate_trees={"schema_version": "semantic", "contract_name": "T", "trees": {}},
    )
    resp = api_client.post(
        f"/api/contract/{address}/probe/signature",
        json={
            "function_signature": "f()",
            "predicate_index": 0,
            "recovered_signer": "not-an-address",
        },
    )
    assert resp.status_code == 422


@requires_postgres
def test_probe_rate_limit_applies_to_signature_route_too(api_client, db_session, monkeypatch):
    import api as api_module

    _no_auth(api_module)
    address = "0x" + uuid.uuid4().hex[:8] + "ed" * 16
    _seed_completed_job_with_artifact(
        db_session,
        address=address,
        predicate_trees={"schema_version": "semantic", "contract_name": "T", "trees": {}},
    )

    from routers import predicate_capabilities

    monkeypatch.setattr(predicate_capabilities, "_PROBE_RATE_LIMIT", 2)
    predicate_capabilities._probe_rate_state.clear()

    headers = {"X-PSAT-Admin-Key": "test-key"}
    sig_payload = {
        "function_signature": "execute()",
        "predicate_index": 0,
        "recovered_signer": "0x" + "11" * 20,
    }
    membership_payload = {
        "function_signature": "open()",
        "predicate_index": 0,
        "member": "0x" + "11" * 20,
    }

    # Membership and signature probes share one (key, address) budget.
    api_client.post(f"/api/contract/{address}/probe/membership", json=membership_payload, headers=headers)
    api_client.post(f"/api/contract/{address}/probe/signature", json=sig_payload, headers=headers)
    third = api_client.post(f"/api/contract/{address}/probe/signature", json=sig_payload, headers=headers)
    assert third.status_code == 429


def test_probe_rate_limit_prunes_stale_buckets(monkeypatch):
    import collections

    from routers import predicate_capabilities

    stale_addr = "0x" + "aa" * 20
    fresh_addr = "0x" + "bb" * 20
    monkeypatch.setattr(predicate_capabilities, "_PROBE_RATE_LIMIT", 3)
    monkeypatch.setattr(predicate_capabilities, "_PROBE_RATE_WINDOW_S", 60.0)
    # Reclamation runs in an amortized sweep; fire it on the next hit instead of after 4096.
    monkeypatch.setattr(predicate_capabilities._probe_limiter, "_sweep_every", 1)
    predicate_capabilities._probe_rate_state.clear()
    predicate_capabilities._probe_rate_state[("old-key", stale_addr, 1)] = collections.deque([1.0])

    predicate_capabilities._probe_rate_check("new-key", fresh_addr, 1)

    assert ("old-key", stale_addr, 1) not in predicate_capabilities._probe_rate_state
    assert ("new-key", fresh_addr, 1) in predicate_capabilities._probe_rate_state


@requires_postgres
def test_probe_membership_picks_most_recent_completed_job(api_client, db_session):
    """An old re-analysis with stale artifacts must not shadow a newer one."""
    import api as api_module
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact

    _no_auth(api_module)
    address = "0x" + "2f" * 20

    older = Job(
        address=address,
        request={"address": address},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    newer = Job(
        address=address,
        request={"address": address},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    db_session.add_all([older, newer])
    db_session.flush()

    def _tree(expr: str) -> dict:
        return {
            "schema_version": "semantic",
            "trees": {
                "f()": {
                    "op": "LEAF",
                    "leaf": {
                        "kind": "equality",
                        "operator": "eq",
                        "authority_role": "caller_authority",
                        "operands": [],
                        "references_msg_sender": True,
                        "parameter_indices": [],
                        "expression": expr,
                        "basis": [],
                    },
                }
            },
        }

    store_artifact(db_session, older.id, "predicate_trees", data={"schema_version": "semantic", "trees": {}})
    store_artifact(db_session, newer.id, "predicate_trees", data=_tree("NEW"))
    db_session.commit()

    resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json={
            "function_signature": "f()",
            "predicate_index": 0,
            "member": "0x" + "11" * 20,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["leaf_kind"] == "equality"
    assert body["reason"] == "non_membership_leaf"
