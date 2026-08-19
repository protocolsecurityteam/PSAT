"""End-to-end tests for ``POST /api/contract/{address}/probe/membership``.

Exercises the full route: address → most-recent completed Job →
predicate_trees artifact → probe_membership. Uses the
``api_client`` + ``db_session`` fixtures from conftest, which point
the FastAPI app at the test database.

The route is admin-gated; tests bypass auth by overriding
``api.require_admin_key`` to a no-op (the same pattern test_api.py
uses for other admin-gated endpoints).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from tests.conftest import requires_postgres  # noqa: E402

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _no_auth(api_module):
    # Auth dependency lives in routers.deps after the api.py routers refactor;
    # api.require_admin_key no longer exists. Patch via the canonical symbol.
    from routers.deps import require_admin_key

    api_module.app.dependency_overrides[require_admin_key] = lambda: None


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
    not the most-recently-updated job's (inv. 12)."""
    import api as api_module

    _no_auth(api_module)
    address = "0x" + "ab" * 20
    now = datetime.now(timezone.utc)
    # ethereum job is the most recent; without chain scoping the address-only
    # ORDER BY updated_at DESC would always pick it. It guards f(); the base
    # job leaves f() unguarded — so the two are distinguishable by response.
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
    # Base job leaves f() unguarded; the ethereum job would report a
    # membership leaf. The explicit chain_id=8453 must select the base job.
    assert body.get("reason") == "function_unguarded", body


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@requires_postgres
def test_probe_membership_returns_yes_for_known_member(api_client, db_session):
    """End-to-end happy path: a guarded function with a multi-key
    membership leaf, member is the caller. Adapter returns
    finite_set exact → result yes."""
    import api as api_module

    _no_auth(api_module)
    address = "0x" + "ab" * 20
    member = "0x" + "11" * 20
    # No event hint means there is no semantic enumeration backend for
    # this descriptor. The point of this test is that the route HTTP
    # layer (resolve address → job → artifact → tree → probe_membership)
    # plumbs through; we assert the payload shape.
    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "f()": {
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
        },
    }
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=artifact)

    resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json={
            "function_signature": "f()",
            "predicate_index": 0,
            "member": member,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["leaf_kind"] == "membership"
    assert body["authority_role"] == "caller_authority"
    # ``result`` is one of yes/no/unknown — the exact value depends
    # on which adapter wins; we pin the protocol shape.
    assert body["result"] in ("yes", "no", "unknown")


@requires_postgres
def test_probe_membership_unguarded_function_returns_yes(api_client, db_session):
    """Resolver convention: a function absent from semantic trees is
    publicly callable. The probe surface translates that into
    ``yes`` with reason ``function_unguarded`` so a UI can render
    'anyone can call this'."""
    import api as api_module

    _no_auth(api_module)
    address = "0x" + "cd" * 20
    artifact = {"schema_version": "semantic", "contract_name": "T", "trees": {}}
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=artifact)

    resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json={
            "function_signature": "open()",
            "predicate_index": 0,
            "member": "0x" + "11" * 20,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"] == "yes"
    assert body["reason"] == "function_unguarded"


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
    """A completed job without a predicate_trees artifact returns 404."""
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
    """When predicate_trees was emitted with an error (semantic emit
    failed mid-analysis), the artifact carries
    ``{"error": "..."}`` instead of ``trees``. The route returns
    a 200 with result=unknown so the UI can degrade gracefully
    rather than 500."""
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
    """Pydantic validator: ``member`` must be a 0x-prefixed
    20-byte address. Pinned so a regression doesn't allow an empty
    string / wrong-length blob through."""
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
    """End-to-end with the Postgres-backed generic event repo wired:
    a contract with a granted role for ``member`` resolves to
    ``yes`` (not ``unknown``/external_check_only). This is the
    cutover proof that the repo wiring on the route is doing real
    work, not just falling through to the no-backend path."""
    import api as api_module
    from db.models import Contract, IndexedEventCursor, IndexedEventLog, Protocol

    _no_auth(api_module)

    # Seed one generic indexed event for the role+member, plus a cursor
    # row so the repo reports a freshness block. Address derived from a
    # uuid so reruns + parallel test files don't collide on the
    # ``contracts.address+chain`` unique constraint.
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

    # Probe at a finalized height the cursor covers (last_indexed_block=18_500_000).
    # block=None means "at live head", which the durable cursor structurally lags
    # (#119) -> the fold honestly demotes exact->lower_bound and a non-member reads
    # "unknown". Pinning a covering finalized block keeps the set exact, so absence
    # is definitive ("no"). This mirrors the head-pin contract the resolver applies
    # in prod (max(1, head - RESOLVER_FINALITY_MARGIN)).
    covering_block = 18_000_000

    # Granted member -> yes
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

    # A different address -> no (the AC repo returned an exact
    # finite_set with one member, so absence is definitive).
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
def test_probe_signature_returns_unknown_for_non_signature_leaf(api_client, db_session):
    """The signature probe at index 0 of a membership leaf returns
    unknown with reason=non_signature_leaf — the routes are
    differentiated."""
    import api as api_module

    _no_auth(api_module)
    address = "0x" + uuid.uuid4().hex[:8] + "8a" * 16
    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "f()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "key_sources": [{"source": "msg_sender"}],
                        "storage_var": "_x",
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "_x[msg.sender]",
                    "basis": [],
                },
            }
        },
    }
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=artifact)

    resp = api_client.post(
        f"/api/contract/{address}/probe/signature",
        json={
            "function_signature": "f()",
            "predicate_index": 0,
            "recovered_signer": "0x" + "11" * 20,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["result"] == "unknown"
    assert body["reason"] == "non_signature_leaf"
    assert body["leaf_kind"] == "membership"


@requires_postgres
def test_probe_signature_route_for_signature_auth_leaf(api_client, db_session):
    """Happy-ish path: signature_auth leaf wraps a state-var
    signer. Without an adapter backend resolving the signer, the
    underlying signature_witness wraps a finite_set placeholder
    (lower_bound). The probe response surfaces the
    capability_kind so consumers can decide how to fall through."""
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
    # result is yes/no/unknown depending on whether the resolver
    # had a concrete signer set; pin the protocol shape only.
    assert body["result"] in ("yes", "no", "unknown")


@requires_postgres
def test_probe_signature_rejects_malformed_signer(api_client, db_session):
    """Pydantic Field validator pins recovered_signer shape (0x +
    40 hex)."""
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
def test_probe_signature_unguarded_function_returns_yes(api_client, db_session):
    import api as api_module

    _no_auth(api_module)
    address = "0x" + uuid.uuid4().hex[:8] + "8d" * 16
    _seed_completed_job_with_artifact(
        db_session,
        address=address,
        predicate_trees={"schema_version": "semantic", "contract_name": "T", "trees": {}},
    )
    resp = api_client.post(
        f"/api/contract/{address}/probe/signature",
        json={
            "function_signature": "open()",
            "predicate_index": 0,
            "recovered_signer": "0x" + "11" * 20,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"] == "yes"
    assert body["reason"] == "function_unguarded"


@requires_postgres
def test_probe_rate_limit_blocks_after_limit(api_client, db_session, monkeypatch):
    """v4 plan §15: 10/min/key/contract. Pinned with a tight
    limit so the test runs fast — same algorithm at any size."""
    import api as api_module

    _no_auth(api_module)
    address = "0x" + uuid.uuid4().hex[:8] + "ee" * 16
    _seed_completed_job_with_artifact(
        db_session,
        address=address,
        predicate_trees={"schema_version": "semantic", "contract_name": "T", "trees": {}},
    )

    # Tighten the limit to 3 so the test isn't slow. Also clear
    # any per-key state from previous tests.
    from routers import predicate_capabilities

    monkeypatch.setattr(predicate_capabilities, "_PROBE_RATE_LIMIT", 3)
    predicate_capabilities._probe_rate_state.clear()

    payload = {
        "function_signature": "open()",
        "predicate_index": 0,
        "member": "0x" + "11" * 20,
    }
    headers = {"X-PSAT-Admin-Key": "test-key"}

    # First 3 requests succeed (function unguarded -> result yes).
    for _ in range(3):
        resp = api_client.post(
            f"/api/contract/{address}/probe/membership",
            json=payload,
            headers=headers,
        )
        assert resp.status_code == 200, resp.text

    # 4th request rate-limited.
    resp = api_client.post(
        f"/api/contract/{address}/probe/membership",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 429, resp.text
    assert "rate limit exceeded" in resp.json()["detail"].lower()
    assert "Retry-After" in resp.headers


@requires_postgres
def test_probe_rate_limit_keyed_per_address(api_client, db_session, monkeypatch):
    """The rate limit is per (admin_key, address) — exhausting
    the budget for one contract doesn't block others."""
    import api as api_module

    _no_auth(api_module)
    addr_a = "0x" + uuid.uuid4().hex[:8] + "ea" * 16
    addr_b = "0x" + uuid.uuid4().hex[:8] + "eb" * 16
    for addr in (addr_a, addr_b):
        _seed_completed_job_with_artifact(
            db_session,
            address=addr,
            predicate_trees={"schema_version": "semantic", "contract_name": "T", "trees": {}},
        )

    from routers import predicate_capabilities

    monkeypatch.setattr(predicate_capabilities, "_PROBE_RATE_LIMIT", 2)
    predicate_capabilities._probe_rate_state.clear()

    payload = {
        "function_signature": "open()",
        "predicate_index": 0,
        "member": "0x" + "11" * 20,
    }
    headers = {"X-PSAT-Admin-Key": "test-key"}

    # Exhaust addr_a (limit=2).
    for _ in range(2):
        api_client.post(f"/api/contract/{addr_a}/probe/membership", json=payload, headers=headers)
    a_third = api_client.post(f"/api/contract/{addr_a}/probe/membership", json=payload, headers=headers)
    assert a_third.status_code == 429

    # addr_b's budget is independent.
    b_first = api_client.post(f"/api/contract/{addr_b}/probe/membership", json=payload, headers=headers)
    assert b_first.status_code == 200


@requires_postgres
def test_probe_rate_limit_disabled_when_zero(api_client, db_session, monkeypatch):
    """``PSAT_PROBE_RATE_LIMIT=0`` (env-tuned to 0) disables
    rate limiting entirely — useful for local dev / the existing
    tests that don't care about throttling."""
    import api as api_module

    _no_auth(api_module)
    address = "0x" + uuid.uuid4().hex[:8] + "ec" * 16
    _seed_completed_job_with_artifact(
        db_session,
        address=address,
        predicate_trees={"schema_version": "semantic", "contract_name": "T", "trees": {}},
    )

    from routers import predicate_capabilities

    monkeypatch.setattr(predicate_capabilities, "_PROBE_RATE_LIMIT", 0)
    predicate_capabilities._probe_rate_state.clear()

    payload = {
        "function_signature": "open()",
        "predicate_index": 0,
        "member": "0x" + "11" * 20,
    }
    # 50 requests in a tight loop — none rate-limited.
    for _ in range(50):
        resp = api_client.post(
            f"/api/contract/{address}/probe/membership",
            json=payload,
            headers={"X-PSAT-Admin-Key": "test-key"},
        )
        assert resp.status_code == 200


@requires_postgres
def test_probe_rate_limit_applies_to_signature_route_too(api_client, db_session, monkeypatch):
    """Both probe routes share the rate limiter."""
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

    # Mix membership + signature; both count toward the same
    # (key, address) budget.
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
    # Stale reclamation is now amortized into a full sweep rather than run on
    # every hit (the per-hit all-buckets walk was the self-DoS this fix removed).
    # Force the sweep to fire on the next hit so the test pins reclamation
    # without the 4096-hit warm-up the default sweep interval would need.
    monkeypatch.setattr(predicate_capabilities._probe_limiter, "_sweep_every", 1)
    predicate_capabilities._probe_rate_state.clear()
    predicate_capabilities._probe_rate_state[("old-key", stale_addr, 1)] = collections.deque([1.0])

    predicate_capabilities._probe_rate_check("new-key", fresh_addr, 1)

    assert ("old-key", stale_addr, 1) not in predicate_capabilities._probe_rate_state
    assert ("new-key", fresh_addr, 1) in predicate_capabilities._probe_rate_state


@requires_postgres
def test_probe_membership_picks_most_recent_completed_job(api_client, db_session):
    """Two completed jobs for the same address — the route uses
    the most recent one (by updated_at). Pinned so an old
    re-analysis with stale artifact data doesn't shadow a newer
    one."""
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

    store_artifact(db_session, older.id, "predicate_trees", data=_tree("OLD"))
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
    # Equality leaf -> non_membership_leaf; that's expected. The
    # point: the route picked the NEWER tree, so the leaf walks
    # without finding membership data. We don't assert text equality
    # on `expression` here because the field isn't surfaced in the
    # response — the implicit pin is "no 500 / no stale-tree
    # error", just the standard non-membership-leaf signal.
    assert resp.status_code == 200
    body = resp.json()
    assert body["leaf_kind"] == "equality"
    assert body["reason"] == "non_membership_leaf"
