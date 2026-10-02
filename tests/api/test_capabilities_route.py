from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

# offline: no live owner()/governor() eth_call during predicate evaluation
pytestmark = pytest.mark.usefixtures("_stub_live_authority")


from tests.conftest import requires_postgres  # noqa: E402


def _seed_completed_job_with_artifact(
    db_session, *, address: str, predicate_trees, chain_id: int = 1, chain: str | None = None
):
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact

    request: dict = {"address": address}
    if chain is not None:
        request["chain"] = chain
    job = Job(
        address=address,
        chain_id=chain_id,
        request=request,
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    db_session.flush()
    if predicate_trees is not None:
        store_artifact(db_session, job.id, "predicate_trees", data=predicate_trees)
    db_session.commit()
    return job


def _equality_leaf_artifact(contract_name: str = "T") -> dict:
    return {
        "schema_version": "semantic",
        "contract_name": contract_name,
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
def test_capabilities_returns_per_function_dict(api_client, db_session):
    address = "0x" + uuid.uuid4().hex[:8] + "a1" * 16
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=_equality_leaf_artifact())

    resp = api_client.get(f"/api/contract/{address}/capabilities")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["contract_address"] == address.lower()
    assert body["chain_id"] == 1
    assert body["block"] is None
    assert "f()" in body["capabilities"]
    cap = body["capabilities"]["f()"]
    assert "kind" in cap
    assert "confidence" in cap
    assert "membership_quality" in cap


@requires_postgres
def test_capabilities_finds_checksummed_address_job(api_client, db_session):
    lower = "0x" + uuid.uuid4().hex[:8] + "ab" * 16
    mixed = lower[:2] + lower[2:].upper()
    _seed_completed_job_with_artifact(db_session, address=mixed, predicate_trees=_equality_leaf_artifact())

    resp = api_client.get(f"/api/contract/{lower}/capabilities")
    assert resp.status_code == 200, resp.text
    assert "f()" in resp.json()["capabilities"]


@requires_postgres
def test_capabilities_returns_404_for_unknown_address(api_client, db_session):
    resp = api_client.get(f"/api/contract/0x{'ee' * 20}/capabilities")
    assert resp.status_code == 404
    assert "No semantic capabilities" in resp.json()["detail"]


@requires_postgres
def test_capabilities_returns_404_when_predicate_tree_artifact_is_missing(api_client, db_session):
    address = "0x" + uuid.uuid4().hex[:8] + "b2" * 16
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=None)
    resp = api_client.get(f"/api/contract/{address}/capabilities")
    assert resp.status_code == 404
    assert "predicate-tree artifact is missing" in resp.json()["detail"]


@requires_postgres
def test_capabilities_empty_dict_for_unguarded_only_contract(api_client, db_session):
    address = "0x" + uuid.uuid4().hex[:8] + "c3" * 16
    _seed_completed_job_with_artifact(
        db_session,
        address=address,
        predicate_trees={"schema_version": "semantic", "contract_name": "T", "trees": {}},
    )
    resp = api_client.get(f"/api/contract/{address}/capabilities")
    assert resp.status_code == 200
    body = resp.json()
    assert body["capabilities"] == {}


@requires_postgres
def test_capabilities_block_query_param(api_client, db_session):
    address = "0x" + uuid.uuid4().hex[:8] + "d4" * 16
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=_equality_leaf_artifact())
    resp = api_client.get(f"/api/contract/{address}/capabilities", params={"block": 18_000_000})
    assert resp.status_code == 200
    assert resp.json()["block"] == 18_000_000


@requires_postgres
def test_capabilities_explicit_chain_isolates_twin(api_client, db_session, monkeypatch):
    """An explicit ``chain_id`` scopes the job pick to that chain: a
    CREATE2 twin analyzed on two chains resolves against the job on the
    REQUESTED chain, never falling back to another chain's trees; a chain with
    no completed job 404s instead of silently serving a twin's data."""
    from routers import predicate_capabilities

    predicate_capabilities._capabilities_cache.clear()
    monkeypatch.setattr(predicate_capabilities, "_CAPABILITIES_CACHE_TTL_S", 0.0)

    address = "0x" + uuid.uuid4().hex[:8] + "e6" * 16

    def _guard_tree(fn: str) -> dict:
        art = _equality_leaf_artifact()
        art["trees"] = {fn: art["trees"]["f()"]}
        return art

    _seed_completed_job_with_artifact(
        db_session, address=address, predicate_trees=_guard_tree("eth_fn()"), chain_id=1, chain="ethereum"
    )
    _seed_completed_job_with_artifact(
        db_session, address=address, predicate_trees=_guard_tree("poly_fn()"), chain_id=137, chain="polygon"
    )

    resp_poly = api_client.get(f"/api/contract/{address}/capabilities", params={"chain_id": 137})
    assert resp_poly.status_code == 200, resp_poly.text
    poly_caps = resp_poly.json()["capabilities"]
    assert "poly_fn()" in poly_caps and "eth_fn()" not in poly_caps, poly_caps

    resp_eth = api_client.get(f"/api/contract/{address}/capabilities", params={"chain_id": 1})
    assert resp_eth.status_code == 200, resp_eth.text
    eth_caps = resp_eth.json()["capabilities"]
    assert "eth_fn()" in eth_caps and "poly_fn()" not in eth_caps, eth_caps

    resp_base = api_client.get(f"/api/contract/{address}/capabilities", params={"chain_id": 8453})
    assert resp_base.status_code == 404, resp_base.text


@requires_postgres
def test_capabilities_response_includes_data_freshness(api_client, db_session, monkeypatch):
    from db.models import IndexedEventCursor
    from routers import predicate_capabilities

    predicate_capabilities._capabilities_cache.clear()
    monkeypatch.setattr(predicate_capabilities, "_CAPABILITIES_CACHE_TTL_S", 0.0)  # disable cache for the test

    address = "0x" + uuid.uuid4().hex[:8] + "df" * 16

    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=address,
            topic0="0x" + "ab" * 32,
            last_indexed_block=18_500_000,
            last_indexed_block_hash=b"\xee" * 32,
            backfill_complete=True,
        )
    )
    db_session.commit()

    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=_equality_leaf_artifact())

    resp = api_client.get(f"/api/contract/{address}/capabilities")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "data_freshness" in body
    event_logs = body["data_freshness"]["event_logs"]
    assert event_logs is not None
    assert event_logs["cursor_count"] == 1
    assert event_logs["last_indexed_block"] == 18_500_000
    assert event_logs["last_run_at"] is not None  # ISO8601 string


@requires_postgres
def test_capabilities_response_freshness_null_when_no_cursor(api_client, db_session, monkeypatch):

    from routers import predicate_capabilities

    predicate_capabilities._capabilities_cache.clear()
    monkeypatch.setattr(predicate_capabilities, "_CAPABILITIES_CACHE_TTL_S", 0.0)

    address = "0x" + uuid.uuid4().hex[:8] + "fa" * 16
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=_equality_leaf_artifact())

    resp = api_client.get(f"/api/contract/{address}/capabilities")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data_freshness"] == {"event_logs": None}


@requires_postgres
@pytest.mark.parametrize(
    "ttl_s, expected_resolver_calls",
    [
        # Repeat hits within the TTL short-circuit the resolver.
        pytest.param(60.0, 1, id="cached-within-ttl"),
        pytest.param(0.0, 2, id="ttl-disabled-when-zero"),
    ],
)
def test_capabilities_response_caching(api_client, db_session, monkeypatch, ttl_s, expected_resolver_calls):
    from services.resolution import capability_resolver as resolver_mod

    address = "0x" + uuid.uuid4().hex[:8] + "ca" * 16
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=_equality_leaf_artifact())

    from routers import predicate_capabilities

    predicate_capabilities._capabilities_cache.clear()
    monkeypatch.setattr(predicate_capabilities, "_CAPABILITIES_CACHE_TTL_S", ttl_s)

    calls = {"n": 0}
    original = resolver_mod.resolve_contract_capabilities

    def _counting(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(resolver_mod, "resolve_contract_capabilities", _counting)

    r1 = api_client.get(f"/api/contract/{address}/capabilities")
    r2 = api_client.get(f"/api/contract/{address}/capabilities")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json() == r2.json()
    assert calls["n"] == expected_resolver_calls


@requires_postgres
def test_capabilities_cache_keyed_on_block_and_chain(api_client, db_session, monkeypatch):
    from services.resolution import capability_resolver as resolver_mod

    address = "0x" + uuid.uuid4().hex[:8] + "cc" * 16
    # The job pick is a hard filter on chain, so seed the twin on both
    # queried chains; the chain_id=137 request resolves its own job rather than
    # relying on a cross-chain fallback.
    _seed_completed_job_with_artifact(
        db_session, address=address, predicate_trees=_equality_leaf_artifact(), chain_id=1, chain="ethereum"
    )
    _seed_completed_job_with_artifact(
        db_session, address=address, predicate_trees=_equality_leaf_artifact(), chain_id=137, chain="polygon"
    )

    from routers import predicate_capabilities

    predicate_capabilities._capabilities_cache.clear()
    monkeypatch.setattr(predicate_capabilities, "_CAPABILITIES_CACHE_TTL_S", 60.0)

    calls = {"n": 0}
    original = resolver_mod.resolve_contract_capabilities

    def _counting(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(resolver_mod, "resolve_contract_capabilities", _counting)

    api_client.get(f"/api/contract/{address}/capabilities")  # default chain=1, block=None
    api_client.get(f"/api/contract/{address}/capabilities?chain_id=137")
    api_client.get(f"/api/contract/{address}/capabilities?block=18000000")
    assert calls["n"] == 3


@requires_postgres
def test_capabilities_route_is_not_admin_gated(api_client, db_session):
    """Adding require_admin_key would lock external consumers out."""
    import api as api_module
    from routers.deps import require_admin_key

    api_module.app.dependency_overrides.pop(require_admin_key, None)

    address = "0x" + uuid.uuid4().hex[:8] + "f6" * 16
    _seed_completed_job_with_artifact(db_session, address=address, predicate_trees=_equality_leaf_artifact())
    resp = api_client.get(f"/api/contract/{address}/capabilities")
    assert resp.status_code == 200
