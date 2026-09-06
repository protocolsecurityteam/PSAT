"""Integration tests for StaticWorker._resolve_proxy() internal logic.

These tests exercise the classify-then-dispatch logic inside _resolve_proxy
without mocking the method itself, covering classification outcomes, child job
creation, deduplication, error handling, and the no-RPC fallback.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from services.discovery.classifier import ClassificationIncompleteError
from tests.attempt_helpers import claimed_call
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from workers.static_worker import StaticWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ADDR = "0x1111111111111111111111111111111111111111"
_IMPL_ADDR = "0x3333333333333333333333333333333333333333"
_FACET1 = "0x4444444444444444444444444444444444444444"
_FACET2 = "0x5555555555555555555555555555555555555555"
# A local (Anvil) URL is the one explicit rpc_url that still propagates to child
# jobs; a hosted URL is ignored in favor of eRPC (see test_erpc_routing.py).
_RPC = "http://127.0.0.1:8545"


def _job(**overrides):
    payload = {
        "id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
        "address": _ADDR,
        "name": "TestContract",
        "request": {"rpc_url": _RPC},
        "protocol_id": None,
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def _capture_store_and_create(monkeypatch):
    """Patch store_artifact and create_job, returning (store_calls, created_jobs)."""
    store_calls: list[tuple] = []
    created_jobs: list[dict] = []

    monkeypatch.setattr(
        "workers.static_worker.store_artifact",
        lambda _session, _job_id, name, data=None, text_data=None: store_calls.append((name, data, text_data)),
    )

    child_counter = iter(range(100))

    def _fake_create(_session, request, **_routing):
        created_jobs.append(request)
        return SimpleNamespace(id=f"child-{next(child_counter)}")

    monkeypatch.setattr("workers.static_worker.create_job", _fake_create)

    return store_calls, created_jobs


# ---------------------------------------------------------------------------
# 1. Non-proxy classification
# ---------------------------------------------------------------------------


def test_non_proxy_stores_flags_with_is_proxy_false(monkeypatch):
    """classify_single returns 'regular' -> contract_flags has is_proxy=False."""
    worker = StaticWorker()
    session = MagicMock()
    job = _job()

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {"type": "regular"},
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    assert len(store_calls) == 1
    name, data, _ = store_calls[0]
    assert name == "contract_flags"
    assert data["is_proxy"] is False
    assert data["classification_type"] == "regular"
    assert created_jobs == []


def test_non_proxy_library_type(monkeypatch):
    """classify_single returns 'library' -> stored as non-proxy with correct type."""
    worker = StaticWorker()
    session = MagicMock()
    job = _job()

    store_calls, _ = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {"type": "library"},
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    assert store_calls[0][1] == {"is_proxy": False, "classification_type": "library"}


# ---------------------------------------------------------------------------
# 2. Proxy classification with implementation
# ---------------------------------------------------------------------------


def test_proxy_with_implementation_creates_child_job(monkeypatch):
    """EIP-1967 proxy with implementation -> flags stored, child job created."""
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    # contract_flags stored correctly
    assert len(store_calls) == 1
    flags = store_calls[0][1]
    assert flags["is_proxy"] is True
    assert flags["classification_type"] == "proxy"
    assert flags["proxy_type"] == "eip1967"
    assert flags["implementation"] == _IMPL_ADDR

    # child job created with correct request
    assert len(created_jobs) == 1
    child_req = created_jobs[0]
    assert child_req["address"] == _IMPL_ADDR
    assert child_req["name"] == "TestContract: (impl)"
    assert child_req["rpc_url"] == _RPC
    assert child_req["parent_job_id"] == str(job.id)
    assert child_req["proxy_address"] == _ADDR
    assert child_req["proxy_type"] == "eip1967"


def test_proxy_child_job_inherits_chain(monkeypatch):
    """When request includes 'chain', child job request also includes it."""
    # Models a base-enabled deployment: impl-child spawns gate off-allowlist
    # chains (inv. 14), so make the premise explicit rather than relying on {1}.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job(request={"rpc_url": _RPC, "chain": "base"})

    _, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    assert len(created_jobs) == 1
    assert created_jobs[0]["chain"] == "base"


def test_proxy_uses_job_name_for_child_naming(monkeypatch):
    """Child job name is built from job.name when available."""
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job(name="MyProxy")

    _, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "FallbackName")

    assert created_jobs[0]["name"] == "MyProxy: (impl)"


def test_proxy_falls_back_to_contract_name_for_child(monkeypatch):
    """When job.name is None, child job uses contract_name."""
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job(name=None)

    _, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "ContractNameFallback")

    assert created_jobs[0]["name"] == "ContractNameFallback: (impl)"


# ---------------------------------------------------------------------------
# 2b. UpgradeableBeacon classification
# ---------------------------------------------------------------------------


def test_beacon_is_analyzed_yet_still_spawns_impl_child(monkeypatch):
    """A type='beacon' classification keeps is_proxy=False so the static worker
    analyses the beacon itself (discovering its owner()), AND still spawns the
    implementation as a beacon-context child so each governed instance resolves
    against the beacon (proxy_type='beacon', proxy_address=<beacon>)."""
    worker = StaticWorker()
    session = MagicMock()
    contract_row = SimpleNamespace(
        is_proxy=None,
        proxy_type=None,
        implementation=None,
        beacon=None,
        admin=None,
        protocol_id=None,
        address=_ADDR,
        discovery_sources=None,
    )
    session.execute.return_value.scalar_one_or_none.return_value = contract_row
    job = _job()

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "beacon",
            "implementation": _IMPL_ADDR,
            "owner": "0x2222222222222222222222222222222222222222",
        },
    )
    # reconcile returns "spawn" -> create_job runs (all dedup lookups miss).
    monkeypatch.setattr("workers.static_worker.reconcile_impl_job_for_proxy", lambda *a, **k: "spawn")
    monkeypatch.setattr("workers.static_worker._redirect_proxy_policy_dependencies", lambda *a, **k: None)

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    # The beacon is analysed as itself: is_proxy stays False.
    assert contract_row.is_proxy is False
    assert contract_row.proxy_type == "beacon"
    assert contract_row.implementation == _IMPL_ADDR
    assert contract_row.beacon == _ADDR

    flags = store_calls[0][1]
    assert flags["is_proxy"] is False
    assert flags["classification_type"] == "beacon"
    assert flags["proxy_type"] == "beacon"
    assert flags["beacon"] == _ADDR

    # The impl child is still spawned in beacon context.
    assert len(created_jobs) == 1
    child_req = created_jobs[0]
    assert child_req["address"] == _IMPL_ADDR
    assert child_req["proxy_address"] == _ADDR
    assert child_req["proxy_type"] == "beacon"


# ---------------------------------------------------------------------------
# 3. Proxy with facets (diamond pattern)
# ---------------------------------------------------------------------------


def test_diamond_proxy_creates_jobs_for_impl_and_facets(monkeypatch):
    """Diamond proxy with impl + 2 facets -> 3 child jobs (impl + 2 facets)."""
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "proxy",
            "proxy_type": "diamond",
            "implementation": _IMPL_ADDR,
            "facets": [_FACET1, _FACET2],
        },
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    # Flags stored with facets
    flags = store_calls[0][1]
    assert flags["is_proxy"] is True
    assert flags["proxy_type"] == "diamond"
    assert flags["facets"] == [_FACET1, _FACET2]

    # 3 child jobs: impl + facet 1 + facet 2
    assert len(created_jobs) == 3
    assert created_jobs[0]["address"] == _IMPL_ADDR
    assert created_jobs[0]["name"] == "TestContract: (impl)"
    assert created_jobs[1]["address"] == _FACET1
    assert created_jobs[1]["name"] == "TestContract: (facet 1)"
    assert created_jobs[2]["address"] == _FACET2
    assert created_jobs[2]["name"] == "TestContract: (facet 2)"


def test_diamond_proxy_deduplicates_impl_in_facets(monkeypatch):
    """If implementation address appears in facets list, it is not duplicated."""
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    _, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "proxy",
            "proxy_type": "diamond",
            "implementation": _IMPL_ADDR,
            "facets": [_IMPL_ADDR, _FACET1],  # impl duplicated in facets
        },
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    # Only 2 child jobs: impl + facet 1 (impl not duplicated)
    assert len(created_jobs) == 2
    addresses = [j["address"] for j in created_jobs]
    assert addresses == [_IMPL_ADDR, _FACET1]


def test_proxy_facets_only_no_impl(monkeypatch):
    """Proxy with facets but no implementation -> child jobs only for facets."""
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    _, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "proxy",
            "proxy_type": "diamond",
            "implementation": None,
            "facets": [_FACET1, _FACET2],
        },
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    assert len(created_jobs) == 2
    assert created_jobs[0]["name"] == "TestContract: (facet 1)"
    assert created_jobs[1]["name"] == "TestContract: (facet 2)"


# ---------------------------------------------------------------------------
# 4. No RPC available
# ---------------------------------------------------------------------------


def test_no_rpc_stores_classification_skipped(monkeypatch):
    """No rpc_url in request and no ETH_RPC env -> classification_skipped."""
    worker = StaticWorker()
    session = MagicMock()
    job = _job(request={})  # no rpc_url

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)
    monkeypatch.delenv("ETH_RPC", raising=False)
    monkeypatch.delenv("ERPC_BASE_URL", raising=False)

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    assert len(store_calls) == 1
    flags = store_calls[0][1]
    assert flags["is_proxy"] is False
    assert flags["classification_skipped"] == "no_rpc"
    assert flags["classification_type"] == "unknown"
    assert created_jobs == []


def test_erpc_mainnet_route_used_when_request_has_no_rpc(monkeypatch):
    """With no rpc_url/chain in the request, the mainnet eRPC route is used (no ETH_RPC fallback)."""
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job(request={"chain_id": 1})  # no rpc_url in request; mainnet chain supplied explicitly

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)
    monkeypatch.delenv("ETH_RPC", raising=False)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    captured_rpc = []
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: (
            captured_rpc.append(rpc_url) or {"type": "proxy", "proxy_type": "eip1967", "implementation": _IMPL_ADDR}
        ),
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    assert captured_rpc == ["https://erpc-proxy.example/main/evm/1"]
    assert store_calls[0][1]["is_proxy"] is True


def test_erpc_chain_route_used_when_request_has_chain(monkeypatch):
    """Configured eRPC route is used when request has a supported chain."""
    worker = StaticWorker()
    session = MagicMock()
    job = _job(request={"chain": "base"})

    store_calls, _created_jobs = _capture_store_and_create(monkeypatch)
    monkeypatch.delenv("ETH_RPC", raising=False)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    captured_rpc = []
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: captured_rpc.append(rpc_url) or {"type": "regular"},
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    assert captured_rpc == ["https://erpc-proxy.example/main/evm/8453"]
    assert store_calls[0][1]["classification_type"] == "regular"


# ---------------------------------------------------------------------------
# 5. classify_single raises exception
# ---------------------------------------------------------------------------


def test_classify_exception_stores_classification_error(monkeypatch):
    """classify_single raises -> contract_flags with classification_error."""
    worker = StaticWorker()
    session = MagicMock()
    job = _job()

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: (_ for _ in ()).throw(ConnectionError("RPC timeout")),
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    assert len(store_calls) == 1
    flags = store_calls[0][1]
    assert flags["is_proxy"] is False
    assert flags["classification_type"] == "unknown"
    assert "RPC timeout" in flags["classification_error"]
    assert created_jobs == []


def test_classify_generic_exception_stores_error(monkeypatch):
    """Any exception type from classify_single is caught and stored."""
    worker = StaticWorker()
    session = MagicMock()
    job = _job()

    store_calls, _ = _capture_store_and_create(monkeypatch)

    def _raise(address, rpc_url, **_kw):
        raise ValueError("unexpected bytecode format")

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        _raise,
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    flags = store_calls[0][1]
    assert "unexpected bytecode format" in flags["classification_error"]


# ---------------------------------------------------------------------------
# 6. Existing impl job skip
# ---------------------------------------------------------------------------


def test_existing_impl_job_skips_child_creation(monkeypatch):
    """If a job already exists for the implementation address, skip creation."""
    worker = StaticWorker()
    session = MagicMock()

    existing_job = SimpleNamespace(id="existing-job-id")
    session.execute.return_value.scalar_one_or_none.return_value = existing_job

    job = _job()

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    # Flags are still stored
    assert store_calls[0][1]["is_proxy"] is True
    assert store_calls[0][1]["implementation"] == _IMPL_ADDR

    # But no child job is created
    assert created_jobs == []


def test_partial_existing_jobs_creates_only_missing(monkeypatch):
    """With multiple impls, only creates child jobs for addresses without existing jobs."""
    worker = StaticWorker()
    session = MagicMock()

    # reconcile_impl_job_for_proxy issues up to 3 lookups per impl (same-proxy /
    # standalone / different-proxy); a same-proxy hit short-circuits to "skip".
    existing_job = SimpleNamespace(id="existing-job-id")
    session.execute.return_value.scalar_one_or_none.side_effect = [
        None,  # Contract table lookup (no row)
        existing_job,  # impl: same-proxy job exists -> "skip" (one query)
        None,  # facet: same-proxy lookup (miss)
        None,  # facet: standalone lookup (miss)
        None,  # facet: different-proxy lookup (miss) -> "spawn"
    ]

    job = _job()
    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {
            "type": "proxy",
            "proxy_type": "diamond",
            "implementation": _IMPL_ADDR,
            "facets": [_FACET1],
        },
    )

    claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    # Only facet child job created (impl was skipped)
    assert len(created_jobs) == 1
    assert created_jobs[0]["address"] == _FACET1
    assert created_jobs[0]["name"] == "TestContract: (facet 1)"


# ---------------------------------------------------------------------------
# #121 — proxy-slot read failure fails closed (re-raise), never analyze a shell
# ---------------------------------------------------------------------------


def test_classification_incomplete_fails_closed_and_reraises(monkeypatch):
    """A ClassificationIncompleteError (proxy-slot read failed, transient RPC)
    must NOT be swallowed into an ``is_proxy=False`` shell that the static stage
    then Slithers. ``_resolve_proxy`` records the degradation and re-raises so the
    static stage fails closed into the worker retry path (registered transient)."""
    worker = StaticWorker()
    session = MagicMock()
    job = _job()

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    def _raise(address, rpc_url, **_kw):
        raise ClassificationIncompleteError("proxy slots unread")

    monkeypatch.setattr("services.discovery.classifier.classify_single", _raise)

    degraded: list = []
    monkeypatch.setattr(
        "workers.static_worker.record_degraded",
        lambda *, phase, exc, context: degraded.append((phase, exc)),
    )

    with pytest.raises(ClassificationIncompleteError):
        claimed_call(worker._resolve_proxy, session, job, _ADDR, "TestContract")

    # Degradation recorded, and crucially NO is_proxy=False contract_flags shell
    # artifact was written (which would have let the stage analyze the shell).
    assert degraded and degraded[0][0] == "proxy_classification"
    assert isinstance(degraded[0][1], ClassificationIncompleteError)
    assert all(name != "contract_flags" for name, _data, _text in store_calls)
    assert created_jobs == []


# ---------------------------------------------------------------------------
# Proxy → impl redirection at the job/dependency layer
#
# Both of these drive ``workers.static_worker`` — ``_redirect_proxy_policy_deps``
# and the dependency-provider lookup the resolver calls into — against real
# rows, so they need a Postgres session rather than the MagicMock above.
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Contract, Job, Protocol

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        s.query(Contract).delete()
        s.query(Job).delete()
        s.query(Protocol).delete()
        s.commit()
        s.close()
        engine.dispose()


def _seed_job_with_artifact(session, *, address: str, predicate_trees: dict | None):
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact

    job = Job(
        address=address,
        request={"address": address, "name": "T"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    if predicate_trees is not None:
        store_artifact(session, job.id, "predicate_trees", data=predicate_trees)
    session.commit()
    return job


@requires_postgres
def test_dependency_provider_lookup_returns_impl_child_for_proxy(session):
    from db.models import Contract, Protocol
    from db.queue import store_artifact
    from services.resolution.capability_resolver import find_dependency_provider_job_for_address

    proxy_addr = "0x" + uuid.uuid4().hex[:8] + "d4" * 16
    impl_addr = "0x" + uuid.uuid4().hex[:8] + "e5" * 16

    proto = Protocol(name=f"capres_dep_provider_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    proxy_job = _seed_job_with_artifact(session, address=proxy_addr, predicate_trees=None)
    proxy_job.request = {"address": proxy_addr, "name": "Registry", "chain": "ethereum"}
    session.add(
        Contract(
            address=proxy_addr,
            chain="ethereum",
            protocol_id=proto.id,
            job_id=proxy_job.id,
            is_proxy=True,
            implementation=impl_addr,
        )
    )

    impl_job = _seed_job_with_artifact(session, address=impl_addr, predicate_trees=None)
    impl_job.request = {
        "address": impl_addr,
        "name": "Registry: (impl)",
        "chain": "ethereum",
        "parent_job_id": str(proxy_job.id),
        "proxy_address": proxy_addr,
    }
    store_artifact(session, impl_job.id, "effective_permissions", data={"functions": []})
    session.commit()

    lookup = find_dependency_provider_job_for_address(session, proxy_addr, chain="ethereum")
    assert lookup is not None
    assert lookup.runtime_job.id == proxy_job.id
    assert lookup.analysis_job.id == impl_job.id


@requires_postgres
def test_static_proxy_resolution_redirects_pending_policy_dependency_to_impl(session):
    from db.models import JobDependency, JobStage
    from workers.static_worker import _redirect_proxy_policy_dependencies

    depender_addr = "0x" + uuid.uuid4().hex[:8] + "f6" * 16
    proxy_addr = "0x" + uuid.uuid4().hex[:8] + "a7" * 16
    impl_addr = "0x" + uuid.uuid4().hex[:8] + "b8" * 16

    depender = _seed_job_with_artifact(session, address=depender_addr, predicate_trees=None)
    session.add(
        JobDependency(
            depender_job_id=depender.id,
            provider_chain="ethereum",
            provider_address=proxy_addr,
            required_stage=JobStage.policy,
            status="pending",
        )
    )
    session.commit()

    changed = _redirect_proxy_policy_dependencies(
        session,
        chain="ethereum",
        proxy_addr=proxy_addr,
        impl_addr=impl_addr,
    )

    assert changed == 1
    row = session.query(JobDependency).filter_by(depender_job_id=depender.id).one()
    assert row.provider_address == impl_addr.lower()
    assert row.status == "pending"
