from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from services.discovery.classifier import ClassificationIncompleteError
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from workers.static_worker import StaticWorker

_ADDR = "0x1111111111111111111111111111111111111111"
_IMPL_ADDR = "0x3333333333333333333333333333333333333333"
_FACET1 = "0x4444444444444444444444444444444444444444"
_FACET2 = "0x5555555555555555555555555555555555555555"
# A local (Anvil) URL is the one explicit rpc_url that still propagates to child
# jobs; a hosted URL is ignored in favor of eRPC (see tests/rpc/test_erpc_routing.py).
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
    store_calls: list[tuple] = []
    created_jobs: list[dict] = []

    monkeypatch.setattr(
        "workers.static_worker.store_artifact",
        lambda _session, _job_id, name, data=None, text_data=None: store_calls.append((name, data, text_data)),
    )

    child_counter = iter(range(100))

    def _fake_create(_session, request):
        created_jobs.append(request)
        return SimpleNamespace(id=f"child-{next(child_counter)}")

    monkeypatch.setattr("workers.static_worker.create_job", _fake_create)

    return store_calls, created_jobs


def test_non_proxy_stores_flags_with_is_proxy_false(monkeypatch):
    worker = StaticWorker()
    session = MagicMock()
    job = _job()

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {"type": "regular"},
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert len(store_calls) == 1
    name, data, _ = store_calls[0]
    assert name == "contract_flags"
    assert data["is_proxy"] is False
    assert data["classification_type"] == "regular"
    assert created_jobs == []


def test_proxy_falls_back_to_contract_name_for_child(monkeypatch):
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

    worker._resolve_proxy(session, job, _ADDR, "ContractNameFallback")

    assert created_jobs[0]["name"] == "ContractNameFallback: (impl)"


def test_beacon_is_analyzed_yet_still_spawns_impl_child(monkeypatch):
    """The beacon is analysed itself (to find its owner) and its implementation is spawned in beacon context."""
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
    monkeypatch.setattr("workers.static_worker.reconcile_impl_job_for_proxy", lambda *a, **k: "spawn")
    monkeypatch.setattr("workers.static_worker._redirect_proxy_policy_dependencies", lambda *a, **k: None)

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert contract_row.is_proxy is False
    assert contract_row.proxy_type == "beacon"
    assert contract_row.implementation == _IMPL_ADDR
    assert contract_row.beacon == _ADDR

    flags = store_calls[0][1]
    assert flags["is_proxy"] is False
    assert flags["classification_type"] == "beacon"
    assert flags["proxy_type"] == "beacon"
    assert flags["beacon"] == _ADDR

    assert len(created_jobs) == 1
    child_req = created_jobs[0]
    assert child_req["address"] == _IMPL_ADDR
    assert child_req["proxy_address"] == _ADDR
    assert child_req["proxy_type"] == "beacon"


def test_proxy_facets_only_no_impl(monkeypatch):
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

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert len(created_jobs) == 2
    assert created_jobs[0]["name"] == "TestContract: (facet 1)"
    assert created_jobs[1]["name"] == "TestContract: (facet 2)"


def test_no_rpc_stores_classification_skipped(monkeypatch):
    worker = StaticWorker()
    session = MagicMock()
    job = _job(request={})  # no rpc_url

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)
    monkeypatch.delenv("ETH_RPC", raising=False)
    monkeypatch.delenv("ERPC_BASE_URL", raising=False)

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert len(store_calls) == 1
    flags = store_calls[0][1]
    assert flags["is_proxy"] is False
    assert flags["classification_skipped"] == "no_rpc"
    assert flags["classification_type"] == "unknown"
    assert created_jobs == []


def test_erpc_chain_route_used_when_request_has_chain(monkeypatch):
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

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert captured_rpc == ["https://erpc-proxy.example/main/evm/8453"]
    assert store_calls[0][1]["classification_type"] == "regular"


def test_classify_exception_stores_classification_error(monkeypatch):
    worker = StaticWorker()
    session = MagicMock()
    job = _job()

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: (_ for _ in ()).throw(ConnectionError("RPC timeout")),
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert len(store_calls) == 1
    flags = store_calls[0][1]
    assert flags["is_proxy"] is False
    assert flags["classification_type"] == "unknown"
    assert "RPC timeout" in flags["classification_error"]
    assert created_jobs == []


def test_partial_existing_jobs_creates_only_missing(monkeypatch):
    worker = StaticWorker()
    session = MagicMock()

    # Up to 3 lookups per impl; a same-proxy hit short-circuits to skip.
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

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert len(created_jobs) == 1
    assert created_jobs[0]["address"] == _FACET1
    assert created_jobs[0]["name"] == "TestContract: (facet 1)"


# #121: a proxy-slot read failure fails closed.


def test_classification_incomplete_fails_closed_and_reraises(monkeypatch):
    """Swallowing it would Slither an ``is_proxy=False`` shell."""
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
        worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert degraded and degraded[0][0] == "proxy_classification"
    assert isinstance(degraded[0][1], ClassificationIncompleteError)
    assert all(name != "contract_flags" for name, _data, _text in store_calls)
    assert created_jobs == []


# These drive real rows, so they need Postgres rather than MagicMock.


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
