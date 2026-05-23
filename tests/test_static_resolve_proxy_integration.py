"""Integration tests for StaticWorker._resolve_proxy() internal logic.

These tests exercise the classify-then-dispatch logic inside _resolve_proxy
without mocking the method itself, covering classification outcomes, child job
creation, deduplication, error handling, and the no-RPC fallback.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workers.static_worker import StaticWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ADDR = "0x1111111111111111111111111111111111111111"
_IMPL_ADDR = "0x3333333333333333333333333333333333333333"
_FACET1 = "0x4444444444444444444444444444444444444444"
_FACET2 = "0x5555555555555555555555555555555555555555"
_RPC = "https://rpc.example"


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

    def _fake_create(_session, request):
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
        lambda address, rpc_url: {"type": "regular"},
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

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
        lambda address, rpc_url: {"type": "library"},
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

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
        lambda address, rpc_url: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

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
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job(request={"rpc_url": _RPC, "chain": "base"})

    _, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

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
        lambda address, rpc_url: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    worker._resolve_proxy(session, job, _ADDR, "FallbackName")

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
        lambda address, rpc_url: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    worker._resolve_proxy(session, job, _ADDR, "ContractNameFallback")

    assert created_jobs[0]["name"] == "ContractNameFallback: (impl)"


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
        lambda address, rpc_url: {
            "type": "proxy",
            "proxy_type": "diamond",
            "implementation": _IMPL_ADDR,
            "facets": [_FACET1, _FACET2],
        },
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

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
        lambda address, rpc_url: {
            "type": "proxy",
            "proxy_type": "diamond",
            "implementation": _IMPL_ADDR,
            "facets": [_IMPL_ADDR, _FACET1],  # impl duplicated in facets
        },
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

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
        lambda address, rpc_url: {
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

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert len(store_calls) == 1
    flags = store_calls[0][1]
    assert flags["is_proxy"] is False
    assert flags["classification_skipped"] == "no_rpc"
    assert flags["classification_type"] == "unknown"
    assert created_jobs == []


def test_no_rpc_env_fallback_used_when_request_has_no_rpc(monkeypatch):
    """ETH_RPC env var is used as fallback when request lacks rpc_url."""
    worker = StaticWorker()
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job(request={})  # no rpc_url in request

    store_calls, created_jobs = _capture_store_and_create(monkeypatch)
    monkeypatch.setenv("ETH_RPC", "https://env-rpc.example")

    captured_rpc = []
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url: (
            captured_rpc.append(rpc_url) or {"type": "proxy", "proxy_type": "eip1967", "implementation": _IMPL_ADDR}
        ),
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    assert captured_rpc == ["https://env-rpc.example"]
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
        lambda address, rpc_url: captured_rpc.append(rpc_url) or {"type": "regular"},
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

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
        lambda address, rpc_url: (_ for _ in ()).throw(ConnectionError("RPC timeout")),
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

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

    def _raise(address, rpc_url):
        raise ValueError("unexpected bytecode format")

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        _raise,
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

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
        lambda address, rpc_url: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": _IMPL_ADDR,
        },
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    # Flags are still stored
    assert store_calls[0][1]["is_proxy"] is True
    assert store_calls[0][1]["implementation"] == _IMPL_ADDR

    # But no child job is created
    assert created_jobs == []


def test_partial_existing_jobs_creates_only_missing(monkeypatch):
    """With multiple impls, only creates child jobs for addresses without existing jobs."""
    worker = StaticWorker()
    session = MagicMock()

    # First call is Contract table lookup, then impl job check, then facet job check
    existing_job = SimpleNamespace(id="existing-job-id")
    session.execute.return_value.scalar_one_or_none.side_effect = [
        None,  # Contract table lookup (no row)
        existing_job,  # impl already exists
        None,  # facet 1 does not exist
    ]

    job = _job()
    store_calls, created_jobs = _capture_store_and_create(monkeypatch)

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url: {
            "type": "proxy",
            "proxy_type": "diamond",
            "implementation": _IMPL_ADDR,
            "facets": [_FACET1],
        },
    )

    worker._resolve_proxy(session, job, _ADDR, "TestContract")

    # Only facet child job created (impl was skipped)
    assert len(created_jobs) == 1
    assert created_jobs[0]["address"] == _FACET1
    assert created_jobs[0]["name"] == "TestContract: (facet 1)"
