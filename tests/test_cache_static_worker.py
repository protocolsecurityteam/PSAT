"""Tests for static worker cache hit/miss and proxy cache (mock-based)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from cache_helpers import (
    ADDR_A,
    IMPL_ADDR,
    IMPL_ADDR_NEW,
    _create_completed_job_with_static_data,
    _create_source_job_with_proxy,
    _create_target_job_with_contract,
    _patch_static_worker_phases,
    db_session,  # noqa: F401
    requires_postgres,
)

pytestmark = requires_postgres

# ---------------------------------------------------------------------------
# Static worker cache hit
# ---------------------------------------------------------------------------


def test_static_worker_cache_hit_skips_analysis(db_session, monkeypatch):
    """Job flagged as static_cached skips Slither/analysis but runs deps."""
    from db.models import Contract
    from db.queue import create_job, store_artifact, store_source_files
    from workers.static_worker import StaticWorker

    # Create a new job with the explicit cache flag set by discovery worker
    job = create_job(db_session, {"address": ADDR_A, "rpc_url": "https://rpc.example", "static_cached": True})
    contract = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="TestContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
    )
    db_session.add(contract)
    db_session.commit()

    store_source_files(db_session, job.id, {"src/TestContract.sol": "contract TestContract {}"})
    store_artifact(db_session, job.id, "contract_analysis", data={"summary": {}})

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    worker.process(db_session, job)

    # Dependency phase and proxy resolution should run; Slither/analysis/tracking should NOT
    assert "resolve_proxy" in phases_run
    assert "dependency" in phases_run
    assert "slither" not in phases_run
    assert "analysis" not in phases_run
    assert "tracking_plan" not in phases_run


# ---------------------------------------------------------------------------
# Static worker cache miss
# ---------------------------------------------------------------------------


def test_static_worker_cache_miss_runs_analysis(db_session, monkeypatch):
    """Job without cached artifacts runs all analysis phases normally."""
    from db.models import Contract
    from db.queue import create_job, store_source_files
    from workers.static_worker import StaticWorker

    job = create_job(db_session, {"address": ADDR_A, "rpc_url": "https://rpc.example"})
    contract = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="TestContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
    )
    db_session.add(contract)
    db_session.commit()

    store_source_files(db_session, job.id, {"src/TestContract.sol": "contract TestContract {}"})

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    worker.process(db_session, job)

    # All phases should run (slither CLI subprocess removed in commit 438a11c).
    assert "resolve_proxy" in phases_run
    assert "dependency" in phases_run
    assert "analysis" in phases_run
    assert "tracking_plan" in phases_run


# ---------------------------------------------------------------------------
# Proxy cache optimization -- _check_proxy_cache tests (mock-based)
# ---------------------------------------------------------------------------


def test_proxy_cache_non_proxy_source(db_session, monkeypatch):
    """Cache hit with non-proxy source: _resolve_proxy is NOT called, contract has is_proxy=False."""
    from sqlalchemy import select

    from db.models import Contract
    from workers.static_worker import StaticWorker

    source_job = _create_source_job_with_proxy(
        db_session,
        is_proxy=False,
        proxy_type=None,
        implementation=None,
    )
    target_job = _create_target_job_with_contract(db_session, source_job.id)

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    worker.process(db_session, target_job)

    assert "resolve_proxy" not in phases_run
    assert "dependency" in phases_run

    contract = db_session.execute(select(Contract).where(Contract.job_id == target_job.id)).scalar_one()
    assert contract.is_proxy is False
    assert contract.implementation is None


def test_proxy_cache_proxy_unchanged(db_session, monkeypatch):
    """Cache hit with unchanged proxy: _resolve_proxy is NOT called, proxy fields are copied."""
    from sqlalchemy import select

    from db.models import Contract
    from workers.static_worker import StaticWorker

    source_job = _create_source_job_with_proxy(
        db_session,
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
        beacon="0xbeac000000000000000000000000000000000000",
        admin="0xad1c000000000000000000000000000000000000",
    )
    target_job = _create_target_job_with_contract(db_session, source_job.id)

    # resolve_current_implementation returns the SAME address -> no upgrade
    monkeypatch.setattr(
        "workers.static_worker.resolve_current_implementation",
        lambda addr, rpc, **kw: IMPL_ADDR,
    )

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    # Proxy contracts raise JobHandledDirectly because the proxy wrapper is
    # completed directly and a child job handles the implementation analysis.
    from workers.base import JobHandledDirectly

    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, target_job)

    assert "resolve_proxy" not in phases_run

    contract = db_session.execute(select(Contract).where(Contract.job_id == target_job.id)).scalar_one()
    assert contract.is_proxy is True
    assert contract.proxy_type == "eip1967"
    assert contract.implementation.lower() == IMPL_ADDR.lower()
    assert contract.beacon is not None
    assert contract.admin is not None


def test_proxy_cache_proxy_upgraded(db_session, monkeypatch):
    """Cache hit but proxy upgraded: _resolve_proxy IS called.

    After _resolve_proxy runs (mocked), the contract is still a proxy so
    the static worker correctly skips Slither and raises JobHandledDirectly.
    """
    from workers.base import JobHandledDirectly
    from workers.static_worker import StaticWorker

    source_job = _create_source_job_with_proxy(
        db_session,
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
    )
    target_job = _create_target_job_with_contract(db_session, source_job.id)

    # resolve_current_implementation returns a DIFFERENT address -> upgrade detected
    monkeypatch.setattr(
        "workers.static_worker.resolve_current_implementation",
        lambda addr, rpc, **kw: IMPL_ADDR_NEW,
    )

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, target_job)

    assert "resolve_proxy" in phases_run


def test_proxy_cache_rpc_fails(db_session, monkeypatch):
    """Cache hit but RPC fails: falls back to full _resolve_proxy.

    After _resolve_proxy runs (mocked), the contract is still a proxy so
    the static worker correctly skips Slither and raises JobHandledDirectly.
    """
    from workers.base import JobHandledDirectly
    from workers.static_worker import StaticWorker

    source_job = _create_source_job_with_proxy(
        db_session,
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
    )
    target_job = _create_target_job_with_contract(db_session, source_job.id)

    def mock_resolve(addr, rpc, **kw):
        raise ConnectionError("RPC node down")

    monkeypatch.setattr("workers.static_worker.resolve_current_implementation", mock_resolve)

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, target_job)

    assert "resolve_proxy" in phases_run


def test_proxy_cache_no_cache_flag(db_session, monkeypatch):
    """Job without static_cached flag: _resolve_proxy IS called normally."""
    from db.models import Contract
    from db.queue import create_job, store_source_files
    from workers.static_worker import StaticWorker

    job = create_job(db_session, {"address": ADDR_A, "rpc_url": "https://rpc.example"})
    contract = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="TestContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
    )
    db_session.add(contract)
    db_session.commit()
    store_source_files(db_session, job.id, {"src/Test.sol": "contract Test {}"})

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    worker.process(db_session, job)

    assert "resolve_proxy" in phases_run


def test_proxy_cache_immutable_eip1167(db_session, monkeypatch):
    """Cache hit with eip1167 (immutable) proxy: reuse without any RPC call."""
    from sqlalchemy import select

    from db.models import Contract
    from workers.static_worker import StaticWorker

    source_job = _create_source_job_with_proxy(
        db_session,
        is_proxy=True,
        proxy_type="eip1167",
        implementation=IMPL_ADDR,
    )
    target_job = _create_target_job_with_contract(db_session, source_job.id)

    # resolve_current_implementation should NOT be called for immutable types
    resolve_called = []

    def mock_resolve(addr, rpc, **kw):
        resolve_called.append(addr)
        return IMPL_ADDR

    monkeypatch.setattr("workers.static_worker.resolve_current_implementation", mock_resolve)

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    from workers.base import JobHandledDirectly

    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, target_job)

    assert "resolve_proxy" not in phases_run
    assert resolve_called == []  # No RPC for immutable proxy type

    contract = db_session.execute(select(Contract).where(Contract.job_id == target_job.id)).scalar_one()
    assert contract.is_proxy is True
    assert contract.proxy_type == "eip1167"
    assert contract.implementation.lower() == IMPL_ADDR.lower()


def test_proxy_cache_diamond_proxy_falls_back(db_session, monkeypatch):
    """Cache hit with diamond proxy (eip2535): falls back to full _resolve_proxy.

    After _resolve_proxy runs (mocked), the contract is still a proxy so
    the static worker correctly skips Slither and raises JobHandledDirectly.
    """
    from workers.base import JobHandledDirectly
    from workers.static_worker import StaticWorker

    source_job = _create_source_job_with_proxy(
        db_session,
        is_proxy=True,
        proxy_type="eip2535",
        implementation=IMPL_ADDR,
    )
    target_job = _create_target_job_with_contract(db_session, source_job.id)

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, target_job)

    assert "resolve_proxy" in phases_run


# ---------------------------------------------------------------------------
# _check_proxy_cache / _apply_proxy_cache unit tests
# ---------------------------------------------------------------------------


def test_apply_proxy_cache_non_proxy(db_session):
    """_apply_proxy_cache on a non-proxy source returns type=regular."""
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import _apply_proxy_cache

    job = create_job(db_session, {"address": ADDR_A})
    src = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="Src",
        is_proxy=False,
        proxy_type=None,
        implementation=None,
        beacon=None,
        admin=None,
    )
    db_session.add(src)
    db_session.flush()

    target = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="Target",
    )
    db_session.add(target)
    db_session.flush()

    result = _apply_proxy_cache(db_session, src, target)
    assert result == {"type": "regular"}
    assert target.is_proxy is False


def test_apply_proxy_cache_proxy(db_session):
    """_apply_proxy_cache on a proxy source copies all proxy fields."""
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import _apply_proxy_cache

    job = create_job(db_session, {"address": ADDR_A})
    src = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="Src",
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
        beacon="0xbeac",
        admin="0xadmn",
    )
    db_session.add(src)
    db_session.flush()

    target = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="Target",
    )
    db_session.add(target)
    db_session.flush()

    result = _apply_proxy_cache(db_session, src, target)
    assert result["type"] == "proxy"
    assert result["proxy_type"] == "eip1967"
    assert result["implementation"] == IMPL_ADDR
    assert target.is_proxy is True
    assert target.proxy_type == "eip1967"
    assert target.implementation == IMPL_ADDR


# ---------------------------------------------------------------------------
# _check_proxy_cache edge case tests
# ---------------------------------------------------------------------------


def test_check_proxy_cache_no_source_job_id(db_session):
    """_check_proxy_cache returns None when cache_source_job_id is missing."""
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import _check_proxy_cache

    job = create_job(
        db_session,
        {
            "address": ADDR_A,
            "rpc_url": "https://rpc.example",
            "static_cached": True,
            # cache_source_job_id intentionally omitted
        },
    )
    contract = Contract(job_id=job.id, address=ADDR_A, contract_name="T")
    db_session.add(contract)
    db_session.flush()

    result = _check_proxy_cache(db_session, job, contract)
    assert result is None


def test_check_proxy_cache_source_contract_missing(db_session):
    """_check_proxy_cache returns None when source job has no contract row."""
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import _check_proxy_cache

    source_job = create_job(db_session, {"address": ADDR_A})
    # No contract row added for source_job

    job = create_job(
        db_session,
        {
            "address": ADDR_A,
            "rpc_url": "https://rpc.example",
            "static_cached": True,
            "cache_source_job_id": str(source_job.id),
        },
    )
    contract = Contract(job_id=job.id, address=ADDR_A, contract_name="T")
    db_session.add(contract)
    db_session.flush()

    result = _check_proxy_cache(db_session, job, contract)
    assert result is None


def test_check_proxy_cache_proxy_no_cached_impl(db_session):
    """_check_proxy_cache returns None when source proxy has no implementation address."""
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import _check_proxy_cache

    source_job = create_job(db_session, {"address": ADDR_A})
    src_contract = Contract(
        job_id=source_job.id,
        address=ADDR_A,
        contract_name="Proxy",
        is_proxy=True,
        proxy_type="eip1967",
        implementation=None,
    )
    db_session.add(src_contract)
    db_session.flush()

    job = create_job(
        db_session,
        {
            "address": ADDR_A,
            "rpc_url": "https://rpc.example",
            "static_cached": True,
            "cache_source_job_id": str(source_job.id),
        },
    )
    contract = Contract(job_id=job.id, address=ADDR_A, contract_name="Proxy")
    db_session.add(contract)
    db_session.flush()

    result = _check_proxy_cache(db_session, job, contract)
    assert result is None


def test_check_proxy_cache_no_rpc_url(db_session):
    """_check_proxy_cache returns None when no RPC URL is available."""
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import _check_proxy_cache

    source_job = create_job(db_session, {"address": ADDR_A})
    src_contract = Contract(
        job_id=source_job.id,
        address=ADDR_A,
        contract_name="Proxy",
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
    )
    db_session.add(src_contract)
    db_session.flush()

    job = create_job(
        db_session,
        {
            "address": ADDR_A,
            # No rpc_url
            "static_cached": True,
            "cache_source_job_id": str(source_job.id),
        },
    )
    contract = Contract(job_id=job.id, address=ADDR_A, contract_name="Proxy")
    db_session.add(contract)
    db_session.flush()

    # Clear ETH_RPC env var to ensure no fallback
    import os

    old_rpc = os.environ.pop("ETH_RPC", None)
    old_erpc = os.environ.pop("ERPC_BASE_URL", None)
    try:
        result = _check_proxy_cache(db_session, job, contract)
        assert result is None
    finally:
        if old_rpc is not None:
            os.environ["ETH_RPC"] = old_rpc
        if old_erpc is not None:
            os.environ["ERPC_BASE_URL"] = old_erpc


# ---------------------------------------------------------------------------
# End-to-end: discovery cache hit -> static worker cache hit
# ---------------------------------------------------------------------------


def test_e2e_discovery_then_static_with_cache(db_session, monkeypatch):
    """End-to-end test: run discovery (cache hit), then static (cached)
    and verify the complete flow works with the static_cached flag."""

    from db.queue import create_job, get_artifact, get_source_files
    from workers.discovery import DiscoveryWorker
    from workers.static_worker import StaticWorker

    # Phase 0: Create a completed job to serve as cache
    _create_completed_job_with_static_data(db_session)

    # Phase 1: Discovery -- should hit cache
    new_job = create_job(db_session, {"address": ADDR_A, "rpc_url": "https://rpc.example"})

    monkeypatch.setattr(
        "workers.discovery.fetch",
        lambda addr: (_ for _ in ()).throw(AssertionError("fetch should not be called")),
    )

    disc_worker = DiscoveryWorker()
    disc_worker.update_detail = MagicMock()
    disc_worker._process_address(db_session, new_job)

    # Verify cache flags set
    db_session.refresh(new_job)
    assert isinstance(new_job.request, dict)
    assert new_job.request.get("static_cached") is True

    # Phase 2: Static -- should skip analysis phases
    static_worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, static_worker)

    static_worker.process(db_session, new_job)

    # Slither/analysis/tracking should be skipped
    assert "slither" not in phases_run
    assert "analysis" not in phases_run
    assert "tracking_plan" not in phases_run
    # But dependency and proxy resolution should run
    assert "dependency" in phases_run

    # Data should be intact
    sources = get_source_files(db_session, new_job.id)
    assert len(sources) == 2
    assert get_artifact(db_session, new_job.id, "contract_analysis") is not None


# ---------------------------------------------------------------------------
# _resolve_dynamic_deps: dead-code removal regression test
# ---------------------------------------------------------------------------


def test_resolve_dynamic_deps_non_dict_request(db_session, monkeypatch):
    """_resolve_dynamic_deps works when job.request is not a dict (e.g. None).

    Previously the function contained a dead assignment
    ``request = job.request if isinstance(job.request, dict) else {}``.
    This test verifies the function operates correctly regardless of the
    type of ``job.request``.
    """
    from db.queue import create_job
    from workers.static_worker import _resolve_dynamic_deps

    job = create_job(db_session, {"address": ADDR_A, "rpc_url": "https://rpc"})
    # Force job.request to None to simulate a non-dict value
    job.request = None
    db_session.flush()

    fake_output = {
        "dependencies": ["0xdead"],
        "transactions_analyzed": [],
        "dependency_graph": [],
        "provenance": {},
    }

    monkeypatch.setattr(
        "workers.static_worker.find_dynamic_dependencies",
        lambda *a, **kw: fake_output,
    )

    result, error = _resolve_dynamic_deps(
        db_session,
        job,
        ADDR_A,
        "https://rpc",
        10,
        None,
        None,
        {},
    )

    assert error is None
    assert result is not None
    assert result["dependencies"] == ["0xdead"]
