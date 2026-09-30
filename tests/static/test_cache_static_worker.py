"""A proxy that's still a proxy after the mocked ``_resolve_proxy`` skips Slither and raises ``JobHandledDirectly``."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.cache_helpers import (
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


def test_static_worker_cache_hit_skips_analysis(db_session, monkeypatch):
    from db.models import Contract
    from db.queue import create_job, store_artifact, store_source_files
    from workers.static_worker import StaticWorker

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

    assert "resolve_proxy" in phases_run
    assert "dependency" in phases_run
    assert "slither" not in phases_run
    assert "analysis" not in phases_run
    assert "tracking_plan" not in phases_run


def test_static_worker_cache_miss_runs_analysis(db_session, monkeypatch):
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

    assert "resolve_proxy" in phases_run
    assert "dependency" in phases_run
    assert "analysis" in phases_run
    assert "tracking_plan" in phases_run


def test_proxy_cache_non_proxy_source(db_session, monkeypatch):
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
    req = target_job.request if isinstance(target_job.request, dict) else {}
    target_job.request = {**req, "chain_id": 1}
    db_session.commit()

    monkeypatch.setattr(
        "workers.static_worker.resolve_current_implementation",
        lambda addr, rpc, **kw: IMPL_ADDR,
    )

    worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, worker)

    # The wrapper completes directly and a child job analyzes the implementation.
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
    from workers.base import JobHandledDirectly
    from workers.static_worker import StaticWorker

    source_job = _create_source_job_with_proxy(
        db_session,
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL_ADDR,
    )
    target_job = _create_target_job_with_contract(db_session, source_job.id)

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


def test_proxy_cache_immutable_eip1167(db_session, monkeypatch):
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


def test_apply_proxy_cache_non_proxy(db_session):
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


@pytest.mark.parametrize(
    ("source_contracts", "request_keys"),
    [
        pytest.param([], ("rpc_url",), id="no-source-job-id"),
        pytest.param([], ("rpc_url", "cache_source_job_id"), id="source-contract-missing"),
        pytest.param(
            [{"contract_name": "Proxy", "is_proxy": True, "proxy_type": "eip1967", "implementation": None}],
            ("rpc_url", "cache_source_job_id"),
            id="proxy-no-cached-impl",
        ),
        pytest.param(
            [{"contract_name": "Proxy", "is_proxy": True, "proxy_type": "eip1967", "implementation": IMPL_ADDR}],
            ("cache_source_job_id",),
            id="no-rpc-url",
        ),
    ],
)
def test_check_proxy_cache_returns_none_on_missing_input(db_session, monkeypatch, source_contracts, request_keys):
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import _check_proxy_cache

    # Otherwise the no-rpc case falls back to the eRPC route.
    monkeypatch.delenv("ETH_RPC", raising=False)
    monkeypatch.delenv("ERPC_BASE_URL", raising=False)

    source_job = create_job(db_session, {"address": ADDR_A})
    for fields in source_contracts:
        db_session.add(Contract(job_id=source_job.id, address=ADDR_A, **fields))
    db_session.flush()

    available = {"rpc_url": "https://rpc.example", "cache_source_job_id": str(source_job.id)}
    job = create_job(
        db_session,
        {"address": ADDR_A, "static_cached": True, **{key: available[key] for key in request_keys}},
    )
    contract = Contract(job_id=job.id, address=ADDR_A, contract_name="Proxy")
    db_session.add(contract)
    db_session.flush()

    assert _check_proxy_cache(db_session, job, contract) is None


def test_e2e_discovery_then_static_with_cache(db_session, monkeypatch):

    from db.queue import create_job, get_artifact, get_source_files
    from workers.discovery import DiscoveryWorker
    from workers.static_worker import StaticWorker

    _create_completed_job_with_static_data(db_session)

    new_job = create_job(db_session, {"address": ADDR_A, "rpc_url": "https://rpc.example"})

    monkeypatch.setattr(
        "workers.discovery.fetch",
        lambda addr: (_ for _ in ()).throw(AssertionError("fetch should not be called")),
    )

    disc_worker = DiscoveryWorker()
    disc_worker.update_detail = MagicMock()
    disc_worker._process_address(db_session, new_job)

    db_session.refresh(new_job)
    assert isinstance(new_job.request, dict)
    assert new_job.request.get("static_cached") is True

    static_worker = StaticWorker()
    phases_run = _patch_static_worker_phases(monkeypatch, static_worker)

    static_worker.process(db_session, new_job)

    assert "slither" not in phases_run
    assert "analysis" not in phases_run
    assert "tracking_plan" not in phases_run
    assert "dependency" in phases_run

    sources = get_source_files(db_session, new_job.id)
    assert len(sources) == 2
    assert get_artifact(db_session, new_job.id, "contract_analysis") is not None
