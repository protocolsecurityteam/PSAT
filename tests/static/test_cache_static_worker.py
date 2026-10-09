"""A proxy that's still a proxy after the mocked ``_resolve_proxy`` skips Slither and raises ``JobHandledDirectly``."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.cache_helpers import (
    ADDR_A,
    IMPL_ADDR,
    _create_completed_job_with_static_data,
    _create_source_job_with_proxy,
    _create_target_job_with_contract,
    _patch_static_worker_phases,
    db_session,  # noqa: F401
    requires_postgres,
)

pytestmark = requires_postgres


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


# The donor is a current-era analysis, so the cache-hit job publishes its materialization, which reads bytecode.
@pytest.mark.usefixtures("_stub_rpc_bytecode")
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
