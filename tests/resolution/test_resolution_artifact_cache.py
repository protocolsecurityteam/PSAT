"""Static artifacts are keyed by ``(chain, bytecode_keccak)``, snapshots and permissions are rebuilt every call, and
concurrent requests serialize on an advisory lock.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from sqlalchemy import Table

from services.resolution import recursive
from services.resolution.recursive import _materialize_contract_artifacts


@pytest.fixture(autouse=True)
def _isolated_contract_materializations(monkeypatch):
    """Otherwise writes go to the dev DB and a leftover stub-keccak row breaks every later stubbed pipeline."""
    import os

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")

    test_engine = create_engine(test_url)
    test_factory = sessionmaker(bind=test_engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("db.contract_materializations.SessionLocal", test_factory)

    from db.models import ContractMaterialization

    cast(Table, ContractMaterialization.__table__).create(test_engine, checkfirst=True)

    with test_factory() as cleanup_session:
        cleanup_session.query(ContractMaterialization).delete()
        cleanup_session.commit()
    try:
        yield
    finally:
        with test_factory() as cleanup_session:
            cleanup_session.query(ContractMaterialization).delete()
            cleanup_session.commit()
        test_engine.dispose()


def _patch_pipeline(monkeypatch, *, scaffold_calls, collect_calls, snapshot_calls):

    def _classify(_addr, _rpc, **_kw):
        return {"type": "contract"}

    def _fetch(_addr, **_kw):
        return {"ContractName": "TestContract", "SourceCode": "// stub"}

    def _scaffold(_addr, _result, project_dir):
        scaffold_calls.append(project_dir)
        project_dir.mkdir(parents=True, exist_ok=True)
        return project_dir

    def _collect_with_artifacts(_project_dir):
        collect_calls.append(_project_dir)
        analysis = {
            "subject": {"address": "0xabc", "name": "TestContract"},
            "functions": [],
            "state_vars": [],
        }
        return analysis, None, None

    def _build_plan(_analysis):
        return {"contract_address": "0xabc", "controllers": []}

    def _build_snapshot(_plan, _rpc_url, **_kw):
        snapshot_calls.append(_plan)
        return {"controllers": []}

    def _build_perms(_analysis, _snapshot):
        return None

    monkeypatch.setattr("services.discovery.classifier.classify_single", _classify)
    monkeypatch.setattr(recursive, "fetch", _fetch)
    monkeypatch.setattr(recursive, "scaffold", _scaffold)
    monkeypatch.setattr(recursive, "collect_contract_analysis_with_artifacts", _collect_with_artifacts)
    monkeypatch.setattr(recursive, "build_control_tracking_plan", _build_plan)
    monkeypatch.setattr(recursive, "build_control_snapshot", _build_snapshot)
    monkeypatch.setattr(recursive, "_build_effective_permissions", _build_perms)
    # Each real eth_getCode takes ~20s.
    monkeypatch.setattr(
        "services.clients.rpc.get_code_with_keccak",
        lambda _rpc, _addr, chain_id=None: ("0x60", "0x" + "ab" * 32),
    )


def test_second_call_serves_static_artifacts_from_cache(monkeypatch):
    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    snapshot_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")
    _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")

    assert len(scaffold_calls) == 1, "second call should skip scaffold"
    assert len(collect_calls) == 1, "second call should skip collect_contract_analysis"


def test_snapshot_always_rebuilt(monkeypatch):
    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    snapshot_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")
    _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")
    _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")

    assert len(snapshot_calls) == 3, "snapshot must be built every call (state-dependent)"


def test_cached_artifacts_are_deep_copied(monkeypatch):
    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    snapshot_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    first = _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")
    first["analysis"]["functions"].append({"poisoned": True})
    first["tracking_plan"]["controllers"].append({"poisoned": True})

    second = _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")
    assert second["analysis"]["functions"] == []
    assert second["tracking_plan"]["controllers"] == []


def test_cache_keyed_by_effective_address_not_input(monkeypatch):
    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    snapshot_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    impl_addr = "0x" + "11" * 20

    def _classify_proxy_to_impl(_addr, _rpc, **_kw):
        return {"type": "proxy", "implementation": impl_addr}

    monkeypatch.setattr("services.discovery.classifier.classify_single", _classify_proxy_to_impl)

    _materialize_contract_artifacts(
        "0x" + "AA" * 20, "http://rpc", workspace_prefix="test", chain="ethereum"
    )  # proxy A → impl
    _materialize_contract_artifacts(
        "0x" + "BB" * 20, "http://rpc", workspace_prefix="test", chain="ethereum"
    )  # proxy B → same impl

    assert len(scaffold_calls) == 1, "same impl must be scaffolded once even for different proxies"


def test_bytecode_keccak_hit_retargets_plan_to_new_address(monkeypatch):
    """A keccak hit returns a plan for a different address with the same bytecode, so it must be retargeted or the
    snapshot reads the wrong contract.
    """
    snapshot_calls: list[Any] = []
    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    keccak = "0x" + "ab" * 32
    monkeypatch.setattr(
        "services.clients.rpc.get_code_with_keccak", lambda _rpc, _addr, chain_id=None: ("0x60", keccak)
    )

    addr_a = "0x" + "11" * 20
    addr_b = "0x" + "22" * 20

    _materialize_contract_artifacts(addr_a, "http://rpc", workspace_prefix="test", chain="ethereum")
    _materialize_contract_artifacts(addr_b, "http://rpc", workspace_prefix="test", chain="ethereum")

    assert len(snapshot_calls) == 2
    assert snapshot_calls[1]["contract_address"] == addr_b.lower()


def test_two_concurrent_requests_dedup_via_advisory_lock(monkeypatch):
    """The lock is no longer held across ``builder()`` (Neon SSL idle drops), so both callers may build; the
    invariant is one ready row.
    """
    import threading

    from db import contract_materializations as cm

    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    snapshot_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    barrier = threading.Barrier(2)

    def _materialize_with_barrier(addr: str) -> None:
        barrier.wait()
        _materialize_contract_artifacts(addr, "http://rpc", workspace_prefix=f"thr-{addr[-4:]}", chain="ethereum")

    t1 = threading.Thread(target=_materialize_with_barrier, args=("0x" + "11" * 20,))
    t2 = threading.Thread(target=_materialize_with_barrier, args=("0x" + "22" * 20,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert 1 <= len(scaffold_calls) <= 2
    assert len(collect_calls) == len(scaffold_calls)

    with cm.SessionLocal() as session:
        row = cm.find_by_keccak(session, chain="ethereum", bytecode_keccak="0x" + "ab" * 32)
    assert row is not None, "concurrent requests must produce exactly one stored row"
    assert row.status == "ready"


def test_materialization_persists_a_row_keyed_by_chain_and_keccak(monkeypatch):
    from db import contract_materializations as cm  # provided by the fix

    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    snapshot_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    addr = "0x" + "33" * 20
    _materialize_contract_artifacts(addr, "http://rpc", workspace_prefix="row-test", chain="ethereum")

    with cm.SessionLocal() as session:
        row = cm.find_by_keccak(session, chain="ethereum", bytecode_keccak="0x" + "ab" * 32)
    assert row is not None
    assert row.status == "ready"
    assert row.bytecode_keccak == "0x" + "ab" * 32


def test_materialize_records_build_then_cache_hit_metrics(monkeypatch):
    """A cache-hit collapse is the redundant-rebuild signal."""
    from utils.logging import stage_metrics_var

    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    snapshot_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")
        _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")
    finally:
        stage_metrics_var.reset(token)

    assert len(scaffold_calls) == 1
    assert metrics.get("materialize_builds") == 1
    assert metrics.get("materialize_cache_hits") == 1
