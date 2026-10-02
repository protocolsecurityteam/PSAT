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
