"""Regression tests for cross-cascade materialization dedup via ``contract_materializations``.

Within a cascade the BFS dedupes by address; the persistent cache reuses work across sibling
jobs walking the same library/implementation. Pinned: static artifacts are keyed by
``(chain, bytecode_keccak)``; snapshot + permissions are rebuilt fresh every call (RPC-state
dependent, never stale); returns are deepcopies; concurrent requests serialize on a Postgres
advisory lock so the loser reads the winner's result.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from sqlalchemy import Table

from services.resolution import recursive
from services.resolution.recursive import _materialize_contract_artifacts


@pytest.fixture(autouse=True)
def _isolated_contract_materializations(monkeypatch):
    """Point ``db.contract_materializations`` at the test DB and wipe the stub keccak row per test.

    Otherwise the cache writes to whatever ``DATABASE_URL`` points to (often a dev DB) and a
    leftover row keyed on the stub keccak ``0xab*32`` stops every later stubbed pipeline
    from executing, breaking the scaffold/collect counters.
    """
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
    # Stub get_code_with_keccak (bytecode-keccak index) so tests make no real eth_getCode RPCs (~20s each).
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
    """Snapshot reads on-chain state; must not be cached."""
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
    """Two proxies pointing at the same impl share cached artifacts (key is the impl address)."""
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


# bytecode-keccak hit must retarget plan to the new address


def test_bytecode_keccak_hit_retargets_plan_to_new_address(monkeypatch):
    """Codex iter-4 P1: a keccak-index hit returns a plan cached for a DIFFERENT address with
    the same bytecode (e.g. two UUPSProxy instances), so plan["contract_address"] points at the
    FIRST address and build_control_snapshot would read the wrong contract's storage. On a hit
    the cache must deepcopy and retarget to the address THIS call is materializing."""
    snapshot_calls: list[Any] = []
    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    # Both addresses share the same bytecode → same keccak.
    keccak = "0x" + "ab" * 32
    monkeypatch.setattr(
        "services.clients.rpc.get_code_with_keccak", lambda _rpc, _addr, chain_id=None: ("0x60", keccak)
    )

    addr_a = "0x" + "11" * 20
    addr_b = "0x" + "22" * 20

    _materialize_contract_artifacts(addr_a, "http://rpc", workspace_prefix="test", chain="ethereum")
    _materialize_contract_artifacts(addr_b, "http://rpc", workspace_prefix="test", chain="ethereum")

    assert len(snapshot_calls) == 2
    # First call is a cache MISS (fixture's hardcoded "0xabc" plan; not under test). The second
    # is a keccak-index HIT and must retarget plan["contract_address"] from "0xabc" to addr_b.
    assert snapshot_calls[1]["contract_address"] == addr_b.lower()


# ---------------------------------------------------------------------------
# Cross-process / cross-job materialization dedup: ``contract_materializations`` is keyed by
# (chain, bytecode_keccak) with pg_advisory_xact_lock request-coalescing. Tests rely on the
# autouse ``_isolated_contract_materializations`` fixture.
# ---------------------------------------------------------------------------


def test_two_processes_materializing_same_bytecode_compile_once(monkeypatch):
    """A second address with the same bytecode_keccak skips the expensive scaffold + Slither work."""
    scaffold_calls: list[Any] = []
    collect_calls: list[Any] = []
    snapshot_calls: list[Any] = []
    _patch_pipeline(
        monkeypatch,
        scaffold_calls=scaffold_calls,
        collect_calls=collect_calls,
        snapshot_calls=snapshot_calls,
    )

    _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="proc-A", chain="ethereum")
    assert len(scaffold_calls) == 1
    assert len(collect_calls) == 1

    _materialize_contract_artifacts("0xDEF", "http://rpc", workspace_prefix="proc-B", chain="ethereum")

    assert len(scaffold_calls) == 1, "second process must not re-scaffold the same bytecode"
    assert len(collect_calls) == 1, "second process must not re-run Slither on the same bytecode"


def test_two_concurrent_requests_dedup_via_advisory_lock(monkeypatch):
    """Two concurrent requests for the same ``(chain, bytecode_keccak)`` collapse to **one stored row**.

    The cache layer no longer holds the advisory lock across ``builder()`` (that caused Neon SSL
    idle drops mid-forge-build): short-lock -> unlocked build -> short-lock recheck-and-upsert.
    Under contention both callers can build, so the build count is 1 or 2; the invariant is a
    single ``status='ready'`` row.
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

    # Build count is non-deterministic under tight contention.
    assert 1 <= len(scaffold_calls) <= 2
    assert len(collect_calls) == len(scaffold_calls)

    # The invariant: exactly one ready row stored for this keccak.
    with cm.SessionLocal() as session:
        row = cm.find_by_keccak(session, chain="ethereum", bytecode_keccak="0x" + "ab" * 32)
    assert row is not None, "concurrent requests must produce exactly one stored row"
    assert row.status == "ready"


def test_materialization_persists_a_row_keyed_by_chain_and_keccak(monkeypatch):
    """A row per (chain, bytecode_keccak) lets operators answer "have we ever materialized this?" without resolving
    artifacts."""
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
    """Build-vs-cache-hit fold against the real ``materialize_or_wait``; only the build wire is stubbed.
    A cache-hit-rate collapse is the redundant-rebuild signal this fold surfaces."""
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
