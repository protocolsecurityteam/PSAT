"""Regression tests for cross-cascade materialization dedup via
``contract_materializations`` in ``services/resolution/recursive.py``.

Within a single cascade the BFS already dedupes by address (``processed``
set). The persistent cache exists for *cross-cascade* reuse: when a
sibling job walks the same OZ library / common implementation, we skip
the scaffold + ``collect_static_facts`` + ``build_observation_plan``
trio.

What we pin here:
1. Static artifacts (analysis + plan) are looked up by
   ``(chain, bytecode_keccak)`` and reused on the second call → only one
   scaffold run.
2. Snapshot + permissions are rebuilt fresh on every call (they depend
   on RPC state via observe_controllers) → never served stale.
3. Returns deepcopies — mutating the returned dict must NOT poison the
   next call.
4. Concurrent requests serialize on a Postgres advisory lock so the
   loser of the race reads the winner's result instead of rebuilding.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from sqlalchemy import Table

from services.resolution import recursive
from services.resolution.recursive import _materialize_contract_artifacts


@pytest.fixture(autouse=True)
def _isolated_contract_materializations(monkeypatch):
    """Point ``db.contract_materializations`` at the test DB and wipe the
    canonical stub keccak row around every test.

    Without this, the new cross-process cache layer integrated into
    ``_materialize_contract_artifacts`` writes to whatever ``DATABASE_URL``
    points to (typically the dev DB on a contributor laptop) and a single
    leftover row keyed on the stub keccak ``0xab*32`` makes every later
    test's stubbed pipeline never execute. Routing the layer through the
    test DB AND clearing the table around each test keeps the
    scaffold/collect counters deterministic.
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
    """Wire up the dependency chain with counters so we can assert which
    layers got skipped on cache hit."""

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
        return (
            analysis,
            {"schema_version": "semantic", "trees": {}},
            {
                "schema_version": "semantic",
                "functions": {},
            },
        )

    def _build_plan(_analysis):
        return {"contract_address": "0xabc", "controllers": []}

    def _build_snapshot(_plan, _rpc_url, **_kw):
        snapshot_calls.append(_plan)
        return {"controllers": []}

    def _build_perms(_analysis, _snapshot, _effects, _trees):
        return None

    monkeypatch.setattr("services.discovery.classifier.classify_single", _classify)
    monkeypatch.setattr(recursive, "fetch", _fetch)
    monkeypatch.setattr(recursive, "scaffold", _scaffold)
    monkeypatch.setattr(recursive, "collect_static_inputs", _collect_with_artifacts)
    monkeypatch.setattr(recursive, "build_observation_plan", _build_plan)
    monkeypatch.setattr(recursive, "observe_controllers", _build_snapshot)
    monkeypatch.setattr(recursive, "_build_permission_index", _build_perms)
    # _materialize_contract_artifacts now calls services.clients.rpc.get_code_with_keccak
    # to populate the bytecode-keccak secondary cache index. Stub it so
    # tests don't make real eth_getCode RPCs (was making each test ~20s
    # before this stub).
    monkeypatch.setattr(
        "services.clients.rpc.get_code_with_keccak",
        lambda _rpc, _addr, chain_id=None: ("0x60", "0x" + "ab" * 32),
    )


def test_second_call_serves_static_artifacts_from_cache(monkeypatch):
    """The whole point: scaffold + collect run once; second call hits cache."""
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
    assert len(collect_calls) == 1, "second call should skip collect_static_facts"


def test_snapshot_always_rebuilt(monkeypatch):
    """Snapshot reads on-chain state — must not be cached. If a future
    refactor extends the cache to cover snapshot, this test catches it."""
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
    """Mutating returned dicts (callers add fields, e.g. contract_address
    override for proxies) must not poison the next cache lookup."""
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
    first["static_facts"]["functions"].append({"poisoned": True})
    first["observation_plan"]["controllers"].append({"poisoned": True})

    second = _materialize_contract_artifacts("0xABC", "http://rpc", workspace_prefix="test", chain="ethereum")
    assert second["static_facts"]["functions"] == []
    assert second["observation_plan"]["controllers"] == []


def test_cache_keyed_by_effective_address_not_input(monkeypatch):
    """When two different proxies point to the same impl, the cache key
    is the impl address — both proxies share the cached static artifacts.
    This is the cross-cascade reuse we want."""
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


# ---------------------------------------------------------------------------
# bytecode-keccak hit must retarget plan to the new address
# ---------------------------------------------------------------------------


def test_bytecode_keccak_hit_retargets_plan_to_new_address(monkeypatch):
    """Codex iter-4 P1: when a keccak-index hit returns analysis+plan
    cached for a DIFFERENT address with the same bytecode (e.g., two
    UUPSProxy instances pointing to different impls), the cached
    plan["contract_address"] points at the FIRST address. Without
    retargeting, observe_controllers reads controller state from
    the wrong contract storage.

    Fix: on cache hit, deepcopy the analysis+plan and overwrite
    contract_address with the address THIS call is materializing.
    Verify that two materializations of the same-bytecode-different-
    address pair both end up reading from the right contract."""
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
    # First call is a cache MISS — uses the test fixture's _build_plan
    # output (hardcoded "0xabc"). Not under test here; the retarget
    # only fires on cache HIT.
    # Second call is a cache HIT via the keccak index — must retarget
    # plan["contract_address"] from "0xabc" to addr_b. Without the fix,
    # observe_controllers would read controller state from the
    # cache-populating contract instead of addr_b.
    assert snapshot_calls[1]["contract_address"] == addr_b.lower()


# ---------------------------------------------------------------------------
# Cross-process / cross-job materialization dedup
# ---------------------------------------------------------------------------
#
# ``contract_materializations`` is the persistent layer that dedupes
# scaffold + Slither work across worker processes and across jobs. Keyed
# by (chain, bytecode_keccak), with request-coalescing via
# pg_advisory_xact_lock so concurrent jobs requesting the same address
# only run the expensive build once.
#
# Tests below lean on the autouse ``_isolated_contract_materializations``
# fixture to point ``db.contract_materializations.SessionLocal`` at the
# test DB and to wipe the canonical stub keccak row before/after every test.


def test_two_processes_materializing_same_bytecode_compile_once(monkeypatch):
    """Worker process A materializes contract X. Process B then
    materializes a *different* address with the *same* bytecode_keccak.
    The persistent cross-process cache means the second call skips the
    expensive scaffold + Slither work entirely.
    """
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
    """Two concurrent materialization requests for the same
    ``(chain, bytecode_keccak)`` must collapse to **one stored row** — the
    second caller serves the first caller's bundle.

    Note: the cache layer no longer holds the advisory lock across
    ``builder()`` (that caused Neon SSL idle drops mid-forge-build). The
    new shape is short-lock → unlocked build → short-lock recheck-and-
    upsert. Under tight contention two callers can both enter ``builder()``;
    the phase-3 recheck collapses the race to one stored row, not one
    build. That's the intentional trade — guaranteed cache write
    correctness, occasional duplicate build under contention.

    The build-count therefore can be 1 or 2 here; what's invariant is
    that only one row is materialized as ``status='ready'``.
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
    """A row per (chain, bytecode_keccak) — operators answer "have we
    ever materialized this?" without resolving artifacts; next-day
    re-runs become pure DB lookups."""
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

    # Open a fresh session against the test DB — the autouse fixture
    # already routed ``cm.SessionLocal`` here, so reuse it for the read.
    with cm.SessionLocal() as session:
        row = cm.find_by_keccak(session, chain="ethereum", bytecode_keccak="0x" + "ab" * 32)
    assert row is not None
    assert row.status == "ready"
    assert row.bytecode_keccak == "0x" + "ab" * 32


def test_materialize_records_build_then_cache_hit_metrics(monkeypatch):
    """Build-vs-cache-hit fold: the first materialize runs the builder
    (forge/Slither), the second is served from the cm cache. Drives the real
    ``materialize_or_wait`` against the test DB; only the build wire is stubbed.
    A cache-hit-rate collapse here is the redundant-rebuild signal this fold
    exists to surface."""
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

    # Sanity: the cache actually engaged (scaffold ran once across two calls).
    assert len(scaffold_calls) == 1
    assert metrics.get("materialize_builds") == 1
    assert metrics.get("materialize_cache_hits") == 1
