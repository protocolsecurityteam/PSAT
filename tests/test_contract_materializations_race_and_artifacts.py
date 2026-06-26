"""Regression tests for the two PR-79 cache bugs:

#1 Duplicate concurrent builds. ``materialize_or_wait`` used to release
   the advisory lock between the phase-1 ready-check and the phase-2
   builder without persisting anything about the in-flight build.
   Two callers reaching phase 1 within the (now 60-150 s) build window
   therefore both ran the full forge+Slither+predicate pipeline; only
   the phase-3 *write* was deduped. The fix is a ``status='building'``
   claim row with ``builder_started_at`` so the second caller polls the
   first to ``ready`` instead of duplicating the build, with a staleness
   threshold so a crashed worker can't wedge the cache.

#4 ``predicate_trees`` was dropped on the write path
   (``services/resolution/recursive.py``: ``_builder`` returned only
   ``contract_name``, ``analysis``, ``tracking_plan``) and the cache row
   had no column to store it anyway. Every cache hit therefore returned
   ``predicate_trees=None`` and silently skipped mapping-writer
   enumeration downstream. The fix adds a JSONB + blob column and
   routes the artifact end-to-end through the cache. ``effects`` was
   considered for the same treatment but has no consumer in this cache
   path (the policy stage reads the per-job artifact written by the
   static worker; ``copy_static_cache`` propagates it across
   same-bytecode jobs).

Both bug paths are best exercised against a real Postgres because the
serialization story rides on ``pg_advisory_xact_lock`` and the row
status transitions. Tests are gated on ``requires_postgres`` so the
offline tier still runs the unit subset.
"""

from __future__ import annotations

import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import contract_materializations as cm  # noqa: E402
from db.models import ContractMaterialization  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def _clean_cm(db_session):
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    yield db_session
    db_session.query(ContractMaterialization).delete()
    db_session.commit()


@pytest.fixture()
def _route_to_test_db(monkeypatch):
    """Point ``cm.SessionLocal`` at TEST_DATABASE_URL so concurrent
    builders don't leak into the dev DB."""
    import os

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")

    engine = create_engine(test_url)
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("db.contract_materializations.SessionLocal", factory)
    yield
    engine.dispose()


@pytest.fixture()
def _short_wait_poll(monkeypatch):
    """Tighten the wait-poll loop so the concurrency tests don't sleep
    for a full second between polls. Staleness stays long so the test
    never accidentally trips into stale-takeover."""
    monkeypatch.setenv("PSAT_MATERIALIZE_WAIT_POLL_INTERVAL_S", "0.05")
    monkeypatch.setenv("PSAT_MATERIALIZE_BUILDER_STALENESS_S", "120")


# ---------------------------------------------------------------------------
# Bug #1: concurrent builders must dedupe through the building-claim row
# ---------------------------------------------------------------------------


@requires_postgres
def test_concurrent_materialize_runs_builder_exactly_once(_route_to_test_db, _clean_cm, _short_wait_poll):
    """Two threads call ``materialize_or_wait`` with the same
    ``(chain, bytecode_keccak)`` while a slow builder is running.

    Pre-fix: both threads' phase-1 ready-checks miss, both run the
    builder concurrently, phase 3 dedupes the *write* but not the
    *work*. ``builder_invocations`` would be 2.

    Post-fix: thread A claims a ``status='building'`` row in phase 1,
    thread B sees ``status='building'`` + recent ``builder_started_at``
    and polls until A flips the row to ``ready``. Builder runs once.
    """
    chain = "ethereum"
    keccak = "0x" + "ab" * 32

    builder_started = threading.Event()
    builder_lock = threading.Lock()
    invocations = {"n": 0}

    def slow_builder() -> dict[str, Any]:
        with builder_lock:
            invocations["n"] += 1
        builder_started.set()
        # Hold long enough for thread B to enter phase 1, observe the
        # building row, and start polling. Without the building-row
        # claim, B would race past phase 1 and also call this builder.
        time.sleep(0.6)
        return {
            "contract_name": "ConcurrentDedup",
            "analysis": {"controllers": []},
            "tracking_plan": {"slots": []},
            "predicate_trees": {"schema_version": "semantic", "trees": {}},
        }

    results: list[Any] = []
    errors: list[BaseException] = []

    def call(addr_suffix: str) -> None:
        try:
            with patch("db.contract_materializations.get_storage_client", return_value=None):
                row = cm.materialize_or_wait(
                    chain=chain,
                    address="0x" + addr_suffix * 40,
                    bytecode_keccak=keccak,
                    builder=slow_builder,
                )
            results.append(row)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=call, args=("1",))
    t2 = threading.Thread(target=call, args=("2",))
    t1.start()
    # Wait until thread A is inside the builder before launching B so B
    # is guaranteed to enter phase 1 against an in-flight building row.
    assert builder_started.wait(timeout=5), "thread A never entered builder"
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert not errors, f"unexpected errors: {errors}"
    assert len(results) == 2, "both threads should have received a row"
    assert invocations["n"] == 1, (
        f"builder was invoked {invocations['n']} times; expected exactly 1. "
        "The phase-1 wait-on-building path is the dedup mechanism — without it, "
        "two concurrent callers each pay the full forge+Slither+predicate cost."
    )
    assert all(r.status == "ready" for r in results)
    assert all(r.contract_name == "ConcurrentDedup" for r in results)


@requires_postgres
def test_stale_building_row_is_taken_over(_route_to_test_db, _clean_cm, monkeypatch):
    """A ``status='building'`` row older than the staleness threshold
    must NOT block fresh callers — the prior worker is presumed dead.
    The next caller takes over (re-claims the row, runs the builder,
    writes ``ready``)."""
    # Short staleness so the test runs fast.
    monkeypatch.setenv("PSAT_MATERIALIZE_BUILDER_STALENESS_S", "60")
    monkeypatch.setenv("PSAT_MATERIALIZE_WAIT_POLL_INTERVAL_S", "0.05")

    chain = "ethereum"
    keccak = "0x" + "cd" * 32

    # Plant a stale building row: claim made 10 minutes ago, no worker
    # alive to advance it.
    stale_row = ContractMaterialization(
        chain=chain,
        bytecode_keccak=keccak,
        address="0x" + "f" * 40,
        status="building",
        builder_started_at=datetime.now(timezone.utc) - timedelta(minutes=10),
    )
    _clean_cm.add(stale_row)
    _clean_cm.commit()

    invocations = {"n": 0}

    def takeover_builder() -> dict[str, Any]:
        invocations["n"] += 1
        return {
            "contract_name": "TakeoverSuccess",
            "analysis": {"controllers": []},
            "tracking_plan": {"slots": []},
        }

    with patch("db.contract_materializations.get_storage_client", return_value=None):
        row = cm.materialize_or_wait(
            chain=chain,
            address="0x" + "1" * 40,
            bytecode_keccak=keccak,
            builder=takeover_builder,
        )

    assert invocations["n"] == 1, "stale building row must not block the caller"
    assert row.status == "ready"
    assert row.contract_name == "TakeoverSuccess"
    assert row.builder_started_at is None, "ready row must clear builder_started_at"


# ---------------------------------------------------------------------------
# Bug #4: predicate_trees round-trips through the cache
# ---------------------------------------------------------------------------


@requires_postgres
def test_predicate_trees_cached_inline(_route_to_test_db, _clean_cm):
    """The builder bundle's ``predicate_trees`` must be persisted on
    the materialization row so cache hits return them.

    Pre-fix the builder closure dropped them. ``cm.hydrate_predicate_trees``
    on a hit returned None and downstream
    ``_mapping_writer_specs_from_predicate_trees`` silently returned
    an empty list — mapping-writer enumeration was disabled on every hit.
    """
    chain = "ethereum"
    keccak = "0x" + "11" * 32

    predicate_payload = {
        "schema_version": "semantic",
        "contract_name": "MapEnumProbe",
        "trees": {
            "grant(address)": {
                "op": "LEAF",
                "leaf": {
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "storage_var": "wards",
                        "enumeration_hint": [
                            {
                                "mapping_name": "wards",
                                "event_signature": "Rely(address)",
                                "event_name": "Rely",
                                "direction": "add",
                                "key_position": 0,
                                "indexed_positions": [0],
                                "writer_function": "rely(address)",
                                "value_position": None,
                            }
                        ],
                    }
                },
            }
        },
    }

    def winner_builder() -> dict[str, Any]:
        return {
            "contract_name": "MapEnumProbe",
            "analysis": {"controllers": []},
            "tracking_plan": {"slots": []},
            "predicate_trees": predicate_payload,
        }

    with patch("db.contract_materializations.get_storage_client", return_value=None):
        winner = cm.materialize_or_wait(
            chain=chain,
            address="0x" + "1" * 40,
            bytecode_keccak=keccak,
            builder=winner_builder,
        )

    # Inline path: JSONB column populated, blob_key NULL.
    assert winner.predicate_trees == predicate_payload
    assert winner.predicate_trees_blob_key is None
    # Hydrator returns the same shape.
    assert cm.hydrate_predicate_trees(winner) == predicate_payload

    # A second caller (different address, same keccak) hits the cache
    # and must receive predicate_trees, not None.
    def loser_builder() -> dict[str, Any]:
        raise AssertionError("loser must not re-run the builder")

    with patch("db.contract_materializations.get_storage_client", return_value=None):
        loser = cm.materialize_or_wait(
            chain=chain,
            address="0x" + "2" * 40,
            bytecode_keccak=keccak,
            builder=loser_builder,
        )

    assert loser.bytecode_keccak == winner.bytecode_keccak
    assert cm.hydrate_predicate_trees(loser) == predicate_payload


@requires_postgres
def test_predicate_trees_cached_via_blob(_route_to_test_db, _clean_cm):
    """When ``get_storage_client`` is configured the bundle's
    ``predicate_trees`` goes to blob storage (not inline JSONB) and the
    row carries the key. The hydrate helper transparently pulls it back
    through the blob path."""

    class _StubStorage:
        def __init__(self) -> None:
            self.objects: dict[str, bytes] = {}
            self.put_calls: list[str] = []

        def put(self, key: str, body: bytes, content_type: str, metadata=None) -> None:
            self.put_calls.append(key)
            self.objects[key] = body

        def get(self, key: str) -> bytes:
            return self.objects[key]

    storage = _StubStorage()
    chain = "ethereum"
    keccak = "0x" + "22" * 32

    predicate_payload = {"schema_version": "semantic", "trees": {"f()": {"op": "LEAF"}}}

    def builder() -> dict[str, Any]:
        return {
            "contract_name": "BlobSemanticProbe",
            "analysis": {"controllers": []},
            "tracking_plan": {"slots": []},
            "predicate_trees": predicate_payload,
        }

    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        row = cm.materialize_or_wait(
            chain=chain,
            address="0x" + "3" * 40,
            bytecode_keccak=keccak,
            builder=builder,
        )

    # Blob path: predicate_trees_blob_key set, JSONB NULL, three puts
    # total (analysis, tracking_plan, predicate_trees).
    assert row.predicate_trees is None
    assert row.predicate_trees_blob_key is not None
    keys_written = sorted(storage.put_calls)
    assert any(k.endswith("/predicate_trees.json") for k in keys_written)

    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        assert cm.hydrate_predicate_trees(row) == predicate_payload


def _row_stub(**kwargs: Any) -> Any:
    """Build a SimpleNamespace mimicking a ContractMaterialization row.
    The hydrate helpers use ``getattr`` so duck-typing is sufficient.
    Returning ``Any`` keeps pyright from rejecting the stub at the
    typed ``ContractMaterialization`` parameter boundary."""
    defaults = dict(
        analysis=None,
        analysis_blob_key=None,
        tracking_plan=None,
        tracking_plan_blob_key=None,
        predicate_trees=None,
        predicate_trees_blob_key=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_hydrate_predicate_trees_unit():
    """Unit-level smoke: ``hydrate_predicate_trees`` reads the
    ``predicate_trees`` column, not ``analysis`` or ``tracking_plan``."""
    row = _row_stub(
        analysis={"should": "not appear"},
        predicate_trees={"trees": {"f()": {}}},
    )
    assert cm.hydrate_predicate_trees(row) == {"trees": {"f()": {}}}


def test_hydrate_predicate_trees_returns_none_for_pre_migration_row():
    """Rows written by the pre-c1d2e3f4a5b6 cache have neither the
    JSONB column nor the blob key. Returning None lets the caller fall
    back to its "no semantic artifact" path instead of crashing."""
    row = _row_stub(
        analysis={"controllers": []},
        tracking_plan={"slots": []},
    )
    assert cm.hydrate_predicate_trees(row) is None


# ---------------------------------------------------------------------------
# analysis_schema_version: an analyzer bump invalidates old rows
# ---------------------------------------------------------------------------


@requires_postgres
def test_find_by_keccak_filters_on_schema_version(_clean_cm):
    """``find_by_keccak`` serves only a row stamped with the current
    ``ANALYSIS_SCHEMA_VERSION``. An older-version row reads as a miss so
    a bumped analyzer rebuilds instead of serving a stale bundle."""
    chain = "ethereum"
    keccak_old = "0x" + "a1" * 32
    keccak_cur = "0x" + "a2" * 32

    _clean_cm.add_all(
        [
            ContractMaterialization(
                chain=chain,
                bytecode_keccak=keccak_old,
                address="0x" + "1" * 40,
                status="ready",
                analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION - 1,
            ),
            ContractMaterialization(
                chain=chain,
                bytecode_keccak=keccak_cur,
                address="0x" + "2" * 40,
                status="ready",
                analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION,
            ),
        ]
    )
    _clean_cm.commit()

    assert cm.find_by_keccak(_clean_cm, chain=chain, bytecode_keccak=keccak_old) is None
    hit = cm.find_by_keccak(_clean_cm, chain=chain, bytecode_keccak=keccak_cur)
    assert hit is not None
    assert hit.bytecode_keccak == keccak_cur


@requires_postgres
def test_find_by_address_filters_on_schema_version(_clean_cm):
    """Address-keyed lookups apply the same version gate as keccak ones."""
    chain = "ethereum"
    addr_old = "0x" + "a3" * 20
    addr_cur = "0x" + "a4" * 20

    _clean_cm.add_all(
        [
            ContractMaterialization(
                chain=chain,
                bytecode_keccak="0x" + "b3" * 32,
                address=addr_old,
                status="ready",
                analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION - 1,
            ),
            ContractMaterialization(
                chain=chain,
                bytecode_keccak="0x" + "b4" * 32,
                address=addr_cur,
                status="ready",
                analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION,
            ),
        ]
    )
    _clean_cm.commit()

    assert cm.find_by_address(_clean_cm, chain=chain, address=addr_old) is None
    hit = cm.find_by_address(_clean_cm, chain=chain, address=addr_cur)
    assert hit is not None
    assert hit.address == addr_cur


@requires_postgres
def test_materialize_rebuilds_old_schema_version_row(_route_to_test_db, _clean_cm, _short_wait_poll):
    """A 'ready' row built by an older analyzer must NOT be served — it
    reads as a miss, the builder runs once, and the row is rewritten at
    the current ``ANALYSIS_SCHEMA_VERSION``."""
    chain = "ethereum"
    keccak = "0x" + "c1" * 32

    _clean_cm.add(
        ContractMaterialization(
            chain=chain,
            bytecode_keccak=keccak,
            address="0x" + "1" * 40,
            contract_name="StaleAnalyzer",
            status="ready",
            analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION - 1,
        )
    )
    _clean_cm.commit()

    invocations = {"n": 0}

    def rebuild_builder() -> dict[str, Any]:
        invocations["n"] += 1
        return {
            "contract_name": "FreshAnalyzer",
            "analysis": {"controllers": []},
            "tracking_plan": {"slots": []},
        }

    with patch("db.contract_materializations.get_storage_client", return_value=None):
        row = cm.materialize_or_wait(
            chain=chain,
            address="0x" + "1" * 40,
            bytecode_keccak=keccak,
            builder=rebuild_builder,
        )

    assert invocations["n"] == 1, "an old-schema-version row must miss and rebuild"
    assert row.status == "ready"
    assert row.contract_name == "FreshAnalyzer"
    assert row.analysis_schema_version == cm.ANALYSIS_SCHEMA_VERSION


@requires_postgres
def test_materialize_serves_current_schema_version_row(_route_to_test_db, _clean_cm, _short_wait_poll):
    """A 'ready' row at the current version is a hit — the builder never
    runs (a re-run would re-pay the forge+Slither cost for nothing)."""
    chain = "ethereum"
    keccak = "0x" + "c2" * 32

    _clean_cm.add(
        ContractMaterialization(
            chain=chain,
            bytecode_keccak=keccak,
            address="0x" + "1" * 40,
            contract_name="CurrentAnalyzer",
            status="ready",
            analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION,
        )
    )
    _clean_cm.commit()

    def must_not_run() -> dict[str, Any]:
        raise AssertionError("current-version row must be served without rebuild")

    with patch("db.contract_materializations.get_storage_client", return_value=None):
        row = cm.materialize_or_wait(
            chain=chain,
            address="0x" + "1" * 40,
            bytecode_keccak=keccak,
            builder=must_not_run,
        )

    assert row.status == "ready"
    assert row.contract_name == "CurrentAnalyzer"
    assert row.analysis_schema_version == cm.ANALYSIS_SCHEMA_VERSION


@requires_postgres
def test_migration_backfills_existing_rows_to_launch_version(_clean_cm):
    """A row inserted without an explicit ``analysis_schema_version`` — the
    shape a pre-column row takes after the migration backfill — carries the
    ``server_default`` the migration installed: schema version 1, the launch
    value of ``ANALYSIS_SCHEMA_VERSION``. This keeps a deploy from
    invalidating the whole cache at once."""
    chain = "ethereum"
    keccak = "0x" + "d1" * 32
    _clean_cm.execute(
        text(
            "INSERT INTO contract_materializations "
            "(chain, bytecode_keccak, address, status) "
            "VALUES (:chain, :keccak, :addr, 'ready')"
        ),
        {"chain": chain, "keccak": keccak, "addr": "0x" + "1" * 40},
    )
    _clean_cm.commit()

    version = _clean_cm.execute(
        text(
            "SELECT analysis_schema_version FROM contract_materializations "
            "WHERE chain = :chain AND bytecode_keccak = :keccak"
        ),
        {"chain": chain, "keccak": keccak},
    ).scalar_one()
    assert version == 1
