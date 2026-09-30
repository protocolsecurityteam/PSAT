"""Regression tests for the two PR-79 cache bugs.

#1 Duplicate concurrent builds: ``materialize_or_wait`` released the advisory lock between the
phase-1 ready-check and the phase-2 builder without recording the in-flight build, so two callers
within the 60-150 s build window both ran the full pipeline (only the phase-3 *write* deduped). The
fix is a ``status='building'`` claim row with ``builder_started_at``; the second caller polls it,
with a staleness threshold so a crashed worker can't wedge the cache.

#4 ``predicate_trees`` was dropped on the write path (``recursive.py`` ``_builder`` omitted it, and
the row had no column), so every cache hit returned ``None`` and skipped mapping-writer enumeration.
The fix adds a JSONB + blob column. ``effects`` has no consumer in this cache path
(``copy_static_cache`` propagates it across same-bytecode jobs).

Gated on ``requires_postgres``: serialization rides on ``pg_advisory_xact_lock`` and status transitions.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from db import contract_materializations as cm
from db.models import ContractMaterialization
from tests.conftest import requires_postgres

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
    """Tighten the wait-poll loop; staleness stays long so the test never trips stale-takeover."""
    monkeypatch.setenv("PSAT_MATERIALIZE_WAIT_POLL_INTERVAL_S", "0.05")
    monkeypatch.setenv("PSAT_MATERIALIZE_BUILDER_STALENESS_S", "120")


# ---------------------------------------------------------------------------
# Bug #1: concurrent builders must dedupe through the building-claim row
# ---------------------------------------------------------------------------


@requires_postgres
def test_concurrent_materialize_runs_builder_exactly_once(_route_to_test_db, _clean_cm, _short_wait_poll):
    """Two threads call ``materialize_or_wait`` for one key while a slow builder runs.

    Pre-fix both phase-1 ready-checks miss and both run the builder (``builder_invocations`` 2).
    Post-fix A claims a ``status='building'`` row and B polls it to ``ready``; the builder runs once."""
    chain = "1"
    keccak = "0x" + "ab" * 32

    builder_started = threading.Event()
    builder_lock = threading.Lock()
    invocations = {"n": 0}

    def slow_builder() -> dict[str, Any]:
        with builder_lock:
            invocations["n"] += 1
        builder_started.set()
        # Hold long enough for B to observe the building row and start polling.
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
        except BaseException as exc:
            errors.append(exc)

    t1 = threading.Thread(target=call, args=("1",))
    t2 = threading.Thread(target=call, args=("2",))
    t1.start()
    # Wait until A is inside the builder so B enters phase 1 against an in-flight building row.
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
    """A ``status='building'`` row older than the staleness threshold must NOT block callers (the
    worker is presumed dead): the next caller re-claims, builds and writes ``ready``."""
    monkeypatch.setenv("PSAT_MATERIALIZE_BUILDER_STALENESS_S", "60")
    monkeypatch.setenv("PSAT_MATERIALIZE_WAIT_POLL_INTERVAL_S", "0.05")

    chain = "1"
    keccak = "0x" + "cd" * 32

    # Plant a stale building row: claimed 10 minutes ago, no live worker.
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
    """The bundle's ``predicate_trees`` must be persisted so cache hits return them; the builder
    closure used to drop them, disabling mapping-writer enumeration
    (``_mapping_writer_specs_from_predicate_trees``) on every hit."""
    chain = "1"
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
    chain = "1"
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
    """A SimpleNamespace row stub (``Any`` keeps pyright from rejecting it at the typed parameter)."""
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


@pytest.mark.parametrize(
    "row_kwargs, expected",
    [
        pytest.param(
            {"analysis": {"should": "not appear"}, "predicate_trees": {"trees": {"f()": {}}}},
            {"trees": {"f()": {}}},
            id="reads-predicate-trees-column",
        ),
        # Pre-c1d2e3f4a5b6 rows have neither column; None lets the caller take its "no semantic artifact" path.
        pytest.param(
            {"analysis": {"controllers": []}, "tracking_plan": {"slots": []}}, None, id="pre-migration-row-is-none"
        ),
    ],
)
def test_hydrate_predicate_trees_unit(row_kwargs, expected):
    assert cm.hydrate_predicate_trees(_row_stub(**row_kwargs)) == expected


# ---------------------------------------------------------------------------
# analysis_schema_version: an analyzer bump invalidates old rows
# ---------------------------------------------------------------------------


@requires_postgres
@pytest.mark.parametrize(
    "find, hit_attr, hit_idx, old_keys, cur_keys",
    [
        pytest.param(
            lambda session, keys: cm.find_by_keccak(session, chain="1", bytecode_keccak=keys[0]),
            "bytecode_keccak",
            0,
            ("0x" + "a1" * 32, "0x" + "1" * 40),
            ("0x" + "a2" * 32, "0x" + "2" * 40),
            id="find_by_keccak",
        ),
        pytest.param(
            lambda session, keys: cm.find_by_address(session, chain="1", address=keys[1]),
            "address",
            1,
            ("0x" + "b3" * 32, "0x" + "a3" * 20),
            ("0x" + "b4" * 32, "0x" + "a4" * 20),
            id="find_by_address",
        ),
    ],
)
def test_find_filters_on_schema_version(_clean_cm, find, hit_attr, hit_idx, old_keys, cur_keys):
    """keys are (bytecode_keccak, address)."""
    _clean_cm.add_all(
        [
            ContractMaterialization(
                chain="1",
                bytecode_keccak=keys[0],
                address=keys[1],
                status="ready",
                analysis_schema_version=version,
            )
            for keys, version in (
                (old_keys, cm.ANALYSIS_SCHEMA_VERSION - 1),
                (cur_keys, cm.ANALYSIS_SCHEMA_VERSION),
            )
        ]
    )
    _clean_cm.commit()

    assert find(_clean_cm, old_keys) is None
    hit = find(_clean_cm, cur_keys)
    assert hit is not None
    assert getattr(hit, hit_attr) == cur_keys[hit_idx]


@requires_postgres
def test_materialize_rebuilds_old_schema_version_row(_route_to_test_db, _clean_cm, _short_wait_poll):
    chain = "1"
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
    """A 'ready' row at the current version is a hit; a re-run would re-pay the forge+Slither cost."""
    chain = "1"
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
