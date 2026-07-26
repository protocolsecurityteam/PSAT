"""Blob-vs-inline storage paths in ``db.contract_materializations``.

The schema carries paired columns (``analysis`` JSONB +
``analysis_blob_key`` Text; same for ``tracking_plan``). When
``ARTIFACT_STORAGE_*`` env vars are set, ``materialize_or_wait``
writes the payloads to object storage and persists only the keys on
the row. When unconfigured, it falls back to inline JSONB.

Reads always go through ``hydrate_analysis`` /
``hydrate_tracking_plan`` which try the blob first and fall back to
inline JSONB on either a missing key or a transient blob fetch
error. That fallback is what lets pre-migration rows keep working
while the backfill catches up — and what insulates the pipeline
from a transient Tigris outage.

These tests mock ``get_storage_client`` rather than spinning up a
minio container so they stay in the offline tier. The minio-backed
end-to-end path is exercised by the live test suite.

Marker: offline (``requires_postgres`` for the ones that need the
real materializations table).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import contract_materializations as cm  # noqa: E402
from db.models import ContractMaterialization  # noqa: E402
from db.storage import StorageError, StorageKeyMissing  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

# --- Stub storage client ----------------------------------------------------


class _StubStorage:
    """In-memory ``StorageClient`` substitute. Tracks puts and gets so
    tests can assert on calls without booting minio."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.put_calls: list[tuple[str, str]] = []  # (key, content_type)
        self.get_calls: list[str] = []
        self.fail_get: set[str] = set()
        self.fail_put: set[str] = set()

    def put(self, key: str, body: bytes, content_type: str, metadata=None) -> None:
        if key in self.fail_put:
            raise StorageError(f"injected put failure for {key}")
        self.put_calls.append((key, content_type))
        self.objects[key] = body

    def get(self, key: str) -> bytes:
        self.get_calls.append(key)
        if key in self.fail_get:
            raise StorageError(f"injected get failure for {key}")
        if key not in self.objects:
            raise StorageKeyMissing(key)
        return self.objects[key]


# --- _hydrate / hydrate_* unit tests (no DB required) -----------------------


def _row(**kwargs: Any) -> Any:
    """Build a SimpleNamespace mimicking a ContractMaterialization row.
    The hydrate helpers use ``getattr`` so duck-typing is sufficient."""
    defaults = dict(
        chain="1",
        bytecode_keccak="0x" + "ab" * 32,
        analysis=None,
        analysis_blob_key=None,
        tracking_plan=None,
        tracking_plan_blob_key=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_hydrate_inline_when_no_blob_key():
    """The legacy path: the row has JSONB but no blob_key."""
    row = _row(analysis={"controllers": ["a", "b"]})
    assert cm.hydrate_analysis(row) == {"controllers": ["a", "b"]}


def test_hydrate_returns_none_when_neither_set():
    """A row without either the inline or the blob copy (e.g. a row
    in ``status='failed'``) returns None rather than crashing."""
    assert cm.hydrate_analysis(_row()) is None


def test_hydrate_reads_blob_when_blob_key_set():
    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/analysis.json"
    storage.objects[key] = json.dumps({"controllers": ["x"]}).encode("utf-8")

    row = _row(analysis_blob_key=key, analysis=None)
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        got = cm.hydrate_analysis(row)

    assert got == {"controllers": ["x"]}
    assert storage.get_calls == [key]


def test_hydrate_falls_back_to_inline_on_blob_fetch_error():
    """A flaky bucket must not break a row that has BOTH a blob_key
    and inline JSONB (the transition window before backfill clears
    JSONB). Inline wins, with a warning."""
    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/analysis.json"
    storage.fail_get.add(key)

    row = _row(analysis_blob_key=key, analysis={"controllers": ["fallback"]})
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        got = cm.hydrate_analysis(row)

    assert got == {"controllers": ["fallback"]}


def test_hydrate_returns_none_on_blob_fetch_error_with_no_inline():
    """A row whose JSONB has been cleared by --clear-jsonb cannot fall
    back. Returning None so the caller surfaces a clean cache miss
    instead of crashing."""
    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/analysis.json"
    storage.fail_get.add(key)

    row = _row(analysis_blob_key=key, analysis=None)
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        got = cm.hydrate_analysis(row)

    assert got is None


def test_hydrate_returns_inline_when_blob_key_set_but_storage_unconfigured():
    """An offline test environment that wrote a row with a blob_key but
    later turned ARTIFACT_STORAGE_* off must still serve inline JSONB
    if it's there. Operationally rare but keeps the test fixture
    permutations sane."""
    row = _row(analysis_blob_key="contract_materializations/x/y/analysis.json", analysis={"v": 1})
    with patch("db.contract_materializations.get_storage_client", return_value=None):
        assert cm.hydrate_analysis(row) == {"v": 1}


def test_hydrate_tracking_plan_uses_tracking_plan_columns():
    """Symmetry check: the helper for tracking_plan reads the
    tracking_plan_* attributes, not analysis_*."""
    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/tracking_plan.json"
    storage.objects[key] = json.dumps({"slots": [1, 2]}).encode("utf-8")

    row = _row(
        analysis={"should": "ignore"},
        tracking_plan_blob_key=key,
        tracking_plan=None,
    )
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        assert cm.hydrate_tracking_plan(row) == {"slots": [1, 2]}


# --- materialize_or_wait integration tests (requires Postgres) --------------


@pytest.fixture()
def _clean_cm(db_session):
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    yield db_session
    db_session.query(ContractMaterialization).delete()
    db_session.commit()


@pytest.fixture()
def _route_to_test_db(monkeypatch):
    """Point db.contract_materializations.SessionLocal at TEST_DATABASE_URL
    so writes don't leak into the dev DB."""
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


@requires_postgres
def test_materialize_writes_to_blob_when_storage_configured(_route_to_test_db, _clean_cm):
    """The new path: writes ``analysis`` and ``tracking_plan`` to blob
    storage, persists only the keys on the row. JSONB columns are NULL.
    """
    storage = _StubStorage()

    def _builder() -> dict[str, Any]:
        return {
            "contract_name": "TestContract",
            "analysis": {"controllers": ["a"]},
            "tracking_plan": {"slots": [{"name": "x", "type": "uint256"}]},
        }

    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        row = cm.materialize_or_wait(
            chain="1",
            address="0x" + "1" * 40,
            bytecode_keccak="0x" + "ab" * 32,
            builder=_builder,
        )

    assert row.status == "ready"
    assert row.analysis is None, "blob path must leave JSONB null"
    assert row.tracking_plan is None
    assert row.analysis_blob_key
    assert row.tracking_plan_blob_key
    # Two puts, in the keccak-namespaced layout.
    assert len(storage.put_calls) == 2
    keys_written = sorted(k for (k, _) in storage.put_calls)
    assert keys_written[0].endswith("/analysis.json")
    assert keys_written[1].endswith("/tracking_plan.json")
    # Round-trip via hydrate_*.
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        assert cm.hydrate_analysis(row) == {"controllers": ["a"]}
        assert cm.hydrate_tracking_plan(row) == {"slots": [{"name": "x", "type": "uint256"}]}


@requires_postgres
def test_materialize_falls_back_to_inline_when_storage_unconfigured(_route_to_test_db, _clean_cm):
    """Local dev / offline tests without ARTIFACT_STORAGE_* must keep
    working — writes go to JSONB inline, blob_key columns stay NULL."""

    def _builder() -> dict[str, Any]:
        return {
            "contract_name": "InlineContract",
            "analysis": {"controllers": ["b"]},
            "tracking_plan": {"slots": []},
        }

    with patch("db.contract_materializations.get_storage_client", return_value=None):
        row = cm.materialize_or_wait(
            chain="1",
            address="0x" + "2" * 40,
            bytecode_keccak="0x" + "cd" * 32,
            builder=_builder,
        )

    assert row.status == "ready"
    assert row.analysis_blob_key is None
    assert row.tracking_plan_blob_key is None
    assert row.analysis == {"controllers": ["b"]}
    assert row.tracking_plan == {"slots": []}


@requires_postgres
def test_materialize_rolls_back_when_blob_upload_fails(_route_to_test_db, _clean_cm):
    """A Tigris transient must not leave a half-written row: the
    transaction rolls back so the next caller can retry the build
    cleanly. The advisory lock is released alongside the rollback."""
    storage = _StubStorage()
    # Pre-compute the blob key that materialize_or_wait will choose so
    # we can mark it as failing.
    chain = "1"
    keccak = "0x" + "ee" * 32
    bad_key = cm._blob_key(chain, keccak, "tracking_plan")
    storage.fail_put.add(bad_key)

    def _builder() -> dict[str, Any]:
        return {
            "contract_name": "FailContract",
            "analysis": {"controllers": ["c"]},
            "tracking_plan": {"slots": [42]},
        }

    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        with pytest.raises(StorageError):
            cm.materialize_or_wait(
                chain=chain,
                address="0x" + "3" * 40,
                bytecode_keccak=keccak,
                builder=_builder,
            )

    # No row committed — the next caller can rebuild.
    assert cm.find_by_keccak(_clean_cm, chain=chain, bytecode_keccak=keccak) is None, (
        "failed-blob-upload must not commit a row"
    )


@requires_postgres
def test_materialize_blob_path_loser_serves_blob_key(_route_to_test_db, _clean_cm):
    """A second caller after the winner committed sees the row's
    ``status='ready'`` on its second read inside the lock and returns
    without re-running the builder. The returned row carries the
    blob_keys the winner wrote, hydrate works the same way."""
    storage = _StubStorage()

    def _builder() -> dict[str, Any]:
        return {
            "contract_name": "Winner",
            "analysis": {"k": "v"},
            "tracking_plan": {"k": "v"},
        }

    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        first = cm.materialize_or_wait(
            chain="1",
            address="0x" + "4" * 40,
            bytecode_keccak="0x" + "11" * 32,
            builder=_builder,
        )

    builder_called = {"n": 0}

    def _builder2() -> dict[str, Any]:
        builder_called["n"] += 1
        raise AssertionError("loser path must not re-run the builder")

    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        second = cm.materialize_or_wait(
            chain="1",
            address="0x" + "5" * 40,  # different address, same keccak
            bytecode_keccak="0x" + "11" * 32,
            builder=_builder2,
        )

    assert builder_called["n"] == 0
    assert second.bytecode_keccak == first.bytecode_keccak
    assert second.analysis_blob_key == first.analysis_blob_key


# --- backfill-script smoke (offline, no storage) ----------------------------


@requires_postgres
def test_backfill_skips_already_migrated_rows(_route_to_test_db, _clean_cm, monkeypatch):
    """Rows that already have ``analysis_blob_key`` are no-ops on
    re-run. Idempotent."""
    from scripts import backfill_contract_materializations_to_blob as backfill

    storage = _StubStorage()
    # Insert a row that's already fully migrated.
    row = ContractMaterialization(
        chain="1",
        bytecode_keccak="0x" + "aa" * 32,
        address="0x" + "1" * 40,
        contract_name="Already",
        analysis=None,
        tracking_plan=None,
        analysis_blob_key="contract_materializations/ethereum/0xaa/analysis.json",
        tracking_plan_blob_key="contract_materializations/ethereum/0xaa/tracking_plan.json",
        status="ready",
    )
    _clean_cm.add(row)
    _clean_cm.commit()

    # Mock the test session factory so the backfill writes via
    # _route_to_test_db's binding.
    with patch("scripts.backfill_contract_materializations_to_blob.get_storage_client", return_value=storage):
        with patch("scripts.backfill_contract_materializations_to_blob.SessionLocal") as mock_sl:
            from sqlalchemy import create_engine
            from sqlalchemy.orm import Session, sessionmaker

            engine = create_engine(uuid_url := __import__("os").environ["TEST_DATABASE_URL"])  # noqa: F841
            factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
            mock_sl.side_effect = factory
            rc = backfill.main(["--chain", "ethereum"])
            engine.dispose()

    assert rc == 0
    # No puts: the row was already migrated.
    assert storage.put_calls == []


@requires_postgres
def test_backfill_dry_run_writes_nothing(_route_to_test_db, _clean_cm):
    """``--dry-run`` reports counts but performs zero writes (neither
    Tigris nor DB)."""
    from scripts import backfill_contract_materializations_to_blob as backfill

    keccak = "0x" + ("ff" * 32)[:64]
    row = ContractMaterialization(
        chain="1",
        bytecode_keccak=keccak,
        address="0x" + "1" * 40,
        contract_name="DryRun",
        analysis={"a": 1},
        tracking_plan={"b": 2},
        analysis_blob_key=None,
        tracking_plan_blob_key=None,
        status="ready",
        # A row the version-filtered ``find_by_keccak`` can see: seed at the
        # current analyzer version, not the DB default, so it stays findable
        # across an ANALYSIS_SCHEMA_VERSION bump.
        analysis_schema_version=cm.ANALYSIS_SCHEMA_VERSION,
    )
    _clean_cm.add(row)
    _clean_cm.commit()

    storage = _StubStorage()

    import os

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    engine = create_engine(os.environ["TEST_DATABASE_URL"])
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)

    with patch("scripts.backfill_contract_materializations_to_blob.get_storage_client", return_value=storage):
        with patch("scripts.backfill_contract_materializations_to_blob.SessionLocal", side_effect=factory):
            rc = backfill.main(["--dry-run"])
    engine.dispose()

    assert rc == 0
    # Dry-run writes nothing to the bucket.
    assert storage.put_calls == []
    # And nothing to the DB (the row is unchanged).
    fresh = cm.find_by_keccak(_clean_cm, chain="1", bytecode_keccak=keccak)
    assert fresh is not None
    assert fresh.analysis_blob_key is None
    assert fresh.analysis == {"a": 1}
