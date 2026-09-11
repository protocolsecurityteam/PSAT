"""Blob-vs-inline storage paths in ``db.contract_materializations``.

The schema carries paired columns (``static_facts`` JSONB +
``static_facts_blob_key`` Text; same for ``observation_plan``). When
``ARTIFACT_STORAGE_*`` env vars are set, ``materialize_or_wait``
writes the payloads to object storage and persists only the keys on
the row. When unconfigured, it falls back to inline JSONB.

Reads always go through ``hydrate_static_facts`` /
``hydrate_observation_plan`` which try the blob first and fall back to
inline JSONB on either a missing key or a transient blob fetch
error. That fallback is what lets pre-migration rows keep working
while the backfill catches up — and what insulates the pipeline
from a transient Tigris outage *when an inline copy exists*. When
one does not, the read raises ``StorageContentNotDetermined``
rather than returning the ``None`` that also means "this row stored
nothing": the pipeline may serve stale, never invented, absence.

These tests mock ``get_storage_client`` rather than spinning up a
minio container so they stay in the offline tier. The minio-backed
end-to-end path is exercised by the live test suite.

Marker: offline (``requires_postgres`` for the ones that need the
real materializations table).
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from db import contract_materializations as cm
from db.models import ContractMaterialization
from db.storage import StorageError, StorageKeyMissing
from tests.conftest import requires_postgres

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
        static_facts=None,
        static_facts_blob_key=None,
        observation_plan=None,
        observation_plan_blob_key=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_hydrate_inline_when_storage_is_unconfigured():
    row = _row(static_facts={"controllers": ["a", "b"]})
    assert cm.hydrate_static_facts(row) == {"controllers": ["a", "b"]}


def test_hydrate_returns_none_when_neither_set():
    """A row without either the inline or the blob copy (e.g. a row
    in ``status='failed'``) returns None rather than crashing."""
    assert cm.hydrate_static_facts(_row()) is None


def test_hydrate_reads_blob_when_blob_key_set():
    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/static_facts.json"
    storage.objects[key] = json.dumps({"controllers": ["x"]}).encode("utf-8")

    row = _row(static_facts_blob_key=key, static_facts=None)
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        got = cm.hydrate_static_facts(row)

    assert got == {"controllers": ["x"]}
    assert storage.get_calls == [key]


def test_hydrate_falls_back_to_inline_on_blob_fetch_error():
    """A flaky bucket must not break a row that has BOTH a blob_key
    and inline JSONB (the transition window before backfill clears
    JSONB). Inline wins, with a warning."""
    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/static_facts.json"
    storage.fail_get.add(key)

    row = _row(static_facts_blob_key=key, static_facts={"controllers": ["fallback"]})
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        got = cm.hydrate_static_facts(row)

    assert got == {"controllers": ["fallback"]}


def test_hydrate_raises_on_blob_fetch_error_with_no_inline():
    """INVERTED (was ``test_hydrate_returns_none_on_blob_fetch_error_with_no_inline``,
    which asserted ``got is None``).

    That assertion pinned the defect. ``None`` here is the same value the
    function returns for a row that genuinely stored nothing, and
    ``services/resolution/recursive`` writes ``or {}`` over it — so an
    unreadable blob rendered as "this contract has no static_facts, no plan and no
    predicate trees", and that state seeded the effects probe and was cached
    under the witness schema version. A "clean cache miss" is a claim about the
    contract; the bucket failing is not.
    """
    from db.storage import StorageContentNotDetermined

    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/static_facts.json"
    storage.fail_get.add(key)

    row = _row(static_facts_blob_key=key, static_facts=None)
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        with pytest.raises(StorageContentNotDetermined) as excinfo:
            cm.hydrate_static_facts(row)
    assert "static_facts_blob_key" in excinfo.value.not_determined

    # Control: nothing recorded at all is still a proven absence, not a raise.
    assert cm.hydrate_static_facts(_row(static_facts_blob_key=None, static_facts=None)) is None


def test_hydrate_returns_inline_when_blob_key_set_but_storage_unconfigured():
    """An offline test environment that wrote a row with a blob_key but
    later turned ARTIFACT_STORAGE_* off must still serve inline JSONB
    if it's there. Operationally rare but keeps the test fixture
    permutations sane."""
    row = _row(static_facts_blob_key="contract_materializations/x/y/static_facts.json", static_facts={"v": 1})
    with patch("db.contract_materializations.get_storage_client", return_value=None):
        assert cm.hydrate_static_facts(row) == {"v": 1}


def test_hydrate_observation_plan_uses_observation_plan_columns():
    """Symmetry check: the helper for observation_plan reads the
    observation_plan_* attributes, not analysis_*."""
    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/observation_plan.json"
    storage.objects[key] = json.dumps({"slots": [1, 2]}).encode("utf-8")

    row = _row(
        static_facts={"should": "ignore"},
        observation_plan_blob_key=key,
        observation_plan=None,
    )
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        assert cm.hydrate_observation_plan(row) == {"slots": [1, 2]}


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
    """The new path: writes ``static_facts`` and ``observation_plan`` to blob
    storage, persists only the keys on the row. JSONB columns are NULL.
    """
    storage = _StubStorage()

    def _builder() -> dict[str, Any]:
        return {
            "contract_name": "TestContract",
            "static_facts": {"controllers": ["a"]},
            "observation_plan": {"slots": [{"name": "x", "type": "uint256"}]},
            "effects": {"schema_version": "semantic", "functions": {}},
        }

    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        row = cm.materialize_or_wait(
            chain="1",
            address="0x" + "1" * 40,
            bytecode_keccak="0x" + "ab" * 32,
            builder=_builder,
        )

    assert row.status == "ready"
    assert row.static_facts is None, "blob path must leave JSONB null"
    assert row.observation_plan is None
    assert row.static_facts_blob_key
    assert row.observation_plan_blob_key
    # Two puts, in the keccak-namespaced layout.
    assert len(storage.put_calls) == 2
    keys_written = sorted(k for (k, _) in storage.put_calls)
    assert {key.rsplit("/", 1)[-1] for key in keys_written} == {"static_facts.json", "observation_plan.json"}
    # Round-trip via hydrate_*.
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        assert cm.hydrate_static_facts(row) == {"controllers": ["a"]}
        assert cm.hydrate_observation_plan(row) == {"slots": [{"name": "x", "type": "uint256"}]}


@requires_postgres
def test_materialize_falls_back_to_inline_when_storage_unconfigured(_route_to_test_db, _clean_cm):
    """Local dev / offline tests without ARTIFACT_STORAGE_* must keep
    working — writes go to JSONB inline, blob_key columns stay NULL."""

    def _builder() -> dict[str, Any]:
        return {
            "contract_name": "InlineContract",
            "static_facts": {"controllers": ["b"]},
            "observation_plan": {"slots": []},
            "effects": {"schema_version": "semantic", "functions": {}},
        }

    with patch("db.contract_materializations.get_storage_client", return_value=None):
        row = cm.materialize_or_wait(
            chain="1",
            address="0x" + "2" * 40,
            bytecode_keccak="0x" + "cd" * 32,
            builder=_builder,
        )

    assert row.status == "ready"
    assert row.static_facts_blob_key is None
    assert row.observation_plan_blob_key is None
    assert row.static_facts == {"controllers": ["b"]}
    assert row.observation_plan == {"slots": []}


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
    bad_key = cm._blob_key(chain, keccak, "observation_plan")
    storage.fail_put.add(bad_key)

    def _builder() -> dict[str, Any]:
        return {
            "contract_name": "FailContract",
            "static_facts": {"controllers": ["c"]},
            "observation_plan": {"slots": [42]},
            "effects": {"schema_version": "semantic", "functions": {}},
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
            "static_facts": {"k": "v"},
            "observation_plan": {"k": "v"},
            "effects": {"schema_version": "semantic", "functions": {}},
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
    assert second.static_facts_blob_key == first.static_facts_blob_key
