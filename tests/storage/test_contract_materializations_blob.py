"""With storage configured, ``materialize_or_wait`` persists blob keys; reads try the blob then inline JSONB, and
otherwise raise ``StorageContentNotDetermined`` rather than a ``None`` that means "stored nothing". Minio
end-to-end is in the live suite.
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


class _StubStorage:
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


def _row(**kwargs: Any) -> Any:
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


@pytest.mark.parametrize(
    ("row_fields", "expected"),
    [
        pytest.param({"analysis": {"controllers": ["a", "b"]}}, {"controllers": ["a", "b"]}, id="inline-no-blob-key"),
        pytest.param({}, None, id="neither-set-is-none"),
        pytest.param(
            {"analysis_blob_key": "contract_materializations/x/y/analysis.json", "analysis": {"v": 1}},
            {"v": 1},
            id="inline-when-blob-key-set-but-storage-unconfigured",
        ),
    ],
)
def test_hydrate_analysis_without_readable_blob(row_fields, expected):
    with patch("db.contract_materializations.get_storage_client", return_value=None):
        assert cm.hydrate_analysis(_row(**row_fields)) == expected


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
    """Covers the pre-backfill window."""
    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/analysis.json"
    storage.fail_get.add(key)

    row = _row(analysis_blob_key=key, analysis={"controllers": ["fallback"]})
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        got = cm.hydrate_analysis(row)

    assert got == {"controllers": ["fallback"]}


def test_hydrate_raises_on_blob_fetch_error_with_no_inline():
    """Inverted: ``None`` equals "stored nothing", and ``or {}`` over it seeded the effects probe and got cached.

    A bucket failure is not a claim about the contract.
    """
    from db.storage import StorageContentNotDetermined

    storage = _StubStorage()
    key = "contract_materializations/ethereum/0xab/analysis.json"
    storage.fail_get.add(key)

    row = _row(analysis_blob_key=key, analysis=None)
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        with pytest.raises(StorageContentNotDetermined) as excinfo:
            cm.hydrate_analysis(row)
    assert "analysis_blob_key" in excinfo.value.not_determined

    assert cm.hydrate_analysis(_row(analysis_blob_key=None, analysis=None)) is None


def test_hydrate_tracking_plan_uses_tracking_plan_columns():
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


@requires_postgres
def test_materialize_writes_to_blob_when_storage_configured(_route_to_test_db, _clean_cm):
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
    assert len(storage.put_calls) == 2
    keys_written = sorted(k for (k, _) in storage.put_calls)
    assert keys_written[0].endswith("/analysis.json")
    assert keys_written[1].endswith("/tracking_plan.json")
    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        assert cm.hydrate_analysis(row) == {"controllers": ["a"]}
        assert cm.hydrate_tracking_plan(row) == {"slots": [{"name": "x", "type": "uint256"}]}


@requires_postgres
def test_materialize_falls_back_to_inline_when_storage_unconfigured(_route_to_test_db, _clean_cm):

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
    """Rolling back releases the advisory lock so the next caller can retry."""
    storage = _StubStorage()
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

    assert cm.find_by_keccak(_clean_cm, chain=chain, bytecode_keccak=keccak) is None, (
        "failed-blob-upload must not commit a row"
    )


@requires_postgres
def test_materialize_blob_path_loser_serves_blob_key(_route_to_test_db, _clean_cm):
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


@requires_postgres
def test_backfill_skips_already_migrated_rows(_route_to_test_db, _clean_cm, monkeypatch):
    from scripts import backfill_contract_materializations_to_blob as backfill

    storage = _StubStorage()
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
    assert storage.put_calls == []


@requires_postgres
def test_backfill_dry_run_writes_nothing(_route_to_test_db, _clean_cm):
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
        # Seeded at the current analyzer version so it stays findable across a schema bump.
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
    assert storage.put_calls == []
    fresh = cm.find_by_keccak(_clean_cm, chain="1", bytecode_keccak=keccak)
    assert fresh is not None
    assert fresh.analysis_blob_key is None
    assert fresh.analysis == {"a": 1}
