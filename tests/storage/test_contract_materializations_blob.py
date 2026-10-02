"""With storage configured, ``materialize_or_wait`` persists blob keys; reads try the blob then inline JSONB, and
otherwise raise ``StorageContentNotDetermined`` rather than a ``None`` that means "stored nothing". Minio
end-to-end is in the live suite.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from db import contract_materializations as cm
from db.storage import StorageError, StorageKeyMissing
from tests.conftest import requires_postgres
from tests.support.materializations import (
    _clean_cm,  # noqa: F401  (fixture, registered by import)
    _route_to_test_db,  # noqa: F401  (fixture, registered by import)
)


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
