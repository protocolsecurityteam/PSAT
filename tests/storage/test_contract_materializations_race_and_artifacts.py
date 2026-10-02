"""PR-79 cache bugs. #1: the advisory lock was released between the ready-check and the builder, so two callers
in the 60-150 s window both built; a ``status='building'`` claim row with a staleness threshold fixes it. #4:
``predicate_trees`` was dropped on write, so every cache hit skipped mapping-writer enumeration.
"""

from __future__ import annotations

import threading
import time
from typing import Any
from unittest.mock import patch

import pytest

from db import contract_materializations as cm
from tests.conftest import requires_postgres
from tests.support.materializations import (
    _clean_cm,  # noqa: F401  (fixture, registered by import)
    _route_to_test_db,  # noqa: F401  (fixture, registered by import)
)


@pytest.fixture()
def _short_wait_poll(monkeypatch):
    monkeypatch.setenv("PSAT_MATERIALIZE_WAIT_POLL_INTERVAL_S", "0.05")
    monkeypatch.setenv("PSAT_MATERIALIZE_BUILDER_STALENESS_S", "120")


@requires_postgres
def test_concurrent_materialize_runs_builder_exactly_once(_route_to_test_db, _clean_cm, _short_wait_poll):
    chain = "1"
    keccak = "0x" + "ab" * 32

    builder_started = threading.Event()
    builder_lock = threading.Lock()
    invocations = {"n": 0}

    def slow_builder() -> dict[str, Any]:
        with builder_lock:
            invocations["n"] += 1
        builder_started.set()
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

    assert row.predicate_trees is None
    assert row.predicate_trees_blob_key is not None
    keys_written = sorted(storage.put_calls)
    assert any(k.endswith("/predicate_trees.json") for k in keys_written)

    with patch("db.contract_materializations.get_storage_client", return_value=storage):
        assert cm.hydrate_predicate_trees(row) == predicate_payload
