"""Resolution and policy run in different processes, so the in-process cache missed across stages and re-paid the 60s
HyperSync timeout (the live concurrency wedge). L1 is cleared between calls to simulate the second process.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from db.models import MappingEnumerationCache
from services.resolution import mapping_enumerator
from services.resolution.mapping_enumerator import (
    _event_topic0,
    clear_enumeration_cache,
    enumerate_mapping_allowlist_sync,
)
from tests.conftest import requires_postgres
from tests.support.hypersync_fakes import _FakeHypersyncModule


@pytest.fixture(autouse=True)
def _enable_db_cache(monkeypatch):
    """Its own ``SessionLocal`` binds to ``DATABASE_URL``; redirect so writes stay out of the dev DB."""
    import os

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    monkeypatch.setenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "1")
    clear_enumeration_cache()

    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        yield
        clear_enumeration_cache()
        return

    test_engine = create_engine(test_url)
    test_factory = sessionmaker(bind=test_engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("db.mapping_enumeration_cache.SessionLocal", test_factory)
    try:
        yield
    finally:
        clear_enumeration_cache()
        test_engine.dispose()


@pytest.fixture()
def _clean_l2(db_session):
    db_session.query(MappingEnumerationCache).delete()
    db_session.commit()
    yield db_session
    db_session.query(MappingEnumerationCache).delete()
    db_session.commit()


def _addr(suffix: str) -> str:
    return "0x" + suffix.lower().rjust(40, "0")


def _indexed_topic(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _log(topic0: str, indexed_args: list[str] | None = None, block: int = 1):
    topics = [topic0] + [_indexed_topic(a) for a in (indexed_args or [])]
    return SimpleNamespace(
        topics=topics,
        data="0x",
        block_number=block,
        transaction_hash="0x" + "f" * 64,
        log_index=0,
    )


def _fake_client(batches):
    counter: dict[str, int] = {"n": 0}

    class _Client:
        async def get(self, _query):
            i = counter["n"]
            counter["n"] += 1
            if i >= len(batches):
                return SimpleNamespace(data=[], next_block=None)
            logs, next_block = batches[i]
            return SimpleNamespace(data=logs, next_block=next_block)

    return _Client(), counter


def _rely_spec():
    return {
        "event_signature": "Rely(address)",
        "mapping_name": "wards",
        "direction": "add",
        "key_position": 0,
        "indexed_positions": [0],
    }


def _deny_spec():
    return {
        "event_signature": "Deny(address)",
        "mapping_name": "wards",
        "direction": "remove",
        "key_position": 0,
        "indexed_positions": [0],
    }


@requires_postgres
def test_l2_cache_hits_across_simulated_process_boundary(_clean_l2):
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    pages = [([_log(rely_topic, indexed_args=[alice], block=10)], None)]
    client, counter = _fake_client(pages)

    addr = "0x" + "AA" * 20

    result1 = enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=client,
        hypersync_module=_FakeHypersyncModule(),
        timeout_s=10,
        max_pages=10,
    )
    assert result1["status"] == "complete"
    assert len(result1["principals"]) == 1
    calls_after_first = counter["n"]
    assert calls_after_first >= 1

    clear_enumeration_cache()
    assert not mapping_enumerator._CACHE

    # A counter increment would mean L2 missed.
    new_client, new_counter = _fake_client(pages)
    result2 = enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=new_client,
        hypersync_module=_FakeHypersyncModule(),
        timeout_s=10,
        max_pages=10,
    )

    assert new_counter["n"] == 0, (
        "L2 missed across simulated process boundary — policy stage re-paginated. "
        "This is the regression introduced by 9ce6fa3 (worker process split)."
    )
    assert result2 == result1
