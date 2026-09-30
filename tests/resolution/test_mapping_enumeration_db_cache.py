"""Resolution and policy run in different processes, so the in-process cache missed across stages and re-paid the 60s
HyperSync timeout (the live concurrency wedge). L1 is cleared between calls to simulate the second process.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from db import mapping_enumeration_cache as db_cache
from db.models import MappingEnumerationCache
from services.resolution import mapping_enumerator
from services.resolution.mapping_enumerator import (
    _event_topic0,
    clear_enumeration_cache,
    enumerate_mapping_allowlist_sync,
)
from tests.conftest import requires_postgres


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


class _FakeFieldEnumMeta(type):
    _members = ("address", "topic0", "data", "block_number")

    def __iter__(cls):
        for name in cls._members:
            yield cls(name)


class _FakeFieldEnum(metaclass=_FakeFieldEnumMeta):
    def __init__(self, name: str):
        self.value = name


class _FakeHypersyncModule:
    Query = SimpleNamespace
    LogSelection = SimpleNamespace
    FieldSelection = SimpleNamespace
    LogField = _FakeFieldEnum


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


@requires_postgres
def test_l2_cache_distinguishes_specs_via_hash(_clean_l2):
    """A stale hit across specs would be a correctness bug."""
    rely_topic = _event_topic0("Rely(address)")
    deny_topic = _event_topic0("Deny(address)")
    alice = _addr("a11ce")
    bob = _addr("b0b")

    addr = "0x" + "BB" * 20

    rely_pages = [([_log(rely_topic, indexed_args=[alice], block=5)], None)]
    rely_client, rely_counter = _fake_client(rely_pages)
    enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=rely_client,
        hypersync_module=_FakeHypersyncModule(),
    )
    assert rely_counter["n"] >= 1

    clear_enumeration_cache()  # cross-process simulation

    rely_deny_pages = [
        (
            [
                _log(rely_topic, indexed_args=[alice], block=5),
                _log(deny_topic, indexed_args=[bob], block=6),
            ],
            None,
        )
    ]
    rely_deny_client, rely_deny_counter = _fake_client(rely_deny_pages)
    result_two_specs = enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec(), _deny_spec()]),
        from_block=0,
        client=rely_deny_client,
        hypersync_module=_FakeHypersyncModule(),
    )

    assert rely_deny_counter["n"] >= 1, (
        "L2 incorrectly returned the rely-only row for a rely+deny query — "
        "specs_hash must participate in the cache key."
    )
    assert result_two_specs["status"] == "complete"


@requires_postgres
def test_l2_cache_persists_truncated_results(_clean_l2):
    """Re-running within the TTL would hit the same bound."""
    rely_topic = _event_topic0("Rely(address)")
    # next_block must increase or the enumerator finishes before max_pages.
    pages = [
        ([_log(rely_topic, indexed_args=[_addr("a")], block=1)], 100),
        ([_log(rely_topic, indexed_args=[_addr("b")], block=200)], 300),
        ([_log(rely_topic, indexed_args=[_addr("c")], block=400)], 500),
    ]
    client, counter = _fake_client(pages)

    addr = "0x" + "CC" * 20

    result1 = enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=client,
        hypersync_module=_FakeHypersyncModule(),
        max_pages=2,  # forces incomplete_max_pages
        timeout_s=60,
    )
    assert result1["status"] == "incomplete_max_pages"
    calls_after_first = counter["n"]

    clear_enumeration_cache()

    new_client, new_counter = _fake_client(pages)
    result2 = enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=new_client,
        hypersync_module=_FakeHypersyncModule(),
        max_pages=2,
        timeout_s=60,
    )
    assert new_counter["n"] == 0, "truncated results must be cached too"
    assert result2["status"] == "incomplete_max_pages"
    assert counter["n"] == calls_after_first


@requires_postgres
def test_l2_ttl_invalidation(monkeypatch, _clean_l2):
    rely_topic = _event_topic0("Rely(address)")
    pages = [([_log(rely_topic, indexed_args=[_addr("a")], block=10)], None)]
    client, counter = _fake_client(pages)

    addr = "0x" + "DD" * 20

    enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=client,
        hypersync_module=_FakeHypersyncModule(),
    )
    assert counter["n"] >= 1
    first_calls = counter["n"]

    monkeypatch.setenv("PSAT_MAPPING_ENUMERATION_CACHE_TTL_S", "0")

    clear_enumeration_cache()  # cross-process simulation
    new_client, new_counter = _fake_client(pages)
    enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=new_client,
        hypersync_module=_FakeHypersyncModule(),
    )
    assert new_counter["n"] >= 1, "TTL-expired row should be treated as a miss"
    assert counter["n"] == first_calls  # original counter untouched


@requires_postgres
@pytest.mark.parametrize(
    "spec_a,spec_b,same",
    [
        pytest.param(
            {**_rely_spec(), "indexed_positions": [0, 1]},
            {**_rely_spec(), "indexed_positions": [1, 0]},
            True,
            id="indexed_positions_order_insensitive",
        ),
        # A Rely-only scan must not return a stale Deny-bearing set.
        pytest.param(_rely_spec(), {**_rely_spec(), "direction": "remove"}, False, id="direction_changes_it"),
    ],
)
def test_specs_fingerprint(_clean_l2, spec_a, spec_b, same):
    assert (db_cache.specs_fingerprint([spec_a]) == db_cache.specs_fingerprint([spec_b])) is same
