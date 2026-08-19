"""Cross-process L2 cache for mapping_enumerator.

Validates the regression that 9ce6fa3 ("perf: parallelize worker pipeline")
introduced: ResolutionWorker and PolicyWorker run in different OS
processes, so the in-process module dict
(``services.resolution.mapping_enumerator._CACHE``) misses across the
stage boundary. With only L1 in place, a single LinkToken job re-pays
the 60s hypersync timeout twice — once per stage — which is the
proximate cause of the live concurrency-test wedge.

The L2 cache lives in ``db.mapping_enumeration_cache`` and is keyed on
``(chain, address, specs_hash)``. The test below clears the L1 dict
between calls to faithfully simulate the second worker process having
no in-memory state to share, then asserts that the second call hits
the persisted row instead of running pagination again.

Marker: offline (PostgreSQL via requires_postgres). No live hypersync.
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
    """Force L2 ON and point its SessionLocal at TEST_DATABASE_URL.

    The unit suite for the in-process layer turns L2 off; this suite
    needs it on. ``db.mapping_enumeration_cache`` opens its own
    ``SessionLocal()`` (so callers don't have to thread sessions through
    the resolution graph), which by default binds to ``DATABASE_URL``;
    redirecting it here keeps the cross-process test honest without
    leaking writes into the dev database.
    """
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
    """Drop any rows left from previous runs so address collisions don't
    silently mask a miss-then-hit assertion."""
    db_session.query(MappingEnumerationCache).delete()
    db_session.commit()
    yield db_session
    db_session.query(MappingEnumerationCache).delete()
    db_session.commit()


# --- minimal fakes (mirrors tests/resolution/test_mapping_enumerator.py) ---------------


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


# --- tests ------------------------------------------------------------------


@requires_postgres
def test_l2_cache_hits_across_simulated_process_boundary(_clean_l2):
    """The regression case: stage 1 worker enumerates and persists; stage
    2 in a fresh process (simulated by clearing L1) reads the L2 row
    instead of re-running the 60s hypersync scan.
    """
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    pages = [([_log(rely_topic, indexed_args=[alice], block=10)], None)]
    client, counter = _fake_client(pages)

    addr = "0x" + "AA" * 20

    # Worker process 1 — resolution stage. L1 + L2 both miss; runs pagination.
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

    # Simulate the OS process boundary: drop the in-memory dict so any
    # subsequent hit must come from the L2 row that was just upserted.
    clear_enumeration_cache()
    assert not mapping_enumerator._CACHE

    # Worker process 2 — policy stage. L1 is empty (clean process). L2
    # must rehydrate. A new client is intentionally passed: if L2 missed
    # we'd see counter["n"] increment.
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
    """A different writer-spec set must NOT share an L2 row even on the
    same address — different specs produce different principal sets, so
    a stale hit would be a correctness bug.
    """
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
    """``incomplete_*`` and ``error`` results are cached intentionally —
    re-running them inside the TTL would just hit the same bound. The
    caller sees ``status`` and decides whether to act.
    """
    rely_topic = _event_topic0("Rely(address)")
    # next_block must strictly increase to keep the loop going; otherwise the
    # enumerator finishes naturally before hitting max_pages.
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
    """Past the TTL, a stale row is treated as a miss — caller re-scans."""
    rely_topic = _event_topic0("Rely(address)")
    pages = [([_log(rely_topic, indexed_args=[_addr("a")], block=10)], None)]
    client, counter = _fake_client(pages)

    addr = "0x" + "DD" * 20

    # First scan with normal TTL — populates L2.
    enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=client,
        hypersync_module=_FakeHypersyncModule(),
    )
    assert counter["n"] >= 1
    first_calls = counter["n"]

    # Force the TTL to zero so the next read sees the row as stale.
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


# --- direct unit tests for the db module ------------------------------------


@requires_postgres
def test_specs_fingerprint_is_order_insensitive_for_indexed_positions():
    """``indexed_positions=[1,0]`` and ``[0,1]`` describe the same spec —
    the fingerprint must collapse them so a benign reordering doesn't
    bust the cache."""
    spec_a = [{**_rely_spec(), "indexed_positions": [0, 1]}]
    spec_b = [{**_rely_spec(), "indexed_positions": [1, 0]}]
    assert db_cache.specs_fingerprint(spec_a) == db_cache.specs_fingerprint(spec_b)


@requires_postgres
def test_specs_fingerprint_changes_on_direction(_clean_l2):
    """Flipping direction must yield a different fingerprint — otherwise
    a Rely-only scan could return a stale Deny-bearing principal set."""
    rely = [_rely_spec()]
    deny = [{**_rely_spec(), "direction": "remove"}]
    assert db_cache.specs_fingerprint(rely) != db_cache.specs_fingerprint(deny)


@requires_postgres
def test_db_module_upsert_and_find_roundtrip(_clean_l2):
    """upsert→find_fresh contract."""
    specs = [_rely_spec()]
    h = db_cache.specs_fingerprint(specs)
    payload = {
        "principals": [
            {
                "address": _addr("a"),
                "mapping_name": "wards",
                "direction_history": ["add"],
                "last_seen_block": 10,
            }
        ],
        "status": "complete",
        "pages_fetched": 1,
        "last_block_scanned": 100,
        "error": None,
    }
    db_cache.upsert(chain="ethereum", address="0x" + "EE" * 20, specs_hash=h, result=payload)
    got = db_cache.find_fresh(chain="ethereum", address="0x" + "EE" * 20, specs_hash=h)
    assert got is not None
    assert got["status"] == "complete"
    assert got["principals"] == payload["principals"]
    assert got["last_block_scanned"] == 100


@requires_postgres
def test_db_module_find_fresh_misses_on_unknown_key(_clean_l2):
    h = db_cache.specs_fingerprint([_rely_spec()])
    assert db_cache.find_fresh(chain="ethereum", address="0x" + "FF" * 20, specs_hash=h) is None
