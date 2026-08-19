"""Issue #119 regression suite — durable event-fold cursor coverage.

These tests fail on the unfixed source (the fold minted ``enumerable``/``exact``
gated only on ``backfill_complete``, never comparing the cursor to the evaluated
height) and pin the complete fix:

  * a warm cursor that does NOT cover the evaluated height (unpinned ``block=None``
    or ``block`` past the cursor) demotes to ``partial``/``cursor_behind_block`` →
    adapter ``finite_set(lower_bound)`` — NEVER a silent ``exact``;
  * a cursor that DOES cover the pinned finalized height stays ``enumerable``/exact;
  * the resolver's deterministic finality-margin pin
    (``_resolve_resolution_block`` = ``head - RESOLVER_FINALITY_MARGIN``) keeps a
    keeping-up cursor exact and demotes a stalled one;
  * the head pin can NOT strip an already-indexed denylist member: an address
    blocked in ``(pin, cursor]`` stays in the negated cofinite blacklist (gated),
    never reading PUBLIC (the round-2 fail-open the reviewer reproduced);
  * the HyperSync sibling demotes an unpinned ``to_block``.

Real ``psat_test`` Postgres + the production ``PostgresEventLogRepo`` /
``EventIndexedAdapter`` (no monkeypatched fold); only rows are seeded.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from db.models import IndexedEventCursor, IndexedEventLog
from services.resolution import capability_resolver
from services.resolution.adapters import EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.capabilities import negate
from services.resolution.capability_resolver import (
    RESOLVER_FINALITY_MARGIN,
    _resolve_resolution_block,
)
from services.resolution.repos.event_logs_hypersync import HyperSyncEventLogRepo
from services.resolution.repos.event_logs_pg import (
    PostgresEventLogRepo,
    _cursor_covers_block,
    _row_ceiling,
)
from tests.conftest import requires_postgres


# Pure-function units (no DB) for the two coverage helpers.
def test_cursor_covers_block_truth_table():
    assert _cursor_covers_block(1000, 990) is True
    assert _cursor_covers_block(1000, 1000) is True
    assert _cursor_covers_block(1000, 1001) is False
    assert _cursor_covers_block(1000, None) is False  # unpinned live head is never covered
    assert _cursor_covers_block(None, 990) is False  # no cursor


def test_row_ceiling_uses_frontier_not_pin():
    # The frontier (cursor) caps the row scan; the lower finality pin never does.
    assert _row_ceiling(1028, 976) == 1028  # pin 976 < frontier -> include up to frontier
    assert _row_ceiling(1028, 2000) == 1028  # pin above frontier -> still the frontier
    assert _row_ceiling(None, 976) == 976  # cold path: fall back to the requested block
    assert _row_ceiling(None, None) is None


pytestmark = requires_postgres

CHAIN_ID = 119_4242
EVENT_ADDRESS = "0x00000000000000000000000000000000c0ffee19"
# keccak256("RoleGranted(bytes32,address,address)")-shaped 32-byte topic stand-in.
TOPIC_ADD = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
TOPIC_REMOVE = "0x9d5d98f0a2f3f3a8d9c2c0b9a3f9b1d0e1c2b3a4958677889a9bbccddeeff0011"

ADMIN_A = "0x000000000000000000000000000000000000aaaa"  # granted @ 900
ADMIN_B = "0x000000000000000000000000000000000000bbbb"  # granted @ 950
DENIED = "0x000000000000000000000000000000000000dead"  # blocked @ 1010 (in (pin, cursor])


def _pad(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _grant_row(topic0: str, acct: str, block: int, log_index: int = 0) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=CHAIN_ID,
        event_address=EVENT_ADDRESS.lower(),
        topic0=topic0,
        tx_hash=(block * 1000 + log_index).to_bytes(32, "big"),
        log_index=log_index,
        block_number=block,
        block_hash=block.to_bytes(32, "big"),
        transaction_index=0,
        topics=[topic0, _pad(acct)],
        data_words=[],
    )


def _seed_cursor(session, *, last_indexed_block: int, topic0: str = TOPIC_ADD, complete: bool = True) -> None:
    session.add(
        IndexedEventCursor(
            chain_id=CHAIN_ID,
            event_address=EVENT_ADDRESS.lower(),
            topic0=topic0,
            last_indexed_block=last_indexed_block,
            backfill_complete=complete,
        )
    )


_KEY_SOURCES = [{"source": "msg_sender"}]
_TOPICS_TO_KEYS = {1: 0}


def _writes(repo: PostgresEventLogRepo, block: int | None, topic0: str = TOPIC_ADD):
    return repo.fold_event_writes(
        chain_id=CHAIN_ID,
        event_address=EVENT_ADDRESS,
        topic0=topic0,
        topics_to_keys=_TOPICS_TO_KEYS,
        data_to_keys={},
        key_sources=_KEY_SOURCES,
        direction="add",
        block=block,
    )


def _allowlist_descriptor() -> dict[str, Any]:
    return {
        "kind": "mapping_membership",
        "key_sources": _KEY_SOURCES,
        "enumeration_hint": [
            {
                "topic0": TOPIC_ADD,
                "direction": "add",
                "event_address": EVENT_ADDRESS,
                "topics_to_keys": _TOPICS_TO_KEYS,
                "data_to_keys": {},
            }
        ],
    }


# --------------------------------------------------------------------------- #
# 1. Fold demotion (the core correctness gate)                                #
# --------------------------------------------------------------------------- #


def test_fold_event_writes_demotes_unpinned_head_to_lower_bound(db_session):
    # Warm, backfill_complete cursor — pre-fix this minted enumerable/exact. An
    # unpinned block=None ("evaluate at live head") cannot be covered by a cursor
    # that structurally lags head, so the fold MUST demote.
    _seed_cursor(db_session, last_indexed_block=1000)
    db_session.add(_grant_row(TOPIC_ADD, ADMIN_A, 900))
    db_session.add(_grant_row(TOPIC_ADD, ADMIN_B, 950))
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)

    result = _writes(repo, block=None)
    assert result.confidence == "partial"
    assert result.partial_reason == "cursor_behind_block"
    # Members are still surfaced (lower_bound = "at least these"), never dropped.
    assert {m[-4:] for m in result.members} == {"aaaa", "bbbb"}


def test_fold_event_writes_demotes_block_past_cursor(db_session):
    _seed_cursor(db_session, last_indexed_block=1000)
    db_session.add(_grant_row(TOPIC_ADD, ADMIN_A, 900))
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)

    result = _writes(repo, block=1050)  # finalized pin ABOVE the stalled cursor
    assert result.confidence == "partial"
    assert result.partial_reason == "cursor_behind_block"


def test_fold_event_writes_covering_block_stays_exact(db_session):
    _seed_cursor(db_session, last_indexed_block=1000)
    db_session.add(_grant_row(TOPIC_ADD, ADMIN_A, 900))
    db_session.add(_grant_row(TOPIC_ADD, ADMIN_B, 950))
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)

    result = _writes(repo, block=990)  # cursor 1000 COVERS the finalized pin
    assert result.confidence == "enumerable"
    assert result.partial_reason is None
    assert {m[-4:] for m in result.members} == {"aaaa", "bbbb"}


def test_fold_event_values_demotes_unpinned_head(db_session):
    _seed_cursor(db_session, last_indexed_block=1000)
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)
    value_hints = [{"topic0": TOPIC_ADD, "topics_to_keys": _TOPICS_TO_KEYS, "data_to_keys": {}, "value_position": 1}]
    res_none = repo.fold_event_values(
        chain_id=CHAIN_ID,
        event_address=EVENT_ADDRESS,
        value_hints=value_hints,
        key_sources=_KEY_SOURCES,
        fold_key_position=None,
        block=None,
    )
    assert res_none.complete is False
    assert res_none.partial_reason == "cursor_behind_block"

    res_cov = repo.fold_event_values(
        chain_id=CHAIN_ID,
        event_address=EVENT_ADDRESS,
        value_hints=value_hints,
        key_sources=_KEY_SOURCES,
        fold_key_position=None,
        block=990,
    )
    assert res_cov.complete is True
    assert res_cov.partial_reason is None


# --------------------------------------------------------------------------- #
# 2. Adapter end-to-end: demotion → lower_bound, coverage → exact             #
# --------------------------------------------------------------------------- #


def test_adapter_unpinned_block_yields_lower_bound(db_session):
    _seed_cursor(db_session, last_indexed_block=1000)
    db_session.add(_grant_row(TOPIC_ADD, ADMIN_A, 900))
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)
    ctx = EvaluationContext(chain_id=CHAIN_ID, contract_address=EVENT_ADDRESS, block=None, event_log_repo=repo)

    cap = EventIndexedAdapter().enumerate(_allowlist_descriptor(), ctx)
    assert cap.kind == "finite_set"
    assert cap.membership_quality == "lower_bound"
    assert ADMIN_A.lower() in (cap.members or [])


def test_adapter_covering_pin_stays_exact(db_session):
    _seed_cursor(db_session, last_indexed_block=1000)
    db_session.add(_grant_row(TOPIC_ADD, ADMIN_A, 900))
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)
    ctx = EvaluationContext(chain_id=CHAIN_ID, contract_address=EVENT_ADDRESS, block=990, event_log_repo=repo)

    cap = EventIndexedAdapter().enumerate(_allowlist_descriptor(), ctx)
    assert cap.kind == "finite_set"
    assert cap.membership_quality == "exact"
    assert cap.members == [ADMIN_A.lower()]


# --------------------------------------------------------------------------- #
# 3. Round-2 headline: the head pin must NOT strip an indexed denylist member  #
# --------------------------------------------------------------------------- #


def test_recently_blocked_indexed_address_stays_in_blacklist_under_head_pin(db_session):
    # A ``falsy``/denylist leaf negates the event-indexed set into a cofinite
    # blacklist ("anyone EXCEPT the blocked set"). cursor=1028 (>= pin), DENIED was
    # blocked @1010 — already indexed, but inside (pin=976, cursor]. The finality
    # pin governs only the exact gate; it must NOT truncate the row scan, or DENIED
    # falls out of the EXACT blacklist and reads PUBLIC (fail-open). Pre-fix
    # (block<=pin row truncation) this returned an empty exact blacklist.
    head = 1040
    pin = head - RESOLVER_FINALITY_MARGIN  # 976
    cursor = 1028
    assert pin < 1010 < cursor  # DENIED indexed but above the finalized pin

    _seed_cursor(db_session, last_indexed_block=cursor)
    db_session.add(_grant_row(TOPIC_ADD, DENIED, 1010))
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)
    ctx = EvaluationContext(chain_id=CHAIN_ID, contract_address=EVENT_ADDRESS, block=pin, event_log_repo=repo)

    blocked_set = EventIndexedAdapter().enumerate(_allowlist_descriptor(), ctx)
    # The blocked set is exact (cursor covers the pin) AND retains the indexed member.
    assert blocked_set.kind == "finite_set"
    assert blocked_set.membership_quality == "exact"
    assert DENIED.lower() in (blocked_set.members or [])

    # negate() is exactly what predicate_evaluator applies to a falsy leaf.
    allowed = negate(blocked_set)
    assert allowed.kind == "cofinite_blacklist"
    assert DENIED.lower() in (allowed.blacklist or [])  # still excluded → gated, not public
    assert allowed.blacklist_quality == "exact"


# --------------------------------------------------------------------------- #
# 4. Resolver finality-margin pin                                             #
# --------------------------------------------------------------------------- #


def test_resolve_resolution_block_pins_head_minus_margin(monkeypatch):
    monkeypatch.setattr(capability_resolver, "rpc_request", lambda *a, **k: hex(5_000_000))
    pin = _resolve_resolution_block("http://rpc.example", None)
    assert pin == 5_000_000 - RESOLVER_FINALITY_MARGIN


def test_resolve_resolution_block_honours_explicit_block(monkeypatch):
    def _boom(*a, **k):  # explicit block must short-circuit before any RPC read
        raise AssertionError("rpc_request must not be called for an explicit block")

    monkeypatch.setattr(capability_resolver, "rpc_request", _boom)
    assert _resolve_resolution_block("http://rpc.example", 123) == 123


def test_resolve_resolution_block_none_without_rpc():
    assert _resolve_resolution_block(None, None) is None


def test_resolve_resolution_block_none_on_rpc_failure(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("node down")

    monkeypatch.setattr(capability_resolver, "rpc_request", _boom)
    assert _resolve_resolution_block("http://rpc.example", None) is None


@pytest.mark.parametrize(
    "cursor_block, stays_exact",
    [
        (5_000_000 - RESOLVER_FINALITY_MARGIN, True),  # keeping-up: cursor == pin
        (5_000_000 - 12, True),  # keeping-up: indexer depth shallower than margin
        (5_000_000 - RESOLVER_FINALITY_MARGIN - 1, False),  # stalled one block below the pin
        (4_000_000, False),  # badly stalled
    ],
)
def test_pin_keeps_keeping_up_cursor_exact_and_demotes_stalled(db_session, monkeypatch, cursor_block, stays_exact):
    monkeypatch.setattr(capability_resolver, "rpc_request", lambda *a, **k: hex(5_000_000))
    pin = _resolve_resolution_block("http://rpc.example", None)

    _seed_cursor(db_session, last_indexed_block=cursor_block)
    db_session.add(_grant_row(TOPIC_ADD, ADMIN_A, 1))
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)

    result = _writes(repo, block=pin)
    if stays_exact:
        assert result.confidence == "enumerable"
        assert result.partial_reason is None
    else:
        assert result.confidence == "partial"
        assert result.partial_reason == "cursor_behind_block"


# --------------------------------------------------------------------------- #
# 5. HyperSync sibling: unpinned to_block demotes (defense-in-depth)          #
# --------------------------------------------------------------------------- #


class _FakeResponse:
    next_block = None
    data = None
    logs: list[Any] = []


class _FakeClient:
    async def get(self, _query):
        return _FakeResponse()


@pytest.fixture
def _stub_hypersync(monkeypatch):
    monkeypatch.setattr(
        "services.resolution.hypersync_bound.build_hypersync_client",
        lambda *a, **k: _FakeClient(),
    )


def _hypersync_repo() -> HyperSyncEventLogRepo:
    return HyperSyncEventLogRepo(from_block=0, bearer_token="test-token")


def test_hypersync_fold_writes_unpinned_to_block_demotes(_stub_hypersync):
    repo = _hypersync_repo()
    result = asyncio.run(
        repo._fold_event_writes_async(
            event_address=EVENT_ADDRESS,
            topic0=TOPIC_ADD,
            topics_to_keys=_TOPICS_TO_KEYS,
            data_to_keys={},
            key_sources=_KEY_SOURCES,
            direction="add",
            to_block=None,
        )
    )
    assert result.confidence == "partial"
    assert result.partial_reason == "cursor_behind_block"


def test_hypersync_fold_history_unpinned_to_block_demotes(_stub_hypersync):
    repo = _hypersync_repo()
    result = asyncio.run(
        repo._fold_event_history_async(
            event_address=EVENT_ADDRESS,
            event_hints=[
                {"topic0": TOPIC_ADD, "direction": "add", "topics_to_keys": _TOPICS_TO_KEYS, "data_to_keys": {}}
            ],
            key_sources=_KEY_SOURCES,
            to_block=None,
        )
    )
    assert result.confidence == "partial"
    assert result.partial_reason == "cursor_behind_block"


def test_hypersync_fold_writes_pinned_to_block_stays_exact(_stub_hypersync):
    repo = _hypersync_repo()
    result = asyncio.run(
        repo._fold_event_writes_async(
            event_address=EVENT_ADDRESS,
            topic0=TOPIC_ADD,
            topics_to_keys=_TOPICS_TO_KEYS,
            data_to_keys={},
            key_sources=_KEY_SOURCES,
            direction="add",
            to_block=5_000_000,
        )
    )
    assert result.confidence == "enumerable"
    assert result.partial_reason is None
