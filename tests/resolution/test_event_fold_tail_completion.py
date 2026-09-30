"""A warm durable fold behind the evaluated block is completed by a live tail over ``(warm_block, pin]``.

Real ``PostgresEventLogRepo`` and ``EventIndexedAdapter``; only ``eth_getLogs`` is stubbed. A complete tail makes the
merged fold exact; without one, value folds and add/remove folds fail closed to ``unsupported``, and nothing ever falls
back to a full live re-scan.
"""

from __future__ import annotations

from typing import Any

import pytest

import services.resolution.mapping_enumerator as mapping_enumerator
from db.models import FIRST_INDEXED_BASIS_CREATION, IndexedEventCursor, IndexedEventLog
from services.resolution.adapters import EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.event_tail import TAIL_MAX_SPAN, scan_event_tail, tail_scanner_for
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from tests.conftest import requires_postgres
from tests.support.tail_wire import install_tail_wire, raw_log

pytestmark = requires_postgres

CHAIN_ID = 1
ADDR = "0x00000000000000000000000000000000000c0de1"
TOPIC_ADD = "0x" + "a1" * 32
TOPIC_REMOVE = "0x" + "a2" * 32
TOPIC_SET = "0x" + "a3" * 32
ALICE = "0x000000000000000000000000000000000000a11c"
BOB = "0x0000000000000000000000000000000000000b0b"
CAROL = "0x000000000000000000000000000000000000ca01"
PIN = 1_050
RPC = "http://tail.stub"


def _word(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _flag(value: int) -> str:
    return "0x" + format(value, "064x")


class _Event:
    """One chain event, as both an indexed row and a raw ``eth_getLogs`` entry."""

    def __init__(self, topic0: str, who: str, block: int, *, value: int | None = None, log_index: int = 0) -> None:
        self.topic0 = topic0
        self.topics = [topic0, _word(who)]
        self.data_words = [_flag(value)] if value is not None else []
        self.block = block
        self.log_index = log_index

    def row(self) -> IndexedEventLog:
        raw = self.raw()
        return IndexedEventLog(
            chain_id=CHAIN_ID,
            event_address=ADDR,
            topic0=self.topic0,
            tx_hash=bytes.fromhex(raw["transactionHash"][2:]),
            log_index=self.log_index,
            block_number=self.block,
            block_hash=bytes.fromhex(raw["blockHash"][2:]),
            transaction_index=0,
            topics=self.topics,
            data_words=self.data_words,
        )

    def raw(self) -> dict[str, Any]:
        return raw_log(ADDR, self.topics, self.block, data_words=self.data_words, log_index=self.log_index)


def _cursor(topic0: str, last: int) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=CHAIN_ID,
        event_address=ADDR,
        topic0=topic0,
        last_indexed_block=last,
        backfill_complete=True,
        first_indexed_block=0,
        first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
    )


def _index(session, cursors: dict[str, int], chain: list[_Event]) -> None:
    """Seed each topic's cursor and the chain events it has indexed (at or below its frontier)."""
    for topic0, last in cursors.items():
        session.add(_cursor(topic0, last))
    for event in chain:
        if event.block <= cursors.get(event.topic0, -1):
            session.add(event.row())
    session.flush()


def _ctx(session, *, block: int | None = PIN, rpc_url: str | None = RPC) -> EvaluationContext:
    return EvaluationContext(
        chain_id=CHAIN_ID,
        contract_address=ADDR,
        block=block,
        rpc_url=rpc_url,
        event_log_repo=PostgresEventLogRepo(session),
        session=session,
        meta={"live_read_memo": {}},
    )


_KEY_SOURCES = [{"source": "msg_sender"}]
_HISTORY_HINTS = [
    {"topic0": TOPIC_ADD, "direction": "add", "event_address": ADDR, "topics_to_keys": {1: 0}, "data_to_keys": {}},
    {
        "topic0": TOPIC_REMOVE,
        "direction": "remove",
        "event_address": ADDR,
        "topics_to_keys": {1: 0},
        "data_to_keys": {},
    },
]
_SET_HINT = {
    "topic0": TOPIC_SET,
    "direction": "set",
    "event_address": ADDR,
    "topics_to_keys": {1: 0},
    "data_to_keys": {},
    "indexed_positions": [0],
    "value_position": 1,
    "event_signature": "AllowedSet(address,uint256)",
    "event_name": "AllowedSet",
    "mapping_name": "allowed",
}


def _history_descriptor(hints: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"kind": "mapping_membership", "key_sources": _KEY_SOURCES, "enumeration_hint": hints or _HISTORY_HINTS}


def _value_descriptor() -> dict[str, Any]:
    return {
        "kind": "mapping_membership",
        "storage_var": "allowed",
        "key_sources": _KEY_SOURCES,
        "enumeration_hint": [_SET_HINT],
    }


@pytest.fixture()
def no_live_scan(monkeypatch):
    def _forbidden(*_a, **_k):
        raise AssertionError("a lagging durable fold must never fall back to a full live scan")

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values_sync", _forbidden)


# -- add/remove fold -------------------------------------------------------------------------------------------------

_HISTORY_CHAIN = [
    _Event(TOPIC_ADD, ALICE, 900),
    _Event(TOPIC_ADD, CAROL, 950),
    _Event(TOPIC_REMOVE, ALICE, 1_030),  # in (frontier, pin]
    _Event(TOPIC_ADD, BOB, 1_040),
]


def test_history_fold_behind_completes_with_a_tail(db_session, monkeypatch):
    _index(db_session, {TOPIC_ADD: 1_000, TOPIC_REMOVE: 1_000}, _HISTORY_CHAIN)
    wire = install_tail_wire(monkeypatch, [e.raw() for e in _HISTORY_CHAIN])

    cap = EventIndexedAdapter().enumerate(_history_descriptor(), _ctx(db_session))

    assert wire.calls == [(1_001, PIN)]
    assert cap.kind == "finite_set"
    assert (cap.membership_quality, cap.members) == ("exact", sorted([BOB, CAROL]))
    assert cap.last_indexed_block == PIN
    assert cap.trace == [
        {
            "step": "event_fold_tail",
            "event_address": ADDR,
            "scan_from_block": 1_001,
            "scan_to_block": PIN,
            "floor_basis": "durable_frontier_tail",
        }
    ]


@pytest.mark.parametrize("block, rpc_url, fail", [(PIN, RPC, True), (PIN, None, False), (None, RPC, False)])
def test_removal_past_the_frontier_never_survives_in_a_bound(db_session, monkeypatch, block, rpc_url, fail):
    """Tail failed, no RPC, or no pin: ALICE's revocation at 1030 is unproven, so no set containing her is published."""
    _index(db_session, {TOPIC_ADD: 1_000, TOPIC_REMOVE: 1_000}, _HISTORY_CHAIN)
    install_tail_wire(monkeypatch, [e.raw() for e in _HISTORY_CHAIN], fail=fail)

    cap = EventIndexedAdapter().enumerate(_history_descriptor(), _ctx(db_session, block=block, rpc_url=rpc_url))

    assert cap.kind == "unsupported"
    assert cap.unsupported_reason == "event_fold_tail_unavailable"


def test_add_only_fold_behind_without_a_tail_stays_a_lower_bound(db_session, monkeypatch):
    add_only = [_HISTORY_HINTS[0]]
    _index(db_session, {TOPIC_ADD: 1_000}, _HISTORY_CHAIN)
    install_tail_wire(monkeypatch, fail=True)

    cap = EventIndexedAdapter().enumerate(_history_descriptor(add_only), _ctx(db_session))

    assert (cap.kind, cap.membership_quality) == ("finite_set", "lower_bound")
    assert cap.members == sorted([ALICE, CAROL])


def test_staggered_cursors_plus_tail_equal_one_full_fold(db_session, monkeypatch):
    chain = [
        _Event(TOPIC_ADD, ALICE, 900),
        _Event(TOPIC_REMOVE, ALICE, 1_010),  # indexed only by the more advanced remove cursor
        _Event(TOPIC_ADD, ALICE, 1_015),
        _Event(TOPIC_ADD, BOB, 1_016),
        _Event(TOPIC_REMOVE, BOB, 1_018),
        _Event(TOPIC_REMOVE, CAROL, 1_045),
        _Event(TOPIC_ADD, CAROL, 1_046),
    ]
    install_tail_wire(monkeypatch, [e.raw() for e in chain])
    _index(db_session, {TOPIC_ADD: 1_000, TOPIC_REMOVE: 1_020}, chain)
    repo = PostgresEventLogRepo(db_session)
    staggered = repo.fold_event_history(
        chain_id=CHAIN_ID,
        event_address=ADDR,
        event_hints=_HISTORY_HINTS,
        key_sources=_KEY_SOURCES,
        block=PIN,
        tail=tail_scanner_for(_ctx(db_session)),
    )
    db_session.rollback()

    _index(db_session, {TOPIC_ADD: PIN, TOPIC_REMOVE: PIN}, chain)
    full = PostgresEventLogRepo(db_session).fold_event_history(
        chain_id=CHAIN_ID, event_address=ADDR, event_hints=_HISTORY_HINTS, key_sources=_KEY_SOURCES, block=PIN
    )

    assert (
        (staggered.confidence, staggered.members) == (full.confidence, full.members) == ("enumerable", [ALICE, CAROL])
    )


def test_behind_fold_cuts_durable_rows_at_the_least_advanced_cursor(db_session):
    """Without a tail, rows past the least advanced cursor are not folded: the tail would replay them."""
    chain = [_Event(TOPIC_ADD, ALICE, 900), _Event(TOPIC_REMOVE, ALICE, 1_010)]
    _index(db_session, {TOPIC_ADD: 1_000, TOPIC_REMOVE: 1_020}, chain)
    result = PostgresEventLogRepo(db_session).fold_event_history(
        chain_id=CHAIN_ID, event_address=ADDR, event_hints=_HISTORY_HINTS, key_sources=_KEY_SOURCES, block=PIN
    )
    assert (result.confidence, result.partial_reason, result.last_indexed_block) == (
        "partial",
        "cursor_behind_block",
        1_000,
    )
    assert result.members == [ALICE]


# -- latest-value fold -----------------------------------------------------------------------------------------------

_VALUE_CHAIN = [
    _Event(TOPIC_SET, ALICE, 900, value=1),
    _Event(TOPIC_SET, CAROL, 950, value=1),
    _Event(TOPIC_SET, ALICE, 1_030, value=0),
    _Event(TOPIC_SET, BOB, 1_040, value=1),
]


def test_lagging_value_fold_plus_tail_is_exact(db_session, monkeypatch, no_live_scan):
    _index(db_session, {TOPIC_SET: 1_000}, _VALUE_CHAIN)
    wire = install_tail_wire(monkeypatch, [e.raw() for e in _VALUE_CHAIN])

    cap = EventIndexedAdapter().enumerate(_value_descriptor(), _ctx(db_session))

    assert wire.calls == [(1_001, PIN)]
    assert (cap.kind, cap.membership_quality) == ("finite_set", "exact")
    assert cap.members == sorted([BOB, CAROL])
    assert cap.trace[0]["floor_basis"] == "durable_frontier_tail"
    assert (cap.trace[0]["scan_from_block"], cap.trace[0]["scan_to_block"]) == (1_001, PIN)


@pytest.mark.parametrize("block, rpc_url, fail", [(PIN, RPC, True), (PIN, None, False), (None, RPC, False)])
def test_value_fold_behind_never_takes_the_live_scan(db_session, monkeypatch, no_live_scan, block, rpc_url, fail):
    _index(db_session, {TOPIC_SET: 1_000}, _VALUE_CHAIN)
    install_tail_wire(monkeypatch, [e.raw() for e in _VALUE_CHAIN], fail=fail)

    cap = EventIndexedAdapter().enumerate(_value_descriptor(), _ctx(db_session, block=block, rpc_url=rpc_url))

    assert cap.kind == "unsupported"
    assert cap.unsupported_reason == "event_fold_tail_unavailable"


def test_value_fold_repo_returns_durable_entries_cut_at_the_frontier(db_session):
    _index(db_session, {TOPIC_SET: 1_000}, _VALUE_CHAIN)
    result = PostgresEventLogRepo(db_session).fold_event_values(
        chain_id=CHAIN_ID,
        event_address=ADDR,
        value_hints=[_SET_HINT],
        key_sources=_KEY_SOURCES,
        fold_key_position=0,
        block=PIN,
    )
    assert (result.complete, result.partial_reason, result.last_indexed_block) == (False, "cursor_behind_block", 1_000)
    assert sorted(e["key"] for e in result.entries) == sorted([ALICE, CAROL])


def test_staggered_value_cursors_plus_tail_equal_one_full_fold(db_session, monkeypatch):
    topic_other = "0x" + "a4" * 32
    other_hint = dict(_SET_HINT, topic0=topic_other)
    chain = [
        _Event(TOPIC_SET, ALICE, 900, value=1),
        _Event(topic_other, ALICE, 1_010, value=0),  # indexed only by the more advanced cursor
        _Event(TOPIC_SET, ALICE, 1_012, value=7),
        _Event(topic_other, BOB, 1_030, value=3),
    ]
    install_tail_wire(monkeypatch, [e.raw() for e in chain])

    def _fold(tail):
        return PostgresEventLogRepo(db_session).fold_event_values(
            chain_id=CHAIN_ID,
            event_address=ADDR,
            value_hints=[_SET_HINT, other_hint],
            key_sources=_KEY_SOURCES,
            fold_key_position=0,
            block=PIN,
            **({"tail": tail} if tail else {}),
        )

    _index(db_session, {TOPIC_SET: 1_000, topic_other: 1_020}, chain)
    staggered = _fold(tail_scanner_for(_ctx(db_session)))
    db_session.rollback()
    _index(db_session, {TOPIC_SET: PIN, topic_other: PIN}, chain)
    full = _fold(None)

    def _values(result):
        return sorted((e["key"], e["value_hex"], e["last_block"]) for e in result.entries)

    assert staggered.complete and full.complete
    assert _values(staggered) == _values(full)
    assert dict((k, v) for k, v, _ in _values(full)) == {ALICE: _flag(7), BOB: _flag(3)}


# -- single-topic write fold -----------------------------------------------------------------------------------------


def test_write_fold_behind_completes_with_a_tail_or_reports_the_failure(db_session, monkeypatch):
    _index(db_session, {TOPIC_ADD: 1_000}, _HISTORY_CHAIN)
    repo = PostgresEventLogRepo(db_session)

    def _writes(tail):
        return repo.fold_event_writes(
            chain_id=CHAIN_ID,
            event_address=ADDR,
            topic0=TOPIC_ADD,
            topics_to_keys={1: 0},
            data_to_keys={},
            key_sources=_KEY_SOURCES,
            direction="add",
            block=PIN,
            tail=tail,
        )

    install_tail_wire(monkeypatch, [e.raw() for e in _HISTORY_CHAIN])
    done = _writes(tail_scanner_for(_ctx(db_session)))
    assert (done.confidence, done.members, done.last_indexed_block) == ("enumerable", sorted([ALICE, BOB, CAROL]), PIN)
    assert done.scan_window == {"scan_from_block": 1_001, "scan_to_block": PIN, "floor_basis": "durable_frontier_tail"}

    install_tail_wire(monkeypatch, fail=True)
    failed = _writes(tail_scanner_for(_ctx(db_session)))
    assert (failed.confidence, failed.partial_reason, failed.last_indexed_block) == (
        "partial",
        "tail_scan_failed",
        1_000,
    )


# -- the tail scan itself --------------------------------------------------------------------------------------------


def test_tail_rejects_a_malformed_log(monkeypatch):
    bad = raw_log(ADDR, [TOPIC_ADD, _word(ALICE)], 1_020)
    bad["data"] = "0x1234"  # not word-aligned
    install_tail_wire(monkeypatch, [bad])
    scan = scan_event_tail(rpc_url=RPC, chain_id=1, event_address=ADDR, topic0s=[TOPIC_ADD], frontier=1_000, block=PIN)
    assert (scan.complete, scan.reason) == (False, "tail_scan_failed")


def test_tail_refuses_a_stalled_span_without_a_request(monkeypatch):
    wire = install_tail_wire(monkeypatch)
    scan = scan_event_tail(
        rpc_url=RPC, chain_id=1, event_address=ADDR, topic0s=[TOPIC_ADD], frontier=0, block=TAIL_MAX_SPAN + 1
    )
    assert (scan.complete, scan.reason, wire.calls) == (False, "tail_span_exceeded", [])


def test_tail_with_nothing_to_scan_is_complete_without_a_request(monkeypatch):
    wire = install_tail_wire(monkeypatch)
    scan = scan_event_tail(rpc_url=RPC, chain_id=1, event_address=ADDR, topic0s=[TOPIC_ADD], frontier=PIN, block=PIN)
    assert (scan.complete, scan.logs, wire.calls) == (True, (), [])


def test_tail_scanner_memoizes_only_complete_scans(monkeypatch):
    ctx = EvaluationContext(chain_id=1, rpc_url=RPC, block=PIN, meta={"live_read_memo": {}})
    wire = install_tail_wire(monkeypatch, fail=True)
    scanner = tail_scanner_for(ctx)
    assert scanner is not None
    assert not scanner(ADDR, [TOPIC_ADD], 1_000, PIN).complete
    wire.fail = False
    assert scanner(ADDR, [TOPIC_ADD], 1_000, PIN).complete
    assert scanner(ADDR, [TOPIC_ADD], 1_000, PIN).complete
    assert len(wire.calls) == 2


def test_no_scanner_without_rpc_or_pin():
    assert tail_scanner_for(EvaluationContext(chain_id=1, rpc_url=None, block=PIN)) is None
    assert tail_scanner_for(EvaluationContext(chain_id=1, rpc_url=RPC, block=None)) is None


def test_rows_past_the_pin_on_an_advanced_cursor_are_not_folded(db_session, monkeypatch):
    """The more advanced cursor holds a grant past the pin; a single full fold at the pin never sees it."""
    dave = "0x000000000000000000000000000000000000da7e"
    chain = [
        _Event(TOPIC_ADD, ALICE, 900),
        _Event(TOPIC_REMOVE, ALICE, 1_010),
        _Event(TOPIC_ADD, dave, 1_080),
    ]
    install_tail_wire(monkeypatch, [e.raw() for e in chain])
    _index(db_session, {TOPIC_ADD: 1_100, TOPIC_REMOVE: 1_000}, chain)
    staggered = PostgresEventLogRepo(db_session).fold_event_history(
        chain_id=CHAIN_ID,
        event_address=ADDR,
        event_hints=_HISTORY_HINTS,
        key_sources=_KEY_SOURCES,
        block=PIN,
        tail=tail_scanner_for(_ctx(db_session)),
    )
    db_session.rollback()

    _index(db_session, {TOPIC_ADD: PIN, TOPIC_REMOVE: PIN}, chain)
    full = PostgresEventLogRepo(db_session).fold_event_history(
        chain_id=CHAIN_ID, event_address=ADDR, event_hints=_HISTORY_HINTS, key_sources=_KEY_SOURCES, block=PIN
    )

    assert (staggered.confidence, staggered.members) == (full.confidence, full.members) == ("enumerable", [])


def test_tail_page_at_the_result_cap_is_never_accepted_as_whole(monkeypatch):
    full_page = [
        raw_log(ADDR, [TOPIC_ADD, _word(ALICE)], 1_020, log_index=i, transaction_index=i) for i in range(10_000)
    ]
    install_tail_wire(monkeypatch, full_page)
    scan = scan_event_tail(rpc_url=RPC, chain_id=1, event_address=ADDR, topic0s=[TOPIC_ADD], frontier=1_000, block=PIN)
    # Scalars only: a failing assertion would otherwise render every log in the scan.
    complete, reason, returned = scan.complete, scan.reason, len(scan.logs)
    assert (complete, reason, returned) == (False, "tail_scan_failed", 0)
