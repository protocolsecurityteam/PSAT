
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from services.resolution.adapters import (
    EnumerationResult,
    EvaluationContext,
)
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo

ADDR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ADDR_C = "0xcccccccccccccccccccccccccccccccccccccccc"


class FakeEventLogRepo:
    def __init__(self, events_by_topic: dict[str, list[tuple[str, str]]]):
        self.events_by_topic = events_by_topic

    def fold_event_writes(
        self, *, chain_id, event_address, topic0, topics_to_keys, data_to_keys, key_sources, direction, block=None
    ):
        records = self.events_by_topic.get(topic0, [])
        members = [addr for d, addr in records if d == direction]
        return EnumerationResult(
            members=members,
            confidence="enumerable",
            last_indexed_block=18_000_000,
        )

    def fold_event_history(self, *, chain_id, event_address, event_hints, key_sources, block=None):
        state: dict[str, bool] = {}
        for hint in event_hints:
            direction = hint.get("direction")
            for event_direction, addr in self.events_by_topic.get(hint.get("topic0"), []):
                if event_direction == direction:
                    state[addr.lower()] = direction == "add"
        return EnumerationResult(
            members=sorted(addr for addr, present in state.items() if present),
            confidence="enumerable",
            last_indexed_block=18_000_000,
        )


class NoCursorEventLogRepo:
    def fold_event_writes(
        self, *, chain_id, event_address, topic0, topics_to_keys, data_to_keys, key_sources, direction, block=None
    ):
        return EnumerationResult(members=[], confidence="partial", partial_reason="no_index_cursor")


class RaisingEventLogRepo:
    def fold_event_writes(
        self, *, chain_id, event_address, topic0, topics_to_keys, data_to_keys, key_sources, direction, block=None
    ):
        del chain_id, event_address, topic0, topics_to_keys, data_to_keys, key_sources, direction, block
        raise RuntimeError("backend unavailable")

    def fold_event_history(self, *, chain_id, event_address, event_hints, key_sources, block=None):
        del chain_id, event_address, event_hints, key_sources, block
        raise RuntimeError("backend unavailable")


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self.rows


class FakeSession:
    def __init__(self, rows):
        self.rows = rows

    def execute(self, _query):
        return FakeScalarResult(self.rows)


def _address_topic(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def test_event_indexed_matches_with_add_event_hint():
    descriptor = {
        "kind": "mapping_membership",
        "enumeration_hint": [
            {"topic0": "0xaa", "direction": "add", "event_address": ADDR_A},
        ],
    }
    score = EventIndexedAdapter.matches(descriptor, EvaluationContext(chain_id=1))
    assert 0 < score <= 60  # low score so specialized adapters win


def test_event_indexed_does_not_match_without_hints():
    descriptor = {"kind": "mapping_membership"}
    assert EventIndexedAdapter.matches(descriptor, EvaluationContext(chain_id=1)) == 0


def test_event_indexed_enumerate_with_repo():
    descriptor = {
        "kind": "mapping_membership",
        "enumeration_hint": [
            {
                "topic0": "0xaa",
                "direction": "add",
                "event_address": ADDR_A,
                "topics_to_keys": {1: 0},
                "data_to_keys": {},
            },
        ],
    }
    repo = FakeEventLogRepo({"0xaa": [("add", ADDR_B), ("add", ADDR_C)]})
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=ADDR_A,
        meta={"event_log_repo": repo},
    )
    cap = EventIndexedAdapter().enumerate(descriptor, ctx)
    assert cap.kind == "finite_set"
    assert cap.members is not None
    assert sorted(cap.members) == sorted([ADDR_B.lower(), ADDR_C.lower()])


def test_postgres_event_repo_folds_add_remove_hints_in_log_order():
    rows = [
        SimpleNamespace(topic0="0xaa", topics=["0xaa", _address_topic(ADDR_B)], data_words=[]),
        SimpleNamespace(topic0="0xbb", topics=["0xbb", _address_topic(ADDR_B)], data_words=[]),
        SimpleNamespace(topic0="0xaa", topics=["0xaa", _address_topic(ADDR_B)], data_words=[]),
    ]
    repo = PostgresEventLogRepo(cast(Any, FakeSession(rows)))
    repo._cursor_state = lambda chain_id, event_address, topic0: (100, True)

    result = repo.fold_event_history(
        chain_id=1,
        event_address=ADDR_A,
        event_hints=[
            {"topic0": "0xaa", "direction": "add", "topics_to_keys": {1: 0}, "data_to_keys": {}},
            {"topic0": "0xbb", "direction": "remove", "topics_to_keys": {1: 0}, "data_to_keys": {}},
        ],
        key_sources=[{"source": "msg_sender"}],
        block=100,
    )

    assert result.confidence == "enumerable"
    assert result.members == [ADDR_B.lower()]


def test_event_indexed_no_backend_yields_check_only():
    descriptor = {
        "kind": "mapping_membership",
        "enumeration_hint": [
            {"topic0": "0xaa", "direction": "add", "event_address": ADDR_A, "topics_to_keys": {}, "data_to_keys": {}},
        ],
    }
    ctx = EvaluationContext(chain_id=1, contract_address=ADDR_A)
    cap = EventIndexedAdapter().enumerate(descriptor, ctx)
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra["topic0"] == "0xaa"


def test_event_indexed_backend_error_yields_check_only():
    descriptor = {
        "kind": "mapping_membership",
        "enumeration_hint": [
            {"topic0": "0xaa", "direction": "add", "event_address": ADDR_A, "topics_to_keys": {}, "data_to_keys": {}},
        ],
    }
    ctx = EvaluationContext(chain_id=1, contract_address=ADDR_A, meta={"event_log_repo": RaisingEventLogRepo()})
    cap = EventIndexedAdapter().enumerate(descriptor, ctx)

    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra["basis"] == ["event_log_backend_error"]


def test_event_indexed_caller_keyed_no_cursor_defers_pending_index():
    # A cold cursor defers (``deferred_pending_index``) instead of a live genesis scan; the caller-gate tag keeps
    # earned-public fail-closed.
    descriptor = {
        "kind": "mapping_membership",
        "key_sources": [{"source": "msg_sender"}],
        "enumeration_hint": [
            {"topic0": "0xaa", "direction": "add", "event_address": ADDR_A, "topics_to_keys": {1: 0}},
        ],
    }
    ctx = EvaluationContext(chain_id=1, contract_address=ADDR_A, meta={"event_log_repo": NoCursorEventLogRepo()})
    cap = EventIndexedAdapter().enumerate(descriptor, ctx)

    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra["basis"] == ["no_index_cursor", "caller_keyed_membership_allowlist"]
    assert cap.check.extra["deferred_pending_index"] is True
    assert cap.check.target_address == ADDR_A

    from services.resolution.permissionless_shapes import CALLER_GATE_BASIS_TAGS

    assert "caller_keyed_membership_allowlist" in CALLER_GATE_BASIS_TAGS


def test_event_indexed_non_caller_keyed_no_cursor_defers_without_caller_gate_tag():
    descriptor = {
        "kind": "mapping_membership",
        "key_sources": [{"source": "parameter", "parameter_index": 0}],
        "enumeration_hint": [
            {"topic0": "0xaa", "direction": "add", "event_address": ADDR_A, "topics_to_keys": {1: 0}},
        ],
    }
    ctx = EvaluationContext(chain_id=1, contract_address=ADDR_A, meta={"event_log_repo": NoCursorEventLogRepo()})
    cap = EventIndexedAdapter().enumerate(descriptor, ctx)

    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra["basis"] == ["no_index_cursor"]
    assert cap.check.extra["deferred_pending_index"] is True


def test_event_indexed_cold_cursor_performs_no_live_scan(monkeypatch):
    # A genesis scan is the 429-storm source.
    import services.resolution.mapping_enumerator as mapping_enumerator

    def boom(*_args, **_kwargs):
        raise AssertionError("cold cursor must defer, never live-scan")

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values_sync", boom)
    descriptor = {
        "kind": "mapping_membership",
        "key_sources": [{"source": "msg_sender"}],
        "enumeration_hint": [
            {"topic0": "0xaa", "direction": "add", "event_address": ADDR_A, "topics_to_keys": {1: 0}},
        ],
    }
    ctx = EvaluationContext(chain_id=1, contract_address=ADDR_A, meta={"event_log_repo": NoCursorEventLogRepo()})
    cap = EventIndexedAdapter().enumerate(descriptor, ctx)
    assert cap.kind == "external_check_only"


# G2 HIT 1: direction comes from the event payload, never hint order.

_CONFLICT_TOPIC = "0xf93f9a76c1bf3444d22400a00cb9fe990e6abe9dbb333fda48859cfee864543d"


def _bool_word(value: bool) -> str:
    return "0x" + ("1" if value else "0").rjust(64, "0")


def _conflict_rows():
    return [
        SimpleNamespace(
            topic0=_CONFLICT_TOPIC,
            topics=[_CONFLICT_TOPIC, _address_topic(ADDR_B)],
            data_words=[_bool_word(True)],
        ),
        SimpleNamespace(
            topic0=_CONFLICT_TOPIC,
            topics=[_CONFLICT_TOPIC, _address_topic(ADDR_C)],
            data_words=[_bool_word(True)],
        ),
        SimpleNamespace(
            topic0=_CONFLICT_TOPIC,
            topics=[_CONFLICT_TOPIC, _address_topic(ADDR_C)],
            data_words=[_bool_word(False)],
        ),
    ]


def _conflict_hints(value_position):
    base = {
        "topic0": _CONFLICT_TOPIC,
        "topics_to_keys": {1: 0},
        "data_to_keys": {},
        "indexed_positions": [0],
        "value_position": value_position,
    }
    return [dict(base, direction="add"), dict(base, direction="remove")]


def _run_conflict_fold(hints):
    repo = PostgresEventLogRepo(cast(Any, FakeSession(_conflict_rows())))
    repo._cursor_state = lambda chain_id, event_address, topic0: (100, True)
    return repo.fold_event_history(
        chain_id=1,
        event_address=ADDR_A,
        event_hints=hints,
        key_sources=[{"source": "msg_sender"}],
        block=100,
    )


def test_same_topic_conflict_folds_from_payload_not_hint_order():
    result = _run_conflict_fold(_conflict_hints(1))
    assert result.confidence == "enumerable"
    assert result.members == [ADDR_B.lower()]


def test_same_topic_conflict_is_hint_order_insensitive():
    forward = _run_conflict_fold(_conflict_hints(1))
    reversed_ = _run_conflict_fold(list(reversed(_conflict_hints(1))))
    assert forward.members == reversed_.members == [ADDR_B.lower()]
    assert forward.confidence == reversed_.confidence == "enumerable"


def test_same_topic_conflict_without_value_position_fails_closed():
    result = _run_conflict_fold(_conflict_hints(None))
    assert result.confidence == "partial"
    assert result.partial_reason == "ambiguous_event_direction"
    assert result.members == []


def test_same_topic_conflict_unreadable_payload_word_fails_closed():
    # The payload can't be read, so the fold must not decide membership.
    result = _run_conflict_fold(_conflict_hints(5))
    assert result.confidence == "partial"
    assert result.partial_reason == "ambiguous_event_direction"
    assert result.members == []


class AmbiguousEventLogRepo:
    def fold_event_history(self, *, chain_id, event_address, event_hints, key_sources, block=None):
        del chain_id, event_address, event_hints, key_sources, block
        return EnumerationResult(members=[], confidence="partial", partial_reason="ambiguous_event_direction")


def test_event_indexed_ambiguous_direction_settles_to_gated_check():
    descriptor = {
        "kind": "mapping_membership",
        "key_sources": [{"source": "msg_sender"}],
        "enumeration_hint": [
            {
                "topic0": _CONFLICT_TOPIC,
                "direction": "add",
                "event_address": ADDR_A,
                "topics_to_keys": {1: 0},
                "data_to_keys": {},
            },
            {
                "topic0": _CONFLICT_TOPIC,
                "direction": "remove",
                "event_address": ADDR_A,
                "topics_to_keys": {1: 0},
                "data_to_keys": {},
            },
        ],
    }
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=ADDR_A,
        meta={"event_log_repo": AmbiguousEventLogRepo()},
    )
    cap = EventIndexedAdapter().enumerate(descriptor, ctx)
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    basis = (cap.check.extra or {}).get("basis") or []
    assert "ambiguous_event_direction" in basis
    assert "caller_keyed_membership_allowlist" in basis
