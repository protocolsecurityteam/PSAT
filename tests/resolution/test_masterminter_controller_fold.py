"""USDC MasterMinter ``onlyController`` (``controllers[msg.sender] != address(0)``) over the durable index.

The descriptor is the one the static stage emits for ``configureMinter(uint256)``; rows are real ``0xe982615d…`` logs.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

import services.resolution.mapping_enumerator as mapping_enumerator
from db.models import IndexedEventCursor, IndexedEventLog
from services.resolution.adapters import EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from tests.conftest import requires_postgres

pytestmark = requires_postgres

MASTER_MINTER = "0xe982615d461dd5cd06575bbea87624fda4e3de17"
CURSOR_BLOCK = 26078988
CONFIGURED_TOPIC0 = "0xa56687ff5096e83f6e2c673cda0b677f56bbfcdf5fe0555d5830c407ede193cb"
REMOVED_TOPIC0 = "0x33d83959be2573f5453b12eb9d43b3499bc57d96bd2f067ba44803c859e81113"

CONTROLLER_A = "0x79e0946e1c186e745f1352d7c21ab04700c99f71"
WORKER_A = "0x5b6122c109b78c6755486966148c1d70a50a47d7"
CONTROLLER_B = "0x1238060eedff5cbc9929f53dfee5c986f52b27f3"
WORKER_B = "0xa669f564133a1612dbd6f5e579863aa0a34448bd"
REMOVED_CONTROLLER = "0x961708aa6bc3b79dff302f3f1525ed1bebc6f35b"
REMOVED_WORKER = "0xa1e2481a9cd0cb0447eeb1cbc26f1b3fff3bec20"


def _word(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


def _log(topic0: str, args: list[str], *, block: int, tx_index: int, log_index: int) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=1,
        event_address=MASTER_MINTER,
        topic0=topic0,
        tx_hash=block.to_bytes(8, "big").rjust(32, b"\x00"),
        log_index=log_index,
        block_number=block,
        block_hash=block.to_bytes(8, "big").rjust(32, b"\x11"),
        transaction_index=tx_index,
        topics=[topic0, *(_word(a) for a in args)],
        data_words=[],
    )


def _cursor(topic0: str) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=1,
        event_address=MASTER_MINTER,
        topic0=topic0,
        last_indexed_block=CURSOR_BLOCK,
        backfill_complete=True,
        first_indexed_block=0,
        first_indexed_block_basis="creation_block_minus_one",
    )


_DESCRIPTOR: dict[str, Any] = {
    "kind": "mapping_membership",
    "key_sources": [{"source": "msg_sender"}],
    "truthy_value": "0",
    "value_predicate": {"op": "ne", "rhs_values": ["0"], "value_type": "address"},
    "storage_var": "controllers",
    "enumeration_hint": [
        {
            "topic0": CONFIGURED_TOPIC0,
            "topics_to_keys": {"1": 0},
            "data_to_keys": {},
            "direction": "set",
            "event_signature": "ControllerConfigured(address,address)",
            "event_name": "ControllerConfigured",
            "mapping_name": "controllers",
            "key_position": 0,
            "indexed_positions": [0, 1],
            "value_position": 1,
            "writer_function": "configureController(address,address)",
        },
        {
            "topic0": REMOVED_TOPIC0,
            "topics_to_keys": {"1": 0},
            "data_to_keys": {},
            "direction": "remove",
            "event_signature": "ControllerRemoved(address)",
            "event_name": "ControllerRemoved",
            "mapping_name": "controllers",
            "key_position": 0,
            "indexed_positions": [0],
            "value_position": None,
            "writer_function": "removeController(address)",
        },
    ],
}


@pytest.fixture
def no_live_calls(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values_sync", lambda *a, **k: calls.append((a, k)) or {})
    return calls


@pytest.fixture
def ctx(db_session) -> EvaluationContext:
    for topic0 in (CONFIGURED_TOPIC0, REMOVED_TOPIC0):
        db_session.add(_cursor(topic0))
    for row in (
        _log(CONFIGURED_TOPIC0, [CONTROLLER_A, WORKER_A], block=7933088, tx_index=1, log_index=0),
        _log(CONFIGURED_TOPIC0, [REMOVED_CONTROLLER, REMOVED_WORKER], block=22427099, tx_index=0, log_index=0),
        _log(REMOVED_TOPIC0, [REMOVED_CONTROLLER], block=22427216, tx_index=0, log_index=0),
        _log(CONFIGURED_TOPIC0, [CONTROLLER_B, WORKER_B], block=26078370, tx_index=0, log_index=0),
    ):
        db_session.add(row)
    db_session.flush()
    return EvaluationContext(
        chain_id=1,
        contract_address=MASTER_MINTER,
        block=CURSOR_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )


def test_controllers_are_enumerated_and_removed_ones_dropped(ctx, no_live_calls):
    cap = EventIndexedAdapter().enumerate(copy.deepcopy(_DESCRIPTOR), ctx)

    assert cap.kind == "finite_set"
    assert cap.membership_quality == "exact"
    assert sorted(cap.members or []) == sorted([CONTROLLER_A, CONTROLLER_B])
    assert no_live_calls == []


def test_unparseable_rhs_is_not_determined_not_an_empty_set(ctx, no_live_calls):
    descriptor = copy.deepcopy(_DESCRIPTOR)
    descriptor["value_predicate"]["rhs_values"] = ["NO_CONTROLLER"]

    cap = EventIndexedAdapter().enumerate(descriptor, ctx)

    assert cap.kind == "unsupported"
    assert cap.unsupported_reason == "value_predicate_not_evaluable"
    assert no_live_calls == []


def test_writer_whose_value_is_not_in_its_event_is_not_determined(ctx, no_live_calls):
    # Artifacts built before ``address(0)`` writes were read as removals carry this hint shape.
    descriptor = copy.deepcopy(_DESCRIPTOR)
    descriptor["enumeration_hint"][1]["direction"] = "set"

    cap = EventIndexedAdapter().enumerate(descriptor, ctx)

    assert cap.kind == "unsupported"
    assert cap.unsupported_reason == "value_writer_event_unfoldable"
    assert no_live_calls == []


def test_row_missing_its_value_word_is_undecodable_not_skipped(ctx, db_session, no_live_calls):
    # A later write the fold can't read would otherwise leave the key's earlier value standing.
    db_session.add(_log(CONFIGURED_TOPIC0, [CONTROLLER_A], block=26078900, tx_index=0, log_index=0))
    db_session.flush()

    cap = EventIndexedAdapter().enumerate(copy.deepcopy(_DESCRIPTOR), ctx)

    assert cap.kind == "unsupported"
    assert cap.unsupported_reason == "event_data_undecodable"
    assert no_live_calls == []
