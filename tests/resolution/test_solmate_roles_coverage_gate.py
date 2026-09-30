"""Solmate ``canCall`` publishes ``exact`` only when its role events are proven through the evaluated block.

Real ``PostgresEventLogRepo`` and ``SolmateRolesAuthorityAdapter``; only ``eth_getLogs`` is stubbed. A cursor behind the
pin (always the case on Base under the old head-64 pin) is completed by a tail, or the result defers.
"""

from __future__ import annotations

from typing import Any

import pytest

from db.models import FIRST_INDEXED_BASIS_CREATION, IndexedEventCursor, IndexedEventLog
from services.resolution.adapters import CallFrame, EvaluationContext
from services.resolution.adapters.solmate_roles import (
    PUBLIC_CAPABILITY_UPDATED,
    ROLE_CAPABILITY_UPDATED,
    USER_ROLE_UPDATED,
    SolmateRolesAuthorityAdapter,
)
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from tests.conftest import requires_postgres
from tests.support.tail_wire import install_tail_wire, raw_log
from utils.evm import CANCALL_SIGNATURE

pytestmark = requires_postgres

AUTHORITY = "0x3994741a5b29c60d0ab318de1024f9256fe959dc"
TARGET = "0x00000000000000000000000000000000000fee11"
SELECTOR = "0x8456cb59"
ALICE = "0x000000000000000000000000000000000000a11c"
BOB = "0x0000000000000000000000000000000000000b0b"
ROLE = 3
CURSOR = 1_000
PIN = 1_050


def _word(value: int) -> str:
    return "0x" + format(value, "064x")


def _addr(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


def _capability(enabled: bool) -> tuple[list[str], list[str]]:
    return [ROLE_CAPABILITY_UPDATED, _word(ROLE), _addr(TARGET), SELECTOR + "0" * 56], [_word(int(enabled))]


def _user_role(user: str, enabled: bool) -> tuple[list[str], list[str]]:
    return [USER_ROLE_UPDATED, _addr(user), _word(ROLE)], [_word(int(enabled))]


def _public(enabled: bool) -> tuple[list[str], list[str]]:
    return [PUBLIC_CAPABILITY_UPDATED, _addr(TARGET), SELECTOR + "0" * 56], [_word(int(enabled))]


def _seed(session, chain_id: int, events: list[tuple[tuple[list[str], list[str]], int]]) -> None:
    for topic0 in (ROLE_CAPABILITY_UPDATED, PUBLIC_CAPABILITY_UPDATED, USER_ROLE_UPDATED):
        session.add(
            IndexedEventCursor(
                chain_id=chain_id,
                event_address=AUTHORITY,
                topic0=topic0,
                last_indexed_block=CURSOR,
                backfill_complete=True,
                first_indexed_block=0,
                first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
            )
        )
    for i, ((topics, data_words), block) in enumerate(events):
        session.add(
            IndexedEventLog(
                chain_id=chain_id,
                event_address=AUTHORITY,
                topic0=topics[0],
                tx_hash=(block * 100 + i).to_bytes(32, "big"),
                log_index=i,
                block_number=block,
                block_hash=block.to_bytes(32, "big"),
                transaction_index=0,
                topics=topics,
                data_words=data_words,
            )
        )
    session.flush()


def _tail(events: list[tuple[tuple[list[str], list[str]], int]]) -> list[dict[str, Any]]:
    return [
        raw_log(AUTHORITY, topics, block, data_words=data, log_index=i)
        for i, ((topics, data), block) in enumerate(events)
    ]


def _ctx(session, chain_id: int, *, block: int | None = PIN, rpc_url: str | None = "http://tail.stub"):
    return EvaluationContext(
        chain_id=chain_id,
        contract_address=TARGET,
        block=block,
        rpc_url=rpc_url,
        event_log_repo=PostgresEventLogRepo(session),
        state_var_values={"authority": AUTHORITY},
        call_frame=CallFrame.root(contract_address=TARGET, function_signature=None, function_selector=SELECTOR),
        meta={"live_read_memo": {}},
    )


_DESCRIPTOR = {
    "kind": "external_set",
    "callee_signature": CANCALL_SIGNATURE,
    "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "authority"}},
}
_DURABLE = [(_capability(True), 100), (_user_role(ALICE, True), 200)]
_GRANT_AND_REVOKE_PAST_CURSOR = [(_user_role(BOB, True), 1_020), (_user_role(ALICE, False), 1_030)]


@pytest.mark.parametrize("chain_id", [1, 8453])
def test_grant_and_revoke_past_the_cursor_are_reflected(db_session, monkeypatch, chain_id):
    _seed(db_session, chain_id, _DURABLE)
    wire = install_tail_wire(monkeypatch, _tail(_GRANT_AND_REVOKE_PAST_CURSOR))

    cap = SolmateRolesAuthorityAdapter().enumerate(_DESCRIPTOR, _ctx(db_session, chain_id))

    assert wire.calls == [(CURSOR + 1, PIN)]
    assert (cap.kind, cap.membership_quality, cap.members) == ("finite_set", "exact", [BOB])
    assert cap.last_indexed_block == PIN
    step = cap.trace[0]
    assert (step["scan_from_block"], step["scan_to_block"], step["floor_basis"]) == (
        CURSOR + 1,
        PIN,
        "durable_frontier_tail",
    )


@pytest.mark.parametrize(
    "block, rpc_url, fail",
    [(PIN, "http://tail.stub", True), (PIN, None, False), (None, "http://tail.stub", False)],
    ids=["tail_failed", "no_rpc", "unpinned"],
)
def test_behind_cursor_defers_instead_of_publishing_exact(db_session, monkeypatch, block, rpc_url, fail):
    _seed(db_session, 8453, _DURABLE)
    install_tail_wire(monkeypatch, _tail(_GRANT_AND_REVOKE_PAST_CURSOR), fail=fail)

    cap = SolmateRolesAuthorityAdapter().enumerate(_DESCRIPTOR, _ctx(db_session, 8453, block=block, rpc_url=rpc_url))

    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra["basis"] == ["cursor_behind_block"]
    assert cap.check.extra["deferred_pending_index"] is True


def test_covered_cursor_needs_no_tail(db_session, monkeypatch):
    _seed(db_session, 1, _DURABLE)
    wire = install_tail_wire(monkeypatch, fail=True)

    cap = SolmateRolesAuthorityAdapter().enumerate(_DESCRIPTOR, _ctx(db_session, 1, block=CURSOR))

    assert wire.calls == []
    assert (cap.kind, cap.membership_quality, cap.members) == ("finite_set", "exact", [ALICE])
    assert cap.last_indexed_block == CURSOR


def test_public_capability_revoked_past_the_cursor_is_not_published_public(db_session, monkeypatch):
    _seed(db_session, 1, [*_DURABLE, (_public(True), 300)])
    install_tail_wire(monkeypatch, _tail([(_public(False), 1_040)]))

    cap = SolmateRolesAuthorityAdapter().enumerate(_DESCRIPTOR, _ctx(db_session, 1))

    assert (cap.kind, cap.members) == ("finite_set", [ALICE])


def test_public_capability_on_a_behind_cursor_defers_without_a_tail(db_session, monkeypatch):
    _seed(db_session, 1, [*_DURABLE, (_public(True), 300)])
    install_tail_wire(monkeypatch, fail=True)

    cap = SolmateRolesAuthorityAdapter().enumerate(_DESCRIPTOR, _ctx(db_session, 1))

    assert cap.kind == "external_check_only"
