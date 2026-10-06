"""Solmate ``RolesAuthority`` role events are folded once per authority per resolver pass, then answered per leaf.

Real ``PostgresEventLogRepo`` and ``SolmateRolesAuthorityAdapter``; only ``eth_getLogs`` is stubbed, and the retry arms
make one repo read fail.
"""

from __future__ import annotations

import random

import pytest

from db.models import FIRST_INDEXED_BASIS_CREATION, IndexedEventCursor, IndexedEventLog
from services.resolution.adapters import CallFrame, EvaluationContext
from services.resolution.adapters.solmate_roles import (
    PUBLIC_CAPABILITY_UPDATED,
    ROLE_CAPABILITY_UPDATED,
    USER_ROLE_UPDATED,
    SolmateRolesAuthorityAdapter,
)
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from tests.conftest import requires_postgres
from tests.support.tail_wire import install_tail_wire, raw_log
from utils.evm import CANCALL_SIGNATURE

pytestmark = requires_postgres

AUTHORITY = "0x3994741a5b29c60d0ab318de1024f9256fe959dc"
TARGETS = ["0x00000000000000000000000000000000000fee11", "0x00000000000000000000000000000000000fee22"]
SELECTORS = ["0x8456cb59", "0x3f4ba83a", "0xa9059cbb"]
USERS = [f"0x{i:040x}" for i in range(0xA1, 0xA6)]
ROLES = [1, 2, 3, 9]
CURSOR = 1_000
PIN = 1_050

_DESCRIPTOR = {
    "kind": "external_set",
    "callee_signature": CANCALL_SIGNATURE,
    "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "authority"}},
}


def _word(value: int) -> str:
    return "0x" + format(value, "064x")


def _addr(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


def _capability(role: int, target: str, selector: str, enabled: bool):
    return [ROLE_CAPABILITY_UPDATED, _word(role), _addr(target), selector + "0" * 56], [_word(int(enabled))]


def _public(target: str, selector: str, enabled: bool):
    return [PUBLIC_CAPABILITY_UPDATED, _addr(target), selector + "0" * 56], [_word(int(enabled))]


def _user_role(user: str, role: int, enabled: bool):
    return [USER_ROLE_UPDATED, _addr(user), _word(role)], [_word(int(enabled))]


def _tail_log(event, block: int):
    topics, data_words = event
    return raw_log(AUTHORITY, topics, block, data_words=data_words)


def _random_events(seed: int) -> list:
    rng = random.Random(seed)
    events = []
    for _ in range(160):
        pick = rng.random()
        enabled = rng.random() < 0.65
        if pick < 0.45:
            events.append(_capability(rng.choice(ROLES), rng.choice(TARGETS), rng.choice(SELECTORS), enabled))
        elif pick < 0.55:
            events.append(_public(rng.choice(TARGETS), rng.choice(SELECTORS), enabled))
        else:
            events.append(_user_role(rng.choice(USERS), rng.choice(ROLES), enabled))
    return events


def _seed(session, events, *, chain_id: int = 1, cursor: int | None = CURSOR, data_hex_at: int | None = None) -> None:
    if cursor is not None:
        for topic0 in (ROLE_CAPABILITY_UPDATED, PUBLIC_CAPABILITY_UPDATED, USER_ROLE_UPDATED):
            session.add(
                IndexedEventCursor(
                    chain_id=chain_id,
                    event_address=AUTHORITY,
                    topic0=topic0,
                    last_indexed_block=cursor,
                    backfill_complete=True,
                    first_indexed_block=0,
                    first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
                )
            )
    for i, (topics, data_words) in enumerate(events):
        block = 10 + i // 3
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
                data_words=None if i == data_hex_at else data_words,
                data_hex="0xdeadbeef" if i == data_hex_at else None,
            )
        )
    session.flush()


def _ctx(session, target: str, selector: str, states: dict | None, *, block: int = CURSOR) -> EvaluationContext:
    meta: dict = {"live_read_memo": {}}
    if states is not None:
        meta["solmate_role_states"] = states
    return EvaluationContext(
        chain_id=1,
        contract_address=target,
        block=block,
        rpc_url="http://tail.stub",
        event_log_repo=PostgresEventLogRepo(session),
        state_var_values={"authority": AUTHORITY},
        call_frame=CallFrame.root(contract_address=target, function_signature=None, function_selector=selector),
        meta=meta,
    )


def _reference(events, target: str, selector: str):
    """The per-leaf fold the adapter performed before folding was shared: ``(public, members)``."""
    roles: set[int] = set()
    public = False
    users: dict[int, set[str]] = {}
    for topics, data_words in events:
        enabled = int(data_words[0], 16) != 0
        if topics[0] == ROLE_CAPABILITY_UPDATED:
            if "0x" + topics[2][-40:] == target and topics[3][:10] == selector:
                roles.add(int(topics[1], 16)) if enabled else roles.discard(int(topics[1], 16))
        elif topics[0] == PUBLIC_CAPABILITY_UPDATED:
            if "0x" + topics[1][-40:] == target and topics[2][:10] == selector:
                public = enabled
        else:
            bucket = users.setdefault(int(topics[2], 16), set())
            bucket.add("0x" + topics[1][-40:]) if enabled else bucket.discard("0x" + topics[1][-40:])
    return public, sorted(set().union(*(users.get(r, set()) for r in roles)))


class _Reads:
    """Counts the repo's role-event reads while passing through to the real repository."""

    def __init__(self, monkeypatch, *, fail_first: str | None = None):
        self.rows = 0
        self.cursors = 0
        self._fail = fail_first
        rows, cursors = PostgresEventLogRepo.iter_event_rows, PostgresEventLogRepo.min_indexed_block
        reads = self

        def iter_event_rows(repo, **kwargs):
            reads.rows += 1
            if reads._fail == "rows":
                reads._fail = None
                raise RuntimeError("stubbed backend failure")
            return rows(repo, **kwargs)

        def min_indexed_block(repo, **kwargs):
            reads.cursors += 1
            if reads._fail == "cursor":
                reads._fail = None
                raise RuntimeError("stubbed cursor failure")
            return cursors(repo, **kwargs)

        monkeypatch.setattr(PostgresEventLogRepo, "iter_event_rows", iter_event_rows)
        monkeypatch.setattr(PostgresEventLogRepo, "min_indexed_block", min_indexed_block)


@pytest.mark.parametrize("seed", [1, 7, 42])
def test_one_fold_answers_every_target_and_selector_like_the_per_leaf_fold(db_session, monkeypatch, seed):
    events = _random_events(seed)
    _seed(db_session, events)
    reads = _Reads(monkeypatch)
    states: dict = {}
    adapter = SolmateRolesAuthorityAdapter()
    for _ in range(2):
        for target in TARGETS:
            for selector in SELECTORS:
                cap = adapter.enumerate(_DESCRIPTOR, _ctx(db_session, target, selector, states))
                public, members = _reference(events, target, selector)
                if public:
                    assert cap.kind == "conditional_universal"
                    continue
                assert (cap.kind, cap.membership_quality, cap.members) == ("finite_set", "exact", members)
                assert cap.last_indexed_block == CURSOR
    assert (reads.rows, reads.cursors) == (1, 1)
    assert list(states) == [(1, AUTHORITY, CURSOR)]


def test_shared_fold_publishes_exactly_what_an_unshared_fold_publishes(db_session, monkeypatch):
    _seed(db_session, _random_events(3))
    install_tail_wire(monkeypatch, [_tail_log(_user_role(USERS[0], 9, True), 1_040)])
    adapter = SolmateRolesAuthorityAdapter()
    states: dict = {}
    for block in (CURSOR, PIN):
        for target in TARGETS:
            for selector in SELECTORS:
                shared = adapter.enumerate(_DESCRIPTOR, _ctx(db_session, target, selector, states, block=block))
                alone = adapter.enumerate(_DESCRIPTOR, _ctx(db_session, target, selector, None, block=block))
                assert capability_to_dict(shared) == capability_to_dict(alone)
    assert sorted(states) == [(1, AUTHORITY, CURSOR), (1, AUTHORITY, PIN)]


@pytest.mark.parametrize(
    "events, cursor, data_hex_at, basis",
    [
        ([_capability(1, TARGETS[0], SELECTORS[0], True)], CURSOR, 0, "undecodable_event_data"),
        ([], CURSOR, None, "authority_unconfirmed_no_role_events"),
        ([_capability(1, TARGETS[0], SELECTORS[0], True)], None, None, "no_index_cursor"),
    ],
    ids=["undecodable", "no_role_events", "no_cursor"],
)
def test_settled_outcomes_are_read_once_per_pass(db_session, monkeypatch, events, cursor, data_hex_at, basis):
    _seed(db_session, events, cursor=cursor, data_hex_at=data_hex_at)
    reads = _Reads(monkeypatch)
    states: dict = {}
    for selector in SELECTORS:
        cap = SolmateRolesAuthorityAdapter().enumerate(_DESCRIPTOR, _ctx(db_session, TARGETS[0], selector, states))
        assert cap.kind == "external_check_only"
        assert cap.check is not None
        assert cap.check.extra["basis"] == [basis]
    assert reads.cursors == 1
    assert reads.rows == (0 if cursor is None else 1)


@pytest.mark.parametrize("fail", ["rows", "cursor"])
def test_backend_failures_are_retried_by_the_next_leaf(db_session, monkeypatch, fail):
    _seed(db_session, [_capability(1, TARGETS[0], SELECTORS[0], True), _user_role(USERS[0], 1, True)])
    _Reads(monkeypatch, fail_first=fail)
    states: dict = {}
    adapter = SolmateRolesAuthorityAdapter()

    failed = adapter.enumerate(_DESCRIPTOR, _ctx(db_session, TARGETS[0], SELECTORS[0], states))
    assert failed.check is not None
    assert failed.check.extra["basis"] == ["event_log_backend_error" if fail == "rows" else "no_index_cursor"]
    assert states == {}

    retried = adapter.enumerate(_DESCRIPTOR, _ctx(db_session, TARGETS[0], SELECTORS[0], states))
    assert (retried.kind, retried.members) == ("finite_set", [USERS[0]])


def test_an_incomplete_tail_is_retried_by_the_next_leaf(db_session, monkeypatch):
    _seed(db_session, [_capability(1, TARGETS[0], SELECTORS[0], True), _user_role(USERS[0], 1, True)])
    wire = install_tail_wire(monkeypatch, [_tail_log(_user_role(USERS[1], 1, True), 1_020)], fail=True)
    states: dict = {}
    adapter = SolmateRolesAuthorityAdapter()

    deferred = adapter.enumerate(_DESCRIPTOR, _ctx(db_session, TARGETS[0], SELECTORS[0], states, block=PIN))
    assert deferred.check is not None
    assert deferred.check.extra["basis"] == ["cursor_behind_block"]
    assert states == {}

    wire.fail = False
    folded = adapter.enumerate(_DESCRIPTOR, _ctx(db_session, TARGETS[0], SELECTORS[0], states, block=PIN))
    assert (folded.kind, folded.members, folded.last_indexed_block) == ("finite_set", sorted(USERS[:2]), PIN)
    assert folded.trace[0]["scan_from_block"] == CURSOR + 1
    assert list(states) == [(1, AUTHORITY, PIN)]


def test_every_answer_is_a_fresh_capability(db_session):
    _seed(db_session, [_capability(1, TARGETS[0], SELECTORS[0], True), _user_role(USERS[0], 1, True)])
    states: dict = {}
    adapter = SolmateRolesAuthorityAdapter()
    first = adapter.enumerate(_DESCRIPTOR, _ctx(db_session, TARGETS[0], SELECTORS[0], states))
    assert first.members is not None
    first.subject = "bound"
    first.members.append(USERS[4])
    first.trace[0]["roles"].append(99)

    second = adapter.enumerate(_DESCRIPTOR, _ctx(db_session, TARGETS[0], SELECTORS[0], states))
    assert second is not first
    assert second.subject != "bound"
    assert second.members == [USERS[0]]
    assert second.trace[0]["roles"] == [1]
