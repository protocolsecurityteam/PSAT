"""Loud decoding: a malformed upstream log rejects its page and stalls the cursor visibly; non-aligned data is stored
losslessly, and every reader of the row treats it as not decodable instead of silently missing it."""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, cast

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import select, update

import services.resolution.mapping_enumerator as mapping_enumerator
import services.resolution.repos.event_logs_rpc as event_logs_rpc
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    FIRST_INDEXED_BASIS_CREATION,
    IndexedEventCursor,
    IndexedEventLog,
)
from services.monitoring.restaking_enrollment import PUBKEY_LINKED_TOPIC0, node_addresses_from_fold
from services.resolution import external_check_materializer
from services.resolution.adapters import EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.adapters.solmate_roles import SolmateRolesAuthorityAdapter
from services.resolution.predicate_evaluator.membership import _observed_event_key_words
from services.resolution.repos.event_logs_pg import (
    UNDECODABLE_EVENT_DATA,
    PostgresEventLogRepo,
    UndecodableEventRow,
)
from services.resolution.repos.event_logs_rpc import RpcEventLogFetcher
from tests.conftest import requires_postgres
from tests.resolution import test_adapter_event_indexed_durable_value_fold as value_fold
from tests.resolution import test_role_holder_plane as role_plane
from tests.resolution import test_solmate_roles_coverage_gate as solmate
from tests.support.sim_chain import SimChain, SimLog, address, topic, word
from utils.chains import chain_by_id
from workers import event_log_indexer as indexer
from workers.event_log_indexer import enroll_event_cursor, scan_enrolled_events

pytestmark = requires_postgres

_HEAD = 2_000_012
_TARGET = 2_000_000
_SEED = 1_990_000
_ADDR = address(0xB0)
_T1, _T2 = topic(0xB1), topic(0xB2)
_UNALIGNED = "0x" + "ab" * 33


@pytest.fixture()
def sim(monkeypatch):
    chain = SimChain(heads={1: _HEAD, 8453: 30_000_075})
    monkeypatch.setattr(event_logs_rpc, "rpc_request", chain.rpc_request)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    indexer._STALLED_GROUPS.clear()
    return chain


def _fetchers():
    base = dataclasses.replace(chain_by_id(8453), hypersync_url="https://base.hypersync.xyz")
    return indexer._build_indexer_fetchers(chains=(chain_by_id(1), base))


def _enroll(session) -> None:
    for t in (_T1, _T2):
        enroll_event_cursor(
            session,
            chain_id=1,
            event_address=_ADDR,
            topic0=t,
            start_block=_SEED,
            first_indexed_block=_SEED,
            first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
            enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
        )
    session.commit()


def _scan(session):
    fetchers = _fetchers()
    return scan_enrolled_events(
        session, fetchers=fetchers[0], head_fetchers=fetchers[1], block_hash_fetchers=fetchers[2]
    )


def _positions(session) -> list[int]:
    session.expire_all()
    return list(session.execute(select(IndexedEventCursor.last_indexed_block)).scalars())


def _fill(sim: SimChain) -> None:
    sim.add_many(
        1,
        [SimLog(_ADDR, (_T1, "0x" + word(b)), "0x" + word(b), b, 0, 0) for b in range(_SEED + 1, _TARGET + 1, 50)],
    )


def _drop(field: str):
    def mutate(log: SimLog, raw: dict) -> dict:
        if log.block == _SEED + 501:
            raw = dict(raw)
            raw.pop(field)
        return raw

    return mutate


def _set(field: str, value):
    def mutate(log: SimLog, raw: dict) -> dict:
        return {**raw, field: value} if log.block == _SEED + 501 else raw

    return mutate


def _clash(kind: str):
    """Make the log at one block collide with the log 50 blocks earlier."""

    def mutate(log: SimLog, raw: dict) -> dict:
        if log.block != _SEED + 551:
            return raw
        earlier = SimChain(heads={1: _HEAD}).raw(1, dataclasses.replace(log, block=_SEED + 501))
        if kind == "identity":
            return {**raw, "transactionHash": earlier["transactionHash"], "logIndex": earlier["logIndex"]}
        if kind == "position":
            return {**raw, "blockNumber": earlier["blockNumber"], "blockHash": earlier["blockHash"]}
        return {**raw, "blockNumber": earlier["blockNumber"], "logIndex": "0x1"}

    return mutate


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(_drop("blockHash"), id="missing-block-hash"),
        pytest.param(_drop("logIndex"), id="missing-log-index"),
        pytest.param(_set("topics", []), id="no-topics"),
        pytest.param(_set("removed", True), id="removed"),
        pytest.param(_set("address", address(0xEE)), id="foreign-emitter"),
        pytest.param(_set("blockNumber", hex(_TARGET + 5)), id="out-of-range"),
        pytest.param(_set("data", "0xabc"), id="odd-length-data"),
        pytest.param(_set("topics", [topic(0x99)]), id="out-of-filter"),
        pytest.param(_clash("identity"), id="conflicting-identity"),
        pytest.param(_clash("position"), id="conflicting-position"),
        pytest.param(_clash("block-hash"), id="two-hashes-one-block"),
    ],
)
def test_a_malformed_log_rejects_the_page_without_advancing(db_session, sim, caplog, mutate):
    _fill(sim)
    sim.mutate_raw = mutate
    _enroll(db_session)

    with caplog.at_level(logging.WARNING, logger="workers.event_log_indexer"):
        first = _scan(db_session)
        second = _scan(db_session)

    assert _positions(db_session) == [_SEED, _SEED]
    assert db_session.execute(select(IndexedEventLog)).first() is None
    assert first.stalled_cursors == second.stalled_cursors == 2
    warnings = [r for r in caplog.records if r.getMessage().startswith("event-log page rejected for a malformed log")]
    assert len(warnings) == 2
    assert (warnings[0].__dict__["from_block"], warnings[0].__dict__["to_block"]) == (_SEED + 1, _TARGET)
    # The stall alerts once, not every pass.
    errors = [r for r in caplog.records if r.levelno == logging.ERROR and "stalled" in r.getMessage()]
    assert len(errors) == 1


def test_a_stall_clears_once_the_upstream_serves_the_page_whole(db_session, sim, caplog):
    _fill(sim)
    sim.mutate_raw = _drop("transactionHash")
    _enroll(db_session)
    assert _scan(db_session).stalled_cursors == 2

    sim.mutate_raw = None
    summary = _scan(db_session)

    assert summary.stalled_cursors == 0
    assert _positions(db_session) == [_TARGET, _TARGET]
    assert indexer._STALLED_GROUPS == set()


def test_non_aligned_data_round_trips_through_data_hex(db_session, sim):
    sim.add(1, SimLog(_ADDR, (_T2,), _UNALIGNED, _SEED + 7, 0, 0))
    sim.add(1, SimLog(_ADDR, (_T1,), "0x" + word(5), _SEED + 8, 0, 1))
    _enroll(db_session)

    _scan(db_session)

    rows = db_session.execute(
        select(IndexedEventLog.topic0, IndexedEventLog.data_words, IndexedEventLog.data_hex).order_by(
            IndexedEventLog.block_number
        )
    ).all()
    assert [tuple(r) for r in rows] == [(_T2, [], _UNALIGNED), (_T1, ["0x" + word(5)], None)]
    assert _positions(db_session) == [_TARGET, _TARGET]
    # Callers outside the indexer see the same lossless field.
    (fetched,) = RpcEventLogFetcher("http://unit.test", chain_id=1).fetch_logs(
        event_address=_ADDR, topics=[_T2], from_block=_SEED, to_block=_SEED + 7
    )
    assert (fetched.data_words, fetched.data_hex) == ([], _UNALIGNED)


# Readers


def _row(**overrides) -> IndexedEventLog:
    fields = dict(
        chain_id=1,
        event_address=_ADDR,
        topic0=_T1,
        tx_hash=b"\x01" * 32,
        log_index=0,
        block_number=_SEED + 5,
        block_hash=b"\x02" * 32,
        transaction_index=0,
        topics=[_T1, "0x" + word(int(address(0xC0), 16))],
        data_words=[],
        data_hex=_UNALIGNED,
    )
    fields.update(overrides)
    return IndexedEventLog(**fields)


def _warm_cursor(topic0: str = _T1) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=1,
        event_address=_ADDR,
        topic0=topic0,
        last_indexed_block=_TARGET,
        backfill_complete=True,
        first_indexed_block=_SEED,
        first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
        enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
    )


def test_write_and_history_folds_are_partial_not_missing(db_session):
    db_session.add_all([_warm_cursor(), _row()])
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)
    key_sources = [{"source": "msg_sender"}]

    writes = repo.fold_event_writes(
        chain_id=1,
        event_address=_ADDR,
        topic0=_T1,
        topics_to_keys={1: 0},
        data_to_keys={},
        key_sources=key_sources,
        direction="add",
        block=_TARGET,
    )
    history = repo.fold_event_history(
        chain_id=1,
        event_address=_ADDR,
        event_hints=[{"topic0": _T1, "topics_to_keys": {1: 0}, "data_to_keys": {}, "direction": "add"}],
        key_sources=key_sources,
        block=_TARGET,
    )

    for result in (writes, history):
        assert (result.confidence, result.partial_reason, result.members) == ("partial", UNDECODABLE_EVENT_DATA, [])
    with pytest.raises(UndecodableEventRow):
        repo.iter_event_rows(chain_id=1, event_address=_ADDR, topic0s=[_T1])


def test_value_fold_is_not_determined_and_never_replays_live(db_session, monkeypatch):
    live_calls: list[tuple] = []
    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values_sync", lambda *a, **k: live_calls.append((a, k)))
    row = value_fold._eig_log(value_fold.CALLER_A, "0x88676cad", True, block=23591216, tx_index=0, log_index=1)
    row.data_words = []
    row.data_hex = _UNALIGNED
    value_fold._seed(db_session, [row], [value_fold._cursor(value_fold.EIG_TOPIC0, last_block=25389740, complete=True)])
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=value_fold.STATE_HOLDER,
        block=value_fold.RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )

    cap = EventIndexedAdapter().enumerate(value_fold._eigenpod_descriptor(), ctx)

    assert cap.kind == "unsupported"
    assert cap.unsupported_reason == "event_data_undecodable"
    assert live_calls == []


def test_solmate_roles_defer_on_an_undecodable_role_row(db_session):
    solmate._seed(db_session, 1, solmate._DURABLE)
    db_session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=solmate.AUTHORITY,
            topic0=solmate.USER_ROLE_UPDATED,
            tx_hash=b"\x09" * 32,
            log_index=99,
            block_number=500,
            block_hash=b"\x03" * 32,
            transaction_index=0,
            topics=solmate._user_role(solmate.BOB, True)[0],
            data_words=[],
            data_hex=_UNALIGNED,
        )
    )
    db_session.flush()

    cap = SolmateRolesAuthorityAdapter().enumerate(
        solmate._DESCRIPTOR, solmate._ctx(db_session, 1, block=solmate.CURSOR)
    )

    assert cap.kind == "external_check_only"
    assert cap.check is not None and cap.check.extra["basis"] == [UNDECODABLE_EVENT_DATA]


def test_membership_key_words_refuse_an_undecodable_row(db_session):
    db_session.add(_row())
    db_session.flush()

    class _Ctx:
        chain_id = 1
        block = _TARGET
        contract_address = _ADDR
        state_var_values: dict = {}

    words = _observed_event_key_words(
        session=db_session,
        outer_ctx=_Ctx(),
        descriptor=cast(Any, {"kind": "mapping_membership"}),
        event_hints=[{"topic0": _T1, "topics_to_keys": {1: 0}, "event_address": _ADDR}],
        key_index=0,
    )

    assert words is None


def test_external_check_candidates_report_skipped_undecodable_rows(db_session):
    hidden, seen = "0x" + "c1" * 20, "0x" + "c2" * 20
    db_session.add(_row(topics=[_T1, "0x" + word(int(hidden, 16))]))
    db_session.add(_row(tx_hash=b"\x05" * 32, data_hex=None, topics=[_T1], data_words=["0x" + word(int(seen, 16))]))
    db_session.flush()

    candidates, undecodable = external_check_materializer._candidate_addresses_from_events(
        session=db_session, chain_id=1, checker_address=_ADDR, limit=10
    )

    assert (candidates, undecodable) == ([seen], 1)


def test_restaking_fold_skips_and_reports_an_undecodable_row(db_session, caplog):
    node = address(0xD1)
    db_session.add(
        _row(topic0=PUBKEY_LINKED_TOPIC0, topics=[PUBKEY_LINKED_TOPIC0, "0x" + "11" * 32, "0x" + word(int(node, 16))])
    )
    db_session.flush()

    with caplog.at_level(logging.WARNING):
        nodes = node_addresses_from_fold(db_session, chain_id=1, event_address=_ADDR)

    assert nodes == []
    assert any(r.getMessage().startswith("undecodable PubkeyLinked rows skipped") for r in caplog.records)


@pytest.mark.parametrize("undecodable", [False, True], ids=["control", "undecodable"])
def test_role_plane_withholds_every_holder_set_on_an_undecodable_row(db_session, monkeypatch, undecodable):
    logs = role_plane._corpus_logs()
    if undecodable:
        logs[-1].data_hex = _UNALIGNED
    role_plane._seed(db_session, logs=logs)
    every_candidate_holds = {
        (role, account): role_plane.TRUE_WORD
        for role in (role_plane.ZERO_ROLE, role_plane.PAUSER, role_plane.OPERATING_ADMIN)
        for account in (
            role_plane.ADMIN_HOLDER,
            role_plane.REVOKED_A,
            role_plane.REVOKED_B,
            role_plane.PAUSER_EXTRA,
            role_plane.OPS_HOLDER,
        )
    }

    rows = role_plane._run(db_session, monkeypatch, every_candidate_holds)

    assert rows
    published = [row["holders"] for row in rows if row["holders"] is not None]
    assert (published == []) is undecodable


_MINTER = "0x" + keccak(text="MINTER_ROLE").hex()


def test_role_plane_withholds_a_role_seen_only_in_an_undecodable_row(db_session, monkeypatch):
    logs = role_plane._corpus_logs()
    only_undecodable = role_plane._log(role_plane.RG, _MINTER, role_plane.OPS_HOLDER, block=22_800_000, log_index=7)
    only_undecodable.data_hex = _UNALIGNED
    role_plane._seed(db_session, logs=[*logs, only_undecodable])

    rows = role_plane._run(db_session, monkeypatch, {})

    by_role = {row["role_hash"]: row for row in rows}
    assert set(by_role) == {role_plane.ZERO_ROLE, role_plane.PAUSER, role_plane.OPERATING_ADMIN, _MINTER}
    minter = by_role[_MINTER]
    assert minter["holders"] is None and minter["holders_basis"] == "not_determined"
    # Its account is never taken as a candidate from a row whose data no ABI decodes.
    assert minter["candidate_count"] is None


def test_role_plane_lists_roles_when_every_row_is_undecodable(db_session, monkeypatch):
    only_undecodable = role_plane._log(role_plane.RG, _MINTER, role_plane.OPS_HOLDER, block=22_800_000, log_index=7)
    only_undecodable.data_hex = _UNALIGNED
    role_plane._seed(db_session, logs=[only_undecodable])

    rows = role_plane._run(db_session, monkeypatch, {})

    assert [(row["role_hash"], row["holders"]) for row in rows] == [(_MINTER, None)]


def test_a_stall_stays_visible_in_progress_published_mid_pass(db_session, sim):
    healthy = address(0xB9)
    _fill(sim)
    sim.add_many(1, [SimLog(healthy, (_T1,), "0x", b, 0, 0) for b in range(_SEED + 2, _TARGET + 1, 100)])
    sim.mutate_raw = _drop("blockHash")
    _enroll(db_session)
    enroll_event_cursor(db_session, chain_id=1, event_address=healthy, topic0=_T1, start_block=_SEED)
    db_session.commit()
    published = []
    fetchers = _fetchers()

    summary = scan_enrolled_events(
        db_session,
        fetchers=fetchers[0],
        head_fetchers=fetchers[1],
        block_hash_fetchers=fetchers[2],
        on_commit=published.append,
    )

    # The stalled group sorts first, so every later commit's progress must still carry its stall.
    assert summary.stalled_cursors == 2
    assert published and all(p.stalled_cursors == 2 for p in published)


def test_a_stall_recovered_through_the_warm_batch_clears(db_session, sim):
    other = address(0xBA)
    for addr in (_ADDR, other):
        sim.add_many(1, [SimLog(addr, (_T1,), "0x", b, 0, 0) for b in range(_TARGET - 400, _TARGET + 1, 7)])
        enroll_event_cursor(db_session, chain_id=1, event_address=addr, topic0=_T1, start_block=_TARGET - 500)
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    db_session.commit()
    sim.mutate_raw = lambda log, raw: {**raw, "removed": True} if log.address == _ADDR else raw
    fetchers = _fetchers()

    def sweep():
        return scan_enrolled_events(
            db_session,
            fetchers=fetchers[0],
            head_fetchers=fetchers[1],
            block_hash_fetchers=fetchers[2],
            scan_mode="warm",
        )

    assert sweep().stalled_cursors == 1
    assert indexer._STALLED_GROUPS
    sim.mutate_raw = None
    assert sweep().stalled_cursors == 0
    assert indexer._STALLED_GROUPS == set()
