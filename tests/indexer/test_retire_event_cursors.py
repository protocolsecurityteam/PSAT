"""``retire``: a tracked cursor is deleted only when every gate holds, only at listed addresses, in bounded batches with
the cursor last; a dry run writes nothing and names exactly the set an apply deletes.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import create_engine, delete, event, func, select, text, update
from sqlalchemy.orm import Session

from db.floor_witnesses import WITNESS_PROVEN, record_floor_witness
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    FIRST_INDEXED_BASIS_CREATION,
    IndexedEventCursor,
    IndexedEventLog,
    IndexerWork,
    Job,
    JobStage,
    JobStatus,
    MonitoredContract,
    Protocol,
)
from db.queue import store_artifact
from services.monitoring.restaking_enrollment import PUBKEY_LINKED_TOPIC0
from services.resolution.role_store_standards import all_topic0s
from tests.conftest import DATABASE_URL, requires_postgres
from workers import retire_event_cursors as retire

pytestmark = requires_postgres

_X = "0x00000000000000000000000000000000000e7101"
_Y = "0x00000000000000000000000000000000000e7102"
_A = "0x" + "a7" * 32
_H = "0x" + "b7" * 32
_SEED = 15_000_000
_CHECK = "beforeTransfer(address,address,address)"


def _abi(outputs: list[str] | None) -> list[dict[str, Any]]:
    entry: dict[str, Any] = {
        "type": "function",
        "name": "beforeTransfer",
        "inputs": [{"type": "address"}] * 3,
    }
    if outputs is not None:
        entry["outputs"] = [{"type": t} for t in outputs]
    return [entry]


class _Abis:
    def __init__(self, by_address: dict[str, list[dict[str, Any]] | None] | None = None) -> None:
        self.by_address = by_address or {}
        self.calls: list[tuple[int, str]] = []

    def __call__(self, chain_id: int, address: str):
        self.calls.append((chain_id, address))
        return self.by_address.get(address)


def _cursor(session, address: str, topic0: str, basis: str, *, chain_id: int = 1) -> None:
    session.add(
        IndexedEventCursor(
            chain_id=chain_id,
            event_address=address,
            topic0=topic0,
            last_indexed_block=_SEED + 1_000,
            backfill_complete=True,
            enrolled_seed_block=_SEED,
            first_indexed_block=_SEED,
            first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
            enrollment_basis=basis,
        )
    )
    session.flush()


def _rows(session, address: str, topic0: str, count: int, *, start: int = 0) -> None:
    session.execute(
        text(
            "INSERT INTO indexed_event_logs (chain_id, event_address, topic0, tx_hash, log_index, block_number, "
            "block_hash, transaction_index, topics, data_words) "
            "SELECT 1, :a, :t, decode(lpad(to_hex(g), 64, '0'), 'hex'), 0, :b + g, decode(repeat('00', 32), 'hex'), "
            "0, jsonb_build_array(CAST(:t AS text)), '[]'::jsonb FROM generate_series(:s, :s + :n - 1) g"
        ),
        {"a": address, "t": topic0, "b": _SEED, "s": start + 1, "n": count},
    )


def _monitored(session, address: str, specs: list[dict[str, Any]], *, chain: str = "ethereum") -> None:
    """Add ``specs`` to the address's monitored contract on ``chain`` (one row per address and chain)."""
    existing = session.execute(
        select(MonitoredContract).where(MonitoredContract.address == address, MonitoredContract.chain == chain)
    ).scalar_one_or_none()
    if existing is not None:
        config = dict(existing.monitoring_config or {})
        existing.monitoring_config = {**config, "tracked_topics": [*config.get("tracked_topics", []), *specs]}
        session.flush()
        return
    protocol = Protocol(name=f"retire-{uuid.uuid4().hex[:12]}")
    session.add(protocol)
    session.flush()
    session.add(
        MonitoredContract(
            address=address,
            chain=chain,
            protocol_id=protocol.id,
            is_active=True,
            monitoring_config={"tracked_topics": specs},
        )
    )
    session.flush()


def _job(session, trees: dict[str, Any], *, chain_id: int = 1, address: str = _Y) -> None:
    job = Job(
        address=address,
        chain_id=chain_id,
        request={"address": address},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    store_artifact(session, job.id, "predicate_trees", data={"trees": trees})


def _leaf(descriptor: dict[str, Any], kind: str = "membership") -> dict[str, Any]:
    return {"op": "LEAF", "leaf": {"kind": kind, "set_descriptor": descriptor}}


def _check_on(address: str) -> dict[str, Any]:
    return _leaf(
        {"kind": "external_set", "authority_contract": {"address": address}, "callee_signature": _CHECK},
        kind="external_bool",
    )


def _scene(session) -> None:
    """X:A is retirable: tracked, its only spec activity-tier, no hint, no restaking, a void check, a sibling cursor."""
    _cursor(session, _X, _A, ENROLLMENT_BASIS_TRACKED_TOPICS)
    _rows(session, _X, _A, 3)
    _cursor(session, _X, _H, ENROLLMENT_BASIS_PREDICATE_HINT)
    _monitored(session, _X, [{"topic0": _A, "witness_tier": "activity"}])
    _job(session, {"transfer(address,uint256)": _check_on(_X)})
    session.commit()


def _verdict(session, abis: _Abis, topic0: str = _A, address: str = _X) -> retire.CursorVerdict:
    verdicts = retire.plan_retirement(session, abi_lookup=abis)
    session.rollback()
    return next(v for v in verdicts if v.address == address and v.topic0 == topic0)


def _failing(verdict: retire.CursorVerdict) -> set[str]:
    return {name for name in retire.GATES if not verdict.gates[name]["pass"]}


def test_the_baseline_scene_is_retirable_with_its_evidence(db_session):
    _scene(db_session)
    verdict = _verdict(db_session, _Abis({_X: _abi([])}))
    assert verdict.retirable and verdict.rows == 3
    check = verdict.gates["no_materializable_check"]["evidence"]["checks"][0]
    assert (check["abi_signature"], check["abi_outputs"], check["blocks"]) == (_CHECK, [], False)
    assert verdict.gates["no_indexed_spec"]["evidence"]["specs"][0]["witness_tier"] == "activity"


def test_gate_1_a_non_tracked_basis_blocks(db_session):
    _scene(db_session)
    db_session.execute(
        update(IndexedEventCursor).where(IndexedEventCursor.topic0 == _A).values(enrollment_basis="not_determined")
    )
    db_session.commit()
    assert _failing(_verdict(db_session, _Abis({_X: _abi([])}))) == {"tracked_basis"}


@pytest.mark.parametrize("tier", ["self_describing", None, "something_new"])
def test_gate_2_an_indexed_or_unstamped_spec_blocks(db_session, tier):
    _scene(db_session)
    spec: dict[str, Any] = {"topic0": _A}
    if tier is not None:
        spec["witness_tier"] = tier
    _monitored(db_session, _X, [spec])
    db_session.commit()
    assert _failing(_verdict(db_session, _Abis({_X: _abi([])}))) == {"no_indexed_spec"}


def test_gate_2_is_chain_scoped(db_session):
    _scene(db_session)
    _monitored(db_session, _X, [{"topic0": _A, "witness_tier": "self_describing"}], chain="base")
    db_session.commit()
    assert _verdict(db_session, _Abis({_X: _abi([])})).retirable


def test_gate_3_a_predicate_hint_on_the_key_blocks(db_session):
    _scene(db_session)
    _job(db_session, {"f()": _leaf({"enumeration_hint": [{"topic0": _A, "event_address": _X}]})})
    db_session.commit()
    verdict = _verdict(db_session, _Abis({_X: _abi([])}))
    assert _failing(verdict) == {"no_predicate_hint"}
    assert len(verdict.gates["no_predicate_hint"]["evidence"]["hint_jobs"]) == 1


def test_gate_3_a_delegated_role_gate_blocks_every_role_store_topic(db_session):
    role_topic = all_topic0s()[0].lower()
    _cursor(db_session, _X, role_topic, ENROLLMENT_BASIS_TRACKED_TOPICS)
    _cursor(db_session, _X, _H, ENROLLMENT_BASIS_PREDICATE_HINT)
    _job(
        db_session,
        {
            "g()": _leaf(
                {
                    "kind": "external_set",
                    "authority_contract": {"address": _X},
                    "callee_signature": "onlyOperator(address)",
                    "key_sources": [{"source": "msg_sender"}],
                },
                kind="external_bool",
            )
        },
    )
    db_session.commit()
    verdict = _verdict(
        db_session,
        _Abis({_X: [{"type": "function", "name": "onlyOperator", "inputs": [{"type": "address"}]}]}),
        role_topic,
    )
    assert _failing(verdict) == {"no_predicate_hint"}
    assert verdict.gates["no_predicate_hint"]["evidence"]["role_store_gate_jobs"]


def test_gate_4_a_restaking_emitter_blocks(db_session):
    _scene(db_session)
    _cursor(db_session, _X, PUBKEY_LINKED_TOPIC0, ENROLLMENT_BASIS_TRACKED_TOPICS)
    db_session.commit()
    assert _failing(_verdict(db_session, _Abis({_X: _abi([])}))) == {"not_restaking_emitter"}


@pytest.mark.parametrize(
    ("abi", "blocks"),
    [
        (_abi([]), False),
        (_abi(["bool"]), True),
        (_abi(["uint256"]), True),
        (None, True),
        ([{"type": "function", "name": "other", "inputs": []}], True),
    ],
    ids=["void", "bool", "word", "abi_unread", "callee_missing"],
)
def test_gate_5_only_a_proven_void_check_lets_the_rows_go(db_session, abi, blocks):
    _scene(db_session)
    verdict = _verdict(db_session, _Abis({_X: abi}))
    assert _failing(verdict) == ({"no_materializable_check"} if blocks else set())


def test_gate_5_is_chain_scoped(db_session):
    _scene(db_session)
    # A Base check on the same address, through a callee mainnet's ABI doesn't have: it says nothing about mainnet rows.
    base_check = _leaf(
        {
            "kind": "external_set",
            "authority_contract": {"address": _X},
            "callee_signature": "canTransfer(address,address)",
        },
        kind="external_bool",
    )
    _job(db_session, {"f(address)": base_check}, chain_id=8453)
    db_session.commit()
    verdict = _verdict(db_session, _Abis({_X: _abi([])}))
    assert verdict.retirable
    assert [c["callee_signature"] for c in verdict.gates["no_materializable_check"]["evidence"]["checks"]] == [_CHECK]


def test_gate_6_the_last_cursor_needs_a_witness_row(db_session):
    _scene(db_session)
    db_session.execute(delete(IndexedEventCursor).where(IndexedEventCursor.topic0 == _H))
    db_session.commit()
    verdict = _verdict(db_session, _Abis({_X: _abi([])}))
    assert _failing(verdict) == {"floor_witness_kept"}
    assert verdict.gates["floor_witness_kept"]["evidence"]["cursors_left_after_retirement"] == 0
    record_floor_witness(db_session, chain_id=1, address=_X, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    db_session.commit()
    assert _verdict(db_session, _Abis({_X: _abi([])})).retirable


def _snapshot(session) -> tuple[Any, ...]:
    session.expire_all()
    return (
        session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one(),
        session.execute(select(func.count()).select_from(IndexedEventLog)).scalar_one(),
        sorted((w.kind, w.key, w.revision) for w in session.execute(select(IndexerWork)).scalars()),
    )


def _two_address_scene(session) -> None:
    _scene(session)
    # Y:A would also be retirable, but Y is never listed.
    _cursor(session, _Y, _A, ENROLLMENT_BASIS_TRACKED_TOPICS)
    _rows(session, _Y, _A, 2)
    _cursor(session, _Y, _H, ENROLLMENT_BASIS_PREDICATE_HINT)
    # X:B is blocked by an indexed spec.
    _cursor(session, _X, "0x" + "c7" * 32, ENROLLMENT_BASIS_TRACKED_TOPICS)
    _monitored(session, _X, [{"topic0": "0x" + "c7" * 32, "witness_tier": "self_describing"}])
    session.commit()


def test_dry_run_writes_nothing_and_names_exactly_the_apply_set(db_session, monkeypatch, capsys):
    _two_address_scene(db_session)
    abis = _Abis({_X: _abi([]), _Y: _abi([])})
    monkeypatch.setattr(retire, "etherscan_abi", abis)
    before = _snapshot(db_session)
    factory = lambda: Session(db_session.get_bind())  # noqa: E731

    assert retire.main(["--dry-run", "--addresses", _X], session_factory=factory) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert _snapshot(db_session) == before
    planned = {(v["chain_id"], v["address"], v["topic0"]) for v in lines[:-1] if v["retirable"]}
    assert planned == {(1, _X, _A)}
    assert lines[-1]["summary"]["retirable_rows"] == 3

    retired = retire.apply_retirement(db_session, addresses=[_X], abi_lookup=abis)
    assert {(v.chain_id, v.address, v.topic0) for v in retired} == planned
    db_session.expire_all()
    remaining = {(c.event_address, c.topic0) for c in db_session.execute(select(IndexedEventCursor)).scalars()}
    assert remaining == {(_X, _H), (_X, "0x" + "c7" * 32), (_Y, _A), (_Y, _H)}
    assert (
        db_session.execute(
            select(func.count()).select_from(IndexedEventLog).where(IndexedEventLog.event_address == _Y)
        ).scalar_one()
        == 2
    )


def test_apply_deletes_in_bounded_batches_with_the_cursor_last_and_marks_reorg(db_session):
    _cursor(db_session, _X, _A, ENROLLMENT_BASIS_TRACKED_TOPICS)
    _rows(db_session, _X, _A, 12_001)
    _cursor(db_session, _X, _H, ENROLLMENT_BASIS_PREDICATE_HINT)
    _rows(db_session, _X, _H, 4)
    db_session.commit()
    db_session.execute(delete(IndexerWork))
    db_session.commit()

    probe_engine = create_engine(DATABASE_URL)
    commits: list[tuple[int, bool]] = []

    def observe(_session) -> None:
        with probe_engine.connect() as probe:
            rows = probe.execute(
                text("SELECT count(*) FROM indexed_event_logs WHERE event_address = :a AND topic0 = :t"),
                {"a": _X, "t": _A},
            ).scalar_one()
            cursor = probe.execute(
                text("SELECT count(*) FROM indexed_event_cursors WHERE event_address = :a AND topic0 = :t"),
                {"a": _X, "t": _A},
            ).scalar_one()
        commits.append((rows, bool(cursor)))

    session = Session(db_session.get_bind())
    event.listen(session, "after_commit", observe)
    try:
        retired = retire.apply_retirement(session, addresses=[_X], abi_lookup=_Abis())
    finally:
        session.close()
        probe_engine.dispose()
    assert [(v.topic0, v.rows) for v in retired] == [(_A, 12_001)]
    deletes = [c for c in commits if c != (12_001, True)]
    assert deletes == [(7_001, True), (2_001, True), (0, False)]
    db_session.expire_all()
    assert (
        db_session.execute(
            select(func.count()).select_from(IndexedEventLog).where(IndexedEventLog.topic0 == _H)
        ).scalar_one()
        == 4
    )
    marks = {(w.kind, w.key) for w in db_session.execute(select(IndexerWork).where(IndexerWork.dirty)).scalars()}
    assert ("reorg", f"1:{_X}") in marks
    assert ("reconcile", "1") in marks


def test_apply_requires_an_address_list(db_session):
    with pytest.raises(SystemExit):
        retire.main(["--apply"], session_factory=lambda: Session(db_session.get_bind()))
    with pytest.raises(ValueError):
        retire.apply_retirement(db_session, addresses=[])
