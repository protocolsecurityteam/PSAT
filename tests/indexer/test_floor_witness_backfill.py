"""The re-witness backfill: one seed witness per restaking cursor and per cursored address with no witness row.

Dry-run reads the chain and writes nothing; ``--apply`` writes only through the witness upsert, and rewrites a
restaking cursor's floor only on a proof.
"""

from __future__ import annotations

import json

from sqlalchemy import func, select

from db.floor_witnesses import WITNESS_PROVEN, read_floor_witness, record_floor_witness
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    FIRST_INDEXED_BASIS_CREATION,
    AddressFloorWitness,
    IndexedEventCursor,
    IndexedEventLog,
)
from services.monitoring.restaking_enrollment import PUBKEY_LINKED_TOPIC0, RESTAKING_FOLD_ENROLLMENT_BASIS
from tests.conftest import requires_postgres
from tests.support.witness_wire import stub_seed_witness
from workers import floor_witness_backfill
from workers.floor_witness_backfill import (
    REASON_NO_WITNESS_ROW,
    REASON_RESTAKING_CURSOR,
    rewitness_candidates,
    rewitness_floor_witnesses,
)

pytestmark = requires_postgres

_CREATION = 17_174_453
_SEED = _CREATION - 1
_RESTAKING = "0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"
_HINTED = "0x00000000000000000000000000000000000b0001"
_WITNESSED = "0x00000000000000000000000000000000000b0002"
_TOPIC = "0x" + "ab" * 32


def _cursor(address: str, topic0: str, *, basis: str, first: int | None, enrollment: str) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=1,
        event_address=address,
        topic0=topic0,
        last_indexed_block=_SEED + 5_000_000,
        backfill_complete=True,
        first_indexed_block=first,
        first_indexed_block_basis=basis,
        enrollment_basis=enrollment,
    )


def _seed_fleet(session) -> None:
    session.add_all(
        [
            # Restaking cursors were enrolled without the witness, so their not_determined was never attempted.
            _cursor(
                _RESTAKING,
                PUBKEY_LINKED_TOPIC0,
                basis="not_determined",
                first=None,
                enrollment=RESTAKING_FOLD_ENROLLMENT_BASIS,
            ),
            _cursor(_HINTED, _TOPIC, basis="not_determined", first=None, enrollment=ENROLLMENT_BASIS_PREDICATE_HINT),
            _cursor(
                _WITNESSED,
                _TOPIC,
                basis=FIRST_INDEXED_BASIS_CREATION,
                first=_SEED,
                enrollment=ENROLLMENT_BASIS_PREDICATE_HINT,
            ),
        ]
    )
    record_floor_witness(session, chain_id=1, address=_WITNESSED, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    session.commit()


def _restaking_cursor(session) -> IndexedEventCursor:
    return session.execute(
        select(IndexedEventCursor).where(IndexedEventCursor.event_address == _RESTAKING)
    ).scalar_one()


def test_candidates_are_restaking_cursors_and_unwitnessed_addresses(db_session):
    _seed_fleet(db_session)
    record_floor_witness(db_session, chain_id=1, address=_RESTAKING, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    assert rewitness_candidates(db_session) == [
        (1, _RESTAKING, REASON_RESTAKING_CURSOR),
        (1, _HINTED, REASON_NO_WITNESS_ROW),
    ]
    assert rewitness_candidates(db_session, chain_id=8453) == []


def test_dry_run_reads_the_chain_and_writes_nothing(db_session, monkeypatch):
    _seed_fleet(db_session)
    wire = stub_seed_witness(monkeypatch, creation_block=_CREATION)
    results = rewitness_floor_witnesses(db_session, apply=False)
    assert {(r.address, r.basis, r.applied) for r in results} == {
        (_RESTAKING, FIRST_INDEXED_BASIS_CREATION, False),
        (_HINTED, FIRST_INDEXED_BASIS_CREATION, False),
    }
    assert wire.calls
    assert db_session.execute(select(func.count()).select_from(AddressFloorWitness)).scalar_one() == 1
    assert _restaking_cursor(db_session).first_indexed_block_basis == "not_determined"


def test_apply_records_proofs_and_rewrites_the_restaking_cursor(db_session, monkeypatch):
    _seed_fleet(db_session)
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    results = rewitness_floor_witnesses(db_session, apply=True)
    assert {r.address: r.cursors_rewritten for r in results} == {_RESTAKING: 1, _HINTED: 0}
    for address in (_RESTAKING, _HINTED, _WITNESSED):
        assert read_floor_witness(db_session, chain_id=1, address=address) == (_SEED, FIRST_INDEXED_BASIS_CREATION)
    cursor = _restaking_cursor(db_session)
    assert (cursor.first_indexed_block, cursor.first_indexed_block_basis) == (_SEED, FIRST_INDEXED_BASIS_CREATION)
    hinted = db_session.execute(
        select(IndexedEventCursor).where(IndexedEventCursor.event_address == _HINTED)
    ).scalar_one()
    # Only restaking cursors had their witness skipped at enrolment; others keep what enrolment recorded.
    assert hinted.first_indexed_block_basis == "not_determined"


def test_apply_records_failures_without_downgrading_a_proof(db_session, monkeypatch):
    _seed_fleet(db_session)
    record_floor_witness(db_session, chain_id=1, address=_RESTAKING, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    db_session.commit()
    stub_seed_witness(monkeypatch, creation_block=_CREATION, fail=True)
    results = rewitness_floor_witnesses(db_session, apply=True)
    assert {(r.address, r.basis, r.cursors_rewritten) for r in results} == {
        (_RESTAKING, "not_determined", 0),
        (_HINTED, "not_determined", 0),
    }
    assert read_floor_witness(db_session, chain_id=1, address=_RESTAKING) == (_SEED, FIRST_INDEXED_BASIS_CREATION)
    assert read_floor_witness(db_session, chain_id=1, address=_HINTED) == (None, "not_determined")
    assert _restaking_cursor(db_session).first_indexed_block_basis == "not_determined"


def test_prior_incarnation_is_recorded_and_the_cursor_is_left_unproven(db_session, monkeypatch):
    _seed_fleet(db_session)
    stub_seed_witness(monkeypatch, creation_block=_CREATION, prior_logs=[{"blockNumber": "0x1"}])
    rewitness_floor_witnesses(db_session, apply=True)
    assert read_floor_witness(db_session, chain_id=1, address=_RESTAKING) == (None, "not_determined")
    assert _restaking_cursor(db_session).first_indexed_block_basis == "not_determined"


def test_unresolvable_creation_block_writes_nothing(db_session, monkeypatch):
    _seed_fleet(db_session)
    wire = stub_seed_witness(monkeypatch, creation_block=None)
    results = rewitness_floor_witnesses(db_session, apply=True)
    assert {(r.seed, r.basis) for r in results} == {(None, None)}
    assert wire.calls == []
    assert db_session.execute(select(func.count()).select_from(AddressFloorWitness)).scalar_one() == 1


def test_restaking_cursor_with_rows_below_the_seed_is_not_rewritten(db_session, monkeypatch):
    _seed_fleet(db_session)
    db_session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=_RESTAKING,
            topic0=PUBKEY_LINKED_TOPIC0,
            tx_hash=b"\x01" * 32,
            log_index=0,
            block_number=_SEED - 10,
            block_hash=b"\x02" * 32,
            transaction_index=0,
            topics=[PUBKEY_LINKED_TOPIC0],
            data_words=[],
        )
    )
    db_session.commit()
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    results = rewitness_floor_witnesses(db_session, apply=True)
    assert {r.address: r.cursors_rewritten for r in results}[_RESTAKING] == 0
    assert _restaking_cursor(db_session).first_indexed_block_basis == "not_determined"


def test_cli_defaults_to_dry_run(db_session, monkeypatch, capsys):
    from tests.conftest import SessionFactory

    _seed_fleet(db_session)
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    monkeypatch.setattr(floor_witness_backfill, "SessionLocal", SessionFactory(db_session))
    monkeypatch.setattr(floor_witness_backfill, "configure_logging", lambda: None)
    assert floor_witness_backfill.main(["--limit", "1"]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [(line["address"], line["applied"]) for line in lines] == [(_RESTAKING, False)]
    assert _restaking_cursor(db_session).first_indexed_block_basis == "not_determined"

    assert floor_witness_backfill.main(["--apply", "--chain-id", "1"]) == 0
    assert _restaking_cursor(db_session).first_indexed_block_basis == FIRST_INDEXED_BASIS_CREATION
