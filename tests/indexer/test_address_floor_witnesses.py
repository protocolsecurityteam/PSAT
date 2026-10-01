"""``address_floor_witnesses``: the per-address deploy-floor witness.

A proven row survives transient failures; only a prior-incarnation result (logs at or below the seed) or a new proof
replaces it. The migration seeds rows from witnessed cursors and refuses to pick a winner when they disagree.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import delete, select, text

from db.floor_witnesses import (
    WITNESS_FAILED,
    WITNESS_PRIOR_INCARNATION,
    WITNESS_PROVEN,
    read_floor_witness,
    record_floor_witness,
)
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    FIRST_INDEXED_BASIS_CREATION,
    AddressFloorWitness,
    IndexedEventCursor,
)
from tests.conftest import requires_postgres
from workers.event_log_indexer import EnrollmentCaches, _enroll_witnessed, _witness_seed_block

pytestmark = requires_postgres

_ADDR = "0x3994741a5b29c60d0ab318de1024f9256fe959dc"
_OTHER = "0x00000000000000000000000000000000000f1002"
_SEED = 20_265_588
_TOPIC = "0x039bcf51833310242b8b7c6aa0fbabf1bf2b5e5270807ee020f1920ef200666b"
_TOPIC_2 = "0x79fc685a7dbabb75a67df5e69a90602cef1f19bc465b060eab1ac56685e04a13"


class _WitnessWire:
    """``rpc_request`` for the three pinned witness reads."""

    def __init__(self, *, prior_logs: list[Any] | None = None, fail: bool = False) -> None:
        self.prior_logs = [] if prior_logs is None else prior_logs
        self.fail = fail
        self.calls: list[str] = []

    def __call__(self, url, method, params, chain_id=None):
        self.calls.append(method)
        if self.fail:
            raise RuntimeError("stubbed upstream failure")
        if method == "eth_getCode":
            return "0x" if int(params[1], 16) == _SEED else "0x6080"
        if method == "eth_getLogs":
            return self.prior_logs
        raise AssertionError(method)


@pytest.fixture()
def wire(monkeypatch):
    import workers.event_log_indexer as eli

    def _install(**kwargs) -> _WitnessWire:
        stub = _WitnessWire(**kwargs)
        monkeypatch.setattr(eli, "rpc_request", stub)
        monkeypatch.setattr(eli, "require_rpc_url", lambda **_kw: "http://stub")
        monkeypatch.setattr(eli, "get_contract_creation_block", lambda *_a, **_k: _SEED + 1)
        return stub

    return _install


def _witness(session) -> tuple[int | None, str] | None:
    return read_floor_witness(session, chain_id=1, address=_ADDR)


def test_failure_never_downgrades_a_proven_row(db_session):
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_FAILED)
    assert _witness(db_session) == (_SEED, FIRST_INDEXED_BASIS_CREATION)


def test_prior_incarnation_downgrades_a_proven_row(db_session):
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PRIOR_INCARNATION)
    assert _witness(db_session) == (None, "not_determined")


def test_failure_records_not_determined_when_nothing_is_proven(db_session):
    assert _witness(db_session) is None
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_FAILED)
    assert _witness(db_session) == (None, "not_determined")
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    assert _witness(db_session) == (_SEED, FIRST_INDEXED_BASIS_CREATION)


def test_proven_outcome_requires_a_block(db_session):
    with pytest.raises(ValueError):
        record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PROVEN)


def test_rows_are_chain_scoped_and_lowercased(db_session):
    record_floor_witness(
        db_session,
        chain_id=8453,
        address=_ADDR.upper().replace("0X", "0x"),
        outcome=WITNESS_PROVEN,
        first_indexed_block=7,
    )
    assert read_floor_witness(db_session, chain_id=8453, address=_ADDR) == (7, FIRST_INDEXED_BASIS_CREATION)
    assert read_floor_witness(db_session, chain_id=1, address=_ADDR) is None


def test_witness_records_each_outcome_through_the_upsert_rule(db_session, wire):
    wire()
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1, session=db_session) == (
        _SEED,
        FIRST_INDEXED_BASIS_CREATION,
    )
    assert _witness(db_session) == (_SEED, FIRST_INDEXED_BASIS_CREATION)

    wire(fail=True)
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1, session=db_session) == (None, "not_determined")
    assert _witness(db_session) == (_SEED, FIRST_INDEXED_BASIS_CREATION)

    wire(prior_logs=[{"blockNumber": "0x1"}])
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1, session=db_session) == (None, "not_determined")
    assert _witness(db_session) == (None, "not_determined")


def test_cached_witness_is_recorded_once_per_address(db_session, wire):
    stub = wire()
    caches = EnrollmentCaches()
    for topic0 in (_TOPIC, _TOPIC_2):
        assert _enroll_witnessed(
            db_session,
            chain_id=1,
            address=_ADDR,
            topic0=topic0,
            seed_cache=caches.seeds,
            witness_cache=caches.witnesses,
            enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
        )
    assert stub.calls == ["eth_getCode", "eth_getCode", "eth_getLogs"]
    assert _witness(db_session) == (_SEED, FIRST_INDEXED_BASIS_CREATION)


def _load_migration():
    path = Path(__file__).resolve().parents[2] / "alembic/versions/eabc0b2e7078_address_floor_witnesses.py"
    spec = importlib.util.spec_from_file_location("_floor_witness_migration", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cursor(address: str, topic0: str, first: int | None, basis: str | None) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=1,
        event_address=address,
        topic0=topic0,
        last_indexed_block=30_000_000,
        backfill_complete=True,
        first_indexed_block=first,
        first_indexed_block_basis=basis,
        enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
    )


def test_migration_backfill_agreeing_cursors_prove_disagreeing_do_not(db_session, caplog):
    migration = _load_migration()
    connection = db_session.connection()
    with Operations.context(MigrationContext.configure(connection)):
        migration.downgrade()
        assert connection.execute(text("SELECT to_regclass('address_floor_witnesses')")).scalar_one() is None
        db_session.execute(delete(IndexedEventCursor))
        db_session.add_all(
            [
                _cursor(_ADDR, _TOPIC, _SEED, FIRST_INDEXED_BASIS_CREATION),
                _cursor(_ADDR, _TOPIC_2, _SEED, FIRST_INDEXED_BASIS_CREATION),
                # An unwitnessed sibling neither proves nor disproves the floor.
                _cursor(_ADDR, "0x" + "11" * 32, None, "not_determined"),
                _cursor(_OTHER, _TOPIC, 100, FIRST_INDEXED_BASIS_CREATION),
                _cursor(_OTHER, _TOPIC_2, 200, FIRST_INDEXED_BASIS_CREATION),
                # Never witnessed at all: no row, so the floor keeps its unwitnessed path.
                _cursor("0x00000000000000000000000000000000000f1003", _TOPIC, None, "not_determined"),
            ]
        )
        db_session.flush()
        with caplog.at_level("WARNING", logger="alembic.runtime.migration"):
            migration.upgrade()
        rows = {
            (r.address, r.first_indexed_block, r.basis)
            for r in db_session.execute(select(AddressFloorWitness)).scalars()
        }
    assert rows == {
        (_ADDR, _SEED, FIRST_INDEXED_BASIS_CREATION),
        (_OTHER, None, "not_determined"),
    }
    assert any(_OTHER in record.getMessage() for record in caplog.records)
    db_session.rollback()
