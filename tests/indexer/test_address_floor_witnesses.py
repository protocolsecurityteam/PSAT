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
_RETRY_MIGRATION = "aa9f6ba5b7df_floor_witness_retry_columns"


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


def _load_migration(name: str = "eabc0b2e7078_address_floor_witnesses"):
    path = Path(__file__).resolve().parents[2] / f"alembic/versions/{name}.py"
    spec = importlib.util.spec_from_file_location(f"_migration_{name}", path)
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
    retry_columns = _load_migration(_RETRY_MIGRATION)
    connection = db_session.connection()
    with Operations.context(MigrationContext.configure(connection)):
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
        retry_columns.downgrade()
        migration.downgrade()
        assert connection.execute(text("SELECT to_regclass('address_floor_witnesses')")).scalar_one() is None
        with caplog.at_level("WARNING", logger="alembic.runtime.migration"):
            migration.upgrade()
        retry_columns.upgrade()
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


def _row(session, address: str = _ADDR) -> AddressFloorWitness:
    session.expire_all()
    return session.execute(
        select(AddressFloorWitness).where(AddressFloorWitness.chain_id == 1, AddressFloorWitness.address == address)
    ).scalar_one()


def _seconds_until_retry(session, address: str = _ADDR) -> float:
    return session.execute(
        text(
            "SELECT extract(epoch FROM next_attempt_at - now()) FROM address_floor_witnesses "
            "WHERE chain_id = 1 AND address = :a"
        ),
        {"a": address},
    ).scalar_one()


def test_failures_back_off_exponentially_up_to_a_day(db_session):
    expected = [600, 1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400]
    for attempt, delay in enumerate(expected, start=1):
        assert record_floor_witness(
            db_session, chain_id=1, address=_ADDR, outcome=WITNESS_FAILED, seed_block=_SEED
        ) == (attempt)
        row = _row(db_session)
        assert (row.outcome, row.attempts, row.seed_block, row.basis) == ("failed", attempt, _SEED, "not_determined")
        assert _seconds_until_retry(db_session) == pytest.approx(delay, abs=5)


def test_proof_resets_the_retry_state(db_session):
    for _ in range(3):
        record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_FAILED, seed_block=_SEED)
    assert (
        record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
        is None
    )
    row = _row(db_session)
    assert (row.outcome, row.attempts, row.next_attempt_at, row.seed_block, row.first_indexed_block) == (
        "proven",
        0,
        None,
        _SEED,
        _SEED,
    )


def test_failure_leaves_decided_rows_untouched(db_session):
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    record_floor_witness(db_session, chain_id=1, address=_OTHER, outcome=WITNESS_PRIOR_INCARNATION, seed_block=_SEED)
    before = {(r.address, r.outcome, r.attempts, r.witnessed_at) for r in (_row(db_session), _row(db_session, _OTHER))}
    for address in (_ADDR, _OTHER):
        assert record_floor_witness(db_session, chain_id=1, address=address, outcome=WITNESS_FAILED) is None
    after = {(r.address, r.outcome, r.attempts, r.witnessed_at) for r in (_row(db_session), _row(db_session, _OTHER))}
    assert after == before


def test_proof_never_overturns_a_prior_incarnation_of_the_same_seed(db_session):
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PRIOR_INCARNATION, seed_block=_SEED)
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    assert _row(db_session).outcome == "prior_incarnation"
    assert _witness(db_session) == (None, "not_determined")
    # The verdict is about one number; a different seed can still be proven.
    record_floor_witness(db_session, chain_id=1, address=_ADDR, outcome=WITNESS_PROVEN, first_indexed_block=_SEED + 7)
    assert _witness(db_session) == (_SEED + 7, FIRST_INDEXED_BASIS_CREATION)


@pytest.mark.parametrize(
    ("outcome", "basis", "block", "retry"),
    [
        ("proven", "not_determined", None, False),
        ("failed", "creation_block_minus_one", 5, True),
        ("prior_incarnation", "creation_block_minus_one", 5, False),
        ("failed", "not_determined", None, False),
        ("proven", "creation_block_minus_one", 5, True),
        ("bogus", "not_determined", None, False),
    ],
)
def test_check_constraints_reject_inconsistent_rows(db_session, outcome, basis, block, retry):
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        db_session.execute(
            text(
                "INSERT INTO address_floor_witnesses (chain_id, address, first_indexed_block, basis, outcome, "
                "next_attempt_at) VALUES (1, :a, :b, :basis, :outcome, CASE WHEN :retry THEN now() END)"
            ),
            {"a": _ADDR, "b": block, "basis": basis, "outcome": outcome, "retry": retry},
        )
    db_session.rollback()


def test_witness_failure_after_the_alert_threshold_warns(db_session, wire, caplog):
    wire(fail=True)
    for _ in range(4):
        _witness_seed_block(_ADDR, _SEED, {}, chain_id=1, session=db_session)
    assert not [r for r in caplog.records if "keeps failing" in r.getMessage()]
    with caplog.at_level("WARNING", logger="workers.event_log_indexer"):
        _witness_seed_block(_ADDR, _SEED, {}, chain_id=1, session=db_session)
    alerts = [r for r in caplog.records if "keeps failing" in r.getMessage()]
    assert len(alerts) == 1 and getattr(alerts[0], "attempts") == 5


def test_enrolment_records_the_seed_whatever_the_witness_says(db_session, wire):
    wire(fail=True)
    caches = EnrollmentCaches()
    assert _enroll_witnessed(
        db_session,
        chain_id=1,
        address=_ADDR,
        topic0=_TOPIC,
        seed_cache=caches.seeds,
        witness_cache=caches.witnesses,
        enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
    )
    cursor = db_session.execute(select(IndexedEventCursor)).scalar_one()
    assert (cursor.enrolled_seed_block, cursor.first_indexed_block, cursor.first_indexed_block_basis) == (
        _SEED,
        None,
        "not_determined",
    )
    row = _row(db_session)
    assert (row.outcome, row.seed_block, row.attempts) == ("failed", _SEED, 1)


def test_retry_migration_classifies_existing_rows_and_round_trips(db_session):
    retry_columns = _load_migration(_RETRY_MIGRATION)
    connection = db_session.connection()
    with Operations.context(MigrationContext.configure(connection)):
        retry_columns.downgrade()
        assert "outcome" not in _columns(connection, "address_floor_witnesses")
        assert "enrolled_seed_block" not in _columns(connection, "indexed_event_cursors")
        connection.execute(
            text(
                "INSERT INTO address_floor_witnesses (chain_id, address, first_indexed_block, basis) VALUES "
                "(1, :proven, 123, 'creation_block_minus_one'), (1, :conflict, NULL, 'not_determined')"
            ),
            {"proven": _ADDR, "conflict": _OTHER},
        )
        retry_columns.upgrade()
        rows = {
            r.address: (r.outcome, r.seed_block, r.attempts, r.next_attempt_at is not None)
            for r in connection.execute(text("SELECT * FROM address_floor_witnesses"))
        }
        assert rows == {_ADDR: ("proven", 123, 0, False), _OTHER: ("cursor_conflict", None, 0, True)}
        due = connection.execute(
            text("SELECT next_attempt_at <= now() FROM address_floor_witnesses WHERE address = :a"), {"a": _OTHER}
        ).scalar_one()
        assert due
        assert {"enrolled_seed_block", "request_span_limit"} <= _columns(connection, "indexed_event_cursors")
    db_session.rollback()


def _columns(connection, table: str) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = :t"), {"t": table}
        )
    }
