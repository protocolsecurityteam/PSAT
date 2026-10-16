"""Database errors reach the worker wrapped by SQLAlchemy, not as the driver's own types. A dropped connection or a
cancelled statement retries; an integrity, programming or data error stays terminal. Every error here is raised for real
against the test database.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import psycopg2
import pytest
import sqlalchemy.exc
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

from db.models import Contract, EffectiveFunction, Job, JobStage, JobStatus
from db.queue import create_job
from services.policy.effective_permissions_writer import write_effective_function_rows
from tests.cache_helpers import DATABASE_URL, requires_postgres
from tests.support.db_fixtures import (
    clean_jobs,  # noqa: F401  (fixture, registered by import)
    test_session_local,  # noqa: F401  (fixture, registered by import)
)
from workers.base import BaseWorker
from workers.retry_policy import classify

pytestmark = [requires_postgres]


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = create_engine(DATABASE_URL)
    try:
        yield engine
    finally:
        engine.dispose()


def _terminate(pid: int) -> None:
    killer = create_engine(DATABASE_URL)
    try:
        with killer.connect() as conn:
            conn.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
    finally:
        killer.dispose()


def _server_closed(conn: Connection) -> None:
    _terminate(conn.execute(text("SELECT pg_backend_pid()")).scalar_one())
    conn.execute(text("SELECT 1"))


def _driver_connection_closed(conn: Connection) -> None:
    dbapi_connection = conn.connection.dbapi_connection
    assert dbapi_connection is not None
    dbapi_connection.close()
    conn.execute(text("SELECT 1"))


def _statement_timeout(conn: Connection) -> None:
    conn.execute(text("SET statement_timeout = 1"))
    conn.execute(text("SELECT pg_sleep(1)"))


def _unique_violation(conn: Connection) -> None:
    conn.execute(text("CREATE TEMP TABLE retry_probe (id int PRIMARY KEY)"))
    conn.execute(text("INSERT INTO retry_probe VALUES (1), (1)"))


def _undefined_table(conn: Connection) -> None:
    conn.execute(text("SELECT * FROM retry_probe_missing"))


def _bad_cast(conn: Connection) -> None:
    conn.execute(text("SELECT 'not a number'::int"))


def _raised(engine: Engine, statement: Callable[[Connection], None]) -> sqlalchemy.exc.DBAPIError:
    with pytest.raises(sqlalchemy.exc.DBAPIError) as caught:
        with engine.connect() as conn:
            statement(conn)
    return caught.value


@pytest.mark.parametrize(
    "statement, wrapper, driver, expected",
    [
        pytest.param(
            _server_closed,
            sqlalchemy.exc.OperationalError,
            psycopg2.OperationalError,
            "transient",
            id="server-closed-connection",
        ),
        pytest.param(
            _driver_connection_closed,
            sqlalchemy.exc.InterfaceError,
            psycopg2.InterfaceError,
            "transient",
            id="driver-connection-closed",
        ),
        pytest.param(
            _statement_timeout,
            sqlalchemy.exc.OperationalError,
            psycopg2.errors.QueryCanceled,
            "transient",
            id="statement-timeout",
        ),
        pytest.param(
            _unique_violation, sqlalchemy.exc.IntegrityError, psycopg2.IntegrityError, "terminal", id="integrity"
        ),
        pytest.param(
            _undefined_table, sqlalchemy.exc.ProgrammingError, psycopg2.ProgrammingError, "terminal", id="programming"
        ),
        pytest.param(_bad_cast, sqlalchemy.exc.DataError, psycopg2.DataError, "terminal", id="data"),
    ],
)
def test_a_wrapped_driver_error_is_classified_by_what_it_wraps(engine, statement, wrapper, driver, expected):
    exc = _raised(engine, statement)

    assert type(exc) is wrapper
    assert isinstance(exc.orig, driver)
    assert not isinstance(exc, driver)
    assert classify(exc) == expected


class _PolicyLikeWorker(BaseWorker):
    """Replaces a contract's ``effective_functions`` rows the way the policy stage does; the first attempt's connection
    drops before the replace commits."""

    stage = JobStage.policy
    next_stage = JobStage.done
    poll_interval = 0.0

    def __init__(self, contract_id: int, records: list[dict]):
        super().__init__()
        self.contract_id = contract_id
        self.records = records
        self.attempts = 0

    def process(self, session, job):
        self.attempts += 1
        write_effective_function_rows(
            session, contract_id=self.contract_id, function_records=self.records, capability_by_function=None
        )
        if self.attempts == 1:
            _terminate(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
        session.commit()


def _rows(session, contract_id: int) -> list[str]:
    session.expire_all()
    return sorted(
        fn.abi_signature
        for fn in session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract_id).all()
    )


def test_a_dropped_connection_mid_write_requeues_and_the_retry_writes_once(clean_jobs, test_session_local):
    session = clean_jobs
    job_row = create_job(session, {"address": "0x" + "d9" * 20, "name": "dropped", "chain": "ethereum"})
    job_row.stage = JobStage.policy
    contract = Contract(address=job_row.address, chain="ethereum", job_id=job_row.id)
    session.add(contract)
    session.commit()
    records = [{"function": f"set{i}(uint256)", "abi_signature": f"set{i}(uint256)"} for i in range(200)]
    worker = _PolicyLikeWorker(contract.id, records)

    try:
        worker._execute_job(session, session.get(Job, job_row.id))

        session.expire_all()
        retried = session.get(Job, job_row.id)
        assert retried is not None
        assert (retried.status, retried.retry_count, retried.last_failure_kind) == (JobStatus.queued, 1, "transient")
        assert retried.next_attempt_at is not None
        # The replace rolled back whole: no partial set for a reader to take as complete.
        assert _rows(session, contract.id) == []

        worker._execute_job(session, retried)

        session.expire_all()
        done = session.get(Job, job_row.id)
        assert done is not None
        assert (done.status, done.stage) == (JobStatus.completed, JobStage.done)
        assert _rows(session, contract.id) == sorted(r["abi_signature"] for r in records)
    finally:
        session.rollback()
        session.query(Contract).filter(Contract.id == contract.id).delete()
        session.commit()
