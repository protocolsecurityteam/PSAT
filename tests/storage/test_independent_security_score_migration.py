"""Run the frozen score-pairing migration against isolated temporary tables."""

from __future__ import annotations

import importlib.util
from decimal import Decimal
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from tests.conftest import requires_postgres


@requires_postgres
def test_independent_score_migration_preserves_numbers_and_refuses_lossy_rollback(db_session):
    path = Path(__file__).parents[2] / "alembic/versions/e1b72d9a640c_independent_security_score.py"
    spec = importlib.util.spec_from_file_location("independent_score_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    connection = db_session.connection()
    # PostgreSQL temporary tables shadow the application tables only on this
    # connection; no existing score, protocol or queue record is changed.
    connection.execute(
        text(f"""
        CREATE TEMP TABLE protocol_scores (
            id integer PRIMARY KEY, grade_state text NOT NULL,
            grade_lambda numeric, confidence_pct numeric, grade_exposure numeric,
            CONSTRAINT ck_protocol_scores_grade_pairing CHECK ({migration._OLD_PAIRING})
        ) ON COMMIT DROP
    """)
    )
    connection.execute(text("CREATE TEMP TABLE protocols (id integer PRIMARY KEY) ON COMMIT DROP"))
    connection.execute(
        text("""CREATE TEMP TABLE protocol_score_queue (
        protocol_id integer PRIMARY KEY, reason text, dirty_at timestamptz
    ) ON COMMIT DROP""")
    )
    connection.execute(text("INSERT INTO protocols VALUES (1),(2)"))
    connection.execute(text("INSERT INTO protocol_score_queue VALUES (1,'previous',now())"))
    connection.execute(text("INSERT INTO protocol_scores VALUES (1,'computed',80,25,50)"))
    connection.execute(text("INSERT INTO protocol_scores VALUES (2,'not_determined',NULL,NULL,NULL)"))
    context = MigrationContext.configure(connection)
    with Operations.context(context):
        migration.upgrade()
    assert (
        connection.execute(
            text("SELECT count(*) FROM protocol_score_queue WHERE reason='independent_security_score'")
        ).scalar()
        == 2
    )
    connection.execute(text("INSERT INTO protocol_scores VALUES (3,'computed',79.39,23,NULL)"))
    assert connection.execute(text("SELECT grade_lambda FROM protocol_scores WHERE id=3")).scalar() == Decimal("79.39")
    for values in [
        "(4,'computed',79,NULL,NULL)",
        "(4,'not_determined',79,23,NULL)",
        "(4,'not_determined',NULL,NULL,0)",
    ]:
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(text("INSERT INTO protocol_scores VALUES " + values))
    with pytest.raises(DBAPIError, match="computed rows with unknown exposure exist"), connection.begin_nested():
        with Operations.context(context):
            migration.downgrade()
    # Refused rollback preserves both the score and its unknown exposure.
    assert connection.execute(text("SELECT grade_exposure FROM protocol_scores WHERE id=3")).scalar() is None
    connection.execute(text("DELETE FROM protocol_scores WHERE id=3"))
    with Operations.context(context):
        migration.downgrade()
        migration.upgrade()
    assert connection.execute(text("SELECT grade_lambda FROM protocol_scores WHERE id=1")).scalar() == 80
    db_session.rollback()
