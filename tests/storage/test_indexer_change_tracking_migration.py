"""Exercise queue bootstrap on pre-existing sources, with transactional DDL."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import delete, func, select, text, update

from db.models import IndexerWork, Job, JobStage, JobStatus, MonitoredContract
from tests.conftest import requires_postgres


@requires_postgres
def test_queue_migration_round_trip_seeds_every_existing_source(db_session):
    path = Path(__file__).resolve().parents[2] / "alembic/versions/c4e8f2a06b93_indexer_change_tracking.py"
    spec = importlib.util.spec_from_file_location("_indexer_work_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    connection = db_session.connection()
    # Both directions happen inside an outer transaction. Rollback restores the
    # head schema and data; no database creation or global fixture mutation.
    with Operations.context(MigrationContext.configure(connection)):
        migration.downgrade()
        assert connection.execute(text("SELECT to_regclass('indexer_work')")).scalar_one() is None
        db_session.execute(delete(Job))
        db_session.execute(delete(MonitoredContract))
        db_session.add_all(
            [
                Job(address=f"0x{i + 1:040x}", chain_id=1, status=JobStatus.completed, stage=JobStage.done)
                for i in range(501)
            ]
        )
        db_session.add(Job(address="0x" + "ff" * 20, chain_id=8453, status=JobStatus.queued, stage=JobStage.discovery))
        db_session.add_all(
            [
                MonitoredContract(address="0x" + "ee" * 20, chain="ethereum", is_active=True),
                MonitoredContract(address="0x" + "dd" * 20, chain="ethereum", is_active=False),
            ]
        )
        db_session.flush()
        migration.upgrade()
        counts = dict(db_session.execute(select(IndexerWork.kind, func.count()).group_by(IndexerWork.kind)).all())
        assert counts == {"job": 501, "monitored": 1, "reconcile": 2}
        db_session.execute(update(Job).where(Job.status == JobStatus.queued).values(status=JobStatus.completed))
        assert (
            db_session.execute(
                select(func.count()).select_from(IndexerWork).where(IndexerWork.kind == "job")
            ).scalar_one()
            == 502
        )
    db_session.rollback()
