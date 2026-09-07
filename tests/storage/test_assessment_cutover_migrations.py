"""Cutover guard and preservation of existing independent cursor provenance."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations

from db.models import ENROLLMENT_BASIS_PREDICATE_HINT, ENROLLMENT_BASIS_TRACKED_TOPICS, IndexedEventCursor
from services.monitoring.restaking_enrollment import PUBKEY_LINKED_TOPIC0, RESTAKING_FOLD_ENROLLMENT_BASIS
from tests.conftest import requires_postgres


def migration(filename):
    path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / filename
    spec = importlib.util.spec_from_file_location("cutover_migration", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_existing_database_requires_explicit_maintenance_acknowledgement(monkeypatch):
    module = migration("a8c2d4e6f901_contract_legacy_assessment.py")
    monkeypatch.setattr(
        module,
        "context",
        SimpleNamespace(
            config=SimpleNamespace(attributes={"assessment_fresh_database": False}),
            get_x_argument=lambda **_: {},
        ),
    )
    # No Alembic operations context exists: refusal must precede all DDL.
    with pytest.raises(RuntimeError, match="all old processes stopped"):
        module.upgrade()


@requires_postgres
def test_restaking_migration_preserves_progress_and_predicate_provenance(db_session, monkeypatch):
    module = migration("e27a490bc381_restaking_cursor_provenance.py")
    for index, basis in enumerate([ENROLLMENT_BASIS_TRACKED_TOPICS, ENROLLMENT_BASIS_PREDICATE_HINT], start=1):
        db_session.add(
            IndexedEventCursor(
                chain_id=1,
                event_address=f"0x{index:040x}",
                topic0=PUBKEY_LINKED_TOPIC0,
                last_indexed_block=12345,
                enrollment_basis=basis,
            )
        )
    db_session.flush()
    monkeypatch.setattr(module, "op", Operations(MigrationContext.configure(db_session.connection())))
    module.upgrade()
    db_session.expire_all()
    tracked = db_session.get(IndexedEventCursor, (1, f"0x{1:040x}", PUBKEY_LINKED_TOPIC0))
    predicate = db_session.get(IndexedEventCursor, (1, f"0x{2:040x}", PUBKEY_LINKED_TOPIC0))
    assert tracked is not None and predicate is not None
    assert tracked.enrollment_basis == RESTAKING_FOLD_ENROLLMENT_BASIS
    assert predicate.enrollment_basis == ENROLLMENT_BASIS_PREDICATE_HINT
    assert tracked.last_indexed_block == predicate.last_indexed_block == 12345
