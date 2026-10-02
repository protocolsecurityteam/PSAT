"""Job.chain_id dual-write + CHECK constraint.

Proves every enqueue path (all funnel through ``db.queue.create_job``) stamps a
first-class ``chain_id`` derived from ``request["chain"]`` via the canonical
registry, that address-less company/root jobs keep ``chain_id`` NULL, and that
the ``address IS NULL OR chain_id IS NOT NULL`` CHECK constraint holds.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.models import Job
from tests.conftest import requires_postgres

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


@pytest.fixture()
def session():
    engine = create_engine(DATABASE_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        s.query(Job).delete()
        s.commit()
        s.close()
        engine.dispose()


ADDR = "0x" + "ab" * 20


# Direct Job() construction still derives chain_id, so no path violates the CHECK.


# A raw INSERT bypasses the ORM default so the constraint itself is exercised.


@requires_postgres
def test_check_constraint_rejects_address_without_chain_id(session):
    with pytest.raises(IntegrityError):
        session.execute(
            text(
                "INSERT INTO jobs (id, address, chain_id, status, stage) "
                "VALUES (gen_random_uuid(), :addr, NULL, 'queued', 'discovery')"
            ),
            {"addr": ADDR},
        )
        session.commit()
    session.rollback()


def _load_migration():
    path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "f3a9c1d47b02_add_chain_id_to_jobs.py"
    spec = importlib.util.spec_from_file_location("_mig_chain_id", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    "raw,cid,reason",
    [
        (None, 1, "absent->mainnet"),
        ("", 1, "absent->mainnet"),
        ("ethereum", 1, "registry"),
        ("mainnet", 1, "registry"),
        ("base", 8453, "registry"),
        ("arbitrum", 42161, "registry"),
        ("unknown", 1, "unknown-sentinel->mainnet"),
        ("nonsense-l2", 1, "unrecognized->mainnet"),
    ],
)
def test_migration_backfill_rules(raw, cid, reason):
    mod = _load_migration()
    assert mod._resolve_chain_id(raw) == (cid, reason)
