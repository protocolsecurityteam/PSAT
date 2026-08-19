"""Architectural invariant: ``materialize_or_wait`` must not hold the
``(chain, bytecode_keccak)`` advisory lock — or any open transaction on
the cache session — during ``builder()``.

The builder is the forge+Slither pipeline; on real contracts that runs
for 1-3 minutes. Holding a Postgres connection idle for that long trips
Neon's pooler-side SSL idle timeout: the final ``UPSERT ... status='ready'``
returns ``psycopg2.OperationalError: SSL connection has been closed
unexpectedly``, the cache row is never written, and the recursive
resolver's catch-all (`services/resolution/recursive.py`) falls back to
rebuilding the same bytecode again. We saw this happen ~21 times across
4 days and 5 PR previews before this test was added.

This test exercises the invariant directly: from inside the builder we
open a separate session and ask Postgres whether the advisory lock for
this (chain, keccak) is currently free via ``pg_try_advisory_xact_lock``.
If the cache layer has released it, the probe acquires it and we
``ROLLBACK`` to release. If the cache layer is still holding it (the
broken shape), the probe returns false and the test fails with the
diagnostic below.

The probe also rolls back so it never leaves the lock held — the outer
``materialize_or_wait`` is free to re-acquire it for its short write tx.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import contract_materializations as cm  # noqa: E402
from db.models import ContractMaterialization  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402


@pytest.fixture()
def _clean_cm(db_session):
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    yield db_session
    db_session.query(ContractMaterialization).delete()
    db_session.commit()


@pytest.fixture()
def _route_to_test_db(monkeypatch):
    """Point ``db.contract_materializations.SessionLocal`` at the test DB.

    Mirrors the fixture in ``test_contract_materializations_blob.py`` —
    duplicated rather than promoted to conftest so this file remains a
    standalone reproduction of the bug.
    """
    import os

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")

    engine = create_engine(test_url)
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("db.contract_materializations.SessionLocal", factory)
    yield
    engine.dispose()


@requires_postgres
def test_materialize_does_not_hold_advisory_lock_during_builder(_route_to_test_db, _clean_cm):
    """The cache layer must release the ``(chain, keccak)`` advisory lock
    before invoking ``builder()``.

    A separate session inside the builder probes the same lock with
    ``pg_try_advisory_xact_lock``. The probe rolls back regardless so it
    can't itself starve the outer call's later write tx.
    """
    chain = "ethereum"
    keccak = "0x" + "12" * 32
    lock_key = f"{chain}:{keccak}"

    state: dict[str, Any] = {"lock_free_during_builder": None}

    def _builder() -> dict[str, Any]:
        with cm.SessionLocal() as probe:
            try:
                got = probe.execute(
                    text("SELECT pg_try_advisory_xact_lock(hashtext(:k))"),
                    {"k": lock_key},
                ).scalar()
                state["lock_free_during_builder"] = bool(got)
            finally:
                # Release whatever the probe acquired so the outer call's
                # short write-phase lock attempt can proceed.
                probe.rollback()
        return {
            "contract_name": "LockReleaseTest",
            "analysis": {"controllers": []},
            "tracking_plan": {"slots": []},
        }

    with patch("db.contract_materializations.get_storage_client", return_value=None):
        row = cm.materialize_or_wait(
            chain=chain,
            address="0x" + "9" * 40,
            bytecode_keccak=keccak,
            builder=_builder,
        )

    assert state["lock_free_during_builder"] is True, (
        "advisory lock was held during builder() — long forge builds will "
        "stall the Postgres connection idle and trip Neon's SSL timeout. "
        "Restructure materialize_or_wait so the lock is released before "
        "the builder runs and reacquired briefly for the final upsert."
    )
    # Sanity: the bundle still landed.
    assert row.status == "ready"
    assert row.contract_name == "LockReleaseTest"
