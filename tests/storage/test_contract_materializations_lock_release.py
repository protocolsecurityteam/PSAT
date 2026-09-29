"""Architectural invariant: ``materialize_or_wait`` must not hold the ``(chain, bytecode_keccak)``
advisory lock, or any open transaction on the cache session, during ``builder()``.

The builder is the forge+Slither pipeline (1-3 minutes on real contracts); an idle connection that
long trips Neon's pooler SSL idle timeout, so the final ``UPSERT ... status='ready'`` fails, the
cache row is never written and the recursive resolver rebuilds the same bytecode (seen ~21 times
over 4 days and 5 PR previews). From inside the builder a separate session probes the lock with
``pg_try_advisory_xact_lock`` (and rolls back so the outer call can re-acquire it); a false
probe means the cache layer is still holding it.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import text

from db import contract_materializations as cm
from db.models import ContractMaterialization
from tests.conftest import requires_postgres


@pytest.fixture()
def _clean_cm(db_session):
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    yield db_session
    db_session.query(ContractMaterialization).delete()
    db_session.commit()


@pytest.fixture()
def _route_to_test_db(monkeypatch):
    """Point ``db.contract_materializations.SessionLocal`` at the test DB (duplicated from
    ``test_contract_materializations_blob.py`` so this file stays a standalone reproduction)."""
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
                # Release the probe lock so the outer write-phase attempt can proceed.
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
    assert row.status == "ready"
    assert row.contract_name == "LockReleaseTest"
