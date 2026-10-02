"""``builder()`` runs forge+Slither for minutes, and holding the lock or a transaction that long tripped Neon's SSL
idle timeout, so the cache row never landed and the same bytecode was rebuilt ~21 times. A separate session probes
the lock from inside the builder.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from sqlalchemy import text

from db import contract_materializations as cm
from tests.conftest import requires_postgres
from tests.support.materializations import (
    _clean_cm,  # noqa: F401  (fixture, registered by import)
    _route_to_test_db,  # noqa: F401  (fixture, registered by import)
)


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
