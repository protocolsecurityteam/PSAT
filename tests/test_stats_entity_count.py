"""``/api/stats`` counts entities as (chain_id, address), not bare addresses.

A CREATE2 twin is one address on two chains — two distinct entities. The
unique-address stat must count them as two, matching the multichain entity
model (inv. 12).
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


def _can_connect() -> bool:
    if not DATABASE_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


def _no_auth(api_module):
    from routers.deps import require_admin_key

    api_module.app.dependency_overrides[require_admin_key] = lambda: None


@requires_postgres
def test_stats_counts_twin_as_two_entities(api_client, db_session):
    import api as api_module
    from db.models import Job, JobStage, JobStatus

    _no_auth(api_module)
    address = "0x" + "ab" * 20
    now = datetime.now(timezone.utc)
    for chain_id in (1, 8453):
        db_session.add(
            Job(
                address=address,
                chain_id=chain_id,
                request={"address": address, "chain": "ethereum" if chain_id == 1 else "base"},
                status=JobStatus.completed,
                stage=JobStage.done,
                created_at=now,
                updated_at=now,
            )
        )
    db_session.commit()

    resp = api_client.get("/api/stats")
    assert resp.status_code == 200
    assert resp.json()["unique_addresses"] == 2
