"""Resolution-worker discovered-contract spawn dedup must be case-insensitive
and chain-scoped: a checksummed-address job cannot be duplicated by a lowercase
cascade spawn, and a same-address job on another chain must not suppress this
chain's child (inv. 12).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func

from tests.conftest import requires_postgres  # noqa: E402


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


def _graph(parent_addr: str, child_addr: str) -> dict:
    return {
        "root_contract_address": parent_addr,
        "nodes": [{"address": child_addr, "analyzed": True, "node_type": "contract", "contract_name": "Child"}],
    }


@requires_postgres
def test_spawn_dedup_is_case_insensitive(db_session):
    from db.models import Job
    from db.queue import create_job
    from workers.resolution_worker import ResolutionWorker

    parent_addr, child_addr = _addr(), _addr()
    parent = create_job(db_session, {"address": parent_addr})
    # An admin-submitted job stored with a checksummed address at the same
    # contract the cascade is about to discover (lowercase).
    create_job(db_session, {"address": child_addr[:2] + child_addr[2:].upper()})
    db_session.commit()

    ResolutionWorker()._queue_discovered_contracts(db_session, parent, _graph(parent_addr, child_addr), "http://r.l")

    assert db_session.query(Job).filter(func.lower(Job.address) == child_addr).count() == 1


@requires_postgres
def test_spawn_dedup_is_chain_scoped(db_session, monkeypatch):
    from db.models import Job
    from db.queue import create_job
    from workers.resolution_worker import ResolutionWorker

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    parent_addr, child_addr = _addr(), _addr()
    parent = create_job(db_session, {"address": parent_addr, "chain": "base"})
    # A same-address twin job on ANOTHER chain must not suppress the base child.
    create_job(db_session, {"address": child_addr, "chain": "ethereum"})
    db_session.commit()

    ResolutionWorker()._queue_discovered_contracts(db_session, parent, _graph(parent_addr, child_addr), "http://r.l")

    base_jobs = db_session.query(Job).filter(func.lower(Job.address) == child_addr).filter(Job.chain_id == 8453).count()
    assert base_jobs == 1
