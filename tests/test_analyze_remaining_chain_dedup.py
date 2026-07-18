"""F8 — analyze-remaining dedups a legacy NULL-chain contract within mainnet.

``queue`` for a discovered-but-unanalyzed Contract passed ``chain=contract.chain``
into ``find_existing_job_for_address``. For a legacy NULL-chain row that dropped
the chain filter entirely, so a job on ANOTHER chain at the same address could be
adopted. The call site now coalesces NULL→"ethereum" (the documented legacy
convention), keeping the dedup mainnet-scoped.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


@requires_postgres
def test_null_chain_contract_does_not_adopt_a_base_job(api_client, db_session):
    from db.models import Contract, Job, Protocol
    from db.queue import create_job

    proto = Protocol(name=f"f8-{uuid.uuid4().hex[:10]}")
    db_session.add(proto)
    db_session.commit()

    addr = _addr()

    # A job for the SAME address already exists on Base (chain_id 8453).
    base_job = create_job(db_session, {"address": addr, "chain": "base"})
    db_session.commit()
    assert base_job.chain_id == 8453

    # A legacy discovered-but-unanalyzed contract at that address with chain=NULL.
    contract = Contract(
        protocol_id=proto.id,
        address=addr,
        chain=None,
        contract_name="Legacy",
        job_id=None,
        discovery_sources=["inventory"],
    )
    db_session.add(contract)
    db_session.commit()

    r = api_client.post(f"/api/company/{proto.name}/analyze-remaining")
    assert r.status_code == 200, r.text

    db_session.expire_all()
    row = db_session.query(Contract).filter_by(protocol_id=proto.id, address=addr).one()
    # It must NOT have been bound to the Base job — dedup is mainnet-scoped now.
    assert row.job_id is not None
    assert row.job_id != base_job.id
    bound = db_session.query(Job).filter_by(id=row.job_id).one()
    assert bound.chain_id == 1  # a fresh mainnet job, not the base one


@requires_postgres
def test_null_chain_contract_adopts_an_existing_mainnet_job(api_client, db_session):
    """The positive arm: a NULL-chain contract still dedups against a real
    mainnet job at the same address (coalesced ethereum matches chain_id 1)."""
    from db.models import Contract, Protocol
    from db.queue import create_job

    proto = Protocol(name=f"f8m-{uuid.uuid4().hex[:10]}")
    db_session.add(proto)
    db_session.commit()

    addr = _addr()
    eth_job = create_job(db_session, {"address": addr, "chain": "ethereum"})
    db_session.commit()
    assert eth_job.chain_id == 1

    contract = Contract(
        protocol_id=proto.id,
        address=addr,
        chain=None,
        contract_name="Legacy",
        job_id=None,
        discovery_sources=["inventory"],
    )
    db_session.add(contract)
    db_session.commit()

    r = api_client.post(f"/api/company/{proto.name}/analyze-remaining")
    assert r.status_code == 200, r.text

    db_session.expire_all()
    row = db_session.query(Contract).filter_by(protocol_id=proto.id, address=addr).one()
    assert row.job_id == eth_job.id
