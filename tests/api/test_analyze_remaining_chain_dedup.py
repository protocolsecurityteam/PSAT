"""F8 — analyze-remaining dedups a legacy NULL-chain contract within mainnet.

``queue`` for a discovered-but-unanalyzed Contract passed ``chain=contract.chain``
into ``find_existing_job_for_address``. For a legacy NULL-chain row that dropped
the chain filter entirely, so a job on ANOTHER chain at the same address could be
adopted. The call site now coalesces NULL→"ethereum" (the documented legacy
convention), keeping the dedup mainnet-scoped.
"""

from __future__ import annotations

import uuid

from tests.conftest import requires_postgres


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
def test_off_allowlist_chain_stub_is_not_queued(api_client, db_session, monkeypatch):
    """Inv. 14: analyze-remaining applies the same deployment allowlist gate as
    the selection worker — a discovered stub on a non-enabled chain is skipped
    (evidence kept, no job spawned); enabled-chain stubs still queue."""
    from db.models import Contract, Protocol

    monkeypatch.delenv("PSAT_SUPPORTED_CHAIN_IDS", raising=False)  # mainnet-only

    proto = Protocol(name=f"f14-{uuid.uuid4().hex[:10]}")
    db_session.add(proto)
    db_session.commit()

    base_addr, eth_addr = _addr(), _addr()
    db_session.add(
        Contract(
            protocol_id=proto.id,
            address=base_addr,
            chain="base",
            contract_name="BaseStub",
            job_id=None,
            discovery_sources=["inventory"],
        )
    )
    db_session.add(
        Contract(
            protocol_id=proto.id,
            address=eth_addr,
            chain="ethereum",
            contract_name="EthStub",
            job_id=None,
            discovery_sources=["inventory"],
        )
    )
    db_session.commit()

    r = api_client.post(f"/api/company/{proto.name}/analyze-remaining")
    assert r.status_code == 200, r.text

    db_session.expire_all()
    base_row = db_session.query(Contract).filter_by(protocol_id=proto.id, address=base_addr).one()
    eth_row = db_session.query(Contract).filter_by(protocol_id=proto.id, address=eth_addr).one()
    assert base_row.job_id is None  # skipped, not spawned
    assert eth_row.job_id is not None  # enabled chain still queues


@requires_postgres
def test_allowlisted_chain_stub_still_queues(api_client, db_session, monkeypatch):
    """Positive arm: with base allowlisted, the same stub queues a base job."""
    from db.models import Contract, Job, Protocol

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")

    proto = Protocol(name=f"f14b-{uuid.uuid4().hex[:10]}")
    db_session.add(proto)
    db_session.commit()

    addr = _addr()
    db_session.add(
        Contract(
            protocol_id=proto.id,
            address=addr,
            chain="base",
            contract_name="BaseStub",
            job_id=None,
            discovery_sources=["inventory"],
        )
    )
    db_session.commit()

    r = api_client.post(f"/api/company/{proto.name}/analyze-remaining")
    assert r.status_code == 200, r.text

    db_session.expire_all()
    row = db_session.query(Contract).filter_by(protocol_id=proto.id, address=addr).one()
    assert row.job_id is not None
    assert db_session.query(Job).filter_by(id=row.job_id).one().chain_id == 8453


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
