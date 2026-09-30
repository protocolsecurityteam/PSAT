"""Company/inventory persist chain threading.

Regression for the PR-154 preview DB: 10 mainnet addresses had two stubs, one ``chain=NULL`` (defillama
persist, no chain) and one ``'ethereum'`` (dapp-crawl persist ~1 min later); ``NULL ≠ NULL`` defeats
``uq_contract_address_chain``.

Fix is in ``db.queue.bulk_upsert_discovered_contracts``: entries without an evidence chain inherit the
job's ``default_chain`` and the dedup key is mainnet-coalesced (``NULL≡'ethereum'``). No backfill.

Real-DB tests: a mocked session can't exercise the uniqueness grain or the coalesced dedup.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import requires_postgres


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


@pytest.fixture()
def proto_id(db_session):
    from db.models import Protocol

    p = Protocol(name=f"inv-dup-{uuid.uuid4().hex[:10]}")
    db_session.add(p)
    db_session.commit()
    return p.id


@requires_postgres
def test_defillama_then_dapp_crawl_same_mainnet_address_yields_one_row(db_session, proto_id):
    from db.models import Contract
    from db.queue import bulk_upsert_discovered_contracts

    addr = _addr()

    # The scan couldn't attribute a chain, so it inherits the job's.
    bulk_upsert_discovered_contracts(
        db_session,
        protocol_id=proto_id,
        entries=[{"address": addr, "chain": None, "new_sources": ["defillama"]}],
        default_chain="ethereum",
    )
    db_session.commit()

    bulk_upsert_discovered_contracts(
        db_session,
        protocol_id=proto_id,
        entries=[{"address": addr, "chain": None, "new_sources": ["dapp_crawl"]}],
        default_chain="ethereum",
    )
    db_session.commit()

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.chain == "ethereum"
    assert set(row.discovery_sources or []) == {"defillama", "dapp_crawl"}
    # Writers nominate, never stamp.
    assert row.protocol_id is None
    assert row.nominated_protocol_id == proto_id


@requires_postgres
def test_dapp_crawl_dedups_against_legacy_null_defillama_stub(db_session, proto_id):
    from db.models import Contract
    from db.queue import bulk_upsert_discovered_contracts

    addr = _addr()
    db_session.add(Contract(address=addr, chain=None, protocol_id=proto_id, discovery_sources=["defillama"]))
    db_session.commit()

    bulk_upsert_discovered_contracts(
        db_session,
        protocol_id=proto_id,
        entries=[{"address": addr, "chain": None, "new_sources": ["dapp_crawl"]}],
        default_chain="ethereum",
    )
    db_session.commit()

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    assert len(rows) == 1  # enriched the legacy NULL row, not a duplicate.
    row = rows[0]
    assert row.chain is None  # decided: no backfill; NULL≡mainnet convention kept.
    assert set(row.discovery_sources or []) == {"defillama", "dapp_crawl"}
    assert row.protocol_id == proto_id


@requires_postgres
def test_same_address_two_evidence_chains_yields_two_rows(db_session, proto_id):
    from db.models import Contract
    from db.queue import bulk_upsert_discovered_contracts

    addr = _addr()
    bulk_upsert_discovered_contracts(
        db_session,
        protocol_id=proto_id,
        entries=[{"address": addr, "chain": "ethereum", "new_sources": ["defillama"]}],
        default_chain="ethereum",
    )
    bulk_upsert_discovered_contracts(
        db_session,
        protocol_id=proto_id,
        entries=[{"address": addr, "chain": "base", "new_sources": ["defillama"]}],
        default_chain="base",
    )
    db_session.commit()

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    # Same address on two chains = two distinct deployments.
    assert {r.chain for r in rows} == {"ethereum", "base"}


@requires_postgres
def test_base_entry_does_not_dedup_against_legacy_null_row(db_session, proto_id):
    """NULL coalesces to 'ethereum', which is not 'base'."""
    from db.models import Contract
    from db.queue import bulk_upsert_discovered_contracts

    addr = _addr()
    db_session.add(Contract(address=addr, chain=None, protocol_id=proto_id, discovery_sources=["defillama"]))
    db_session.commit()

    bulk_upsert_discovered_contracts(
        db_session,
        protocol_id=proto_id,
        entries=[{"address": addr, "chain": "base", "new_sources": ["defillama"]}],
        default_chain="base",
    )
    db_session.commit()

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    assert {r.chain for r in rows} == {None, "base"}


@requires_postgres
def test_unknown_chain_entry_is_preserved_and_isolated(db_session, proto_id):
    """'unknown' is a real resolve-later bucket that chain_resolver probes."""
    from db.models import Contract
    from db.queue import bulk_upsert_discovered_contracts

    addr = _addr()
    bulk_upsert_discovered_contracts(
        db_session,
        protocol_id=proto_id,
        entries=[{"address": addr, "chain": "ethereum", "new_sources": ["defillama"]}],
        default_chain="ethereum",
    )
    db_session.commit()

    bulk_upsert_discovered_contracts(
        db_session,
        protocol_id=proto_id,
        entries=[{"address": addr, "chain": "unknown", "new_sources": ["inventory"]}],
        default_chain="ethereum",
    )
    db_session.commit()

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    assert {r.chain for r in rows} == {"ethereum", "unknown"}


@requires_postgres
def test_defillama_worker_chainless_job_writes_ethereum_not_null(db_session, monkeypatch):
    from db.models import Contract, JobStage
    from db.queue import create_job
    from workers.base import JobHandledDirectly
    from workers.defillama_worker import DefiLlamaWorker

    addr = _addr()
    job = create_job(
        db_session,
        {"defillama_protocol": "aave-v3", "company": f"AaveDup{uuid.uuid4().hex[:6]}"},
        initial_stage=JobStage.defillama_scan,
    )

    monkeypatch.setattr(
        "workers.defillama_worker.scan_protocol",
        lambda **kw: {"addresses": [addr], "scan_time": 1.0, "address_details": []},
    )
    monkeypatch.setattr(
        "workers.defillama_worker.resolve_protocol",
        lambda name: {"slug": None, "url": None, "name": None, "chains": [], "all_slugs": [], "all_names": []},
    )
    worker = DefiLlamaWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)

    row = db_session.query(Contract).filter(Contract.address == addr).one()
    assert row.chain == "ethereum"
    assert "defillama" in (row.discovery_sources or [])
