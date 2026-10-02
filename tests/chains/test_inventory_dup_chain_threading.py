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
