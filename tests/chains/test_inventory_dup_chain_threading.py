"""[P2-pre] company/inventory persist chain threading (MULTICHAIN_INVARIANTS.md Appendix A).

Regression coverage for the duplicate-stub bug found in the PR-154 preview DB:
for 10 mainnet addresses, two unanalyzed Contract stubs coexisted — one
``chain=NULL`` (the defillama company-inventory persist path passing no chain)
and one ``chain='ethereum'`` written ~1 min later by the dapp-crawl persist path.
``NULL ≠ NULL`` defeats ``uq_contract_address_chain``, so the second writer minted
a duplicate instead of matching the first (invariants 1, 6, 12).

The fix lives in ``db.queue.bulk_upsert_discovered_contracts`` — the shared writer
for all three company-inventory sources (inventory, defillama, dapp_crawl): an
entry with no evidence chain of its own inherits the job's ``default_chain``, and
the dedup key is mainnet-coalesced (``NULL≡'ethereum'``) so writers match each
other's rows regardless of historical NULLs. No data backfill (decided in the
doc): reads keep the NULL≡mainnet coalescing convention.

Real-DB tests, because the fix hinges on the ``(address, chain)`` uniqueness grain
and the coalesced dedup — a mocked session can't exercise it.
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


# ---------------------------------------------------------------------------
# (a) defillama-then-dapp_crawl of the same mainnet address → ONE merged row
# ---------------------------------------------------------------------------


@requires_postgres
def test_defillama_then_dapp_crawl_same_mainnet_address_yields_one_row(db_session, proto_id):
    """The observed dup anatomy, with both writers now on the fix: a chainless
    defillama persist followed by a chainless dapp_crawl persist of the same
    mainnet address collapses to one row with unioned discovery_sources."""
    from db.models import Contract
    from db.queue import bulk_upsert_discovered_contracts

    addr = _addr()

    # Writer 1 (defillama): the scan couldn't attribute a chain → inherits the
    # job's mainnet chain instead of persisting NULL.
    bulk_upsert_discovered_contracts(
        db_session,
        protocol_id=proto_id,
        entries=[{"address": addr, "chain": None, "new_sources": ["defillama"]}],
        default_chain="ethereum",
    )
    db_session.commit()

    # Writer 2 (dapp_crawl, ~1 min later): same address, same mainnet job.
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
    # Writers nominate, never stamp (membership-gate invariant 1).
    assert row.protocol_id is None
    assert row.nominated_protocol_id == proto_id


@requires_postgres
def test_dapp_crawl_dedups_against_legacy_null_defillama_stub(db_session, proto_id):
    """Migration-realistic case: a legacy defillama write already persisted
    ``chain=NULL`` (pre-fix). A later mainnet dapp_crawl write must dedup against
    it via the coalesced key rather than mint a second stub — no backfill needed."""
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


# ---------------------------------------------------------------------------
# (b) same address on two evidence chains still yields two rows
# ---------------------------------------------------------------------------


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
    # Same address on two chains = two distinct deployments (invariant 1).
    assert {r.chain for r in rows} == {"ethereum", "base"}


@requires_postgres
def test_base_entry_does_not_dedup_against_legacy_null_row(db_session, proto_id):
    """A non-mainnet write must NOT collapse onto a legacy NULL (mainnet) stub:
    coalescing maps NULL→'ethereum', and 'base' ≠ 'ethereum', so they stay two rows."""
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


# ---------------------------------------------------------------------------
# (c) an 'unknown'-chains entry stays its own resolve-later bucket
# ---------------------------------------------------------------------------


@requires_postgres
def test_unknown_chain_entry_is_preserved_and_isolated(db_session, proto_id):
    """Design intent preserved: ``'unknown'`` is a real "resolve later" bucket
    (chain_resolver probes it), not absent evidence. It is never coerced to the
    job chain, and its coalesced key ('unknown' ≠ 'ethereum') keeps it from
    deduping against — or minting a dup against — a mainnet stub at the same address."""
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


# ---------------------------------------------------------------------------
# Worker-level: the defillama scan (spawned with no chain) never writes NULL
# ---------------------------------------------------------------------------


@requires_postgres
def test_defillama_worker_chainless_job_writes_ethereum_not_null(db_session, monkeypatch):
    """End-to-end for the writer that produced the NULL stubs: a defillama scan
    job whose request carries no chain persists ``chain='ethereum'`` (the mainnet
    edge default) for an address the scan couldn't attribute, not ``chain=NULL``."""
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
