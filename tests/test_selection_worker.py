"""Integration tests for the ``SelectionWorker``.

The selection stage unifies the three discovery sources (inventory,
DApp crawl, DefiLlama scan) into a single ranked pass: every
discovered contract competes for the ``analyze_limit`` budget on
equal footing, so the right outcome is driven by rank order across
sources rather than first-writer-wins.

These tests run against a real Postgres session (``db_session``
fixture) and exercise the worker's two claim paths, the confidence
filter, the default-confidence shim for sources that don't ship a
score, and the dedup + proxy re-queue branch that coverage-level
behavior relies on.
"""

from __future__ import annotations

import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy import update as sa_update

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402
from workers.base import JobHandledDirectly  # noqa: E402

pytestmark = [requires_postgres]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _stub_activity_fetch(monkeypatch):
    """Replace the Etherscan activity fetch with a deterministic local lookup.

    ``enrich_with_activity`` calls ``services.discovery.activity.etherscan.get``
    once per contract; stubbing at that seam keeps the real scoring math in
    the loop while removing network traffic. Individual tests can override
    ``_ACTIVITY_TIMES`` to control ranking.
    """
    from services.discovery import activity as activity_module

    def fake_etherscan_get(module, action, **params):
        addr = str(params.get("address", "")).lower()
        ts = _ACTIVITY_TIMES.get(addr)
        if ts is not None:
            return {"result": [{"timeStamp": str(int(ts))}]}
        return {"result": []}

    monkeypatch.setattr(activity_module.etherscan, "get", fake_etherscan_get)


# Mutable mapping used by the stub above. Tests populate it in arrange.
_ACTIVITY_TIMES: dict[str, float] = {}


@pytest.fixture(autouse=True)
def _reset_activity_times():
    _ACTIVITY_TIMES.clear()
    yield
    _ACTIVITY_TIMES.clear()


@pytest.fixture()
def worker():
    """SelectionWorker with signal handlers patched so pytest stays clean."""
    from workers.selection_worker import SelectionWorker

    with patch("signal.signal"):
        yield SelectionWorker()


@pytest.fixture()
def seed_protocol(db_session):
    """A bare Protocol row + id/name/address_factory, with cleanup on teardown.

    ``address_factory`` hands out globally unique 20-byte addresses so
    tests don't collide with leftover rows under the ``(address, chain)``
    unique constraint.
    """
    from db.models import Contract, Job, Protocol

    name = f"sel-worker-{uuid.uuid4().hex[:10]}"
    protocol = Protocol(name=name)
    db_session.add(protocol)
    db_session.commit()
    protocol_id = protocol.id

    minted: list[str] = []

    def address_factory() -> str:
        raw = uuid.uuid4().hex  # 32 hex chars
        addr = ("0x" + raw + "0" * 8).lower()
        minted.append(addr)
        return addr

    try:
        yield protocol_id, name, address_factory
    finally:
        db_session.rollback()
        child_jobs = db_session.query(Job).filter(Job.request["protocol_id"].as_integer() == protocol_id).all()
        for job in child_jobs:
            db_session.delete(job)
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        if minted:
            db_session.query(Contract).filter(Contract.address.in_(minted)).delete(synchronize_session=False)
            db_session.query(Job).filter(Job.address.in_(minted)).delete(synchronize_session=False)
        db_session.query(Job).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


def _add_contract(
    session,
    *,
    protocol_id: int,
    address: str,
    discovery_sources: list[str] | str | None,
    confidence: float | None = None,
    name: str | None = None,
    chain: str | None = "ethereum",
    is_proxy: bool = False,
    job_id=None,
):
    """Insert a Contract row, accepting either ``discovery_sources`` list or a
    single string for convenience (tests that pre-date the array column)."""
    from db.models import Contract

    if isinstance(discovery_sources, str):
        sources = [discovery_sources]
    elif discovery_sources is None:
        sources = None
    else:
        sources = list(discovery_sources)

    row = Contract(
        protocol_id=protocol_id,
        address=address.lower(),
        chain=chain,
        contract_name=name,
        confidence=confidence,
        discovery_sources=sources,
        is_proxy=is_proxy,
        job_id=job_id,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def _add_selection_job(
    session,
    *,
    protocol_id: int,
    company: str,
    analyze_limit: int = 3,
    updated_at: datetime | None = None,
):
    from db.models import Job, JobStage, JobStatus

    job = Job(
        company=company,
        protocol_id=protocol_id,
        stage=JobStage.selection,
        status=JobStatus.queued,
        request={
            "company": company,
            "protocol_id": protocol_id,
            "analyze_limit": analyze_limit,
            "rpc_url": "https://rpc.example",
        },
    )
    session.add(job)
    session.commit()
    if updated_at is not None:
        session.execute(sa_update(Job).where(Job.id == job.id).values(updated_at=updated_at))
        session.commit()
        session.refresh(job)
    return job


def _add_sibling_job(
    session,
    *,
    stage,
    status,
    root_job_id: str,
):
    from db.models import Job

    job = Job(
        company="sibling",
        stage=stage,
        status=status,
        request={"root_job_id": root_job_id, "defillama_protocol": "sibling"},
    )
    session.add(job)
    session.commit()
    return job


# ---------------------------------------------------------------------------
# 1. Happy path: ranks across sources, writes top-N child jobs, completes
# ---------------------------------------------------------------------------


@requires_postgres
def test_selection_ranks_across_sources_and_queues_top_n(db_session, worker, seed_protocol):
    """All three discovery sources compete in one ranking pass.

    Seed: inventory (high confidence), dapp_crawl (null confidence → defaults
    to 0.7), defillama (null confidence → 0.7), plus one very-low-confidence
    inventory row that should be filtered out. Activity scores favour the
    dapp_crawl and one inventory row.
    """
    from db.models import Contract, Job, JobStage, JobStatus
    from db.queue import get_artifact

    protocol_id, company, addr = seed_protocol

    now = time.time()
    long_ago = now - 365 * 86400

    inv_top = addr()
    dapp_top = addr()
    defi_mid = addr()
    inv_lowconf = addr()
    inv_stale = addr()

    _add_contract(db_session, protocol_id=protocol_id, address=inv_top, discovery_sources="inventory", confidence=0.9)
    _add_contract(
        db_session, protocol_id=protocol_id, address=dapp_top, discovery_sources="dapp_crawl", confidence=None
    )
    _add_contract(db_session, protocol_id=protocol_id, address=defi_mid, discovery_sources="defillama", confidence=None)
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=inv_lowconf,
        discovery_sources="inventory",
        confidence=0.2,
    )
    _add_contract(db_session, protocol_id=protocol_id, address=inv_stale, discovery_sources="inventory", confidence=0.8)

    _ACTIVITY_TIMES.update(
        {
            inv_top: now,
            dapp_top: now,
            defi_mid: now - 30 * 86400,
            inv_stale: long_ago,
        }
    )

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=3)

    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)
    db_session.refresh(job)

    # Parent job finished and moved to done
    assert job.stage == JobStage.done
    assert job.status == JobStatus.completed

    # 3 child analysis jobs created
    children = (
        db_session.execute(select(Job).where(Job.request["parent_job_id"].as_string() == str(job.id))).scalars().all()
    )
    assert len(children) == 3
    child_addresses = {child.address for child in children}
    # Top three by rank_score: recent activity wins over stale inventory
    assert child_addresses == {inv_top, dapp_top, defi_mid}
    # The low-confidence inventory row was filtered; the stale one was ranked lower
    assert inv_lowconf not in child_addresses
    assert inv_stale not in child_addresses

    # Children carry the parent's protocol, lineage, and discovery_sources
    for child in children:
        req = child.request
        assert isinstance(req, dict)
        assert req["protocol_id"] == protocol_id
        assert req["root_job_id"] == str(job.id)
        assert req["parent_job_id"] == str(job.id)
        assert req["rpc_url"] == "https://rpc.example"
        assert any(s in {"inventory", "dapp_crawl", "defillama"} for s in req.get("discovery_sources", []))

    # Rank scores are persisted back onto the Contract rows so the UI
    # and the analyze-remaining fallback see the same ordering.
    ranked_rows = {
        row.address: row
        for row in db_session.execute(
            select(Contract).where(Contract.protocol_id == protocol_id, Contract.address.in_(child_addresses))
        )
        .scalars()
        .all()
    }
    assert all(row.rank_score is not None for row in ranked_rows.values())

    summary = get_artifact(db_session, job.id, "selection_summary")
    assert isinstance(summary, dict)
    assert summary["analyzed_count"] == 3
    assert summary["ranked_count"] >= 3
    assert len(summary["child_jobs"]) == 3


# ---------------------------------------------------------------------------
# 2. Confidence filter: everything below _MIN_CONFIDENCE_THRESHOLD is skipped
# ---------------------------------------------------------------------------


@requires_postgres
def test_selection_filters_below_confidence_threshold(db_session, worker, seed_protocol):
    from db.models import Job

    protocol_id, company, addr = seed_protocol

    # All three rows sit below the 0.3 threshold (dapp_crawl/defillama would
    # default to 0.7 if null — forcing a low value here keeps the filter honest)
    for source in ("inventory", "dapp_crawl", "defillama"):
        _add_contract(
            db_session,
            protocol_id=protocol_id,
            address=addr(),
            discovery_sources=source,
            confidence=0.1,
        )

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=5)
    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)
    db_session.refresh(job)

    assert job.status.value == "completed"
    children = (
        db_session.execute(select(Job).where(Job.request["parent_job_id"].as_string() == str(job.id))).scalars().all()
    )
    assert children == []


# ---------------------------------------------------------------------------
# 3. Default confidence applied to null dapp_crawl / defillama rows
# ---------------------------------------------------------------------------


@requires_postgres
def test_null_confidence_dapp_and_defillama_rows_participate(db_session, worker, seed_protocol):
    """Null-confidence dapp_crawl/defillama rows should clear the threshold.

    Without the default-confidence shim, a row with ``confidence=NULL`` would
    be filtered out. The selector applies a source-specific default (0.7 for
    on-chain-evidence sources) so those contracts get ranked at all.
    """
    from db.models import Job

    protocol_id, company, addr = seed_protocol
    target = addr()
    _add_contract(db_session, protocol_id=protocol_id, address=target, discovery_sources="dapp_crawl", confidence=None)

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=3)
    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)
    db_session.refresh(job)

    children = (
        db_session.execute(select(Job).where(Job.request["parent_job_id"].as_string() == str(job.id))).scalars().all()
    )
    assert [c.address for c in children] == [target]


# ---------------------------------------------------------------------------
# 4. upgrade_history rows are excluded from selection
# ---------------------------------------------------------------------------


@requires_postgres
def test_upgrade_history_rows_are_excluded(db_session, worker, seed_protocol):
    from db.models import Job

    protocol_id, company, addr = seed_protocol
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=addr(),
        discovery_sources="upgrade_history",
        confidence=0.9,
    )
    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=3)
    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)

    children = (
        db_session.execute(select(Job).where(Job.request["parent_job_id"].as_string() == str(job.id))).scalars().all()
    )
    assert children == []


# ---------------------------------------------------------------------------
# 5. Dedup: address with an existing non-proxy job is skipped
# ---------------------------------------------------------------------------


@requires_postgres
def test_existing_non_proxy_job_skips_address(db_session, worker, seed_protocol):
    """When a contract already has a live analysis job, the selector skips it.

    This prevents duplicate work across re-runs of a protocol. Proxies
    intentionally fall through to the re-queue branch exercised in the next
    test — they need re-analysis to catch upgrades.
    """
    from db.models import Job, JobStage, JobStatus

    protocol_id, company, addr = seed_protocol
    target = addr()
    _add_contract(db_session, protocol_id=protocol_id, address=target, discovery_sources="inventory", confidence=0.9)

    # Existing job for that address (not a proxy)
    existing = Job(
        address=target,
        stage=JobStage.static,
        status=JobStatus.processing,
        request={"address": target, "chain": "ethereum"},
    )
    db_session.add(existing)
    db_session.commit()

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=3)
    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)

    new_children = (
        db_session.execute(select(Job).where(Job.request["parent_job_id"].as_string() == str(job.id))).scalars().all()
    )
    assert new_children == []


# ---------------------------------------------------------------------------
# 6. Proxy re-queue branch: even with an existing job, proxies get re-queued
# ---------------------------------------------------------------------------


@requires_postgres
def test_proxy_with_existing_job_is_re_queued(db_session, worker, seed_protocol):
    from db.models import Job, JobStage, JobStatus

    protocol_id, company, addr = seed_protocol
    target = addr()
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=target,
        discovery_sources="inventory",
        confidence=0.9,
        is_proxy=True,
    )

    existing = Job(
        address=target,
        stage=JobStage.static,
        status=JobStatus.processing,
        request={"address": target, "chain": "ethereum"},
    )
    db_session.add(existing)
    db_session.commit()

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=3)
    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)

    new_children = (
        db_session.execute(select(Job).where(Job.request["parent_job_id"].as_string() == str(job.id))).scalars().all()
    )
    assert [c.address for c in new_children] == [target]


# ---------------------------------------------------------------------------
# 6b. Within-cascade dedupe predicate: the JSON filters, against real SQL
# ---------------------------------------------------------------------------


@requires_postgres
def test_existing_in_same_cascade_matches_only_the_address_cascade_and_chain(db_session, seed_protocol):
    """``_existing_in_same_cascade`` is the ``--force`` in-cascade dedupe gate
    (``selection_worker.py:357``). Its three filters — address, the
    ``request->>'root_job_id'`` JSON predicate, and the *conditional* chain
    predicate — are only meaningful against real SQL, so drive it on Postgres.
    """
    from db.models import Job, JobStage, JobStatus
    from workers.selection_worker import _existing_in_same_cascade

    _protocol_id, _company, addr = seed_protocol
    target, unrelated = addr(), addr()

    def _job(address: str, root_job_id: str, chain: str):
        db_session.add(
            Job(
                address=address,
                stage=JobStage.static,
                status=JobStatus.queued,
                request={"address": address, "root_job_id": root_job_id, "chain": chain},
            )
        )

    _job(target, "root-1", "ethereum")
    _job(target, "root-2", "base")
    _job(unrelated, "root-1", "ethereum")
    db_session.commit()

    assert _existing_in_same_cascade(db_session, target, "ethereum", "root-1") is True
    # root-2's only job is on base: the chain predicate is applied, not ignored.
    assert _existing_in_same_cascade(db_session, target, "ethereum", "root-2") is False
    # chain=None omits the filter entirely rather than matching a NULL chain.
    assert _existing_in_same_cascade(db_session, target, None, "root-2") is True
    # A cascade with no job for this address is not a match.
    assert _existing_in_same_cascade(db_session, target, "ethereum", "root-3") is False
    # Another address in the same cascade does not answer for this one.
    assert _existing_in_same_cascade(db_session, unrelated, "ethereum", "root-2") is False


# ---------------------------------------------------------------------------
# 7. Readiness predicate: claim blocks while a dapp_crawl sibling is in flight
# ---------------------------------------------------------------------------


@requires_postgres
def test_claim_blocks_while_sibling_in_flight(db_session, worker, seed_protocol):
    from db.models import JobStage, JobStatus

    protocol_id, company, _addr = seed_protocol
    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=3)
    _add_sibling_job(
        db_session,
        stage=JobStage.dapp_crawl,
        status=JobStatus.processing,
        root_job_id=str(job.id),
    )

    assert worker._claim_ready_job(db_session) is None


@requires_postgres
def test_claim_fires_when_sibling_completes(db_session, worker, seed_protocol):
    from db.models import JobStage, JobStatus

    protocol_id, company, _addr = seed_protocol
    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=3)
    _add_sibling_job(
        db_session,
        stage=JobStage.dapp_crawl,
        status=JobStatus.completed,
        root_job_id=str(job.id),
    )
    _add_sibling_job(
        db_session,
        stage=JobStage.defillama_scan,
        status=JobStatus.completed,
        root_job_id=str(job.id),
    )

    claimed = worker._claim_ready_job(db_session)
    assert claimed is not None
    assert claimed.id == job.id


# ---------------------------------------------------------------------------
# 8. Stuck-sibling escape hatch: claim fires past the timeout regardless
# ---------------------------------------------------------------------------


@requires_postgres
def test_corroborated_contract_outranks_single_source_peer(db_session, worker, seed_protocol):
    """A contract tagged by multiple discovery sources outranks a peer
    with the same raw confidence tagged by only one — the corroboration
    boost is the whole point of the array column.
    """
    from db.models import Contract, Job

    protocol_id, company, addr = seed_protocol

    solo = addr()
    triple = addr()
    # Identical raw confidence + identical activity → the only
    # differentiator is the source union.
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=solo,
        discovery_sources=["inventory"],
        confidence=0.5,
    )
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=triple,
        discovery_sources=["inventory", "dapp_crawl", "defillama"],
        confidence=0.5,
    )

    now = time.time()
    _ACTIVITY_TIMES.update({solo: now, triple: now})

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=1)
    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)

    children = (
        db_session.execute(select(Job).where(Job.request["parent_job_id"].as_string() == str(job.id))).scalars().all()
    )
    assert [c.address for c in children] == [triple]

    # Persisted rank_score reflects the boost (triple-source > solo).
    rows = {
        row.address: row
        for row in db_session.execute(select(Contract).where(Contract.address.in_([solo, triple]))).scalars().all()
    }
    assert rows[triple].rank_score > rows[solo].rank_score


@requires_postgres
def test_stuck_job_escape_hatch_claims_past_timeout(db_session, worker, seed_protocol):
    from db.models import JobStage, JobStatus

    protocol_id, company, _addr = seed_protocol
    stuck_time = datetime.now(timezone.utc) - timedelta(hours=2)
    job = _add_selection_job(
        db_session,
        protocol_id=protocol_id,
        company=company,
        analyze_limit=3,
        updated_at=stuck_time,
    )
    # A sibling still processing — normally would hold the claim back
    _add_sibling_job(
        db_session,
        stage=JobStage.defillama_scan,
        status=JobStatus.processing,
        root_job_id=str(job.id),
    )

    # Ready claim returns None (sibling is still in flight)
    assert worker._claim_ready_job(db_session) is None
    # Stuck claim bypasses the readiness predicate
    claimed = worker._claim_stuck_job(db_session)
    assert claimed is not None
    assert claimed.id == job.id
