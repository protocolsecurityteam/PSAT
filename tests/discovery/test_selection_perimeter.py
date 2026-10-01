"""The selection stage's omission ledger.

`contracts.id=11` (0xcd425f44…, an OZ TimelockController with authority over 53
`function_principals` rows) has no analysis job: it ranked 0.3836 at queue
position 42 while `analyze_limit` was 2, and the budget cut left **no record**.
The fix is one job plus a ledger, never a raised threshold.

Two ledgers: ``not_selected`` (ranked candidates that lost the budget or
deduped) and ``pre_rank_excluded`` (rows removed BEFORE ranking: sub-threshold,
superseded-impl anchors). Only both being empty proves nothing was dropped.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest

from tests.conftest import requires_postgres
from workers.base import JobHandledDirectly

pytestmark = [requires_postgres]


@pytest.fixture(autouse=True)
def _stub_activity_fetch(monkeypatch):
    """No network in the ranker; every row gets the same neutral activity."""
    from services.discovery import activity as activity_module

    monkeypatch.setattr(activity_module.etherscan, "get", lambda module, action, **params: {"result": []})


@pytest.fixture()
def worker():
    from workers.selection_worker import SelectionWorker

    with patch("signal.signal"):
        yield SelectionWorker()


@pytest.fixture()
def seed(db_session):
    from db.models import Contract, Job, Protocol

    name = f"sel-perim-{uuid.uuid4().hex[:10]}"
    protocol = Protocol(name=name)
    db_session.add(protocol)
    db_session.commit()
    protocol_id = protocol.id
    minted: list[str] = []

    def address_factory() -> str:
        addr = ("0x" + uuid.uuid4().hex + "0" * 8).lower()
        minted.append(addr)
        return addr

    try:
        yield protocol_id, name, address_factory
    finally:
        db_session.rollback()
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        if minted:
            db_session.query(Contract).filter(Contract.address.in_(minted)).delete(synchronize_session=False)
            db_session.query(Job).filter(Job.address.in_(minted)).delete(synchronize_session=False)
        db_session.query(Job).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def _add_contract(session, *, protocol_id, address, sources, confidence, chain="ethereum"):
    from db.models import Contract

    row = Contract(
        protocol_id=protocol_id,
        address=address.lower(),
        chain=chain,
        confidence=confidence,
        discovery_sources=list(sources),
    )
    session.add(row)
    session.commit()
    return row


def _add_selection_job(session, *, protocol_id, company, analyze_limit):
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
    return job


def _run(worker, session, job):
    try:
        worker.process(session, job)
    except JobHandledDirectly:
        pass


def _summary(session, job_id) -> dict:
    from db.queue import get_artifact

    summary = get_artifact(session, job_id, "selection_summary")
    assert isinstance(summary, dict), "selection_summary artifact missing"
    return summary


def test_pre_rank_exclusions_are_enumerated_not_counted(db_session, worker, seed):
    """FALSIFIER (A1): three rows, one sub-threshold, one superseded-impl anchor,
    one selected. ``not_selected`` is empty yet two rows were dropped upstream;
    each must be named with its reason."""
    protocol_id, company, address_factory = seed
    low = address_factory()
    anchor = address_factory()
    winner = address_factory()

    _add_contract(db_session, protocol_id=protocol_id, address=low, sources=["inventory"], confidence=0.25)
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=anchor,
        sources=["upgrade_history"],
        confidence=0.95,
    )
    _add_contract(db_session, protocol_id=protocol_id, address=winner, sources=["inventory"], confidence=0.9)

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=1)
    _run(worker, db_session, job)

    summary = _summary(db_session, job.id)
    excluded = summary["pre_rank_excluded"]

    assert len(excluded) == 2, excluded
    by_addr = {row["address"]: row for row in excluded}
    assert by_addr[low]["reason"] == "below_confidence_threshold"
    assert by_addr[low]["effective_confidence"] == pytest.approx(0.25)
    assert by_addr[anchor]["reason"] == "superseded_impl_anchor"
    # The anchor never competed, so it carries no confidence verdict.
    assert "effective_confidence" not in by_addr[anchor]

    # Empty because the one eligible row won — which is why it alone proves nothing.
    assert summary["not_selected"] == []
    assert summary["analyzed_count"] == 1


def test_current_impl_anchor_is_not_excluded(db_session, worker, seed):
    """The negative control on the anchor arm: an ``upgrade_history`` row that
    also carries ``current_implementation`` is the proxy's LIVE impl and must
    still compete. Excluding it would silently drop the contract where the
    proxy's real functions live."""
    protocol_id, company, address_factory = seed
    live_impl = address_factory()
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=live_impl,
        sources=["upgrade_history", "current_implementation"],
        confidence=0.9,
    )
    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=1)
    _run(worker, db_session, job)

    summary = _summary(db_session, job.id)
    assert summary["pre_rank_excluded"] == []
    assert [c["address"] for c in summary["child_jobs"]] == [live_impl]


def test_budget_exhausted_records_every_ranked_loser(db_session, worker, seed):
    """A candidate that loses the budget inside the loop is named with its rank
    — the 0xcd425f44 shape, where rank 0.3836 at position 42 lost to
    ``analyze_limit=2`` and vanished."""
    protocol_id, company, address_factory = seed
    addrs = [address_factory() for _ in range(3)]
    for addr, conf in zip(addrs, (0.9, 0.8, 0.7)):
        _add_contract(db_session, protocol_id=protocol_id, address=addr, sources=["inventory"], confidence=conf)

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=1)
    _run(worker, db_session, job)

    summary = _summary(db_session, job.id)
    assert summary["analyzed_count"] == 1
    assert len(summary["not_selected"]) == 2
    for record in summary["not_selected"]:
        assert record["reason"] == "budget_exhausted"
        assert record["chain"] == "ethereum"
        assert isinstance(record["rank_score"], (int, float))

    selected = {c["address"] for c in summary["child_jobs"]}
    dropped = {r["address"] for r in summary["not_selected"]}
    assert selected.isdisjoint(dropped)
    assert selected | dropped == set(addrs)


def test_prefilled_budget_enumerates_instead_of_returning_empty(db_session, worker, seed):
    """FALSIFIER (A2): with the budget already spent by prior children,
    ``_queue_top_n`` used to ``return []`` BEFORE the loop, dropping every ranked
    candidate unrecorded. All four must be enumerated."""
    from db.models import Job, JobStage, JobStatus

    protocol_id, company, address_factory = seed
    addrs = [address_factory() for _ in range(4)]
    for addr, conf in zip(addrs, (0.9, 0.85, 0.8, 0.75)):
        _add_contract(db_session, protocol_id=protocol_id, address=addr, sources=["inventory"], confidence=conf)

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=2)
    root_job_id = str(job.id)
    for _ in range(2):
        child = Job(
            company=company,
            protocol_id=protocol_id,
            stage=JobStage.discovery,
            status=JobStatus.queued,
            address=address_factory(),
            request={"root_job_id": root_job_id, "protocol_id": protocol_id},
        )
        db_session.add(child)
    db_session.commit()

    _run(worker, db_session, job)

    summary = _summary(db_session, job.id)
    assert summary["analyzed_count"] == 0
    assert summary["child_jobs"] == []
    assert len(summary["not_selected"]) == 4
    assert {r["reason"] for r in summary["not_selected"]} == {"budget_exhausted"}
    assert {r["address"] for r in summary["not_selected"]} == set(addrs)


def test_chain_disabled_candidate_is_recorded_and_consumes_no_budget(db_session, worker, seed, monkeypatch):
    """A chain-gated candidate is an omission (it could have been analysed on an
    enabled deployment), and it must not eat the budget a valid candidate needs.
    """
    protocol_id, company, address_factory = seed
    disabled = address_factory()
    enabled = address_factory()
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=disabled,
        sources=["inventory"],
        confidence=0.95,
        chain="base",
    )
    _add_contract(db_session, protocol_id=protocol_id, address=enabled, sources=["inventory"], confidence=0.9)

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=1)
    _run(worker, db_session, job)

    summary = _summary(db_session, job.id)
    dropped = {r["address"]: r for r in summary["not_selected"]}
    assert dropped[disabled]["reason"] == "chain_not_enabled"
    # Discriminating assertion: had the gate consumed budget, the higher-ranked
    # disabled row would have starved the enabled one.
    assert [c["address"] for c in summary["child_jobs"]] == [enabled]


def test_below_cut_chain_disabled_reports_the_gate_not_the_budget(db_session, worker, seed, monkeypatch):
    """FALSIFIER (ordering): a chain-disabled candidate ranked BELOW the cut must
    report ``chain_not_enabled``, not ``budget_exhausted`` — the recorded cause
    is the ledger's value. The disabled row ranks LAST, so a wrong check order
    would reject it on budget first."""
    protocol_id, company, address_factory = seed
    top, disabled = address_factory(), address_factory()
    _add_contract(db_session, protocol_id=protocol_id, address=top, sources=["inventory"], confidence=0.95)
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        address=disabled,
        sources=["inventory"],
        confidence=0.5,
        chain="base",
    )

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=1)
    _run(worker, db_session, job)

    summary = _summary(db_session, job.id)
    assert [c["address"] for c in summary["child_jobs"]] == [top]
    dropped = {r["address"]: r["reason"] for r in summary["not_selected"]}
    assert dropped[disabled] == "chain_not_enabled"


def test_no_candidates_still_publishes_both_ledgers(db_session, worker, seed):
    """The empty run publishes both keys. A consumer must never have to treat an
    ABSENT ledger as an empty one — absence would mean "this producer predates
    the ledger", which is a different fact."""
    protocol_id, company, _ = seed
    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=2)
    _run(worker, db_session, job)

    summary = _summary(db_session, job.id)
    assert summary["not_selected"] == []
    assert summary["pre_rank_excluded"] == []
