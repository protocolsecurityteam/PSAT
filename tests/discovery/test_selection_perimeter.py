"""The selection stage's omission ledger (C2).

`contracts.id=11` (0xcd425f44…, a live 2-day OZ TimelockController holding
authority over 53 `function_principals` rows across 16 contracts) has no
analysis job. The cause was not a bug: it ranked 0.3836 and sat at queue
positions 42-57 while `analyze_limit` was 2, so the budget cut it — and the cut
left **no record**. A dropped candidate that is indistinguishable from a
candidate that never existed is the defect; the targeted fix is one job plus a
ledger, never a raised threshold.

Two ledgers, because two different populations get dropped:

* ``not_selected`` — RANKED candidates that lost the budget or deduped away;
* ``pre_rank_excluded`` — rows removed BEFORE ranking (sub-threshold
  confidence, superseded-impl anchors), which never competed at all.

Only both being empty proves nothing was dropped. ``not_selected == []`` alone
does not: the pre-rank filters run upstream of it, and one of them used to exist
solely as a ``record_stage_metric`` count.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402
from workers.base import JobHandledDirectly  # noqa: E402

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
    """FALSIFIER (A1): three rows, one sub-threshold, one superseded-impl
    anchor, one selected. ``not_selected`` is empty — nothing lost the budget —
    yet two rows were dropped upstream, and each is named with its reason.

    Before this, the sub-threshold row survived only as ``record_stage_metric
    ("dropped", n)`` and the anchor was removed in SQL, so an empty
    ``not_selected`` would have read as "nothing was dropped" on both counts.
    """
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

    # The one eligible row won the budget, so the ranked-population ledger is
    # legitimately empty — which is exactly why it alone proves nothing.
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
        # The rank is what makes the record actionable: it says how far off the
        # cut the candidate was, which is the whole content of "0.3836 at 42".
        assert isinstance(record["rank_score"], (int, float))

    selected = {c["address"] for c in summary["child_jobs"]}
    dropped = {r["address"] for r in summary["not_selected"]}
    assert selected.isdisjoint(dropped)
    assert selected | dropped == set(addrs)


def test_prefilled_budget_enumerates_instead_of_returning_empty(db_session, worker, seed):
    """FALSIFIER (A2): the early-return path. With the budget already spent by
    prior children, ``_queue_top_n`` used to ``return []`` BEFORE the loop, so
    every ranked candidate was dropped without a record — the C2 defect
    reproduced inside its own fix. All four must be enumerated."""
    from db.models import Job, JobStage, JobStatus

    protocol_id, company, address_factory = seed
    addrs = [address_factory() for _ in range(4)]
    for addr, conf in zip(addrs, (0.9, 0.85, 0.8, 0.75)):
        _add_contract(db_session, protocol_id=protocol_id, address=addr, sources=["inventory"], confidence=conf)

    job = _add_selection_job(db_session, protocol_id=protocol_id, company=company, analyze_limit=2)
    root_job_id = str(job.id)
    # Two analysis children already exist under this root: the budget is full.
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
    """FALSIFIER (ordering). A chain-disabled candidate ranked BELOW the cut must
    report ``chain_not_enabled``, not ``budget_exhausted``.

    With the budget checked first, every below-the-cut candidate read
    `budget_exhausted` regardless of why it was really ineligible. Nothing was
    dropped silently — but the recorded cause was wrong, and the cause is the
    entire value of the ledger. Here the disabled row ranks LAST, so the budget
    would have rejected it first if the order were wrong.
    """
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
