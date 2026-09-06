"""Observability contract for the ``SelectionWorker``.

Locks in the logging/metrics behaviour added under logging backlog
#16-selection:

* per-stage progress counts reach ``record_stage_metric`` —
  ``candidates`` / ``eligible`` / ``dropped`` plus the activity split
  (``activity_fetched`` / ``activity_neutral``), which distinguishes a
  ranking made on real on-chain data from one collapsed to the neutral
  0.5 fallback when Etherscan is unavailable;
* selection facts (address, rank_score, reason) live in ``extra={}`` as
  queryable JSON fields, not interpolated into the ``%s`` message text;
* exactly one INFO ``"Selection complete"`` summary describes what was
  selected and why (``outcome`` / ``queued_count`` / ``selected``).

Offline: the only wire (Etherscan activity fetch) is stubbed; everything
else runs against the real worker + a real Postgres session.
"""

from __future__ import annotations

import logging
import time
import uuid
from unittest.mock import patch

import pytest

from tests.attempt_helpers import claimed_call
from tests.conftest import requires_postgres
from utils.logging import bind_trace_context, stage_metrics_var
from workers.base import JobHandledDirectly

pytestmark = [requires_postgres]


# Maps lowercased address -> last-active unix ts; absent => neutral fallback.
_ACTIVITY_TIMES: dict[str, float] = {}


@pytest.fixture(autouse=True)
def _stub_activity_fetch(monkeypatch):
    """Stub the only wire: ``services.discovery.activity.etherscan.get``.

    Keeps the real scoring/ranking math in the loop but removes network
    traffic. An address absent from ``_ACTIVITY_TIMES`` returns an empty
    result, driving the neutral-score path.
    """
    from services.discovery import activity as activity_module

    def fake_etherscan_get(module, action, **params):
        ts = _ACTIVITY_TIMES.get(str(params.get("address", "")).lower())
        if ts is not None:
            return {"result": [{"timeStamp": str(int(ts))}]}
        return {"result": []}

    monkeypatch.setattr(activity_module.etherscan, "get", fake_etherscan_get)
    _ACTIVITY_TIMES.clear()
    yield
    _ACTIVITY_TIMES.clear()


@pytest.fixture()
def worker():
    from workers.selection_worker import SelectionWorker

    with patch("signal.signal"):
        yield SelectionWorker()


def _seed(db_session):
    from db.models import Contract, Job, JobStage, JobStatus, Protocol

    protocol = Protocol(name=f"sel-log-{uuid.uuid4().hex[:10]}")
    db_session.add(protocol)
    db_session.commit()

    def mint() -> str:
        return ("0x" + uuid.uuid4().hex + "0" * 8).lower()

    fetched = mint()  # has activity data -> activity_fetched
    neutral = mint()  # no activity data -> activity_neutral 0.5 fallback
    dropped = mint()  # below confidence threshold -> dropped

    _ACTIVITY_TIMES[fetched] = time.time()

    for addr, conf in ((fetched, 0.9), (neutral, 0.9), (dropped, 0.01)):
        db_session.add(
            Contract(
                protocol_id=protocol.id,
                address=addr,
                chain="ethereum",
                confidence=conf,
                discovery_sources=["inventory"],
            )
        )
    db_session.commit()

    job = Job(
        company="acme",
        protocol_id=protocol.id,
        stage=JobStage.selection,
        status=JobStatus.queued,
        request={"protocol_id": protocol.id, "analyze_limit": 5},
    )
    db_session.add(job)
    db_session.commit()
    return job, fetched, neutral


@pytest.fixture()
def selection_pass(db_session, worker, caplog):
    """Run one selection pass and hand back everything it emitted.

    Three independent contracts are asserted below — the stage metrics, the
    summary line, and the facts-in-``extra`` rule — and they used to share one
    169-line test, so a break in any of them showed up as the same red line.
    """
    from types import SimpleNamespace

    from db.models import Job

    job, fetched, neutral = _seed(db_session)
    protocol_id = job.protocol_id

    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        with bind_trace_context(
            trace_id="trace-sel", job_id=str(job.id), stage="selection", worker_id="SelectionWorker-1"
        ):
            with caplog.at_level(logging.INFO, logger="workers.selection_worker"):
                with pytest.raises(JobHandledDirectly):
                    claimed_call(worker.process, db_session, job)
    finally:
        stage_metrics_var.reset(token)
        # db_session teardown clears Contract/Protocol but not Job; drop the
        # selection job + its analysis children so they don't leak into the
        # shared DB and perturb other selection tests in the full suite.
        db_session.rollback()
        db_session.query(Job).filter(Job.request["protocol_id"].as_integer() == protocol_id).delete(
            synchronize_session=False
        )
        db_session.query(Job).filter(Job.id == job.id).delete(synchronize_session=False)
        db_session.commit()

    return SimpleNamespace(metrics=metrics, records=list(caplog.records), fetched=fetched, neutral=neutral)


@requires_postgres
def test_selection_reports_progress_counts_as_stage_metrics(selection_pass):
    # Per-stage progress counts reach the monitor UI via record_stage_metric.
    metrics = selection_pass.metrics
    assert metrics["candidates"] == 3
    assert metrics["eligible"] == 2
    assert metrics["dropped"] == 1
    # One contract had on-chain activity; one fell back to the neutral 0.5.
    assert metrics["activity_fetched"] == 1
    assert metrics["activity_neutral"] == 1
    assert metrics["ranked_candidates"] == 2
    assert metrics["queued"] == 2


@requires_postgres
def test_selection_emits_exactly_one_summary_line(selection_pass):
    # Exactly one INFO summary describing what was selected and why.
    summaries = [r for r in selection_pass.records if r.getMessage() == "Selection complete"]
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.levelno == logging.INFO
    assert summary.outcome == "queued"
    assert summary.queued_count == 2
    assert {s["address"] for s in summary.selected} == {selection_pass.fetched, selection_pass.neutral}


@requires_postgres
def test_selection_facts_live_in_extra_not_in_the_message(selection_pass):
    # Facts live in extra={}, not interpolated into the message string.
    queued = [r for r in selection_pass.records if r.getMessage() == "Queued analysis child for candidate"]
    assert len(queued) == 2
    for rec in queued:
        assert rec.address in (selection_pass.fetched, selection_pass.neutral)
        assert hasattr(rec, "rank_score")
        assert hasattr(rec, "discovery_sources")
        # The address is a queryable field, never baked into the human message.
        assert rec.address not in rec.getMessage()
