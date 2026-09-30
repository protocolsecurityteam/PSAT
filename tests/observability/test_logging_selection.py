"""``activity_fetched`` vs ``activity_neutral`` separates a ranking on real data from one collapsed to 0.5 when
Etherscan is down. Only the Etherscan fetch is stubbed.
"""

from __future__ import annotations

import logging
import time
import uuid
from unittest.mock import patch

import pytest

from tests.conftest import requires_postgres
from utils.logging import bind_trace_context, stage_metrics_var
from workers.base import JobHandledDirectly

pytestmark = [requires_postgres]


_ACTIVITY_TIMES: dict[str, float] = {}


@pytest.fixture(autouse=True)
def _stub_activity_fetch(monkeypatch):
    """An address absent from ``_ACTIVITY_TIMES`` drives the neutral path."""
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
    """Split from one 169-line test so a break names what failed."""
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
                    worker.process(db_session, job)
    finally:
        stage_metrics_var.reset(token)
        # Teardown doesn't clear Job rows.
        db_session.rollback()
        db_session.query(Job).filter(Job.request["protocol_id"].as_integer() == protocol_id).delete(
            synchronize_session=False
        )
        db_session.query(Job).filter(Job.id == job.id).delete(synchronize_session=False)
        db_session.commit()

    return SimpleNamespace(metrics=metrics, records=list(caplog.records), fetched=fetched, neutral=neutral)


@requires_postgres
def test_selection_reports_progress_counts_as_stage_metrics(selection_pass):
    metrics = selection_pass.metrics
    assert metrics["candidates"] == 3
    assert metrics["eligible"] == 2
    assert metrics["dropped"] == 1
    assert metrics["activity_fetched"] == 1
    assert metrics["activity_neutral"] == 1
    assert metrics["ranked_candidates"] == 2
    assert metrics["queued"] == 2


@requires_postgres
def test_selection_emits_exactly_one_summary_line(selection_pass):
    summaries = [r for r in selection_pass.records if r.getMessage() == "Selection complete"]
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.levelno == logging.INFO
    assert summary.outcome == "queued"
    assert summary.queued_count == 2
    assert {s["address"] for s in summary.selected} == {selection_pass.fetched, selection_pass.neutral}


@requires_postgres
def test_selection_facts_live_in_extra_not_in_the_message(selection_pass):
    queued = [r for r in selection_pass.records if r.getMessage() == "Queued analysis child for candidate"]
    assert len(queued) == 2
    for rec in queued:
        assert rec.address in (selection_pass.fetched, selection_pass.neutral)
        assert hasattr(rec, "rank_score")
        assert hasattr(rec, "discovery_sources")
        assert rec.address not in rec.getMessage()
