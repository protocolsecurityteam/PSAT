"""Offline observability tests for the discovery service layer.

Locks in the new emission behavior added for the logging/observability wave:
  * classifier swallows that downgrade a contract to ``regular`` now pair a
    WARNING with ``record_degraded(phase='classify')`` and a
    ``classify_fallbacks`` stage metric (Backlog #8);
  * ``run_discovery`` folds its per-protocol budget counters
    (search/research calls, estimated cost) into stage metrics and times its
    audit/address sub-phases via ``log_timed_phase`` (Backlog #16);
  * the inventory deployer-expansion swallow records a degraded breadcrumb
    instead of only appending to the artifact ``notes`` (Backlog #8).

All stubbed at the wire — no live network/RPC.
"""

from __future__ import annotations

from contextlib import contextmanager

from utils.logging import (
    bind_trace_context,
    degraded_errors_var,
    stage_metrics_var,
)


@contextmanager
def _job_context():
    """Bind the per-job degraded + stage-metric accumulators a worker installs."""
    metrics: dict = {}
    errors: list = []
    m_token = stage_metrics_var.set(metrics)
    e_token = degraded_errors_var.set(errors)
    try:
        with bind_trace_context(
            trace_id="trace-d",
            job_id="job-d",
            stage="discovery",
            worker_id="DiscoveryWorker-1",
        ):
            yield metrics, errors
    finally:
        stage_metrics_var.reset(m_token)
        degraded_errors_var.reset(e_token)


def test_classifier_fallback_records_degraded_and_metric(monkeypatch):
    from services.discovery import classifier

    # Every classify attempt fails -> parallel_map surfaces the exception per
    # address and classify_contracts must fall back to "regular".
    def _boom(addr, rpc_url, code_cache=None):
        raise RuntimeError("rpc down")

    monkeypatch.setattr(classifier, "classify_single", _boom)

    target = "0x" + "11" * 20
    dep = "0x" + "22" * 20

    with _job_context() as (metrics, errors):
        result = classifier.classify_contracts(target, [dep], rpc_url="http://stub")

    # Both addresses degraded to regular.
    assert metrics["classify_fallbacks"] == 2
    assert all(info["type"] == "regular" for info in result["classifications"].values())

    degraded = [e for e in errors if e.phase == "classify"]
    assert len(degraded) == 1
    assert degraded[0].severity == "degraded"
    assert degraded[0].stage == "discovery"
    assert degraded[0].context["classify_fallbacks"] == 2


def test_classifier_no_fallback_metric_is_zero(monkeypatch):
    from services.discovery import classifier

    def _ok(addr, rpc_url, code_cache=None):
        return {"address": addr, "type": "regular"}

    monkeypatch.setattr(classifier, "classify_single", _ok)

    with _job_context() as (metrics, errors):
        classifier.classify_contracts("0x" + "11" * 20, [], rpc_url="http://stub")

    assert metrics["classify_fallbacks"] == 0
    assert [e for e in errors if e.phase == "classify"] == []


def test_run_discovery_folds_budget_metrics(monkeypatch):
    from services.discovery import run_discovery as rd

    monkeypatch.setattr(rd, "_cached_deep_research", lambda *a, **k: {"data": {"auditReports": [], "contracts": []}})
    monkeypatch.setattr(rd.audit_reports_mod, "search_audit_reports", lambda *a, **k: {"reports": []})
    monkeypatch.setattr(rd.inventory_mod, "search_protocol_inventory", lambda *a, **k: {"contracts": []})
    monkeypatch.setattr(rd, "_needs_dependency_pass", lambda *a, **k: False)
    monkeypatch.setattr(rd, "validate_claimed_chains", lambda contracts, **k: contracts)
    monkeypatch.setattr(rd, "enrich_audit_reports", lambda *a, **k: None)

    with _job_context() as (metrics, _errors):
        out = rd.run_discovery("stubproto")

    # The two unconditional deep-research charges (audit seeds + addresses).
    assert metrics["research_calls"] == 2
    assert metrics["search_calls"] == 0
    assert metrics["estimated_cost_usd"] == out["meta"]["estimated_cost_usd"]
    assert metrics["dependency_pass_triggered"] is False
    # log_timed_phase folded per-phase timings for the wrapped sub-phases.
    assert "phase_ms_discovery_audits" in metrics
    assert "phase_ms_discovery_addresses" in metrics
