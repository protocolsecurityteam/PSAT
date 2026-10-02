"""Classifier fallbacks, run_discovery metrics and inventory swallows record degraded breadcrumbs (Backlog #8/#16);
the DEBUG-only swallows that hid two audit-discovery collapses now WARN.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager

from utils.logging import (
    bind_trace_context,
    degraded_errors_var,
    stage_metrics_var,
)


@contextmanager
def _job_context():
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

    def _boom(addr, rpc_url, code_cache=None):
        raise RuntimeError("rpc down")

    monkeypatch.setattr(classifier, "classify_single", _boom)

    target = "0x" + "11" * 20
    dep = "0x" + "22" * 20

    with _job_context() as (metrics, errors):
        result = classifier.classify_contracts(target, [dep], rpc_url="http://stub")

    assert metrics["classify_fallbacks"] == 2
    assert all(info["type"] == "regular" for info in result["classifications"].values())

    degraded = [e for e in errors if e.phase == "classify"]
    assert len(degraded) == 1
    assert degraded[0].severity == "degraded"
    assert degraded[0].stage == "discovery"
    assert degraded[0].context["classify_fallbacks"] == 2


def test_classifier_no_fallback_metric_is_zero(monkeypatch):
    from services.discovery import classifier

    def _ok(addr, rpc_url, code_cache=None, *, chain_id=None):
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

    assert metrics["research_calls"] == 2
    assert metrics["search_calls"] == 0
    assert metrics["estimated_cost_usd"] == out["meta"]["estimated_cost_usd"]
    assert metrics["dependency_pass_triggered"] is False
    assert "phase_ms_discovery_audits" in metrics
    assert "phase_ms_discovery_addresses" in metrics


def test_chain_probe_failure_warns_instead_of_reading_as_no_code(monkeypatch, caplog):
    """D3: an empty probe result is indistinguishable from "no code here"."""
    from services.discovery import chain_resolver

    monkeypatch.setattr(chain_resolver, "_erpc_url_for_chain", lambda _chain: "http://stub")

    def _boom(_url, _addresses):
        raise TimeoutError("probe timed out")

    monkeypatch.setattr(chain_resolver, "_batch_get_code", _boom)

    with _job_context() as (_metrics, errors):
        with caplog.at_level(logging.WARNING, logger="services.discovery.chain_resolver"):
            hits = chain_resolver._probe_chain_batch(["0x" + "11" * 20], "base")

    assert hits == set()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].probe_chain == "base"
    assert not hasattr(warnings[0], "chain")
    assert warnings[0].exc_type == "TimeoutError"

    degraded = [e for e in errors if e.phase == "chain_probe"]
    assert len(degraded) == 1
    assert degraded[0].context["probe_chain"] == "base"
    # The provider's text separates a 402 from a 401 from a timeout.
    assert "probe timed out" in degraded[0].message


def test_chain_probe_error_fills_warn_even_when_the_batch_returns(monkeypatch, caplog):
    """``_batch_get_code`` answers ``"0x"`` on transport errors, so a chain outage returns successfully."""
    import urllib.error

    from services.discovery import chain_resolver, static_dependencies

    monkeypatch.setattr(chain_resolver, "_erpc_url_for_chain", lambda _chain: "http://stub")

    def _no_batch(*_a, **_kw):
        raise urllib.error.URLError("connection refused")

    def _no_code(*_a, **_kw):
        raise RuntimeError("rpc 500")

    monkeypatch.setattr(chain_resolver.urllib.request, "urlopen", _no_batch)
    monkeypatch.setattr(static_dependencies, "get_code", _no_code)

    addresses = ["0x" + "11" * 20, "0x" + "22" * 20]
    with _job_context() as (_metrics, errors):
        with caplog.at_level(logging.WARNING, logger="services.discovery.chain_resolver"):
            hits = chain_resolver._probe_chain_batch(addresses, "base")

    assert hits == set()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].probe_failed == 2
    assert warnings[0].probe_chain == "base"
    assert warnings[0].exc_type == "RuntimeError"

    degraded = [e for e in errors if e.phase == "chain_probe"]
    assert len(degraded) == 1
    assert degraded[0].context["probe_failed"] == 2


def test_chain_probe_counts_per_item_rpc_errors(monkeypatch, caplog):
    """An errored item lands as ``"0x"``, the same shape as real no-code."""
    import json

    from services.discovery import chain_resolver

    monkeypatch.setattr(chain_resolver, "_erpc_url_for_chain", lambda _chain: "http://stub")

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def read(self) -> bytes:
            return json.dumps(
                [
                    {"jsonrpc": "2.0", "id": 0, "error": {"code": -32000, "message": "execution reverted"}},
                    {"jsonrpc": "2.0", "id": 1, "result": "0x"},
                ]
            ).encode("utf-8")

    monkeypatch.setattr(chain_resolver.urllib.request, "urlopen", lambda *_a, **_kw: _Response())

    with _job_context() as (_metrics, errors):
        with caplog.at_level(logging.WARNING, logger="services.discovery.chain_resolver"):
            hits = chain_resolver._probe_chain_batch(["0x" + "11" * 20, "0x" + "22" * 20], "base")

    assert hits == set()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].probe_failed == 1
    assert warnings[0].exc_type is None
    assert [e for e in errors if e.phase == "chain_probe"] == []


def test_audit_classification_llm_failure_warns(monkeypatch, caplog):
    """D2: the shape behind both prior audit-discovery collapses."""
    from services.discovery import audit_reports_llm

    def _boom(*_a, **_kw):
        raise RuntimeError("402 payment required")

    monkeypatch.setattr(audit_reports_llm.llm, "chat", _boom)

    with _job_context() as (_metrics, errors):
        with caplog.at_level(logging.WARNING, logger="services.discovery.audit_reports_llm"):
            out = audit_reports_llm.classify_search_results(
                [{"title": "Acme audit", "url": "https://example.com/a.pdf"}], "acme"
            )

    assert out == []
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].exc_type == "RuntimeError"
    assert warnings[0].company == "acme"

    degraded = [e for e in errors if e.phase == "audit_classification"]
    assert len(degraded) == 1
    assert "402 payment required" in degraded[0].message


def test_activity_fetch_failures_summarized_once_per_pass(monkeypatch, caplog):
    from services.discovery import activity

    def _boom(*_a, **_kw):
        raise RuntimeError("etherscan down")

    monkeypatch.setattr(activity.etherscan, "get", _boom)

    contracts = [{"address": "0x" + f"{i:040x}", "chains": ["ethereum"]} for i in range(3)]

    with _job_context() as (_metrics, errors):
        with caplog.at_level(logging.WARNING, logger="services.discovery.activity"):
            activity.enrich_with_activity(contracts)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].failed == 3
    assert warnings[0].exc_types == ["RuntimeError"]

    degraded = [e for e in errors if e.phase == "activity_enrichment"]
    assert len(degraded) == 1
    assert "etherscan down" in degraded[0].message
    # The log is what says the neutral score was a guess.
    assert all(c["activity"]["score"] == 0.5 for c in contracts)
