"""Observability locks for the resolution stage (backlog #6/#14/#15).

Offline: every external read (hypersync scan, scan-floor lookup) is stubbed —
no live network / RPC. Asserts the degraded breadcrumbs, split stage metrics,
and per-decision DEBUG ``extra={}`` fields the monitor/Loki surfaces depend on.
"""

from __future__ import annotations

import logging

from services.resolution import recursive
from services.resolution.adapters import event_indexed, solmate_roles
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from utils.logging import bind_trace_context, degraded_errors_var, stage_metrics_var


def test_incomplete_mapping_enumeration_degrades_and_counts(monkeypatch):
    """A truncated mapping scan must land in stage_errors AND bump the
    ``mapping_enum_incomplete`` metric — not silently drop authorized addrs."""
    monkeypatch.setenv("ENVIO_API_TOKEN", "test-token")
    monkeypatch.setattr(
        "services.resolution.creation_block_floor.resolve_scan_floor",
        lambda address, chain_id, **kw: 100,
    )
    monkeypatch.setattr(
        "services.resolution.mapping_enumerator.enumerate_mapping_allowlist_sync",
        lambda *a, **k: {
            "principals": [],
            "status": "incomplete_timeout",
            "pages_fetched": 5,
            "last_block_scanned": 200,
            "error": None,
        },
    )

    accumulator: list = []
    metrics: dict = {}
    tok_d = degraded_errors_var.set(accumulator)
    tok_m = stage_metrics_var.set(metrics)
    try:
        with bind_trace_context(trace_id="t", job_id="j", stage="resolution", worker_id="w"):
            status = recursive._replay_mapping_principals(
                address="0x" + "ab" * 20,
                mapping_specs=[{"mapping_name": "allow"}],  # type: ignore[arg-type]
                contract_node_id="address:0x" + "ab" * 20,
                depth=0,
                nodes={},
                edges={},
            )
    finally:
        stage_metrics_var.reset(tok_m)
        degraded_errors_var.reset(tok_d)

    assert status == "incomplete_timeout"
    assert metrics["mapping_enum_incomplete"] == 1
    assert len(accumulator) == 1
    assert accumulator[0].phase == "mapping_enum_incomplete"
    assert accumulator[0].context["status"] == "incomplete_timeout"


def test_proxies_redirected_metric_increments():
    metrics: dict = {}
    tok = stage_metrics_var.set(metrics)
    try:
        recursive._bump_stage_metric("proxies_redirected")
        recursive._bump_stage_metric("proxies_redirected")
    finally:
        stage_metrics_var.reset(tok)
    assert metrics["proxies_redirected"] == 2


def test_solmate_decline_emits_decision_extra(caplog):
    """The Veda cold-index race shows up as an adapter 'deferred' decision —
    queryable by adapter/address/decision/reason, not buried."""
    authority = "0x" + "cd" * 20
    with caplog.at_level(logging.DEBUG, logger="services.resolution.adapters.solmate_roles"):
        solmate_roles._check_only(authority, {"callee_selector": None}, ["no_index_cursor"])

    rec = next(r for r in caplog.records if getattr(r, "decision", None))
    assert rec.adapter == "solmate_roles_authority"
    assert rec.address == authority
    assert rec.decision == "deferred"
    assert rec.reason == "no_index_cursor"


def test_event_indexed_external_check_emits_decision_extra(caplog):
    ctx = EvaluationContext()
    descriptor = {"callee_selector": None}
    hint = {"topic0": "0x" + "11" * 32, "direction": "add"}
    with caplog.at_level(logging.DEBUG, logger="services.resolution.adapters.event_indexed"):
        event_indexed.EventIndexedAdapter()._external_check(descriptor, hint, ctx, ["event_address_unresolved"])  # type: ignore[arg-type]

    rec = next(r for r in caplog.records if getattr(r, "adapter", None) == "event_indexed")
    assert rec.decision == "external_check"
    assert rec.reason == "event_address_unresolved"


def test_predicate_evaluator_leaf_decision_extra(caplog):
    tree = {"op": "LEAF", "leaf": {"kind": "unsupported", "unsupported_reason": "x"}}
    with caplog.at_level(logging.DEBUG, logger="services.resolution.predicate_evaluator"):
        cap = evaluate_tree(tree, EvaluationContext())  # type: ignore[arg-type]

    assert cap.kind == "unsupported"
    rec = next(r for r in caplog.records if getattr(r, "adapter", None) == "predicate_evaluator")
    assert rec.decision == "unsupported"
    assert rec.reason == "unsupported"
