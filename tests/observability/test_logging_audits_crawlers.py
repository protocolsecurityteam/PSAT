"""Offline logging/observability tests for the audits + crawlers part.

Locks in the new observable behavior for Backlog #9-part: external-call
failures on the DefiLlama and DApp crawl paths now surface a ``record_degraded``
entry plus a ``record_stage_metric`` count instead of completing as a silent
success, and the audit scope LLM failure carries a queryable ``failure_kind``
that splits an upstream API outage from a parser bug.

All stubbed at the wire — no live network, no RPC, no playwright browser.
"""

from __future__ import annotations

import asyncio

from utils.logging import (
    bind_trace_context,
    degraded_errors_var,
    stage_metrics_var,
)


def _bound_accumulators():
    """Bind fresh degraded + stage-metric accumulators under a job context.

    Returns ``(errors_list, metrics_dict, reset_callable)`` mirroring the
    pattern in tests/observability/test_record_degraded.py.
    """
    errors: list = []
    metrics: dict = {}
    etok = degraded_errors_var.set(errors)
    mtok = stage_metrics_var.set(metrics)
    ctx = bind_trace_context(
        trace_id="trace-ac",
        job_id="job-ac",
        stage="defillama_scan",
        worker_id="DefiLlamaWorker-1",
    )
    ctx.__enter__()

    def _reset():
        ctx.__exit__(None, None, None)
        stage_metrics_var.reset(mtok)
        degraded_errors_var.reset(etok)

    return errors, metrics, _reset


# --------------------------------------------------------------------------- #
#  DefiLlama: protocol-not-found surfaces degraded + protocol_matched=False
# --------------------------------------------------------------------------- #


def test_defillama_not_found_records_degraded_and_metric(tmp_path):
    from services.crawlers.defillama.scan import scan_protocol

    # Minimal repo layout: an empty projects/ dir so no protocol can match,
    # and no coreAssets.json (load_core_assets tolerates that, returns {}).
    (tmp_path / "projects").mkdir()

    errors, metrics, reset = _bound_accumulators()
    try:
        result = scan_protocol(
            protocol_name="totally-nonexistent-protocol",
            repo_path=tmp_path,
            no_clone=True,
        )
    finally:
        reset()

    # Completes (no raise) with an empty result, but the miss is now visible.
    assert result["addresses"] == []
    assert metrics.get("protocol_matched") is False
    assert any(e.phase == "defillama_match" for e in errors)


def test_defillama_match_records_protocol_matched_true(tmp_path):
    from services.crawlers.defillama.scan import scan_protocol

    projects = tmp_path / "projects"
    projects.mkdir()
    # A single-file adapter whose normalized name matches the query exactly.
    (projects / "myproto.js").write_text("module.exports = {};\n")

    errors, metrics, reset = _bound_accumulators()
    try:
        scan_protocol(protocol_name="myproto", repo_path=tmp_path, no_clone=True)
    finally:
        reset()

    assert metrics.get("protocol_matched") is True
    assert not any(e.phase == "defillama_match" for e in errors)


# --------------------------------------------------------------------------- #
#  DefiLlama: a failed `git pull` is degraded, not silently swallowed
# --------------------------------------------------------------------------- #


def test_defillama_pull_failure_records_degraded(tmp_path, monkeypatch):
    from services.crawlers.defillama import scan as scan_mod

    (tmp_path / ".git").mkdir()  # make clone_or_update_repo take the pull path

    calls: list = []

    def _fake_stream(cmd, *, logger, source, **kwargs):
        calls.append((cmd, source))
        return 1  # non-zero exit -> degraded pull

    monkeypatch.setattr(scan_mod, "stream_subprocess", _fake_stream)

    errors, metrics, reset = _bound_accumulators()
    try:
        # Must not raise — a stale checkout is still scannable.
        scan_mod.clone_or_update_repo(tmp_path)
    finally:
        reset()

    assert calls and calls[0][1] == "git"
    assert any(e.phase == "defillama_repo_pull" for e in errors)


# --------------------------------------------------------------------------- #
#  DApp: a sniffer exception is swallowed-but-degraded, not `except: pass`
# --------------------------------------------------------------------------- #


def test_dapp_sniffer_exception_records_degraded_and_counts():
    from services.crawlers.dapp.browser import DAppCrawler
    from services.crawlers.dapp.wallet import HoneypotWallet

    crawler = DAppCrawler(wallet=HoneypotWallet(), chain_id=1)

    class _BoomResponse:
        url = "https://example.test/api/data.json"

        @property
        def headers(self):  # accessed inside the sniffer's try-block
            raise RuntimeError("boom headers")

    errors, metrics, reset = _bound_accumulators()
    try:
        # The sniffer must swallow the error (no raise) yet record it.
        asyncio.run(crawler._sniff_response(_BoomResponse(), page_url="https://example.test"))
    finally:
        reset()

    assert crawler._sniff_errors == 1
    assert metrics.get("sniff_errors") == 1
    assert any(e.phase == "dapp_sniff" for e in errors)
    assert errors[0].exc_type.endswith("RuntimeError")


# --------------------------------------------------------------------------- #
#  Scope LLM: failure_kind splits an API outage from a parser bug
# --------------------------------------------------------------------------- #


def test_scope_llm_error_carries_failure_kind():
    from services.audits.scope_extraction._errors import LLMUnavailableError

    api = LLMUnavailableError("402 payment required")
    parse = LLMUnavailableError("bad json", failure_kind="parse")
    assert api.failure_kind == "api"  # default = upstream outage signature
    assert parse.failure_kind == "parse"


def test_scope_llm_fallback_degrades_with_failure_kind(monkeypatch):
    """The LLM-unavailable fallback path records a degraded entry whose
    context carries the discriminating ``failure_kind``."""
    import services.audits.scope_extraction as scope_mod
    from services.audits.scope_extraction._errors import LLMUnavailableError
    from services.audits.scope_extraction._locate import ScopeSection

    # Storage returns a body that contains a scope section trigger.
    raw = "Scope\n\nMyContract is in scope.\n"

    class _Client:
        def get(self, key):
            return raw.encode("utf-8")

    monkeypatch.setattr(scope_mod, "get_storage_client", lambda: _Client())
    monkeypatch.setattr(
        scope_mod,
        "locate_scope_section",
        lambda text: [ScopeSection(start_page=1, end_page=1, header="Scope", text_slice="MyContract")],
    )

    def _boom(*a, **k):
        raise LLMUnavailableError("openrouter 402", failure_kind="api")

    monkeypatch.setattr(scope_mod, "extract_scope_with_llm", _boom)
    # Force the chunk-scan fallback to also be unavailable so we exercise both
    # degraded branches deterministically.
    monkeypatch.setattr(
        scope_mod,
        "extract_scope_via_chunk_scan",
        lambda *a, **k: (_ for _ in ()).throw(LLMUnavailableError("402", failure_kind="api")),
    )
    monkeypatch.setattr(scope_mod, "extract_contracts_regex_fallback", lambda combined: [])

    errors, metrics, reset = _bound_accumulators()
    try:
        outcome = scope_mod.process_audit_scope(
            audit_report_id=4242,
            text_storage_key="k",
            text_sha256=None,
            audit_title="t",
            auditor="a",
        )
    finally:
        reset()

    # Never raises; degrades with the queryable failure_kind in context.
    assert outcome.status in ("skipped", "failed")
    assert metrics.get("scope_llm_failure_kind") == "api"
    degraded = [e for e in errors if e.phase == "scope_llm"]
    assert degraded and degraded[0].context.get("failure_kind") == "api"
