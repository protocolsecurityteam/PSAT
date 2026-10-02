"""Backlog #9: crawl failures record degraded plus a count instead of a silent success, and scope LLM failures carry
``failure_kind`` separating an outage from a parser bug.
"""

from __future__ import annotations

import asyncio

import pytest

from utils.logging import (
    bind_trace_context,
    degraded_errors_var,
    stage_metrics_var,
)


def _bound_accumulators():
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


@pytest.mark.parametrize(
    "protocol_name,project_file,matched",
    [
        pytest.param("totally-nonexistent-protocol", None, False, id="not_found"),
        pytest.param("myproto", "myproto.js", True, id="match"),
    ],
)
def test_defillama_match_records_degraded_and_metric(tmp_path, protocol_name, project_file, matched):
    from services.crawlers.defillama.scan import scan_protocol

    projects = tmp_path / "projects"
    projects.mkdir()
    if project_file:
        (projects / project_file).write_text("module.exports = {};\n")

    errors, metrics, reset = _bound_accumulators()
    try:
        result = scan_protocol(protocol_name=protocol_name, repo_path=tmp_path, no_clone=True)
    finally:
        reset()

    assert result["addresses"] == []
    assert metrics.get("protocol_matched") is matched
    assert any(e.phase == "defillama_match" for e in errors) is not matched


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
        # A stale checkout is still scannable.
        scan_mod.clone_or_update_repo(tmp_path)
    finally:
        reset()

    assert calls and calls[0][1] == "git"
    assert any(e.phase == "defillama_repo_pull" for e in errors)


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
        asyncio.run(crawler._sniff_response(_BoomResponse(), page_url="https://example.test"))
    finally:
        reset()

    assert crawler._sniff_errors == 1
    assert metrics.get("sniff_errors") == 1
    assert any(e.phase == "dapp_sniff" for e in errors)
    assert errors[0].exc_type.endswith("RuntimeError")


def test_scope_llm_fallback_degrades_with_failure_kind(monkeypatch):
    import services.audits.scope_extraction as scope_mod
    from services.audits.scope_extraction._errors import LLMUnavailableError
    from services.audits.scope_extraction._locate import ScopeSection

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

    assert outcome.status in ("skipped", "failed")
    assert metrics.get("scope_llm_failure_kind") == "api"
    degraded = [e for e in errors if e.phase == "scope_llm"]
    assert degraded and degraded[0].context.get("failure_kind") == "api"
