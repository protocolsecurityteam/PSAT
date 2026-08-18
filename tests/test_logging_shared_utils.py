"""Logging/observability locks for the shared low-level I/O utils.

Covers the swallow sites in ``utils.rpc`` / ``utils.llm`` / ``utils.etherscan`` /
``utils.concurrency`` that used to emit nothing (or an ERROR traceback) on a
degraded-but-continuing failure. Each test stubs the wire — no live network/RPC —
and asserts the new observable behaviour: a WARNING with facts in ``extra``, the
paired ``record_degraded`` entry, and the LLM completion INFO + ``llm_calls`` metric.
"""

from __future__ import annotations

import logging

import pytest
import requests

import utils.etherscan as etherscan
import utils.llm as llm
import utils.rpc as rpc
from utils.concurrency import parallel_map
from utils.logging import bind_trace_context, degraded_errors_var, stage_metrics_var


class _FailingSession:
    def post(self, *args, **kwargs):
        raise requests.ConnectionError("connection reset by peer")


class _FakeStreamResponse:
    def __init__(self, *, status_code: int = 200, lines: list[bytes] | None = None):
        self.status_code = status_code
        self._lines = lines or []

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)  # pyright: ignore[reportArgumentType]

    def iter_lines(self):
        yield from self._lines


def test_rpc_whole_chunk_failure_warns_with_chunk_start_and_degrades(monkeypatch, caplog):
    monkeypatch.setattr(rpc, "_get_session", lambda: _FailingSession())
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(trace_id="t1", job_id="j1", stage="resolution", worker_id="w1"):
            with caplog.at_level(logging.WARNING, logger="utils.rpc"):
                results = rpc.rpc_batch_request_with_status("http://erpc/main/evm/1", [("eth_call", [{}, "latest"])])
    finally:
        degraded_errors_var.reset(token)

    # Conservative default preserved: the failed chunk's slot stays errored.
    assert results == [(None, True)]

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and r.name == "utils.rpc"]
    assert warnings, "a whole-chunk batch failure must emit a WARNING"
    rec = warnings[0]
    assert rec.chunk_start == 0
    assert rec.exc_type == "ConnectionError"

    assert len(accumulator) == 1
    assert accumulator[0].phase == "rpc_batch_chunk"
    assert accumulator[0].severity == "degraded"


def test_eth_call_batch_whole_chunk_failure_warns_and_degrades(monkeypatch, caplog):
    monkeypatch.setattr(rpc, "_get_session", lambda: _FailingSession())
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(trace_id="t1", job_id="j1", stage="resolution", worker_id="w1"):
            with caplog.at_level(logging.WARNING, logger="utils.rpc"):
                results = rpc.eth_call_batch("http://erpc/main/evm/1", [{"to": "0x" + "1" * 40, "data": "0x"}])
    finally:
        degraded_errors_var.reset(token)

    assert results[0].success is False
    assert any(r.name == "utils.rpc" and getattr(r, "exc_type", None) == "ConnectionError" for r in caplog.records)
    assert accumulator and accumulator[0].phase == "eth_call_batch_chunk"


def test_llm_completion_emits_info_with_fields_and_llm_calls_metric(monkeypatch, caplog):
    monkeypatch.setenv("OPEN_ROUTER_KEY", "test-key")
    lines = [
        b'data: {"choices":[{"delta":{"content":"hello "}}]}',
        b'data: {"choices":[{"delta":{"content":"world"},"finish_reason":"stop"}]}',
        b"data: [DONE]",
    ]
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _FakeStreamResponse(lines=lines))

    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        with bind_trace_context(trace_id="t1", job_id="j1", stage="discovery", worker_id="w1"):
            with caplog.at_level(logging.INFO, logger="utils.llm"):
                out = llm.openrouter.chat([{"role": "user", "content": "hi"}], model="test/model")
    finally:
        stage_metrics_var.reset(token)

    assert out == "hello world"
    infos = [r for r in caplog.records if r.name == "utils.llm" and r.levelno == logging.INFO]
    assert infos, "a completion must emit one INFO line"
    rec = infos[0]
    assert rec.model == "test/model"
    assert rec.finish_reason == "stop"
    assert rec.content_len == len("hello world")
    assert isinstance(rec.duration_ms, int)

    assert metrics.get("llm_calls") == 1


def test_llm_402_emits_loud_warning(monkeypatch, caplog):
    monkeypatch.setenv("OPEN_ROUTER_KEY", "test-key")
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _FakeStreamResponse(status_code=402))

    with caplog.at_level(logging.WARNING, logger="utils.llm"):
        with pytest.raises(requests.HTTPError):
            llm.openrouter.chat([{"role": "user", "content": "hi"}], model="test/model")

    warnings = [r for r in caplog.records if r.name == "utils.llm" and r.levelno == logging.WARNING]
    assert warnings, "a 402 must emit a loud WARNING before raising"
    assert warnings[0].failure_kind == "payment_required"
    assert warnings[0].status_code == 402


def test_etherscan_get_contract_info_errored_fetch_warns_and_degrades(monkeypatch, caplog):
    def _boom(*a, **k):
        raise RuntimeError("etherscan down")

    monkeypatch.setattr(etherscan, "get", _boom)
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(trace_id="t1", job_id="j1", stage="discovery", worker_id="w1"):
            with caplog.at_level(logging.WARNING, logger="utils.etherscan"):
                name, selectors = etherscan.get_contract_info("0x" + "a" * 40, chain_id=1)
    finally:
        degraded_errors_var.reset(token)

    assert name is None and selectors == {}
    warnings = [r for r in caplog.records if r.name == "utils.etherscan" and r.levelno == logging.WARNING]
    assert warnings, "an errored Etherscan fetch must WARN (distinct from an unverified contract)"
    assert warnings[0].address == "0x" + "a" * 40
    assert warnings[0].exc_type == "RuntimeError"
    assert accumulator and accumulator[0].phase == "etherscan_getsourcecode"


def test_parallel_map_heartbeat_failure_demoted_to_warning_with_exc_type(caplog):
    """A raising heartbeat is swallowed-and-continued, so it must be a WARNING
    carrying exc_type — never an ERROR traceback."""

    def _bad_heartbeat() -> None:
        raise ValueError("heartbeat boom")

    with caplog.at_level(logging.WARNING, logger="utils.concurrency"):
        results = parallel_map(lambda x: x * 2, [1, 2, 3], max_workers=1, heartbeat=_bad_heartbeat)

    assert [r for _, r in results] == [2, 4, 6]
    warnings = [r for r in caplog.records if r.name == "utils.concurrency"]
    assert warnings, "a raising heartbeat must emit a WARNING"
    assert all(r.levelno == logging.WARNING for r in warnings)
    assert warnings[0].exc_type == "ValueError"
