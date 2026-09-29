"""Covers the sanitized-exception branches in ``services/clients/rpc`` and the
``protocol_monitor`` startup logging that runs URLs through
``sanitize_url`` before they reach the log stream.
"""

from __future__ import annotations

import sys
import threading
from unittest.mock import MagicMock

import pytest
import requests

from services.clients import rpc as rpc_mod

_ALCHEMY = "https://eth-mainnet.g.alchemy.com/v2/FAKE_ALCHEMY_KEY_FOR_TESTS"


# rpc_request: HTTPError branch


def _fake_session(response: MagicMock) -> MagicMock:
    session = MagicMock()
    session.post.return_value = response
    return session


def test_rpc_request_http_404_wraps_in_sanitized_runtime_error(monkeypatch):
    resp = MagicMock()
    resp.status_code = 404

    def _raise():
        raise requests.HTTPError(f"404 Client Error for url: {_ALCHEMY}", response=resp)

    resp.raise_for_status.side_effect = _raise
    monkeypatch.setattr(rpc_mod, "_get_session", lambda: _fake_session(resp))

    with pytest.raises(RuntimeError) as excinfo:
        rpc_mod.rpc_request(_ALCHEMY, "eth_blockNumber", [], retries=0)

    msg = str(excinfo.value)
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in msg
    assert "<redacted>" in msg
    assert "404" in msg


def test_rpc_request_retries_exhausted_message_is_sanitized(monkeypatch):
    resp = MagicMock()
    resp.status_code = 503  # retryable
    resp.raise_for_status.side_effect = requests.HTTPError("503")
    monkeypatch.setattr(rpc_mod, "_get_session", lambda: _fake_session(resp))
    monkeypatch.setattr(rpc_mod.time, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError) as excinfo:
        rpc_mod.rpc_request(_ALCHEMY, "eth_blockNumber", [], retries=2)

    msg = str(excinfo.value)
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in msg
    assert "<redacted>" in msg


def test_rpc_request_connection_error_message_is_sanitized(monkeypatch):
    session = MagicMock()
    session.post.side_effect = requests.ConnectionError(f"connection reset by peer for {_ALCHEMY}")
    monkeypatch.setattr(rpc_mod, "_get_session", lambda: session)
    monkeypatch.setattr(rpc_mod.time, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError) as excinfo:
        rpc_mod.rpc_request(_ALCHEMY, "eth_blockNumber", [], retries=0)

    msg = str(excinfo.value)
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in msg
    assert "<redacted>" in msg


@pytest.mark.parametrize(
    "exc,expect_timeout",
    [
        (requests.Timeout("read timed out"), True),
        (requests.exceptions.ReadTimeout("read timed out"), True),
        (requests.ConnectionError("connection reset by peer"), False),
    ],
)
def test_client_timeouts_surface_as_a_typed_subclass(monkeypatch, exc, expect_timeout):
    """A timeout (client stopped waiting) vs a connection error (transport failed) must be
    distinguishable by TYPE, never message, for callers sizing their own windows. Both remain
    RuntimeError so no existing handler changes."""
    session = MagicMock()
    session.post.side_effect = exc
    monkeypatch.setattr(rpc_mod, "_get_session", lambda: session)
    monkeypatch.setattr(rpc_mod.time, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError) as excinfo:
        rpc_mod.rpc_request(_ALCHEMY, "eth_blockNumber", [], retries=0)

    assert isinstance(excinfo.value, rpc_mod.RpcClientTimeout) is expect_timeout
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in str(excinfo.value)


# rpc_batch_request: HTTPError + transport-error branches


def test_rpc_batch_request_http_error_wraps_in_sanitized_runtime_error(monkeypatch):
    resp = MagicMock()
    resp.status_code = 429
    err = requests.HTTPError(f"429 for {_ALCHEMY}")
    err.response = resp
    resp.raise_for_status.side_effect = err
    monkeypatch.setattr(rpc_mod, "_get_session", lambda: _fake_session(resp))

    with pytest.raises(RuntimeError) as excinfo:
        rpc_mod.rpc_batch_request(_ALCHEMY, [("eth_blockNumber", [])])

    msg = str(excinfo.value)
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in msg
    assert "<redacted>" in msg
    assert "HTTP 429" in msg


def test_rpc_batch_request_transport_error_wraps_in_sanitized_runtime_error(monkeypatch):
    session = MagicMock()
    session.post.side_effect = requests.Timeout(f"timeout connecting to {_ALCHEMY}")
    monkeypatch.setattr(rpc_mod, "_get_session", lambda: session)

    with pytest.raises(RuntimeError) as excinfo:
        rpc_mod.rpc_batch_request(_ALCHEMY, [("eth_blockNumber", [])])

    msg = str(excinfo.value)
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in msg
    assert "<redacted>" in msg


# protocol_monitor.main: the rpc URL is sanitized before logging


def test_protocol_monitor_logs_redacted_rpc_url(monkeypatch):
    import importlib
    import logging

    pm = importlib.import_module("workers.protocol_monitor")

    monkeypatch.setattr(sys, "argv", ["protocol_monitor", "--rpc-url", _ALCHEMY])

    # Stub signal handlers (they sys.exit on SIGTERM in prod) and the loop entry points so no real work runs.
    monkeypatch.setattr(pm.signal, "signal", lambda *a, **kw: None)

    fake_unified = MagicMock()
    fake_unified.DEFAULT_POLL_INTERVAL = 60
    fake_unified.DEFAULT_SCAN_INTERVAL = 60
    fake_unified.run_poll_loop = MagicMock()
    fake_unified.run_scan_loop = MagicMock()
    monkeypatch.setitem(sys.modules, "services.monitoring.unified_watcher", fake_unified)

    fake_tvl = MagicMock()
    fake_tvl.DEFAULT_TVL_INTERVAL = 60
    fake_tvl.run_tvl_loop = MagicMock()
    monkeypatch.setitem(sys.modules, "services.monitoring.tvl", fake_tvl)

    # Default mode blocks in Supervisor.run_forever(). The sanitization contract lives in the
    # startup log + loop wiring, so drive each supervised loop once (stop event pre-set) and return.
    def run_once(self):
        stop = threading.Event()
        stop.set()
        for _name, target in self._loops:
            target(stop)

    monkeypatch.setattr(pm.Supervisor, "run_forever", run_once)

    # Capture on the module logger, not caplog: main() calls configure_logging(), which clears
    # root handlers on its first per-process call and would drop caplog's handler.
    records: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Capture()
    pm.logger.addHandler(handler)
    pm.logger.setLevel(logging.INFO)
    try:
        pm.main()
    finally:
        pm.logger.removeHandler(handler)

    combined = " ".join(records)
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in combined
    # The host is preserved so operators can still see which provider is in use.
    assert "eth-mainnet.g.alchemy.com" in combined
    # The underlying run_scan_loop received the unredacted URL (workers need the real key).
    fake_unified.run_scan_loop.assert_called_once()
    args, _kwargs = fake_unified.run_scan_loop.call_args
    assert args[0] == _ALCHEMY


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
