"""Covers the sanitized-exception branches in ``utils/rpc`` and the
``protocol_monitor`` startup logging that runs URLs through
``sanitize_url`` before they reach the log stream.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils import rpc as rpc_mod

_ALCHEMY = "https://eth-mainnet.g.alchemy.com/v2/FAKE_ALCHEMY_KEY_FOR_TESTS"


# ---------------------------------------------------------------------------
# rpc_request: HTTPError branch
# ---------------------------------------------------------------------------


def _fake_session(response: MagicMock) -> MagicMock:
    session = MagicMock()
    session.post.return_value = response
    return session


def test_rpc_request_http_404_wraps_in_sanitized_runtime_error(monkeypatch):
    """A non-retryable 4xx must surface as a RuntimeError without the URL."""
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
    """After retries exhausted on transient errors, the URL must be redacted."""
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
    """A transport-level failure echoes the URL via str(exc) — must be scrubbed."""
    session = MagicMock()
    session.post.side_effect = requests.ConnectionError(
        f"connection reset by peer for {_ALCHEMY}"
    )
    monkeypatch.setattr(rpc_mod, "_get_session", lambda: session)
    monkeypatch.setattr(rpc_mod.time, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError) as excinfo:
        rpc_mod.rpc_request(_ALCHEMY, "eth_blockNumber", [], retries=0)

    msg = str(excinfo.value)
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in msg
    assert "<redacted>" in msg


# ---------------------------------------------------------------------------
# rpc_batch_request: HTTPError + transport-error branches
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# protocol_monitor.main: the rpc URL is sanitized before logging
# ---------------------------------------------------------------------------


def test_protocol_monitor_logs_redacted_rpc_url(monkeypatch, caplog):
    """Driving ``main()`` with ``--rpc-url=<Alchemy URL>`` must not log the raw URL."""
    import importlib

    pm = importlib.import_module("workers.protocol_monitor")

    monkeypatch.setattr(sys, "argv", ["protocol_monitor", "--rpc-url", _ALCHEMY])

    # Stub out signal handlers (they call sys.exit on SIGTERM in real prod) and
    # the watcher entry point so main() returns immediately after logging.
    monkeypatch.setattr(pm.signal, "signal", lambda *a, **kw: None)

    fake_unified = MagicMock()
    fake_unified.DEFAULT_POLL_INTERVAL = 60
    fake_unified.DEFAULT_SCAN_INTERVAL = 60
    fake_unified.run_poll_loop = MagicMock()
    fake_unified.run_scan_loop = MagicMock()
    monkeypatch.setitem(sys.modules, "services.monitoring.unified_watcher", fake_unified)

    with caplog.at_level("INFO"):
        pm.main()

    combined = " ".join(rec.getMessage() for rec in caplog.records)
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in combined
    # The host is preserved so operators can still see which provider is in use.
    assert "eth-mainnet.g.alchemy.com" in combined
    # And the underlying run_*_loop received the unredacted URL (workers
    # need the real key to make requests).
    fake_unified.run_scan_loop.assert_called_once()
    args, _kwargs = fake_unified.run_scan_loop.call_args
    assert args[0] == _ALCHEMY


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
