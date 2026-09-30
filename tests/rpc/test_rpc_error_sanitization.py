
from __future__ import annotations

import sys
import threading
from unittest.mock import MagicMock

import pytest
import requests

from services.clients import rpc as rpc_mod

_ALCHEMY = "https://eth-mainnet.g.alchemy.com/v2/FAKE_ALCHEMY_KEY_FOR_TESTS"


def _fake_session(response: MagicMock) -> MagicMock:
    session = MagicMock()
    session.post.return_value = response
    return session


def _http_error_session(status: int, make_exc) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.raise_for_status.side_effect = make_exc(resp)
    return _fake_session(resp)


def _transport_error_session(exc: Exception) -> MagicMock:
    session = MagicMock()
    session.post.side_effect = exc
    return session


def _single(retries):
    return lambda: rpc_mod.rpc_request(_ALCHEMY, "eth_blockNumber", [], retries=retries)


def _batch():
    return rpc_mod.rpc_batch_request(_ALCHEMY, [("eth_blockNumber", [])])


def _batch_http_error(resp):
    err = requests.HTTPError(f"429 for {_ALCHEMY}")
    err.response = resp
    return err


# Every failure branch must redact the URL's API key from the raised message.
@pytest.mark.parametrize(
    "make_session, call, extra_substrings",
    [
        pytest.param(
            lambda: _http_error_session(
                404, lambda resp: requests.HTTPError(f"404 Client Error for url: {_ALCHEMY}", response=resp)
            ),
            _single(0),
            ["404"],
            id="request-http-404",
        ),
        pytest.param(
            lambda: _http_error_session(503, lambda resp: requests.HTTPError("503")),  # retryable
            _single(2),
            [],
            id="request-retries-exhausted",
        ),
        pytest.param(
            lambda: _transport_error_session(requests.ConnectionError(f"connection reset by peer for {_ALCHEMY}")),
            _single(0),
            [],
            id="request-connection-error",
        ),
        pytest.param(
            lambda: _http_error_session(429, _batch_http_error),
            _batch,
            ["HTTP 429"],
            id="batch-http-error",
        ),
        pytest.param(
            lambda: _transport_error_session(requests.Timeout(f"timeout connecting to {_ALCHEMY}")),
            _batch,
            [],
            id="batch-transport-error",
        ),
    ],
)
def test_rpc_errors_redact_api_key(monkeypatch, make_session, call, extra_substrings):
    session = make_session()
    monkeypatch.setattr(rpc_mod, "_get_session", lambda: session)
    monkeypatch.setattr(rpc_mod.time, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError) as excinfo:
        call()

    msg = str(excinfo.value)
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in msg
    assert "<redacted>" in msg
    for needle in extra_substrings:
        assert needle in msg


@pytest.mark.parametrize(
    "exc,expect_timeout",
    [
        (requests.Timeout("read timed out"), True),
        (requests.exceptions.ReadTimeout("read timed out"), True),
        (requests.ConnectionError("connection reset by peer"), False),
    ],
)
def test_client_timeouts_surface_as_a_typed_subclass(monkeypatch, exc, expect_timeout):
    """Callers distinguish timeout from connection error by type, never message; both stay RuntimeError."""
    session = MagicMock()
    session.post.side_effect = exc
    monkeypatch.setattr(rpc_mod, "_get_session", lambda: session)
    monkeypatch.setattr(rpc_mod.time, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError) as excinfo:
        rpc_mod.rpc_request(_ALCHEMY, "eth_blockNumber", [], retries=0)

    assert isinstance(excinfo.value, rpc_mod.RpcClientTimeout) is expect_timeout
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in str(excinfo.value)


def test_protocol_monitor_logs_redacted_rpc_url(monkeypatch):
    import importlib
    import logging

    pm = importlib.import_module("workers.protocol_monitor")

    monkeypatch.setattr(sys, "argv", ["protocol_monitor", "--rpc-url", _ALCHEMY])

    # Signal handlers sys.exit on SIGTERM.
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

    # Drive each supervised loop once instead of blocking in run_forever.
    def run_once(self):
        stop = threading.Event()
        stop.set()
        for _name, target in self._loops:
            target(stop)

    monkeypatch.setattr(pm.Supervisor, "run_forever", run_once)

    # configure_logging() clears root handlers on first call, dropping caplog's.
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
    assert "eth-mainnet.g.alchemy.com" in combined
    # Workers need the real key.
    fake_unified.run_scan_loop.assert_called_once()
    args, _kwargs = fake_unified.run_scan_loop.call_args
    assert args[0] == _ALCHEMY


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
