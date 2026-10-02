"""Per-thread Sessions let urllib3 reuse TCP/TLS sockets for RPC-heavy stages."""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import MagicMock, patch

from services.clients import rpc


def _reset_thread_session():
    if hasattr(rpc._session_local, "session"):
        del rpc._session_local.session


def test_same_thread_reuses_session():
    _reset_thread_session()
    s1 = rpc._get_session()
    s2 = rpc._get_session()
    assert s1 is s2, "per-thread Session must be cached, not rebuilt per call"


def test_different_threads_get_different_sessions():
    """Sharing would corrupt socket state under load, invisibly in single-threaded benches."""
    _reset_thread_session()
    main_session = rpc._get_session()
    other_session: list[Any] = []

    def _worker():
        other_session.append(rpc._get_session())

    t = threading.Thread(target=_worker)
    t.start()
    t.join(timeout=5)
    assert other_session, "worker thread did not run"
    assert other_session[0] is not main_session


def test_rpc_request_routes_through_session():
    """A revert to bare ``requests.post`` would lose pooling silently."""
    _reset_thread_session()
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": "0xdead"}

    session = rpc._get_session()
    with patch.object(session, "post", return_value=fake_response) as mocked_post:
        result = rpc.rpc_request("https://example.invalid", "eth_call", [{}, "latest"])
    assert result == "0xdead"
    assert mocked_post.call_count == 1


def test_rpc_request_retries_on_retryable_status():
    _reset_thread_session()

    failing = MagicMock()
    failing.status_code = 503
    failing.json.return_value = {}

    succeeding = MagicMock()
    succeeding.status_code = 200
    succeeding.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": "0xok"}

    session = rpc._get_session()
    with (
        patch.object(session, "post", side_effect=[failing, succeeding]) as mocked_post,
        patch("services.clients.rpc.time.sleep"),  # don't actually back off in tests
    ):
        result = rpc.rpc_request("https://example.invalid", "eth_call", [{}, "latest"], retries=1)
    assert result == "0xok"
    assert mocked_post.call_count == 2


def test_rpc_batch_request_routes_through_session():
    _reset_thread_session()
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = [
        {"jsonrpc": "2.0", "id": 0, "result": "0x01"},
        {"jsonrpc": "2.0", "id": 1, "result": "0x02"},
    ]

    session = rpc._get_session()
    with patch.object(session, "post", return_value=fake_response) as mocked_post:
        results = rpc.rpc_batch_request(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == ["0x01", "0x02"]
    assert mocked_post.call_count == 1
