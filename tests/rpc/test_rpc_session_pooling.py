"""Per-thread Sessions let urllib3 reuse TCP/TLS sockets for RPC-heavy stages."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from services.clients import rpc


def _reset_thread_session():
    if hasattr(rpc._session_local, "session"):
        del rpc._session_local.session


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
