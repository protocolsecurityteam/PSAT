"""``rpc_batch_request`` returns None for both error and no data; a cache reading transient failure as "function
absent" would cement a misclassification.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from services.clients import rpc


def _reset_thread_session():
    if hasattr(rpc._session_local, "session"):
        del rpc._session_local.session


def _make_response(status_code: int, payload):
    r = MagicMock()
    r.status_code = status_code
    r.raise_for_status.return_value = None
    r.json.return_value = payload
    return r


def test_out_of_range_id_in_response_is_ignored():
    _reset_thread_session()
    response = _make_response(
        200,
        [
            {"jsonrpc": "2.0", "id": 99, "result": "0xignore"},  # out of range
            {"jsonrpc": "2.0", "id": 0, "result": "0xok"},
        ],
    )
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_with_status("https://example.invalid", [("eth_call", [{}, "latest"])])
    assert results == [("0xok", False)]


def test_empty_calls_short_circuits_without_http():
    _reset_thread_session()
    session = rpc._get_session()
    with patch.object(session, "post") as mocked_post:
        results = rpc.rpc_batch_request_with_status("https://example.invalid", [])
    assert results == []
    assert mocked_post.call_count == 0
