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


def test_all_success_returns_results_with_error_false():
    _reset_thread_session()
    response = _make_response(
        200,
        [
            {"jsonrpc": "2.0", "id": 0, "result": "0xaa"},
            {"jsonrpc": "2.0", "id": 1, "result": "0xbb"},
        ],
    )
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_with_status(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == [("0xaa", False), ("0xbb", False)]


def test_per_call_error_does_not_taint_neighbours():
    _reset_thread_session()
    response = _make_response(
        200,
        [
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32000, "message": "execution reverted"}},
            {"jsonrpc": "2.0", "id": 1, "result": "0xok"},
        ],
    )
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_with_status(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == [(None, True), ("0xok", False)]


def test_whole_chunk_transport_failure_marks_all_errored():
    """Otherwise callers would cache (None, False) and never re-probe."""
    _reset_thread_session()
    session = rpc._get_session()
    with patch.object(session, "post", side_effect=ConnectionError("DNS")):
        results = rpc.rpc_batch_request_with_status(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == [(None, True), (None, True)]


def test_single_dict_response_normalized_to_list():
    _reset_thread_session()
    response = _make_response(200, {"jsonrpc": "2.0", "id": 0, "result": "0xsolo"})
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_with_status("https://example.invalid", [("eth_call", [{}, "latest"])])
    assert results == [("0xsolo", False)]


def test_malformed_payload_marks_chunk_errored():
    _reset_thread_session()
    response = _make_response(200, "not-a-list")
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_with_status(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == [(None, True), (None, True)]


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


def test_successful_null_result_preserved_with_error_false():
    _reset_thread_session()
    response = _make_response(
        200,
        [{"jsonrpc": "2.0", "id": 0, "result": "0x"}],
    )
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_with_status("https://example.invalid", [("eth_call", [{}, "latest"])])
    assert results == [("0x", False)]


def test_classified_per_call_error_is_error_not_transport():
    _reset_thread_session()
    response = _make_response(
        200,
        [
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32000, "message": "execution reverted"}},
            {"jsonrpc": "2.0", "id": 1, "result": "0xok"},
        ],
    )
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_classified(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == [(None, "error"), ("0xok", "ok")]


def test_classified_transport_failure_is_transport_not_error():
    _reset_thread_session()
    session = rpc._get_session()
    with patch.object(session, "post", side_effect=ConnectionError("DNS")):
        results = rpc.rpc_batch_request_classified(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == [(None, "transport"), (None, "transport")]


def test_classified_skipped_id_stays_transport():
    _reset_thread_session()
    response = _make_response(
        200,
        [{"jsonrpc": "2.0", "id": 1, "result": "0xok"}],  # id 0 missing
    )
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_classified(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == [(None, "transport"), ("0xok", "ok")]


def test_classified_empty_return_is_ok_with_verbatim_result():
    """The caller decides what it means."""
    _reset_thread_session()
    response = _make_response(200, [{"jsonrpc": "2.0", "id": 0, "result": "0x"}])
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_classified("https://example.invalid", [("eth_call", [{}, "latest"])])
    assert results == [("0x", "ok")]
