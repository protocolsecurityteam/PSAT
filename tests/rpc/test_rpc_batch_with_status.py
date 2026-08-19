"""Regression tests for ``services.clients.rpc.rpc_batch_request_with_status``.

The existing ``rpc_batch_request`` returns ``None`` for both error AND
"function legitimately returned no data" — fine for callers that don't
need to distinguish, but fatal for cache layers like
``classify_resolved_address`` where treating a transient RPC failure as
"function absent" would cement a misclassification.

The ``_with_status`` variant fixes that by returning ``(result, had_error)``.
This test file pins the contract at the boundary so a future refactor
can't silently revert to the lossy shape.

What we cover:
1. Success: every call returns ``(result, had_error=False)``.
2. Per-call JSON-RPC error: that slot returns ``(None, True)``;
   neighbours are unaffected.
3. Whole-chunk transport failure (network/5xx): every slot returns
   ``(None, True)``.
4. Provider returns single dict instead of list: handled.
5. Provider returns malformed payload (not list, not dict): every slot
   in chunk returns ``(None, True)``.
6. Out-of-range ``id`` in response: ignored (not crashed).
7. Empty input → empty output (don't make any HTTP call).
8. Result correctly preserves ``None`` returned by a successful call
   (e.g. ``eth_call`` to a missing function returning ``"0x"`` is
   passed through verbatim — caller decides what "0x" means).
9. The three-state core ``rpc_batch_request_classified`` keeps an
   answered per-call error (``"error"``) apart from a batch the node
   never answered (``"transport"``) — the ``_with_status`` wrapper
   collapses both to ``had_error=True`` (pinned by 2/3 above), so any
   caller that must publish an earned negative uses the classified form.
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
    """One slot errors; the other returns clean. The whole point of the
    helper is keeping these signals independent."""
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
    """If the HTTP call itself fails (network, DNS, 5xx), every slot in
    that chunk must be flagged. Conflating with success would cause
    callers to cache (None, False) and never re-probe."""
    _reset_thread_session()
    session = rpc._get_session()
    with patch.object(session, "post", side_effect=ConnectionError("DNS")):
        results = rpc.rpc_batch_request_with_status(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == [(None, True), (None, True)]


def test_single_dict_response_normalized_to_list():
    """Some providers return one item as a dict instead of a 1-element
    list when the batch has a single call. Must still parse cleanly."""
    _reset_thread_session()
    response = _make_response(200, {"jsonrpc": "2.0", "id": 0, "result": "0xsolo"})
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_with_status("https://example.invalid", [("eth_call", [{}, "latest"])])
    assert results == [("0xsolo", False)]


def test_malformed_payload_marks_chunk_errored():
    """Provider returned a non-list/non-dict body (e.g. an HTML error
    page parsed as JSON-string by accident). Defensive: flag everything."""
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
    """Defensive against a misbehaving provider — must not IndexError."""
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
    """Empty input must not make any HTTP call — both correctness and
    a defensive measure against misuse."""
    _reset_thread_session()
    session = rpc._get_session()
    with patch.object(session, "post") as mocked_post:
        results = rpc.rpc_batch_request_with_status("https://example.invalid", [])
    assert results == []
    assert mocked_post.call_count == 0


def test_successful_null_result_preserved_with_error_false():
    """eth_call to a missing function returns ``"0x"`` (success, just no
    data). Must come back as (``"0x"``, False) — caller decides whether
    "no data" means "function absent". Conflating with error would lose
    that distinction."""
    _reset_thread_session()
    response = _make_response(
        200,
        [{"jsonrpc": "2.0", "id": 0, "result": "0x"}],
    )
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_with_status("https://example.invalid", [("eth_call", [{}, "latest"])])
    assert results == [("0x", False)]


# ---------------------------------------------------------------------------
# rpc_batch_request_classified — the three-state core
# ---------------------------------------------------------------------------


def test_classified_per_call_error_is_error_not_transport():
    """A revert is an ANSWERED call: the node observed it and said no.
    It must never read as the transport shape (unobserved), and the ok
    neighbour keeps its result."""
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
    """A batch the node never answered observed nothing: every slot is
    ``"transport"`` — never the earned-looking per-call ``"error"``."""
    _reset_thread_session()
    session = rpc._get_session()
    with patch.object(session, "post", side_effect=ConnectionError("DNS")):
        results = rpc.rpc_batch_request_classified(
            "https://example.invalid",
            [("eth_call", [{}, "latest"]), ("eth_call", [{}, "latest"])],
        )
    assert results == [(None, "transport"), (None, "transport")]


def test_classified_skipped_id_stays_transport():
    """A slot the response never named was not observed — it stays
    ``"transport"``, not ``"ok"`` and not ``"error"``."""
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
    """``"0x"`` from a permissive fallback is an answered, error-free call:
    ``("0x", "ok")`` verbatim — the CALLER decides what an empty return
    means (the poll loop publishes it as ``no_value``)."""
    _reset_thread_session()
    response = _make_response(200, [{"jsonrpc": "2.0", "id": 0, "result": "0x"}])
    session = rpc._get_session()
    with patch.object(session, "post", return_value=response):
        results = rpc.rpc_batch_request_classified("https://example.invalid", [("eth_call", [{}, "latest"])])
    assert results == [("0x", "ok")]
