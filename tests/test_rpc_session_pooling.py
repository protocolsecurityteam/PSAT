"""Regression tests for the per-thread ``requests.Session`` introduced
in ``utils/rpc.py``.

Bare ``requests.post()`` opens a new socket per call. Per-thread Sessions
let the underlying urllib3 connection pool reuse TCP/TLS sockets across
calls — relevant for RPC-heavy stages (resolution recursive walk) where
TLS handshake latency dominates the cost of an individual eth_call.

What we pin here:
1. The same Session is returned on repeated calls within one thread (the
   whole point — reuse).
2. Different threads get *different* Session objects (requests.Session
   is not thread-safe, so a global one would race).
3. ``rpc_request`` actually calls through the cached Session, not
   ``requests.post`` directly — a refactor that silently reverts to
   bare ``requests.post`` would re-introduce the per-call handshake.
4. The retry path still works after the Session swap (regression guard
   for the error-handling branch, which sits inside the Session call).
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils import rpc


def _reset_thread_session():
    """Clear the per-thread Session cache so a test starts fresh."""
    if hasattr(rpc._session_local, "session"):
        del rpc._session_local.session


def test_same_thread_reuses_session():
    _reset_thread_session()
    s1 = rpc._get_session()
    s2 = rpc._get_session()
    assert s1 is s2, "per-thread Session must be cached, not rebuilt per call"


def test_different_threads_get_different_sessions():
    """requests.Session is not thread-safe across calls. If two threads
    ever shared one, we'd get sporadic socket-state corruption under
    load. Keep this guard tight — it's invisible in single-threaded
    bench runs but burns prod."""
    _reset_thread_session()
    main_session = rpc._get_session()
    other_session: list[Any] = []

    def _worker():
        # No reset here — we want each thread to get its own fresh one.
        other_session.append(rpc._get_session())

    t = threading.Thread(target=_worker)
    t.start()
    t.join(timeout=5)
    assert other_session, "worker thread did not run"
    assert other_session[0] is not main_session


def test_rpc_request_routes_through_session():
    """If a future refactor reverts to bare ``requests.post`` we lose
    pooling silently — bench wouldn't catch it for weeks. Pin the
    Session.post call site."""
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
    """The retry loop must still work after the Session swap. We hit the
    retry branch by returning a 503 once, then a 200."""
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
        patch("utils.rpc.time.sleep"),  # don't actually back off in tests
    ):
        result = rpc.rpc_request("https://example.invalid", "eth_call", [{}, "latest"], retries=1)
    assert result == "0xok"
    assert mocked_post.call_count == 2


def test_rpc_batch_request_routes_through_session():
    """Same regression guard as above, but for the batch path."""
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
