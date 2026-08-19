"""Unit tests for ``utils.rpc.eth_call_batch`` — the revert-data-preserving
JSON-RPC array batch the differential probe rides on. Stubs the HTTP session so
no live RPC is touched (fully deterministic)."""

from __future__ import annotations

from typing import Any

from eth_abi.abi import encode as abi_encode

import utils.rpc as rpc


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, payload):
        self._payload = payload
        self.posted: Any = None

    def post(self, url, json=None, timeout=None, headers=None):  # noqa: A002
        self.posted = json
        return _FakeResponse(self._payload)


def _error_string(msg: str) -> str:
    return "0x08c379a0" + abi_encode(["string"], [msg]).hex()


def test_eth_call_batch_preserves_success_revert_and_node_error(monkeypatch):
    revert_hex = _error_string("Ownable: caller is not the owner")
    payload = [
        {"jsonrpc": "2.0", "id": 0, "result": "0x" + "0" * 63 + "1"},
        {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted", "data": revert_hex}},
        {"jsonrpc": "2.0", "id": 2, "error": {"code": 3, "message": "execution reverted"}},  # no data
    ]
    session = _FakeSession(payload)
    monkeypatch.setattr(rpc, "_get_session", lambda: session)

    calls = [
        {"from": "0x" + "11" * 20, "to": "0x" + "22" * 20, "data": "0xabcdef01"},
        {"from": "0x" + "33" * 20, "to": "0x" + "22" * 20, "data": "0xabcdef01"},
        {"from": "0x" + "44" * 20, "to": "0x" + "22" * 20, "data": "0xabcdef01"},
    ]
    out = rpc.eth_call_batch("http://rpc", calls, "0x10")

    assert out[0].success is True
    assert out[0].return_data == "0x" + "0" * 63 + "1"
    assert out[0].revert_data is None

    assert out[1].success is False
    assert out[1].revert_data == revert_hex.lower()  # revert DATA preserved for attribution
    assert out[1].error_message == "execution reverted"

    assert out[2].success is False
    assert out[2].revert_data is None  # no data → indeterminate, never attributable

    # The per-call ``from`` override is actually sent on the wire.
    assert session.posted[0]["params"][0]["from"] == "0x" + "11" * 20
    assert session.posted[0]["params"][1] == "0x10"  # pinned block tag


def test_eth_call_batch_transport_failure_flags_every_slot(monkeypatch):
    class _BoomSession:
        def post(self, *a, **k):
            raise OSError("connection refused")

    monkeypatch.setattr(rpc, "_get_session", lambda: _BoomSession())
    out = rpc.eth_call_batch("http://rpc", [{"to": "0x" + "22" * 20, "data": "0x00"}], "latest")
    assert out[0].success is False
    assert out[0].revert_data is None
    assert "transport" in (out[0].error_message or "")


def test_eth_call_batch_empty_calls():
    assert rpc.eth_call_batch("http://rpc", [], "latest") == []


def test_extract_revert_data_shapes():
    assert rpc._extract_revert_data("0x08c379a0dead") == "0x08c379a0dead"
    assert rpc._extract_revert_data("Reverted 0xdeadbeef") == "0xdeadbeef"
    assert rpc._extract_revert_data("0x") == "0x"  # empty/bare revert is a real, comparable gate
    assert rpc._extract_revert_data(None) is None
    assert rpc._extract_revert_data("execution reverted") is None  # no payload
    assert rpc._extract_revert_data({"data": "0xfeed"}) == "0xfeed"  # nested
