"""Unit tests for the ``services.clients.rpc.multicall3_aggregate3`` primitive.

The Multicall3 ``aggregate3`` helper collapses N read-only ``eth_call``s into one
billable call. These tests stub only the wire (``services.clients.rpc.rpc_request``) with a
fake that behaves like a real Multicall3 endpoint — decoding the ``aggregate3``
calldata and re-encoding ``(bool,bytes)[]`` — so they exercise the real ABI
encode/decode in the helper and pin:

* round-trip of success + revert (allowFailure) results, aligned to input order;
* empty input issues no RPC;
* chunking preserves global order and bounds per-call width;
* a malformed / wrong-length response raises (so callers fall back per-call);
* transport errors propagate (so callers fall back);
* the derived selector matches canonical Multicall3 ``aggregate3``.
"""

from __future__ import annotations

import pytest
from eth_abi.abi import decode, encode

import services.clients.rpc as rpc_mod
from services.clients.rpc import MULTICALL3_ADDRESS, multicall3_aggregate3, selector


def _fake_multicall_chain(state: dict[tuple[str, str], tuple[bool, str]], *, recorder: list | None = None):
    """Return a fake ``rpc_request`` that answers an aggregate3 eth_call from ``state``.

    ``state`` maps ``(target_lower, calldata_hex_lower) -> (success, return_hex)``; a missing
    sub-call reverts ``(False, "0x")`` — exactly how Multicall3 reports a reverting call under
    ``allowFailure=true``.
    """

    def fake(_rpc_url: str, method: str, params: list, **_kw):
        assert method == "eth_call"
        call = params[0]
        assert call["to"].lower() == MULTICALL3_ADDRESS.lower()
        if recorder is not None:
            recorder.append(call)
        sub_calls = decode(["(address,bool,bytes)[]"], bytes.fromhex(call["data"][10:]))[0]
        out = []
        for target, allow_failure, calldata in sub_calls:
            assert allow_failure is True, "helper must always set allowFailure=true"
            key = (target.lower(), "0x" + calldata.hex())
            success, ret_hex = state.get(key, (False, "0x"))
            ret_bytes = bytes.fromhex(ret_hex[2:]) if ret_hex.startswith("0x") and len(ret_hex) > 2 else b""
            out.append((success, ret_bytes))
        return "0x" + encode(["(bool,bytes)[]"], [out]).hex()

    return fake


def test_selector_is_canonical_aggregate3():
    assert selector("aggregate3((address,bool,bytes)[])") == "0x82ad56cb"


def test_aggregate3_round_trip_success_and_revert(monkeypatch):
    a = "0x" + "11" * 20
    b = "0x" + "22" * 20
    state = {
        (a, "0x06fdde03"): (True, "0x" + "ab" * 32),
        (b, "0xdeadbeef"): (False, "0x"),  # reverts
    }
    monkeypatch.setattr(rpc_mod, "rpc_request", _fake_multicall_chain(state))
    out = multicall3_aggregate3("http://rpc", [(a, "0x06fdde03"), (b, "0xdeadbeef")])
    assert out == [(True, "0x" + "ab" * 32), (False, "0x")]


def test_empty_calls_issues_no_rpc(monkeypatch):
    called = []
    monkeypatch.setattr(rpc_mod, "rpc_request", lambda *a, **k: called.append(1))
    assert multicall3_aggregate3("http://rpc", []) == []
    assert called == []


def test_chunking_preserves_order_and_bounds_width(monkeypatch):
    a = "0x" + "11" * 20
    recorder: list = []
    state = {(a, f"0x{i:08x}"): (True, "0x" + format(i, "064x")) for i in range(5)}
    monkeypatch.setattr(rpc_mod, "rpc_request", _fake_multicall_chain(state, recorder=recorder))
    items = [(a, f"0x{i:08x}") for i in range(5)]
    out = multicall3_aggregate3("http://rpc", items, chunk_size=2)
    assert len(recorder) == 3, "5 items at chunk_size=2 → 3 aggregate3 calls (2+2+1)"
    assert out == [(True, "0x" + format(i, "064x")) for i in range(5)]


def test_wrong_length_response_raises(monkeypatch):
    a = "0x" + "11" * 20

    def bad(_rpc_url, _method, _params, **_kw):
        # One result for two requested calls.
        return "0x" + encode(["(bool,bytes)[]"], [[(True, b"")]]).hex()

    monkeypatch.setattr(rpc_mod, "rpc_request", bad)
    with pytest.raises(RuntimeError):
        multicall3_aggregate3("http://rpc", [(a, "0x01"), (a, "0x02")])


def test_non_hex_response_raises(monkeypatch):
    monkeypatch.setattr(rpc_mod, "rpc_request", lambda *a, **k: None)
    with pytest.raises(RuntimeError):
        multicall3_aggregate3("http://rpc", [("0x" + "11" * 20, "0x01")])


def test_transport_error_propagates(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("rpc down")

    monkeypatch.setattr(rpc_mod, "rpc_request", boom)
    with pytest.raises(RuntimeError):
        multicall3_aggregate3("http://rpc", [("0x" + "11" * 20, "0x01")])
