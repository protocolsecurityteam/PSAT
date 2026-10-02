"""The wire stub decodes aggregate3 calldata and re-encodes ``(bool,bytes)[]``, so the real ABI code runs."""

from __future__ import annotations

import pytest
from eth_abi.abi import decode, encode

import services.clients.rpc as rpc_mod
from services.clients.rpc import MULTICALL3_ADDRESS, multicall3_aggregate3


def _fake_multicall_chain(state: dict[tuple[str, str], tuple[bool, str]], *, recorder: list | None = None):
    """A missing sub-call reverts ``(False, "0x")``, as Multicall3 reports under ``allowFailure=true``."""

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


def test_non_hex_response_raises(monkeypatch):
    monkeypatch.setattr(rpc_mod, "rpc_request", lambda *a, **k: None)
    with pytest.raises(RuntimeError):
        multicall3_aggregate3("http://rpc", [("0x" + "11" * 20, "0x01")])
