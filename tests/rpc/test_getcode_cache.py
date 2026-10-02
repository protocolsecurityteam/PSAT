from __future__ import annotations

import pytest
from eth_utils.crypto import keccak

from services.clients import rpc


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch):
    # The PG layer adds an eth_chainId call and these tests count rpc_request calls.
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", False)
    rpc.clear_getcode_cache()
    yield
    rpc.clear_getcode_cache()


def test_different_addresses_keep_separate_slots(monkeypatch):
    calls = {"n": 0}

    def _fake_rpc(_url, _method, params, retries=1, *, chain_id=None):
        calls["n"] += 1
        return "0x" + (params[0][2:4] * 32)

    monkeypatch.setattr(rpc, "rpc_request", _fake_rpc)

    a = "0x" + "11" * 20
    b = "0x" + "22" * 20
    code_a = rpc.get_code("https://rpc", a)
    code_b = rpc.get_code("https://rpc", b)
    assert code_a != code_b
    assert calls["n"] == 2, "two distinct addresses must each hit the wire once"

    rpc.get_code("https://rpc", a)
    rpc.get_code("https://rpc", b)
    assert calls["n"] == 2


def test_get_code_and_get_code_with_keccak_share_cache(monkeypatch):
    calls = {"n": 0}

    def _fake_rpc(_url, _method, _params, retries=1, *, chain_id=None):
        calls["n"] += 1
        return "0xabcd"

    monkeypatch.setattr(rpc, "rpc_request", _fake_rpc)

    addr = "0x" + "ee" * 20
    code = rpc.get_code("https://rpc", addr)
    code2, keccak_hex = rpc.get_code_with_keccak("https://rpc", addr)
    assert code == code2
    assert calls["n"] == 1, "second getter must hit the cache populated by the first"
    assert keccak_hex == "0x" + keccak(bytes.fromhex("abcd")).hex()


def test_cache_eviction_under_ceiling(monkeypatch):
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x60")
    monkeypatch.setattr(rpc, "_GETCODE_CACHE_MAX", 8)
    for i in range(20):
        rpc.get_code("https://rpc", f"0x{i:040x}")
    assert len(rpc._GETCODE_CACHE) <= rpc._GETCODE_CACHE_MAX


def test_get_code_batch_short_circuits_already_cached(monkeypatch):
    rpc.clear_getcode_cache()

    def _fake_batch(_url, calls_list, *, chain_id=None):
        assert len(calls_list) <= 1, "cached addresses must be filtered before batching"
        return [("0xff00", False) for _ in calls_list]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x60806040")

    pre = "0x" + "aa" * 20
    rpc.get_code("https://rpc", pre)
    new = "0x" + "bb" * 20
    out = rpc.get_code_batch("https://rpc", [pre, new])
    assert out[pre] == "0x60806040"
    assert out[new] == "0xff00"


def test_get_code_batch_empty_input_no_http(monkeypatch):
    rpc.clear_getcode_cache()

    def _no_call(*_a, **_kw):
        raise AssertionError("must not call rpc_batch_request_with_status on empty input")

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _no_call)
    assert rpc.get_code_batch("https://rpc", []) == {}


def test_get_code_batch_omits_errored_slots(monkeypatch):
    """Absence triggers a per-address retry."""
    rpc.clear_getcode_cache()

    def _fake_batch(_url, calls_list, *, chain_id=None):
        return [("0x60", False), (None, True), ("0x80", False)]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)
    addrs = ["0x" + f"{i:040x}" for i in range(3)]
    out = rpc.get_code_batch("https://rpc", addrs)
    assert addrs[0].lower() in out
    assert addrs[1].lower() not in out  # errored slot omitted
    assert addrs[2].lower() in out


def test_get_code_batch_populates_keccak_index(monkeypatch):
    """The bytecode-keccak content cache and classifier shortcut depend on it."""
    rpc.clear_getcode_cache()

    def _fake_batch(_url, calls_list, *, chain_id=None):
        return [("0xdeadbeef", False) for _ in calls_list]

    follow_up_calls = {"n": 0}

    def _no_followup(*_a, **_kw):
        follow_up_calls["n"] += 1
        return "0xfresh"

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)
    monkeypatch.setattr(rpc, "rpc_request", _no_followup)

    addr = "0x" + "11" * 20
    rpc.get_code_batch("https://rpc", [addr])
    code, keccak_hex = rpc.get_code_with_keccak("https://rpc", addr)
    assert code == "0xdeadbeef"
    assert keccak_hex == "0x" + keccak(bytes.fromhex("deadbeef")).hex()
    assert follow_up_calls["n"] == 0, "follow-up must hit cache from the batch"


def test_get_code_batch_evicts_when_over_ceiling(monkeypatch):
    rpc.clear_getcode_cache()
    monkeypatch.setattr(rpc, "_GETCODE_CACHE_MAX", 8)

    def _fake_batch(_url, calls_list, *, chain_id=None):
        return [("0x60", False) for _ in calls_list]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)

    for batch_n in range(3):
        addrs = [f"0x{batch_n}{i:039x}" for i in range(8)]
        rpc.get_code_batch("https://rpc", addrs)

    assert len(rpc._GETCODE_CACHE) <= rpc._GETCODE_CACHE_MAX, (
        f"batch insert bypassed eviction: cache has {len(rpc._GETCODE_CACHE)} entries (max {rpc._GETCODE_CACHE_MAX})"
    )
