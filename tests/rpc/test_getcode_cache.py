"""Regression tests for the process-wide eth_getCode cache in ``services.clients.rpc``.

Bytecode is effectively immutable for a cascade, which probes the same addresses across stages
and sibling jobs, so caching bytecode + keccak saves the RTT. Pinned: repeat calls hit the
cache; RPC errors are NOT cached (a transient failure would cement an empty reading); TTL
expiry re-fetches; ``get_code`` and ``get_code_with_keccak`` share one cache; the keccak is
correct (load-bearing for the B10 Slither result cache); empty bytecode (``"0x"``) is cached.
"""

from __future__ import annotations

import pytest
from eth_utils.crypto import keccak

from services.clients import rpc


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch):
    # The PG bytecode layer would inject an extra eth_chainId call into every test here (they
    # count rpc_request invocations); pin it off. Covered in tests/rpc/test_bytecode_pg_cache.py.
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", False)
    rpc.clear_getcode_cache()
    yield
    rpc.clear_getcode_cache()


def test_repeat_call_hits_cache(monkeypatch):
    calls = {"n": 0}

    def _fake_rpc(_url, _method, _params, retries=1, *, chain_id=None):
        calls["n"] += 1
        return "0x6080604052"  # tiny EVM bytecode

    monkeypatch.setattr(rpc, "rpc_request", _fake_rpc)

    a = "0x" + "ab" * 20
    rpc.get_code("https://rpc", a)
    rpc.get_code("https://rpc", a)
    rpc.get_code("https://rpc", a)
    assert calls["n"] == 1, "second + third call must hit the cache"


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


def test_rpc_error_does_not_cache(monkeypatch):
    """Cementing a transient error would make the next classify misread an EOA / wrong contract."""
    raises = {"n": 0}

    def _fake_rpc(_url, _method, _params, retries=1, *, chain_id=None):
        raises["n"] += 1
        if raises["n"] == 1:
            raise RuntimeError("RPC down")
        return "0x60"

    monkeypatch.setattr(rpc, "rpc_request", _fake_rpc)

    addr = "0x" + "cc" * 20
    with pytest.raises(RuntimeError):
        rpc.get_code("https://rpc", addr)
    code = rpc.get_code("https://rpc", addr)
    assert code == "0x60"
    assert raises["n"] == 2


def test_ttl_expiry_triggers_refetch(monkeypatch):
    calls = {"n": 0}

    def _fake_rpc(_url, _method, _params, retries=1, *, chain_id=None):
        calls["n"] += 1
        return "0x60"

    monkeypatch.setattr(rpc, "rpc_request", _fake_rpc)

    fake_now = [1000.0]
    monkeypatch.setattr(rpc.time, "monotonic", lambda: fake_now[0])

    addr = "0x" + "dd" * 20
    rpc.get_code("https://rpc", addr)
    fake_now[0] += rpc._GETCODE_CACHE_TTL_S + 1
    rpc.get_code("https://rpc", addr)
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


def test_keccak_matches_eth_utils_for_real_bytecode(monkeypatch):
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x60806040526001600055")
    addr = "0x" + "ff" * 20
    _code, keccak_hex = rpc.get_code_with_keccak("https://rpc", addr)
    expected = "0x" + keccak(bytes.fromhex("60806040526001600055")).hex()
    assert keccak_hex == expected


def test_empty_bytecode_is_cached_with_correct_keccak(monkeypatch):
    """EOAs return ``"0x"``; caching it is fine (keccak of empty bytes is stable) so classify doesn't re-probe EOAs."""
    calls = {"n": 0}

    def _fake_rpc(_url, _method, _params, retries=1, *, chain_id=None):
        calls["n"] += 1
        return "0x"

    monkeypatch.setattr(rpc, "rpc_request", _fake_rpc)

    addr = "0x" + "00" * 19 + "01"
    code, keccak_hex = rpc.get_code_with_keccak("https://rpc", addr)
    assert code == "0x"
    assert keccak_hex == "0x" + keccak(b"").hex()

    rpc.get_code_with_keccak("https://rpc", addr)
    assert calls["n"] == 1


def test_address_normalization_keys_lowercased(monkeypatch):
    """Checksummed and lowercase addresses must hit the same slot (a mismatch would silently double cache pressure)."""
    calls = {"n": 0}

    def _fake_rpc(_url, _method, _params, retries=1, *, chain_id=None):
        calls["n"] += 1
        return "0x60"

    monkeypatch.setattr(rpc, "rpc_request", _fake_rpc)

    upper = "0x" + "AB" * 20
    lower = upper.lower()
    rpc.get_code("https://rpc", upper)
    rpc.get_code("https://rpc", lower)
    assert calls["n"] == 1, "case variations must share a single cache slot"


def test_cache_eviction_under_ceiling(monkeypatch):
    """Long-lived workers probe many addresses; the bound + oldest-quartile eviction must keep memory bounded."""
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x60")
    monkeypatch.setattr(rpc, "_GETCODE_CACHE_MAX", 8)
    for i in range(20):
        rpc.get_code("https://rpc", f"0x{i:040x}")
    assert len(rpc._GETCODE_CACHE) <= rpc._GETCODE_CACHE_MAX


# Phase B Step 4: get_code_batch — batch eth_getCode for many addresses


def test_get_code_batch_single_request_for_n_addresses(monkeypatch):
    rpc.clear_getcode_cache()
    calls = {"n": 0}

    def _fake_batch(_url, calls_list, *, chain_id=None):
        calls["n"] += 1
        return [(f"0x{i:02x}", False) for i in range(len(calls_list))]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)
    addrs = ["0x" + f"{i:040x}" for i in range(5)]
    out = rpc.get_code_batch("https://rpc", addrs)
    assert len(out) == 5
    assert calls["n"] == 1, "must batch all 5 addresses into one HTTP call"


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
    """Per-call errors OMIT that address from the map; the caller treats absence as a trigger to retry per-address."""
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
    """A later get_code_with_keccak must hit the batch-populated cache (keccak stored alongside the
    bytecode; load-bearing for the bytecode-keccak content cache and classifier shortcut)."""
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


# Codex iter-4 P2: providers may return "0x0" for empty bytecode


def test_get_code_with_keccak_handles_0x0_provider_response(monkeypatch):
    """Codex iter-4 P2: some providers return empty bytecode as odd-length "0x0", which would crash
    bytes.fromhex; normalize to "0x" so the EOA keccak is keccak(b'')."""
    rpc.clear_getcode_cache()
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x0")
    code, keccak_hex = rpc.get_code_with_keccak("https://rpc", "0x" + "11" * 20)
    assert code == "0x"
    assert keccak_hex == "0x" + keccak(b"").hex()


def test_get_code_batch_handles_0x0_provider_response(monkeypatch):
    rpc.clear_getcode_cache()

    def _fake_batch(_url, calls_list, *, chain_id=None):
        return [("0x0", False) for _ in calls_list]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)
    out = rpc.get_code_batch("https://rpc", ["0x" + "22" * 20])
    addr = "0x" + "22" * 20
    assert out[addr] == "0x"
    code, keccak_hex = rpc.get_code_with_keccak("https://rpc", addr)
    assert code == "0x"
    assert keccak_hex == "0x" + keccak(b"").hex()


# Codex iter-5 P2: batch insert path must honour the cache bound


def test_get_code_batch_evicts_when_over_ceiling(monkeypatch):
    """Codex iter-5 P2: get_code_batch inserted straight into _GETCODE_CACHE without the
    oldest-quartile eviction, so repeated large batches would exceed _GETCODE_CACHE_MAX."""
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


def test_get_code_batch_eviction_keeps_recent_entries(monkeypatch):
    """Dropping the oldest 25% must preserve the most recent entries (likely re-hit on the next BFS layer)."""
    rpc.clear_getcode_cache()
    monkeypatch.setattr(rpc, "_GETCODE_CACHE_MAX", 4)

    def _fake_batch(_url, calls_list, *, chain_id=None):
        return [("0x60", False) for _ in calls_list]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)

    older = [f"0x0{i:039x}" for i in range(4)]
    rpc.get_code_batch("https://rpc", older)
    newer = [f"0x9{i:039x}" for i in range(4)]
    rpc.get_code_batch("https://rpc", newer)

    keys = {k[1] for k in rpc._GETCODE_CACHE.keys()}
    for addr in newer:
        assert addr.lower() in keys, f"recent {addr} should not have been evicted"
