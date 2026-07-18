"""Regression tests for the process-wide eth_getCode cache in
``utils.rpc``.

Bytecode at a deployed address is effectively immutable for the lifetime
of a cascade. The cascade probes the same addresses across stages (
discovery → resolution → policy) and across sibling jobs touching shared
infra (OZ libraries, common impls). Caching the bytecode + its keccak
saves the RTT on every repeat probe.

What we pin:
1. Repeat call within TTL hits the cache (no second RPC).
2. RPC errors are NOT cached — must propagate, otherwise a transient
   failure cements an empty bytecode reading.
3. TTL expiry triggers re-fetch.
4. Different addresses keep separate slots.
5. ``get_code`` and ``get_code_with_keccak`` share the same cache (i.e.,
   one call populates both).
6. The keccak is computed correctly (matches eth_utils.keccak of the
   raw bytecode bytes — load-bearing for B10 Slither result cache).
7. Empty bytecode (``"0x"``) is cached; keccak is keccak of empty bytes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from eth_utils.crypto import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils import rpc


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch):
    # The cross-process PG bytecode layer would inject an extra eth_chainId
    # discovery call into every test in this file (which counts rpc_request
    # invocations). Pin it off; PG-cache behaviour is covered separately in
    # tests/test_bytecode_pg_cache.py.
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
        # Return different bytecode per address so we can detect mixups.
        return "0x" + (params[0][2:4] * 32)

    monkeypatch.setattr(rpc, "rpc_request", _fake_rpc)

    a = "0x" + "11" * 20
    b = "0x" + "22" * 20
    code_a = rpc.get_code("https://rpc", a)
    code_b = rpc.get_code("https://rpc", b)
    assert code_a != code_b
    assert calls["n"] == 2, "two distinct addresses must each hit the wire once"

    # And both are cached.
    rpc.get_code("https://rpc", a)
    rpc.get_code("https://rpc", b)
    assert calls["n"] == 2


def test_rpc_error_does_not_cache(monkeypatch):
    """Cementing a transient error as a cached value would cause the next
    classify on this address to misread an EOA / wrong contract."""
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
    # Second call MUST go back to the wire (no cached error).
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
    """One call populates the cache; the OTHER getter sees the same hit."""
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
    # And the keccak is correct.
    assert keccak_hex == "0x" + keccak(bytes.fromhex("abcd")).hex()


def test_keccak_matches_eth_utils_for_real_bytecode(monkeypatch):
    """Load-bearing for B10 (content-addressed Slither cache): the keccak
    we cache must equal eth_utils.keccak(bytes.fromhex(bytecode_no_prefix))."""
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x60806040526001600055")
    addr = "0x" + "ff" * 20
    _code, keccak_hex = rpc.get_code_with_keccak("https://rpc", addr)
    expected = "0x" + keccak(bytes.fromhex("60806040526001600055")).hex()
    assert keccak_hex == expected


def test_empty_bytecode_is_cached_with_correct_keccak(monkeypatch):
    """EOA addresses return ``"0x"``. Caching this is fine — keccak of
    empty bytes is well-defined and stable. Subsequent calls must hit
    the cache (don't re-probe EOAs every classify)."""
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
    """``get_code(rpc, "0xABCD...")`` and ``get_code(rpc, "0xabcd...")``
    must hit the same cache slot — Ethereum addresses are case-insensitive
    and a checksummed-vs-lower mismatch would silently double the cache
    pressure."""
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
    """Long-lived workers can probe many addresses. The bound + oldest-
    quartile eviction must keep memory bounded without crashing."""
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x60")
    # Temporarily lower the ceiling so the test isn't slow.
    monkeypatch.setattr(rpc, "_GETCODE_CACHE_MAX", 8)
    for i in range(20):
        rpc.get_code("https://rpc", f"0x{i:040x}")
    # Cache size must stay under the ceiling.
    assert len(rpc._GETCODE_CACHE) <= rpc._GETCODE_CACHE_MAX


def test_clear_getcode_cache_empties_state():
    rpc._GETCODE_CACHE[("https://rpc", "0xabc")] = ("0x60", "0x" + "0" * 64, 0.0)
    assert len(rpc._GETCODE_CACHE) == 1
    rpc.clear_getcode_cache()
    assert len(rpc._GETCODE_CACHE) == 0


def test_get_code_uses_cached_value_with_unrelated_get_code_with_keccak(monkeypatch):
    """Belt-and-suspenders cross-API check: any future split that gives
    each function its own private cache would silently double RPC load."""
    calls = []

    def _fake_rpc(_url, _method, params, retries=1, *, chain_id=None):
        calls.append(params[0])
        return "0xdeadbeef"

    monkeypatch.setattr(rpc, "rpc_request", _fake_rpc)
    addr = "0x" + "11" * 20

    rpc.get_code_with_keccak("https://rpc", addr)
    rpc.get_code("https://rpc", addr)
    rpc.get_code_with_keccak("https://rpc", addr)
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Phase B Step 4: get_code_batch — batch eth_getCode for many addresses
# ---------------------------------------------------------------------------


def test_get_code_batch_single_request_for_n_addresses(monkeypatch):
    """The whole point: one HTTP call for N addresses instead of N calls.
    Verifies via a single rpc_batch_request_with_status invocation."""
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
    """Addresses already in the per-thread cache must NOT be re-fetched.
    Saves the wire entirely when subsequent batches overlap with prior."""
    rpc.clear_getcode_cache()

    def _fake_batch(_url, calls_list, *, chain_id=None):
        # Should only ever be called for cache-MISS addresses.
        assert len(calls_list) <= 1, "cached addresses must be filtered before batching"
        return [("0xff00", False) for _ in calls_list]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x60806040")

    # Pre-populate cache for one address via the single-call API.
    pre = "0x" + "aa" * 20
    rpc.get_code("https://rpc", pre)
    # Now batch over [pre, new] — pre should be served from cache, new from batch.
    new = "0x" + "bb" * 20
    out = rpc.get_code_batch("https://rpc", [pre, new])
    assert out[pre] == "0x60806040"
    assert out[new] == "0xff00"


def test_get_code_batch_empty_input_no_http(monkeypatch):
    """Empty input must short-circuit cleanly, never call the wire."""
    rpc.clear_getcode_cache()

    def _no_call(*_a, **_kw):
        raise AssertionError("must not call rpc_batch_request_with_status on empty input")

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _no_call)
    assert rpc.get_code_batch("https://rpc", []) == {}


def test_get_code_batch_omits_errored_slots(monkeypatch):
    """Per-call errors → that address is OMITTED from the returned map.
    Caller (e.g., static_dependencies) treats absence as a fall-back
    trigger to retry per-address."""
    rpc.clear_getcode_cache()

    def _fake_batch(_url, calls_list, *, chain_id=None):
        # First call succeeds, second errors, third succeeds.
        return [("0x60", False), (None, True), ("0x80", False)]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)
    addrs = ["0x" + f"{i:040x}" for i in range(3)]
    out = rpc.get_code_batch("https://rpc", addrs)
    assert addrs[0].lower() in out
    assert addrs[1].lower() not in out  # errored slot omitted
    assert addrs[2].lower() in out


def test_get_code_batch_populates_keccak_index(monkeypatch):
    """A subsequent get_code_with_keccak must hit the cache populated by
    the batch — proves the keccak is computed and stored alongside the
    bytecode (load-bearing for the bytecode-keccak content cache from
    Step 2 / classifier shortcut from Step 3)."""
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


# ---------------------------------------------------------------------------
# Codex iter-4 P2: providers may return "0x0" for empty bytecode
# ---------------------------------------------------------------------------


def test_get_code_with_keccak_handles_0x0_provider_response(monkeypatch):
    """Codex iter-4 P2: some RPC providers return empty bytecode as
    "0x0" (odd-length hex) instead of "0x". bytes.fromhex would crash.
    Normalize to "0x" so the keccak computation produces keccak(b'')
    cleanly for EOAs."""
    rpc.clear_getcode_cache()
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x0")
    code, keccak_hex = rpc.get_code_with_keccak("https://rpc", "0x" + "11" * 20)
    assert code == "0x"
    assert keccak_hex == "0x" + keccak(b"").hex()


def test_get_code_batch_handles_0x0_provider_response(monkeypatch):
    """Same odd-length protection in the batch path."""
    rpc.clear_getcode_cache()

    def _fake_batch(_url, calls_list, *, chain_id=None):
        return [("0x0", False) for _ in calls_list]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)
    out = rpc.get_code_batch("https://rpc", ["0x" + "22" * 20])
    addr = "0x" + "22" * 20
    # Normalized to "0x" before storing.
    assert out[addr] == "0x"
    # And the keccak in cache is keccak(b'').
    code, keccak_hex = rpc.get_code_with_keccak("https://rpc", addr)
    assert code == "0x"
    assert keccak_hex == "0x" + keccak(b"").hex()


# ---------------------------------------------------------------------------
# Codex iter-5 P2: batch insert path must honour the cache bound
# ---------------------------------------------------------------------------


def test_get_code_batch_evicts_when_over_ceiling(monkeypatch):
    """Codex iter-5 P2 — get_code_batch was inserting directly into
    _GETCODE_CACHE without running the oldest-quartile eviction that
    the single-call path uses. Repeated large batches in a long-lived
    worker would exceed _GETCODE_CACHE_MAX with full bytecode payloads.
    Verify the bound now holds for the batch path too."""
    rpc.clear_getcode_cache()
    monkeypatch.setattr(rpc, "_GETCODE_CACHE_MAX", 8)

    def _fake_batch(_url, calls_list, *, chain_id=None):
        return [("0x60", False) for _ in calls_list]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)

    # Insert 24 distinct addresses via successive batch calls.
    for batch_n in range(3):
        addrs = [f"0x{batch_n}{i:039x}" for i in range(8)]
        rpc.get_code_batch("https://rpc", addrs)

    # Cache must NOT have grown unboundedly.
    assert len(rpc._GETCODE_CACHE) <= rpc._GETCODE_CACHE_MAX, (
        f"batch insert bypassed eviction: cache has {len(rpc._GETCODE_CACHE)} entries (max {rpc._GETCODE_CACHE_MAX})"
    )


def test_get_code_batch_eviction_keeps_recent_entries(monkeypatch):
    """The eviction policy (drop oldest 25%) must preserve the most
    recently inserted entries — those are the ones likely to be re-hit
    on the next BFS layer."""
    rpc.clear_getcode_cache()
    monkeypatch.setattr(rpc, "_GETCODE_CACHE_MAX", 4)

    def _fake_batch(_url, calls_list, *, chain_id=None):
        return [("0x60", False) for _ in calls_list]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _fake_batch)

    older = [f"0x0{i:039x}" for i in range(4)]
    rpc.get_code_batch("https://rpc", older)
    newer = [f"0x9{i:039x}" for i in range(4)]
    rpc.get_code_batch("https://rpc", newer)

    # At least the newer addresses survived (eviction dropped older ones).
    keys = {k[1] for k in rpc._GETCODE_CACHE.keys()}
    for addr in newer:
        assert addr.lower() in keys, f"recent {addr} should not have been evicted"
