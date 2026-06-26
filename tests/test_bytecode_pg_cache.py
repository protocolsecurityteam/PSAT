"""Regression tests for the Postgres-backed eth_getCode cache layer in
``utils.rpc``.

The in-memory ``_GETCODE_CACHE`` is per-process; this PG layer
(``bytecode_cache`` table) lets workers share bytecode hits across the
fleet so a cold cascade on worker A populates the cache for worker B's
sibling cascade later.

What we pin:
1. PSAT_BYTECODE_PG_CACHE=0 → no DB calls attempted (CLI without DB
   keeps working).
2. DB unavailable → graceful degradation (no crash, no exception).
3. PG hit → returned without hitting the wire AND promoted into the
   in-memory cache (second same-process call is free).
4. PG miss → wire is hit AND response written back to PG.
5. Batch path: mixed in-mem hits / PG hits / wire misses correctly
   compose; PG bulk read replaces N round-trips with one.
6. chain_id is discovered once per RPC URL via ``eth_chainId`` and
   cached; explicit ``chain_id=`` kwarg skips the discovery RPC.
7. Address case is normalized so PG keys are deterministic.
8. Wire errors are NOT persisted to PG (matches in-memory behaviour).
9. Parity: PG-on vs PG-off return identical (bytecode, keccak) for the
   same address — load-bearing for PSAT_RPC_FANOUT parity tests.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils import rpc


@pytest.fixture(autouse=True)
def _isolated_caches():
    rpc.clear_getcode_cache()
    yield
    rpc.clear_getcode_cache()


# ---------------------------------------------------------------------------
# Disabled flag and graceful fallback
# ---------------------------------------------------------------------------


def test_pg_disabled_skips_db(monkeypatch):
    """PSAT_BYTECODE_PG_CACHE=0 → _pg_bytecode_get must not import db.models."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", False)

    def _no_db(*_a, **_kw):
        raise AssertionError("disabled flag must short-circuit before DB import")

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_no_db)}):
        assert rpc._pg_bytecode_get(1, "0xabc") is None
        rpc._pg_bytecode_put(1, "0xabc", "0x60", "0x" + "0" * 64)
        assert rpc._pg_bytecode_get_many(1, ["0xabc"]) == {}
        rpc._pg_bytecode_put_many(1, [("0xabc", "0x60", "0x" + "0" * 64)])


def test_pg_get_returns_none_on_db_unavailable(monkeypatch):
    """A DB connection failure must degrade gracefully — return None,
    don't crash. CLI-without-DB usage relies on this."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)

    def _raise(*_a, **_kw):
        raise RuntimeError("DB connection refused")

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_raise)}):
        assert rpc._pg_bytecode_get(1, "0xabc") is None
        # And puts must swallow too.
        rpc._pg_bytecode_put(1, "0xabc", "0x60", "0x" + "0" * 64)


# ---------------------------------------------------------------------------
# Single-address path: get_code_with_keccak
# ---------------------------------------------------------------------------


def test_pg_hit_promotes_to_in_memory(monkeypatch):
    """A PG hit must populate the in-memory cache too — second call in
    the same process never reaches PG."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)

    pg_calls = {"n": 0}

    def _pg_get(_c, _a):
        pg_calls["n"] += 1
        return ("0xdeadbeef", "0x" + "ab" * 32)

    monkeypatch.setattr(rpc, "_pg_bytecode_get", _pg_get)
    monkeypatch.setattr(rpc, "_pg_bytecode_put", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        rpc, "rpc_request", lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("must not hit wire on PG hit"))
    )

    addr = "0x" + "11" * 20
    code, kek = rpc.get_code_with_keccak("https://rpc", addr)
    assert code == "0xdeadbeef"
    assert kek == "0x" + "ab" * 32
    assert pg_calls["n"] == 1

    # Second call: in-memory hit, PG must not be queried again.
    code2, kek2 = rpc.get_code_with_keccak("https://rpc", addr)
    assert (code2, kek2) == (code, kek)
    assert pg_calls["n"] == 1


def test_pg_miss_writes_back(monkeypatch):
    """PG miss → wire is hit → result is upserted to PG."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)
    monkeypatch.setattr(rpc, "_pg_bytecode_get", lambda *_a, **_kw: None)

    writes: list[tuple] = []
    monkeypatch.setattr(rpc, "_pg_bytecode_put", lambda c, a, b, k: writes.append((c, a, b, k)))

    def _wire(_url, method, _params, retries=1):
        assert method == "eth_getCode"
        return "0x60806040"

    monkeypatch.setattr(rpc, "rpc_request", _wire)

    addr = "0x" + "22" * 20
    rpc.get_code_with_keccak("https://rpc", addr)
    assert len(writes) == 1
    chain_id, written_addr, bytecode, _kek = writes[0]
    assert chain_id == 1
    assert written_addr == addr.lower()
    assert bytecode == "0x60806040"


def test_rpc_error_not_persisted_to_pg(monkeypatch):
    """Wire failures must NOT be persisted to PG — matches the in-memory
    behaviour at utils/rpc.py:105-107. Cementing a transient RPC error
    would poison the cross-process cache for every other worker."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)
    monkeypatch.setattr(rpc, "_pg_bytecode_get", lambda *_a, **_kw: None)

    def _no_write(*_a, **_kw):
        raise AssertionError("error path must not persist")

    monkeypatch.setattr(rpc, "_pg_bytecode_put", _no_write)
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("RPC down")))

    with pytest.raises(RuntimeError):
        rpc.get_code_with_keccak("https://rpc", "0x" + "33" * 20)


def test_no_chain_id_skips_pg(monkeypatch):
    """If we can't resolve chain_id (eth_chainId fails on a CLI call),
    skip the PG layer cleanly and fall straight through to the wire."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: None)

    def _no_pg(*_a, **_kw):
        raise AssertionError("must skip PG when chain_id unavailable")

    monkeypatch.setattr(rpc, "_pg_bytecode_get", _no_pg)
    monkeypatch.setattr(rpc, "_pg_bytecode_put", _no_pg)
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x6080")

    code, _kek = rpc.get_code_with_keccak("https://rpc", "0x" + "44" * 20)
    assert code == "0x6080"


# ---------------------------------------------------------------------------
# chain_id discovery
# ---------------------------------------------------------------------------


def test_chain_id_resolved_via_eth_chainid_once(monkeypatch):
    """First call discovers chain_id via eth_chainId; second call against
    the same URL reuses the cached value."""
    rpc._chain_id_cache.clear()
    calls = {"chain_id": 0, "code": 0}

    def _wire(_url, method, _params, retries=1):
        if method == "eth_chainId":
            calls["chain_id"] += 1
            return "0x1"
        if method == "eth_getCode":
            calls["code"] += 1
            return "0x60"
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(rpc, "rpc_request", _wire)
    monkeypatch.setattr(rpc, "_pg_bytecode_get", lambda *_a, **_kw: None)
    monkeypatch.setattr(rpc, "_pg_bytecode_put", lambda *_a, **_kw: None)

    rpc.get_code_with_keccak("https://rpc", "0x" + "55" * 20)
    rpc.clear_getcode_cache()  # force re-fetch but keep chain_id cache
    rpc._GETCODE_CACHE.clear()  # alt: clear without touching chain id (clear_getcode_cache wipes both)
    # clear_getcode_cache() above already cleared chain ids; re-prime explicitly.
    rpc._chain_id_cache["https://rpc"] = 1
    rpc.get_code_with_keccak("https://rpc", "0x" + "66" * 20)

    # First call: 1 chain id + 1 get_code. Second call (after re-priming chain id): 1 get_code only.
    assert calls["chain_id"] == 1
    assert calls["code"] == 2


def test_chain_id_kwarg_skips_discovery(monkeypatch):
    """Explicit chain_id= must short-circuit the eth_chainId discovery RPC."""
    rpc._chain_id_cache.clear()

    def _no_chainid(_url, method, *_a, **_kw):
        if method == "eth_chainId":
            raise AssertionError("must not call eth_chainId when chain_id is supplied")
        return "0x60"

    monkeypatch.setattr(rpc, "rpc_request", _no_chainid)
    monkeypatch.setattr(rpc, "_pg_bytecode_get", lambda *_a, **_kw: None)
    monkeypatch.setattr(rpc, "_pg_bytecode_put", lambda *_a, **_kw: None)

    rpc.get_code_with_keccak("https://rpc", "0x" + "77" * 20, chain_id=137)
    assert rpc._chain_id_cache["https://rpc"] == 137


def test_chain_id_discovery_failure_returns_none(monkeypatch):
    """eth_chainId failures must return None so PG layer is skipped, not crash."""
    rpc._chain_id_cache.clear()
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("boom")))
    assert rpc._resolve_chain_id("https://rpc-down") is None


# ---------------------------------------------------------------------------
# Batch path
# ---------------------------------------------------------------------------


def test_batch_pg_hits_skip_wire(monkeypatch):
    """Batch path: all PG hits → wire batch is never called."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)

    addrs = [("0x" + f"{i:040x}").lower() for i in range(3)]

    def _pg_many(_c, requested):
        return {a: ("0xff", "0x" + "00" * 32) for a in [r.lower() for r in requested]}

    monkeypatch.setattr(rpc, "_pg_bytecode_get_many", _pg_many)

    def _no_batch(*_a, **_kw):
        raise AssertionError("must not hit wire when PG covers everything")

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _no_batch)

    out = rpc.get_code_batch("https://rpc", addrs)
    assert out == {a: "0xff" for a in addrs}


def test_batch_mixed_pg_hits_and_misses(monkeypatch):
    """PG covers some addresses; wire batch is called only for the misses,
    and freshly-fetched rows are written back."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)

    cached_addr = ("0x" + "aa" * 20).lower()
    miss_addrs = [("0x" + f"{i:040x}").lower() for i in (1, 2)]
    all_addrs = [cached_addr] + miss_addrs

    monkeypatch.setattr(rpc, "_pg_bytecode_get_many", lambda _c, _addrs: {cached_addr: ("0xcafe", "0x" + "11" * 32)})

    wire_calls: list[list] = []

    def _wire_batch(_url, calls):
        wire_calls.append([c[1][0] for c in calls])
        return [("0xbeef", False), ("0xfeed", False)]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _wire_batch)

    writes: list[list] = []
    monkeypatch.setattr(rpc, "_pg_bytecode_put_many", lambda _c, rows: writes.append(rows))

    out = rpc.get_code_batch("https://rpc", all_addrs)
    assert out[cached_addr] == "0xcafe"
    assert out[miss_addrs[0]] == "0xbeef"
    assert out[miss_addrs[1]] == "0xfeed"
    # Wire batch was issued only for the two misses.
    assert len(wire_calls) == 1
    assert sorted(a.lower() for a in wire_calls[0]) == sorted(miss_addrs)
    # Both freshly-fetched rows were upserted to PG.
    assert len(writes) == 1
    assert {row[0] for row in writes[0]} == set(miss_addrs)


def test_batch_no_db_falls_through_to_wire(monkeypatch):
    """DB unavailable → batch path must behave exactly like before this change."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: None)

    def _wire_batch(_url, calls):
        return [("0x60", False) for _ in calls]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _wire_batch)
    addrs = [("0x" + f"{i:040x}").lower() for i in range(3)]
    out = rpc.get_code_batch("https://rpc", addrs)
    assert len(out) == 3


# ---------------------------------------------------------------------------
# Parity (PSAT_RPC_FANOUT-style: PG off vs on, same outputs)
# ---------------------------------------------------------------------------


def test_parity_pg_off_vs_on_byte_identical(monkeypatch):
    """Same wire response with PG enabled vs disabled must produce
    byte-identical (bytecode, keccak) tuples for the same address.
    Mirrors the parity convention from memory/feedback_parity_tests.md."""
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)
    monkeypatch.setattr(rpc, "_pg_bytecode_get", lambda *_a, **_kw: None)
    monkeypatch.setattr(rpc, "_pg_bytecode_put", lambda *_a, **_kw: None)
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x60806040526001600055")

    addr = "0x" + "99" * 20
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    rpc.clear_getcode_cache()
    on = rpc.get_code_with_keccak("https://rpc", addr)

    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", False)
    rpc.clear_getcode_cache()
    off = rpc.get_code_with_keccak("https://rpc", addr)

    assert on == off


def test_pg_address_case_normalized(monkeypatch):
    """Upper- and lower-case address forms must hit the same PG row."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)

    seen: list[str] = []

    def _pg_get(_c, addr):
        seen.append(addr)
        return None

    monkeypatch.setattr(rpc, "_pg_bytecode_get", _pg_get)
    monkeypatch.setattr(rpc, "_pg_bytecode_put", lambda *_a, **_kw: None)
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x60")

    rpc.get_code_with_keccak("https://rpc", "0x" + "AB" * 20)
    rpc.clear_getcode_cache()
    rpc.get_code_with_keccak("https://rpc", "0x" + "ab" * 20)
    assert seen[0] == seen[1] == ("0x" + "ab" * 20)


# ---------------------------------------------------------------------------
# In-memory getcode key re-keyed on (chain_id, address) — P2.4
# ---------------------------------------------------------------------------


def test_getcode_inmem_key_dedups_url_aliases(monkeypatch):
    """Two RPC URLs that resolve to the same chain id share one in-mem slot:
    the second URL's read is served from cache without a second wire call."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)
    monkeypatch.setattr(rpc, "_pg_bytecode_get", lambda *_a, **_kw: None)
    monkeypatch.setattr(rpc, "_pg_bytecode_put", lambda *_a, **_kw: None)

    wire = {"n": 0}

    def _wire(_url, _method, _params, retries=1):
        wire["n"] += 1
        return "0x6080"

    monkeypatch.setattr(rpc, "rpc_request", _wire)

    addr = "0x" + "ab" * 20
    rpc.get_code_with_keccak("https://erpc-a/main/evm/1", addr)
    rpc.get_code_with_keccak("https://erpc-b/main/evm/1", addr)
    assert wire["n"] == 1, "same chain id → distinct URLs must share one cache slot"
    assert list(rpc._GETCODE_CACHE.keys()) == [(1, addr)]


def test_getcode_inmem_key_falls_back_to_url_when_no_chain_id(monkeypatch):
    """With the chain id unresolvable (PG off), the in-mem key falls back to
    (rpc_url, addr): distinct URLs keep distinct slots, exactly as before."""
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", False)

    wire = {"n": 0}

    def _wire(_url, _method, _params, retries=1):
        wire["n"] += 1
        return "0x6080"

    monkeypatch.setattr(rpc, "rpc_request", _wire)

    addr = "0x" + "cd" * 20
    rpc.get_code_with_keccak("https://node-a", addr)
    rpc.get_code_with_keccak("https://node-b", addr)
    assert wire["n"] == 2
    assert set(rpc._GETCODE_CACHE.keys()) == {("https://node-a", addr), ("https://node-b", addr)}


# ---------------------------------------------------------------------------
# _chain_id_cache is size-capped — P2.3
# ---------------------------------------------------------------------------


def test_chain_id_cache_bounded(monkeypatch):
    """A caller minting per-request URLs can't grow _chain_id_cache without
    bound — it's FIFO-capped at _CHAIN_ID_CACHE_MAX."""
    rpc._chain_id_cache.clear()
    monkeypatch.setattr(rpc, "_CHAIN_ID_CACHE_MAX", 4)
    for i in range(20):
        rpc._remember_chain_id(f"https://rpc-{i}", 1)
    assert len(rpc._chain_id_cache) <= rpc._CHAIN_ID_CACHE_MAX


def test_remember_chain_id_evicts_oldest(monkeypatch):
    """At the cap the oldest-inserted URL is dropped; the newest survives."""
    rpc._chain_id_cache.clear()
    monkeypatch.setattr(rpc, "_CHAIN_ID_CACHE_MAX", 3)
    for i in range(3):
        rpc._remember_chain_id(f"https://rpc-{i}", i)
    rpc._remember_chain_id("https://rpc-new", 99)
    assert "https://rpc-0" not in rpc._chain_id_cache
    assert rpc._chain_id_cache["https://rpc-new"] == 99
    assert len(rpc._chain_id_cache) == 3
