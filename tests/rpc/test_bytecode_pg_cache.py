"""Regression tests for the Postgres-backed eth_getCode cache layer in ``services.clients.rpc``.

The in-memory ``_GETCODE_CACHE`` is per-process; the PG layer (``bytecode_cache`` table) lets
workers share bytecode hits across the fleet. Pinned: ``PSAT_BYTECODE_PG_CACHE=0`` and DB
outages degrade gracefully (CLI without DB keeps working); PG hits are promoted in-memory;
wire errors are never persisted; chain_id is discovered once per URL; addresses are
case-normalized for deterministic keys; PG-on vs PG-off parity is load-bearing for
PSAT_RPC_FANOUT parity tests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from services.clients import rpc


@pytest.fixture(autouse=True)
def _isolated_caches():
    rpc.clear_getcode_cache()
    yield
    rpc.clear_getcode_cache()


# Disabled flag and graceful fallback


def _raise_db_down(*_a, **_kw):
    raise RuntimeError("DB connection refused")


def _fail_if_db_touched(*_a, **_kw):
    raise AssertionError("disabled flag must short-circuit before DB import")


@pytest.mark.parametrize(
    ("enabled", "session_local"),
    [
        pytest.param(False, _fail_if_db_touched, id="disabled_skips_db"),
        # A DB connection failure must return None, not crash (CLI-without-DB relies on this).
        pytest.param(True, _raise_db_down, id="db_unavailable"),
    ],
)
def test_pg_layer_degrades_without_db(monkeypatch, enabled, session_local):
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", enabled)

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=session_local)}):
        assert rpc._pg_bytecode_get(1, "0xabc") is None
        rpc._pg_bytecode_put(1, "0xabc", "0x60", "0x" + "0" * 64)
        assert rpc._pg_bytecode_get_many(1, ["0xabc"]) == {}
        rpc._pg_bytecode_put_many(1, [("0xabc", "0x60", "0x" + "0" * 64)])


# Single-address path: get_code_with_keccak


def test_pg_hit_promotes_to_in_memory(monkeypatch):
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

    code2, kek2 = rpc.get_code_with_keccak("https://rpc", addr)
    assert (code2, kek2) == (code, kek)
    assert pg_calls["n"] == 1


def test_pg_miss_writes_back(monkeypatch):
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)
    monkeypatch.setattr(rpc, "_pg_bytecode_get", lambda *_a, **_kw: None)

    writes: list[tuple] = []
    monkeypatch.setattr(rpc, "_pg_bytecode_put", lambda c, a, b, k: writes.append((c, a, b, k)))

    def _wire(_url, method, _params, retries=1, *, chain_id=None):
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
    """Wire failures must NOT be persisted (matches in-memory behaviour at services/clients/rpc.py:105-107);
    cementing a transient RPC error would poison the cross-process cache for every worker."""
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
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: None)

    def _no_pg(*_a, **_kw):
        raise AssertionError("must skip PG when chain_id unavailable")

    monkeypatch.setattr(rpc, "_pg_bytecode_get", _no_pg)
    monkeypatch.setattr(rpc, "_pg_bytecode_put", _no_pg)
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: "0x6080")

    code, _kek = rpc.get_code_with_keccak("https://rpc", "0x" + "44" * 20)
    assert code == "0x6080"


# chain_id discovery


def test_chain_id_kwarg_skips_discovery(monkeypatch):
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
    rpc._chain_id_cache.clear()
    monkeypatch.setattr(rpc, "rpc_request", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("boom")))
    assert rpc._resolve_chain_id("https://rpc-down") is None


# Batch path


def test_batch_pg_hits_skip_wire(monkeypatch):
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
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: 1)

    cached_addr = ("0x" + "aa" * 20).lower()
    miss_addrs = [("0x" + f"{i:040x}").lower() for i in (1, 2)]
    all_addrs = [cached_addr] + miss_addrs

    monkeypatch.setattr(rpc, "_pg_bytecode_get_many", lambda _c, _addrs: {cached_addr: ("0xcafe", "0x" + "11" * 32)})

    wire_calls: list[list] = []

    def _wire_batch(_url, calls, chain_id=None):
        wire_calls.append([c[1][0] for c in calls])
        return [("0xbeef", False), ("0xfeed", False)]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _wire_batch)

    writes: list[list] = []
    monkeypatch.setattr(rpc, "_pg_bytecode_put_many", lambda _c, rows: writes.append(rows))

    out = rpc.get_code_batch("https://rpc", all_addrs)
    assert out[cached_addr] == "0xcafe"
    assert out[miss_addrs[0]] == "0xbeef"
    assert out[miss_addrs[1]] == "0xfeed"
    assert len(wire_calls) == 1
    assert sorted(a.lower() for a in wire_calls[0]) == sorted(miss_addrs)
    assert len(writes) == 1
    assert {row[0] for row in writes[0]} == set(miss_addrs)


def test_batch_no_db_falls_through_to_wire(monkeypatch):
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", True)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: None)

    def _wire_batch(_url, calls, chain_id=None):
        return [("0x60", False) for _ in calls]

    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _wire_batch)
    addrs = [("0x" + f"{i:040x}").lower() for i in range(3)]
    out = rpc.get_code_batch("https://rpc", addrs)
    assert len(out) == 3


# Parity (PSAT_RPC_FANOUT-style: PG off vs on, same outputs)


def test_parity_pg_off_vs_on_byte_identical(monkeypatch):
    """Same wire response with PG on vs off must give byte-identical (bytecode, keccak) tuples."""
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


# In-memory getcode key re-keyed on (chain_id, address)


@pytest.mark.parametrize(
    ("pg_enabled", "chain_id", "urls", "addr", "expected_wire_calls", "expected_keys"),
    [
        pytest.param(
            True,
            1,
            ["https://erpc-a/main/evm/1", "https://erpc-b/main/evm/1"],
            "0x" + "ab" * 20,
            1,
            {(1, "0x" + "ab" * 20)},
            id="dedups_url_aliases_by_chain_id",
        ),
        pytest.param(
            False,
            None,
            ["https://node-a", "https://node-b"],
            "0x" + "cd" * 20,
            2,
            {("https://node-a", "0x" + "cd" * 20), ("https://node-b", "0x" + "cd" * 20)},
            id="falls_back_to_url_when_no_chain_id",
        ),
    ],
)
def test_getcode_inmem_key(monkeypatch, pg_enabled, chain_id, urls, addr, expected_wire_calls, expected_keys):
    monkeypatch.setattr(rpc, "_PG_BYTECODE_CACHE_ENABLED", pg_enabled)
    monkeypatch.setattr(rpc, "_resolve_chain_id", lambda *_a, **_kw: chain_id)
    monkeypatch.setattr(rpc, "_pg_bytecode_get", lambda *_a, **_kw: None)
    monkeypatch.setattr(rpc, "_pg_bytecode_put", lambda *_a, **_kw: None)

    wire = {"n": 0}

    def _wire(_url, _method, _params, retries=1, *, chain_id=None):
        wire["n"] += 1
        return "0x6080"

    monkeypatch.setattr(rpc, "rpc_request", _wire)

    for url in urls:
        rpc.get_code_with_keccak(url, addr)
    assert wire["n"] == expected_wire_calls
    assert set(rpc._GETCODE_CACHE.keys()) == expected_keys


# _chain_id_cache is size-capped


@pytest.mark.parametrize(
    ("cap", "inserted"),
    [
        pytest.param(4, 20, id="bounded_under_churn"),
        pytest.param(3, 3, id="evicts_oldest_at_cap"),
    ],
)
def test_chain_id_cache_is_bounded_and_evicts_oldest(monkeypatch, cap, inserted):
    rpc._chain_id_cache.clear()
    monkeypatch.setattr(rpc, "_CHAIN_ID_CACHE_MAX", cap)
    for i in range(inserted):
        rpc._remember_chain_id(f"https://rpc-{i}", i)
    rpc._remember_chain_id("https://rpc-new", 99)
    assert "https://rpc-0" not in rpc._chain_id_cache
    assert rpc._chain_id_cache["https://rpc-new"] == 99
    assert len(rpc._chain_id_cache) == cap
