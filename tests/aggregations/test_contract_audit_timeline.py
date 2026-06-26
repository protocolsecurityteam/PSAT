"""Regression tests for the audit-timeline live-keccak helper in
``services.aggregations.contract_audit_timeline``.

The live ``bytecode_keccak_now`` is read from the durable ``bytecode_cache``
layer (utils.rpc PG cache — the system of record for deployed bytecode); only
addresses absent from that layer are fetched live (which itself populates it).
There is no timeline-local process-global cache. What we pin:

1. A ``bytecode_cache`` hit supplies its stored ``code_keccak`` directly and
   never fires a live RPC.
2. A ``bytecode_cache`` miss falls back to the live ``_fetch_bytecode_keccak``.
3. Empty / falsy addresses are skipped.
4. The unbounded ``_BYTECODE_KECCAK_CACHE`` is eliminated (not merely bounded),
   so nothing can accumulate in the long-lived web process.

The two collaborators are imported lazily inside the helper, so the patches
target their source modules (``utils.rpc`` / ``services.audits.coverage``).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from services.aggregations import contract_audit_timeline as cat


def test_reads_keccak_from_pg_bytecode_cache(monkeypatch):
    """A bytecode_cache hit supplies code_keccak directly — no live RPC."""
    addr = "0x" + "ab" * 20
    monkeypatch.setattr("utils.rpc._pg_bytecode_get", lambda _c, _a: ("0x6080", "0x" + "11" * 32))

    def _no_live(_a):
        raise AssertionError("must not fetch live when bytecode_cache has the row")

    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", _no_live)

    out = cat._bytecode_keccak_now_batch({addr})
    assert out == {addr.lower(): "0x" + "11" * 32}


def test_reads_pg_on_mainnet_chain_id(monkeypatch):
    """Coverage anchors are ethereum-deployed: the PG read uses chain id 1."""
    seen: list[int] = []

    def _pg(chain_id, _addr):
        seen.append(chain_id)
        return ("0x60", "0x" + "33" * 32)

    monkeypatch.setattr("utils.rpc._pg_bytecode_get", _pg)
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda _a: None)

    cat._bytecode_keccak_now_batch({"0x" + "ee" * 20})
    assert seen == [1]


def test_falls_back_to_live_on_pg_miss(monkeypatch):
    """A bytecode_cache miss falls back to the live fetch path."""
    addr = "0x" + "cd" * 20
    monkeypatch.setattr("utils.rpc._pg_bytecode_get", lambda _c, _a: None)
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda _a: "0x" + "22" * 32)

    out = cat._bytecode_keccak_now_batch({addr})
    assert out == {addr.lower(): "0x" + "22" * 32}


def test_skips_empty_addresses(monkeypatch):
    """Falsy entries (``""`` / ``None``) are skipped, never queried."""

    def _no_pg(_c, _a):
        raise AssertionError("empty address must not be queried")

    monkeypatch.setattr("utils.rpc._pg_bytecode_get", _no_pg)
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda _a: None)
    bad_addrs: set = {"", None}  # deliberately malformed input the batcher must skip
    out = cat._bytecode_keccak_now_batch(bad_addrs)
    assert out == {}


def test_no_process_global_keccak_cache():
    """The third keccak cache is eliminated, not merely bounded — no
    process-global dict can accumulate in the web process."""
    assert not hasattr(cat, "_BYTECODE_KECCAK_CACHE")
    assert not hasattr(cat, "_BYTECODE_KECCAK_TTL_SECONDS")
