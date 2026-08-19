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

import uuid

from services.aggregations import contract_audit_timeline as cat
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr


def test_reads_keccak_from_pg_bytecode_cache(monkeypatch):
    """A bytecode_cache hit supplies code_keccak directly — no live RPC."""
    addr = "0x" + "ab" * 20
    monkeypatch.setattr("utils.rpc._pg_bytecode_get", lambda _c, _a: ("0x6080", "0x" + "11" * 32))

    def _no_live(_a, _chain):
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
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda _a, _chain: None)

    cat._bytecode_keccak_now_batch({"0x" + "ee" * 20})
    assert seen == [1]


def test_falls_back_to_live_on_pg_miss(monkeypatch):
    """A bytecode_cache miss falls back to the live fetch path."""
    addr = "0x" + "cd" * 20
    monkeypatch.setattr("utils.rpc._pg_bytecode_get", lambda _c, _a: None)
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda _a, _chain: "0x" + "22" * 32)

    out = cat._bytecode_keccak_now_batch({addr})
    assert out == {addr.lower(): "0x" + "22" * 32}


def test_skips_empty_addresses(monkeypatch):
    """Falsy entries (``""`` / ``None``) are skipped, never queried."""

    def _no_pg(_c, _a):
        raise AssertionError("empty address must not be queried")

    monkeypatch.setattr("utils.rpc._pg_bytecode_get", _no_pg)
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda _a, _chain: None)
    bad_addrs: set = {"", None}  # deliberately malformed input the batcher must skip
    out = cat._bytecode_keccak_now_batch(bad_addrs)
    assert out == {}


def test_no_process_global_keccak_cache():
    """The third keccak cache is eliminated, not merely bounded — no
    process-global dict can accumulate in the web process."""
    assert not hasattr(cat, "_BYTECODE_KECCAK_CACHE")
    assert not hasattr(cat, "_BYTECODE_KECCAK_TTL_SECONDS")


@requires_postgres
def test_current_status_needs_a_determined_lower_bound_for_open_ended(db_session):
    """``covered_to_block is None`` alone is not "this row covers the
    currently-open impl window" — it is also what a row whose upper bound was never
    determined looks like, and this module's own ImplWindow docstring calls that
    inference invalid. ``AuditContractCoverage`` carries no ``successor`` column, so
    the lower bound is the only evidence available here.

    Armed population 15 (``match_confidence='high'`` with BOTH bounds NULL);
    realised badge changes today 0 — the 2 high-confidence rows that do land on a
    current impl are ``covered_from_block`` set / ``covered_to_block`` NULL and keep
    the badge (the positive control below).
    """
    from types import SimpleNamespace

    from services.aggregations.contract_audit_timeline import _current_status

    p = _add_protocol(db_session, f"e2e-l21-{uuid.uuid4().hex[:8]}")
    impl_addr = _addr("l21i")
    proxy_addr = _addr("l21p")
    impl_job = _add_job(db_session, address=impl_addr, protocol_id=p.id, name="Impl")
    proxy_job = _add_job(db_session, address=proxy_addr, protocol_id=p.id, name="Proxy")
    impl = _add_contract(db_session, address=impl_addr, job=impl_job, protocol_id=p.id, contract_name="Impl")
    proxy = _add_contract(
        db_session,
        address=proxy_addr,
        job=proxy_job,
        protocol_id=p.id,
        is_proxy=True,
        implementation=impl_addr,
        contract_name="Proxy",
    )

    # ``_current_status`` reads the coverage rows it is handed and only queries for
    # the impl Contract, so the rows are built in memory — the table's
    # (report, contract) unique key would otherwise force one AuditReport per shape
    # for no gain in what is being tested.
    def _cov(**kwargs):
        base = {
            "contract_id": impl.id,
            "match_type": "impl_era",
            "match_confidence": "high",
            "equivalence_status": "pending",
            "proof_kind": None,
            "covered_from_block": None,
            "covered_to_block": None,
        }
        base.update(kwargs)
        return SimpleNamespace(**base)

    # POSITIVE CONTROL: bounded start, no end — genuinely open-ended, keeps "audited".
    open_ended = _cov(covered_from_block=100)
    assert _current_status(db_session, proxy, [open_ended]) == "audited"

    # Neither bound determined: never windowed at all, so it cannot earn the badge
    # on the strength of a missing number.
    unbounded = _cov()
    assert _current_status(db_session, proxy, [unbounded]) == "unaudited_since_upgrade"

    # NEGATIVE CONTROL: a cryptographic proof still overrides everything, so the
    # narrowing cannot have removed the strongest evidence path.
    proven = _cov(match_confidence="low", equivalence_status="proven", proof_kind="bytecode_match")
    assert _current_status(db_session, proxy, [unbounded, proven]) == "audited"
