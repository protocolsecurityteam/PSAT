"""Collaborators are imported lazily inside the helper, so patches target their source modules."""

from __future__ import annotations

import uuid

from services.aggregations import contract_audit_timeline as cat
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr


def test_reads_keccak_from_pg_bytecode_cache(monkeypatch):
    addr = "0x" + "ab" * 20
    monkeypatch.setattr("services.clients.rpc._pg_bytecode_get", lambda _c, _a: ("0x6080", "0x" + "11" * 32))

    def _no_live(_a, _chain):
        raise AssertionError("must not fetch live when bytecode_cache has the row")

    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", _no_live)

    out = cat._bytecode_keccak_now_batch({addr})
    assert out == {addr.lower(): "0x" + "11" * 32}


def test_reads_pg_on_mainnet_chain_id(monkeypatch):
    seen: list[int] = []

    def _pg(chain_id, _addr):
        seen.append(chain_id)
        return ("0x60", "0x" + "33" * 32)

    monkeypatch.setattr("services.clients.rpc._pg_bytecode_get", _pg)
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda _a, _chain: None)

    cat._bytecode_keccak_now_batch({"0x" + "ee" * 20})
    assert seen == [1]


def test_falls_back_to_live_on_pg_miss(monkeypatch):
    addr = "0x" + "cd" * 20
    monkeypatch.setattr("services.clients.rpc._pg_bytecode_get", lambda _c, _a: None)
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda _a, _chain: "0x" + "22" * 32)

    out = cat._bytecode_keccak_now_batch({addr})
    assert out == {addr.lower(): "0x" + "22" * 32}


def test_skips_empty_addresses(monkeypatch):

    def _no_pg(_c, _a):
        raise AssertionError("empty address must not be queried")

    monkeypatch.setattr("services.clients.rpc._pg_bytecode_get", _no_pg)
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda _a, _chain: None)
    bad_addrs: set = {"", None}  # deliberately malformed input the batcher must skip
    out = cat._bytecode_keccak_now_batch(bad_addrs)
    assert out == {}


@requires_postgres
def test_current_status_needs_a_determined_lower_bound_for_open_ended(db_session):
    """A NULL ``covered_to_block`` also describes a row whose upper bound was never determined; the lower bound is
    the only evidence.
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

    # Rows are built in memory: ``_current_status`` only queries for the impl Contract, and the
    # table's (report, contract) unique key would force one AuditReport per shape.
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

    open_ended = _cov(covered_from_block=100)
    assert _current_status(db_session, proxy, [open_ended]) == "audited"

    unbounded = _cov()
    assert _current_status(db_session, proxy, [unbounded]) == "unaudited_since_upgrade"

    # A cryptographic proof still overrides everything.
    proven = _cov(match_confidence="low", equivalence_status="proven", proof_kind="bytecode_match")
    assert _current_status(db_session, proxy, [unbounded, proven]) == "audited"
