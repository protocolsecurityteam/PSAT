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
