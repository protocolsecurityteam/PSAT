"""Perimeter W2 producer: ``_structural_ownership``'s verified
edges become witness rows + gate promotion — never a stamped ``protocol_id``.
"""

from __future__ import annotations

import pytest

from db.models import (
    WITNESS_RULE_W1_CODE,
    WITNESS_RULE_W2_STRUCTURAL,
    Contract,
    ContractMembershipWitness,
    ContractProbeAttempt,
)
from services.clients.rpc import EthCallResult
from services.discovery import probes
from services.discovery.perimeter import _produce_structural_witnesses, produce_structural_witness
from tests.conftest import ADDR, requires_postgres
from tests.support.membership_builders import _protocol

pytestmark = [requires_postgres]

_ZERO_WORD = "0x" + "0" * 64


@pytest.fixture()
def erpc_env(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "http://erpc.test")


def _stub_probe_wire(monkeypatch, *, code: str = "0x6001") -> dict:
    seen: dict = {"probed": []}

    def fake_rpc_request(rpc_url, method, params, *args, **kwargs):
        if method == "eth_blockNumber":
            return hex(150)
        if method == "eth_getCode":
            seen["probed"].append(params[0])
            return code
        raise AssertionError(f"unexpected rpc method {method}")

    monkeypatch.setattr(probes, "rpc_request", fake_rpc_request)
    monkeypatch.setattr(
        probes,
        "eth_call_batch",
        lambda rpc_url, calls, block_tag="latest", **kw: [
            EthCallResult(False, "0x", None, "execution reverted") for _ in calls
        ],
    )
    monkeypatch.setattr(probes, "rpc_batch_request", lambda rpc_url, calls, *a, **kw: [_ZERO_WORD for _ in calls])
    monkeypatch.setattr(probes.etherscan, "get", lambda module, action, chain_id, **params: {"result": []})
    return seen


def _contract(session, address: str, **kwargs) -> Contract:
    row = Contract(address=address.lower(), chain=kwargs.pop("chain", "ethereum"), **kwargs)
    session.add(row)
    session.flush()
    return row


def _witnesses(session, contract_id: int) -> list[ContractMembershipWitness]:
    return (
        session.query(ContractMembershipWitness)
        .filter_by(contract_id=contract_id, rule=WITNESS_RULE_W2_STRUCTURAL)
        .all()
    )


def test_w2_protocol_mismatch_and_chain_mismatch_admit_nothing(db_session):
    p1 = _protocol(db_session)
    p2 = _protocol(db_session)
    candidate = _contract(db_session, ADDR(0x410))
    member_other_protocol = _contract(db_session, ADDR(0x411), protocol_id=p2.id, implementation=candidate.address)
    assert (
        produce_structural_witness(
            db_session,
            candidate=candidate,
            parent=member_other_protocol,
            protocol_id=p1.id,
            relationship="implementation",
        )
        is None
    )
    member_other_chain = _contract(
        db_session, ADDR(0x412), chain="base", protocol_id=p1.id, implementation=candidate.address
    )
    assert (
        produce_structural_witness(
            db_session,
            candidate=candidate,
            parent=member_other_chain,
            protocol_id=p1.id,
            relationship="implementation",
        )
        is None
    )
    assert _witnesses(db_session, candidate.id) == []


def test_w2_proxy_direction_requires_candidate_back_link(db_session):
    protocol = _protocol(db_session)
    member_impl = _contract(db_session, ADDR(0x420), protocol_id=protocol.id)
    proxy = _contract(db_session, ADDR(0x421), is_proxy=True, implementation=member_impl.address)
    assert (
        produce_structural_witness(
            db_session, candidate=proxy, parent=member_impl, protocol_id=protocol.id, relationship="proxy"
        )
        == "proxy"
    )
    rows = _witnesses(db_session, proxy.id)
    assert len(rows) == 1 and rows[0].evidence["edge_kind"] == "proxy"

    stray = _contract(db_session, ADDR(0x422), is_proxy=True, implementation=ADDR(0x999))
    assert (
        produce_structural_witness(
            db_session, candidate=stray, parent=member_impl, protocol_id=protocol.id, relationship="proxy"
        )
        is None
    )


def test_witness_pass_probes_unprobed_candidates_near_line(db_session, monkeypatch, erpc_env):
    # A dep with an existing row (and an existing job — it never re-enters the
    # fetch path) still completes W2+W1 here: the pass runs the nomination probe
    # for witnessed candidates lacking an attempt, and promotes.
    protocol = _protocol(db_session)
    parent = _contract(db_session, ADDR(0x440), protocol_id=protocol.id, implementation=ADDR(0x441))
    dep = _contract(db_session, ADDR(0x441))
    db_session.flush()
    seen = _stub_probe_wire(monkeypatch)

    _produce_structural_witnesses(db_session, parent, {dep.address: "implementation"})

    assert seen["probed"] == [dep.address]
    attempt = db_session.get(ContractProbeAttempt, (dep.id, 1))
    assert attempt is not None and attempt.results["status"] == "probed"
    w1 = db_session.query(ContractMembershipWitness).filter_by(contract_id=dep.id, rule=WITNESS_RULE_W1_CODE).one()
    assert w1.evidence == {"chain_id": 1, "code_probe_block": 150, "code_present": True}
    assert dep.protocol_id == protocol.id
    assert "structural_witness" in (dep.discovery_sources or [])
