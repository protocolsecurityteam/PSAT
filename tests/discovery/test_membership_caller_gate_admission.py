"""A bare caller gate admits nobody (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §3.2
invariant 6, ``W3_D2_SOURCES``).

``ControllerValue.authority_provenance='caller_gate'`` records a proven fact —
this address is checked against ``msg.sender`` on some entry point — and that
is what monitoring and scoring read it for. It is NOT a governance derivation:
LayerZero's ``if (msg.sender != endpoint) revert`` on the delivery entry point
lowers to exactly the same leaf as ``msg.sender != _owner``, so admitting the
D2 controller off that row admits an integration counterparty (EndpointV2, and
through its owner slot the OneSig multisig behind it) as readily as an
authority.

Pinned here: the EndpointV2/OneSig shape earns ZERO witnesses on both chains
and demotes on re-earn, the caller-gate rows survive untouched, and the
governance derivations (probed ``owner()``/``authority()`` reads, resolved
proxy-admin slots, authority-derived principals) keep admitting.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from db.models import (
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
    ControllerValue,
    Protocol,
)
from services.discovery import membership_gate as gate
from tests.conftest import requires_postgres

pytestmark = [requires_postgres]

#: The real (address, chain) rows the dev DB carries for the shape.
ENDPOINT_V2 = "0x1a44076050125825900e736c501f859c50fe728c"
ONESIG_ETHEREUM = "0xbe010a7e3686fdf65e93344ab664d065a0b02478"
ONESIG_BASE = "0xa0392d116d71ed3b75086194aba6de3cd1e39b7e"

_CHAIN_IDS = {"ethereum": 1, "base": 8453}


def _protocol(session) -> Protocol:
    row = Protocol(name=f"callergate-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _addr(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _contract(session, address: str, *, chain: str = "ethereum", **fields) -> Contract:
    row = Contract(address=address.lower(), chain=chain, **fields)
    session.add(row)
    session.flush()
    session.add(
        ContractCreationWitness(
            chain_id=_CHAIN_IDS[chain],
            address=address.lower(),
            code_probe_block=50,
            code_absent_at_probe=False,
        )
    )
    session.flush()
    return row


def _member(session, protocol: Protocol, address: str, *, chain: str = "ethereum", **fields) -> Contract:
    row = _contract(session, address, chain=chain, protocol_id=protocol.id, nominated_protocol_id=protocol.id, **fields)
    chain_id = _CHAIN_IDS[chain]
    gate.write_witness(
        session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=chain_id, code_probe_block=50),
    )
    gate.write_witness(
        session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w6_llama_seed",
        evidence=gate.w6_evidence(adapter_slug="etherfi", chain_id=chain_id, code_probe_block=50),
    )
    return row


def _caller_gate(session, *, on: Contract, controller_id: str, value: str) -> ControllerValue:
    row = ControllerValue(
        contract_id=on.id,
        controller_id=controller_id,
        value=value.lower(),
        resolved_type="contract",
        authority_provenance="caller_gate",
    )
    session.add(row)
    session.flush()
    return row


def _probe_read(session, contract: Contract, *, name: str, value: str, chain: str = "ethereum") -> None:
    session.add(
        ContractProbeAttempt(
            contract_id=contract.id,
            chain_id=_CHAIN_IDS[chain],
            block_number=60,
            results={
                "status": "probed",
                "code_present": True,
                "reads": {name: {"value": value.lower()}},
                "resolved_addresses": [value.lower()],
            },
        )
    )
    session.flush()


def _active_rules(session, contract: Contract) -> set[str]:
    return {
        row.rule
        for row in session.execute(
            select(ContractMembershipWitness).where(
                ContractMembershipWitness.contract_id == contract.id,
                ContractMembershipWitness.revoked_at.is_(None),
            )
        ).scalars()
    }


@pytest.mark.parametrize("chain", ["ethereum", "base"])
def test_endpoint_and_onesig_earn_zero_witnesses(db_session, chain):
    """The measured dev-DB shape, both chains: the protocol's OApp members
    carry ``external_contract:endpoint`` caller gates naming EndpointV2, and
    EndpointV2's own ``state_variable:_owner`` names OneSig. Neither may earn a
    witness — and OneSig must not ride in behind EndpointV2."""
    protocol = _protocol(db_session)
    onesig_address = ONESIG_ETHEREUM if chain == "ethereum" else ONESIG_BASE
    oapp = _member(db_session, protocol, _addr(0xE01), chain=chain)
    endpoint = _contract(db_session, ENDPOINT_V2, chain=chain, nominated_protocol_id=protocol.id)
    onesig = _contract(db_session, onesig_address, chain=chain, nominated_protocol_id=protocol.id)
    _caller_gate(db_session, on=oapp, controller_id="external_contract:endpoint", value=endpoint.address)
    _caller_gate(db_session, on=endpoint, controller_id="state_variable:_owner", value=onesig.address)

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(endpoint.id, onesig.id)))
    db_session.commit()

    assert endpoint.protocol_id is None
    assert onesig.protocol_id is None
    assert _active_rules(db_session, endpoint) == set()
    assert _active_rules(db_session, onesig) == set()
    assert endpoint.id not in result.promoted_contract_ids
    assert onesig.id not in result.promoted_contract_ids


def test_caller_gate_member_demotes_on_re_earn(db_session):
    """A standing member whose only witness was the D2 caller-gate edge loses
    it: the via-fact no longer verifies, so the row demotes to candidate with
    its nomination and witness history preserved (invariant 4)."""
    protocol = _protocol(db_session)
    oapp = _member(db_session, protocol, _addr(0xE10))
    endpoint = _contract(db_session, ENDPOINT_V2, protocol_id=protocol.id, nominated_protocol_id=protocol.id)
    _caller_gate(db_session, on=oapp, controller_id="external_contract:endpoint", value=endpoint.address)
    gate.write_witness(
        db_session,
        contract_id=endpoint.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=50),
    )
    stale = ContractMembershipWitness(
        contract_id=endpoint.id,
        protocol_id=protocol.id,
        rule="w3_control",
        via_address=oapp.address,
        evidence={
            "direction": "d2",
            "source": "controller_values",
            "via": oapp.address,
            "perimeter_entry_transitive": False,
        },
    )
    db_session.add(stale)
    db_session.flush()

    assert not gate._witness_fact_holds(
        db_session,
        contract=endpoint,
        protocol_id=protocol.id,
        rule=stale.rule,
        evidence=stale.evidence,
        via_address=stale.via_address,
    )
    revoked, demoted = gate._revocation_quiescence(db_session, {oapp.address})
    db_session.commit()

    assert endpoint.protocol_id is None
    assert endpoint.nominated_protocol_id == protocol.id
    assert endpoint.id in demoted
    assert stale.id in revoked


def test_caller_gate_controller_facts_stay_recorded(db_session):
    """The rows are real facts for monitoring and scoring — refusing to admit
    on them must not delete or rewrite them."""
    protocol = _protocol(db_session)
    oapp = _member(db_session, protocol, _addr(0xE20))
    endpoint = _contract(db_session, ENDPOINT_V2, nominated_protocol_id=protocol.id)
    row = _caller_gate(db_session, on=oapp, controller_id="external_contract:endpoint", value=endpoint.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(endpoint.id,)))
    db_session.commit()

    stored = db_session.get(ControllerValue, row.id)
    assert stored is not None
    assert stored.value == endpoint.address
    assert stored.authority_provenance == "caller_gate"


def test_probed_owner_read_still_admits_the_controller(db_session):
    """Positive control: a governance derivation — the §3.5 probe's
    ``owner()`` read on a member — keeps admitting its controller under D2."""
    protocol = _protocol(db_session)
    member = _member(db_session, protocol, _addr(0xE30))
    controller = _contract(db_session, _addr(0xE31), nominated_protocol_id=protocol.id)
    _probe_read(db_session, member, name="owner", value=controller.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(controller.id,)))
    db_session.commit()

    assert controller.protocol_id == protocol.id
    witness = db_session.execute(
        select(ContractMembershipWitness).where(
            ContractMembershipWitness.contract_id == controller.id,
            ContractMembershipWitness.rule == "w3_control",
            ContractMembershipWitness.revoked_at.is_(None),
        )
    ).scalar_one()
    assert witness.evidence["direction"] == "d2"
    assert witness.evidence["source"] == "probe"


def test_d2_evidence_refuses_the_caller_gate_source(db_session):
    """The evidence constructor is the boundary: a D2 witness citing
    ``controller_values`` is not constructible, so no writer can mint one."""
    with pytest.raises(ValueError, match="d2 source"):
        gate.w3_evidence(direction="d2", source="controller_values", via_address=_addr(0xE40))
