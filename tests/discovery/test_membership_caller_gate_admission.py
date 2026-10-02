"""A bare caller gate admits nobody (``W3_D2_SOURCES``).

LayerZero's ``msg.sender != endpoint`` lowers to the same leaf as ``msg.sender != _owner``, so admitting off it
would admit an integration counterparty (EndpointV2, and via its owner the OneSig multisig).
"""

from __future__ import annotations

import uuid

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

ENDPOINT_V2 = "0x1a44076050125825900e736c501f859c50fe728c"

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


def test_caller_gate_member_demotes_on_re_earn(db_session):
    """A standing member whose only witness was the D2 caller-gate edge loses
    it: the via-fact no longer verifies, so the row demotes to candidate with
    its nomination and witness history preserved."""
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
