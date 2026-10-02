"""Addresses-payload membership fields.

The inventory served by ``/api/company/{name}/addresses`` carries members AND
this protocol's candidates/pruned rows, each with ``membership_state`` derived
through the gate helper plus witness/probe reason fields — so the UI can show
a candidate's named missing piece without composing anything.
"""

from __future__ import annotations

import uuid

import pytest

from db.models import (
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
)
from services.aggregations.company_overview.payload import (
    all_addresses_for_protocol,
)
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres


@pytest.fixture()
def protocol(db_session):
    return _add_protocol(db_session, f"member-payload-{uuid.uuid4().hex[:8]}")


def _row(payload, address):
    matches = [r for r in payload if r["address"] == address]
    assert len(matches) == 1, f"expected exactly one payload row for {address}, got {len(matches)}"
    return matches[0]


def _add_member(db_session, protocol, *, name="Member"):
    address = _addr("m")
    job = _add_job(db_session, address=address, protocol_id=protocol.id, name=name)
    return _add_contract(db_session, address=address, job=job, protocol_id=protocol.id, contract_name=name)


def _add_candidate(db_session, protocol, *, chain="ethereum", name="Candidate"):
    c = Contract(
        address=_addr("c"),
        chain=chain,
        protocol_id=None,
        nominated_protocol_id=protocol.id,
        contract_name=name,
    )
    db_session.add(c)
    db_session.commit()
    db_session.refresh(c)
    return c


def test_member_carries_state_and_admitting_witnesses(db_session, protocol):
    member = _add_member(db_session, protocol)
    via = _addr("via")
    db_session.add(
        ContractMembershipWitness(
            contract_id=member.id,
            protocol_id=protocol.id,
            rule="w1_code",
            evidence={"chain_id": 1, "code_probe_block": 100, "code_present": True},
        )
    )
    db_session.add(
        ContractMembershipWitness(
            contract_id=member.id,
            protocol_id=protocol.id,
            rule="w2_structural",
            via_address=via,
            evidence={
                "edge_kind": "implementation",
                "member_contract_id": member.id,
                "member_address": via,
                "resolved_pointer": member.address,
            },
        )
    )
    db_session.commit()

    payload = all_addresses_for_protocol(db_session, protocol)
    row = _row(payload, member.address)
    assert row["membership_state"] == "member"
    assert row["membership_reason"] is None
    # W1 is a precondition, not an admitting reason, so it is not a display witness.
    assert row["membership_witnesses"] == [
        {"rule": "w2_structural", "via_address": via, "edge_kind": "implementation", "heuristic": False}
    ]


def test_candidate_probed_reason_names_the_reads(db_session, protocol):
    cand = _add_candidate(db_session, protocol)
    owner = _addr("owner")
    db_session.add(
        ContractProbeAttempt(
            contract_id=cand.id,
            chain_id=1,
            block_number=1234,
            results={
                "status": "probed",
                "code_present": True,
                "reads": {
                    "owner": {"ok": True, "value": owner, "error": None},
                    "authority": {"ok": True, "value": None, "error": None},
                    "implementation": {"ok": False, "value": None, "error": "no_result"},
                },
                "resolved_addresses": [owner],
            },
        )
    )
    db_session.commit()

    row = _row(all_addresses_for_protocol(db_session, protocol), cand.address)
    assert row["membership_state"] == "candidate"
    assert row["membership_witnesses"] == []
    assert row["membership_reason"] == {
        "kind": "probe_unresolved",
        "probe_block": 1234,
        "resolved_reads": {"owner": owner},
        "unresolved_reads": ["authority", "implementation"],
    }


@pytest.mark.parametrize(
    "chain, probe, expected_reason",
    [
        pytest.param(
            "unknown",
            {"chain_id": 0, "results": {"status": "not_routable", "chain": "unknown"}},
            {"kind": "chain_not_routable", "chain": "unknown"},
            id="unroutable-chain",
        ),
        pytest.param("ethereum", None, {"kind": "no_probe_attempt"}, id="no-probe-row"),
        pytest.param(
            "ethereum",
            {"chain_id": 1, "results": {"status": "rpc_error", "error": "boom"}},
            {"kind": "probe_error"},
            id="rpc-error-is-probe-error",
        ),
    ],
)
def test_candidate_membership_reason(db_session, protocol, chain, probe, expected_reason):
    cand = _add_candidate(db_session, protocol, chain=chain)
    if probe is not None:
        db_session.add(ContractProbeAttempt(contract_id=cand.id, block_number=None, **probe))
        db_session.commit()

    row = _row(all_addresses_for_protocol(db_session, protocol), cand.address)
    assert row["membership_state"] == "candidate"
    assert row["membership_reason"] == expected_reason


def test_pruned_carries_code_absent_block(db_session, protocol):
    cand = _add_candidate(db_session, protocol, name="Phantom")
    db_session.add(
        ContractCreationWitness(
            chain_id=1, address=cand.address.lower(), code_probe_block=999, code_absent_at_probe=True
        )
    )
    db_session.commit()

    row = _row(all_addresses_for_protocol(db_session, protocol), cand.address)
    assert row["membership_state"] == "pruned"
    assert row["membership_reason"] == {"kind": "code_absent", "code_probe_block": 999}
