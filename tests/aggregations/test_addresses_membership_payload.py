"""Addresses-payload membership fields (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.2).

The inventory served by ``/api/company/{name}/addresses`` carries members AND
this protocol's candidates/pruned rows, each with ``membership_state`` derived
through the gate helper plus witness/probe reason fields — so the UI can show
a candidate's named missing piece (invariant 5) without composing anything.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import event

from db.models import (
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
)
from services.aggregations.company_overview.payload import (
    _all_addresses_count,
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

    payload = all_addresses_for_protocol(db_session, protocol, [])
    row = _row(payload, member.address)
    assert row["membership_state"] == "member"
    assert row["membership_reason"] is None
    # W1 is the precondition, not an admitting reason — only admitting rules
    # appear in the display witnesses.
    assert row["membership_witnesses"] == [
        {"rule": "w2_structural", "via_address": via, "edge_kind": "implementation", "heuristic": False}
    ]


def test_witness_display_entry_flags_heuristic_rules():
    """§9 invariant 1: no export presents a heuristic membership as proven —
    the display entry carries the gate's own heuristic predicate."""
    from services.aggregations.company_overview.payload import _witness_display_entry

    w4h = ContractMembershipWitness(
        contract_id=1,
        protocol_id=1,
        rule="w4h_deployer_affinity",
        evidence={"deployer": _addr("d")},
    )
    assert _witness_display_entry(w4h)["heuristic"] is True

    derived = ContractMembershipWitness(
        contract_id=1,
        protocol_id=1,
        rule="w2_structural",
        via_address=_addr("via"),
        evidence={"edge_kind": "implementation", "heuristic_via": True},
    )
    assert _witness_display_entry(derived)["heuristic"] is True

    proven = ContractMembershipWitness(
        contract_id=1,
        protocol_id=1,
        rule="w2_structural",
        via_address=_addr("via"),
        evidence={"edge_kind": "implementation"},
    )
    assert _witness_display_entry(proven)["heuristic"] is False


def test_member_revoked_witness_not_displayed(db_session, protocol):
    from datetime import datetime, timezone

    member = _add_member(db_session, protocol)
    db_session.add(
        ContractMembershipWitness(
            contract_id=member.id,
            protocol_id=protocol.id,
            rule="w5_human",
            evidence={"actor": "ops", "asserted_at": "2026-08-24T00:00:00+00:00"},
            revoked_at=datetime.now(timezone.utc),
        )
    )
    db_session.commit()

    row = _row(all_addresses_for_protocol(db_session, protocol, []), member.address)
    assert row["membership_state"] == "member"
    assert row["membership_witnesses"] == []


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

    row = _row(all_addresses_for_protocol(db_session, protocol, []), cand.address)
    assert row["membership_state"] == "candidate"
    assert row["membership_witnesses"] == []
    assert row["membership_reason"] == {
        "kind": "probe_unresolved",
        "probe_block": 1234,
        "resolved_reads": {"owner": owner},
        "unresolved_reads": ["authority", "implementation"],
    }


def test_candidate_unroutable_chain_reason(db_session, protocol):
    cand = _add_candidate(db_session, protocol, chain="unknown")
    db_session.add(
        ContractProbeAttempt(
            contract_id=cand.id,
            chain_id=0,
            block_number=None,
            results={"status": "not_routable", "chain": "unknown"},
        )
    )
    db_session.commit()

    row = _row(all_addresses_for_protocol(db_session, protocol, []), cand.address)
    assert row["membership_state"] == "candidate"
    assert row["membership_reason"] == {"kind": "chain_not_routable", "chain": "unknown"}


def test_candidate_without_probe_row_says_so(db_session, protocol):
    cand = _add_candidate(db_session, protocol)
    row = _row(all_addresses_for_protocol(db_session, protocol, []), cand.address)
    assert row["membership_state"] == "candidate"
    assert row["membership_reason"] == {"kind": "no_probe_attempt"}


def test_candidate_probe_error_reason(db_session, protocol):
    cand = _add_candidate(db_session, protocol)
    db_session.add(
        ContractProbeAttempt(
            contract_id=cand.id,
            chain_id=1,
            block_number=None,
            results={"status": "rpc_error", "error": "boom"},
        )
    )
    db_session.commit()

    row = _row(all_addresses_for_protocol(db_session, protocol, []), cand.address)
    assert row["membership_state"] == "candidate"
    assert row["membership_reason"] == {"kind": "probe_error"}


def test_pruned_carries_code_absent_block(db_session, protocol):
    cand = _add_candidate(db_session, protocol, name="Phantom")
    db_session.add(
        ContractCreationWitness(
            chain_id=1, address=cand.address.lower(), code_probe_block=999, code_absent_at_probe=True
        )
    )
    db_session.commit()

    row = _row(all_addresses_for_protocol(db_session, protocol, []), cand.address)
    assert row["membership_state"] == "pruned"
    assert row["membership_reason"] == {"kind": "code_absent", "code_probe_block": 999}


def test_unclaimed_and_foreign_rows_excluded(db_session, protocol):
    other = _add_protocol(db_session, f"member-payload-other-{uuid.uuid4().hex[:8]}")
    unclaimed = Contract(address=_addr("u"), chain="ethereum", protocol_id=None, nominated_protocol_id=None)
    # A member of ANOTHER protocol that this protocol also nominated stays in
    # the other protocol's inventory only.
    foreign = Contract(address=_addr("f"), chain="ethereum", protocol_id=other.id, nominated_protocol_id=protocol.id)
    db_session.add_all([unclaimed, foreign])
    db_session.commit()

    addrs = {r["address"] for r in all_addresses_for_protocol(db_session, protocol, [])}
    assert unclaimed.address not in addrs
    assert foreign.address not in addrs


def test_count_matches_inventory_extension(db_session, protocol):
    _add_member(db_session, protocol)
    _add_candidate(db_session, protocol)
    pruned = _add_candidate(db_session, protocol)
    db_session.add(
        ContractCreationWitness(
            chain_id=1, address=pruned.address.lower(), code_probe_block=5, code_absent_at_probe=True
        )
    )
    db_session.commit()

    assert _all_addresses_count(db_session, protocol, []) == 3
    assert len(all_addresses_for_protocol(db_session, protocol, [])) == 3


def test_membership_enrichment_is_batched(db_session, protocol):
    for _ in range(4):
        member = _add_member(db_session, protocol)
        db_session.add(
            ContractMembershipWitness(
                contract_id=member.id,
                protocol_id=protocol.id,
                rule="w6_llama_seed",
                evidence={"adapter_slug": "x", "chain_id": 1, "code_probe_block": 1},
            )
        )
    for _ in range(4):
        cand = _add_candidate(db_session, protocol)
        db_session.add(
            ContractProbeAttempt(
                contract_id=cand.id,
                chain_id=1,
                block_number=7,
                results={"status": "probed", "code_present": True, "reads": {}, "resolved_addresses": []},
            )
        )
    db_session.commit()

    queries: list[str] = []

    def before_cursor_execute(conn, cursor, statement, params, context, executemany):
        if statement.strip().lower().startswith("select"):
            queries.append(statement)

    event.listen(db_session.bind, "before_cursor_execute", before_cursor_execute)
    try:
        payload = all_addresses_for_protocol(db_session, protocol, [])
    finally:
        event.remove(db_session.bind, "before_cursor_execute", before_cursor_execute)

    assert len(payload) == 8
    # contracts + completed-jobs + code facts + witnesses + probe attempts —
    # one query per evidence table, never per row.
    assert len(queries) <= 6, f"expected ≤ 6 SELECTs for 8 rows, got {len(queries)}:\n" + "\n".join(queries)
