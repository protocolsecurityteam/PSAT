"""W4-H heuristic deployer lineage (DEPLOYER_HEURISTIC_SPEC.md §1, §5, §6, §9).

Covers the qualification bars (≥2 anchors, affinity ≥ 0.9, challenges < 3),
proof precedence over Class A/B, the derived registry states, the damped
challenge path (one foreign anchor is one row, never a family collapse), the
non-transitivity rule and its ONE same-contract exception, and the ordering
invariant that heuristic promotion runs last and feeds nothing back.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from db.models import (
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ControllerValue,
    DeployerAffinityChallenge,
    Protocol,
    ProtocolDeployer,
)
from services.discovery import membership_gate as gate
from tests.conftest import requires_postgres

pytestmark = [requires_postgres]

_TX = "0x" + "cd" * 32


def _protocol(session, label: str = "w4h") -> Protocol:
    row = Protocol(name=f"{label}-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _addr(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _code_fact(session, address: str, *, tx: str | None = _TX, absent: bool = False) -> None:
    session.add(
        ContractCreationWitness(
            chain_id=1,
            address=address.lower(),
            code_probe_block=50,
            code_absent_at_probe=absent,
            creation_tx_hash=tx,
            creation_block=10 if tx else None,
        )
    )
    session.flush()


def _contract(session, address: str, **fields) -> Contract:
    row = Contract(address=address.lower(), chain=fields.pop("chain", "ethereum"), **fields)
    session.add(row)
    session.flush()
    return row


def _anchor(session, protocol: Protocol, address: str, *, deployer: str, **fields) -> Contract:
    """A PROVEN member of *protocol* deployed by *deployer* — W1 + W6, which
    is a non-lineage, non-heuristic witness and therefore an anchor."""
    row = _contract(
        session, address, protocol_id=protocol.id, nominated_protocol_id=protocol.id, deployer=deployer, **fields
    )
    _code_fact(session, address)
    gate.write_witness(
        session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=50),
    )
    gate.write_witness(
        session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w6_llama_seed",
        evidence=gate.w6_evidence(adapter_slug="seed", chain_id=1, code_probe_block=50),
    )
    return row


def _candidate(session, protocol: Protocol, address: str, *, deployer: str, **fields) -> Contract:
    row = _contract(session, address, nominated_protocol_id=protocol.id, deployer=deployer, **fields)
    _code_fact(session, address)
    return row


def _rules(session, contract: Contract) -> set[str]:
    return {
        row.rule
        for row in session.execute(
            select(ContractMembershipWitness).where(
                ContractMembershipWitness.contract_id == contract.id,
                ContractMembershipWitness.revoked_at.is_(None),
            )
        ).scalars()
    }


def _h_row(session, protocol: Protocol, deployer: str) -> ProtocolDeployer | None:
    return session.execute(
        select(ProtocolDeployer).where(
            ProtocolDeployer.protocol_id == protocol.id,
            ProtocolDeployer.address == deployer,
            ProtocolDeployer.trust_class == "H",
        )
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Qualification (§1)
# ---------------------------------------------------------------------------


def test_two_anchors_grant_h_and_admit_the_siblings(db_session):
    protocol = _protocol(db_session)
    deployer = _addr(0xD01)
    _anchor(db_session, protocol, _addr(0xA01), deployer=deployer)
    _anchor(db_session, protocol, _addr(0xA02), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0xA03), deployer=deployer)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()

    row = _h_row(db_session, protocol, deployer)
    assert row is not None
    assert row.evidence["anchor_count"] == 2
    assert row.evidence["foreign_anchor_count"] == 0
    assert row.evidence["affinity"] == 1.0
    assert row.evidence["thresholds"] == {"min_anchors": 2, "min_affinity": 0.9, "challenge_quorum": 3}
    assert row.evidence["version"] == 1

    assert sibling.protocol_id == protocol.id
    assert _rules(db_session, sibling) == {"w1_code", "w4h_deployer_affinity"}
    witness = db_session.execute(
        select(ContractMembershipWitness).where(
            ContractMembershipWitness.contract_id == sibling.id,
            ContractMembershipWitness.rule == "w4h_deployer_affinity",
        )
    ).scalar_one()
    assert witness.via_address == deployer
    assert witness.evidence["anchors_at_grant"] == 2
    assert witness.evidence["affinity_at_grant"] == 1.0
    assert witness.evidence["creation_tx_hash"] == _TX


def test_one_anchor_short_grants_nothing(db_session):
    """The floor is symmetric with ruling 2: no single observation may create a
    family, exactly as no single observation may revoke one."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD02)
    _anchor(db_session, protocol, _addr(0xB01), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0xB02), deployer=deployer)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()

    assert _h_row(db_session, protocol, deployer) is None
    assert sibling.protocol_id is None
    assert _rules(db_session, sibling) == set()


def test_affinity_below_floor_grants_nothing(db_session):
    """Nine own anchors against two foreign ones is 0.818 — below θ."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "other")
    deployer = _addr(0xD03)
    for n in range(9):
        _anchor(db_session, protocol, _addr(0xC00 + n), deployer=deployer)
    for n in range(2):
        _anchor(db_session, other, _addr(0xC20 + n), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0xC40), deployer=deployer)

    affinity = gate.compute_deployer_affinity(db_session, protocol_id=protocol.id, address=deployer)
    assert affinity.anchor_count == 9
    assert affinity.foreign_anchor_count == 2
    assert affinity.affinity == pytest.approx(0.818182, abs=1e-6)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()
    assert _h_row(db_session, protocol, deployer) is None
    assert sibling.protocol_id is None


def test_unknown_creations_never_enter_the_denominator(db_session):
    """§1/invariant 4: a creation with no witness for any protocol is
    not_determined — context, never counterevidence."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD04)
    _anchor(db_session, protocol, _addr(0xE01), deployer=deployer)
    _anchor(db_session, protocol, _addr(0xE02), deployer=deployer)
    for n in range(20):
        _candidate(db_session, protocol, _addr(0xE10 + n), deployer=deployer)

    affinity = gate.compute_deployer_affinity(db_session, protocol_id=protocol.id, address=deployer)
    assert affinity.anchor_count == 2
    assert affinity.foreign_anchor_count == 0
    assert affinity.affinity == 1.0


def test_proof_class_takes_precedence(db_session):
    protocol = _protocol(db_session)
    deployer = _addr(0xD05)
    anchor = _anchor(db_session, protocol, _addr(0xF01), deployer=deployer)
    _anchor(db_session, protocol, _addr(0xF02), deployer=deployer)
    # A real §3.3 Class-A perimeter fact: the EOA is a resolved controller of
    # an anchoring member.
    db_session.add(
        ControllerValue(
            contract_id=anchor.id,
            controller_id="state_variable:owner",
            value=deployer,
            authority_provenance="caller_gate",
        )
    )
    db_session.flush()
    sibling = _candidate(db_session, protocol, _addr(0xF03), deployer=deployer)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()

    assert _h_row(db_session, protocol, deployer) is None
    # The proof class admits it instead — under W4, not W4-H.
    assert _rules(db_session, sibling) == {"w1_code", "w4_deployer"}


def test_admission_requires_w1_and_a_creation_witness(db_session):
    protocol = _protocol(db_session)
    deployer = _addr(0xD06)
    _anchor(db_session, protocol, _addr(0x1101), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x1102), deployer=deployer)
    no_code = _contract(db_session, _addr(0x1103), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, no_code.address, tx=_TX, absent=True)
    no_creation = _contract(db_session, _addr(0x1104), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, no_creation.address, tx=None)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(no_code.id, no_creation.id)))
    db_session.commit()

    assert no_code.protocol_id is None
    assert no_creation.protocol_id is None
    assert _rules(db_session, no_code) == set()
    assert _rules(db_session, no_creation) == set()


# ---------------------------------------------------------------------------
# Damped revocation (§5)
# ---------------------------------------------------------------------------


def test_one_foreign_anchor_is_one_challenge_row_not_a_collapse(db_session):
    """Ruling 2, the worked example: a single foreign witness lands as one
    challenge row. Nothing is revoked, nothing is demoted."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "lombard")
    deployer = _addr(0xD07)
    for n in range(16):
        _anchor(db_session, protocol, _addr(0x1200 + n), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0x1240), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()
    assert sibling.protocol_id == protocol.id

    _anchor(db_session, other, _addr(0x1250), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(changed_deployer_addresses=(deployer,)))
    db_session.commit()

    row = _h_row(db_session, protocol, deployer)
    assert row is not None and row.revoked_at is None
    assert row.evidence["challenge_count"] == 1
    assert row.evidence["anchor_count"] == 16
    assert row.evidence["foreign_anchor_count"] == 1
    assert gate.heuristic_registry_state(db_session, deployer_row=row) == "active"
    assert sibling.protocol_id == protocol.id


def test_quorum_freezes_admissions_and_keeps_standing_members(db_session):
    protocol = _protocol(db_session)
    other = _protocol(db_session, "lombard")
    deployer = _addr(0xD08)
    for n in range(30):
        _anchor(db_session, protocol, _addr(0x1300 + n), deployer=deployer)
    standing = _candidate(db_session, protocol, _addr(0x1340), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(standing.id,)))
    db_session.commit()
    assert standing.protocol_id == protocol.id

    for n in range(3):
        _anchor(db_session, other, _addr(0x1350 + n), deployer=deployer)
    later = _candidate(db_session, protocol, _addr(0x1360), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(later.id,)))
    db_session.commit()

    row = _h_row(db_session, protocol, deployer)
    assert row is not None and row.revoked_at is None
    assert gate.heuristic_registry_state(db_session, deployer_row=row) == "frozen"
    assert standing.protocol_id == protocol.id
    assert later.protocol_id is None


def test_challenge_revoked_with_its_foreign_witness(db_session):
    """A challenge is derived from a real witness row, never from suspicion:
    revoking that witness revokes the challenge."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "lombard")
    deployer = _addr(0xD09)
    for n in range(10):
        _anchor(db_session, protocol, _addr(0x1400 + n), deployer=deployer)
    foreign = _anchor(db_session, other, _addr(0x1420), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0x1430), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()

    row = _h_row(db_session, protocol, deployer)
    assert row is not None
    assert gate.sync_deployer_challenges(db_session, deployer_row=row) == 1

    for witness in gate.active_witnesses(db_session, contract_id=foreign.id, protocol_id=other.id):
        gate.revoke_witness(db_session, witness, reason="human_ruling")
    db_session.flush()

    assert gate.sync_deployer_challenges(db_session, deployer_row=row) == 0
    challenge = db_session.execute(
        select(DeployerAffinityChallenge).where(DeployerAffinityChallenge.protocol_deployer_id == row.id)
    ).scalar_one()
    assert challenge.revoked_at is not None
    assert challenge.revocation_reason == "foreign_witness_revoked"


def test_auto_revoke_below_the_hysteresis_floor(db_session):
    """affinity < 0.5 — the EOA is proven more foreign than ours — auto-revokes
    the row and demotes exactly the members left with no other witness."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "lombard")
    deployer = _addr(0xD0A)
    for n in range(2):
        _anchor(db_session, protocol, _addr(0x1500 + n), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0x1510), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()
    assert sibling.protocol_id == protocol.id

    for n in range(3):
        _anchor(db_session, other, _addr(0x1520 + n), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(changed_deployer_addresses=(deployer,)))
    db_session.commit()

    row = _h_row(db_session, protocol, deployer)
    assert row is not None
    assert row.revoked_at is not None
    assert sibling.protocol_id is None
    assert _rules(db_session, sibling) == {"w1_code"}


def test_suspended_when_anchors_erode(db_session):
    """Basis erosion is not counterevidence: the row suspends (no new
    admissions), standing members keep."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD0B)
    anchors = [_anchor(db_session, protocol, _addr(0x1600 + n), deployer=deployer) for n in range(2)]
    sibling = _candidate(db_session, protocol, _addr(0x1610), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()

    for witness in gate.active_witnesses(db_session, contract_id=anchors[0].id, protocol_id=protocol.id):
        gate.revoke_witness(db_session, witness, reason="anchor_lost")
    db_session.flush()

    row = _h_row(db_session, protocol, deployer)
    assert row is not None
    assert gate.heuristic_registry_state(db_session, deployer_row=row) == "suspended"
    assert sibling.protocol_id == protocol.id


# ---------------------------------------------------------------------------
# Non-transitivity and the §6 same-contract exception
# ---------------------------------------------------------------------------


def test_heuristic_member_anchors_nothing(db_session):
    """§6: a heuristic member is invisible to every evidence rule — it is no
    one's anchor, licenses no factory child, and its proxy-admin does not
    inherit."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD0C)
    _anchor(db_session, protocol, _addr(0x1700), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x1701), deployer=deployer)
    heuristic = _candidate(db_session, protocol, _addr(0x1710), deployer=deployer, admin=_addr(0x1711))
    admin = _candidate(db_session, protocol, _addr(0x1711), deployer=_addr(0xDEAD))

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(heuristic.id, admin.id)))
    db_session.commit()

    assert heuristic.protocol_id == protocol.id
    assert gate.member_for_evidence(db_session, contract_id=heuristic.id, protocol_id=protocol.id) is False
    assert admin.protocol_id is None
    assert _rules(db_session, admin) == set()
    # And it never counts as its own deployer's anchor (invariant 3).
    affinity = gate.compute_deployer_affinity(db_session, protocol_id=protocol.id, address=deployer)
    assert affinity.anchor_count == 2


def test_same_contract_implementation_inherits_and_rides_the_revocation(db_session):
    """§6's ONE exception, as measured on CumulativeMerkleDrop: the impl of an
    H-member proxy is admitted, displays as heuristic, and falls when the
    proxy's own w4h witness is revoked."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD0D)
    _anchor(db_session, protocol, _addr(0x1800), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x1801), deployer=deployer)
    impl = _candidate(db_session, protocol, _addr(0x1811), deployer=_addr(0xBEEF))
    proxy = _candidate(db_session, protocol, _addr(0x1810), deployer=deployer, implementation=impl.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(proxy.id, impl.id)))
    db_session.commit()

    assert proxy.protocol_id == protocol.id
    assert impl.protocol_id == protocol.id
    derived = db_session.execute(
        select(ContractMembershipWitness).where(
            ContractMembershipWitness.contract_id == impl.id,
            ContractMembershipWitness.rule == "w2_structural",
            ContractMembershipWitness.revoked_at.is_(None),
        )
    ).scalar_one()
    assert derived.evidence["heuristic_via"] is True
    assert gate.witness_is_heuristic(derived) is True
    assert gate.member_for_evidence(db_session, contract_id=impl.id, protocol_id=protocol.id) is False

    row = _h_row(db_session, protocol, deployer)
    assert row is not None
    gate.demote(db_session, deployer_row=row, reason="human_ruling")
    db_session.commit()

    assert proxy.protocol_id is None
    assert impl.protocol_id is None


def test_heuristic_via_is_same_contract_only(db_session):
    with pytest.raises(ValueError, match="same-contract"):
        gate.w2_evidence(
            edge_kind="proxy_admin",
            member_contract_id=1,
            member_address=_addr(0x1),
            resolved_pointer=_addr(0x2),
            heuristic_via=True,
        )


def test_heuristic_promotion_never_preempts_a_proof(db_session):
    """§9 invariant 8: W4-H is the last stratum, so a row that can be proven is
    proven — the heuristic rule never supplies its witness."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD0E)
    _anchor(db_session, protocol, _addr(0x1900), deployer=deployer)
    member = _anchor(db_session, protocol, _addr(0x1901), deployer=deployer)
    impl = _candidate(db_session, protocol, _addr(0x1910), deployer=deployer)
    member.implementation = impl.address
    db_session.flush()

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(impl.id,)))
    db_session.commit()

    assert impl.protocol_id == protocol.id
    assert _rules(db_session, impl) == {"w1_code", "w2_structural"}
    assert gate.member_for_evidence(db_session, contract_id=impl.id, protocol_id=protocol.id) is True
