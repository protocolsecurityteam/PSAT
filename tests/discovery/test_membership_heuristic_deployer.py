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


def test_same_run_promotion_recomputes_a_foreign_standing_h_row(db_session):
    """A proof-round promotion is a fresh FOREIGN anchor against a standing H
    row keyed by the same EOA under ANOTHER protocol: the promoted contract's
    deployer joins the W4-H scope, so the third foreign anchor arriving
    through the promotion auto-revokes (P1, X) in the SAME evaluate."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "lombard")
    deployer = _addr(0xD30)
    _anchor(db_session, protocol, _addr(0x2700), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2701), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0x2702), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()
    assert sibling.protocol_id == protocol.id

    # Two standing foreign anchors: 2/4 = 0.5 — AT the floor, not below it.
    third_address = _addr(0x2712)
    _anchor(db_session, other, _addr(0x2710), deployer=deployer, implementation=third_address)
    _anchor(db_session, other, _addr(0x2711), deployer=deployer)
    # The third arrives as a pending candidate of the OTHER protocol; its W2
    # promotion in the proof rounds pushes affinity to 2/5 = 0.4.
    third = _candidate(db_session, other, third_address, deployer=deployer)

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(third.id,)))
    db_session.commit()

    assert third.protocol_id == other.id
    row = _h_row(db_session, protocol, deployer)
    assert row is not None and row.revoked_at is not None
    assert row.revocation_reason == "affinity_below_auto_revoke_floor"
    assert sibling.protocol_id is None
    assert sibling.id in result.demoted_contract_ids


def test_entry_delta_member_recomputes_a_foreign_standing_h_row(db_session):
    """``run_probe_pass`` promotes near-line and hands the members to
    ``evaluate`` as the entry delta — those members' deployers must reach the
    W4-H scope, or a should-be-revoked H row of another protocol stands."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "lombard")
    deployer = _addr(0xD31)
    _anchor(db_session, protocol, _addr(0x2800), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2801), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0x2802), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()
    assert sibling.protocol_id == protocol.id

    _anchor(db_session, other, _addr(0x2810), deployer=deployer)
    _anchor(db_session, other, _addr(0x2811), deployer=deployer)
    # The third foreign anchor was stamped BEFORE this evaluate (the probe-pass
    # shape) — the delta names the member, never its deployer.
    third = _anchor(db_session, other, _addr(0x2812), deployer=deployer)

    result = gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(third.id,)))
    db_session.commit()

    row = _h_row(db_session, protocol, deployer)
    assert row is not None and row.revoked_at is not None
    assert sibling.protocol_id is None
    assert sibling.id in result.demoted_contract_ids


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


def test_implementation_discovered_after_its_proxy_still_inherits(db_session):
    """§6 late arrival: the implementation row appears only AFTER the run that
    admitted the proxy heuristically — the next evaluate still carries it, as
    the same heuristic_via W2 a same-run discovery would have minted."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD23)
    _anchor(db_session, protocol, _addr(0x2400), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2401), deployer=deployer)
    impl_address = _addr(0x2411)
    proxy = _candidate(db_session, protocol, _addr(0x2410), deployer=deployer, implementation=impl_address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(proxy.id,)))
    db_session.commit()
    assert proxy.protocol_id == protocol.id
    assert gate.member_for_evidence(db_session, contract_id=proxy.id, protocol_id=protocol.id) is False

    impl = _candidate(db_session, protocol, impl_address, deployer=_addr(0xBEE3))
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(impl.id,)))
    db_session.commit()

    assert impl.protocol_id == protocol.id
    derived = db_session.execute(
        select(ContractMembershipWitness).where(
            ContractMembershipWitness.contract_id == impl.id,
            ContractMembershipWitness.rule == "w2_structural",
            ContractMembershipWitness.revoked_at.is_(None),
        )
    ).scalar_one()
    assert derived.evidence["heuristic_via"] is True
    assert derived.evidence["edge_kind"] == "implementation"
    assert derived.via_address == proxy.address
    assert gate.witness_is_heuristic(derived) is True
    assert gate.member_for_evidence(db_session, contract_id=impl.id, protocol_id=protocol.id) is False

    # Settled: a re-evaluation over unchanged facts mints and revokes nothing.
    before = {(row.id, row.revoked_at) for row in db_session.execute(select(ContractMembershipWitness)).scalars()}
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(impl.id,)))
    db_session.commit()
    after = {(row.id, row.revoked_at) for row in db_session.execute(select(ContractMembershipWitness)).scalars()}
    assert after == before


def test_late_inherited_w2_falls_with_the_proxys_heuristic_standing(db_session):
    """Revocation propagation for the late-minted W2: an affinity collapse that
    auto-revokes the H row demotes the proxy, and the implementation's
    heuristic_via W2 falls with it."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "lombard")
    deployer = _addr(0xD24)
    _anchor(db_session, protocol, _addr(0x2500), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2501), deployer=deployer)
    impl_address = _addr(0x2511)
    proxy = _candidate(db_session, protocol, _addr(0x2510), deployer=deployer, implementation=impl_address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(proxy.id,)))
    db_session.commit()

    impl = _candidate(db_session, protocol, impl_address, deployer=_addr(0xBEE4))
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(impl.id,)))
    db_session.commit()
    assert proxy.protocol_id == protocol.id and impl.protocol_id == protocol.id

    for n in range(3):
        _anchor(db_session, other, _addr(0x2520 + n), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(changed_deployer_addresses=(deployer,)))
    db_session.commit()

    row = _h_row(db_session, protocol, deployer)
    assert row is not None and row.revoked_at is not None
    assert proxy.protocol_id is None
    assert impl.protocol_id is None
    assert "w2_structural" not in _rules(db_session, impl)


def test_late_inheritance_refused_off_a_stale_h_row(db_session):
    """Revocations before inheritance: a late impl candidate WITHOUT deployer
    attribution names no (protocol, deployer) pair, so only the seed's via
    members can pull the stale H row into the stratum — the row (live affinity
    below the auto-revoke floor) is revoked, the via proxy demoted, and the
    impl NOT admitted off the dead row."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "lombard")
    deployer = _addr(0xD32)
    _anchor(db_session, protocol, _addr(0x2900), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2901), deployer=deployer)
    impl_address = _addr(0x2911)
    proxy = _candidate(db_session, protocol, _addr(0x2910), deployer=deployer, implementation=impl_address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(proxy.id,)))
    db_session.commit()
    assert proxy.protocol_id == protocol.id

    # The row goes stale out-of-band: three foreign anchors written with no
    # evaluate naming the deployer — live affinity 2/5 = 0.4, recorded active.
    for n in range(3):
        _anchor(db_session, other, _addr(0x2920 + n), deployer=deployer)

    impl = _contract(db_session, impl_address, nominated_protocol_id=protocol.id)
    _code_fact(db_session, impl.address)
    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(impl.id,)))
    db_session.commit()

    row = _h_row(db_session, protocol, deployer)
    assert row is not None and row.revoked_at is not None
    assert row.revocation_reason == "affinity_below_auto_revoke_floor"
    assert proxy.protocol_id is None
    assert proxy.id in result.demoted_contract_ids
    assert impl.protocol_id is None
    assert _rules(db_session, impl) == set()


def test_heuristic_member_without_pointer_seeds_no_late_inheritance(db_session):
    """No-op guarantees: a heuristic member with no implementation pointer
    seeds nothing, an unrelated late candidate stays pending, and a second
    evaluate over unchanged facts mints and revokes nothing."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD25)
    _anchor(db_session, protocol, _addr(0x2600), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2601), deployer=deployer)
    member = _candidate(db_session, protocol, _addr(0x2602), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(member.id,)))
    db_session.commit()
    assert member.protocol_id == protocol.id
    assert gate.member_for_evidence(db_session, contract_id=member.id, protocol_id=protocol.id) is False

    late = _candidate(db_session, protocol, _addr(0x2603), deployer=_addr(0xBEE5))
    assert gate._w4h_late_inheritance_seed(db_session, {late.id}) == set()

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(late.id,)))
    db_session.commit()
    assert late.protocol_id is None
    assert _rules(db_session, late) == set()

    before = {(row.id, row.revoked_at) for row in db_session.execute(select(ContractMembershipWitness)).scalars()}
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(late.id,)))
    db_session.commit()
    after = {(row.id, row.revoked_at) for row in db_session.execute(select(ContractMembershipWitness)).scalars()}
    assert after == before


def test_exclusivity_requires_a_proven_member(db_session):
    """§9 invariant 3 on the shared-operator kill: a heuristic-only member is
    not_determined there — it neither supplies the mandatory proven member nor
    refuses the verdict as foreign."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD20)
    operator = _addr(0xD21)
    _anchor(db_session, protocol, _addr(0x2200), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2201), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0x2202), deployer=deployer)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()
    assert sibling.protocol_id == protocol.id
    assert gate.member_for_evidence(db_session, contract_id=sibling.id, protocol_id=protocol.id) is False

    db_session.add(
        ControllerValue(
            contract_id=sibling.id, controller_id="owner", value=operator, authority_provenance="caller_gate"
        )
    )
    db_session.flush()
    assert not gate._controller_is_exclusive(
        db_session,
        protocol_id=protocol.id,
        controller_address=operator,
        chain_key="ethereum",
        exclude_contract_ids=set(),
    )

    proven = _anchor(db_session, protocol, _addr(0x2203), deployer=_addr(0xBEE1))
    db_session.add(
        ControllerValue(
            contract_id=proven.id, controller_id="owner", value=operator, authority_provenance="caller_gate"
        )
    )
    db_session.flush()
    # One proven member licenses; the heuristic member is tolerated as family.
    assert gate._controller_is_exclusive(
        db_session,
        protocol_id=protocol.id,
        controller_address=operator,
        chain_key="ethereum",
        exclude_contract_ids=set(),
    )


def test_proxy_over_heuristic_only_impl_member_derives_no_w2(db_session):
    """§6 is one-directional: an H-member proxy carries its implementation,
    but a heuristic-only IMPL member is invisible to the reverse proxy edge —
    no W2 for the proxy, flagged or not, and a re-evaluation over unchanged
    facts mints and revokes nothing."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD22)
    _anchor(db_session, protocol, _addr(0x2300), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2301), deployer=deployer)
    impl = _candidate(db_session, protocol, _addr(0x2302), deployer=deployer)
    proxy = _candidate(db_session, protocol, _addr(0x2303), deployer=_addr(0xBEE2), implementation=impl.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(impl.id, proxy.id)))
    db_session.commit()

    assert impl.protocol_id == protocol.id
    assert gate.member_for_evidence(db_session, contract_id=impl.id, protocol_id=protocol.id) is False
    assert proxy.protocol_id is None
    assert _rules(db_session, proxy) == set()

    before = {(row.id, row.revoked_at) for row in db_session.execute(select(ContractMembershipWitness)).scalars()}
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(impl.id, proxy.id)))
    db_session.commit()
    after = {(row.id, row.revoked_at) for row in db_session.execute(select(ContractMembershipWitness)).scalars()}
    assert after == before


def test_heuristic_via_is_same_contract_only(db_session):
    with pytest.raises(ValueError, match="same-contract"):
        gate.w2_evidence(
            edge_kind="proxy_admin",
            member_contract_id=1,
            member_address=_addr(0x1),
            resolved_pointer=_addr(0x2),
            heuristic_via=True,
        )


def test_proof_class_row_never_accrues_challenges(db_session):
    """Challenges are an H-class concept (§5): the W4-H stratum leaves a
    standing Class-A row alone — no challenge sync, no grant attempt."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "other")
    deployer = _addr(0xD10)
    anchor = _anchor(db_session, protocol, _addr(0x2001), deployer=deployer)
    # A real Class-A perimeter fact keeps the row standing through stratum (ii).
    db_session.add(
        ControllerValue(
            contract_id=anchor.id,
            controller_id="state_variable:owner",
            value=deployer,
            authority_provenance="caller_gate",
        )
    )
    db_session.flush()
    verdict = gate.classify_deployer(db_session, protocol_id=protocol.id, address=deployer)
    assert verdict.trust_class == "A"
    row = gate.register_deployer(db_session, protocol_id=protocol.id, address=deployer, classification=verdict)

    # A foreign anchor the challenge sync would observe: a CANDIDATE of another
    # protocol attributed to the EOA, holding a non-lineage witness — no member
    # stamp, so it mints no cross-protocol collision either.
    foreign = _contract(db_session, _addr(0x2002), nominated_protocol_id=other.id, deployer=deployer)
    _code_fact(db_session, foreign.address)
    gate.write_witness(
        db_session,
        contract_id=foreign.id,
        protocol_id=other.id,
        rule="w6_llama_seed",
        evidence=gate.w6_evidence(adapter_slug="seed", chain_id=1, code_probe_block=50),
    )
    # A creation-less candidate keeps (protocol, EOA) in the W4-H stratum's
    # scope without ever settling.
    blocked = _contract(db_session, _addr(0x2003), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, blocked.address, tx=None)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(blocked.id,)))
    db_session.commit()

    db_session.refresh(row)
    assert row.trust_class == "A" and row.revoked_at is None
    assert _h_row(db_session, protocol, deployer) is None
    challenges = (
        db_session.execute(
            select(DeployerAffinityChallenge).where(DeployerAffinityChallenge.protocol_deployer_id == row.id)
        )
        .scalars()
        .all()
    )
    assert challenges == []


def test_reevaluation_over_unchanged_facts_leaves_evidence_untouched(db_session):
    """A second evaluate over an unchanged DB is a no-op on the H registry:
    the recorded evidence — ``computed_at`` included — stays byte-identical."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD11)
    _anchor(db_session, protocol, _addr(0x2101), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2102), deployer=deployer)
    sibling = _candidate(db_session, protocol, _addr(0x2103), deployer=deployer)
    # A creation-less candidate keeps the (protocol, EOA) pair examined on
    # every run without ever settling.
    blocked = _contract(db_session, _addr(0x2104), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, blocked.address, tx=None)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id, blocked.id)))
    db_session.commit()
    row = _h_row(db_session, protocol, deployer)
    assert row is not None and sibling.protocol_id == protocol.id
    first = dict(row.evidence)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(blocked.id,)))
    db_session.commit()
    db_session.refresh(row)
    assert row.evidence == first


def test_anchor_swap_preserving_counts_refreshes_evidence(db_session):
    """§8.1: the evidence names the actual inputs. An anchor swap that leaves
    all four live numbers unchanged still rewrites ``anchors`` (and
    ``computed_at``); a further no-change evaluate leaves it byte-identical."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD33)
    swapped = _anchor(db_session, protocol, _addr(0x2A00), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2A01), deployer=deployer)
    # A creation-less candidate keeps the (protocol, EOA) pair examined on
    # every run without ever settling.
    blocked = _contract(db_session, _addr(0x2A03), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, blocked.address, tx=None)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(blocked.id,)))
    db_session.commit()
    row = _h_row(db_session, protocol, deployer)
    assert row is not None
    first = dict(row.evidence)
    assert swapped.id in [anchor["contract_id"] for anchor in first["anchors"]]

    # Swap: one anchor out, a replacement in — every count is preserved.
    replacement = _anchor(db_session, protocol, _addr(0x2A02), deployer=deployer)
    for witness in gate.active_witnesses(db_session, contract_id=swapped.id, protocol_id=protocol.id):
        gate.revoke_witness(db_session, witness, reason="anchor_swap")
    db_session.flush()

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(blocked.id,)))
    db_session.commit()
    db_session.refresh(row)
    for key in ("anchor_count", "foreign_anchor_count", "affinity", "challenge_count"):
        assert row.evidence[key] == first[key]
    anchor_ids = [anchor["contract_id"] for anchor in row.evidence["anchors"]]
    assert replacement.id in anchor_ids and swapped.id not in anchor_ids
    assert row.evidence["computed_at"] != first["computed_at"]

    second = dict(row.evidence)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(blocked.id,)))
    db_session.commit()
    db_session.refresh(row)
    assert row.evidence == second


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
