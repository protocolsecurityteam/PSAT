"""W4-H heuristic deployer lineage.

Covers the qualification bars (≥2 anchors, affinity ≥ 0.9, challenges < 3),
proof precedence over Class A/B, the derived registry states, the damped
challenge path (one foreign anchor is one row, never a family collapse), the
non-transitivity rule and its ONE same-contract exception, and the ordering
invariant that heuristic promotion runs last and feeds nothing back.
"""

from __future__ import annotations

import uuid

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
from tests.support.membership_builders import _contract

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


def _anchor(session, protocol: Protocol, address: str, *, deployer: str, **fields) -> Contract:
    """W1 + W6 is a non-lineage, non-heuristic witness, so it anchors."""
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
# Qualification
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Damped revocation
# ---------------------------------------------------------------------------


def test_one_foreign_anchor_is_one_challenge_row_not_a_collapse(db_session):
    """Ruling 2: a single foreign witness is one challenge row; nothing is revoked."""
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
    """Revoking the foreign witness revokes the challenge."""
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


def test_suspended_when_anchors_erode(db_session):
    """Basis erosion is not counterevidence."""
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
# Non-transitivity and the same-contract exception
# ---------------------------------------------------------------------------


def test_same_contract_implementation_inherits_and_rides_the_revocation(db_session):
    """The same-contract exception, as measured on CumulativeMerkleDrop: the impl of an
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


def test_late_inherited_w2_falls_with_the_proxys_heuristic_standing(db_session):
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
    """Without deployer attribution only the seed's via members pull the stale H row into the stratum."""
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


def test_exclusivity_requires_a_proven_member(db_session):
    """For the shared-operator kill: a heuristic-only member is
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
    assert gate._controller_is_exclusive(
        db_session,
        protocol_id=protocol.id,
        controller_address=operator,
        chain_key="ethereum",
        exclude_contract_ids=set(),
    )


def test_proof_class_row_never_accrues_challenges(db_session):
    """Challenges are an H-class concept: the W4-H stratum leaves a
    standing Class-A row alone — no challenge sync, no grant attempt."""
    protocol = _protocol(db_session)
    other = _protocol(db_session, "other")
    deployer = _addr(0xD10)
    anchor = _anchor(db_session, protocol, _addr(0x2001), deployer=deployer)
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

    # No member stamp, so it mints no cross-protocol collision.
    foreign = _contract(db_session, _addr(0x2002), nominated_protocol_id=other.id, deployer=deployer)
    _code_fact(db_session, foreign.address)
    gate.write_witness(
        db_session,
        contract_id=foreign.id,
        protocol_id=other.id,
        rule="w6_llama_seed",
        evidence=gate.w6_evidence(adapter_slug="seed", chain_id=1, code_probe_block=50),
    )
    # Keeps (protocol, EOA) in scope without ever settling.
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


def test_anchor_swap_preserving_counts_refreshes_evidence(db_session):
    """The evidence names the actual inputs. An anchor swap that leaves
    all four live numbers unchanged still rewrites ``anchors`` (and
    ``computed_at``); a further no-change evaluate leaves it byte-identical."""
    protocol = _protocol(db_session)
    deployer = _addr(0xD33)
    swapped = _anchor(db_session, protocol, _addr(0x2A00), deployer=deployer)
    _anchor(db_session, protocol, _addr(0x2A01), deployer=deployer)
    blocked = _contract(db_session, _addr(0x2A03), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, blocked.address, tx=None)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(blocked.id,)))
    db_session.commit()
    row = _h_row(db_session, protocol, deployer)
    assert row is not None
    first = dict(row.evidence)
    assert swapped.id in [anchor["contract_id"] for anchor in first["anchors"]]

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
