"""Anchored-authority-chain transitivity (DISCOVERY_MEMBERSHIP_GATE_SPEC.md
§3.2, deliberate extension).

The shapes pinned here are the ones the dev DB actually carries: a protocol's
governance component (registry → timelock → multisig) enters the graph only
through W3-D2 edges, so D2 non-transitivity leaves it and every ward it
governs unwitnessed. The extension admits exactly the case where the D2
controller's OWN controllers root in the protocol's independently anchored
perimeter, and refuses the shared-operator shape it must never license.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func

from db.models import (
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Protocol,
    RoleHolderPlane,
)
from services.discovery import membership_gate as gate
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]

PROPOSER_ROLE = "0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1"
DEFAULT_ADMIN_ROLE = "0x" + "0" * 64
UNRELATED_ROLE = "0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a"


@pytest.fixture()
def protocol(db_session):
    row = Protocol(name=f"anchor-{uuid.uuid4().hex[:10]}")
    db_session.add(row)
    db_session.flush()
    return row


def _contract(db_session, address, *, protocol_id=None, nominated=None, chain="ethereum", implementation=None):
    row = Contract(
        address=address.lower(),
        chain=chain,
        protocol_id=protocol_id,
        nominated_protocol_id=nominated,
        implementation=implementation,
    )
    db_session.add(row)
    db_session.flush()
    db_session.add(
        ContractCreationWitness(chain_id=1, address=row.address, code_probe_block=1000, code_absent_at_probe=False)
    )
    db_session.flush()
    return row


def _anchored_member(db_session, protocol, address):
    """A member whose admitting witness rests on no via-fact at all (W5) —
    the only kind that can terminate an anchor chain outright."""
    row = _contract(db_session, address, protocol_id=protocol.id, nominated=protocol.id)
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="admin", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc)),
    )
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=1000),
    )
    db_session.flush()
    return row


def _anchored_holder(db_session, protocol, address):
    """A role holder / Safe signer that is itself an independently anchored
    MEMBER — the only terminal a SET-valued link may root at (spec §3.2
    extension, set-arity rule)."""
    return _anchored_member(db_session, protocol, address).address


def _probe_read(db_session, subject, value):
    """Persist the §3.5 probe read of a governance getter, merged into the
    subject's single attempt row under the first free slot of the three reads
    the gate consults. This is the derivation a W3-D2 witness rests on
    (``W3_D2_SOURCES``) — a bare caller gate is not one."""
    row = db_session.get(ContractProbeAttempt, (subject.id, 1))
    reads = dict(row.results.get("reads", {})) if row is not None and isinstance(row.results, dict) else {}
    slot = next(
        (
            name
            for name in ("owner", "authority", "admin")
            if name not in reads or reads[name]["value"] == value.lower()
        ),
        "owner",
    )
    reads[slot] = {"value": value.lower()}
    resolved = sorted({read["value"] for read in reads.values()})
    results = {"status": "probed", "code_present": True, "reads": reads, "resolved_addresses": resolved}
    if row is None:
        db_session.add(ContractProbeAttempt(contract_id=subject.id, chain_id=1, block_number=1000, results=results))
    else:
        row.results = results
    db_session.flush()


def _caller_gate(db_session, subject, value, controller_id="owner"):
    """The subject's resolved owner/authority, recorded on both derivations the
    gate reads: the static caller-gate row (which feeds the anchor-chain and
    exclusivity walks) and the probe read (which is what admits under D2)."""
    db_session.add(
        ControllerValue(
            contract_id=subject.id,
            controller_id=controller_id,
            value=value.lower(),
            authority_provenance="caller_gate",
        )
    )
    db_session.flush()
    _probe_read(db_session, subject, value)


def _principal(db_session, host, address, *, resolved_type=None, details=None, function_name="admin"):
    fn = EffectiveFunction(contract_id=host.id, function_name=f"{function_name}-{uuid.uuid4().hex[:6]}")
    db_session.add(fn)
    db_session.flush()
    row = FunctionPrincipal(function_id=fn.id, address=address.lower(), resolved_type=resolved_type, details=details)
    db_session.add(row)
    db_session.flush()
    return row


def _role_plane(db_session, registry_address, role_hash, holders, *, role_name="PROPOSER_ROLE"):
    db_session.add(
        RoleHolderPlane(
            chain_id=1,
            registry_address=registry_address.lower(),
            role_hash=role_hash,
            holders=[h.lower() for h in holders],
            holders_basis="pinned_has_role_confirmed",
            holder_set_exhaustive="not_determined",
            as_of_block=25_000_000,
            as_of_block_hash=b"\xab" * 32,
            cursor_first_indexed_block=None,
            cursor_first_indexed_block_basis="not_determined",
            cursor_last_indexed_block=24_999_000,
            cursor_enrollment_bases={},
            cursor_page_completeness="not_determined",
            coverage="lower_bound",
            role_name=role_name,
            role_name_basis=(
                "accesscontrol_default_admin_literal" if role_hash == DEFAULT_ADMIN_ROLE else "keccak_preimage"
            ),
            candidate_count=len(holders),
            unconfirmed_candidate_count=0,
            fold_chain_disagreements=[],
        )
    )
    db_session.flush()


def _unclaimed_ward(db_session, controller):
    """A row the controller is observed to control that no protocol claims.
    Every D2 fixture carries one so the pre-existing exclusivity arm cannot
    stand in for the anchor chain under test (and so a refusal is a real
    refusal, not exclusivity quietly admitting)."""
    row = Contract(address=ADDR(int(controller.address, 16) + 0x800000), chain="ethereum")
    db_session.add(row)
    db_session.flush()
    _caller_gate(db_session, row, controller.address)
    return row


def _d2_member(db_session, protocol, address, *, controls):
    """A controller that enters the perimeter ONLY through W3-D2: it
    caller-gates *controls*, and holds no other admitting witness."""
    row = _contract(db_session, address, nominated=protocol.id)
    _caller_gate(db_session, controls, row.address)
    _unclaimed_ward(db_session, row)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(row.id,)))
    db_session.flush()
    assert row.protocol_id == protocol.id, "fixture: the D2 controller must have entered as a member"
    rules = {
        (w.rule, (w.evidence or {}).get("direction"))
        for w in gate.active_witnesses(db_session, contract_id=row.id, protocol_id=protocol.id)
    }
    assert ("w3_control", "d2") in rules and ("w3_control", "d1") not in rules
    return row


def _witness_rules(db_session, contract, protocol):
    return {
        (w.rule, (w.evidence or {}).get("direction"))
        for w in gate.active_witnesses(db_session, contract_id=contract.id, protocol_id=protocol.id)
    }


def _d1_witness(db_session, contract, protocol) -> ContractMembershipWitness:
    for w in gate.active_witnesses(db_session, contract_id=contract.id, protocol_id=protocol.id):
        if w.rule == "w3_control" and (w.evidence or {}).get("direction") == "d1":
            return w
    raise AssertionError(f"contract {contract.id} holds no active W3-D1 witness for protocol {protocol.id}")


# ---------------------------------------------------------------------------
# (a) the timelock shape ADMITS, and the ward's proxy rides the same fixpoint
# ---------------------------------------------------------------------------


def test_timelock_anchored_through_role_holder_admits_wards_and_their_proxies(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0xA01))
    timelock = _d2_member(db_session, protocol, ADDR(0xA02), controls=anchor)

    # The timelock's own controller: a Safe holding PROPOSER_ROLE which is
    # itself an independently anchored member (set-arity rule).
    safe = _anchored_holder(db_session, protocol, ADDR(0xA03))
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])

    ward = _contract(db_session, ADDR(0xA05), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)
    proxy = _contract(db_session, ADDR(0xA06), nominated=protocol.id, implementation=ward.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id, proxy.id)))
    db_session.flush()

    assert ward.protocol_id == protocol.id
    assert proxy.protocol_id == protocol.id, "the ward's proxy must earn W2 in the SAME fixpoint run"
    assert ("w2_structural", None) in _witness_rules(db_session, proxy, protocol)

    witness = _d1_witness(db_session, ward, protocol)
    chain = witness.evidence["anchor_chain"]
    assert chain["links"] == [
        {"from": timelock.address, "address": safe, "kind": "role_holder", "detail": PROPOSER_ROLE}
    ]
    assert chain["anchor_address"] == safe
    assert chain["anchor_kind"] == "member", "a set-valued link may root only at an anchored member"
    assert chain["anchor_rule"] == "w5_human"


def test_anchor_chain_evidence_round_trips_and_is_stable(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0xB01))
    timelock = _d2_member(db_session, protocol, ADDR(0xB02), controls=anchor)
    safe = _anchored_holder(db_session, protocol, ADDR(0xB03))
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])

    first = gate._via_transitivity(
        db_session, protocol_id=protocol.id, via_address=timelock.address, chain_key="ethereum"
    )
    second = gate._via_transitivity(
        db_session, protocol_id=protocol.id, via_address=timelock.address, chain_key="ethereum"
    )
    assert first is not None
    assert second is not None
    assert first.arm == "anchor_chain"
    assert first.anchor_chain == second.anchor_chain, "derivation must be deterministic"

    evidence = gate.w3_evidence(
        direction="d1",
        source="controller_values",
        via_address=timelock.address,
        via_transitive=True,
        anchor_chain=first.anchor_chain,
    )
    assert gate._validate_evidence("w3_control", evidence) == evidence
    # A hand-rolled chain with an unknown link kind is refused (invariant 2).
    with pytest.raises(ValueError):
        gate._validate_evidence(
            "w3_control",
            {
                **evidence,
                "anchor_chain": {
                    **evidence["anchor_chain"],
                    "links": [{**evidence["anchor_chain"]["links"][0], "kind": "vibes"}],
                },
            },
        )


@pytest.mark.parametrize(
    "kind,detail",
    [
        ("owner_or_authority", "probe"),
        ("owner_or_authority", "whatever the caller felt like"),
        ("owner_or_authority", None),
        ("proxy_admin", "controller_values"),
        ("probe_read", "proxy_admin_slot"),
        ("role_holder", "PROPOSER_ROLE"),
        ("role_holder", "0x" + "A" * 64),
        ("role_holder", ADDR(7)),
        ("role_holder", None),
        ("safe_signer", "controller_values"),
        ("safe_signer", "0x" + "0" * 64),
        ("safe_signer", None),
    ],
)
def test_anchor_chain_link_detail_is_a_closed_set_per_kind(kind, detail):
    """The detail is the W3 source or the identity the link was read under —
    never free text, never another kind's token (invariant 2)."""
    link = {"from": ADDR(1), "address": ADDR(2), "kind": kind, "detail": detail}
    evidence = {
        "direction": "d1",
        "source": "controller_values",
        "via": ADDR(1),
        "via_transitive": True,
        "anchor_chain": {
            "links": [link],
            "anchor_address": ADDR(2),
            "anchor_kind": "member",
            "anchor_rule": "w5_human",
        },
    }
    with pytest.raises(ValueError):
        gate._validate_evidence("w3_control", evidence)


@pytest.mark.parametrize(
    "kind,detail",
    [
        ("owner_or_authority", "controller_values"),
        ("proxy_admin", "proxy_admin_slot"),
        ("probe_read", "probe"),
        ("role_holder", PROPOSER_ROLE),
        ("safe_signer", ADDR(9)),
    ],
)
def test_anchor_chain_link_detail_accepts_exactly_its_kinds_token(kind, detail):
    link = {"from": ADDR(1), "address": ADDR(2), "kind": kind, "detail": detail}
    evidence = {
        "direction": "d1",
        "source": "controller_values",
        "via": ADDR(1),
        "via_transitive": True,
        "anchor_chain": {
            "links": [link],
            "anchor_address": ADDR(2),
            "anchor_kind": "member",
            "anchor_rule": "w5_human",
        },
    }
    assert gate._validate_evidence("w3_control", evidence) == evidence


def test_role_holder_link_needs_a_proven_role_identity(db_session, protocol):
    """A role nobody proved a preimage for keys nothing (``db/models/roles.py``)."""
    anchor = _anchored_member(db_session, protocol, ADDR(0xC01))
    timelock = _d2_member(db_session, protocol, ADDR(0xC02), controls=anchor)
    safe = _anchored_holder(db_session, protocol, ADDR(0xC03))
    _role_plane(db_session, timelock.address, UNRELATED_ROLE, [safe], role_name="PAUSER_ROLE")

    ward = _contract(db_session, ADDR(0xC05), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id is None


def test_default_admin_role_anchors_on_the_zero_hash_alone(db_session, protocol):
    """DEFAULT_ADMIN_ROLE is the zero word — the one role identity provable
    without a name, so an unnamed plane row still contributes its holders."""
    anchor = _anchored_member(db_session, protocol, ADDR(0xC21))
    registry = _d2_member(db_session, protocol, ADDR(0xC22), controls=anchor)
    admin = _anchored_holder(db_session, protocol, ADDR(0xC23))
    _role_plane(db_session, registry.address, DEFAULT_ADMIN_ROLE, [admin], role_name="DEFAULT_ADMIN_ROLE")

    ward = _contract(db_session, ADDR(0xC24), nominated=protocol.id)
    _caller_gate(db_session, ward, registry.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()

    assert ward.protocol_id == protocol.id
    chain = _d1_witness(db_session, ward, protocol).evidence["anchor_chain"]
    assert chain["links"][0]["kind"] == "role_holder"
    assert chain["links"][0]["detail"] == DEFAULT_ADMIN_ROLE


def test_withheld_holder_set_contributes_no_link(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0xC11))
    timelock = _d2_member(db_session, protocol, ADDR(0xC12), controls=anchor)
    db_session.add(
        RoleHolderPlane(
            chain_id=1,
            registry_address=timelock.address,
            role_hash=PROPOSER_ROLE,
            holders=None,
            holders_basis="not_determined",
            holder_set_exhaustive="not_determined",
            as_of_block=None,
            as_of_block_hash=None,
            cursor_first_indexed_block=None,
            cursor_first_indexed_block_basis="not_determined",
            cursor_last_indexed_block=None,
            cursor_enrollment_bases={},
            cursor_page_completeness="not_determined",
            coverage="partial",
            role_name="PROPOSER_ROLE",
            role_name_basis="keccak_preimage",
            candidate_count=None,
            unconfirmed_candidate_count=None,
            fold_chain_disagreements=None,
        )
    )
    db_session.flush()
    ward = _contract(db_session, ADDR(0xC13), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id is None


# ---------------------------------------------------------------------------
# (b) the Safe-direct shape ADMITS — no timelock hop
# ---------------------------------------------------------------------------


def test_anchored_safe_admits_its_direct_wards(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0xD01))
    safe = _d2_member(db_session, protocol, ADDR(0xD02), controls=anchor)
    # The Safe's own signer set. The signer is itself an independently
    # anchored member — a set-valued link roots nowhere weaker.
    signer = _anchored_holder(db_session, protocol, ADDR(0xD03))
    _principal(db_session, safe, safe.address, resolved_type="safe", details={"owners": [signer]})

    ward = _contract(db_session, ADDR(0xD05), nominated=protocol.id)
    _caller_gate(db_session, ward, safe.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()

    assert ward.protocol_id == protocol.id
    chain = _d1_witness(db_session, ward, protocol).evidence["anchor_chain"]
    assert chain["links"] == [{"from": safe.address, "address": signer, "kind": "safe_signer", "detail": safe.address}]
    assert chain["anchor_kind"] == "member"


# ---------------------------------------------------------------------------
# (c) the EndpointV2 shape REFUSES — owner roots outside the perimeter
# ---------------------------------------------------------------------------


def test_controller_whose_owner_roots_outside_the_perimeter_is_not_transitive(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0xE01))
    endpoint = _d2_member(db_session, protocol, ADDR(0xE02), controls=anchor)
    _caller_gate(db_session, endpoint, ADDR(0xE03))  # a governance address this protocol never resolved

    ward = _contract(db_session, ADDR(0xE04), nominated=protocol.id)
    _caller_gate(db_session, ward, endpoint.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()

    assert ward.protocol_id is None, "a D2 entry may not license the controller's other wards"
    assert (
        gate._via_transitivity(db_session, protocol_id=protocol.id, via_address=endpoint.address, chain_key="ethereum")
        is None
    )
    # The D2 membership itself is untouched.
    assert endpoint.protocol_id == protocol.id
    assert ("w3_control", "d2") in _witness_rules(db_session, endpoint, protocol)


def test_foreign_link_refuses_the_whole_controller_set(db_session, protocol):
    """Positive counterevidence beats a rooted sibling link: a controller set
    naming another protocol's member roots nothing."""
    other = Protocol(name=f"other-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.flush()

    anchor = _anchored_member(db_session, protocol, ADDR(0xE11))
    timelock = _d2_member(db_session, protocol, ADDR(0xE12), controls=anchor)
    safe = _anchored_holder(db_session, protocol, ADDR(0xE13))
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])
    foreign = _contract(db_session, ADDR(0xE15), protocol_id=other.id, nominated=other.id)
    _caller_gate(db_session, timelock, foreign.address, controller_id="secondOwner")

    ward = _contract(db_session, ADDR(0xE16), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id is None


# ---------------------------------------------------------------------------
# (d) the shared-ops-Safe shape REFUSES — signers visible only via the Safe
# ---------------------------------------------------------------------------


def test_shared_ops_safe_whose_signers_root_only_through_itself_is_refused(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0xF01))
    ops_safe = _d2_member(db_session, protocol, ADDR(0xF02), controls=anchor)
    signer = ADDR(0xF03)
    # The signer set as the analysis of the ANCHORED member resolved it: the
    # only place these signers appear is the Safe itself.
    _principal(db_session, anchor, ops_safe.address, resolved_type="safe", details={"owners": [signer]})

    ward = _contract(db_session, ADDR(0xF04), nominated=protocol.id)
    _caller_gate(db_session, ward, ops_safe.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()

    assert ward.protocol_id is None, "a shared operator must not license every ward it also controls"
    assert (
        gate._via_transitivity(db_session, protocol_id=protocol.id, via_address=ops_safe.address, chain_key="ethereum")
        is None
    )


def test_sibling_safes_sharing_a_signer_do_not_launder_each_other(db_session, protocol):
    """Two D2-only Safes of the same anchored member, one signer in common.

    The shared signer is a perimeter principal of the member through EITHER
    Safe, so a set-valued link allowed to root at a perimeter principal would
    let S1's wards in on S2's affiliation. A signer set roots only at an
    anchored member, and a ``safe_owner`` fact anchors nothing at all."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x1201))
    safe_one = _d2_member(db_session, protocol, ADDR(0x1202), controls=anchor)
    safe_two = _d2_member(db_session, protocol, ADDR(0x1203), controls=anchor)
    shared_signer = ADDR(0x1204)
    for safe in (safe_one, safe_two):
        _principal(
            db_session, anchor, safe.address, resolved_type="safe", details={"owners": [shared_signer, ADDR(0x1205)]}
        )
        _principal(
            db_session, safe, safe.address, resolved_type="safe", details={"owners": [shared_signer, ADDR(0x1205)]}
        )

    ward = _contract(db_session, ADDR(0x1206), nominated=protocol.id)
    _caller_gate(db_session, ward, safe_one.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()

    assert ward.protocol_id is None
    for safe in (safe_one, safe_two):
        assert (
            gate._via_transitivity(db_session, protocol_id=protocol.id, via_address=safe.address, chain_key="ethereum")
            is None
        )
    # The signer is a perimeter principal for the §3.3 ladder, which reads
    # safe_owner facts on purpose — only the anchor chain refuses them.
    assert gate._perimeter_fact(db_session, protocol_id=protocol.id, address=shared_signer) is not None
    assert (
        gate._perimeter_anchor(db_session, protocol_id=protocol.id, address=shared_signer, blocked=frozenset()) is None
    )


def test_set_valued_link_may_not_enter_on_a_d2_only_member(db_session, protocol):
    """The element of a set-valued link must itself be an independently
    anchored member — the recursion is bound to the same test as the direct
    branch, so a holder that is only a D2 entry cannot walk on to an anchor
    through its own owner."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x1501))
    timelock = _d2_member(db_session, protocol, ADDR(0x1502), controls=anchor)
    # The role holder is a member, but by a D2 entry only.
    holder = _d2_member(db_session, protocol, ADDR(0x1503), controls=anchor)
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [holder.address])
    # ...and its own singleton owner WOULD anchor, were the element eligible.
    governor = ADDR(0x1504)
    _caller_gate(db_session, holder, governor)
    _caller_gate(db_session, anchor, governor, controller_id="governor")

    ward = _contract(db_session, ADDR(0x1505), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id is None
    assert (
        gate._via_transitivity(db_session, protocol_id=protocol.id, via_address=timelock.address, chain_key="ethereum")
        is None
    )
    # The same owner still anchors the holder's OWN wards: only the set-valued
    # hop is bound, not the singleton one.
    holder_ward = _contract(db_session, ADDR(0x1506), nominated=protocol.id)
    _caller_gate(db_session, holder_ward, holder.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(holder_ward.id,)))
    db_session.flush()
    assert holder_ward.protocol_id == protocol.id


def test_set_valued_link_may_not_root_at_a_perimeter_principal(db_session, protocol):
    """R1: 1-of-N membership of an authority set is affiliation, not control.
    The same shape admits the moment the holder is an anchored member."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x1301))
    timelock = _d2_member(db_session, protocol, ADDR(0x1302), controls=anchor)
    holder = ADDR(0x1303)
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [holder])
    # A textbook perimeter principal: it caller-gates the W5-anchored member.
    _caller_gate(db_session, anchor, holder, controller_id="governor")

    ward = _contract(db_session, ADDR(0x1304), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id is None

    # Same facts, holder promoted to an independently anchored member.
    promoted = _anchored_member(db_session, protocol, ADDR(0x1305))
    _role_plane(db_session, timelock.address, DEFAULT_ADMIN_ROLE, [promoted.address])
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id == protocol.id
    chain = _d1_witness(db_session, ward, protocol).evidence["anchor_chain"]
    assert chain["anchor_kind"] == "member"
    assert chain["anchor_address"] == promoted.address


def test_singleton_link_still_roots_at_a_perimeter_principal(db_session, protocol):
    """The arity split cuts only the SET-valued kinds: a single resolved
    owner/authority is one named authority, and still roots at a §3.3
    perimeter principal."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x1401))
    registry = _d2_member(db_session, protocol, ADDR(0x1402), controls=anchor)
    owner = ADDR(0x1403)
    _caller_gate(db_session, registry, owner)
    _caller_gate(db_session, anchor, owner, controller_id="governor")

    ward = _contract(db_session, ADDR(0x1404), nominated=protocol.id)
    _caller_gate(db_session, ward, registry.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id == protocol.id
    chain = _d1_witness(db_session, ward, protocol).evidence["anchor_chain"]
    assert chain["links"][0]["kind"] == "owner_or_authority"
    assert chain["anchor_kind"] == "perimeter_principal"


def test_anchor_resting_on_the_controller_itself_is_refused_then_admitted_independently(db_session, protocol):
    """The dev-DB bootstrap shape: the controller's own owner looks anchored,
    but the member anchoring it is a member only BECAUSE of the controller
    (W2 implementation-of-the-controller). Nothing may be licensed by its own
    D2 entry — the same facts admit only once an independent anchor exists."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x1101))
    registry = _d2_member(db_session, protocol, ADDR(0x1102), controls=anchor)
    impl = _contract(db_session, ADDR(0x1103), nominated=protocol.id)
    registry.implementation = impl.address
    db_session.flush()
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(impl.id,)))
    db_session.flush()
    assert ("w2_structural", None) in _witness_rules(db_session, impl, protocol)

    gov = ADDR(0x1104)
    _caller_gate(db_session, registry, gov)  # the registry's own owner
    _caller_gate(db_session, impl, gov, controller_id="ownerOnImpl")  # ...seen only on its own impl

    ward = _contract(db_session, ADDR(0x1105), nominated=protocol.id)
    _caller_gate(db_session, ward, registry.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id is None
    assert (
        gate._via_transitivity(db_session, protocol_id=protocol.id, via_address=registry.address, chain_key="ethereum")
        is None
    )

    # One independent observation of the same owner settles it.
    _caller_gate(db_session, anchor, gov, controller_id="governor")
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id == protocol.id
    assert _d1_witness(db_session, ward, protocol).evidence["anchor_chain"]["anchor_address"] == gov


# ---------------------------------------------------------------------------
# (e) chain break revokes exactly the dependents
# ---------------------------------------------------------------------------


def _timelock_shape(db_session, protocol, base):
    anchor = _anchored_member(db_session, protocol, ADDR(base + 1))
    timelock = _d2_member(db_session, protocol, ADDR(base + 2), controls=anchor)
    safe = _anchored_holder(db_session, protocol, ADDR(base + 3))
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])
    ward = _contract(db_session, ADDR(base + 5), nominated=protocol.id)
    _caller_gate(db_session, ward, timelock.address)
    proxy = _contract(db_session, ADDR(base + 6), nominated=protocol.id, implementation=ward.address)
    independent = _anchored_member(db_session, protocol, ADDR(base + 7))
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id, proxy.id)))
    db_session.flush()
    assert ward.protocol_id == protocol.id and proxy.protocol_id == protocol.id
    return anchor, timelock, safe, ward, proxy, independent


def test_role_holder_change_revokes_the_dependent_chain(db_session, protocol):
    anchor, timelock, safe, ward, proxy, independent = _timelock_shape(db_session, protocol, 0x2100)

    plane = db_session.get(RoleHolderPlane, (1, timelock.address, PROPOSER_ROLE))
    replacement = ADDR(0x2199)
    plane.holders = [replacement]
    db_session.flush()

    gate.evaluate(
        db_session,
        gate.FactsDelta(new_edge_addresses=(timelock.address, safe, replacement)),
    )
    db_session.flush()

    assert ward.protocol_id is None, "the D1 witness must fall with its anchor chain"
    assert proxy.protocol_id is None, "and the W2 resting on the ward with it"
    assert independent.protocol_id == protocol.id, "a member with an independent witness is untouched"
    assert anchor.protocol_id == protocol.id
    assert timelock.protocol_id == protocol.id, "the controller's own D2 entry is unaffected"


def test_anchoring_member_demotion_revokes_the_dependent_chain(db_session, protocol):
    anchor, timelock, safe, ward, proxy, independent = _timelock_shape(db_session, protocol, 0x2200)

    for row in db_session.query(ContractMembershipWitness).filter_by(contract_id=anchor.id):
        gate.revoke_witness(db_session, row, reason="test_seed_revoked")
    gate.demote_member(db_session, contract=anchor, reason="test")
    db_session.flush()

    gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(anchor.address,)))
    db_session.flush()

    assert ward.protocol_id is None
    assert proxy.protocol_id is None
    assert independent.protocol_id == protocol.id


def test_anchor_link_address_reaches_the_revocation_frontier(db_session, protocol):
    """The recorded chain's link — not the witness's own via — is what changed."""
    _anchor, timelock, safe, ward, _proxy, _independent = _timelock_shape(db_session, protocol, 0x2300)
    assert gate._vias_citing_evidence_address(db_session, [safe]) == {timelock.address}
    chain = _d1_witness(db_session, ward, protocol).evidence["anchor_chain"]
    assert gate._vias_citing_evidence_address(db_session, [chain["anchor_address"]]) == {timelock.address}
    assert gate._vias_citing_evidence_address(db_session, [ADDR(0x23FF)]) == set()


def test_foreign_promotion_of_a_published_anchor_revokes_in_the_same_run(db_session, protocol):
    """A promotion is counterevidence for STANDING witnesses, not only recall.

    Once another protocol claims the address a published anchor chain cites,
    the link is proven foreign and the transitivity it carried is gone. The
    same ``evaluate`` that promotes must revoke the dependent D1 and demote the
    member it was holding up — waiting for reconcile leaves a member with no
    verified witness (invariant 8)."""
    _anchor, timelock, safe, ward, proxy, independent = _timelock_shape(db_session, protocol, 0x2400)
    other = Protocol(name=f"claimant-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.flush()

    # The anchor address is a row the OTHER protocol is about to promote.
    claimed = db_session.query(Contract).filter(func.lower(Contract.address) == safe).one()
    claimed.protocol_id = None
    claimed.nominated_protocol_id = other.id
    other_anchor = _anchored_member(db_session, other, ADDR(0x2490))
    _caller_gate(db_session, other_anchor, claimed.address, controller_id="operator")
    db_session.flush()

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(claimed.id,)))
    db_session.flush()

    assert claimed.protocol_id == other.id, "the other protocol's own edge admits it"
    assert claimed.id in result.promoted_contract_ids
    assert ward.protocol_id is None, "the dependent D1 must fall in the promoting run"
    assert ward.id in result.demoted_contract_ids
    assert proxy.protocol_id is None
    assert independent.protocol_id == protocol.id
    assert timelock.protocol_id == protocol.id


def test_api_level_new_member_delta_seeds_the_revocation_stratum(db_session, protocol):
    """The same shape reached through the public delta a caller passes with no
    edge addresses at all (``perimeter.py`` promotes and reports ids)."""
    _anchor, _timelock, safe, ward, _proxy, _independent = _timelock_shape(db_session, protocol, 0x2500)
    other = Protocol(name=f"claimant-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.flush()
    claimed = db_session.query(Contract).filter(func.lower(Contract.address) == safe).one()
    claimed.protocol_id = other.id
    db_session.flush()

    gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(claimed.id,)))
    db_session.flush()
    assert ward.protocol_id is None


def test_foreign_promotion_breaks_a_d2_exclusive_via_in_the_same_run(db_session, protocol):
    """The ``d2_exclusive`` arm publishes no anchor chain and keys its
    dependents on the controller, so a promoted row reaches them only through
    its own controllers. A controller whose observed control set has just
    widened past the protocol is no longer exclusive, and everything it
    licensed must fall in the promoting run (invariant 8)."""
    # Built without ``_d2_member``: exclusivity needs the controller's whole
    # observed ward set inside the protocol, so this shape carries no
    # unclaimed ward.
    controller = _contract(db_session, ADDR(0x2602), nominated=protocol.id)
    anchor = _anchored_member(db_session, protocol, ADDR(0x2601))
    contested = _anchored_member(db_session, protocol, ADDR(0x2603))
    for subject in (anchor, contested):
        _caller_gate(db_session, subject, controller.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(controller.id,)))
    db_session.flush()
    assert _witness_rules(db_session, controller, protocol) == {("w1_code", None), ("w3_control", "d2")}

    ward = _contract(db_session, ADDR(0x2604), nominated=protocol.id)
    _caller_gate(db_session, ward, controller.address)
    independent = _anchored_member(db_session, protocol, ADDR(0x2605))
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()

    assert ward.protocol_id == protocol.id
    proof = gate._via_transitivity(
        db_session, protocol_id=protocol.id, via_address=controller.address, chain_key="ethereum"
    )
    assert proof is not None
    assert proof.arm == "d2_exclusive"
    assert "anchor_chain" not in (_d1_witness(db_session, ward, protocol).evidence or {})

    # Another protocol takes one of the controller's other wards.
    other = Protocol(name=f"claimant-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.flush()
    for row in db_session.query(ContractMembershipWitness).filter_by(contract_id=contested.id):
        gate.revoke_witness(db_session, row, reason="test_handover")
    gate.demote_member(db_session, contract=contested, reason="test_handover")
    contested.nominated_protocol_id = other.id
    other_anchor = _anchored_member(db_session, other, ADDR(0x2690))
    _caller_gate(db_session, other_anchor, contested.address, controller_id="operator")
    db_session.flush()

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(contested.id,)))
    db_session.flush()

    assert contested.protocol_id == other.id
    assert contested.id in result.promoted_contract_ids
    assert (
        gate._via_transitivity(
            db_session, protocol_id=protocol.id, via_address=controller.address, chain_key="ethereum"
        )
        is None
    )
    assert ward.protocol_id is None, "the d2_exclusive dependent must fall in the promoting run"
    assert ward.id in result.demoted_contract_ids
    assert anchor.protocol_id == protocol.id
    assert independent.protocol_id == protocol.id
    assert controller.protocol_id == protocol.id


# ---------------------------------------------------------------------------
# (f) confluence — arrival order does not change the settled state
# ---------------------------------------------------------------------------


def _settled_state(db_session, protocol, base):
    """Membership + witness rules keyed by each row's OFFSET from the fixture
    base, so two independently addressed builds compare directly."""
    state = {}
    for row in db_session.query(Contract).filter(Contract.nominated_protocol_id == protocol.id).all():
        state[int(row.address, 16) - base] = (
            row.protocol_id is not None,
            tuple(sorted(_witness_rules(db_session, row, protocol))),
        )
    return state


def test_two_arrival_orders_settle_identically(db_session, protocol):
    def build(base, chain_first):
        proto = Protocol(name=f"order-{uuid.uuid4().hex[:8]}")
        db_session.add(proto)
        db_session.flush()
        anchor = _anchored_member(db_session, proto, ADDR(base + 1))
        timelock = _d2_member(db_session, proto, ADDR(base + 2), controls=anchor)
        ward = _contract(db_session, ADDR(base + 5), nominated=proto.id)
        _caller_gate(db_session, ward, timelock.address)
        proxy = _contract(db_session, ADDR(base + 6), nominated=proto.id, implementation=ward.address)

        def land_chain():
            safe = _anchored_holder(db_session, proto, ADDR(base + 3))
            _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])
            gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(timelock.address, safe)))

        if chain_first:
            land_chain()
            gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id, proxy.id)))
        else:
            gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id, proxy.id)))
            land_chain()
        db_session.flush()
        return _settled_state(db_session, proto, base)

    chain_first = build(0x3100, True)
    ward_first = build(0x3200, False)
    assert chain_first == ward_first
    assert any(is_member for is_member, _ in chain_first.values())
    assert ("w3_control", "d1") in dict(chain_first)[5][1]


# ---------------------------------------------------------------------------
# (g) §2 overreach family stays refused under the new arm
# ---------------------------------------------------------------------------


def test_call_target_operand_never_admits_even_with_an_anchor_chain(db_session, protocol):
    """WETH9/Lido/USDC/Seaport/DepositContract shape: the member names the
    external as an integration operand. A live anchor chain elsewhere in the
    protocol changes nothing — ``call_target`` is not a control edge."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x4001))
    timelock = _d2_member(db_session, protocol, ADDR(0x4002), controls=anchor)
    safe = _anchored_holder(db_session, protocol, ADDR(0x4003))
    _role_plane(db_session, timelock.address, PROPOSER_ROLE, [safe])

    weth9 = _contract(db_session, ADDR(0x4005), nominated=protocol.id)
    db_session.add(
        ControllerValue(
            contract_id=anchor.id,
            controller_id="nativeWrapper",
            value=weth9.address,
            authority_provenance="call_target",
        )
    )
    # The external's own owner is this protocol's timelock only in the
    # not-determined sense: nothing resolved it.
    db_session.flush()

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(weth9.id,)))
    db_session.flush()
    assert weth9.protocol_id is None


def test_null_provenance_controller_never_becomes_an_anchor_link(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0x4101))
    timelock = _d2_member(db_session, protocol, ADDR(0x4102), controls=anchor)
    rooted = ADDR(0x4103)
    _principal(db_session, anchor, rooted, resolved_type="eoa")
    db_session.add(ControllerValue(contract_id=timelock.id, controller_id="endpoint", value=rooted))
    db_session.flush()

    links = gate._own_controller_links(db_session, protocol_id=protocol.id, controller=timelock)
    assert all(link.address != rooted for link in links)
