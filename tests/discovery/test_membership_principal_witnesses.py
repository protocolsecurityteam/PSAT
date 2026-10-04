"""Principal-edge and member-factory admission.

The recall gap these close is the dev DB's own shape: a protocol's governance
components are resolved as ``FunctionPrincipal`` rows on member functions, not
as ``ControllerValue`` rows on the component, so the old timelock and the
contracts its principals control held no admitting witness at all.

Both new arms rest on the independent anchoring discipline: a principal fact hosted only
on a W3-D2 entry (the EndpointV2 shape) licenses nothing, because the D2 entry
itself is non-transitive.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from db.models import (
    WITNESS_RULE_W3_CONTROL,
    WITNESS_RULE_W4_FACTORY,
    Contract,
    ContractCreationWitness,
    ContractProbeAttempt,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Protocol,
)
from services.discovery import membership_gate as gate
from services.discovery.membership_gate import readers
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]


@pytest.fixture()
def protocol(db_session):
    row = Protocol(name=f"principal-{uuid.uuid4().hex[:10]}")
    db_session.add(row)
    db_session.flush()
    return row


def _contract(db_session, address, *, protocol_id=None, nominated=None, chain="ethereum", code=True, factory=None):
    row = Contract(address=address.lower(), chain=chain, protocol_id=protocol_id, nominated_protocol_id=nominated)
    db_session.add(row)
    db_session.flush()
    if code:
        db_session.add(
            ContractCreationWitness(
                chain_id=1,
                address=row.address,
                code_probe_block=1000,
                code_absent_at_probe=False,
                creation_factory=factory.lower() if factory else None,
            )
        )
        db_session.flush()
    return row


def _anchored_member(db_session, protocol, address, *, factory=None):
    """A member whose admitting witness rests on no via-fact at all (W5) — the
    only kind that anchors outright."""
    row = _contract(db_session, address, protocol_id=protocol.id, nominated=protocol.id, factory=factory)
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="admin", asserted_at=datetime(2026, 8, 25, tzinfo=timezone.utc)),
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


def _probe_read(db_session, subject, value):
    """The probe read of a governance getter — the derivation a W3-D2
    witness rests on (``W3_D2_SOURCES``); a bare caller gate is not one."""
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
    """The subject's resolved owner/authority on both derivations the gate
    reads: the static caller-gate row and the probe read that admits under D2."""
    _probe_read(db_session, subject, value)
    db_session.add(
        ControllerValue(
            contract_id=subject.id,
            controller_id=controller_id,
            value=value.lower(),
            authority_provenance="caller_gate",
        )
    )
    db_session.flush()


def _unclaimed_ward(db_session, controller):
    """A row the controller is observed to control that no protocol claims —
    every D2 fixture carries one so the pre-existing exclusivity arm cannot
    stand in for the rule under test, and a refusal is a real refusal."""
    row = Contract(address=ADDR(int(controller.address, 16) + 0x800000), chain="ethereum")
    db_session.add(row)
    db_session.flush()
    _caller_gate(db_session, row, controller.address)
    return row


def _d2_only_member(db_session, protocol, address, *, controls):
    """The EndpointV2 shape: a row that entered ONLY as a resolved controller
    of a member (W3-D2), so it anchors nothing."""
    row = _contract(db_session, address, nominated=protocol.id)
    _caller_gate(db_session, controls, row.address)
    _unclaimed_ward(db_session, row)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(row.id,)))
    db_session.flush()
    assert row.protocol_id == protocol.id, "fixture: the D2 controller must have entered as a member"
    assert {rule for rule, _ in _rules(db_session, row, protocol)} == {"w1_code", WITNESS_RULE_W3_CONTROL}
    assert _rules(db_session, row, protocol) >= {(WITNESS_RULE_W3_CONTROL, "d2")}
    return row


AUTHORITY_PATH = ["enumerable_role_store"]
#: The resolver derived this caller set by enumerating a param-keyed mapping —
#: membership of a mapping the contract's own writers populate, not authority.


def _claim(claim_id, tier="standard_exact", **witness):
    return {"claim_id": claim_id, "tier": tier, "witness": witness}


ADMIN_CLAIMS = [_claim("ownership.transfer")]


def _principal(
    db_session,
    host,
    address,
    *,
    resolved_type=None,
    details=None,
    name="admin",
    selector=None,
    resolver_path=AUTHORITY_PATH,
    claims=ADMIN_CLAIMS,
):
    fn = EffectiveFunction(
        contract_id=host.id,
        function_name=f"{name}-{uuid.uuid4().hex[:6]}",
        selector=selector,
        claims=[dict(claim) for claim in claims] if claims is not None else None,
    )
    db_session.add(fn)
    db_session.flush()
    merged = dict(details or {})
    if resolver_path is not None:
        merged["resolver_path"] = list(resolver_path)
    row = FunctionPrincipal(
        function_id=fn.id, address=address.lower(), resolved_type=resolved_type, details=merged or None
    )
    db_session.add(row)
    db_session.flush()
    return row


def _rules(db_session, contract, protocol):
    return {
        (w.rule, (w.evidence or {}).get("direction"))
        for w in gate.active_witnesses(db_session, contract_id=contract.id, protocol_id=protocol.id)
    }


def _admitting_rules(db_session, contract, protocol):
    return {rule for rule, _ in _rules(db_session, contract, protocol) if rule != "w1_code"}


def _witness(db_session, contract, protocol, rule, direction=None):
    for w in gate.active_witnesses(db_session, contract_id=contract.id, protocol_id=protocol.id):
        if w.rule == rule and (direction is None or (w.evidence or {}).get("direction") == direction):
            return w
    raise AssertionError(f"contract {contract.id} holds no active {rule}/{direction} witness")


# ---------------------------------------------------------------------------
# Evidence shapes (constructor-built, round-trip validated)
# ---------------------------------------------------------------------------


def _fact(**overrides):
    base = {
        "kind": "function_principal",
        "function_principal_id": 5,
        "function_id": 9,
        "member_contract_id": 11,
        "member_address": ADDR(0x11),
        "resolved_type": "timelock",
        "safe_address": None,
    }
    base.update(overrides)
    return base


def test_w4_factory_evidence_round_trips():
    evidence = gate.w4_factory_evidence(
        factory_address=ADDR(0x55), factory_member_contract_id=3, chain_id=1, creation_tx_hash=None
    )
    assert gate._validate_evidence(WITNESS_RULE_W4_FACTORY, evidence) == evidence


# ---------------------------------------------------------------------------
# (a) D2-principal — the old-timelock shape
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# (b) D1-principal — the AtomicQueue shape, and its authority cascade
# ---------------------------------------------------------------------------


def test_owner_that_is_a_member_principal_admits_and_cascades(db_session, protocol):
    """AtomicQueue: its owner EOA is a resolved principal of an anchored
    member, so the queue admits on W3-D1 — and the row the queue in turn
    controls admits behind it."""
    member = _anchored_member(db_session, protocol, ADDR(0x2000))
    owner_eoa = ADDR(0x2001)
    _principal(db_session, member, owner_eoa, resolved_type="eoa")

    queue = _contract(db_session, ADDR(0x2002), nominated=protocol.id)
    _caller_gate(db_session, queue, owner_eoa)
    ward = _contract(db_session, ADDR(0x2003), nominated=protocol.id)
    _caller_gate(db_session, ward, queue.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(queue.id, ward.id)))
    db_session.flush()

    assert queue.protocol_id == protocol.id
    witness = _witness(db_session, queue, protocol, WITNESS_RULE_W3_CONTROL, "d1")
    assert witness.via_address == owner_eoa.lower()
    assert witness.evidence["principal_fact"]["member_contract_id"] == member.id
    assert witness.evidence["principal_fact"]["kind"] == "function_principal"
    # The cascade: the queue is now an anchored member, so its own ward admits.
    assert ward.protocol_id == protocol.id


def test_d1_via_controlling_a_foreign_row_is_refused(db_session, protocol):
    """Shared-operator counterevidence: an operator
    observed controlling a row that provably belongs elsewhere licenses
    nothing here."""
    other = Protocol(name=f"other-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.flush()
    member = _anchored_member(db_session, protocol, ADDR(0x2200))
    operator = ADDR(0x2201)
    _principal(db_session, member, operator, resolved_type="eoa")
    foreign = _contract(db_session, ADDR(0x2202), protocol_id=other.id, nominated=other.id)
    _caller_gate(db_session, foreign, operator)

    subject = _contract(db_session, ADDR(0x2203), nominated=protocol.id)
    _caller_gate(db_session, subject, operator)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(subject.id,)))
    db_session.flush()
    assert subject.protocol_id is None


# ---------------------------------------------------------------------------
# (c) Non-transitivity — a principal hosted only on a D2-only member admits NOTHING
# ---------------------------------------------------------------------------


def test_the_same_principals_admit_once_an_anchoring_member_hosts_them(db_session, protocol):
    """Control for the refusal above: the fact, not the row, is what changes."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x3100))
    endpoint = _d2_only_member(db_session, protocol, ADDR(0x3101), controls=anchor)
    controller = _contract(db_session, ADDR(0x3102), nominated=protocol.id)
    _principal(db_session, endpoint, controller.address, resolved_type="timelock")
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(controller.id,)))
    db_session.flush()
    assert controller.protocol_id is None

    _principal(db_session, anchor, controller.address, resolved_type="timelock")
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(controller.id,)))
    db_session.flush()
    assert controller.protocol_id == protocol.id
    assert _witness(db_session, controller, protocol, WITNESS_RULE_W3_CONTROL, "d2").via_address == anchor.address


# ---------------------------------------------------------------------------
# Revocation — the hosting member's demotion cascades
# ---------------------------------------------------------------------------


def test_hosting_member_demotion_revokes_and_cascades(db_session, protocol):
    member = _anchored_member(db_session, protocol, ADDR(0x4000))
    timelock = _contract(db_session, ADDR(0x4001), nominated=protocol.id)
    _principal(db_session, member, timelock.address, resolved_type="timelock")
    owner_eoa = ADDR(0x4002)
    _principal(db_session, member, owner_eoa, resolved_type="eoa")
    subject = _contract(db_session, ADDR(0x4003), nominated=protocol.id)
    _caller_gate(db_session, subject, owner_eoa)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(timelock.id, subject.id)))
    db_session.flush()
    assert timelock.protocol_id == protocol.id and subject.protocol_id == protocol.id

    for row in gate.active_witnesses(db_session, contract_id=member.id, protocol_id=protocol.id):
        gate.revoke_witness(db_session, row, reason="test_demotion")
    gate.demote_member(db_session, contract=member, reason="test_demotion")
    db_session.flush()

    gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(member.address,)))
    db_session.flush()

    assert timelock.protocol_id is None, "the D2-principal witness rests on the demoted host"
    assert subject.protocol_id is None, "the D1-principal proof rests on the same host"
    assert _admitting_rules(db_session, timelock, protocol) == set()
    assert _admitting_rules(db_session, subject, protocol) == set()


def test_dropping_the_principal_row_revokes_the_witness(db_session, protocol):
    """The FunctionPrincipal rewrite path: a re-analysis that no longer
    resolves the principal must not leave the witness standing."""
    member = _anchored_member(db_session, protocol, ADDR(0x4100))
    timelock = _contract(db_session, ADDR(0x4101), nominated=protocol.id)
    row = _principal(db_session, member, timelock.address, resolved_type="timelock")
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(timelock.id,)))
    db_session.flush()
    assert timelock.protocol_id == protocol.id

    before = gate.principal_addresses(db_session, [member.id])
    db_session.delete(row)
    db_session.flush()
    gate.evaluate(
        db_session,
        gate.FactsDelta(new_edge_addresses=tuple(sorted(before | {member.address})), recheck_contract_ids=(member.id,)),
    )
    db_session.flush()
    assert timelock.protocol_id is None


# ---------------------------------------------------------------------------
# (e) overreach family stays refused under both new arms
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# (f) Member-factory admission (owner ruling)
# ---------------------------------------------------------------------------


# CRITICAL: only an anchored (non-D2-only) member factory may license its children.


# ---------------------------------------------------------------------------
# (g) Confluence — arrival order does not change the settled state
# ---------------------------------------------------------------------------


def _settled_state(db_session, proto, base):
    state = {}
    for row in db_session.query(Contract).filter(Contract.nominated_protocol_id == proto.id).all():
        state[int(row.address, 16) - base] = (
            row.protocol_id is not None,
            tuple(sorted(_rules(db_session, row, proto))),
        )
    return state


def test_principal_arms_settle_identically_across_arrival_orders(db_session):
    def build(base, principals_first):
        proto = Protocol(name=f"order-{uuid.uuid4().hex[:8]}")
        db_session.add(proto)
        db_session.flush()
        anchor = _anchored_member(db_session, proto, ADDR(base + 1))
        timelock = _contract(db_session, ADDR(base + 2), nominated=proto.id)
        owner_eoa = ADDR(base + 3)
        ward = _contract(db_session, ADDR(base + 4), nominated=proto.id)
        _caller_gate(db_session, ward, owner_eoa)
        # The spawn hangs off the ward, which enters on W3-D1 — a D2 entry
        # (the timelock) anchors nothing, factory lineage included.
        spawn = _contract(db_session, ADDR(base + 5), nominated=proto.id, factory=ward.address)

        def land_principals():
            _principal(db_session, anchor, timelock.address, resolved_type="timelock")
            _principal(db_session, anchor, owner_eoa, resolved_type="eoa")
            gate.evaluate(
                db_session,
                gate.FactsDelta(new_edge_addresses=(timelock.address, owner_eoa), recheck_contract_ids=(anchor.id,)),
            )

        def land_candidates():
            gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(timelock.id, ward.id, spawn.id)))

        if principals_first:
            land_principals()
            land_candidates()
        else:
            land_candidates()
            land_principals()
        db_session.flush()
        return _settled_state(db_session, proto, base)

    principals_first = build(0x7100, True)
    candidates_first = build(0x7200, False)
    assert principals_first == candidates_first
    assert all(is_member for is_member, _ in principals_first.values())
    assert (WITNESS_RULE_W4_FACTORY, None) in dict(principals_first)[5][1]


def test_settling_is_idempotent_under_the_principal_arms(db_session, protocol):
    """A second evaluation over unchanged evidence must promote and demote
    nothing. A non-monotone transitivity arm shows up here first: it makes a
    row oscillate between promoted and demoted instead of settling."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x7300))
    timelock = _contract(db_session, ADDR(0x7301), nominated=protocol.id)
    _principal(db_session, anchor, timelock.address, resolved_type="timelock")
    owner_eoa = ADDR(0x7302)
    _principal(db_session, anchor, owner_eoa, resolved_type="eoa")
    ward = _contract(db_session, ADDR(0x7303), nominated=protocol.id)
    _caller_gate(db_session, ward, owner_eoa)
    spawn = _contract(db_session, ADDR(0x7304), nominated=protocol.id, factory=ward.address)

    ids = (timelock.id, ward.id, spawn.id)
    first = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=ids))
    db_session.flush()
    assert set(first.promoted_contract_ids) == set(ids)

    second = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=ids))
    db_session.flush()
    assert second.promoted_contract_ids == ()
    assert second.demoted_contract_ids == ()
    assert all(session_row.protocol_id == protocol.id for session_row in (timelock, ward, spawn))


def test_losing_the_anchoring_witness_without_demotion_still_cascades(db_session, protocol):
    """The drift shape reconcile caught on the dev-DB re-earn: a member keeps
    membership on a W3-D2 witness while the W3-D1 witness that made it ANCHOR
    is revoked. Everything resting on its anchoring — factory lineage,
    principal-keyed W3 — must fall with it."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x8000))
    owner_eoa = ADDR(0x8001)
    _principal(db_session, anchor, owner_eoa, resolved_type="eoa")

    # The factory enters on BOTH a D1 (anchoring) and a D2 (non-anchoring)
    # witness, so losing the D1 leaves it a member that no longer anchors.
    factory = _contract(db_session, ADDR(0x8002), nominated=protocol.id)
    _caller_gate(db_session, factory, owner_eoa)
    _caller_gate(db_session, anchor, factory.address)
    _unclaimed_ward(db_session, factory)
    child = _contract(db_session, ADDR(0x8003), nominated=protocol.id, factory=factory.address)
    grandchild = _contract(db_session, ADDR(0x8004), nominated=protocol.id, factory=child.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(factory.id, child.id, grandchild.id)))
    db_session.flush()
    assert factory.protocol_id == protocol.id
    assert _rules(db_session, factory, protocol) >= {
        (WITNESS_RULE_W3_CONTROL, "d1"),
        (WITNESS_RULE_W3_CONTROL, "d2"),
    }
    assert child.protocol_id == protocol.id and grandchild.protocol_id == protocol.id

    db_session.query(FunctionPrincipal).filter(FunctionPrincipal.address == owner_eoa.lower()).delete(
        synchronize_session=False
    )
    db_session.flush()
    gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(anchor.address, owner_eoa)))
    db_session.flush()

    assert factory.protocol_id == protocol.id, "the D2 witness still holds — the factory stays a member"
    assert (WITNESS_RULE_W3_CONTROL, "d1") not in _rules(db_session, factory, protocol)
    assert child.protocol_id is None, "a D2-only member anchors no factory lineage"
    assert grandchild.protocol_id is None, "and the cascade follows"


# ---------------------------------------------------------------------------
# (h) Control screen — a principal admits only where its permission grants control
# ---------------------------------------------------------------------------

# Pendle SY on an etherfi teller: ``bulkDeposit`` routes the caller's own deposit; a privileged depositor isn't a
# controller.
DEPOSIT_CLAIMS = [_claim("value_router"), _claim("flow.in", "idiom_structural")]


def test_contract_principal_on_an_operational_function_is_not_admitted(db_session, protocol):
    teller = _anchored_member(db_session, protocol, ADDR(0x9000))
    depositor = _contract(db_session, ADDR(0x9001), nominated=protocol.id)
    _principal(
        db_session, teller, depositor.address, resolved_type="contract", name="bulkDeposit", claims=DEPOSIT_CLAIMS
    )

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(depositor.id,)))
    db_session.flush()

    assert depositor.protocol_id is None
    assert _admitting_rules(db_session, depositor, protocol) == set()


def test_contract_principal_on_a_pause_function_is_admitted(db_session, protocol):
    teller = _anchored_member(db_session, protocol, ADDR(0x9100))
    pauser = _contract(db_session, ADDR(0x9101), nominated=protocol.id)
    row = _principal(
        db_session,
        teller,
        pauser.address,
        resolved_type="contract",
        name="pause",
        claims=[_claim("pause.set", "idiom_structural")],
    )

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(pauser.id,)))
    db_session.flush()

    assert pauser.protocol_id == protocol.id
    witness = _witness(db_session, pauser, protocol, WITNESS_RULE_W3_CONTROL, "d2")
    assert witness.via_address == teller.address
    assert witness.evidence["principal_fact"]["function_principal_id"] == row.id


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param([_claim("flow.out", "policy_derived")], id="control-minted-after-the-gate"),
        pytest.param([_claim("pause.set", "behavioral_observed", effect_verdict_id=7)], id="observed-without-static"),
        pytest.param([_claim("erc20.transfer"), _claim("rate_limit.consume")], id="user-and-fact"),
        pytest.param([], id="no-claims"),
        pytest.param(None, id="claims-not-written"),
    ],
)
def test_a_function_without_static_control_never_admits(db_session, protocol, claims):
    host = _anchored_member(db_session, protocol, ADDR(0x9200))
    candidate = _contract(db_session, ADDR(0x9201), nominated=protocol.id)
    _principal(db_session, host, candidate.address, resolved_type="contract", claims=claims)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate.id,)))
    db_session.flush()

    assert candidate.protocol_id is None


def test_an_observed_claim_keeps_the_static_witness_it_superseded(db_session, protocol):
    """The effects bridge replaces a static claim with its observed one; the carried static tier still admits, so a
    later re-check can't flip on whether the fork ran."""
    host = _anchored_member(db_session, protocol, ADDR(0x9300))
    candidate = _contract(db_session, ADDR(0x9301), nominated=protocol.id)
    observed = _claim("pause.set", "behavioral_observed", effect_verdict_id=7, static_tier="idiom_structural")
    _principal(db_session, host, candidate.address, resolved_type="contract", claims=[observed])

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate.id,)))
    db_session.flush()

    assert candidate.protocol_id == protocol.id


# etherfi's ``pauseUntil`` as the timestamp-latch matcher emits it (pinned in tests/static/test_claims_pause_until.py).
PAUSE_UNTIL_STATIC = _claim(
    "pause.set",
    "idiom_structural",
    kind="pause_flag",
    flags=[{"var": "PAUSABLE_UNTIL_STORAGE_SLOT", "member": "pausedUntil", "latch": "timestamp"}],
    polarity="set",
)


def _pause_until_claims(history: str) -> list:
    """``pauseUntil``'s claims as each analysis leaves them.

    ``fresh``: the static claim alone (a static ``pause.set`` keeps the row out of fork probing). ``observed``: the
    bridge's claim over it. ``reanalysed``: prod's path, where the policy writer carries the old observed-only claim and
    its relinked verdict into the merge beside the new static claim.
    """
    from types import SimpleNamespace
    from typing import Any, cast

    from services.effects.claims_bridge import merge_observed_claims, verdict_to_claim
    from services.effects.config import EFFECT_CLASS_FREEZE_PAUSE, TIER_FORK, VERDICT_PROVEN
    from services.static.claims.types import Claim

    if history == "fresh":
        return [PAUSE_UNTIL_STATIC]
    verdict: Any = SimpleNamespace(
        id=7,
        effect_class=EFFECT_CLASS_FREEZE_PAUSE,
        verdict=VERDICT_PROVEN,
        tier=TIER_FORK,
        behavior_hash="bh",
        current_check_passed=None,
        witness={"pause_effective": True, "auto_expiry": None, "duration_bound_source": "not_determined"},
        observed_residue=None,
    )
    prior: list[Claim] = [cast(Claim, PAUSE_UNTIL_STATIC)]
    if history == "reanalysed":
        observed_only = verdict_to_claim(verdict)
        assert observed_only is not None and "static_tier" not in observed_only["witness"]
        prior.append(observed_only)
    claims = merge_observed_claims(prior, [verdict])
    assert [(c["claim_id"], c["tier"], c["witness"].get("static_tier")) for c in claims] == [
        ("pause.set", "behavioral_observed", "idiom_structural")
    ]
    return list(claims)


@pytest.mark.parametrize("history", ["fresh", "observed", "reanalysed"])
def test_a_contract_principal_on_pause_until_is_admitted(db_session, protocol, history):
    """The guardian Safe on etherfi's ``pauseUntil`` admits through the unchanged rule. Before the static claim existed
    the row was observed-only and admitted nothing."""
    eeth = _anchored_member(db_session, protocol, ADDR(0x9350))
    safe = _contract(db_session, ADDR(0x9351), nominated=protocol.id)
    row = _principal(
        db_session, eeth, safe.address, resolved_type="safe", name="pauseUntil", claims=_pause_until_claims(history)
    )

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(safe.id,)))
    db_session.flush()

    assert safe.protocol_id == protocol.id
    witness = _witness(db_session, safe, protocol, WITNESS_RULE_W3_CONTROL, "d2")
    assert witness.via_address == eeth.address
    assert witness.evidence["principal_fact"]["function_principal_id"] == row.id


def test_an_operational_eoa_principal_licenses_no_perimeter_transitivity(db_session, protocol):
    """The D1 perimeter arm reads the same rows: an EOA depositor isn't a perimeter principal, so the queue it owns
    doesn't admit until the EOA holds a control grant."""
    member = _anchored_member(db_session, protocol, ADDR(0x9400))
    depositor_eoa = ADDR(0x9401)
    _principal(db_session, member, depositor_eoa, resolved_type="eoa", name="bulkDeposit", claims=DEPOSIT_CLAIMS)
    queue = _contract(db_session, ADDR(0x9402), nominated=protocol.id)
    _caller_gate(db_session, queue, depositor_eoa)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(queue.id,)))
    db_session.flush()
    assert queue.protocol_id is None

    _principal(db_session, member, depositor_eoa, resolved_type="eoa", name="pause", claims=[_claim("pause.set")])
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(queue.id,)))
    db_session.flush()
    assert queue.protocol_id == protocol.id
    assert _witness(db_session, queue, protocol, WITNESS_RULE_W3_CONTROL, "d1").evidence["principal_fact"]


def test_teller_policy_rerun_revokes_the_operational_cascade(db_session, protocol, monkeypatch):
    """Pendle witnesses a DB already holds fall on the teller's next policy run: the SY proxy's principal witness,
    then its implementation's W2, then the governance proxy's probe witness, then the governance implementation's W2.
    """
    teller = _anchored_member(db_session, protocol, ADDR(0x9500))
    sy_proxy = _contract(db_session, ADDR(0x9501), nominated=protocol.id)
    sy_impl = _contract(db_session, ADDR(0x9502), nominated=protocol.id)
    governance = _contract(db_session, ADDR(0x9503), nominated=protocol.id)
    governance_impl = _contract(db_session, ADDR(0x9504), nominated=protocol.id)
    sy_proxy.implementation = sy_impl.address
    governance.implementation = governance_impl.address
    _caller_gate(db_session, sy_proxy, governance.address, controller_id="admin")
    _unclaimed_ward(db_session, governance)
    _principal(
        db_session, teller, sy_proxy.address, resolved_type="contract", name="bulkDeposit", claims=DEPOSIT_CLAIMS
    )
    cascade = (sy_proxy, sy_impl, governance, governance_impl)

    with monkeypatch.context() as unscreened:
        unscreened.setattr(readers, "_function_grants_control", lambda _claims: True)
        gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=tuple(row.id for row in cascade)))
        db_session.flush()
    assert all(row.protocol_id == protocol.id for row in cascade)
    assert _witness(db_session, sy_proxy, protocol, WITNESS_RULE_W3_CONTROL, "d2").evidence["source"] == (
        "function_principal"
    )
    assert _witness(db_session, sy_impl, protocol, "w2_structural").via_address == sy_proxy.address
    assert _witness(db_session, governance, protocol, WITNESS_RULE_W3_CONTROL, "d2").evidence["source"] == "probe"
    assert _witness(db_session, governance_impl, protocol, "w2_structural").via_address == governance.address

    gate.evaluate_principal_change(
        db_session,
        contract_id=teller.id,
        addresses=gate.principal_addresses(db_session, [teller.id]),
        context="test_teller_policy_rerun",
    )

    assert teller.protocol_id == protocol.id
    for row in cascade:
        assert row.protocol_id is None, row.address
        assert _admitting_rules(db_session, row, protocol) == set(), row.address
