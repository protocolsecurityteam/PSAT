"""Discovery-worker membership-gate producers (spec §3.3 wire, §3.4 events 1+4).

Covers the deployer-ladder enumeration wire, the worker's gate intake, the
event-1 probe pass, and the chain-enable boot sweep. All wire stubbed at the
transport boundary (``probes.rpc_request`` / ``etherscan.get``) — never the
real network.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select

from db.models import (
    WITNESS_RULE_W1_CODE,
    WITNESS_RULE_W2_STRUCTURAL,
    WITNESS_RULE_W4_DEPLOYER,
    WITNESS_RULE_W6_LLAMA_SEED,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
    Job,
    JobStage,
    JobStatus,
    OpsKv,
    Protocol,
    ProtocolDeployer,
)
from services.clients.rpc import EthCallResult
from services.discovery import deployer_enumeration, probes
from services.discovery import membership_gate as gate
from services.discovery.deployer_enumeration import (
    DEPLOYER_ENUMERATION_CAP,
    enumerate_deployer_creations,
    session_deployer_enumerator,
)
from tests.conftest import ADDR, requires_postgres
from utils.evm import OWNER_SELECTOR
from workers.discovery import (
    ENABLED_CHAINS_SEEN_KEY,
    _gate_intake,
    _register_protocol_deployer,
    run_chain_enable_sweep,
    run_probe_pass,
)

pytestmark = [requires_postgres]

_TX = "0x" + "34" * 32
_ZERO_WORD = "0x" + "0" * 64


def _protocol(session) -> Protocol:
    row = Protocol(name=f"proto-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _contract(
    session,
    address: str,
    *,
    chain: str = "ethereum",
    protocol_id: int | None = None,
    nominated_protocol_id: int | None = None,
    deployer: str | None = None,
    implementation: str | None = None,
    discovery_sources: list[str] | None = None,
) -> Contract:
    row = Contract(
        address=address.lower(),
        chain=chain,
        protocol_id=protocol_id,
        nominated_protocol_id=nominated_protocol_id,
        deployer=deployer,
        implementation=implementation,
        discovery_sources=discovery_sources,
    )
    session.add(row)
    session.flush()
    return row


def _job(session, *, protocol_id: int | None, address: str, request: dict | None = None) -> Job:
    row = Job(
        id=uuid.uuid4(),
        address=address.lower(),
        protocol_id=protocol_id,
        status=JobStatus.processing,
        stage=JobStage.discovery,
        request=request or {"chain": "ethereum"},
    )
    session.add(row)
    session.flush()
    return row


def _seed_w1(session, contract: Contract, protocol_id: int, *, chain_id: int = 1) -> None:
    gate.write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=gate.w1_evidence(chain_id=chain_id, code_probe_block=100),
    )


def _seed_w2(session, contract: Contract, anchor: Contract, protocol_id: int) -> None:
    # The witness row is a claim; promote re-verifies the via-fact against the
    # stored resolution, so the anchor's pointer must actually carry the edge.
    anchor.implementation = contract.address
    session.flush()
    gate.write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=gate.w2_evidence(
            edge_kind="implementation",
            member_contract_id=anchor.id,
            member_address=anchor.address,
            resolved_pointer=contract.address,
        ),
        via_address=anchor.address,
    )


def _stub_txlist(
    monkeypatch,
    txs_by_chain: dict[int, list | Exception],
    internal_by_txhash: dict[str, list | Exception] | None = None,
) -> list[tuple]:
    calls: list[tuple] = []
    internal = internal_by_txhash or {}

    def fake_get(module, action, chain_id, empty_result_ok=False, **params):
        calls.append((module, action, chain_id, params))
        assert module == "account"
        if action == "txlistinternal":
            entry = internal.get(params["txhash"], [])
            if isinstance(entry, Exception):
                raise entry
            return {"result": entry}
        assert action == "txlist"
        entry = txs_by_chain.get(chain_id, [])
        if isinstance(entry, Exception):
            raise entry
        return {"result": entry}

    monkeypatch.setattr(deployer_enumeration.etherscan, "get", fake_get)
    return calls


def _creation_tx(target: str) -> dict:
    return {"to": "", "contractAddress": target, "hash": _TX}


def _call_tx(sender: str, *, tx_hash: str, to: str = "0x" + "aa" * 20, is_error: str = "0") -> dict:
    return {"from": sender, "to": to, "contractAddress": "", "hash": tx_hash, "isError": is_error}


def _create_frame(target: str, factory: str, *, kind: str = "create2", is_error: str = "0") -> dict:
    return {"type": kind, "from": factory, "to": "", "contractAddress": target, "isError": is_error}


def _created_addresses(creations) -> list[str]:
    return sorted({c.address for c in creations})


# ---------------------------------------------------------------------------
# §3.3 ladder wire: enumeration
# ---------------------------------------------------------------------------


def test_enumeration_collects_direct_creations(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _stub_txlist(
        monkeypatch,
        {1: [_creation_tx(ADDR(0x201)), {"to": ADDR(0x999), "contractAddress": ""}, _creation_tx(ADDR(0x202))]},
    )
    created, scope, complete = enumerate_deployer_creations(ADDR(0x200))
    assert _created_addresses(created) == sorted([ADDR(0x201), ADDR(0x202)])
    assert all(c.factory is None and c.chain_id == 1 for c in created)
    assert scope == [1]
    assert complete is True


def test_enumeration_unions_internal_creations_with_factory_attribution(monkeypatch):
    # Etherscan attributes factory-mediated creations to the tx ORIGIN, so the
    # EOA's own sent calls are resolved per-txhash and their CREATE frames
    # union with the direct creations — factory recorded per child.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x260)
    tx_hash = "0x" + "45" * 32
    _stub_txlist(
        monkeypatch,
        {1: [_creation_tx(ADDR(0x261)), _call_tx(eoa, tx_hash=tx_hash, to=ADDR(0x262))]},
        internal_by_txhash={tx_hash: [_create_frame(ADDR(0x263), ADDR(0x262))]},
    )
    created, scope, complete = enumerate_deployer_creations(eoa)
    assert _created_addresses(created) == sorted([ADDR(0x261), ADDR(0x263)])
    assert {c.address: c.factory for c in created} == {ADDR(0x261): None, ADDR(0x263): ADDR(0x262)}
    assert scope == [1]
    assert complete is True


def test_enumeration_internal_only_creation_is_complete(monkeypatch):
    # A purely factory-mediated deployer now has an enumerable history.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x264)
    tx_hash = "0x" + "46" * 32
    _stub_txlist(
        monkeypatch,
        {1: [_call_tx(eoa, tx_hash=tx_hash)]},
        internal_by_txhash={tx_hash: [_create_frame(ADDR(0x265), ADDR(0x266))]},
    )
    created, scope, complete = enumerate_deployer_creations(eoa)
    assert _created_addresses(created) == [ADDR(0x265)]
    assert scope == [1]
    assert complete is True


def test_enumeration_skips_received_failed_and_frameless_txs(monkeypatch):
    # Received txs, reverted txs, failed CREATE frames and call frames are
    # never creations of this EOA; only its own successful calls are resolved.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x267)
    resolved = "0x" + "47" * 32
    _stub_txlist(
        monkeypatch,
        {
            1: [
                _call_tx(ADDR(0x999), tx_hash="0x" + "48" * 32),  # received — not resolved
                _call_tx(eoa, tx_hash="0x" + "49" * 32, is_error="1"),  # reverted — not resolved
                _call_tx(eoa, tx_hash=resolved),
            ]
        },
        internal_by_txhash={
            resolved: [
                {"type": "call", "from": ADDR(0x262), "to": ADDR(0x263), "contractAddress": "", "isError": "0"},
                _create_frame(ADDR(0x268), ADDR(0x262), is_error="1"),
            ]
        },
    )
    created, scope, complete = enumerate_deployer_creations(eoa)
    assert created == []
    assert complete is False  # empty enumeration can never license exclusivity


def test_enumeration_internal_failure_is_incomplete(monkeypatch):
    # EITHER endpoint failing for a chain ⇒ that chain out of scope,
    # incomplete — a half-enumerated chain must never claim completeness.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x269)
    tx_hash = "0x" + "4a" * 32
    _stub_txlist(
        monkeypatch,
        {1: [_creation_tx(ADDR(0x26A)), _call_tx(eoa, tx_hash=tx_hash)]},
        internal_by_txhash={tx_hash: RuntimeError("etherscan down")},
    )
    created, scope, complete = enumerate_deployer_creations(eoa)
    assert created == []
    assert scope == []
    assert complete is False


def test_enumeration_internal_budget_exceeded_is_incomplete(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x26B)
    window = [
        _call_tx(eoa, tx_hash="0x" + f"{n:064x}") for n in range(deployer_enumeration.INTERNAL_RESOLUTION_TX_BUDGET + 1)
    ]
    calls = _stub_txlist(monkeypatch, {1: window})
    created, scope, complete = enumerate_deployer_creations(eoa)
    assert created == []
    assert scope == []
    assert complete is False
    # The budget refusal is decided BEFORE any internal call is spent.
    assert [c for c in calls if c[1] == "txlistinternal"] == []


def test_enumeration_combined_cap_is_incomplete(monkeypatch):
    # The cap applies to the COMBINED direct ∪ internal creation set.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x26C)
    tx_hash = "0x" + "4b" * 32
    frames = [_create_frame(ADDR(0x100000 + n), ADDR(0x262)) for n in range(DEPLOYER_ENUMERATION_CAP - 1)]
    _stub_txlist(
        monkeypatch,
        {1: [_creation_tx(ADDR(0x26D)), _call_tx(eoa, tx_hash=tx_hash)]},
        internal_by_txhash={tx_hash: frames},
    )
    created, scope, complete = enumerate_deployer_creations(eoa)
    assert created == []
    assert scope == []
    assert complete is False


def test_enumeration_cap_exceeded_is_incomplete(monkeypatch):
    # A full txlist window is a truncation, never a complete history — and the
    # truncated chain never enters the recorded scope.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    window = [_creation_tx(ADDR(0x300 + n)) for n in range(3)] + [{"to": ADDR(0x999), "contractAddress": ""}] * (
        DEPLOYER_ENUMERATION_CAP - 3
    )
    _stub_txlist(monkeypatch, {1: window})
    created, scope, complete = enumerate_deployer_creations(ADDR(0x2FF))
    assert complete is False
    assert created == []
    assert scope == []


def test_enumeration_empty_or_failed_is_incomplete(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _stub_txlist(monkeypatch, {1: []})
    assert enumerate_deployer_creations(ADDR(0x210)) == ([], [1], False)
    _stub_txlist(monkeypatch, {1: RuntimeError("etherscan down")})
    assert enumerate_deployer_creations(ADDR(0x210)) == ([], [], False)


def test_enumeration_zero_tx_chain_stays_in_scope(monkeypatch):
    # An enabled chain the EOA never acted on is a COMPLETE (empty) answer,
    # not a failure — it must not bar Class B for the chains it did act on.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    _stub_txlist(monkeypatch, {1: [_creation_tx(ADDR(0x220))], 8453: []})
    created, scope, complete = enumerate_deployer_creations(ADDR(0x221))
    assert _created_addresses(created) == [ADDR(0x220)]
    assert scope == [1, 8453]
    assert complete is True


def test_enumeration_any_enabled_chain_failing_is_incomplete(monkeypatch):
    # EOAs are chain-agnostic: completeness requires every enabled chain's
    # window to come back clean, and the failed chain stays out of scope.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    _stub_txlist(monkeypatch, {1: [_creation_tx(ADDR(0x220))], 8453: RuntimeError("boom")})
    created, scope, complete = enumerate_deployer_creations(ADDR(0x221))
    assert _created_addresses(created) == [ADDR(0x220)]
    assert scope == [1]
    assert complete is False


# ---------------------------------------------------------------------------
# §3.3 ladder wire: registration
# ---------------------------------------------------------------------------


def _seed_stale_w2(session, contract: Contract, former_anchor: Contract, protocol_id: int) -> None:
    """An unrevoked W2 row whose edge no longer holds (the anchor's pointer
    was since rewritten). F1 membership evidence for the Class-B mapping test;
    promotion still requires a witness that VERIFIES — the W4 under test."""
    former_anchor.implementation = contract.address
    session.flush()
    gate.write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=gate.w2_evidence(
            edge_kind="implementation",
            member_contract_id=former_anchor.id,
            member_address=former_anchor.address,
            resolved_pointer=contract.address,
        ),
        via_address=former_anchor.address,
    )
    former_anchor.implementation = None
    session.flush()


def _seed_class_b_shape(db_session, protocol, eoa: str) -> list[Contract]:
    members = []
    for n in (0x230, 0x231):
        anchor = _contract(db_session, ADDR(n + 0x100), protocol_id=protocol.id)
        member = _contract(db_session, ADDR(n), protocol_id=protocol.id, deployer=eoa)
        _seed_w2(db_session, member, anchor, protocol.id)
        members.append(member)
    return members


def test_ladder_wire_registers_class_b_with_scope_and_snapshot(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x240)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    calls = _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members]})

    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)

    assert row is not None and row.trust_class == "B"
    # The evidence names WHAT was enumerated — never a bare complete flag.
    assert row.evidence["enumeration"]["complete"] is True
    assert row.evidence["enumeration"]["chain_ids"] == [1]
    assert sorted(row.evidence["enumeration"]["addresses"]) == sorted(m.address for m in members)
    assert len(calls) == 1


def test_ladder_wire_cap_exceeded_is_class_c_no_row(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x250)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    window = [_creation_tx(m.address) for m in members] + [{"to": ADDR(0x999), "contractAddress": ""}] * (
        DEPLOYER_ENUMERATION_CAP - 2
    )
    _stub_txlist(monkeypatch, {1: window})

    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)

    assert row is None
    assert db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.address == eoa)).first() is None


def test_ladder_wire_foreign_creation_is_class_c(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x260)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members] + [_creation_tx(ADDR(0x999))]})

    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa) is None


def test_ladder_wire_nominates_unknown_creations_and_still_refuses_b(db_session, monkeypatch):
    """2b + F1 pin: a complete enumeration's unknown creation is NOMINATED
    (free recall, queued for probes) — and that bare nomination must NOT count
    as mapped, so Class B still refuses on the very row it just nominated."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x2C0)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    tx_hash = "0x" + "51" * 32
    unknown = ADDR(0x2C1)
    _stub_txlist(
        monkeypatch,
        {1: [_creation_tx(m.address) for m in members] + [_call_tx(eoa, tx_hash=tx_hash, to=ADDR(0x2C2))]},
        internal_by_txhash={tx_hash: [_create_frame(unknown, ADDR(0x2C2))]},
    )
    sink: set[int] = set()

    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa, reprobe_sink=sink) is None
    assert db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.address == eoa)).first() is None

    row = db_session.execute(select(Contract).where(Contract.address == unknown)).scalar_one()
    assert row.protocol_id is None
    assert row.nominated_protocol_id == protocol.id
    assert row.deployer == eoa
    assert row.chain == "ethereum"
    assert row.discovery_sources == [gate.ENUMERATION_SOURCE_TAG]
    assert row.id in sink

    # Idempotent: a re-run neither duplicates the row nor re-nominates.
    sink.clear()
    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa, reprobe_sink=sink) is None
    assert db_session.execute(select(Contract).where(Contract.address == unknown)).scalar_one() is row
    assert row.id not in sink


def test_ladder_wire_member_factory_child_mints_b_with_factory_evidence(db_session, monkeypatch):
    """2a: a creation minted by the protocol's own anchoring MEMBER factory
    counts as mapped (deliberate §3.3 deviation) — Class B mints and the
    evidence records the factory attribution."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x2C4)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    factory = _contract(db_session, ADDR(0x2C5), protocol_id=protocol.id)
    factory_anchor = _contract(db_session, ADDR(0x2C6), protocol_id=protocol.id)
    _seed_w2(db_session, factory, factory_anchor, protocol.id)
    tx_hash = "0x" + "52" * 32
    child = ADDR(0x2C7)
    _stub_txlist(
        monkeypatch,
        {1: [_creation_tx(m.address) for m in members] + [_call_tx(eoa, tx_hash=tx_hash, to=factory.address)]},
        internal_by_txhash={tx_hash: [_create_frame(child, factory.address)]},
    )
    sink: set[int] = set()

    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa, reprobe_sink=sink)

    assert row is not None and row.trust_class == "B"
    assert row.evidence["member_factory_mapped"] == {"count": 1, "factories": [factory.address]}
    assert row.evidence["enumeration"]["factories"] == {child: factory.address}
    assert child in row.evidence["enumeration"]["addresses"]
    # Mapping only: the child is nominated as a candidate, never admitted.
    child_row = db_session.execute(select(Contract).where(Contract.address == child)).scalar_one()
    assert child_row.protocol_id is None
    assert child_row.nominated_protocol_id == protocol.id
    assert child_row.id in sink


def test_fixpoint_enumeration_nominates_and_queues_probes(db_session, monkeypatch):
    """The gate-side wire: a complete enumeration inside the fixpoint's ladder
    stratum nominates unknown creations through the enumerator's ``creations``
    channel and queues them as reprobe candidates."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x2C8)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    candidate = _contract(db_session, ADDR(0x2C9), nominated_protocol_id=protocol.id, deployer=eoa)
    tx_hash = "0x" + "53" * 32
    unknown = ADDR(0x2CA)
    _stub_txlist(
        monkeypatch,
        {
            1: [_creation_tx(m.address) for m in members]
            + [_creation_tx(candidate.address), _call_tx(eoa, tx_hash=tx_hash, to=ADDR(0x2CB))]
        },
        internal_by_txhash={tx_hash: [_create_frame(unknown, ADDR(0x2CB))]},
    )

    result = gate.evaluate(
        db_session,
        gate.FactsDelta(recheck_contract_ids=(candidate.id,)),
        deployer_enumerator=session_deployer_enumerator(db_session),
    )

    row = db_session.execute(select(Contract).where(Contract.address == unknown)).scalar_one()
    assert row.nominated_protocol_id == protocol.id
    assert row.discovery_sources == [gate.ENUMERATION_SOURCE_TAG]
    assert row.id in result.reprobe_contract_ids
    # The unknown creation held no evidence, so Class B stayed refused.
    assert db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.address == eoa)).first() is None


def test_ladder_wire_class_a_skips_enumeration(db_session, monkeypatch):
    from db.models import ControllerValue

    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(0x270), protocol_id=protocol.id)
    # F2: only a member with a non-D2 admitting witness anchors Class A.
    anchor = _contract(db_session, ADDR(0x272), protocol_id=protocol.id)
    _seed_w2(db_session, member, anchor, protocol.id)
    eoa = ADDR(0x271)
    db_session.add(
        ControllerValue(contract_id=member.id, controller_id="owner", value=eoa, authority_provenance="caller_gate")
    )
    db_session.flush()
    calls = _stub_txlist(monkeypatch, {})

    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)

    assert row is not None and row.trust_class == "A"
    assert calls == []


def test_ladder_wire_skips_enumeration_without_sibling_members(db_session, monkeypatch):
    # <2 member rows claim the deployer: Class B is unreachable, so the
    # Etherscan window is never spent.
    protocol = _protocol(db_session)
    calls = _stub_txlist(monkeypatch, {})
    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=ADDR(0x280)) is None
    assert calls == []


def test_ladder_wire_refuses_b_when_own_member_is_on_unenumerated_chain(db_session, monkeypatch):
    # Coverage refusal (scope): a KNOWN creation on a chain outside the
    # enumerated scope makes the enumeration incomplete — Class C.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x2B8)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    _contract(db_session, ADDR(0x2B9), chain="base", protocol_id=protocol.id, deployer=eoa)
    _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members]})

    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa) is None
    assert db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.address == eoa)).first() is None


def test_ladder_wire_refuses_b_when_any_protocols_row_is_out_of_scope(db_session, monkeypatch):
    # The scope check spans ANY contracts row claiming the deployer — a
    # foreign protocol's CANDIDATE on an unenumerated chain refuses too
    # (classify's collision check only sees foreign MEMBERS).
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    other = _protocol(db_session)
    eoa = ADDR(0x2BA)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    _contract(db_session, ADDR(0x2BB), chain="base", nominated_protocol_id=other.id, deployer=eoa)
    _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members]})

    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa) is None


def test_ladder_wire_refuses_b_when_known_creation_missing_from_enumeration(db_session, monkeypatch):
    # Coverage refusal (consistency): a member recorded as this EOA's creation
    # that the enumeration does not contain is an attribution mismatch
    # (contractCreator vs txlist) — Class C, never B.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x2BC)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    _stub_txlist(monkeypatch, {1: [_creation_tx(members[0].address)]})  # members[1] missing

    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa) is None


def test_ladder_wire_counterevidence_revokes_stale_b_row(db_session, monkeypatch):
    # A registered B row does not survive a Class C verdict carrying
    # counterevidence: the row is revoked and lineage-only members demote
    # (invariant 8).
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x2C4)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    lineage_only = _contract(db_session, ADDR(0x2C5), protocol_id=protocol.id, deployer=eoa)
    known = [*members, lineage_only]
    _stub_txlist(monkeypatch, {1: [_creation_tx(c.address) for c in known]})
    registry = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)
    assert registry is not None and registry.trust_class == "B"
    gate.write_witness(
        db_session,
        contract_id=lineage_only.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W4_DEPLOYER,
        evidence=gate.w4_evidence(
            deployer_address=eoa, deployer_registry_id=registry.id, creation_tx_hash=_TX, creation_block=7
        ),
        via_address=eoa,
    )
    db_session.commit()

    # A foreign creation is later observed; the reuse shortcut must not mask
    # it (the triggering contract is outside the recorded snapshot).
    _stub_txlist(monkeypatch, {1: [_creation_tx(c.address) for c in known] + [_creation_tx(ADDR(0x998))]})
    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa, contract_address=ADDR(0x997))

    assert row is None
    db_session.refresh(registry)
    assert registry.revoked_at is not None
    assert registry.revocation_reason == "foreign_or_unknown_creations"
    assert lineage_only.protocol_id is None
    assert lineage_only.nominated_protocol_id == protocol.id
    # Independently witnessed members are untouched.
    assert all(m.protocol_id == protocol.id for m in members)


def test_ladder_wire_coverage_gap_revokes_standing_b_row(db_session, monkeypatch):
    # F3: a coverage gap (known creation missing from a COMPLETE enumeration)
    # is positive counterevidence against a standing B row — unlike budget/cap
    # incompleteness, which never revokes.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x2E4)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members]})
    registry = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)
    assert registry is not None and registry.trust_class == "B"
    db_session.commit()

    # A later creation attributed to the EOA (getcontractcreation) that its
    # txlist does NOT contain: the standing license provably missed one.
    _contract(db_session, ADDR(0x2E5), nominated_protocol_id=protocol.id, deployer=eoa)
    db_session.flush()
    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa, contract_address=ADDR(0x2E5))

    assert row is None
    db_session.refresh(registry)
    assert registry.revoked_at is not None
    assert registry.revocation_reason == "enumeration_coverage_gap"


def test_fixpoint_coverage_gap_revokes_standing_b_row(db_session):
    # F3, gate path: the enumerator adapter surfaces the gap; the fixpoint's
    # stratum-(ii) reclassification revokes the standing row.
    protocol = _protocol(db_session)
    eoa = ADDR(0x2E6)
    _seed_class_b_shape(db_session, protocol, eoa)
    registry = gate.register_deployer(
        db_session,
        protocol_id=protocol.id,
        address=eoa,
        classification=gate.DeployerClassification(
            trust_class="B",
            evidence={"corroborating_member_ids": [], "enumeration": {"count": 2, "complete": True}},
        ),
    )
    db_session.commit()

    class Enumerator:
        coverage_gaps = {eoa: f"known_creation_missing_from_enumeration:{ADDR(0x2E7)}"}

        def __call__(self, addr: str):
            return (), False

    enumerator = Enumerator()
    gate.evaluate(
        db_session,
        gate.FactsDelta(changed_deployer_addresses=(eoa,)),
        deployer_enumerator=enumerator,
    )
    db_session.commit()
    db_session.refresh(registry)
    assert registry.revoked_at is not None
    assert registry.revocation_reason == "enumeration_coverage_gap"


def test_ladder_wire_snapshot_reuse_skips_reenumeration(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x2C6)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    calls = _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members]})
    first = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)
    assert first is not None and len(calls) == 1

    # Address inside the recorded snapshot: reuse, no re-enumeration.
    again = _register_protocol_deployer(
        db_session, protocol_id=protocol.id, deployer=eoa, contract_address=members[0].address
    )
    assert again is not None and again.id == first.id
    assert len(calls) == 1

    # Address outside the snapshot: full re-enumeration (fix-2's revocation
    # opportunity), snapshot refreshed to cover the newcomer. F1: the
    # newcomer maps through membership evidence, never its bare nomination.
    newcomer = _contract(db_session, ADDR(0x2C7), nominated_protocol_id=protocol.id, deployer=eoa)
    _seed_w2(db_session, newcomer, _contract(db_session, ADDR(0x2C8), protocol_id=protocol.id), protocol.id)
    _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members] + [_creation_tx(newcomer.address)]})
    refreshed = _register_protocol_deployer(
        db_session, protocol_id=protocol.id, deployer=eoa, contract_address=newcomer.address
    )
    assert refreshed is not None and refreshed.id == first.id
    assert newcomer.address in refreshed.evidence["enumeration"]["addresses"]


# ---------------------------------------------------------------------------
# §3.3 Class B through the gate fixpoint (worker adapter)
# ---------------------------------------------------------------------------


def test_fixpoint_mints_class_b_through_worker_adapter(db_session, monkeypatch):
    """The fixpoint reaches Class B with the worker's Etherscan-backed
    adapter — the same enumeration+coverage path the ladder wire uses."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x310)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    sibling = _contract(db_session, ADDR(0x312), nominated_protocol_id=protocol.id, deployer=eoa)
    db_session.add(
        ContractCreationWitness(
            chain_id=1,
            address=sibling.address,
            creation_tx_hash=_TX,
            creation_block=5,
            code_probe_block=100,
            code_absent_at_probe=False,
        )
    )
    # F1: the sibling maps into the exclusivity set only through membership
    # evidence; its stale W2 maps it while W4 remains the admitting witness.
    _seed_stale_w2(db_session, sibling, _contract(db_session, ADDR(0x313), protocol_id=protocol.id), protocol.id)
    db_session.flush()
    _stub_txlist(monkeypatch, {1: [_creation_tx(c.address) for c in (*members, sibling)]})

    result = gate.evaluate(
        db_session,
        gate.FactsDelta(recheck_contract_ids=(sibling.id,)),
        deployer_enumerator=session_deployer_enumerator(db_session),
    )
    db_session.commit()

    registry = db_session.execute(
        select(ProtocolDeployer).where(ProtocolDeployer.address == eoa, ProtocolDeployer.protocol_id == protocol.id)
    ).scalar_one()
    assert registry.trust_class == "B" and registry.revoked_at is None
    assert sibling.id in result.promoted_contract_ids
    assert sibling.protocol_id == protocol.id


def test_class_b_verdict_parity_between_ladder_wire_and_fixpoint(db_session, monkeypatch):
    """One Class-B evidence path: for the same fixture the ladder wire and the
    fixpoint adapter agree — refusal on a coverage gap, Class B once the
    enumeration covers every known creation."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x316)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    stray = _contract(db_session, ADDR(0x317), nominated_protocol_id=protocol.id, deployer=eoa)
    # F1: the stray maps only through membership evidence.
    _seed_w2(db_session, stray, _contract(db_session, ADDR(0x318), protocol_id=protocol.id), protocol.id)
    # The enumerated window misses the stray known creation → coverage gap.
    _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members]})

    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa) is None
    history, complete = session_deployer_enumerator(db_session)(eoa)
    verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=complete
    )
    assert verdict.trust_class is None
    assert db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.address == eoa)).first() is None

    # A window covering the stray flips BOTH paths to Class B.
    _stub_txlist(monkeypatch, {1: [_creation_tx(c.address) for c in (*members, stray)]})
    history, complete = session_deployer_enumerator(db_session)(eoa)
    parity_verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=complete
    )
    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)
    assert parity_verdict.trust_class == "B"
    assert row is not None and row.trust_class == "B"


# ---------------------------------------------------------------------------
# W5 assertion: admin submission end to end
# ---------------------------------------------------------------------------


def test_w5_end_to_end_admin_submission_to_membership(api_client, db_session, monkeypatch):
    """Admin address+company submission → job.request carries the attributed
    assertion → fetch intake writes the W5 witness (candidate until W1) → the
    event-1 probe supplies W1 and the row promotes to member."""
    from db.models import WITNESS_RULE_W5_HUMAN

    protocol = _protocol(db_session)
    db_session.commit()
    address = ADDR(0x2F9)
    resp = api_client.post("/api/analyze", json={"address": address, "name": "t", "company": protocol.name})
    assert resp.status_code == 200, resp.text
    job = db_session.query(Job).filter_by(id=resp.json()["job_id"]).one()
    payload = (job.request or {}).get(gate.HUMAN_ASSERTION_REQUEST_KEY)
    assert isinstance(payload, dict) and payload["actor"]
    assert job.protocol_id == protocol.id

    contract = _contract(db_session, address)
    request = job.request if isinstance(job.request, dict) else {}

    # No eRPC route: intake records the W5 witness, but W1 is missing —
    # candidate, never a member (invariant 3).
    monkeypatch.delenv("ERPC_BASE_URL", raising=False)
    _gate_intake(db_session, job, contract, request)
    w5 = (
        db_session.query(ContractMembershipWitness).filter_by(contract_id=contract.id, rule=WITNESS_RULE_W5_HUMAN).one()
    )
    assert w5.evidence["actor"] == payload["actor"]
    assert contract.protocol_id is None
    assert contract.nominated_protocol_id == protocol.id

    # The chain becomes routable: the probe supplies W1 and W5 admits.
    monkeypatch.setenv("ERPC_BASE_URL", "http://erpc.test")
    _stub_probe_wire(monkeypatch)
    _gate_intake(db_session, job, contract, request)
    assert contract.protocol_id == protocol.id


# ---------------------------------------------------------------------------
# Gate intake (fetch/cache-hit path)
# ---------------------------------------------------------------------------


def test_gate_intake_promotes_witnessed_candidate_and_never_stamps_otherwise(db_session):
    protocol = _protocol(db_session)
    anchor = _contract(db_session, ADDR(0x290), protocol_id=protocol.id)
    ready = _contract(db_session, ADDR(0x291), nominated_protocol_id=protocol.id)
    db_session.add(
        ContractProbeAttempt(contract_id=ready.id, chain_id=1, block_number=90, results={"status": "probed"})
    )
    _seed_w1(db_session, ready, protocol.id)
    _seed_w2(db_session, ready, anchor, protocol.id)

    bare = _contract(db_session, ADDR(0x292))
    db_session.add(ContractProbeAttempt(contract_id=bare.id, chain_id=1, block_number=90, results={"status": "probed"}))
    db_session.flush()

    ready_request = {"discovery_sources": ["inventory"]}
    job = _job(db_session, protocol_id=protocol.id, address=ready.address, request=ready_request)
    _gate_intake(db_session, job, ready, ready_request)
    assert ready.protocol_id == protocol.id
    assert "inventory" in (ready.discovery_sources or [])

    bare_request = {"discovery_sources": ["dapp_crawl"]}
    job2 = _job(db_session, protocol_id=protocol.id, address=bare.address, request=bare_request)
    _gate_intake(db_session, job2, bare, bare_request)
    # Nominated as a candidate; no witness → no stamp (invariant 1).
    assert bare.protocol_id is None
    assert bare.nominated_protocol_id == protocol.id


def test_gate_intake_structural_hint_is_reverified_not_trusted(db_session):
    protocol = _protocol(db_session)
    candidate = _contract(db_session, ADDR(0x2A1), nominated_protocol_id=protocol.id)
    db_session.add(
        ContractProbeAttempt(contract_id=candidate.id, chain_id=1, block_number=90, results={"status": "probed"})
    )
    db_session.flush()

    # Parent whose stored resolution does NOT point at the candidate: the
    # request flag alone must produce nothing.
    liar_job = _job(db_session, protocol_id=protocol.id, address=ADDR(0x2A2))
    _contract(db_session, ADDR(0x2A2), protocol_id=protocol.id, implementation=ADDR(0x2A9)).job_id = liar_job.id
    db_session.flush()
    request = {
        "discovery_relationship": "implementation",
        "parent_is_member": True,
        "parent_job_id": str(liar_job.id),
    }
    _gate_intake(db_session, liar_job, candidate, request)
    assert candidate.protocol_id is None
    assert (
        db_session.query(ContractMembershipWitness)
        .filter_by(contract_id=candidate.id, rule=WITNESS_RULE_W2_STRUCTURAL)
        .count()
        == 0
    )

    # Parent whose stored implementation IS the candidate: the edge verifies,
    # the witness lands, and with W1 the row promotes.
    honest_job = _job(db_session, protocol_id=protocol.id, address=ADDR(0x2A3))
    parent = _contract(db_session, ADDR(0x2A3), protocol_id=protocol.id, implementation=candidate.address)
    parent.job_id = honest_job.id
    db_session.flush()
    _seed_w1(db_session, candidate, protocol.id)
    request = {
        "discovery_relationship": "implementation",
        "parent_is_member": True,
        "parent_job_id": str(honest_job.id),
    }
    _gate_intake(db_session, honest_job, candidate, request)
    witness = (
        db_session.query(ContractMembershipWitness)
        .filter_by(contract_id=candidate.id, rule=WITNESS_RULE_W2_STRUCTURAL)
        .one()
    )
    assert witness.via_address == parent.address
    assert candidate.protocol_id == protocol.id


def test_gate_intake_registers_deployer_and_writes_w4(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x2B0)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    newcomer = _contract(db_session, ADDR(0x2B1), nominated_protocol_id=protocol.id, deployer=eoa)
    db_session.add(
        ContractProbeAttempt(contract_id=newcomer.id, chain_id=1, block_number=90, results={"status": "probed"})
    )
    # Creation tx already witnessed (probe pass persisted it).
    db_session.add(
        ContractCreationWitness(chain_id=1, address=newcomer.address, creation_tx_hash=_TX, creation_block=50)
    )
    _seed_w1(db_session, newcomer, protocol.id)
    # F1: the newcomer maps into the exclusivity set through its stale W2;
    # the W4 under test is what verifies and admits.
    _seed_stale_w2(db_session, newcomer, _contract(db_session, ADDR(0x2B2), protocol_id=protocol.id), protocol.id)
    db_session.flush()
    _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members] + [_creation_tx(newcomer.address)]})

    job = _job(db_session, protocol_id=protocol.id, address=newcomer.address)
    _gate_intake(db_session, job, newcomer, {})

    registry = db_session.execute(
        select(ProtocolDeployer).where(ProtocolDeployer.address == eoa, ProtocolDeployer.protocol_id == protocol.id)
    ).scalar_one()
    assert registry.trust_class == "B"
    w4 = (
        db_session.query(ContractMembershipWitness)
        .filter_by(contract_id=newcomer.id, rule=WITNESS_RULE_W4_DEPLOYER)
        .one()
    )
    assert w4.via_address == eoa
    assert w4.evidence["creation_tx_hash"] == _TX
    assert newcomer.protocol_id == protocol.id


# ---------------------------------------------------------------------------
# §3.4 event 1: near-line probe pass
# ---------------------------------------------------------------------------


@pytest.fixture()
def erpc_env(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "http://erpc.test")


def _stub_probe_wire(monkeypatch, *, code: str = "0x6001") -> dict:
    seen: dict = {"probed": []}

    def fake_rpc_request(rpc_url, method, params, *args, **kwargs):
        if method == "eth_blockNumber":
            return hex(120)
        if method == "eth_getCode":
            seen["probed"].append(params[0])
            return code
        raise AssertionError(f"unexpected rpc method {method}")

    def fake_eth_call_batch(rpc_url, calls, block_tag="latest", **kwargs):
        results = []
        for call in calls:
            assert call["data"] in (OWNER_SELECTOR, probes.AUTHORITY_SELECTOR)
            results.append(EthCallResult(False, "0x", None, "execution reverted"))
        return results

    def fake_rpc_batch_request(rpc_url, calls, *args, **kwargs):
        return [_ZERO_WORD for _ in calls]

    def fake_etherscan_get(module, action, chain_id, **params):
        return {"result": []}

    monkeypatch.setattr(probes, "rpc_request", fake_rpc_request)
    monkeypatch.setattr(probes, "eth_call_batch", fake_eth_call_batch)
    monkeypatch.setattr(probes, "rpc_batch_request", fake_rpc_batch_request)
    monkeypatch.setattr(probes.etherscan, "get", fake_etherscan_get)
    return seen


def test_probe_pass_probes_fresh_candidates_and_writes_w1(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    other = _protocol(db_session)
    fresh = _contract(db_session, ADDR(0x2C0), nominated_protocol_id=protocol.id)
    already = _contract(db_session, ADDR(0x2C1), nominated_protocol_id=protocol.id)
    db_session.add(
        ContractProbeAttempt(contract_id=already.id, chain_id=1, block_number=80, results={"status": "probed"})
    )
    foreign = _contract(db_session, ADDR(0x2C2), nominated_protocol_id=other.id)
    db_session.flush()
    seen = _stub_probe_wire(monkeypatch)

    run_probe_pass(db_session, protocol.id)

    # Bounded: only THIS protocol's un-probed candidate hit the wire.
    assert seen["probed"] == [fresh.address]
    w1 = db_session.query(ContractMembershipWitness).filter_by(contract_id=fresh.id, rule=WITNESS_RULE_W1_CODE).one()
    assert w1.evidence == {"chain_id": 1, "code_probe_block": 120, "code_present": True}
    assert db_session.query(ContractMembershipWitness).filter_by(contract_id=foreign.id).count() == 0
    # W1 alone admits nothing.
    assert fresh.protocol_id is None


def test_probe_pass_promotes_when_probe_completes_the_witness_set(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    anchor = _contract(db_session, ADDR(0x2D0), protocol_id=protocol.id)
    candidate = _contract(db_session, ADDR(0x2D1), nominated_protocol_id=protocol.id)
    _seed_w2(db_session, candidate, anchor, protocol.id)
    db_session.flush()
    _stub_probe_wire(monkeypatch)

    result = run_probe_pass(db_session, protocol.id)

    assert candidate.protocol_id == protocol.id
    assert candidate.id in result.promoted_contract_ids


def test_probe_pass_reprobes_error_attempts(db_session, monkeypatch, erpc_env):
    # An rpc_error / not_routable attempt is an attempt, never a verdict —
    # the next pass must re-probe instead of parking the row forever.
    protocol = _protocol(db_session)
    stuck = _contract(db_session, ADDR(0x2C8), nominated_protocol_id=protocol.id)
    db_session.add(
        ContractProbeAttempt(
            contract_id=stuck.id, chain_id=1, block_number=None, results={"status": "rpc_error", "error": "boom"}
        )
    )
    db_session.flush()
    seen = _stub_probe_wire(monkeypatch)

    run_probe_pass(db_session, protocol.id)

    assert seen["probed"] == [stuck.address]
    w1 = db_session.query(ContractMembershipWitness).filter_by(contract_id=stuck.id, rule=WITNESS_RULE_W1_CODE).one()
    assert w1.evidence["code_probe_block"] == 120


def test_probe_pass_retargets_demoted_member_after_revocation(db_session, monkeypatch, erpc_env):
    """Request/queue-context demotions run no inline probe; the next probe
    pass re-targets the row because its completed attempt predates the newest
    witness revocation (invariant 8 via the normal event flow)."""
    from datetime import datetime, timezone

    protocol = _protocol(db_session)
    anchor = _contract(db_session, ADDR(0x320), protocol_id=protocol.id)
    member = _contract(db_session, ADDR(0x321), protocol_id=protocol.id, nominated_protocol_id=protocol.id)
    _seed_w2(db_session, member, anchor, protocol.id)
    db_session.add(
        ContractProbeAttempt(
            contract_id=member.id,
            chain_id=1,
            block_number=90,
            results={"status": "probed"},
            probed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    )
    db_session.flush()
    witness = db_session.query(ContractMembershipWitness).filter_by(contract_id=member.id).one()
    gate.revoke_witness(db_session, witness, reason="protocol_merge_revoked_deployer")
    member.protocol_id = None
    db_session.commit()

    seen = _stub_probe_wire(monkeypatch)
    run_probe_pass(db_session, protocol.id)

    assert member.address in seen["probed"]


def test_gate_intake_reprobes_members_demoted_by_counterevidence(db_session, monkeypatch, erpc_env):
    """The intake's counterevidence revocation feeds the demoted lineage-only
    member straight back into the probe machinery (bounded, same pass)."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x340)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    calls = _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members]})
    lineage_only = _contract(db_session, ADDR(0x341), protocol_id=protocol.id, deployer=eoa)
    known = [*members, lineage_only]
    _stub_txlist(monkeypatch, {1: [_creation_tx(c.address) for c in known]})
    registry = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)
    assert registry is not None and registry.trust_class == "B"
    gate.write_witness(
        db_session,
        contract_id=lineage_only.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W4_DEPLOYER,
        evidence=gate.w4_evidence(
            deployer_address=eoa, deployer_registry_id=registry.id, creation_tx_hash=_TX, creation_block=7
        ),
        via_address=eoa,
    )
    newcomer = _contract(db_session, ADDR(0x342), nominated_protocol_id=protocol.id, deployer=eoa)
    db_session.commit()

    # One transport stub for both consumers (probes + enumeration share the
    # etherscan module): the re-enumeration now surfaces a foreign creation.
    seen = _stub_probe_wire(monkeypatch)
    foreign_window = [_creation_tx(c.address) for c in (*known, newcomer)] + [_creation_tx(ADDR(0x998))]

    def fake_etherscan(module, action, chain_id, empty_result_ok=False, **params):
        if action == "txlist":
            return {"result": foreign_window}
        return {"result": []}

    monkeypatch.setattr(probes.etherscan, "get", fake_etherscan)
    del calls

    job = _job(db_session, protocol_id=protocol.id, address=newcomer.address)
    _gate_intake(db_session, job, newcomer, {})

    db_session.refresh(registry)
    assert registry.revoked_at is not None
    assert lineage_only.protocol_id is None
    # The demoted member was re-probed in the same pass, not parked silently.
    assert lineage_only.address in seen["probed"]


def test_probe_pass_reprobes_renominated_pruned_rows(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    pruned = _contract(db_session, ADDR(0x2E0), nominated_protocol_id=protocol.id)
    db_session.add(
        ContractProbeAttempt(contract_id=pruned.id, chain_id=1, block_number=70, results={"status": "probed"})
    )
    db_session.add(
        ContractCreationWitness(chain_id=1, address=pruned.address, code_probe_block=70, code_absent_at_probe=True)
    )
    db_session.flush()
    seen = _stub_probe_wire(monkeypatch)  # code now present at the address

    run_probe_pass(db_session, protocol.id)

    assert seen["probed"] == [pruned.address]
    witness = db_session.get(ContractCreationWitness, (1, pruned.address))
    assert witness is not None and witness.code_absent_at_probe is False
    assert gate.resolve_membership_state(db_session, pruned) == "candidate"


# ---------------------------------------------------------------------------
# W6 live producer (spec §3.2 W6): defillama tag + W1 mint the seed witness
# ---------------------------------------------------------------------------


def _w6_rows(session, contract_id: int):
    return (
        session.query(ContractMembershipWitness)
        .filter_by(contract_id=contract_id, rule=WITNESS_RULE_W6_LLAMA_SEED)
        .all()
    )


def test_probe_pass_seeds_w6_and_promotes_defillama_nomination(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    candidate = _contract(db_session, ADDR(0x2F0), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    db_session.flush()
    _stub_probe_wire(monkeypatch)

    result = run_probe_pass(db_session, protocol.id)

    (w6,) = _w6_rows(db_session, candidate.id)
    assert w6.revoked_at is None
    assert w6.evidence == {"adapter_slug": protocol.name, "chain_id": 1, "code_probe_block": 120}
    assert candidate.protocol_id == protocol.id
    assert candidate.id in result.promoted_contract_ids


def test_probe_pass_no_w6_without_defillama_tag(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    candidate = _contract(
        db_session, ADDR(0x2F1), nominated_protocol_id=protocol.id, discovery_sources=["exa_deep_research"]
    )
    db_session.flush()
    _stub_probe_wire(monkeypatch)

    run_probe_pass(db_session, protocol.id)

    assert _w6_rows(db_session, candidate.id) == []
    # W1 alone admits nothing.
    assert candidate.protocol_id is None


def test_probe_pass_no_w6_when_defillama_nomination_fails_w1(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    candidate = _contract(db_session, ADDR(0x2F2), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    db_session.flush()
    _stub_probe_wire(monkeypatch, code="0x")

    run_probe_pass(db_session, protocol.id)

    assert _w6_rows(db_session, candidate.id) == []
    assert candidate.protocol_id is None
    assert gate.resolve_membership_state(db_session, candidate) == "pruned"


def test_gate_intake_seeds_w6_for_already_probed_defillama_row(db_session, monkeypatch, erpc_env):
    # A row probed before the defillama tag arrived: intake must still seed
    # W6 from the persisted code fact, not only from a fresh probe.
    protocol = _protocol(db_session)
    candidate = _contract(db_session, ADDR(0x2F3), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    db_session.add(
        ContractProbeAttempt(contract_id=candidate.id, chain_id=1, block_number=90, results={"status": "probed"})
    )
    db_session.add(
        ContractCreationWitness(chain_id=1, address=candidate.address, code_probe_block=90, code_absent_at_probe=False)
    )
    db_session.flush()
    _stub_probe_wire(monkeypatch)

    job = _job(db_session, protocol_id=protocol.id, address=candidate.address)
    _gate_intake(db_session, job, candidate, {"discovery_sources": ["defillama"]})

    (w6,) = _w6_rows(db_session, candidate.id)
    assert w6.evidence["code_probe_block"] == 90
    assert candidate.protocol_id == protocol.id


def test_seed_llama_witness_never_rearms_revoked_seed(db_session):
    protocol = _protocol(db_session)
    candidate = _contract(db_session, ADDR(0x2F4), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    db_session.add(
        ContractCreationWitness(chain_id=1, address=candidate.address, code_probe_block=90, code_absent_at_probe=False)
    )
    db_session.flush()
    assert gate.seed_llama_witness(db_session, contract=candidate) is True
    (w6,) = _w6_rows(db_session, candidate.id)
    gate.revoke_witness(db_session, w6, reason="listing_hijack")
    db_session.flush()

    assert gate.seed_llama_witness(db_session, contract=candidate) is False
    (w6_after,) = _w6_rows(db_session, candidate.id)
    assert w6_after.revoked_at is not None


# ---------------------------------------------------------------------------
# §3.4 event 4: chain-enable boot sweep
# ---------------------------------------------------------------------------


@pytest.fixture()
def _clean_marker(db_session):
    db_session.execute(delete(OpsKv).where(OpsKv.key == ENABLED_CHAINS_SEEN_KEY))
    db_session.commit()
    yield
    db_session.execute(delete(OpsKv).where(OpsKv.key == ENABLED_CHAINS_SEEN_KEY))
    db_session.commit()


def test_boot_sweep_seeds_marker_on_first_boot(db_session, monkeypatch, _clean_marker):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")

    def no_wire(*args, **kwargs):
        raise AssertionError("first boot must not probe")

    monkeypatch.setattr(probes, "rpc_request", no_wire)

    run_chain_enable_sweep(db_session)

    marker = db_session.get(OpsKv, ENABLED_CHAINS_SEEN_KEY)
    assert marker is not None and marker.value == [1]


def test_boot_sweep_noop_when_unchanged(db_session, monkeypatch, _clean_marker):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    db_session.add(OpsKv(key=ENABLED_CHAINS_SEEN_KEY, value=[1]))
    db_session.commit()

    def no_wire(*args, **kwargs):
        raise AssertionError("unchanged allowlist must not probe")

    monkeypatch.setattr(probes, "rpc_request", no_wire)

    run_chain_enable_sweep(db_session)

    marker = db_session.get(OpsKv, ENABLED_CHAINS_SEEN_KEY)
    assert marker is not None and marker.value == [1]


def test_boot_sweep_probes_new_chain_and_enqueues_selection(db_session, monkeypatch, erpc_env, _clean_marker):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    db_session.add(OpsKv(key=ENABLED_CHAINS_SEEN_KEY, value=[1]))
    protocol = _protocol(db_session)
    anchor = _contract(db_session, ADDR(0x2F0), chain="base", protocol_id=protocol.id)
    parked = _contract(db_session, ADDR(0x2F1), chain="base", nominated_protocol_id=protocol.id)
    _seed_w2(db_session, parked, anchor, protocol.id)
    pruned = _contract(db_session, ADDR(0x2F2), chain="base", nominated_protocol_id=protocol.id)
    db_session.add(
        ContractCreationWitness(chain_id=8453, address=pruned.address, code_probe_block=10, code_absent_at_probe=True)
    )
    mainnet_candidate = _contract(db_session, ADDR(0x2F3), chain="ethereum", nominated_protocol_id=protocol.id)
    db_session.commit()
    seen = _stub_probe_wire(monkeypatch)

    run_chain_enable_sweep(db_session)

    # Only the newly enabled chain's non-pruned candidates were swept.
    assert seen["probed"] == [parked.address]
    db_session.refresh(parked)
    assert parked.protocol_id == protocol.id
    assert mainnet_candidate.protocol_id is None
    selection = (
        db_session.execute(select(Job).where(Job.stage == JobStage.selection, Job.protocol_id == protocol.id))
        .scalars()
        .all()
    )
    assert len(selection) == 1
    marker = db_session.get(OpsKv, ENABLED_CHAINS_SEEN_KEY)
    assert marker is not None and marker.value == [1, 8453]

    # Re-running with the marker updated is a no-op (no duplicate selection job).
    def no_wire(*args, **kwargs):
        raise AssertionError("swept chain must not re-probe")

    monkeypatch.setattr(probes, "rpc_request", no_wire)
    run_chain_enable_sweep(db_session)
    selection = (
        db_session.execute(select(Job).where(Job.stage == JobStage.selection, Job.protocol_id == protocol.id))
        .scalars()
        .all()
    )
    assert len(selection) == 1


def test_boot_sweep_dedupes_pending_selection_pass(db_session, monkeypatch, erpc_env, _clean_marker):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    db_session.add(OpsKv(key=ENABLED_CHAINS_SEEN_KEY, value=[1]))
    protocol = _protocol(db_session)
    anchor = _contract(db_session, ADDR(0x310), chain="base", protocol_id=protocol.id)
    parked = _contract(db_session, ADDR(0x311), chain="base", nominated_protocol_id=protocol.id)
    _seed_w2(db_session, parked, anchor, protocol.id)
    existing = Job(
        id=uuid.uuid4(),
        protocol_id=protocol.id,
        status=JobStatus.queued,
        stage=JobStage.selection,
        request={},
    )
    db_session.add(existing)
    db_session.commit()
    _stub_probe_wire(monkeypatch)

    run_chain_enable_sweep(db_session)

    selection = db_session.execute(
        select(Job.id).where(Job.stage == JobStage.selection, Job.protocol_id == protocol.id)
    ).all()
    assert len(selection) == 1
