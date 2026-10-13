"""Discovery-worker membership-gate producers.

Covers the deployer-ladder enumeration wire, the worker's gate intake, the
nomination probe pass, and the chain-enable boot sweep. All wire stubbed at the
transport boundary (``probes.rpc_request`` / ``etherscan.get``) — never the
real network.
"""

from __future__ import annotations

import time
import uuid
from threading import Barrier, Thread

import pytest
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.orm import Session

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
    MonitoringEnrollmentQueue,
    OpsKv,
    Protocol,
    ProtocolDeployer,
    ProtocolScoreQueue,
)
from services.clients.rpc import EthCallResult
from services.discovery import deployer_enumeration, probes
from services.discovery import membership_gate as gate
from services.discovery.deployer_enumeration import (
    DEPLOYER_ENUMERATION_CAP,
    enumerate_deployer_creations,
    session_deployer_enumerator,
)
from tests.conftest import ADDR, DATABASE_URL, requires_postgres
from tests.support.membership_builders import _protocol
from utils.evm import OWNER_SELECTOR
from workers.discovery import (
    ENABLED_CHAINS_SEEN_KEY,
    _gate_intake,
    _register_protocol_deployer,
    run_chain_enable_sweep,
    run_probe_pass,
)

pytestmark = [requires_postgres]


def test_concurrent_gate_cascades_mark_protocol_queues_in_one_order(db_session):
    """Opposite contract traversal orders must not deadlock on queue rows."""
    from services.discovery.membership_gate.admission import _mark_membership_dirty, defer_membership_dirty

    protocols = [Protocol(name=f"dirty-order-{uuid.uuid4().hex}") for _ in range(2)]
    db_session.add_all(protocols)
    db_session.commit()
    ids = [protocol.id for protocol in protocols]
    barrier = Barrier(2)
    errors: list[BaseException] = []
    engine = create_engine(DATABASE_URL)

    def mark_in_order(order: list[int]) -> None:
        try:
            with Session(engine) as session:
                session.execute(text("SET LOCAL statement_timeout = '5s'"))
                with defer_membership_dirty(session):
                    _mark_membership_dirty(session, order[0])
                    barrier.wait(timeout=5)
                    _mark_membership_dirty(session, order[1])
                session.commit()
        except BaseException as exc:
            errors.append(exc)

    try:
        threads = [Thread(target=mark_in_order, args=(ids,)), Thread(target=mark_in_order, args=(ids[::-1],))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert not any(thread.is_alive() for thread in threads)
        assert not errors
        assert set(db_session.execute(select(MonitoringEnrollmentQueue.protocol_id)).scalars()) >= set(ids)
    finally:
        db_session.rollback()
        db_session.execute(delete(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id.in_(ids)))
        db_session.execute(delete(ProtocolScoreQueue).where(ProtocolScoreQueue.protocol_id.in_(ids)))
        db_session.execute(delete(Protocol).where(Protocol.id.in_(ids)))
        db_session.commit()
        engine.dispose()


_TX = "0x" + "34" * 32
_ZERO_WORD = "0x" + "0" * 64


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
    # promote re-verifies the via-fact against the stored resolution.
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


def _call_tx(
    sender: str, *, tx_hash: str, to: str = "0x" + "aa" * 20, is_error: str = "0", confirmations: str | None = None
) -> dict:
    tx = {"from": sender, "to": to, "contractAddress": "", "hash": tx_hash, "isError": is_error}
    if confirmations is not None:
        tx["confirmations"] = confirmations
    return tx


def _create_frame(target: str, factory: str, *, kind: str = "create2", is_error: str = "0") -> dict:
    return {"type": kind, "from": factory, "to": "", "contractAddress": target, "isError": is_error}


def _created_addresses(creations) -> list[str]:
    return sorted({c.address for c in creations})


# ---------------------------------------------------------------------------
# ladder wire: enumeration
# ---------------------------------------------------------------------------


def test_enumeration_skips_received_failed_and_frameless_txs(monkeypatch):
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


def test_internal_empty_caching_gated_on_tx_maturity(monkeypatch):
    """Only a confirmations reading past the maturity floor licenses persisting an empty trace."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x26E)
    fresh_hash = "0x" + "4c" * 32
    mature_hash = "0x" + "4d" * 32
    unknown_hash = "0x" + "4e" * 32
    calls = _stub_txlist(
        monkeypatch,
        {
            1: [
                _creation_tx(ADDR(0x26F)),
                _call_tx(eoa, tx_hash=fresh_hash, confirmations="3"),
                _call_tx(
                    eoa,
                    tx_hash=mature_hash,
                    confirmations=str(deployer_enumeration.INTERNAL_TRACE_CACHE_MIN_CONFIRMATIONS),
                ),
                _call_tx(eoa, tx_hash=unknown_hash),
            ]
        },
    )
    _, scope, complete = enumerate_deployer_creations(eoa)
    assert scope == [1]
    assert complete is True
    by_hash = {c[3]["txhash"]: c[3]["cache_empty"] for c in calls if c[1] == "txlistinternal"}
    assert by_hash == {fresh_hash: False, mature_hash: True, unknown_hash: False}


_FAIL_EOA = ADDR(0x269)
_FAIL_HASH = "0x" + "4a" * 32
_COMBINED_EOA = ADDR(0x26C)
_COMBINED_HASH = "0x" + "4b" * 32


# A half-enumerated chain never claims completeness; a dropped chain leaves the scope empty.
@pytest.mark.parametrize(
    ("eoa", "txs_by_chain", "internal_by_txhash", "expected"),
    [
        pytest.param(
            _FAIL_EOA,
            {1: [_creation_tx(ADDR(0x26A)), _call_tx(_FAIL_EOA, tx_hash=_FAIL_HASH)]},
            {_FAIL_HASH: RuntimeError("etherscan down")},
            ([], [], False),
            id="internal_failure",
        ),
        pytest.param(
            _COMBINED_EOA,
            {1: [_creation_tx(ADDR(0x26D)), _call_tx(_COMBINED_EOA, tx_hash=_COMBINED_HASH)]},
            {
                _COMBINED_HASH: [
                    _create_frame(ADDR(0x100000 + n), ADDR(0x262)) for n in range(DEPLOYER_ENUMERATION_CAP - 1)
                ]
            },
            ([], [], False),
            id="combined_cap",
        ),
        # A full txlist window is a truncation.
        pytest.param(
            ADDR(0x2FF),
            {
                1: [_creation_tx(ADDR(0x300 + n)) for n in range(3)]
                + [{"to": ADDR(0x999), "contractAddress": ""}] * (DEPLOYER_ENUMERATION_CAP - 3)
            },
            None,
            ([], [], False),
            id="cap_exceeded",
        ),
        pytest.param(ADDR(0x210), {1: []}, None, ([], [1], False), id="empty_txlist"),
        pytest.param(ADDR(0x210), {1: RuntimeError("etherscan down")}, None, ([], [], False), id="failed_txlist"),
    ],
)
def test_enumeration_is_incomplete(monkeypatch, eoa, txs_by_chain, internal_by_txhash, expected):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _stub_txlist(monkeypatch, txs_by_chain, internal_by_txhash)
    assert enumerate_deployer_creations(eoa) == expected


def test_enumeration_any_enabled_chain_failing_is_incomplete(monkeypatch):
    # EOAs are chain-agnostic, so every enabled chain's window must come back clean.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    _stub_txlist(monkeypatch, {1: [_creation_tx(ADDR(0x220))], 8453: RuntimeError("boom")})
    created, scope, complete = enumerate_deployer_creations(ADDR(0x221))
    assert _created_addresses(created) == [ADDR(0x220)]
    assert scope == [1]
    assert complete is False


# ---------------------------------------------------------------------------
# ladder wire: registration
# ---------------------------------------------------------------------------


def _seed_stale_w2(session, contract: Contract, former_anchor: Contract, protocol_id: int) -> None:
    """An unrevoked W2 row whose edge no longer holds (the anchor's pointer
    was since rewritten). Membership evidence for the Class-B mapping test;
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
    assert row.evidence["enumeration"]["complete"] is True
    assert row.evidence["enumeration"]["chain_ids"] == [1]
    assert sorted(row.evidence["enumeration"]["addresses"]) == sorted(m.address for m in members)
    assert len(calls) == 1


def test_ladder_wire_counts_unknown_creations_without_materializing(db_session, monkeypatch):
    """Coverage honesty: an unknown creation in a complete
    enumeration is COUNTED (Class B refuses) but never becomes a contracts row."""
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
    assert db_session.execute(select(Contract).where(Contract.address == unknown)).first() is None
    assert sink == set()


def test_ladder_wire_member_factory_child_mints_b_with_factory_evidence(db_session, monkeypatch):
    """2a: a creation minted by the protocol's own anchoring MEMBER factory
    counts as mapped (deliberate deviation) — Class B mints and the
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
    assert db_session.execute(select(Contract).where(Contract.address == child)).first() is None
    assert sink == set()


def _seed_own_member_on_unenumerated_chain(db_session, protocol, eoa, members):
    # A known creation outside the enumerated scope makes it incomplete.
    _contract(db_session, ADDR(0x2B9), chain="base", protocol_id=protocol.id, deployer=eoa)
    return members


def _seed_foreign_candidate_on_unenumerated_chain(db_session, protocol, eoa, members):
    # classify's collision check only sees foreign members, so a foreign candidate must refuse here.
    other = _protocol(db_session)
    _contract(db_session, ADDR(0x2BB), chain="base", nominated_protocol_id=other.id, deployer=eoa)
    return members


def _drop_a_known_creation_from_enumeration(db_session, protocol, eoa, members):
    # A contractCreator/txlist attribution mismatch is Class C.
    return members[:1]


@pytest.mark.parametrize(
    ("eoa", "seed"),
    [
        pytest.param(ADDR(0x2B8), _seed_own_member_on_unenumerated_chain, id="own_member_on_unenumerated_chain"),
        pytest.param(ADDR(0x2BA), _seed_foreign_candidate_on_unenumerated_chain, id="any_protocols_row_out_of_scope"),
        pytest.param(ADDR(0x2BC), _drop_a_known_creation_from_enumeration, id="known_creation_missing"),
    ],
)
def test_ladder_wire_refuses_b_on_coverage_gap(db_session, monkeypatch, eoa, seed):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    enumerated = seed(db_session, protocol, eoa, members)
    _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in enumerated]})

    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa) is None
    assert db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.address == eoa)).first() is None


def test_ladder_wire_coverage_gap_revokes_standing_b_row(db_session, monkeypatch):
    # a coverage gap (known creation missing from a COMPLETE enumeration)
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

    _contract(db_session, ADDR(0x2E5), nominated_protocol_id=protocol.id, deployer=eoa)
    db_session.flush()
    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa, contract_address=ADDR(0x2E5))

    assert row is None
    db_session.refresh(registry)
    assert registry.revoked_at is not None
    assert registry.revocation_reason == "enumeration_coverage_gap"


def test_fixpoint_coverage_gap_revokes_standing_b_row(db_session):
    # gate path: the enumerator adapter surfaces the gap; the fixpoint's
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

    again = _register_protocol_deployer(
        db_session, protocol_id=protocol.id, deployer=eoa, contract_address=members[0].address
    )
    assert again is not None and again.id == first.id
    assert len(calls) == 1

    # Address outside the snapshot: full re-enumeration (fix-2's revocation
    # opportunity), snapshot refreshed to cover the newcomer. The
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
# Class B through the gate fixpoint (worker adapter)
# ---------------------------------------------------------------------------


def test_class_b_verdict_parity_between_ladder_wire_and_fixpoint(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x316)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    stray = _contract(db_session, ADDR(0x317), nominated_protocol_id=protocol.id, deployer=eoa)
    # the stray maps only through membership evidence.
    _seed_w2(db_session, stray, _contract(db_session, ADDR(0x318), protocol_id=protocol.id), protocol.id)
    _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members]})

    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa) is None
    history, complete = session_deployer_enumerator(db_session)(eoa)
    verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=complete
    )
    assert verdict.trust_class is None
    assert db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.address == eoa)).first() is None

    _stub_txlist(monkeypatch, {1: [_creation_tx(c.address) for c in (*members, stray)]})
    history, complete = session_deployer_enumerator(db_session)(eoa)
    parity_verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=complete
    )
    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)
    assert parity_verdict.trust_class == "B"
    assert row is not None and row.trust_class == "B"


def test_w5_end_to_end_admin_submission_to_membership(api_client, db_session, monkeypatch):
    """Admin address+company submission → job.request carries the attributed
    assertion → fetch intake writes the W5 witness (candidate until W1) → the
    nomination probe supplies W1 and the row promotes to member."""
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
    # candidate, never a member.
    monkeypatch.delenv("ERPC_BASE_URL", raising=False)
    _gate_intake(db_session, job, contract, request)
    w5 = (
        db_session.query(ContractMembershipWitness).filter_by(contract_id=contract.id, rule=WITNESS_RULE_W5_HUMAN).one()
    )
    assert w5.evidence["actor"] == payload["actor"]
    assert contract.protocol_id is None
    assert contract.nominated_protocol_id == protocol.id

    monkeypatch.setenv("ERPC_BASE_URL", "http://erpc.test")
    _stub_probe_wire(monkeypatch)
    _gate_intake(db_session, job, contract, request)
    assert contract.protocol_id == protocol.id


def test_gate_intake_structural_hint_is_reverified_not_trusted(db_session):
    protocol = _protocol(db_session)
    candidate = _contract(db_session, ADDR(0x2A1), nominated_protocol_id=protocol.id)
    db_session.add(
        ContractProbeAttempt(contract_id=candidate.id, chain_id=1, block_number=90, results={"status": "probed"})
    )
    db_session.flush()

    # The request flag alone must produce nothing.
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
    db_session.add(
        ContractCreationWitness(chain_id=1, address=newcomer.address, creation_tx_hash=_TX, creation_block=50)
    )
    _seed_w1(db_session, newcomer, protocol.id)
    # the newcomer maps into the exclusivity set through its stale W2;
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
# near-line probe pass
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

    assert seen["probed"] == [fresh.address]
    w1 = db_session.query(ContractMembershipWitness).filter_by(contract_id=fresh.id, rule=WITNESS_RULE_W1_CODE).one()
    assert w1.evidence == {"chain_id": 1, "code_probe_block": 120, "code_present": True}
    assert db_session.query(ContractMembershipWitness).filter_by(contract_id=foreign.id).count() == 0
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


def test_probe_pass_budget_defers_tail_with_named_record(db_session, monkeypatch, erpc_env):
    """The tail is a named deferral, never a silent drop."""
    from utils.logging import degraded_errors_var

    monkeypatch.setenv("PSAT_PROBE_PASS_MAX", "2")
    protocol = _protocol(db_session)
    c1 = _contract(db_session, ADDR(0x2E4), nominated_protocol_id=protocol.id)
    c2 = _contract(db_session, ADDR(0x2E5), nominated_protocol_id=protocol.id)
    c3 = _contract(db_session, ADDR(0x2E6), nominated_protocol_id=protocol.id)
    db_session.flush()
    seen = _stub_probe_wire(monkeypatch)
    beats = {"n": 0}

    errors: list = []
    token = degraded_errors_var.set(errors)
    try:
        run_probe_pass(db_session, protocol.id, heartbeat=lambda: beats.__setitem__("n", beats["n"] + 1))
    finally:
        degraded_errors_var.reset(token)

    assert seen["probed"] == [c1.address, c2.address]
    assert beats["n"] == 2
    budget_errors = [e for e in errors if e.phase == "membership_probe_pass_budget"]
    assert len(budget_errors) == 1
    assert budget_errors[0].context == {"protocol_id": protocol.id, "budget": 2, "deferred": 1}

    seen2 = _stub_probe_wire(monkeypatch)
    run_probe_pass(db_session, protocol.id)
    assert seen2["probed"] == [c3.address]


def test_probe_pass_retargets_demoted_member_after_revocation(db_session, monkeypatch, erpc_env):
    """Request/queue-context demotions run no inline probe; the next probe
    pass re-targets the row because its completed attempt predates the newest
    witness revocation (via the normal event flow)."""
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

    # Probes and enumeration share the etherscan module.
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
# W6 live producer: defillama tag + W1 mint the seed witness
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


@pytest.mark.parametrize(
    ("address", "sources", "code", "state"),
    [
        pytest.param(ADDR(0x2F1), ["exa_deep_research"], "0x6001", None, id="without_defillama_tag"),
        pytest.param(ADDR(0x2F2), ["defillama"], "0x", "pruned", id="defillama_nomination_fails_w1"),
    ],
)
def test_probe_pass_no_w6(db_session, monkeypatch, erpc_env, address, sources, code, state):
    protocol = _protocol(db_session)
    candidate = _contract(db_session, address, nominated_protocol_id=protocol.id, discovery_sources=sources)
    db_session.flush()
    _stub_probe_wire(monkeypatch, code=code)

    run_probe_pass(db_session, protocol.id)

    assert _w6_rows(db_session, candidate.id) == []
    assert candidate.protocol_id is None
    if state is not None:
        assert gate.resolve_membership_state(db_session, candidate) == state


def test_gate_intake_seeds_w6_for_already_probed_defillama_row(db_session, monkeypatch, erpc_env):
    # Intake must seed W6 from the persisted code fact, not only a fresh probe.
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


def test_listing_seed_mints_w6_only_with_a_code_present_probe(db_session):
    """The tag alone mints nothing, and a code-absent probe mints nothing."""
    protocol = _protocol(db_session)
    unprobed = _contract(db_session, ADDR(0x2F6), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    db_session.flush()
    assert gate.seed_llama_witness(db_session, contract=unprobed) is False
    assert _w6_rows(db_session, unprobed.id) == []

    empty = _contract(db_session, ADDR(0x2F7), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    db_session.add(
        ContractCreationWitness(chain_id=1, address=empty.address, code_probe_block=91, code_absent_at_probe=True)
    )
    db_session.flush()
    assert gate.seed_llama_witness(db_session, contract=empty) is False
    assert _w6_rows(db_session, empty.id) == []

    token = _contract(db_session, ADDR(0x2F8), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    db_session.add(
        ContractCreationWitness(chain_id=1, address=token.address, code_probe_block=92, code_absent_at_probe=False)
    )
    db_session.flush()
    assert gate.seed_llama_witness(db_session, contract=token) is True
    (w6,) = _w6_rows(db_session, token.id)
    assert w6.evidence["code_probe_block"] == 92


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
# chain-enable boot sweep
# ---------------------------------------------------------------------------


@pytest.fixture()
def _clean_marker(db_session):
    db_session.execute(delete(OpsKv).where(OpsKv.key == ENABLED_CHAINS_SEEN_KEY))
    db_session.commit()
    yield
    db_session.execute(delete(OpsKv).where(OpsKv.key == ENABLED_CHAINS_SEEN_KEY))
    db_session.commit()


@pytest.mark.parametrize("pre_seeded", [False, True], ids=["first_boot", "unchanged"])
def test_boot_sweep_seeds_marker_and_never_probes_without_a_new_chain(
    db_session, monkeypatch, _clean_marker, pre_seeded
):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    if pre_seeded:
        db_session.add(OpsKv(key=ENABLED_CHAINS_SEEN_KEY, value=[1]))
        db_session.commit()

    def no_wire(*args, **kwargs):
        raise AssertionError("first boot / unchanged allowlist must not probe")

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


# ---------------------------------------------------------------------------
# ladder wire: kept enumerations
# ---------------------------------------------------------------------------


def _counting_wire(monkeypatch, txs_by_deployer_chain: dict[tuple[str, int], list], creations: dict[str, dict]):
    """One Etherscan stub for enumeration (``txlist``/``txlistinternal``) and creation lookups. Returns the per
    ``(deployer, chain)`` ``txlist`` call counter."""
    txlist_calls: dict[tuple[str, int], int] = {}

    def fake_get(module, action, chain_id, empty_result_ok=False, **params):
        if action == "txlist":
            key = (params["address"].lower(), chain_id)
            txlist_calls[key] = txlist_calls.get(key, 0) + 1
            return {"result": txs_by_deployer_chain.get(key, [])}
        if action == "txlistinternal":
            return {"result": []}
        assert action == "getcontractcreation"
        wanted = params["contractaddresses"].split(",")
        return {"result": [creations[a] for a in wanted if a in creations]}

    monkeypatch.setattr(deployer_enumeration.etherscan, "get", fake_get)
    return txlist_calls


def _block_tx(tx: dict, block: int, *, confirmations: int = 10_000) -> dict:
    return {**tx, "blockNumber": str(block), "confirmations": str(confirmations)}


def _anchored_members(session, protocol, eoa: str, base: int) -> list[Contract]:
    members = []
    for n in (base, base + 1):
        anchor = _contract(session, ADDR(n + 0x100), protocol_id=protocol.id)
        member = _contract(session, ADDR(n), protocol_id=protocol.id, deployer=eoa)
        _seed_w2(session, member, anchor, protocol.id)
        members.append(member)
    return members


def _probed_candidate(session, protocol, eoa: str, n: int, *, chain: str = "ethereum") -> Contract:
    """A probed, code-present candidate deployed by *eoa*, holding a stale W2 so a Class-B row maps it and W4 admits."""
    chain_id = 1 if chain == "ethereum" else 8453
    candidate = _contract(session, ADDR(n), chain=chain, nominated_protocol_id=protocol.id, deployer=eoa)
    session.add(
        ContractProbeAttempt(contract_id=candidate.id, chain_id=chain_id, block_number=90, results={"status": "probed"})
    )
    session.add(
        ContractCreationWitness(
            chain_id=chain_id,
            address=candidate.address,
            creation_tx_hash="0x" + f"{n:064x}",
            creation_block=50,
            code_probe_block=90,
            code_absent_at_probe=False,
        )
    )
    _seed_w1(session, candidate, protocol.id, chain_id=chain_id)
    _seed_stale_w2(session, candidate, _contract(session, ADDR(n + 0x100), protocol_id=protocol.id), protocol.id)
    return candidate


def _sent_txs(eoa: str, count: int) -> list[dict]:
    return [_call_tx(eoa, tx_hash="0x" + f"{0x7000 + n:064x}", confirmations="10000") for n in range(count)]


def _forget_kept_enumerations(session) -> None:
    from db.models import DeployerChainEnumeration

    session.query(DeployerChainEnumeration).delete()
    session.commit()


@pytest.mark.parametrize("arm", ["kept", "not_kept"])
def test_kept_enumerations_admit_and_refuse_exactly_as_fresh_ones(db_session, monkeypatch, arm):
    """Same members admitted and refused with or without kept enumerations; with them, one ``txlist`` per deployer
    and chain however many contracts arrive."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    protocol = _protocol(db_session)
    complete_eoa, storm_eoa = ADDR(0x5A0), ADDR(0x5B0)
    complete_members = _anchored_members(db_session, protocol, complete_eoa, 0x5A1)
    storm_members = _anchored_members(db_session, protocol, storm_eoa, 0x5B1)
    admitted = [_probed_candidate(db_session, protocol, complete_eoa, 0x5C0 + n) for n in range(4)]
    refused = [_probed_candidate(db_session, protocol, storm_eoa, 0x5D0 + n) for n in range(3)]
    refused += [_probed_candidate(db_session, protocol, storm_eoa, 0x5E0 + n, chain="base") for n in range(3)]
    db_session.commit()
    txlist_calls = _counting_wire(
        monkeypatch,
        {
            (complete_eoa, 1): [_creation_tx(c.address) for c in (*complete_members, *admitted)],
            (storm_eoa, 1): [_creation_tx(c.address) for c in (*storm_members, *refused[:3])]
            + _sent_txs(storm_eoa, deployer_enumeration.INTERNAL_RESOLUTION_TX_BUDGET + 1),
            (storm_eoa, 8453): [_creation_tx(c.address) for c in refused[3:]],
        },
        creations={},
    )

    for candidate in (*admitted, *refused):
        if arm == "not_kept":
            _forget_kept_enumerations(db_session)
        job = _job(db_session, protocol_id=protocol.id, address=candidate.address)
        _gate_intake(db_session, job, candidate, {})

    for row in (*admitted, *refused):
        db_session.refresh(row)
    assert [c.protocol_id for c in admitted] == [protocol.id] * 4
    assert [c.protocol_id for c in refused] == [None] * 6
    registry = {
        (r.address, r.trust_class)
        for r in db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.protocol_id == protocol.id))
        .scalars()
        .all()
    }
    assert registry == {(complete_eoa, "B")}
    if arm == "not_kept":
        assert txlist_calls[(storm_eoa, 1)] >= len(refused)
    else:
        assert txlist_calls == {(complete_eoa, 1): 1, (complete_eoa, 8453): 1, (storm_eoa, 1): 1, (storm_eoa, 8453): 1}


def _kept(session, eoa: str, chain_id: int):
    from db.models import DeployerChainEnumeration

    session.expire_all()
    return session.get(DeployerChainEnumeration, (chain_id, eoa))


def test_internal_budget_outcome_is_kept_incomplete_until_the_budget_covers_it(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x600)
    created = ADDR(0x601)
    _contract(db_session, created, deployer=eoa)
    db_session.commit()
    sent = deployer_enumeration.INTERNAL_RESOLUTION_TX_BUDGET + 1
    calls = _counting_wire(monkeypatch, {(eoa, 1): [_creation_tx(created), *_sent_txs(eoa, sent)]}, creations={})

    for _ in range(3):
        creations, scope, complete, gap, _as_of = deployer_enumeration.enumerate_with_coverage(db_session, eoa)
        assert (creations, scope, complete, gap) == ([], [], False, None)
    assert calls == {(eoa, 1): 1}
    kept = _kept(db_session, eoa, 1)
    assert kept is not None and (kept.outcome, kept.observed_count, kept.creations) == (
        "internal_budget_exceeded",
        sent,
        None,
    )

    monkeypatch.setattr(deployer_enumeration, "INTERNAL_RESOLUTION_TX_BUDGET", sent)
    _creations, scope, complete, _gap, _as_of = deployer_enumeration.enumerate_with_coverage(db_session, eoa)
    assert calls == {(eoa, 1): 2}
    assert (scope, complete) == ([1], True)


def test_a_failed_enumeration_is_never_kept(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x610)
    calls = _stub_txlist(monkeypatch, {1: RuntimeError("etherscan down")})

    for _ in range(2):
        assert deployer_enumeration.enumerate_with_coverage(db_session, eoa)[:4] == ([], [], False, None)

    assert len(calls) == 2
    assert _kept(db_session, eoa, 1) is None


def test_complete_enumeration_stands_until_a_newer_creation_claims_the_deployer(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x620)
    first, inside, newer, unplaced = ADDR(0x621), ADDR(0x622), ADDR(0x623), ADDR(0x624)
    _contract(db_session, first, deployer=eoa)
    db_session.commit()
    window = [_block_tx(_creation_tx(first), 100), _block_tx(_call_tx(eoa, tx_hash="0x" + "61" * 32), 200)]
    calls = _counting_wire(monkeypatch, {(eoa, 1): window}, creations={})

    assert deployer_enumeration.enumerate_with_coverage(db_session, eoa)[1:4] == ([1], True, None)
    kept = _kept(db_session, eoa, 1)
    assert kept is not None and (kept.outcome, kept.settled_through_block) == ("complete", 200)

    # A listed contract, or one created inside the settled range (an attribution gap, not new history), changes
    # nothing a fresh enumeration would say.
    _contract(db_session, inside, deployer=eoa)
    db_session.add(ContractCreationWitness(chain_id=1, address=inside, creation_tx_hash=_TX, creation_block=150))
    db_session.commit()
    assert deployer_enumeration.enumerate_with_coverage(db_session, eoa)[2:4] == (
        False,
        f"known_creation_missing_from_enumeration:{inside}",
    )
    assert calls == {(eoa, 1): 1}

    _contract(db_session, newer, deployer=eoa)
    db_session.add(ContractCreationWitness(chain_id=1, address=newer, creation_tx_hash=_TX, creation_block=201))
    db_session.commit()
    deployer_enumeration.enumerate_with_coverage(db_session, eoa)
    assert calls == {(eoa, 1): 2}

    db_session.query(Contract).filter(Contract.address.in_([inside, newer])).delete()
    _contract(db_session, unplaced, deployer=eoa)
    db_session.commit()
    deployer_enumeration.enumerate_with_coverage(db_session, eoa)
    deployer_enumeration.enumerate_with_coverage(db_session, eoa)
    assert calls == {(eoa, 1): 4}


def _class_b_then_a_foreign_creation(db_session, monkeypatch, eoa: str, base: int):
    """A Class-B row for *eoa*, after which the EOA deploys a contract that never enters our DB."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    members = _anchored_members(db_session, protocol, eoa, base)
    db_session.commit()
    window = [_block_tx(_creation_tx(m.address), 100 + n) for n, m in enumerate(members)]
    calls = _counting_wire(monkeypatch, {(eoa, 1): window}, creations={})
    first = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)
    db_session.commit()
    assert first is not None and first.trust_class == "B"
    window.append(_block_tx(_creation_tx(ADDR(base + 0x80)), 300))
    return protocol, calls, first


def _age_kept_enumerations(session, eoa: str, seconds: int) -> None:
    from sqlalchemy import func, update

    from db.models import DeployerChainEnumeration

    session.execute(
        update(DeployerChainEnumeration)
        .where(DeployerChainEnumeration.deployer == eoa)
        .values(enumerated_at=func.now() - text(f"interval '{seconds} seconds'"))
    )
    session.commit()


def test_a_complete_enumeration_past_the_reuse_window_is_redone_and_its_foreign_creation_revokes(
    db_session, monkeypatch
):
    eoa = ADDR(0x7A0)
    protocol, calls, _first = _class_b_then_a_foreign_creation(db_session, monkeypatch, eoa, 0x7A1)
    _age_kept_enumerations(db_session, eoa, probes.CREATION_ABSENCE_REVALIDATE_S + 1)

    assert _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa) is None
    db_session.commit()

    assert calls == {(eoa, 1): 2}
    rows = (
        db_session.execute(
            select(ProtocolDeployer).where(ProtocolDeployer.protocol_id == protocol.id, ProtocolDeployer.address == eoa)
        )
        .scalars()
        .all()
    )
    assert [(r.trust_class, r.revocation_reason) for r in rows] == [("B", "foreign_or_unknown_creations")]


def test_a_reused_complete_enumeration_publishes_when_it_ran(db_session, monkeypatch):
    from datetime import datetime

    eoa = ADDR(0x7B0)
    protocol, calls, first = _class_b_then_a_foreign_creation(db_session, monkeypatch, eoa, 0x7B1)
    first_chains = first.evidence["enumeration"]["chains"]
    _age_kept_enumerations(db_session, eoa, 60)
    kept = _kept(db_session, eoa, 1)
    assert kept is not None

    second = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)
    db_session.commit()

    assert calls == {(eoa, 1): 1}
    assert second is not None and second.trust_class == "B"
    (chain,) = second.evidence["enumeration"]["chains"]
    assert (chain["chain_id"], chain["settled_through_block"]) == (1, 101)
    assert datetime.fromisoformat(chain["enumerated_at"]) == kept.enumerated_at
    assert datetime.fromisoformat(chain["enumerated_at"]) < datetime.fromisoformat(first_chains[0]["enumerated_at"])


def test_an_immature_internal_trace_ends_the_settled_range_before_it(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x630)
    window = [
        _block_tx(_creation_tx(ADDR(0x631)), 100),
        _block_tx(_call_tx(eoa, tx_hash="0x" + "62" * 32), 300, confirmations=2),
        _block_tx(_call_tx(eoa, tx_hash="0x" + "63" * 32), 400),
    ]
    _counting_wire(monkeypatch, {(eoa, 1): window}, creations={})

    deployer_enumeration.enumerate_with_coverage(db_session, eoa)

    kept = _kept(db_session, eoa, 1)
    assert kept is not None and kept.settled_through_block == 299


def test_a_slow_enumeration_runs_to_completion(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    eoa = ADDR(0x640)
    internal_calls: list[str] = []

    def slow_get(module, action, chain_id, empty_result_ok=False, **params):
        if action == "txlist":
            return {"result": [_creation_tx(ADDR(0x641)), *_sent_txs(eoa, 5)] if chain_id == 1 else []}
        internal_calls.append(params["txhash"])
        time.sleep(0.05)
        return {"result": []}

    monkeypatch.setattr(deployer_enumeration.etherscan, "get", slow_get)

    creations, scope, complete, _gap, _as_of = deployer_enumeration.enumerate_with_coverage(db_session, eoa)
    assert len(internal_calls) == 5
    assert (scope, complete) == ([1, 8453], True)
    assert [c.address for c in creations] == [ADDR(0x641)]
    assert _kept(db_session, eoa, 1).outcome == "complete"


def test_concurrent_enumerations_of_one_deployer_keep_one_row(db_session, monkeypatch):
    from db.models import DeployerChainEnumeration

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    eoa = ADDR(0x650)
    barrier = Barrier(2)

    def get(module, action, chain_id, empty_result_ok=False, **params):
        barrier.wait(timeout=5)
        return {"result": [_creation_tx(ADDR(0x651))]}

    monkeypatch.setattr(deployer_enumeration.etherscan, "get", get)
    engine = create_engine(DATABASE_URL)
    errors: list[BaseException] = []
    results: list[tuple] = []

    def enumerate_once() -> None:
        try:
            with Session(engine) as session:
                results.append(deployer_enumeration.enumerate_with_coverage(session, eoa)[1:3])
        except BaseException as exc:
            errors.append(exc)

    try:
        threads = [Thread(target=enumerate_once) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert not errors
        assert results == [([1], True), ([1], True)]
        rows = db_session.execute(select(DeployerChainEnumeration).where(DeployerChainEnumeration.deployer == eoa))
        assert [(r.chain_id, r.outcome) for r in rows.scalars()] == [(1, "complete")]
    finally:
        engine.dispose()
