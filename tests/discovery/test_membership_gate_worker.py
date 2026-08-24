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
from services.discovery import membership_gate as gate
from services.discovery import probes
from tests.conftest import ADDR, requires_postgres
from utils.evm import OWNER_SELECTOR
from workers import discovery as worker_mod
from workers.discovery import (
    DEPLOYER_ENUMERATION_CAP,
    ENABLED_CHAINS_SEEN_KEY,
    _enumerate_deployer_creations,
    _gate_intake,
    _job_assertion,
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
) -> Contract:
    row = Contract(
        address=address.lower(),
        chain=chain,
        protocol_id=protocol_id,
        nominated_protocol_id=nominated_protocol_id,
        deployer=deployer,
        implementation=implementation,
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


def _stub_txlist(monkeypatch, txs_by_chain: dict[int, list | Exception]) -> list[tuple]:
    calls: list[tuple] = []

    def fake_get(module, action, chain_id, empty_result_ok=False, **params):
        calls.append((module, action, chain_id, params))
        assert (module, action) == ("account", "txlist")
        entry = txs_by_chain.get(chain_id, [])
        if isinstance(entry, Exception):
            raise entry
        return {"result": entry}

    monkeypatch.setattr(worker_mod.etherscan, "get", fake_get)
    return calls


def _creation_tx(target: str) -> dict:
    return {"to": "", "contractAddress": target, "hash": _TX}


# ---------------------------------------------------------------------------
# §3.3 ladder wire: enumeration
# ---------------------------------------------------------------------------


def test_enumeration_collects_direct_creations(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _stub_txlist(
        monkeypatch,
        {1: [_creation_tx(ADDR(0x201)), {"to": ADDR(0x999), "contractAddress": ""}, _creation_tx(ADDR(0x202))]},
    )
    created, complete = _enumerate_deployer_creations(ADDR(0x200))
    assert created == sorted([ADDR(0x201), ADDR(0x202)])
    assert complete is True


def test_enumeration_cap_exceeded_is_incomplete(monkeypatch):
    # A full txlist window is a truncation, never a complete history.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    window = [_creation_tx(ADDR(0x300 + n)) for n in range(3)] + [{"to": ADDR(0x999), "contractAddress": ""}] * (
        DEPLOYER_ENUMERATION_CAP - 3
    )
    _stub_txlist(monkeypatch, {1: window})
    created, complete = _enumerate_deployer_creations(ADDR(0x2FF))
    assert complete is False
    assert created == []


def test_enumeration_empty_or_failed_is_incomplete(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _stub_txlist(monkeypatch, {1: []})
    assert _enumerate_deployer_creations(ADDR(0x210)) == ([], False)
    _stub_txlist(monkeypatch, {1: RuntimeError("etherscan down")})
    assert _enumerate_deployer_creations(ADDR(0x210)) == ([], False)


def test_enumeration_any_enabled_chain_failing_is_incomplete(monkeypatch):
    # EOAs are chain-agnostic: completeness requires every enabled chain's
    # window to come back clean.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    _stub_txlist(monkeypatch, {1: [_creation_tx(ADDR(0x220))], 8453: RuntimeError("boom")})
    created, complete = _enumerate_deployer_creations(ADDR(0x221))
    assert created == [ADDR(0x220)]
    assert complete is False


# ---------------------------------------------------------------------------
# §3.3 ladder wire: registration
# ---------------------------------------------------------------------------


def _seed_class_b_shape(db_session, protocol, eoa: str) -> list[Contract]:
    members = []
    for n in (0x230, 0x231):
        anchor = _contract(db_session, ADDR(n + 0x100), protocol_id=protocol.id)
        member = _contract(db_session, ADDR(n), protocol_id=protocol.id, deployer=eoa)
        _seed_w2(db_session, member, anchor, protocol.id)
        members.append(member)
    return members


def test_ladder_wire_registers_class_b(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = _protocol(db_session)
    eoa = ADDR(0x240)
    members = _seed_class_b_shape(db_session, protocol, eoa)
    calls = _stub_txlist(monkeypatch, {1: [_creation_tx(m.address) for m in members]})

    row = _register_protocol_deployer(db_session, protocol_id=protocol.id, deployer=eoa)

    assert row is not None and row.trust_class == "B"
    assert row.evidence["enumeration"]["complete"] is True
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


def test_ladder_wire_class_a_skips_enumeration(db_session, monkeypatch):
    from db.models import ControllerValue

    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(0x270), protocol_id=protocol.id)
    eoa = ADDR(0x271)
    db_session.add(ControllerValue(contract_id=member.id, controller_id="owner", value=eoa))
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


# ---------------------------------------------------------------------------
# W5 assertion helper
# ---------------------------------------------------------------------------


def test_job_assertion_shapes():
    def job_with(request):
        return Job(id=uuid.uuid4(), request=request, status=JobStatus.queued, stage=JobStage.discovery)

    good = job_with({"human_assertion": {"actor": " admin@psat ", "asserted_at": "2026-08-24T00:00:00+00:00"}})
    assert _job_assertion(good) == {"actor": "admin@psat", "asserted_at": "2026-08-24T00:00:00+00:00"}
    assert _job_assertion(job_with({})) is None
    assert _job_assertion(job_with({"human_assertion": "admin"})) is None
    assert _job_assertion(job_with({"human_assertion": {"actor": " ", "asserted_at": "x"}})) is None
    assert _job_assertion(job_with({"human_assertion": {"actor": "admin"}})) is None


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
        "parent_owns_high": True,
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
        "parent_owns_high": True,
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
