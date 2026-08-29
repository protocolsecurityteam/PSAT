"""Corroboration probes (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §3.5), wire stubbed
at the transport boundary (``rpc_request`` / ``eth_call_batch`` /
``rpc_batch_request`` / ``etherscan.get``) — never the real network.
"""

from __future__ import annotations

import uuid

import pytest

from db.models import Contract, ContractCreationWitness, ContractProbeAttempt, Protocol
from services.clients.rpc import EthCallResult
from services.discovery import membership_gate as gate
from services.discovery import probes
from tests.conftest import ADDR, requires_postgres
from utils.evm import EIP1967_IMPL_SLOT, OWNER_SELECTOR

pytestmark = [requires_postgres]

_OWNER = ADDR(0xAA)
_IMPL = ADDR(0xBB)
_CREATOR = ADDR(0xCC)
_TX = "0x" + "12" * 32


def _word(address: str) -> str:
    return "0x" + "0" * 24 + address[2:]


_ZERO_WORD = "0x" + "0" * 64


def _protocol(session) -> Protocol:
    row = Protocol(name=f"proto-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _contract(session, address: str, *, chain: str = "ethereum", nominated: int | None = None) -> Contract:
    row = Contract(address=address.lower(), chain=chain, nominated_protocol_id=nominated)
    session.add(row)
    session.flush()
    return row


@pytest.fixture()
def erpc_env(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "http://erpc.test")


def _stub_wire(
    monkeypatch,
    *,
    code: str = "0x6001",
    owner_result: EthCallResult | None = None,
    authority_result: EthCallResult | None = None,
    impl_word: str = _ZERO_WORD,
    creation_result: list | None = None,
) -> dict:
    seen: dict = {"rpc": [], "calls": [], "batch": [], "etherscan": []}

    def fake_rpc_request(rpc_url, method, params, *args, **kwargs):
        seen["rpc"].append((method, params))
        if method == "eth_blockNumber":
            return hex(100)
        if method == "eth_getCode":
            return code
        raise AssertionError(f"unexpected rpc method {method}")

    def fake_eth_call_batch(rpc_url, calls, block_tag="latest", **kwargs):
        seen["calls"].append((tuple(c["data"] for c in calls), block_tag))
        results = []
        for call in calls:
            if call["data"] == OWNER_SELECTOR:
                results.append(owner_result or EthCallResult(False, "0x", None, "execution reverted"))
            else:
                results.append(authority_result or EthCallResult(False, "0x", None, "execution reverted"))
        return results

    def fake_rpc_batch_request(rpc_url, calls, *args, **kwargs):
        seen["batch"].append(calls)
        out = []
        for method, params in calls:
            assert method == "eth_getStorageAt"
            out.append(impl_word if params[1] == EIP1967_IMPL_SLOT else _ZERO_WORD)
        return out

    def fake_etherscan_get(module, action, chain_id, **params):
        seen["etherscan"].append((module, action, chain_id, params))
        return {"result": creation_result if creation_result is not None else []}

    monkeypatch.setattr(probes, "rpc_request", fake_rpc_request)
    monkeypatch.setattr(probes, "eth_call_batch", fake_eth_call_batch)
    monkeypatch.setattr(probes, "rpc_batch_request", fake_rpc_batch_request)
    monkeypatch.setattr(probes.etherscan, "get", fake_etherscan_get)
    return seen


def test_probe_persists_code_creation_and_reads(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(0x100), nominated=protocol.id)
    seen = _stub_wire(
        monkeypatch,
        owner_result=EthCallResult(True, _word(_OWNER), None, None),
        impl_word=_word(_IMPL),
        creation_result=[
            {"contractAddress": row.address, "txHash": _TX, "blockNumber": "55", "contractCreator": _CREATOR}
        ],
    )

    result = gate.probe(db_session, row)

    assert result.routable is True
    assert result.block_number == 100
    assert result.code_present is True
    assert result.owner == _OWNER
    assert result.authority is None
    assert result.implementation == _IMPL
    assert result.creation_tx_hash == _TX
    assert result.creation_block == 55
    assert result.deployer == _CREATOR
    assert set(result.resolved_addresses) == {_OWNER, _IMPL}
    # Deployer learned by the probe lands on the row.
    assert row.deployer == _CREATOR

    witness = db_session.get(ContractCreationWitness, (1, row.address))
    assert witness is not None
    assert witness.code_probe_block == 100
    assert witness.code_absent_at_probe is False
    assert witness.creation_tx_hash == _TX
    assert witness.creation_block == 55

    attempt = db_session.get(ContractProbeAttempt, (row.id, 1))
    assert attempt is not None
    assert attempt.block_number == 100
    assert attempt.results["status"] == "probed"
    assert set(attempt.results["resolved_addresses"]) == {_OWNER, _IMPL}
    # Reads are pinned at the block the probe read.
    assert all(tag == hex(100) for _data, tag in seen["calls"])


def test_probe_code_absent_prunes_with_proof(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(0x101), nominated=protocol.id)
    seen = _stub_wire(monkeypatch, code="0x")

    result = gate.probe(db_session, row)

    assert result.code_present is False
    witness = db_session.get(ContractCreationWitness, (1, row.address))
    assert witness is not None and witness.code_absent_at_probe is True
    assert witness.code_probe_block == 100
    # No resolution reads against an empty address.
    assert seen["calls"] == [] and seen["batch"] == []
    assert gate.resolve_membership_state(db_session, row) == "pruned"


def test_probe_unroutable_chain_is_recorded_not_silent(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(0x102), chain="unknown", nominated=protocol.id)
    seen = _stub_wire(monkeypatch)

    result = gate.probe(db_session, row)

    assert result.routable is False
    assert result.code_present is None
    assert seen["rpc"] == [] and seen["etherscan"] == []
    attempt = db_session.get(ContractProbeAttempt, (row.id, probes.UNRESOLVABLE_CHAIN_ID))
    assert attempt is not None
    assert attempt.results["status"] == "not_routable"
    assert attempt.results["chain"] == "unknown"


def test_probe_rpc_failure_is_an_attempt_not_a_verdict(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(0x103), nominated=protocol.id)
    _stub_wire(monkeypatch)

    def boom(*args, **kwargs):
        raise RuntimeError("RPC request failed")

    monkeypatch.setattr(probes, "rpc_request", boom)

    result = gate.probe(db_session, row)

    assert result.routable is True
    assert result.code_present is None
    # A transport failure never writes a code verdict.
    assert db_session.get(ContractCreationWitness, (1, row.address)) is None
    attempt = db_session.get(ContractProbeAttempt, (row.id, 1))
    assert attempt is not None and attempt.results["status"] == "rpc_error"
    assert gate.resolve_membership_state(db_session, row) == "candidate"


def test_probe_reads_resolving_nowhere_keep_parked_explainable(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(0x104), nominated=protocol.id)
    _stub_wire(monkeypatch)  # owner/authority revert, slots zero, no creation answer

    result = gate.probe(db_session, row)

    assert result.code_present is True
    assert result.resolved_addresses == ()
    attempt = db_session.get(ContractProbeAttempt, (row.id, 1))
    assert attempt is not None
    reads = attempt.results["reads"]
    assert reads["owner"]["ok"] is False and reads["owner"]["value"] is None
    assert reads["implementation"]["ok"] is True and reads["implementation"]["value"] is None
    assert attempt.results["resolved_addresses"] == []


@pytest.mark.parametrize("bad_code", [None, 42, "not-hex", "0xzz", "0x123"])
def test_probe_malformed_getcode_never_mints_a_verdict(db_session, monkeypatch, erpc_env, bad_code):
    # Only a well-formed hex string is a code verdict; None / missing /
    # garbage / odd-length hex must never prove presence OR absence.
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(0x110), nominated=protocol.id)
    _stub_wire(monkeypatch, code=bad_code)

    result = gate.probe(db_session, row)

    assert result.routable is True
    assert result.code_present is None
    assert db_session.get(ContractCreationWitness, (1, row.address)) is None
    attempt = db_session.get(ContractProbeAttempt, (row.id, 1))
    assert attempt is not None and attempt.results["status"] == "rpc_error"
    assert gate.resolve_membership_state(db_session, row) == "candidate"


def test_failed_reprobe_preserves_last_good_results(db_session, monkeypatch, erpc_env):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(0x112), nominated=protocol.id)
    _stub_wire(monkeypatch, owner_result=EthCallResult(True, _word(_OWNER), None, None))
    gate.probe(db_session, row)
    attempt = db_session.get(ContractProbeAttempt, (row.id, 1))
    assert attempt is not None and _OWNER in attempt.results["resolved_addresses"]

    def boom(*args, **kwargs):
        raise RuntimeError("RPC request failed")

    monkeypatch.setattr(probes, "rpc_request", boom)
    gate.probe(db_session, row)

    # The failed attempt lands as last_error; the good reads survive.
    attempt = db_session.get(ContractProbeAttempt, (row.id, 1))
    assert attempt is not None
    assert attempt.results["status"] == "probed"
    assert _OWNER in attempt.results["resolved_addresses"]
    assert attempt.results["last_error"]["status"] == "rpc_error"
    assert attempt.block_number == 100
    # Targeted lookup still reaches the candidate through the preserved reads.
    result = gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(_OWNER,)))
    assert row.id in result.targeted_contract_ids


def test_fetch_creations_batches_five_per_call(db_session, monkeypatch):
    addresses = [ADDR(0x200 + n) for n in range(7)]
    calls: list[str] = []

    def fake_etherscan_get(module, action, chain_id, **params):
        assert (module, action) == ("contract", "getcontractcreation")
        batch = params["contractaddresses"].split(",")
        assert len(batch) <= 5
        calls.append(params["contractaddresses"])
        return {
            "result": [
                {"contractAddress": a, "txHash": _TX, "blockNumber": "7", "contractCreator": _CREATOR} for a in batch
            ]
        }

    monkeypatch.setattr(probes.etherscan, "get", fake_etherscan_get)
    out = probes.fetch_creations(db_session, addresses, chain_id=1)

    assert len(calls) == 2
    assert set(out) == {a.lower() for a in addresses}
    witness = db_session.get(ContractCreationWitness, (1, addresses[0].lower()))
    assert witness is not None and witness.creation_tx_hash == _TX and witness.creation_block == 7
