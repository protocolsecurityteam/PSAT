"""A contract allocated at genesis (an L2 predeploy) has no creation tx and no deployer.

Etherscan answers ``getcontractcreation`` for a predeploy with ``contractCreator: "GENESIS"`` and
``txHash: "GENESIS_<address>"``. Neither is an address or a tx hash, so neither may reach a deployer or creation-tx
column. The wire is stubbed at HTTP (Etherscan) and ``rpc_request`` (the probe); everything else is real.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from db.models import (
    WITNESS_RULE_W1_CODE,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ProtocolDeployer,
)
from db.queue import create_job
from services.clients import etherscan
from services.clients.rpc import EthCallResult
from services.discovery import probes
from services.discovery.deployer import _batch_get_creators
from tests.conftest import requires_postgres
from tests.support.membership_builders import _protocol

pytestmark = [requires_postgres]

PREDEPLOY = "0x4200000000000000000000000000000000000006"
NORMAL = "0x" + "c0" * 20
NORMAL_CREATOR = "0x" + "4f" * 20
NORMAL_TX = "0x" + "b9" * 32

_SOURCE = {
    "ContractName": "WETH9",
    "SourceCode": "pragma solidity ^0.5.17;\ncontract WETH9 { }",
    "CompilerVersion": "v0.5.17+commit.d19bba13",
    "OptimizationUsed": "1",
    "Runs": "200",
    "EVMVersion": "istanbul",
    "LicenseType": "GNU GPLv3",
}


def _genesis_record(address: str) -> dict[str, Any]:
    return {
        "contractAddress": address,
        "contractCreator": "GENESIS",
        "txHash": f"GENESIS_{address[2:]}",
        "blockNumber": "0",
        "timestamp": "1686789347",
        "contractFactory": "",
        "creationBytecode": "0x60806040",
    }


def _normal_record(address: str) -> dict[str, Any]:
    return {
        "contractAddress": address,
        "contractCreator": NORMAL_CREATOR,
        "txHash": NORMAL_TX,
        "blockNumber": "4719568",
        "timestamp": "1513077455",
        "contractFactory": "",
        "creationBytecode": "0x6060",
    }


class _Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


@pytest.fixture()
def etherscan_wire(monkeypatch):
    """``records[address]`` answers ``getcontractcreation``; every source fetch answers ``_SOURCE``."""
    records: dict[str, dict[str, Any]] = {}
    calls: list[dict[str, Any]] = []

    def get(_url, params=None, timeout=None):
        params = dict(params or {})
        calls.append(params)
        if params.get("action") == "getsourcecode":
            return _Response({"status": "1", "message": "OK", "result": [dict(_SOURCE)]})
        assert params.get("action") == "getcontractcreation"
        wanted = [a.lower() for a in params["contractaddresses"].split(",")]
        found = [records[a] for a in wanted if a in records]
        if not found:
            return _Response({"status": "0", "message": "No data found", "result": None})
        return _Response({"status": "1", "message": "OK", "result": found})

    monkeypatch.setattr(etherscan.requests, "get", get)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "k")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
    monkeypatch.setattr(etherscan, "_RATE_LIMIT_RETRIES", 0)
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", False)
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", False)
    return records, calls


@pytest.fixture()
def probe_wire(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "http://erpc.test")
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")

    def fake_rpc_request(rpc_url, method, params, *args, **kwargs):
        if method == "eth_blockNumber":
            return hex(30_000_000)
        if method == "eth_getCode":
            return "0x6080604052"
        raise AssertionError(f"unexpected rpc method {method}")

    def fake_eth_call_batch(rpc_url, calls, block_tag="latest", **kwargs):
        return [EthCallResult(False, "0x", None, "execution reverted") for _ in calls]

    def fake_rpc_batch_request(rpc_url, calls, *args, **kwargs):
        return ["0x" + "0" * 64 for _ in calls]

    monkeypatch.setattr(probes, "rpc_request", fake_rpc_request)
    monkeypatch.setattr(probes, "eth_call_batch", fake_eth_call_batch)
    monkeypatch.setattr(probes, "rpc_batch_request", fake_rpc_batch_request)


def _discover(session, address: str, protocol_id: int) -> Contract:
    from workers.discovery import DiscoveryWorker

    job = create_job(session, {"address": address, "chain": "base", "protocol_id": protocol_id})
    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    worker._process_address(session, job)
    session.expire_all()
    row = session.execute(select(Contract).where(Contract.address == address, Contract.chain == "base")).scalar_one()
    return row


def test_genesis_predeploy_completes_discovery_and_membership(db_session, etherscan_wire, probe_wire):
    records, _calls = etherscan_wire
    records[PREDEPLOY] = _genesis_record(PREDEPLOY)
    protocol = _protocol(db_session)
    db_session.commit()

    row = _discover(db_session, PREDEPLOY, protocol.id)

    assert row.deployer is None
    witness = db_session.get(ContractCreationWitness, (8453, PREDEPLOY))
    assert witness is not None
    assert (witness.creation_genesis, witness.creation_tx_hash, witness.creation_block) == (True, None, 0)
    assert witness.creation_factory is None
    assert (witness.code_absent_at_probe, witness.code_probe_block) == (False, 30_000_000)
    w1 = db_session.execute(
        select(ContractMembershipWitness).where(
            ContractMembershipWitness.contract_id == row.id, ContractMembershipWitness.rule == WITNESS_RULE_W1_CODE
        )
    ).scalar_one()
    assert w1.revoked_at is None
    assert (
        db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.protocol_id == protocol.id)).first() is None
    )


def test_normal_creator_is_unchanged(db_session, etherscan_wire, probe_wire):
    records, _calls = etherscan_wire
    records[NORMAL] = _normal_record(NORMAL)
    protocol = _protocol(db_session)
    db_session.commit()

    row = _discover(db_session, NORMAL, protocol.id)

    assert row.deployer == NORMAL_CREATOR
    witness = db_session.get(ContractCreationWitness, (8453, NORMAL))
    assert witness is not None
    assert (witness.creation_genesis, witness.creation_tx_hash, witness.creation_block) == (False, NORMAL_TX, 4719568)


def test_probe_reports_genesis_as_no_deployer(db_session, etherscan_wire, probe_wire):
    records, _calls = etherscan_wire
    records[PREDEPLOY] = _genesis_record(PREDEPLOY)
    protocol = _protocol(db_session)
    row = Contract(address=PREDEPLOY, chain="base", nominated_protocol_id=protocol.id)
    db_session.add(row)
    db_session.flush()

    result = probes.run_probe(db_session, row)

    assert result.created_at_genesis is True
    assert (result.deployer, result.creation_tx_hash, result.creation_block) == (None, None, 0)
    assert row.deployer is None


def test_creator_batch_lookup_names_no_genesis_deployer(etherscan_wire):
    records, _calls = etherscan_wire
    records[PREDEPLOY] = _genesis_record(PREDEPLOY)
    records[NORMAL] = _normal_record(NORMAL)

    assert _batch_get_creators([PREDEPLOY, NORMAL], chain_id=8453) == {NORMAL: NORMAL_CREATOR}


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        pytest.param(_genesis_record(PREDEPLOY), (True, None, None, 0), id="genesis_creator_and_tx_marker"),
        pytest.param(
            {**_genesis_record(PREDEPLOY), "contractCreator": "genesis"}, (True, None, None, 0), id="lowercase_marker"
        ),
        pytest.param(
            {**_genesis_record(PREDEPLOY), "contractCreator": ""}, (True, None, None, 0), id="tx_marker_alone"
        ),
        pytest.param(_normal_record(NORMAL), (False, NORMAL_CREATOR, NORMAL_TX, 4719568), id="normal"),
        pytest.param(
            {**_normal_record(NORMAL), "contractCreator": "not-an-address"},
            (False, None, NORMAL_TX, 4719568),
            id="malformed_creator_is_no_creator",
        ),
        pytest.param(
            {**_normal_record(NORMAL), "txHash": "0x1234"}, (False, NORMAL_CREATOR, None, 4719568), id="malformed_tx"
        ),
    ],
)
def test_creation_record_parsing(item, expected):
    record = etherscan.parse_creation_record(item)
    assert record is not None
    assert (record.genesis, record.creator, record.tx_hash, record.block) == expected


def test_upgrade_history_creation_witness_records_genesis_without_a_tx(db_session, etherscan_wire):
    from services.discovery import upgrade_history

    records, _calls = etherscan_wire
    records[PREDEPLOY] = _genesis_record(PREDEPLOY)

    written = upgrade_history._fetch_creation_witnesses(
        db_session, chain_id=8453, candidates={PREDEPLOY: (100, "0x" + "aa" * 32)}, rpc_url="http://erpc.test"
    )

    assert written == 1
    witness = db_session.get(ContractCreationWitness, (8453, PREDEPLOY))
    assert witness is not None
    assert (witness.creation_genesis, witness.creation_tx_hash, witness.creation_block) == (True, None, 0)
    assert witness.code_absent_at_probe is None
