"""Proposal event identity and fail-closed scenario publication guards."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import pytest
from eth_abi.abi import encode
from eth_utils.crypto import keccak
from sqlalchemy.orm import Session

from db.queue import publish_assessment_projection
from schemas.temporal_assessment import ConfigurationParameter
from services.assessment import governance_workflow as workflow
from services.assessment.governance import ChainPoint, record_configuration
from services.assessment.governance_collectors import collect_governance
from services.assessment.repository import load_temporal_assessment
from services.clients.rpc import rpc_request
from services.effects.anvil import SubprocessAnvil, anvil_available
from tests.assessment.test_temporal_repository import _assessment, _job
from tests.conftest import requires_postgres


def _event_fixture():
    governor = "0x" + "11" * 20
    target = "0x" + "22" * 20
    action = bytes.fromhex("11223344")
    description = "Reduce delay"
    description_hash = keccak(text=description)
    proposal_id = int.from_bytes(
        keccak(encode(["address[]", "uint256[]", "bytes[]", "bytes32"], [[target], [0], [action], description_hash])),
        "big",
    )
    block_hash = "0x" + "ab" * 32
    tx_hash = "0x" + "cd" * 32
    event = encode(
        workflow._PROPOSAL_TYPES,
        [proposal_id, governor, [target], [0], [""], [action], 105, 205, description],
    )
    receipt = {
        "status": "0x1",
        "blockNumber": "0x64",
        "blockHash": block_hash,
        "logs": [
            {"address": governor, "topics": [workflow._PROPOSAL_TOPIC], "data": "0x" + event.hex(), "logIndex": "0x0"}
        ],
    }
    baseline: ChainPoint = {"chain_id": 1, "block_number": 110, "block_hash": "0x" + "ef" * 32}
    return governor, target, proposal_id, tx_hash, block_hash, receipt, baseline


def test_proposal_actions_require_canonical_receipt_and_hash(monkeypatch):
    governor, target, proposal_id, tx_hash, block_hash, receipt, baseline = _event_fixture()

    def rpc(_url, method, _params, **_kwargs):
        return receipt if method == "eth_getTransactionReceipt" else {"hash": block_hash}

    monkeypatch.setattr(workflow, "rpc_request", rpc)
    found = workflow.proposal_from_receipt(
        rpc_url="http://localhost",
        chain_id=1,
        governor=governor,
        proposal_id=proposal_id,
        transaction_hash=tx_hash,
        baseline=baseline,
    )
    assert found["actions"] == [
        {"kind": "call", "chain_id": 1, "sender": governor, "target": target, "calldata": "0x11223344", "value": "0"}
    ]
    assert found["vote_end"] - found["vote_start"] == 100
    forged = encode(
        workflow._PROPOSAL_TYPES,
        [proposal_id + 1, governor, [target], [0], [""], [bytes.fromhex("11223344")], 105, 205, "Reduce delay"],
    )
    receipt["logs"][0]["data"] = "0x" + forged.hex()
    with pytest.raises(ValueError, match="hash to proposal id"):
        workflow.proposal_from_receipt(
            rpc_url="http://localhost",
            chain_id=1,
            governor=governor,
            proposal_id=proposal_id + 1,
            transaction_hash=tx_hash,
            baseline=baseline,
        )

    receipt["logs"][0]["data"] = (
        "0x"
        + encode(
            workflow._PROPOSAL_TYPES,
            [proposal_id, governor, [target], [0], [""], [bytes.fromhex("11223344")], 105, 205, "Reduce delay"],
        ).hex()
    )
    receipt["blockHash"] = "0x" + "ee" * 32
    with pytest.raises(ValueError, match="canonical"):
        workflow.proposal_from_receipt(
            rpc_url="http://localhost",
            chain_id=1,
            governor=governor,
            proposal_id=proposal_id,
            transaction_hash=tx_hash,
            baseline=baseline,
        )


def test_creation_binding_rejects_unsupported_clock_and_inconsistent_period(monkeypatch):
    governor, _target, proposal_id, _tx, block_hash, _receipt, _baseline = _event_fixture()
    proposal = {
        "vote_start": 105,
        "vote_end": 205,
        "source": {"block_hash": block_hash, "block_number": 100, "log_index": 0},
    }

    def attempt() -> None:
        workflow._bind_creation_period(
            cast(Session, None),
            None,
            rpc_url="http://localhost",
            chain_id=1,
            governor=governor,
            proposal_id=proposal_id,
            proposal=proposal,
            manifest={},
        )

    monkeypatch.setattr(
        workflow,
        "rpc_request",
        lambda *_args, **_kwargs: (
            "0x"
            + encode(
                ["string"],
                ["mode=timestamp"],
            ).hex()
        ),
    )
    with pytest.raises(ValueError, match="clock mode is unsupported"):
        attempt()

    def inconsistent(_url, _method, params, **_kwargs):
        if params[0]["data"] == workflow._selector("CLOCK_MODE()"):
            return "0x" + encode(["string"], ["mode=blocknumber&from=default"]).hex()
        return "0x" + encode(["uint256"], [99]).hex()

    monkeypatch.setattr(workflow, "rpc_request", inconsistent)
    with pytest.raises(ValueError, match="timing disagree"):
        attempt()


@requires_postgres
@pytest.mark.skipif(not anvil_available(), reason="anvil unavailable")
def test_verified_proposal_executes_on_local_fork_and_publishes_target_delta(db_session):
    fixture = Path(__file__).parents[1] / "fixtures/contracts/governance/proposal_scenario.sol"
    compiler = Path.home() / ".solc-select/artifacts/solc-0.8.10/solc-0.8.10"
    if not compiler.exists():
        pytest.skip("offline Solidity 0.8.10 compiler unavailable")
    result = subprocess.run(
        [str(compiler), "--combined-json", "abi,bin", str(fixture)],
        check=True,
        capture_output=True,
        text=True,
    )
    contracts = json.loads(result.stdout)["contracts"]
    governor_code = next(row["bin"] for key, row in contracts.items() if key.endswith(":ScenarioGovernor"))
    target_code = next(row["bin"] for key, row in contracts.items() if key.endswith(":ScenarioTarget"))
    port = workflow._available_port()
    sender = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    with SubprocessAnvil(port=port, hardfork_name="prague") as source:
        source_url = f"http://127.0.0.1:{port}"
        governor = source.deploy(sender, "0x" + governor_code)
        target = source.deploy(sender, "0x" + target_code + encode(["address"], [governor]).hex())
        action_data = workflow._selector("updateDelay(uint256)") + encode(["uint256"], [21600]).hex()
        propose_data = (
            workflow._selector("propose(address,bytes,string)")
            + encode(
                ["address", "bytes", "string"],
                [target, bytes.fromhex(action_data[2:]), "Reduce delay"],
            ).hex()
        )
        proposal_tx = source.send({"from": sender, "to": governor, "data": propose_data})
        source.mine()
        receipt = rpc_request(source_url, "eth_getTransactionReceipt", [proposal_tx], chain_id=31337)
        event_log = next(log for log in receipt["logs"] if log["topics"] == [workflow._PROPOSAL_TOPIC])
        proposal_id = int(workflow.decode(workflow._PROPOSAL_TYPES, bytes.fromhex(event_log["data"][2:]))[0])
        height = int(rpc_request(source_url, "eth_blockNumber", [], chain_id=31337), 16)
        block = rpc_request(source_url, "eth_getBlockByNumber", [hex(height), False], chain_id=31337)
        baseline: ChainPoint = {"chain_id": 31337, "block_number": height, "block_hash": block["hash"]}

        job = _job(db_session)
        publish_assessment_projection(db_session, job.id, _assessment("0x" + "aa" * 20, 90))
        collected = collect_governance(
            db_session,
            job.id,
            rpc_url=source_url,
            chain_id=31337,
            address=governor,
            proposal_ids=[proposal_id],
        )
        assert collected.point == baseline
        record_configuration(
            db_session,
            job.id,
            contract_address=target,
            point=baseline,
            parameter=ConfigurationParameter.minimum_delay,
            value=172800,
            unit="seconds",
            clock=None,
            source={"method": "getMinDelay"},
            implementation={"test": "local_anvil"},
        )
        db_session.commit()
        claims = workflow.execute_proposal_scenario(
            db_session,
            job.id,
            rpc_url=source_url,
            chain_id=31337,
            governor=governor,
            proposal_id=proposal_id,
            proposal_transaction_hash=proposal_tx,
            sender=sender,
            baseline=baseline,
        )
        assert claims
        observed = load_temporal_assessment(db_session, job.id)
        assert observed is not None
        assert not any(claim["id"] in claims for claim in observed["claims"])
        assert observed["view"]["scope"]["block_number"] == str(height)
        creation_height = int(receipt["blockNumber"], 16)
        historical = load_temporal_assessment(db_session, job.id, at_block=creation_height)
        assert historical is None or all(
            int(claim["scope"]["at"]["block_number"]) <= creation_height
            for claim in historical["claims"]
            if claim["scope"]["kind"] == "point"
        )

        # The second proposal is well formed but its target rejects the
        # Governor caller. The fork must report execution failure without a
        # scenario transition or moving observed current off the new baseline.
        denied_target = source.deploy(sender, "0x" + target_code + encode(["address"], [sender]).hex())
        denied_propose = (
            workflow._selector("propose(address,bytes,string)")
            + encode(
                ["address", "bytes", "string"],
                [denied_target, bytes.fromhex(action_data[2:]), "Denied delay"],
            ).hex()
        )
        denied_tx = source.send({"from": sender, "to": governor, "data": denied_propose})
        source.mine()
        denied_receipt = rpc_request(source_url, "eth_getTransactionReceipt", [denied_tx], chain_id=31337)
        denied_log = next(log for log in denied_receipt["logs"] if log["topics"] == [workflow._PROPOSAL_TOPIC])
        denied_id = int(workflow.decode(workflow._PROPOSAL_TYPES, bytes.fromhex(denied_log["data"][2:]))[0])
        denied_height = int(rpc_request(source_url, "eth_blockNumber", [], chain_id=31337), 16)
        denied_block = rpc_request(source_url, "eth_getBlockByNumber", [hex(denied_height), False], chain_id=31337)
        denied_baseline: ChainPoint = {
            "chain_id": 31337,
            "block_number": denied_height,
            "block_hash": denied_block["hash"],
        }
        record_configuration(
            db_session,
            job.id,
            contract_address=denied_target,
            point=denied_baseline,
            parameter=ConfigurationParameter.minimum_delay,
            value=172800,
            unit="seconds",
            clock=None,
            source={"method": "getMinDelay"},
            implementation={"test": "local_anvil"},
        )
        db_session.commit()
        assert (
            workflow.execute_proposal_scenario(
                db_session,
                job.id,
                rpc_url=source_url,
                chain_id=31337,
                governor=governor,
                proposal_id=denied_id,
                proposal_transaction_hash=denied_tx,
                sender=sender,
                baseline=denied_baseline,
            )
            == []
        )
        after_failure = load_temporal_assessment(db_session, job.id)
        assert after_failure is not None
        assert after_failure["view"]["scope"]["block_number"] == str(denied_height)
        assert any(
            diagnostic["code"].value == "execution_failure"
            for analysis in after_failure["analyses"]
            for diagnostic in analysis["diagnostics"]
        )

        # A value-bearing action needs msg.value on Governor.execute. The
        # changed getter is the witness that the payable action ran on fork.
        payable_data = workflow._selector("updateDelay(uint256)") + encode(["uint256"], [3600]).hex()
        value_propose = (
            workflow._selector("proposeValue(address,bytes,string,uint256)")
            + encode(
                ["address", "bytes", "string", "uint256"],
                [target, bytes.fromhex(payable_data[2:]), "Payable delay", 1],
            ).hex()
        )
        value_tx = source.send({"from": sender, "to": governor, "data": value_propose})
        source.mine()
        value_receipt = rpc_request(source_url, "eth_getTransactionReceipt", [value_tx], chain_id=31337)
        value_log = next(log for log in value_receipt["logs"] if log["topics"] == [workflow._PROPOSAL_TOPIC])
        value_id = int(workflow.decode(workflow._PROPOSAL_TYPES, bytes.fromhex(value_log["data"][2:]))[0])
        value_height = int(rpc_request(source_url, "eth_blockNumber", [], chain_id=31337), 16)
        value_block = rpc_request(source_url, "eth_getBlockByNumber", [hex(value_height), False], chain_id=31337)
        value_baseline: ChainPoint = {
            "chain_id": 31337,
            "block_number": value_height,
            "block_hash": value_block["hash"],
        }
        record_configuration(
            db_session,
            job.id,
            contract_address=target,
            point=value_baseline,
            parameter=ConfigurationParameter.minimum_delay,
            value=172800,
            unit="seconds",
            clock=None,
            source={"method": "getMinDelay"},
            implementation={"test": "local_anvil"},
        )
        db_session.commit()
        value_claims = workflow.execute_proposal_scenario(
            db_session,
            job.id,
            rpc_url=source_url,
            chain_id=31337,
            governor=governor,
            proposal_id=value_id,
            proposal_transaction_hash=value_tx,
            sender=sender,
            baseline=value_baseline,
        )
        current = load_temporal_assessment(db_session, job.id)
        assert current is not None
        assert value_claims, [item for analysis in current["analyses"] for item in analysis["diagnostics"]]
