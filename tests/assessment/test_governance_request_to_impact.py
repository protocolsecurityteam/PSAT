"""Scenario ingress can flow through the worker publication seam to impact."""

from __future__ import annotations

import uuid

from eth_utils.crypto import keccak

from db.models import Job, Protocol
from db.queue import publish_assessment_projection
from schemas.temporal_assessment import ConfigurationParameter
from services.assessment import governance_workflow
from services.assessment.governance import ChainPoint, record_configuration
from services.assessment.impact import build_proposal_impact
from services.effects.anvil import EthCallResult
from tests.assessment.test_temporal_repository import _assessment
from tests.conftest import requires_postgres

GOVERNOR = "0x" + "11" * 20
TARGET = "0x" + "22" * 20
SENDER = "0x" + "33" * 20


class Fork:
    def __init__(self, baseline):
        self.baseline = baseline
        self.executed = False

    def fork_block_number(self):
        return self.baseline["block_number"]

    def block_hash(self, _number):
        return self.baseline["block_hash"]

    def hardfork(self):
        return "prague"

    def versions(self):
        return {"anvil": "test"}

    def snapshot(self):
        return "snapshot"

    def revert(self, _snapshot):
        return True

    def impersonate(self, _sender):
        pass

    def stop_impersonate(self, _sender):
        pass

    def call(self, tx):
        if tx["to"] == TARGET and tx["data"] == governance_workflow._selector("getMinDelay()"):
            value = 21600 if self.executed else 172800
            return EthCallResult(True, "0x" + value.to_bytes(32, "big").hex(), None, None)
        if tx["to"] == GOVERNOR and tx["data"].startswith(
            governance_workflow._selector("execute(address[],uint256[],bytes[],bytes32)")
        ):
            return EthCallResult(True, "0x", None, None)
        return EthCallResult(False, "0x", None, "unsupported getter")

    def send(self, _tx):
        self.executed = True
        return "0x" + "ee" * 32

    def mine(self):
        pass

    def receipt(self, _tx_hash):
        return {"status": "0x1"}


@requires_postgres
def test_scenario_api_request_reaches_impact_with_full_proof(api_client, db_session, monkeypatch):
    company = f"scenario-{uuid.uuid4().hex[:10]}"
    db_session.add(Protocol(name=company))
    db_session.commit()
    # Far above JS's safe integer range. The browser sends a decimal string.
    proposal_id = 2**200 + 7
    response = api_client.post(
        "/api/analyze",
        json={
            "address": GOVERNOR,
            "chain": "ethereum",
            "company": company,
            "scenario_proposal_id": str(proposal_id),
            "scenario_proposal_transaction_hash": "0x" + "cc" * 32,
            "scenario_sender": SENDER,
        },
    )
    assert response.status_code == 200, response.text
    job = db_session.get(Job, uuid.UUID(response.json()["job_id"]))
    assert job is not None and job.request["scenario_proposal_id"] == proposal_id
    publish_assessment_projection(db_session, job.id, _assessment(GOVERNOR, 90))
    baseline: ChainPoint = {"chain_id": 1, "block_number": 110, "block_hash": "0x" + "ef" * 32}
    record_configuration(
        db_session,
        job.id,
        contract_address=GOVERNOR,
        point=baseline,
        parameter=ConfigurationParameter.minimum_delay,
        value=172800,
        unit="seconds",
        clock=None,
        source={"method": "getMinDelay"},
        implementation={"collector": "test"},
    )
    proposal = {
        "actions": [
            {
                "kind": "call",
                "chain_id": 1,
                "sender": GOVERNOR,
                "target": TARGET,
                "calldata": "0x11223344",
                "value": "0",
            }
        ],
        "description_hash": keccak(text="Reduce delay"),
        "source": {
            "transaction_hash": job.request["scenario_proposal_transaction_hash"],
            "block_number": 100,
            "block_hash": "0x" + "ab" * 32,
            "log_index": 0,
        },
    }
    monkeypatch.setattr(governance_workflow, "proposal_from_receipt", lambda **_kwargs: proposal)
    monkeypatch.setattr(governance_workflow, "_bind_creation_period", lambda *_args, **_kwargs: None)
    claims = governance_workflow.execute_proposal_scenario(
        db_session,
        job.id,
        rpc_url="http://localhost:8545",
        chain_id=1,
        governor=GOVERNOR,
        proposal_id=job.request["scenario_proposal_id"],
        proposal_transaction_hash=job.request["scenario_proposal_transaction_hash"],
        sender=job.request["scenario_sender"],
        baseline=baseline,
        transport=Fork(baseline),
    )
    assert len(claims) == 1
    impact = build_proposal_impact(db_session, company, [job])
    change = impact["changes"][0]
    assert (change["before"], change["after"]) == (172800, 21600)
    assert change["proof"]["complete"] is True
    assert len(change["proof"]["prerequisites"]) == 2
    assert change["proof"]["evidence"][0]["payload"]["data"]["execution"]["success"] is True

    class NoChangeFork(Fork):
        def send(self, _tx):
            return "0x" + "ee" * 32

    assert (
        governance_workflow.execute_proposal_scenario(
            db_session,
            job.id,
            rpc_url="http://localhost:8545",
            chain_id=1,
            governor=GOVERNOR,
            proposal_id=job.request["scenario_proposal_id"],
            proposal_transaction_hash=job.request["scenario_proposal_transaction_hash"],
            sender=job.request["scenario_sender"],
            baseline=baseline,
            transport=NoChangeFork(baseline),
        )
        == []
    )
    limitations = build_proposal_impact(db_session, company, [job])["limitations"]
    assert any(row["code"] == "incomplete_coverage" for row in limitations)

    class RevertFork(Fork):
        def call(self, tx):
            if tx["to"] == GOVERNOR and tx["data"].startswith(
                governance_workflow._selector("execute(address[],uint256[],bytes[],bytes32)")
            ):
                return EthCallResult(False, "0x", "0xdead", "proposal is not executable")
            return super().call(tx)

    assert (
        governance_workflow.execute_proposal_scenario(
            db_session,
            job.id,
            rpc_url="http://localhost:8545",
            chain_id=1,
            governor=GOVERNOR,
            proposal_id=job.request["scenario_proposal_id"],
            proposal_transaction_hash=job.request["scenario_proposal_transaction_hash"],
            sender=job.request["scenario_sender"],
            baseline=baseline,
            transport=RevertFork(baseline),
        )
        == []
    )
    limitations = build_proposal_impact(db_session, company, [job])["limitations"]
    assert any(row["code"] == "execution_failure" and "not executable" in row["message"] for row in limitations)

    class LostGetterFork(Fork):
        def call(self, tx):
            if self.executed and tx["to"] == TARGET:
                return EthCallResult(False, "0x", None, "getter unavailable")
            return super().call(tx)

    assert (
        governance_workflow.execute_proposal_scenario(
            db_session,
            job.id,
            rpc_url="http://localhost:8545",
            chain_id=1,
            governor=GOVERNOR,
            proposal_id=job.request["scenario_proposal_id"],
            proposal_transaction_hash=job.request["scenario_proposal_transaction_hash"],
            sender=job.request["scenario_sender"],
            baseline=baseline,
            transport=LostGetterFork(baseline),
        )
        == []
    )
    limitations = build_proposal_impact(db_session, company, [job])["limitations"]
    assert any(row["code"] == "incomplete_coverage" and "readback unavailable" in row["message"] for row in limitations)
