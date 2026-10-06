import uuid
from datetime import datetime, timedelta, timezone

import pytest

from db.models import Contract, Job, JobStage, JobStatus, MonitoredContract, Protocol
from db.queue import store_artifact
from tests.conftest import requires_postgres

pytestmark = [requires_postgres, pytest.mark.usefixtures("_stub_live_authority")]


@pytest.fixture
def recovery_pair(db_session):
    address = "0x" + uuid.uuid4().hex + "11" * 4
    protocol = Protocol(name="recovery-boundary-" + uuid.uuid4().hex)
    db_session.add(protocol)
    db_session.flush()
    now = datetime.now(timezone.utc)
    original = Job(
        address=address,
        protocol_id=protocol.id,
        chain_id=1,
        request={"address": address, "chain": "ethereum"},
        status=JobStatus.completed,
        stage=JobStage.done,
        updated_at=now,
    )
    retry = Job(
        address=address,
        protocol_id=protocol.id,
        chain_id=1,
        request={"address": address, "chain": "ethereum", "effects_resume_work_id": 42},
        status=JobStatus.completed,
        stage=JobStage.done,
        updated_at=now + timedelta(minutes=1),
    )
    db_session.add_all([original, retry])
    db_session.flush()
    contract = Contract(address=address, chain="ethereum", protocol_id=protocol.id, job_id=original.id)
    db_session.add(contract)
    tree = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "f()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [{"source": "msg_sender"}],
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "key_sources": [{"source": "msg_sender"}],
                        "storage_var": "members",
                    },
                    "expression": "members[msg.sender]",
                    "basis": [],
                },
            }
        },
    }
    store_artifact(db_session, original.id, "predicate_trees", data=tree)
    store_artifact(db_session, original.id, "dependency_graph_viz", data={"nodes": [address]})
    db_session.commit()
    return protocol, contract, original, retry


@pytest.mark.parametrize("reader", ["capabilities", "membership", "signature", "artifact", "company", "listing"])
def test_public_analysis_readers_keep_full_analysis(api_client, db_session, recovery_pair, reader):
    from api import app
    from routers.deps import require_admin

    protocol, contract, original, retry = recovery_pair
    address = contract.address
    app.dependency_overrides[require_admin] = lambda: None
    try:
        if reader in ("membership", "signature"):
            who = "member" if reader == "membership" else "recovered_signer"
            response = api_client.post(
                f"/api/contract/{address}/probe/{reader}",
                json={
                    "function_signature": "f()",
                    "predicate_index": 0,
                    who: "0x" + "22" * 20,
                },
            )
        else:
            path = {
                "capabilities": f"/api/contract/{address}/capabilities",
                "artifact": f"/api/analyses/{address}/artifact/dependency_graph_viz",
                "company": f"/api/company/{protocol.name}/semantic_capabilities",
                "listing": "/api/analyses",
            }[reader]
            response = api_client.get(path)
        assert response.status_code == 200, response.text
        body = response.json()
        if reader == "capabilities":
            assert "f()" in body["capabilities"]
        elif reader == "company":
            assert "f()" in body["contracts"][address]
        elif reader == "artifact":
            assert body == {"nodes": [address]}
        elif reader == "listing":
            assert len([entry for entry in body if entry["address"] == address]) == 1
    finally:
        app.dependency_overrides.pop(require_admin, None)


def test_retry_does_not_suppress_real_state_change_reanalysis(db_session, recovery_pair):
    from services.monitoring.reanalysis import maybe_queue_reanalysis
    from services.resolution.deferred_reconciler import _address_has_active_job

    protocol, contract, original, retry = recovery_pair
    retry.status = JobStatus.queued
    retry.stage = JobStage.effects
    db_session.commit()
    assert not _address_has_active_job(db_session, contract.address, chain_id=1, exclude_job_id=original.id)
    monitored = MonitoredContract(
        address=contract.address, chain="ethereum", protocol_id=protocol.id, contract_id=contract.id
    )
    full = maybe_queue_reanalysis(db_session, monitored, "upgraded")
    assert full is not None and full.id != retry.id
    assert full.request is not None
    assert full.request["reanalysis_trigger"] == "upgraded"
    assert _address_has_active_job(db_session, contract.address, chain_id=1, exclude_job_id=original.id)
