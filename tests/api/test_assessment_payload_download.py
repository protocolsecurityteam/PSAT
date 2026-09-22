"""Evidence bytes are downloadable only through the selected assessment view."""

from __future__ import annotations

from db.models import AssessmentPayload
from db.queue import publish_assessment_projection
from schemas.temporal_assessment import ConfigurationParameter
from services.assessment.governance import ChainPoint, record_configuration, record_scenario_configuration
from services.assessment.repository import load_temporal_assessment
from tests.assessment.test_temporal_repository import ADDRESS, _assessment, _job
from tests.conftest import requires_postgres


def _point(block: int) -> ChainPoint:
    return {"chain_id": 1, "block_number": block, "block_hash": "0x" + f"{block:064x}"}


@requires_postgres
def test_payload_download_is_exact_and_scoped_to_job_and_context(api_client, db_session):
    first = _job(db_session)
    second = _job(db_session)
    for job in (first, second):
        publish_assessment_projection(db_session, job.id, _assessment(ADDRESS, 90))
    baseline = record_configuration(
        db_session,
        first.id,
        contract_address=ADDRESS,
        point=_point(100),
        parameter=ConfigurationParameter.minimum_delay,
        value="172800",
        unit="seconds",
        clock=None,
        source={"method": "getMinDelay"},
        implementation={"collector": "test"},
    )
    _, context_id = record_scenario_configuration(
        db_session,
        first.id,
        contract_address=ADDRESS,
        baseline=_point(100),
        step=1,
        parameter=ConfigurationParameter.minimum_delay,
        value="21600",
        unit="seconds",
        actions=[{"kind": "call", "target": ADDRESS, "calldata": "0x", "sender": ADDRESS, "value": "0"}],
        assumptions=[],
        prerequisite_claims=[baseline],
        implementation={"engine": "test"},
        execution={
            "success": True,
            "fork_block_number": 100,
            "transaction_hash": "0x" + "ee" * 32,
            "trace": "x" * 35000,
        },
    )
    db_session.commit()
    observed = load_temporal_assessment(db_session, first.id)
    scenario = load_temporal_assessment(db_session, first.id, context_id=context_id)
    assert observed is not None and scenario is not None
    scenario_evidence = next(
        evidence
        for evidence in scenario["evidence"]
        if evidence["id"]
        in {
            item
            for claim in scenario["claims"]
            if claim["scope_kind"].value == "scenario"
            for item in claim["evidence"]
        }
    )
    payload_id = scenario_evidence["payload"]
    raw = db_session.get(AssessmentPayload, payload_id).data
    assert len(raw) > 32 * 1024
    path = f"/api/analyses/{first.id}/assessment-payload/{payload_id}"
    result = api_client.get(path, params={"context_id": context_id})
    assert result.status_code == 200
    assert result.content == raw
    assert result.headers["content-type"].startswith("application/octet-stream")
    assert result.headers["x-content-type-options"] == "nosniff"
    assert result.headers["content-disposition"].startswith("attachment;")
    assert api_client.get(path).status_code == 404
    assert (
        api_client.get(
            f"/api/analyses/{second.id}/assessment-payload/{payload_id}", params={"context_id": context_id}
        ).status_code
        == 404
    )
