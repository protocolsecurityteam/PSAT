"""Governance collection inputs survive validation with bounded identities."""

import pytest
from pydantic import ValidationError

from schemas.api_requests import AnalyzeRequest


def test_governance_request_normalizes_and_preserves_ids():
    request = AnalyzeRequest(
        address="0x" + "11" * 20,
        collect_governance=True,
        proposal_ids=[7, 7, 9],
        operation_ids=["0x" + "AB" * 32],
    )
    assert request.proposal_ids == [7, 9]
    assert request.operation_ids == ["0x" + "ab" * 32]
    assert request.model_dump()["collect_governance"] is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("proposal_ids", [-1]),
        ("proposal_ids", [2**256]),
        ("operation_ids", ["0x1234"]),
    ],
)
def test_governance_request_rejects_invalid_ids(field, value):
    with pytest.raises(ValidationError):
        AnalyzeRequest(address="0x" + "11" * 20, **{field: value})


def test_scenario_requires_complete_verified_proposal_reference():
    request = AnalyzeRequest(
        address="0x" + "11" * 20,
        scenario_proposal_id=7,
        scenario_proposal_transaction_hash="0x" + "AB" * 32,
        scenario_sender="0x" + "BB" * 20,
    )
    assert request.scenario_proposal_transaction_hash == "0x" + "ab" * 32
    assert request.scenario_sender == "0x" + "bb" * 20
    with pytest.raises(ValidationError):
        AnalyzeRequest(address="0x" + "11" * 20, scenario_proposal_id=7)
