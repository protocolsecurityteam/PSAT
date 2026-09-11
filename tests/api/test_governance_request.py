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
