"""Selection uses evidence of material impact without pretending exact severity is settled."""

import copy

import pytest

from services.clients.jev import DEFAULT_MODEL
from services.resolution.logic_assessment import _decision
from services.resolution.logic_impact import ImpactPolicy, _estimate, validate_answer
from tests.logic.test_impact import inputs, response


def scored(probabilities, confidence=0):
    return {
        "type": "score",
        "score": sum(i * p for i, p in enumerate(probabilities)),
        "confidence": confidence,
        "probabilities": {str(i): p for i, p in enumerate(probabilities)},
    }


def estimate(authority, *, context=0.99, scope="shared_control"):
    answer = response(scope=scope)
    answer["answers"]["authority_power"] = scored(authority)
    answer["answers"]["asset_power"] = scored([0.4, 0.3, 0.2, 0.1])
    answer["answers"]["availability_power"] = scored([0.4, 0.3, 0.2, 0.1])
    answer["answers"]["context_sufficient"]["noul"] = context
    validate_answer(answer, DEFAULT_MODEL)
    return _estimate(answer, {"source_complete": True}, ImpactPolicy())


@pytest.mark.parametrize("probabilities", [[0, 0.1, 0.85, 0.05], [0, 0.05, 0.45, 0.5]])
def test_material_authority_survives_uncertain_other_dimensions_and_exact_level(probabilities):
    result = estimate(probabilities)
    assert result["level"] == "unknown"
    assert result["material_impact"] and result["material_dimensions"] == ["authority_power"]
    _, _, report = inputs()
    row = report["rows"][0]
    before = copy.deepcopy(row)
    assert _decision(row, {"level": "unknown", "model_status": "rated", "estimate": result})[0] == "expand"
    assert row == before


def test_marginal_probabilities_are_not_summed_across_dimensions():
    result = estimate([0.4, 0.3, 0.2, 0.1])
    assert not result["material_impact"] and result["material_dimensions"] == []


@pytest.mark.parametrize("scope", ["unclear", "own_entitlement", "no_persistent_effect"])
def test_conflicting_or_unresolved_scope_never_recommends(scope):
    assert not estimate([0, 0, 0.9, 0.1], scope=scope)["material_impact"]


def test_missing_context_still_blocks_selection():
    assert not estimate([0, 0, 0.9, 0.1], context=0.5)["material_impact"]


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r["access"].update(status="unresolved", issues=[{"kind": "unsupported", "detail": "callee"}]),
        lambda r: r["access"].update(activity="inactive_at_block"),
        lambda r: r["access"].update(identity_dimensions=["origin"]),
    ],
)
def test_material_rating_never_relaxes_authorization(change):
    _, _, report = inputs()
    row = report["rows"][0]
    change(row)
    result = estimate([0, 0.1, 0.85, 0.05])
    assert _decision(row, {"level": "unknown", "model_status": "rated", "estimate": result})[0] == "review"


@pytest.mark.parametrize("dimension", ["asset_power", "authority_power", "availability_power"])
@pytest.mark.parametrize(
    "distribution,selected",
    [
        ([0.1, 0.1, 0.7, 0.1], True),
        ([0.1, 0.1, 0.4, 0.4], True),
        ([0.100001, 0.1, 0.699999, 0.1], False),
    ],
)
def test_material_threshold_is_split_independent(dimension, distribution, selected):
    answer = response(scope="shared_control")
    for key in ("asset_power", "authority_power", "availability_power"):
        answer["answers"][key] = scored([0.7, 0.3, 0, 0])
    answer["answers"][dimension] = scored(distribution)
    validate_answer(answer, DEFAULT_MODEL)
    result = _estimate(answer, {"source_complete": True}, ImpactPolicy())
    assert result["material_impact"] is selected
    assert result["level"] == "unknown"
