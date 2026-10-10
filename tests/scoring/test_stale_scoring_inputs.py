"""A refresh whose policy stage replaced principal rows but whose distillation failed leaves signals naming rows that
no longer exist. The grade is withheld rather than folded from what survives, and those signals answer nothing.
"""

from __future__ import annotations

import uuid
from dataclasses import replace

import pytest

from db.models import Contract, EffectiveFunction, FunctionPrincipal, FunctionScoreSignal, Job, JobStatus, Protocol
from services.policy.effective_permissions_writer import write_effective_function_rows
from services.resolution.capabilities import CapabilityExpr
from services.scoring.fold import compute_protocol_score
from services.scoring.population import replace_contract_signals
from services.scoring.schema import PrincipalRef, entity_key
from tests.conftest import requires_postgres
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_V,
    VAULT,
    facts,
    fold,  # noqa: F401  (fold fixture, registered by import)
    magnitude,
    proven,
    reaches,
    sig,
    value_plane,
)
from utils.scoring_status import GRADE_STATE_COMPUTED, GRADE_STATE_NOT_DETERMINED


def _population():
    public = sig(
        function_id=10,
        authority_openness="open",
        principal_state="none_required",
        **proven(0.1),
        **reaches(KEY_C),
        gates=magnitude(1_000_000),
    )
    privileged = sig(
        function_id=20,
        contract_id=2,
        deployment_address=VAULT,
        selector="0x12345678",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(100, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_V),
        gates=magnitude(9_000_000),
    )
    return public, privileged


BALANCES: dict[str, dict[str, float]] = {KEY_C: {"asset": 1_000_000.0}, KEY_V: {"asset": 9_000_000.0}}


def test_before_the_refresh_the_grade_is_unchanged(fold):
    document = fold(list(_population()), value=value_plane(BALANCES), principals={100: facts(100, EOA, "eoa")})

    assert document.grade_state == GRADE_STATE_COMPUTED
    assert (document.grade_lambda, document.grade_exposure, document.confidence_pct) == (71.2, 18.0, 100.0)
    assert len(document.findings) == 2
    assert "grade_withheld" not in document.provenance
    assert not any(w["kind"] == "stale_scoring_inputs" for w in document.warnings)


def test_after_a_failed_refresh_the_grade_is_withheld_not_improved(fold):
    public, privileged = _population()
    document = fold(
        [replace(public, function_id=None), replace(privileged, function_id=None)],
        value=value_plane(BALANCES),
        # Policy reinserted the same EOA under a new id; the signal still names 100.
        principals={},
    )

    assert document.grade_state == GRADE_STATE_NOT_DETERMINED
    assert (document.grade_lambda, document.grade_exposure, document.confidence_pct) == (None, None, None)
    withheld = document.provenance["grade_withheld"]
    assert withheld["basis"] == "stale_scoring_inputs"
    assert withheld["reason"].startswith("stale scoring inputs: 1 enumerated signal(s)")
    assert withheld["withheld_by_signals"] == [
        {"entity": entity_key("ethereum", VAULT), "function": "f", "capability": "upgrade.implementation"}
    ]
    # The fold-from-survivors figure is kept only as provenance, and confidence is charged for the unreadable answer.
    assert withheld["grade_lambda_computed"] == 97.0
    assert withheld["confidence_pct_computed"] == 50.0
    assert document.model_parameters["confidence_detail"]["reachability_answered_pct"] == 50.0
    kinds = {w["kind"] for w in document.warnings}
    assert {"principal_row_missing", "stale_scoring_inputs"} <= kinds


def test_an_unpriced_perimeter_still_withholds_for_its_own_reason(fold):
    public, privileged = _population()
    document = fold([public, privileged], principals={100: facts(100, EOA, "eoa")})

    assert document.grade_state == GRADE_STATE_NOT_DETERMINED
    withheld = document.provenance["grade_withheld"]
    assert withheld["basis"] == "exposure_denominator_not_determined"
    assert withheld["reason"] == "no priced value in the perimeter, so the exposure denominator is not_determined"
    assert "withheld_by_signals" not in withheld


@pytest.fixture
def scored_contract(db_session):
    protocol = Protocol(name=f"stale-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.flush()
    job = Job(id=uuid.uuid4(), protocol_id=protocol.id, status=JobStatus.completed)
    db_session.add(job)
    db_session.flush()
    contract = Contract(address="0x" + uuid.uuid4().hex[:40], chain="ethereum", protocol_id=protocol.id, job_id=job.id)
    db_session.add(contract)
    db_session.commit()
    yield protocol, contract
    db_session.rollback()
    db_session.query(FunctionScoreSignal).filter_by(protocol_id=protocol.id).delete()
    db_session.query(EffectiveFunction).filter_by(contract_id=contract.id).delete()
    db_session.query(Contract).filter_by(id=contract.id).delete()
    db_session.query(Job).filter_by(id=job.id).delete()
    db_session.query(Protocol).filter_by(id=protocol.id).delete()
    db_session.commit()


def _policy_pass(session, contract: Contract) -> FunctionPrincipal:
    write_effective_function_rows(
        session,
        contract_id=contract.id,
        function_records=[
            {
                "function": "upgradeTo(address)",
                "abi_signature": "upgradeTo(address)",
                "selector": "0x3659cfe6",
                "effect_labels": [],
                "effect_targets": [],
                "action_summary": "stub",
                "authority_public": False,
                "authority_roles": [],
                "controllers": [],
                "direct_owner": None,
            }
        ],
        capability_by_function={"upgradeTo(address)": CapabilityExpr.finite_set([EOA], quality="exact")},
        resolve_principal_type=lambda _address: ("eoa", {}),
    )
    session.commit()
    return (
        session.query(FunctionPrincipal)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .filter(EffectiveFunction.contract_id == contract.id)
        .one()
    )


@requires_postgres
def test_the_persisted_path_withholds_after_policy_replaces_principal_rows(db_session, scored_contract):
    protocol, contract = scored_contract
    principal = _policy_pass(db_session, contract)
    signal = sig(
        protocol_id=protocol.id,
        contract_id=contract.id,
        deployment_address=contract.address,
        function_id=principal.function_id,
        selector="0x3659cfe6",
        function_name="upgradeTo",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(principal.id, "ethereum", EOA),),
        **proven(1.0),
    )
    replace_contract_signals(db_session, contract_id=contract.id, signals=[signal])
    db_session.commit()

    before = compute_protocol_score(db_session, protocol.id)
    assert "stale_scoring_inputs" not in {w["kind"] for w in before.warnings}
    assert (before.provenance.get("grade_withheld") or {}).get("basis") != "stale_scoring_inputs"

    # The next policy pass replaces the rows; distillation then fails, so the old signal row stays.
    replaced = _policy_pass(db_session, contract)
    assert replaced.id != principal.id
    stored = db_session.query(FunctionScoreSignal).filter_by(contract_id=contract.id).one()
    assert stored.function_id is None

    after = compute_protocol_score(db_session, protocol.id)
    assert after.grade_state == GRADE_STATE_NOT_DETERMINED
    assert after.provenance["grade_withheld"]["basis"] == "stale_scoring_inputs"
    assert "stale_scoring_inputs" in {w["kind"] for w in after.warnings}


def test_a_partial_principal_set_withholds_the_grade_rather_than_dropping_its_finding(fold):
    public, privileged = _population()
    partial = replace(
        privileged,
        principal_state="not_determined",
        principal_refs=(),
        witness_notes=("principal_set_not_exact:lower_bound",),
    )
    document = fold([public, partial], value=value_plane(BALANCES), principals={})

    assert document.grade_state == GRADE_STATE_NOT_DETERMINED
    assert (document.grade_lambda, document.grade_exposure, document.confidence_pct) == (None, None, None)
    withheld = document.provenance["grade_withheld"]
    assert withheld["basis"] == "partial_principal_sets"
    assert withheld["reason"].startswith("partial principal sets: 1 grade-bearing signal(s)")
    assert withheld["withheld_by_signals"] == [
        {"entity": entity_key("ethereum", VAULT), "function": "f", "capability": "upgrade.implementation"}
    ]
    assert withheld["grade_lambda_computed"] == 97.0


def test_an_unresolved_signal_without_a_partial_set_keeps_the_grade_as_before(fold):
    public, privileged = _population()
    unresolved = replace(privileged, principal_state="not_determined", principal_refs=())
    document = fold([public, unresolved], value=value_plane(BALANCES), principals={})

    assert document.grade_state == GRADE_STATE_COMPUTED
    assert "grade_withheld" not in document.provenance
