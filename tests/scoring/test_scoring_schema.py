"""Each test pins a way a ``not_determined`` could become a published fact: a defaulted discriminator, a number on an
undetermined severity, an empty list read as a proven caller set, proven-absent collapsing into unread, an unread
destination read as unconstrained, or ``_latest`` serving a stale computed row.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.exc import IntegrityError

from db.models import (
    Contract,
    FunctionScoreSignal,
    Job,
    Protocol,
    ProtocolScore,
)
from services.scoring.population import (
    replace_contract_signals,
)
from services.scoring.schema import (
    NOT_DETERMINED,
    FunctionSignal,
    is_entity_key,
    not_determined_signal_defaults,
)
from utils.scoring_status import (
    DESTINATION_BEARING_CLAIMS,
    DESTINATION_SHAPE_NOT_APPLICABLE,
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_UNCONSTRAINED_PROVEN,
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    MODEL_VERSION,
    OPENNESS_NOT_DETERMINED,
    PERIMETER_SETTLED,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    REACH_GATE_NOT_DETERMINED,
    SCORE_TRIGGER_JOB,
    SEVERITY_STATE_NOT_DETERMINED,
    SEVERITY_STATE_PROVEN,
    VALUE_BOUND_NOT_DETERMINED,
    VALUE_STATE_NOT_DETERMINED,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
    WITNESS_TIER_NOT_DETERMINED,
)


def _signal(**overrides: Any) -> FunctionSignal:
    base: dict[str, Any] = dict(
        job_id=uuid.uuid4(),
        protocol_id=1,
        contract_id=1,
        chain="ethereum",
        deployment_address="0xdead",
        function_name="setImplementation",
        claim_id="upgrade.implementation",
        **not_determined_signal_defaults(),
    )
    base.update(overrides)
    return FunctionSignal(**base)


class _Fixture:
    """The live split-proxy shape: secondary implementations as distinct ``contracts`` rows at one runtime address."""

    def __init__(self, protocol, job, later_job, contract, sibling):
        self.protocol = protocol
        self.job = job
        self.later_job = later_job
        self.contract = contract
        self.sibling = sibling


@pytest.fixture()
def scoring_protocol(db_session):
    protocol = Protocol(name=f"scoretest-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.flush()
    jobs = [Job(id=uuid.uuid4(), protocol_id=protocol.id) for _ in range(2)]
    contracts = [
        Contract(address=f"0x{uuid.uuid4().hex[:40]}", chain="ethereum", protocol_id=protocol.id) for _ in range(2)
    ]
    db_session.add_all(jobs + contracts)
    db_session.commit()
    try:
        yield _Fixture(protocol, jobs[0], jobs[1], contracts[0], contracts[1])
    finally:
        db_session.rollback()
        db_session.query(FunctionScoreSignal).filter_by(protocol_id=protocol.id).delete()
        db_session.query(ProtocolScore).filter_by(protocol_id=protocol.id).delete()
        for contract in contracts:
            db_session.query(Contract).filter_by(id=contract.id).delete()
        for job in jobs:
            db_session.query(Job).filter_by(id=job.id).delete()
        db_session.query(Protocol).filter_by(id=protocol.id).delete()
        db_session.commit()


SHARED_ADDRESS = "0x8f08b70456eb22f6109f57b8fafe862ed28e6040"


def _row(fx, **overrides: Any) -> FunctionScoreSignal:
    base: dict[str, Any] = dict(
        job_id=fx.job.id,
        protocol_id=fx.protocol.id,
        contract_id=fx.contract.id,
        chain="ethereum",
        deployment_address=SHARED_ADDRESS,
        selector="0x12345678",
        function_name="setImplementation",
        claim_id="upgrade.implementation",
        witness_tier=WITNESS_TIER_NOT_DETERMINED,
        severity_state=SEVERITY_STATE_NOT_DETERMINED,
        severity_proven=None,
        severity_basis=[],
        authority_openness=OPENNESS_NOT_DETERMINED,
        principal_state=PRINCIPAL_STATE_NOT_DETERMINED,
        principal_refs=[],
        value_state=VALUE_STATE_NOT_DETERMINED,
        value_bound=VALUE_BOUND_NOT_DETERMINED,
        value_entity_keys=[],
        value_basis=NOT_DETERMINED,
        destination_state=NOT_DETERMINED,
        destination_shape=None,
        reach_gate_state=REACH_GATE_NOT_DETERMINED,
        gate_inputs={},
        citations=[],
        witness_notes=[],
    )
    base.update(overrides)
    return FunctionScoreSignal(**base)


def _signal_for(fx, **overrides: Any) -> FunctionSignal:
    bound: dict[str, Any] = dict(
        protocol_id=fx.protocol.id,
        contract_id=fx.contract.id,
        job_id=fx.job.id,
        deployment_address=SHARED_ADDRESS,
        selector="0x12345678",
    )
    bound.update(overrides)
    return _signal(**bound)


# CRITICAL cases guard a published-state biconditional.
_REJECTED_SIGNAL_ROWS = [
    pytest.param(
        dict(severity_state=SEVERITY_STATE_NOT_DETERMINED, severity_proven=1.0), id="undetermined_severity_number"
    ),
    pytest.param(dict(severity_state=SEVERITY_STATE_PROVEN, severity_proven=None), id="proven_severity_no_number"),
    pytest.param(
        dict(severity_state=SEVERITY_STATE_PROVEN, severity_proven=0.9, severity_basis=[]),
        id="proven_severity_no_basis",
    ),
    pytest.param(
        dict(principal_state=PRINCIPAL_STATE_ENUMERATED, principal_refs=[]), id="empty_enumerated_principal_set"
    ),
    pytest.param(
        dict(value_state=VALUE_STATE_NOT_DETERMINED, value_entity_keys=["ethereum::0x1"]),
        id="undetermined_value_smuggles_entity_keys",
    ),
    pytest.param(
        dict(destination_state=NOT_DETERMINED, destination_shape="caller_arbitrary"),
        id="undetermined_destination_carries_shape",
    ),
    pytest.param(
        dict(
            claim_id="delegatecall.execute",
            destination_state=DESTINATION_STATE_NOT_APPLICABLE,
            destination_shape=DESTINATION_SHAPE_NOT_APPLICABLE,
        ),
        id="destination_bearing_claim_not_applicable",
    ),
    pytest.param(
        dict(destination_state=DESTINATION_STATE_UNCONSTRAINED_PROVEN, destination_shape=None),
        id="proven_destination_without_shape",
    ),
    pytest.param(
        dict(
            principal_state=PRINCIPAL_STATE_NOT_DETERMINED,
            principal_refs=[{"function_principal_id": 1, "chain": "ethereum", "address": "0xa"}],
        ),
        id="non_enumerated_principal_carries_refs",
    ),
    pytest.param(dict(principal_refs={"function_principal_id": 1}), id="principal_refs_as_object"),
    pytest.param(
        dict(
            value_state=VALUE_STATE_PROVEN_NO_REACH,
            value_basis="proven_no_reach",
            value_entity_keys=["ethereum::0x1"],
        ),
        id="proven_no_reach_carries_entity_keys",
    ),
    pytest.param(
        dict(
            value_state=VALUE_STATE_PROVEN_REACH,
            value_basis="observed_reach_value_usd",
            value_entity_keys=["ethereum::0x1", None],
        ),
        id="value_entity_keys_contain_null",
    ),
]


@pytest.mark.usefixtures("scoring_protocol")
@pytest.mark.parametrize("overrides", _REJECTED_SIGNAL_ROWS)
def test_signal_row_check_constraints_reject(db_session, scoring_protocol, overrides):
    db_session.add(_row(scoring_protocol, **overrides))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_reanalysis_replaces_prior_jobs_signals_for_the_same_contract(db_session, scoring_protocol):
    """Re-analysis mints a new job, so a job-scoped delete would double-count the contract."""
    fx = scoring_protocol
    db_session.add_all([_row(fx, selector=f"0x0000000{n}") for n in (1, 2)])
    db_session.commit()

    replaced = replace_contract_signals(
        db_session,
        contract_id=fx.contract.id,
        signals=[_signal_for(fx, selector="0x00000009")],
        job_id=fx.later_job.id,
    )
    db_session.commit()

    assert replaced == 2
    remaining = db_session.query(FunctionScoreSignal).filter_by(contract_id=fx.contract.id).all()
    assert [r.selector for r in remaining] == ["0x00000009"]
    assert remaining[0].job_id == fx.later_job.id


@pytest.mark.usefixtures("scoring_protocol")
def test_identity_still_rejects_a_true_duplicate(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add_all([_row(fx), _row(fx)])
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def _score(fx, **overrides: Any) -> ProtocolScore:
    base: dict[str, Any] = dict(
        protocol_id=fx.protocol.id,
        model_version=MODEL_VERSION,
        trigger=SCORE_TRIGGER_JOB,
        grade_state=GRADE_STATE_COMPUTED,
        grade_lambda=-30.0,
        grade_exposure=1_400_000_000,
        confidence_pct=71.0,
        perimeter_state=PERIMETER_SETTLED,
        findings={"findings": []},
        provenance={"planes": {}},
        model_parameters={"lambda": 0.6},
    )
    base.update(overrides)
    return ProtocolScore(**base)


@pytest.mark.usefixtures("scoring_protocol")
@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(dict(grade_state=GRADE_STATE_NOT_DETERMINED), id="grade_pairing_undetermined_with_values"),
        pytest.param(dict(grade_state=GRADE_STATE_COMPUTED, confidence_pct=None), id="grade_pairing_no_confidence"),
        pytest.param(dict(findings={"a": 1}, storage_key="scores/1.json"), id="document_inline_and_spilled"),
        pytest.param(dict(findings=None, storage_key=None), id="document_neither_inline_nor_spilled"),
    ],
)
def test_score_check_constraints_reject(db_session, scoring_protocol, overrides):
    db_session.add(_score(scoring_protocol, **overrides))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_is_entity_key_rejects_unscoped_and_malformed_tokens():
    assert is_entity_key("ethereum::0xabc")
    assert not is_entity_key("0xabc")
    assert not is_entity_key("ethereum::0xABC")
    assert not is_entity_key("::0xabc")
    assert not is_entity_key("ethereum::")
    assert not is_entity_key("a::b::c")


def test_gate_inputs_must_be_tri_envelopes():
    with pytest.raises(ValueError, match="tri-state envelope"):
        _signal(gate_inputs={"pause_effective": True})


# N-a: chain is part of the entity key; a non-lowercased address breaks the identity join.
@pytest.mark.usefixtures("scoring_protocol")
@pytest.mark.parametrize(
    ("match", "overrides"),
    [
        pytest.param("passed to replace", lambda fx: dict(contract_id=fx.sibling.id), id="another_contract"),
        pytest.param("claims chain", lambda fx: dict(chain="optimism"), id="another_chain"),
        pytest.param(
            "lowercased", lambda fx: dict(deployment_address=SHARED_ADDRESS.upper()), id="uppercased_deployment_address"
        ),
    ],
)
def test_replace_rejects_a_mismatched_signal(db_session, scoring_protocol, match, overrides):
    fx = scoring_protocol
    with pytest.raises(ValueError, match=match):
        replace_contract_signals(
            db_session,
            contract_id=fx.contract.id,
            signals=[_signal_for(fx, **overrides(fx))],
            job_id=fx.job.id,
        )
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_a_rejected_signal_leaves_the_original_set_fully_intact(db_session, scoring_protocol):
    """R2-B1: the fail-forward caller commits anyway, so validation must run before the delete."""
    fx = scoring_protocol
    db_session.add_all([_row(fx, selector=f"0x0000000{n}") for n in (1, 2)])
    db_session.commit()

    with pytest.raises(ValueError, match="passed to replace"):
        replace_contract_signals(
            db_session,
            contract_id=fx.contract.id,
            signals=[
                _signal_for(fx, selector="0x00000009"),
                _signal_for(fx, selector="0x0000000a", contract_id=fx.sibling.id),
            ],
            job_id=fx.later_job.id,
        )
    db_session.commit()

    survivors = db_session.query(FunctionScoreSignal).filter_by(contract_id=fx.contract.id).all()
    assert sorted(r.selector for r in survivors) == ["0x00000001", "0x00000002"]


@pytest.mark.usefixtures("scoring_protocol")
def test_replace_accepts_chain_aliases_of_the_contracts_chain(db_session, scoring_protocol):
    fx = scoring_protocol
    replace_contract_signals(
        db_session,
        contract_id=fx.contract.id,
        signals=[_signal_for(fx, chain="mainnet")],
        job_id=fx.job.id,
    )
    db_session.commit()
    assert db_session.query(FunctionScoreSignal).filter_by(contract_id=fx.contract.id).count() == 1


def test_destination_bearing_claims_exist_in_the_claims_registry():
    from services.static.claims.matchers import discover
    from services.static.claims.registry import registry

    discover()
    registry_ids = set(registry())
    unknown = [c for c in DESTINATION_BEARING_CLAIMS if c not in registry_ids]
    assert unknown == [], (
        f"DESTINATION_BEARING_CLAIMS names claims the registry does not define: {unknown}. "
        "Rename them in utils/scoring_status.py or the destination guard stops firing."
    )
