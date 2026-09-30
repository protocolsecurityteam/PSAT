"""Each test pins a way a ``not_determined`` could become a published fact: a defaulted discriminator, a number on an
undetermined severity, an empty list read as a proven caller set, proven-absent collapsing into unread, an unread
destination read as unconstrained, or ``_latest`` serving a stale computed row.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from db.models import (
    Contract,
    FunctionScoreSignal,
    Job,
    Protocol,
    ProtocolScore,
    ProtocolScoreLatest,
)
from services.aggregations.company_overview import _entity_key as canon_entity_key
from services.scoring.population import (
    current_signals_for_protocol,
    replace_contract_signals,
)
from services.scoring.schema import (
    NOT_DETERMINED,
    FunctionSignal,
    PrincipalRef,
    ScoreDocument,
    Tri,
    coalesce_chain,
    entity_key,
    is_entity_key,
    not_determined_signal_defaults,
    signal_to_row_kwargs,
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
    OPENNESS_RESTRICTED,
    PERIMETER_SETTLED,
    PERIMETER_UNSETTLED,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NONE_REQUIRED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    REACH_GATE_NOT_DETERMINED,
    SCORE_TRIGGER_DIRTY_LOOP,
    SCORE_TRIGGER_JOB,
    SEVERITY_STATE_NOT_DETERMINED,
    SEVERITY_STATE_PROVEN,
    VALUE_BOUND_FLOOR,
    VALUE_BOUND_NOT_DETERMINED,
    VALUE_STATE_NOT_DETERMINED,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
    WITNESS_TIER_BEHAVIORAL_OBSERVED,
    WITNESS_TIER_NOT_DETERMINED,
)


def test_entity_key_is_chain_scoped():
    """#158 twin aliasing."""
    assert entity_key("ethereum", "0xAbC") != entity_key("optimism", "0xAbC")
    assert entity_key("ethereum", "0xAbC") == "ethereum::0xabc"


def test_tri_holds_three_distinct_states():
    proven_present = Tri.proven(VALUE_STATE_PROVEN_REACH, ("ethereum::0x1",))
    proven_absent = Tri.proven(VALUE_STATE_PROVEN_NO_REACH, ())
    undetermined = Tri.not_determined()

    states = {proven_present.state, proven_absent.state, undetermined.state}
    assert len(states) == 3
    assert proven_present.is_determined and proven_absent.is_determined
    assert not undetermined.is_determined


def test_not_determined_cannot_carry_a_value():
    with pytest.raises(ValueError):
        Tri(state=NOT_DETERMINED, value=1.0)


def test_proven_cannot_be_spelled_not_determined():
    with pytest.raises(ValueError):
        Tri.proven(NOT_DETERMINED, 1.0)


def test_reading_a_payload_requires_naming_the_state():
    undetermined = Tri[float].not_determined()
    with pytest.raises(ValueError):
        undetermined.require(SEVERITY_STATE_PROVEN)

    proven = Tri.proven(SEVERITY_STATE_PROVEN, 0.9)
    assert proven.require(SEVERITY_STATE_PROVEN) == 0.9
    with pytest.raises(ValueError):
        proven.require(SEVERITY_STATE_NOT_DETERMINED)


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


def test_every_three_state_field_must_be_named():
    with pytest.raises(TypeError):
        FunctionSignal(  # pyright: ignore[reportCallIssue]
            job_id=uuid.uuid4(),
            protocol_id=1,
            contract_id=1,
            chain="ethereum",
            deployment_address="0xdead",
            function_name="f",
            claim_id="upgrade.implementation",
        )


def test_contract_id_is_required_because_it_is_identity():
    """R2-B2: the in-memory CLI path has no DB to reject a None, so a default would collapse split-proxy siblings."""
    fields = {
        "job_id": uuid.uuid4(),
        "protocol_id": 1,
        "chain": "ethereum",
        "deployment_address": "0xdead",
        "function_name": "f",
        "claim_id": "pause.set",
        **not_determined_signal_defaults(),
    }
    with pytest.raises(TypeError, match="contract_id"):
        FunctionSignal(**fields)
    assert FunctionSignal(contract_id=7, **fields).contract_id == 7


def test_fully_undetermined_signal_is_constructible_and_not_scored():
    sig = _signal()
    assert sig.severity.state == SEVERITY_STATE_NOT_DETERMINED
    assert sig.witness_tier == WITNESS_TIER_NOT_DETERMINED
    assert sig.authority_openness == OPENNESS_NOT_DETERMINED
    assert sig.principal_state == PRINCIPAL_STATE_NOT_DETERMINED
    assert sig.value_state == VALUE_STATE_NOT_DETERMINED
    assert sig.enters_grade is False


def test_proven_severity_enters_grade_and_must_name_its_basis():
    scored = _signal(
        severity=Tri.proven(SEVERITY_STATE_PROVEN, 1.0),
        severity_basis=("base",),
        witness_tier=WITNESS_TIER_BEHAVIORAL_OBSERVED,
    )
    assert scored.enters_grade is True

    with pytest.raises(ValueError, match="name what proved it"):
        _signal(severity=Tri.proven(SEVERITY_STATE_PROVEN, 1.0), severity_basis=())


def test_proven_zero_severity_is_not_undetermined():
    zero = _signal(
        claim_id="pause.set",
        severity=Tri.proven(SEVERITY_STATE_PROVEN, 0.0),
        severity_basis=("base",),
    )
    assert zero.enters_grade is True
    assert zero.severity.require(SEVERITY_STATE_PROVEN) == 0.0
    assert zero.severity.state != _signal().severity.state


def test_empty_principal_set_cannot_be_published_as_enumerated():
    with pytest.raises(ValueError, match="enumerated"):
        _signal(principal_state=PRINCIPAL_STATE_ENUMERATED, principal_refs=())


def test_value_states_are_three_and_bounds_require_a_proven_reach():
    reached = _signal(
        value_state=VALUE_STATE_PROVEN_REACH,
        value_entity_keys=("ethereum::0x1",),
        value_bound=VALUE_BOUND_FLOOR,
        value_basis="observed_reach_floor_usd",
    )
    assert reached.value_bound == VALUE_BOUND_FLOOR

    absent = _signal(value_state=VALUE_STATE_PROVEN_NO_REACH, value_basis="proven_no_reach")
    assert absent.value_entity_keys == ()

    with pytest.raises(ValueError, match="proven_reach"):
        _signal(value_state=VALUE_STATE_PROVEN_REACH, value_entity_keys=())
    with pytest.raises(ValueError, match="bounded"):
        _signal(value_bound=VALUE_BOUND_FLOOR)


def test_destination_not_applicable_differs_from_not_determined():
    """Collapsing them makes the -30λ F→C delegatecall false positive representable."""
    inapplicable = _signal(claim_id="pause.set", destination=Tri.proven(DESTINATION_STATE_NOT_APPLICABLE, "none"))
    unread = _signal(claim_id="delegatecall.execute")
    assert inapplicable.destination.state != unread.destination.state
    assert unread.destination.state == NOT_DETERMINED
    assert unread.enters_grade is False


def test_score_document_grade_and_confidence_are_determined_together():
    doc = ScoreDocument(
        protocol_id=1,
        model_version=MODEL_VERSION,
        computed_at=datetime.now(timezone.utc),
        trigger=SCORE_TRIGGER_DIRTY_LOOP,
        perimeter_state=PERIMETER_SETTLED,
        grade_state=GRADE_STATE_COMPUTED,
        grade_lambda=-30.0,
        grade_exposure=1.4e9,
        confidence_pct=71.0,
        findings=[],
        earned_negatives=[],
        warnings=[],
        model_parameters={"lambda": 0.6},
        provenance={},
    )
    assert doc.document()["model_version"] == MODEL_VERSION

    with pytest.raises(ValueError, match="together"):
        ScoreDocument(
            protocol_id=1,
            model_version=MODEL_VERSION,
            computed_at=datetime.now(timezone.utc),
            trigger=SCORE_TRIGGER_DIRTY_LOOP,
            perimeter_state=PERIMETER_SETTLED,
            grade_state=GRADE_STATE_COMPUTED,
            grade_lambda=-30.0,
            grade_exposure=1.4e9,
            confidence_pct=None,
            findings=[],
            earned_negatives=[],
            warnings=[],
            model_parameters={},
            provenance={},
        )


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


@pytest.mark.usefixtures("scoring_protocol")
def test_signal_three_states_round_trip(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add_all(
        [
            _row(fx, selector="0x00000001"),
            _row(
                fx,
                selector="0x00000002",
                severity_state=SEVERITY_STATE_PROVEN,
                severity_proven=0.0,
                severity_basis=["base"],
                claim_id="pause.set",
                principal_state=PRINCIPAL_STATE_ENUMERATED,
                principal_refs=[{"function_principal_id": 3, "chain": "ethereum", "address": "0xaaa"}],
                authority_openness=OPENNESS_RESTRICTED,
                value_state=VALUE_STATE_PROVEN_REACH,
                value_entity_keys=["ethereum::0xvault"],
                value_bound=VALUE_BOUND_FLOOR,
                value_basis="observed_reach_floor_usd",
            ),
            _row(
                fx,
                selector="0x00000003",
                value_state=VALUE_STATE_PROVEN_NO_REACH,
                value_basis="proven_no_reach",
                principal_state=PRINCIPAL_STATE_NONE_REQUIRED,
            ),
        ]
    )
    db_session.commit()

    rows = (
        db_session.query(FunctionScoreSignal)
        .filter_by(protocol_id=fx.protocol.id)
        .order_by(FunctionScoreSignal.selector)
        .all()
    )
    assert [r.severity_state for r in rows] == [
        SEVERITY_STATE_NOT_DETERMINED,
        SEVERITY_STATE_PROVEN,
        SEVERITY_STATE_NOT_DETERMINED,
    ]
    assert rows[0].severity_proven is None
    assert float(rows[1].severity_proven) == 0.0
    assert len({r.value_state for r in rows}) == 3
    assert rows[1].principal_refs[0]["function_principal_id"] == 3


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
def test_unconstrained_proven_destination_may_carry_a_shape(db_session, scoring_protocol):
    db_session.add(
        _row(
            scoring_protocol,
            destination_state=DESTINATION_STATE_UNCONSTRAINED_PROVEN,
            destination_shape="caller_arbitrary",
        )
    )
    db_session.commit()


@pytest.mark.usefixtures("scoring_protocol")
def test_state_columns_have_no_default(db_session, scoring_protocol):
    """A server default would record ``not_determined`` for a writer that never decided."""
    discriminators = [
        "severity_state",
        "witness_tier",
        "authority_openness",
        "principal_state",
        "value_state",
        "value_bound",
        "destination_state",
        "reach_gate_state",
    ]
    defaulted = db_session.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'function_score_signals' AND column_default IS NOT NULL "
            "AND column_name = ANY(:cols)"
        ),
        {"cols": discriminators},
    ).fetchall()
    assert defaulted == [], f"discriminators must not be defaultable: {defaulted}"

    nullable = db_session.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'function_score_signals' AND is_nullable = 'YES' "
            "AND column_name = ANY(:cols)"
        ),
        {"cols": discriminators},
    ).fetchall()
    assert nullable == [], f"discriminators must be NOT NULL: {nullable}"


@pytest.mark.usefixtures("scoring_protocol")
def test_score_state_columns_have_no_default(db_session, scoring_protocol):
    for column in ("grade_state", "perimeter_state"):
        row = db_session.execute(
            text(
                "SELECT column_default, is_nullable FROM information_schema.columns "
                "WHERE table_name = 'protocol_scores' AND column_name = :col"
            ),
            {"col": column},
        ).one()
        assert row[0] is None and row[1] == "NO", f"{column} is defaultable or nullable"


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
def test_replace_does_not_touch_a_sibling_contract(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add_all([_row(fx), _row(fx, contract_id=fx.sibling.id)])
    db_session.commit()

    replace_contract_signals(db_session, contract_id=fx.contract.id, signals=[], job_id=fx.later_job.id)
    db_session.commit()

    survivors = db_session.query(FunctionScoreSignal).filter_by(protocol_id=fx.protocol.id).all()
    assert [r.contract_id for r in survivors] == [fx.sibling.id]


@pytest.mark.usefixtures("scoring_protocol")
def test_split_proxy_siblings_share_a_deployment_address_without_colliding(db_session, scoring_protocol):
    """Without ``contract_id`` in the identity this is a unique-constraint violation."""
    fx = scoring_protocol
    db_session.add_all([_row(fx), _row(fx, contract_id=fx.sibling.id)])
    db_session.commit()

    rows = db_session.query(FunctionScoreSignal).filter_by(deployment_address=SHARED_ADDRESS).all()
    assert len(rows) == 2
    assert {r.contract_id for r in rows} == {fx.contract.id, fx.sibling.id}
    assert len({r.selector for r in rows}) == 1


@pytest.mark.usefixtures("scoring_protocol")
def test_identity_still_rejects_a_true_duplicate(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add_all([_row(fx), _row(fx)])
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_deleting_a_contract_stops_it_charging_exposure(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add(_row(fx))
    db_session.commit()

    db_session.query(Contract).filter_by(id=fx.contract.id).delete()
    db_session.commit()

    assert db_session.query(FunctionScoreSignal).filter_by(protocol_id=fx.protocol.id).count() == 0


@pytest.mark.usefixtures("scoring_protocol")
def test_losing_the_job_keeps_the_signal(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add(_row(fx))
    db_session.commit()

    db_session.query(Job).filter_by(id=fx.job.id).delete()
    db_session.commit()

    row = db_session.query(FunctionScoreSignal).filter_by(protocol_id=fx.protocol.id).one()
    assert row.job_id is None


@pytest.mark.usefixtures("scoring_protocol")
def test_population_read_is_ordered_and_typed(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add_all(
        [
            _row(fx, selector="0x00000003", claim_id="pause.set"),
            _row(fx, selector="0x00000001"),
            _row(fx, selector="0x00000002", contract_id=fx.sibling.id),
        ]
    )
    db_session.commit()

    signals = current_signals_for_protocol(db_session, fx.protocol.id)
    assert [s.selector for s in signals] == ["0x00000001", "0x00000003", "0x00000002"]
    assert all(isinstance(s, FunctionSignal) for s in signals)


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


@pytest.mark.usefixtures("scoring_protocol")
@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(
            dict(
                grade_state=GRADE_STATE_NOT_DETERMINED,
                grade_lambda=None,
                grade_exposure=None,
                confidence_pct=None,
            ),
            id="undetermined_grade_without_values",
        ),
        pytest.param(dict(findings=None, storage_key="scores/1.json"), id="spilled_document"),
    ],
)
def test_score_check_constraints_accept_the_valid_pairing(db_session, scoring_protocol, overrides):
    db_session.add(_score(scoring_protocol, **overrides))
    db_session.commit()


@pytest.mark.usefixtures("scoring_protocol")
def test_latest_view_returns_the_newest_row_per_protocol(db_session, scoring_protocol):
    fx = scoring_protocol
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            _score(fx, computed_at=now - timedelta(hours=2), confidence_pct=10.0),
            _score(fx, computed_at=now - timedelta(hours=1), confidence_pct=20.0),
            _score(fx, computed_at=now, confidence_pct=30.0),
        ]
    )
    db_session.commit()

    latest = db_session.query(ProtocolScoreLatest).filter_by(protocol_id=fx.protocol.id).all()
    assert len(latest) == 1
    assert float(latest[0].confidence_pct) == 30.0


@pytest.mark.usefixtures("scoring_protocol")
def test_latest_view_prefers_the_newest_verdict_over_the_newest_grade(db_session, scoring_protocol):
    """Serving the last computed row would republish a stale grade as current."""
    fx = scoring_protocol
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            _score(fx, computed_at=now - timedelta(hours=1)),
            _score(
                fx,
                computed_at=now,
                grade_state=GRADE_STATE_NOT_DETERMINED,
                grade_lambda=None,
                grade_exposure=None,
                confidence_pct=None,
                perimeter_state=PERIMETER_UNSETTLED,
            ),
        ]
    )
    db_session.commit()

    latest = db_session.query(ProtocolScoreLatest).filter_by(protocol_id=fx.protocol.id).one()
    assert latest.grade_state == GRADE_STATE_NOT_DETERMINED
    assert latest.grade_lambda is None


@pytest.mark.usefixtures("scoring_protocol")
def test_latest_view_breaks_same_instant_ties_deterministically(db_session, scoring_protocol):
    fx = scoring_protocol
    now = datetime.now(timezone.utc)
    db_session.add_all([_score(fx, computed_at=now, confidence_pct=c) for c in (11.0, 22.0)])
    db_session.commit()

    rows = db_session.query(ProtocolScoreLatest).filter_by(protocol_id=fx.protocol.id).all()
    assert len(rows) == 1
    newest_id = (
        db_session.query(ProtocolScore.id)
        .filter_by(protocol_id=fx.protocol.id)
        .order_by(ProtocolScore.id.desc())
        .first()[0]
    )
    assert rows[0].id == newest_id


def test_chain_aliases_collapse_to_one_entity_key():
    """Otherwise the value axis charges one vault three times."""
    keys = {entity_key(c, "0xVAULT") for c in (None, "", "  ", "mainnet", "Ethereum", "ETHEREUM", "ethereum")}
    assert keys == {"ethereum::0xvault"}
    assert coalesce_chain("MAINNET") == "ethereum"


def test_entity_key_is_byte_identical_to_the_codebase_canon():
    for chain in (None, "", "mainnet", "Ethereum", "optimism", "BASE"):
        for address in ("0xAbC", "0xdeadBEEF"):
            assert entity_key(chain, address) == canon_entity_key(chain, address)


def test_is_entity_key_rejects_unscoped_and_malformed_tokens():
    assert is_entity_key("ethereum::0xabc")
    assert not is_entity_key("0xabc")
    assert not is_entity_key("ethereum::0xABC")
    assert not is_entity_key("::0xabc")
    assert not is_entity_key("ethereum::")
    assert not is_entity_key("a::b::c")


def test_signal_rejects_unscoped_value_entity_keys():
    with pytest.raises(ValueError, match="canonical"):
        _signal(
            value_state=VALUE_STATE_PROVEN_REACH,
            value_entity_keys=("0xvault",),
            value_basis="observed_reach_value_usd",
        )


def test_proven_state_must_carry_its_witness_value():
    with pytest.raises(ValueError, match="must carry its witness"):
        Tri(state=SEVERITY_STATE_PROVEN, value=None)
    with pytest.raises(ValueError, match="must carry its witness"):
        Tri(state=DESTINATION_STATE_NOT_APPLICABLE, value=None)


def test_gate_input_raises_on_a_gate_that_was_never_distilled():
    sig = _signal(gate_inputs={"pause_effective": Tri.not_determined().to_json()})
    assert sig.gate_input("pause_effective").state == NOT_DETERMINED
    with pytest.raises(KeyError, match="duration_bound_seconds"):
        sig.gate_input("duration_bound_seconds")


def test_gate_inputs_must_be_tri_envelopes():
    with pytest.raises(ValueError, match="tri-state envelope"):
        _signal(gate_inputs={"pause_effective": True})


def test_destination_bearing_claim_cannot_be_not_applicable():
    for claim in DESTINATION_BEARING_CLAIMS:
        with pytest.raises(ValueError, match="launder"):
            _signal(
                claim_id=claim,
                destination=Tri.proven(DESTINATION_STATE_NOT_APPLICABLE, DESTINATION_SHAPE_NOT_APPLICABLE),
            )
    ok = _signal(
        claim_id="pause.set",
        destination=Tri.proven(DESTINATION_STATE_NOT_APPLICABLE, DESTINATION_SHAPE_NOT_APPLICABLE),
    )
    assert ok.destination.state == DESTINATION_STATE_NOT_APPLICABLE


@pytest.mark.usefixtures("scoring_protocol")
def test_signal_row_seam_round_trips_all_three_states(db_session, scoring_protocol):
    """A state in the wrong column leaves every value legal, so no CHECK would notice."""
    fx = scoring_protocol
    originals = [
        _signal_for(fx, selector="0x00000001"),
        _signal_for(
            fx,
            selector="0x00000002",
            claim_id="pause.set",
            witness_tier=WITNESS_TIER_BEHAVIORAL_OBSERVED,
            severity=Tri.proven(SEVERITY_STATE_PROVEN, 0.0),
            severity_basis=("base", "keyset_independent:6>=4"),
            authority_openness=OPENNESS_RESTRICTED,
            principal_state=PRINCIPAL_STATE_ENUMERATED,
            principal_refs=(PrincipalRef(function_principal_id=42, chain="ethereum", address="0xaaa"),),
            value_state=VALUE_STATE_PROVEN_REACH,
            value_entity_keys=(entity_key("ethereum", "0xVAULT"),),
            value_bound=VALUE_BOUND_FLOOR,
            value_basis="observed_reach_floor_usd",
            destination=Tri.proven(DESTINATION_STATE_NOT_APPLICABLE, DESTINATION_SHAPE_NOT_APPLICABLE),
            gate_inputs={"pause_effective": Tri.proven(SEVERITY_STATE_PROVEN, True).to_json()},
            citations=({"field": "observed_reach_floor_usd"},),
            witness_notes=("keyset_independent",),
        ),
        _signal_for(
            fx,
            selector="0x00000003",
            claim_id="pause.set",
            value_state=VALUE_STATE_PROVEN_NO_REACH,
            value_basis="proven_no_reach",
            principal_state=PRINCIPAL_STATE_NONE_REQUIRED,
        ),
    ]
    for signal in originals:
        db_session.add(FunctionScoreSignal(**signal_to_row_kwargs(signal, job_id=fx.job.id)))
    db_session.commit()

    restored = current_signals_for_protocol(db_session, fx.protocol.id)
    assert len(restored) == 3
    for original, back in zip(originals, restored):
        assert back.severity == original.severity
        assert back.severity_basis == original.severity_basis
        assert back.destination == original.destination
        assert back.principal_state == original.principal_state
        assert back.principal_refs == original.principal_refs
        assert back.value_state == original.value_state
        assert back.value_bound == original.value_bound
        assert back.value_entity_keys == original.value_entity_keys
        assert back.authority_openness == original.authority_openness
        assert back.witness_tier == original.witness_tier
        assert back.gate_inputs == original.gate_inputs
        assert back.enters_grade == original.enters_grade

    assert len({s.value_state for s in restored}) == 3
    assert restored[1].severity.require(SEVERITY_STATE_PROVEN) == 0.0
    assert restored[0].severity.value is None


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
def test_latest_view_correlates_per_protocol(db_session, scoring_protocol):
    fx = scoring_protocol
    other = Protocol(name=f"scoretest-other-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.commit()
    now = datetime.now(timezone.utc)
    try:
        db_session.add_all(
            [
                _score(fx, computed_at=now - timedelta(hours=1), confidence_pct=11.0),
                _score(fx, computed_at=now, confidence_pct=22.0),
            ]
        )
        older = _score(fx, computed_at=now - timedelta(days=1), confidence_pct=33.0)
        older.protocol_id = other.id
        db_session.add(older)
        db_session.commit()

        rows = (
            db_session.query(ProtocolScoreLatest)
            .filter(ProtocolScoreLatest.protocol_id.in_([fx.protocol.id, other.id]))
            .all()
        )
        assert len(rows) == 2
        by_protocol = {r.protocol_id: float(r.confidence_pct) for r in rows}
        assert by_protocol[fx.protocol.id] == 22.0
        assert by_protocol[other.id] == 33.0
    finally:
        db_session.rollback()
        db_session.query(ProtocolScore).filter_by(protocol_id=other.id).delete()
        db_session.query(Protocol).filter_by(id=other.id).delete()
        db_session.commit()


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
def test_replace_rejects_a_signal_claiming_another_protocol(db_session, scoring_protocol):
    fx = scoring_protocol
    other = Protocol(name=f"scoretest-wrong-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.commit()
    try:
        with pytest.raises(ValueError, match="claims protocol"):
            replace_contract_signals(
                db_session,
                contract_id=fx.contract.id,
                signals=[_signal_for(fx, protocol_id=other.id)],
                job_id=fx.job.id,
            )
        db_session.rollback()
    finally:
        db_session.query(Protocol).filter_by(id=other.id).delete()
        db_session.commit()


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


@pytest.mark.usefixtures("scoring_protocol")
def test_replace_refuses_an_unknown_contract(db_session, scoring_protocol):
    fx = scoring_protocol
    with pytest.raises(ValueError, match="does not exist"):
        replace_contract_signals(db_session, contract_id=-1, signals=[], job_id=fx.job.id)
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_second_replace_of_one_contract_in_a_transaction_raises(db_session, scoring_protocol):
    """The second delete would silently drop the first call's rows."""
    fx = scoring_protocol
    replace_contract_signals(
        db_session,
        contract_id=fx.contract.id,
        signals=[_signal_for(fx, selector="0x00000001")],
        job_id=fx.job.id,
    )
    with pytest.raises(ValueError, match="complete signal set"):
        replace_contract_signals(
            db_session,
            contract_id=fx.contract.id,
            signals=[_signal_for(fx, selector="0x00000002")],
            job_id=fx.job.id,
        )
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_the_grouping_guard_resets_between_transactions(db_session, scoring_protocol):
    fx = scoring_protocol
    replace_contract_signals(
        db_session,
        contract_id=fx.contract.id,
        signals=[_signal_for(fx, selector="0x00000001")],
        job_id=fx.job.id,
    )
    db_session.commit()

    replace_contract_signals(
        db_session,
        contract_id=fx.contract.id,
        signals=[_signal_for(fx, selector="0x00000002")],
        job_id=fx.later_job.id,
    )
    db_session.commit()

    rows = db_session.query(FunctionScoreSignal).filter_by(contract_id=fx.contract.id).all()
    assert [r.selector for r in rows] == ["0x00000002"]


@pytest.mark.usefixtures("scoring_protocol")
def test_siblings_may_each_be_replaced_in_one_transaction(db_session, scoring_protocol):
    fx = scoring_protocol
    replace_contract_signals(db_session, contract_id=fx.contract.id, signals=[_signal_for(fx)], job_id=fx.job.id)
    replace_contract_signals(
        db_session,
        contract_id=fx.sibling.id,
        signals=[_signal_for(fx, contract_id=fx.sibling.id)],
        job_id=fx.job.id,
    )
    db_session.commit()
    assert db_session.query(FunctionScoreSignal).filter_by(protocol_id=fx.protocol.id).count() == 2


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
