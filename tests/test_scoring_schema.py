"""The scorer's two planes, and the three-state encoding they are built around.

Every test here pins one of the ways a ``not_determined`` could quietly become a
published fact:

  * a state discriminator acquiring a default, so an INSERT that determined
    nothing still records a state;
  * an undetermined severity carrying a number a reader could pick up anyway;
  * an empty principal list published as a proven caller set;
  * a proven-absent value and an unread value collapsing into one state;
  * an unread destination presenting as an unconstrained one — the escalation
    that made the prototype's delegatecall false positive an F;
  * the ``_latest`` view answering with a stale computed row instead of the
    newest verdict.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402

from db.models import FunctionScoreSignal, Job, Protocol, ProtocolScore, ProtocolScoreLatest  # noqa: E402
from services.scoring.schema import (  # noqa: E402
    NOT_DETERMINED,
    FunctionSignal,
    PrincipalRef,
    ScoreDocument,
    Tri,
    entity_key,
    not_determined_signal_defaults,
)
from utils.scoring_status import (  # noqa: E402
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_UNCONSTRAINED_PROVEN,
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    MODEL_VERSION,
    OPENNESS_NOT_DETERMINED,
    OPENNESS_RESTRICTED,
    PERIMETER_NOT_DETERMINED,
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

# --------------------------------------------------------------------------
# The typed contract (no DB)
# --------------------------------------------------------------------------


def test_entity_key_is_chain_scoped():
    """The same address on two chains is two entities (#158 twin aliasing)."""
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
    """No silent ``None`` flows into arithmetic from an undetermined fact."""
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
        chain="ethereum",
        deployment_address="0xdead",
        function_name="setImplementation",
        claim_id="upgrade.implementation",
        **not_determined_signal_defaults(),
    )
    base.update(overrides)
    return FunctionSignal(**base)


def test_every_three_state_field_must_be_named():
    """No dataclass default may supply a state — omitting one is a TypeError.

    This is what makes ``not_determined`` un-defaultable: a distiller that never
    decided a state cannot construct the row at all.
    """
    with pytest.raises(TypeError):
        FunctionSignal(  # type: ignore[call-arg]
            job_id=uuid.uuid4(),
            protocol_id=1,
            chain="ethereum",
            deployment_address="0xdead",
            function_name="f",
            claim_id="upgrade.implementation",
        )


def test_fully_undetermined_signal_is_constructible_and_not_scored():
    sig = _signal()
    assert sig.severity.state == SEVERITY_STATE_NOT_DETERMINED
    assert sig.witness_tier == WITNESS_TIER_NOT_DETERMINED
    assert sig.authority_openness == OPENNESS_NOT_DETERMINED
    assert sig.principal_state == PRINCIPAL_STATE_NOT_DETERMINED
    assert sig.value_state == VALUE_STATE_NOT_DETERMINED
    # The fail-closed gate: an undetermined severity never enters the grade.
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
    """``pause.set`` builds up from a proven 0.0 — a fact, not an absence."""
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


def test_principal_refs_carry_no_resolution():
    ref = PrincipalRef(function_principal_id=7, chain="ethereum", address="0xAAA")
    assert set(ref.to_json()) == {"function_principal_id", "chain", "address"}
    assert ref.key == "ethereum::0xaaa"
    assert PrincipalRef.from_json(ref.to_json()) == ref


def test_value_states_are_three_and_bounds_require_a_proven_reach():
    reached = _signal(
        value_state=VALUE_STATE_PROVEN_REACH,
        value_entity_keys=("ethereum::0x1",),
        value_bound=VALUE_BOUND_FLOOR,
        value_basis="observed_reach_floor_usd",
    )
    assert reached.value_bound == VALUE_BOUND_FLOOR

    # Proven-absent reach is a real, distinct state and carries no entities.
    absent = _signal(value_state=VALUE_STATE_PROVEN_NO_REACH, value_basis="proven_no_reach")
    assert absent.value_entity_keys == ()

    with pytest.raises(ValueError, match="proven_reach"):
        _signal(value_state=VALUE_STATE_PROVEN_REACH, value_entity_keys=())
    with pytest.raises(ValueError, match="bounded"):
        _signal(value_bound=VALUE_BOUND_FLOOR)


def test_destination_not_applicable_differs_from_not_determined():
    """``pause.set`` has no destination; an unread delegatecall has one.

    Collapsing these makes the banned escalation representable again: an
    unproven destination graded as an unconstrained one is the −30λ, F→C false
    positive this schema exists to prevent.
    """
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


def test_perimeter_has_a_third_state():
    """A queue read that failed lands on neither polarity."""
    assert len({PERIMETER_SETTLED, PERIMETER_UNSETTLED, PERIMETER_NOT_DETERMINED}) == 3


# --------------------------------------------------------------------------
# Persistence round-trip
# --------------------------------------------------------------------------


@pytest.fixture()
def scoring_protocol(db_session):
    protocol = Protocol(name=f"scoretest-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.flush()
    job = Job(id=uuid.uuid4(), protocol_id=protocol.id)
    db_session.add(job)
    db_session.commit()
    try:
        yield protocol, job
    finally:
        db_session.rollback()
        db_session.query(FunctionScoreSignal).filter_by(protocol_id=protocol.id).delete()
        db_session.query(ProtocolScore).filter_by(protocol_id=protocol.id).delete()
        db_session.query(Job).filter_by(id=job.id).delete()
        db_session.query(Protocol).filter_by(id=protocol.id).delete()
        db_session.commit()


def _row(protocol, job, **overrides: Any) -> FunctionScoreSignal:
    base: dict[str, Any] = dict(
        job_id=job.id,
        protocol_id=protocol.id,
        chain="ethereum",
        deployment_address="0xdead",
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


@pytest.mark.usefixtures("scoring_protocol")
def test_signal_three_states_round_trip(db_session, scoring_protocol):
    protocol, job = scoring_protocol
    db_session.add_all(
        [
            _row(protocol, job, selector="0x00000001"),
            _row(
                protocol,
                job,
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
                protocol,
                job,
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
        .filter_by(protocol_id=protocol.id)
        .order_by(FunctionScoreSignal.selector)
        .all()
    )
    assert [r.severity_state for r in rows] == [
        SEVERITY_STATE_NOT_DETERMINED,
        SEVERITY_STATE_PROVEN,
        SEVERITY_STATE_NOT_DETERMINED,
    ]
    # A proven 0.0 survives as a number, not as a NULL indistinguishable from
    # the undetermined row above it.
    assert rows[0].severity_proven is None
    assert float(rows[1].severity_proven) == 0.0
    # All three value states are distinct on the way back out.
    assert len({r.value_state for r in rows}) == 3
    assert rows[1].principal_refs[0]["function_principal_id"] == 3


@pytest.mark.usefixtures("scoring_protocol")
def test_undetermined_severity_cannot_carry_a_number(db_session, scoring_protocol):
    protocol, job = scoring_protocol
    db_session.add(_row(protocol, job, severity_state=SEVERITY_STATE_NOT_DETERMINED, severity_proven=1.0))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_proven_severity_requires_a_number_and_a_basis(db_session, scoring_protocol):
    protocol, job = scoring_protocol
    db_session.add(_row(protocol, job, severity_state=SEVERITY_STATE_PROVEN, severity_proven=None))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(
        _row(protocol, job, severity_state=SEVERITY_STATE_PROVEN, severity_proven=0.9, severity_basis=[]),
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_empty_enumerated_principal_set_is_rejected(db_session, scoring_protocol):
    protocol, job = scoring_protocol
    db_session.add(_row(protocol, job, principal_state=PRINCIPAL_STATE_ENUMERATED, principal_refs=[]))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_undetermined_value_cannot_smuggle_entity_keys(db_session, scoring_protocol):
    """A partial set under ``not_determined`` is a set a reader could total."""
    protocol, job = scoring_protocol
    db_session.add(_row(protocol, job, value_state=VALUE_STATE_NOT_DETERMINED, value_entity_keys=["ethereum::0x1"]))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_undetermined_destination_cannot_carry_a_shape(db_session, scoring_protocol):
    protocol, job = scoring_protocol
    db_session.add(_row(protocol, job, destination_state=NOT_DETERMINED, destination_shape="caller_arbitrary"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(
        _row(
            protocol,
            job,
            destination_state=DESTINATION_STATE_UNCONSTRAINED_PROVEN,
            destination_shape="caller_arbitrary",
        )
    )
    db_session.commit()


@pytest.mark.usefixtures("scoring_protocol")
def test_state_columns_have_no_default(db_session, scoring_protocol):
    """A raw INSERT omitting a discriminator raises instead of defaulting.

    The whole convention rests on this: with a server default, a writer that
    never determined the fact would record ``not_determined`` silently, which is
    exactly an unread witness becoming a published one.
    """
    protocol, job = scoring_protocol
    with pytest.raises(IntegrityError):
        db_session.execute(
            text(
                "INSERT INTO function_score_signals "
                "(job_id, protocol_id, chain, deployment_address, function_name, claim_id, "
                " witness_tier, severity_basis, authority_openness, principal_state, principal_refs, "
                " value_state, value_bound, value_entity_keys, value_basis, destination_state, "
                " reach_gate_state, gate_inputs, citations, witness_notes) "
                "VALUES (:job, :proto, 'ethereum', '0xdead', 'f', 'pause.set', "
                " :tier, '{}', :open, :pstate, '[]'::jsonb, "
                " :vstate, :vbound, '{}', 'x', :dstate, :rgate, '{}'::jsonb, '[]'::jsonb, '{}')"
            ),
            {
                "job": str(job.id),
                "proto": protocol.id,
                "tier": WITNESS_TIER_NOT_DETERMINED,
                "open": OPENNESS_NOT_DETERMINED,
                "pstate": PRINCIPAL_STATE_NOT_DETERMINED,
                "vstate": VALUE_STATE_NOT_DETERMINED,
                "vbound": VALUE_BOUND_NOT_DETERMINED,
                "dstate": NOT_DETERMINED,
                "rgate": REACH_GATE_NOT_DETERMINED,
            },
        )
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_signals_are_replaced_wholesale_per_job(db_session, scoring_protocol):
    protocol, job = scoring_protocol
    db_session.add_all([_row(protocol, job, selector=f"0x0000000{n}") for n in (1, 2)])
    db_session.commit()

    db_session.query(FunctionScoreSignal).filter_by(job_id=job.id).delete(synchronize_session=False)
    db_session.add(_row(protocol, job, selector="0x00000009"))
    db_session.commit()

    remaining = db_session.query(FunctionScoreSignal).filter_by(job_id=job.id).all()
    assert [r.selector for r in remaining] == ["0x00000009"]


def _score(protocol, **overrides: Any) -> ProtocolScore:
    base: dict[str, Any] = dict(
        protocol_id=protocol.id,
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
def test_score_grade_pairing_is_enforced(db_session, scoring_protocol):
    protocol, _job = scoring_protocol
    db_session.add(_score(protocol, grade_state=GRADE_STATE_NOT_DETERMINED))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(_score(protocol, grade_state=GRADE_STATE_COMPUTED, confidence_pct=None))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(
        _score(
            protocol,
            grade_state=GRADE_STATE_NOT_DETERMINED,
            grade_lambda=None,
            grade_exposure=None,
            confidence_pct=None,
        )
    )
    db_session.commit()


@pytest.mark.usefixtures("scoring_protocol")
def test_score_document_is_inline_or_spilled_never_both(db_session, scoring_protocol):
    protocol, _job = scoring_protocol
    db_session.add(_score(protocol, findings={"a": 1}, storage_key="scores/1.json"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(_score(protocol, findings=None, storage_key=None))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(_score(protocol, findings=None, storage_key="scores/1.json"))
    db_session.commit()


@pytest.mark.usefixtures("scoring_protocol")
def test_latest_view_returns_the_newest_row_per_protocol(db_session, scoring_protocol):
    protocol, _job = scoring_protocol
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            _score(protocol, computed_at=now - timedelta(hours=2), confidence_pct=10.0),
            _score(protocol, computed_at=now - timedelta(hours=1), confidence_pct=20.0),
            _score(protocol, computed_at=now, confidence_pct=30.0),
        ]
    )
    db_session.commit()

    latest = db_session.query(ProtocolScoreLatest).filter_by(protocol_id=protocol.id).all()
    assert len(latest) == 1
    assert float(latest[0].confidence_pct) == 30.0


@pytest.mark.usefixtures("scoring_protocol")
def test_latest_view_prefers_the_newest_verdict_over_the_newest_grade(db_session, scoring_protocol):
    """A ``not_determined`` fold wins if it is newest.

    Serving the last COMPUTED row instead would republish a stale grade as
    current — an absence reading as a fact at the read surface.
    """
    protocol, _job = scoring_protocol
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            _score(protocol, computed_at=now - timedelta(hours=1)),
            _score(
                protocol,
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

    latest = db_session.query(ProtocolScoreLatest).filter_by(protocol_id=protocol.id).one()
    assert latest.grade_state == GRADE_STATE_NOT_DETERMINED
    assert latest.grade_lambda is None


@pytest.mark.usefixtures("scoring_protocol")
def test_latest_view_breaks_same_instant_ties_deterministically(db_session, scoring_protocol):
    protocol, _job = scoring_protocol
    now = datetime.now(timezone.utc)
    db_session.add_all([_score(protocol, computed_at=now, confidence_pct=c) for c in (11.0, 22.0)])
    db_session.commit()

    rows = db_session.query(ProtocolScoreLatest).filter_by(protocol_id=protocol.id).all()
    assert len(rows) == 1
    newest_id = (
        db_session.query(ProtocolScore.id)
        .filter_by(protocol_id=protocol.id)
        .order_by(ProtocolScore.id.desc())
        .first()[0]
    )
    assert rows[0].id == newest_id
