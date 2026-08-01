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

from db.models import (  # noqa: E402
    Contract,
    FunctionScoreSignal,
    Job,
    Protocol,
    ProtocolScore,
    ProtocolScoreLatest,
)
from services.aggregations.company_overview import _entity_key as canon_entity_key  # noqa: E402
from services.scoring.population import (  # noqa: E402
    current_signals_for_protocol,
    replace_contract_signals,
)
from services.scoring.schema import (  # noqa: E402
    NOT_DETERMINED,
    FunctionSignal,
    PrincipalRef,
    ScoreDocument,
    Tri,
    coalesce_chain,
    entity_key,
    is_entity_key,
    not_determined_signal_defaults,
    signal_from_row,
    signal_to_row_kwargs,
)
from utils.scoring_status import (  # noqa: E402
    DESTINATION_BEARING_CLAIMS,
    DESTINATION_SHAPE_NOT_APPLICABLE,
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
    """No dataclass default may supply a state — omitting one is a TypeError.

    This is what makes ``not_determined`` un-defaultable: a distiller that never
    decided a state cannot construct the row at all.
    """
    with pytest.raises(TypeError):
        FunctionSignal(  # type: ignore[call-arg]
            job_id=uuid.uuid4(),
            protocol_id=1,
            contract_id=1,
            chain="ethereum",
            deployment_address="0xdead",
            function_name="f",
            claim_id="upgrade.implementation",
        )


def test_contract_id_is_required_because_it_is_identity():
    """R2-B2: split-proxy siblings are only told apart by contract_id.

    On the in-memory CLI path there is no DB to reject a None, so a default
    would let two siblings collapse into one another in the oracle.
    """
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
        FunctionSignal(**fields)  # type: ignore[call-arg]
    assert FunctionSignal(contract_id=7, **fields).contract_id == 7


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


class _Fixture:
    """Two jobs and two contracts sharing one deployment_address.

    The shared address is the split-proxy shape that is live on this corpus: a
    proxy whose secondary implementations are distinct ``contracts`` rows at one
    runtime address. It is the fixture default rather than a special case
    because the identity key has to survive it.
    """

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
    # Two implementation contracts at their own addresses, both of whose
    # functions are deployed behind ONE proxy — so their signals share a
    # deployment_address. This is the split-proxy secondary-impl shape that is
    # live on this corpus, and the identity key has to survive it.
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
    """The typed counterpart of :func:`_row`, bound to the fixture's identity."""
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
    # A proven 0.0 survives as a number, not as a NULL indistinguishable from
    # the undetermined row above it.
    assert rows[0].severity_proven is None
    assert float(rows[1].severity_proven) == 0.0
    # All three value states are distinct on the way back out.
    assert len({r.value_state for r in rows}) == 3
    assert rows[1].principal_refs[0]["function_principal_id"] == 3


@pytest.mark.usefixtures("scoring_protocol")
def test_undetermined_severity_cannot_carry_a_number(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add(_row(fx, severity_state=SEVERITY_STATE_NOT_DETERMINED, severity_proven=1.0))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_proven_severity_requires_a_number_and_a_basis(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add(_row(fx, severity_state=SEVERITY_STATE_PROVEN, severity_proven=None))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(
        _row(fx, severity_state=SEVERITY_STATE_PROVEN, severity_proven=0.9, severity_basis=[]),
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_empty_enumerated_principal_set_is_rejected(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add(_row(fx, principal_state=PRINCIPAL_STATE_ENUMERATED, principal_refs=[]))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_undetermined_value_cannot_smuggle_entity_keys(db_session, scoring_protocol):
    """A partial set under ``not_determined`` is a set a reader could total."""
    fx = scoring_protocol
    db_session.add(_row(fx, value_state=VALUE_STATE_NOT_DETERMINED, value_entity_keys=["ethereum::0x1"]))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_undetermined_destination_cannot_carry_a_shape(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add(_row(fx, destination_state=NOT_DETERMINED, destination_shape="caller_arbitrary"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(
        _row(
            fx,
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

    # And NOT NULL, so omission is an error rather than a NULL third state.
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
    """The real currency case: a SECOND job distilling the same contract.

    Re-analysis mints a new job, so a job-scoped delete would leave the first
    job's rows behind and the fold would count the contract twice. The delete is
    contract-scoped precisely so the later distillation supersedes the earlier
    one regardless of which job produced it.
    """
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
    """Contract-scoped means contract-scoped, even at a shared deployment address."""
    fx = scoring_protocol
    db_session.add_all([_row(fx), _row(fx, contract_id=fx.sibling.id)])
    db_session.commit()

    replace_contract_signals(db_session, contract_id=fx.contract.id, signals=[], job_id=fx.later_job.id)
    db_session.commit()

    survivors = db_session.query(FunctionScoreSignal).filter_by(protocol_id=fx.protocol.id).all()
    assert [r.contract_id for r in survivors] == [fx.sibling.id]


@pytest.mark.usefixtures("scoring_protocol")
def test_split_proxy_siblings_share_a_deployment_address_without_colliding(db_session, scoring_protocol):
    """Two contracts, one deployment_address, same selector and claim.

    Live on this corpus: secondary implementations behind one proxy. Without
    ``contract_id`` in the identity this is a unique-constraint violation and one
    of the two contracts' signals can never be written at all.
    """
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
    """A contract dropped from the perimeter must not outlive its own analysis."""
    fx = scoring_protocol
    db_session.add(_row(fx))
    db_session.commit()

    db_session.query(Contract).filter_by(id=fx.contract.id).delete()
    db_session.commit()

    assert db_session.query(FunctionScoreSignal).filter_by(protocol_id=fx.protocol.id).count() == 0


@pytest.mark.usefixtures("scoring_protocol")
def test_losing_the_job_keeps_the_signal(db_session, scoring_protocol):
    """``job_id`` is provenance: pruning it must not withdraw a current signal."""
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
def test_score_grade_pairing_is_enforced(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add(_score(fx, grade_state=GRADE_STATE_NOT_DETERMINED))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(_score(fx, grade_state=GRADE_STATE_COMPUTED, confidence_pct=None))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(
        _score(
            fx,
            grade_state=GRADE_STATE_NOT_DETERMINED,
            grade_lambda=None,
            grade_exposure=None,
            confidence_pct=None,
        )
    )
    db_session.commit()


@pytest.mark.usefixtures("scoring_protocol")
def test_score_document_is_inline_or_spilled_never_both(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add(_score(fx, findings={"a": 1}, storage_key="scores/1.json"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(_score(fx, findings=None, storage_key=None))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(_score(fx, findings=None, storage_key="scores/1.json"))
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
    """A ``not_determined`` fold wins if it is newest.

    Serving the last COMPUTED row instead would republish a stale grade as
    current — an absence reading as a fact at the read surface.
    """
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


# --------------------------------------------------------------------------
# Reviewer-required coverage: normalization, seam, gate reader, guards
# --------------------------------------------------------------------------


def test_chain_aliases_collapse_to_one_entity_key():
    """MAX-per-entity only dedups if the alias forms mint ONE key.

    Without the fold, ``"mainnet"``/``"Ethereum"``/``None`` would be three keys
    for one vault and the value axis would charge it three times.
    """
    keys = {entity_key(c, "0xVAULT") for c in (None, "", "  ", "mainnet", "Ethereum", "ETHEREUM", "ethereum")}
    assert keys == {"ethereum::0xvault"}
    assert coalesce_chain("MAINNET") == "ethereum"


def test_entity_key_is_byte_identical_to_the_codebase_canon():
    for chain in (None, "", "mainnet", "Ethereum", "optimism", "BASE"):
        for address in ("0xAbC", "0xdeadBEEF"):
            assert entity_key(chain, address) == canon_entity_key(chain, address)


def test_is_entity_key_rejects_unscoped_and_malformed_tokens():
    assert is_entity_key("ethereum::0xabc")
    # A bare address aliases every chain's copy of it into one entity.
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
    """S2: the pairing is biconditional in the Python layer too."""
    with pytest.raises(ValueError, match="must carry its witness"):
        Tri(state=SEVERITY_STATE_PROVEN, value=None)
    with pytest.raises(ValueError, match="must carry its witness"):
        Tri(state=DESTINATION_STATE_NOT_APPLICABLE, value=None)


def test_gate_input_raises_on_a_gate_that_was_never_distilled():
    """A ``dict.get`` here would return None and read as 'no constraint'."""
    sig = _signal(gate_inputs={"pause_effective": Tri.not_determined().to_json()})
    assert sig.gate_input("pause_effective").state == NOT_DETERMINED
    with pytest.raises(KeyError, match="duration_bound_seconds"):
        sig.gate_input("duration_bound_seconds")


def test_gate_inputs_must_be_tri_envelopes():
    with pytest.raises(ValueError, match="tri-state envelope"):
        _signal(gate_inputs={"pause_effective": True})


def test_gate_input_round_trips_all_three_states():
    gates = {
        "proven_present": Tri.proven(SEVERITY_STATE_PROVEN, 0.2).to_json(),
        "not_determined": Tri.not_determined().to_json(),
    }
    sig = _signal(gate_inputs=gates)
    assert sig.gate_input("proven_present").require(SEVERITY_STATE_PROVEN) == 0.2
    assert sig.gate_input("not_determined").value is None


def test_destination_bearing_claim_cannot_be_not_applicable():
    """Item 6: an unread delegatecall destination must not launder as 'none'."""
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
def test_destination_bearing_claim_cannot_be_not_applicable_in_the_db(db_session, scoring_protocol):
    fx = scoring_protocol
    db_session.add(
        _row(
            fx,
            claim_id="delegatecall.execute",
            destination_state=DESTINATION_STATE_NOT_APPLICABLE,
            destination_shape=DESTINATION_SHAPE_NOT_APPLICABLE,
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_proven_destination_must_carry_a_shape_in_the_db(db_session, scoring_protocol):
    """N2: the reverse arm of the destination biconditional."""
    fx = scoring_protocol
    db_session.add(_row(fx, destination_state=DESTINATION_STATE_UNCONSTRAINED_PROVEN, destination_shape=None))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_non_enumerated_principal_state_cannot_carry_refs(db_session, scoring_protocol):
    """N2: the reverse arm of the principal pairing."""
    fx = scoring_protocol
    db_session.add(
        _row(
            fx,
            principal_state=PRINCIPAL_STATE_NOT_DETERMINED,
            principal_refs=[{"function_principal_id": 1, "chain": "ethereum", "address": "0xa"}],
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_principal_refs_cannot_be_smuggled_as_an_object(db_session, scoring_protocol):
    """S3: a JSONB object is invisible to a length test but not to a reader."""
    fx = scoring_protocol
    db_session.add(_row(fx, principal_refs={"function_principal_id": 1}))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_proven_no_reach_cannot_carry_entity_keys(db_session, scoring_protocol):
    """N2: the reverse arm of the value pairing — an earned negative is empty."""
    fx = scoring_protocol
    db_session.add(
        _row(
            fx,
            value_state=VALUE_STATE_PROVEN_NO_REACH,
            value_basis="proven_no_reach",
            value_entity_keys=["ethereum::0x1"],
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_value_entity_keys_reject_nulls(db_session, scoring_protocol):
    """S7: a NULL element is an entity the fold cannot key."""
    fx = scoring_protocol
    db_session.add(
        _row(
            fx,
            value_state=VALUE_STATE_PROVEN_REACH,
            value_basis="observed_reach_value_usd",
            value_entity_keys=["ethereum::0x1", None],
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_signal_row_seam_round_trips_all_three_states(db_session, scoring_protocol):
    """S5: every field's three states survive the trip through Postgres.

    Both directions are exercised, because the failure this guards against is a
    state written to the wrong column — every individual value stays legal, so
    no CHECK downstream would notice.
    """
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

    # The three states stayed three on the way back out.
    assert len({s.value_state for s in restored}) == 3
    assert restored[1].severity.require(SEVERITY_STATE_PROVEN) == 0.0
    assert restored[0].severity.value is None


@pytest.mark.usefixtures("scoring_protocol")
def test_signal_from_row_is_the_inverse_of_to_row_kwargs(db_session, scoring_protocol):
    fx = scoring_protocol
    original = _signal_for(fx, severity=Tri.proven(SEVERITY_STATE_PROVEN, 0.75), severity_basis=("base",))
    row = FunctionScoreSignal(**signal_to_row_kwargs(original, job_id=fx.job.id))
    db_session.add(row)
    db_session.commit()
    assert signal_from_row(row) == original


@pytest.mark.usefixtures("scoring_protocol")
def test_replace_rejects_a_signal_for_another_contract(db_session, scoring_protocol):
    fx = scoring_protocol
    with pytest.raises(ValueError, match="passed to replace"):
        replace_contract_signals(
            db_session,
            contract_id=fx.contract.id,
            signals=[_signal_for(fx, contract_id=fx.sibling.id)],
            job_id=fx.job.id,
        )
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_latest_view_correlates_per_protocol(db_session, scoring_protocol):
    """N3: one protocol's newest row never becomes another's."""
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


# --------------------------------------------------------------------------
# Round-2: all-or-nothing replace, cross-field agreement, grouping guard
# --------------------------------------------------------------------------


@pytest.mark.usefixtures("scoring_protocol")
def test_a_rejected_signal_leaves_the_original_set_fully_intact(db_session, scoring_protocol):
    """R2-B1: validation runs before the delete, so a bad list changes nothing.

    The distillation call site is fail-forward, so it catches the raise and
    commits anyway. If the delete had already run, that commit would persist a
    partially replaced contract — charging a subset of its exposure with no
    trace that the rest went missing.
    """
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
    # The fail-forward caller commits regardless.
    db_session.commit()

    survivors = db_session.query(FunctionScoreSignal).filter_by(contract_id=fx.contract.id).all()
    assert sorted(r.selector for r in survivors) == ["0x00000001", "0x00000002"]


@pytest.mark.usefixtures("scoring_protocol")
def test_a_rejected_first_element_does_not_drop_the_contract(db_session, scoring_protocol):
    """The raise-on-first-element case: the contract must not vanish."""
    fx = scoring_protocol
    db_session.add(_row(fx))
    db_session.commit()

    with pytest.raises(ValueError):
        replace_contract_signals(
            db_session,
            contract_id=fx.contract.id,
            signals=[_signal_for(fx, contract_id=fx.sibling.id)],
            job_id=fx.later_job.id,
        )
    db_session.commit()

    assert db_session.query(FunctionScoreSignal).filter_by(contract_id=fx.contract.id).count() == 1


@pytest.mark.usefixtures("scoring_protocol")
def test_replace_rejects_a_signal_claiming_another_protocol(db_session, scoring_protocol):
    """N-a: a mismatched protocol_id would be read by the WRONG protocol's fold."""
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
def test_replace_rejects_a_signal_claiming_another_chain(db_session, scoring_protocol):
    """N-a: chain is part of the entity key; a mismatch mis-keys every value."""
    fx = scoring_protocol
    with pytest.raises(ValueError, match="claims chain"):
        replace_contract_signals(
            db_session,
            contract_id=fx.contract.id,
            signals=[_signal_for(fx, chain="optimism")],
            job_id=fx.job.id,
        )
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_replace_accepts_chain_aliases_of_the_contracts_chain(db_session, scoring_protocol):
    """The agreement test coalesces, so "mainnet" is not a false mismatch."""
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
def test_replace_rejects_an_uppercased_deployment_address(db_session, scoring_protocol):
    fx = scoring_protocol
    with pytest.raises(ValueError, match="lowercased"):
        replace_contract_signals(
            db_session,
            contract_id=fx.contract.id,
            signals=[_signal_for(fx, deployment_address=SHARED_ADDRESS.upper())],
            job_id=fx.job.id,
        )
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_replace_refuses_an_unknown_contract(db_session, scoring_protocol):
    fx = scoring_protocol
    with pytest.raises(ValueError, match="does not exist"):
        replace_contract_signals(db_session, contract_id=-1, signals=[], job_id=fx.job.id)
    db_session.rollback()


@pytest.mark.usefixtures("scoring_protocol")
def test_second_replace_of_one_contract_in_a_transaction_raises(db_session, scoring_protocol):
    """Item-4: grouping by (contract_id, deployment_address) must not truncate.

    The second call's delete would drop the first call's rows, leaving the
    contract carrying only its last deployment group — silent recall loss.
    """
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
    """The invariant is per-pass: the next distillation may replace again."""
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
    """The guard is per contract, not per pass — siblings are distinct contracts."""
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
    """N-b: a renamed or new destination-driven claim must not lose the guard."""
    from services.static.claims.matchers import discover
    from services.static.claims.registry import registry

    discover()
    registry_ids = set(registry())
    unknown = [c for c in DESTINATION_BEARING_CLAIMS if c not in registry_ids]
    assert unknown == [], (
        f"DESTINATION_BEARING_CLAIMS names claims the registry does not define: {unknown}. "
        "Rename them in utils/scoring_status.py or the destination guard stops firing."
    )
