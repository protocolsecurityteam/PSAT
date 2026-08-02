"""The scorer's pipeline seams: the effects hook, the dirty marks, the loop, the API.

The core (distillation + fold) is pinned elsewhere. What is pinned here is
everything between it and the run:

  * a job's effects completion persists signals and enqueues a re-fold, and a
    distillation that raises does NOT fail the job — effects never emits
    ``failed_terminal``, so a scoring bug must not become a pipeline outage;
  * a persist that fails on contract N leaves contracts 1..N-1 standing, and
    leaves no half-replaced contract behind;
  * every write site that changes a scored input marks, and a mark that cannot
    be written never fails its host;
  * the loop folds dirty protocols before stale ones, stamps the perimeter it
    was handed rather than a polarity of its own, accumulates history instead of
    overwriting it, clears only the exact mark it consumed, and backs off a
    protocol whose fold keeps raising;
  * the double-replace guard stays armed across the savepoints the hook is made
    of, which is the only shape it ever actually sees;
  * the endpoint serves the ledger payload verbatim, distinguishes "no score"
    from "unreadable document", and reassembles a spilled one.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from db.models import (
    AuditContractCoverage,
    AuditReport,
    Contract,
    EffectiveFunction,
    FunctionScoreSignal,
    Job,
    JobStatus,
    MonitoredContract,
    Protocol,
    ProtocolScore,
    ProtocolScoreQueue,
)
from services.scoring import loop as score_loop
from services.scoring import persist as score_persist
from services.scoring.dirty import (
    SCORE_DIRTY_COVERAGE,
    SCORE_DIRTY_COVERAGE_VERIFY,
    SCORE_DIRTY_EFFECTS,
    SCORE_DIRTY_MANUAL,
    SCORE_DIRTY_REANALYSIS,
    mark_protocol_score_dirty,
)
from services.scoring.loop import DueProtocol, score_protocol, select_due_protocols
from services.scoring.persist import (
    INLINE_DOCUMENT_LIMIT_BYTES,
    ScoreDocumentUnavailable,
    load_score_document,
    persist_score_document,
)
from services.scoring.population import replace_contract_signals
from services.scoring.schema import FunctionSignal, ScoreDocument, not_determined_signal_defaults
from tests.conftest import DATABASE_URL
from utils.scoring_status import (
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    MODEL_VERSION,
    PERIMETER_NOT_DETERMINED,
    PERIMETER_SETTLED,
    PERIMETER_UNSETTLED,
    SCORE_TRIGGER_DIRTY_LOOP,
    SCORE_TRIGGER_MANUAL,
    SCORE_TRIGGER_STALENESS_SWEEP,
)

PAUSE_CLAIM = {
    "claim_id": "pause.set",
    "tier": "standard_exact",
    "witness": {"kind": "pause_latch"},
}


class _Fixture:
    """One protocol, one job, and whatever contracts a test asks for."""

    def __init__(self, session, protocol, job):
        self.session = session
        self.protocol = protocol
        self.job = job
        self.contracts: list[Contract] = []

    def contract(self, address: str | None = None, *, job: Job | None = None) -> Contract:
        row = Contract(
            address=address or ("0x" + uuid.uuid4().hex[:40]),
            chain="ethereum",
            protocol_id=self.protocol.id,
            job_id=(job or self.job).id,
        )
        self.session.add(row)
        self.session.commit()
        self.contracts.append(row)
        return row

    def function(self, contract: Contract, *, name: str = "pause") -> EffectiveFunction:
        row = EffectiveFunction(
            contract_id=contract.id,
            deployment_address=contract.address,
            function_name=name,
            selector="0x" + uuid.uuid4().hex[:8],
            abi_signature=f"{name}()",
            authority_public=True,
            authority_openness="open",
            claims=[PAUSE_CLAIM],
        )
        self.session.add(row)
        self.session.commit()
        return row

    def queued_row(self) -> ProtocolScoreQueue | None:
        return self.session.get(ProtocolScoreQueue, self.protocol.id)

    def signals(self) -> list[FunctionScoreSignal]:
        return self.session.query(FunctionScoreSignal).filter_by(protocol_id=self.protocol.id).order_by("id").all()

    def scores(self) -> list[ProtocolScore]:
        return (
            self.session.query(ProtocolScore)
            .filter_by(protocol_id=self.protocol.id)
            .order_by(ProtocolScore.computed_at, ProtocolScore.id)
            .all()
        )


@pytest.fixture()
def fx(db_session):
    """A protocol scoped to one test, torn down whole.

    Its own ``Protocol`` row rather than a shared one: the fold, the queue and
    the score history are all protocol-keyed, so a test that leaked rows into a
    neighbour's protocol would change that neighbour's grade.
    """
    protocol = Protocol(name=f"scoreint-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.flush()
    # ``completed``, not the ``queued`` default: an in-flight job is what makes
    # the perimeter unsettled, and the fixture must not stamp that on every test
    # that never asked for it.
    job = Job(id=uuid.uuid4(), protocol_id=protocol.id, status=JobStatus.completed)
    db_session.add(job)
    db_session.commit()
    protocol_id, contract_ids = protocol.id, []
    fixture = _Fixture(db_session, protocol, job)
    try:
        yield fixture
    finally:
        db_session.rollback()
        contract_ids = [c.id for c in fixture.contracts]
        db_session.query(FunctionScoreSignal).filter_by(protocol_id=protocol_id).delete()
        db_session.query(ProtocolScore).filter_by(protocol_id=protocol_id).delete()
        db_session.query(ProtocolScoreQueue).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        db_session.query(MonitoredContract).filter_by(protocol_id=protocol_id).delete()
        for contract_id in contract_ids:
            db_session.query(Contract).filter_by(id=contract_id).delete()
        db_session.query(Job).filter(Job.protocol_id == protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


@pytest.fixture()
def other_session():
    """A SECOND connection, for the interleavings a single session cannot express.

    The mark's ``dirty_at`` is ``transaction_timestamp()`` and the defect it
    guards against is a mark stamped in one transaction becoming visible only
    after another transaction has already read the population. One session
    cannot hold two transactions, so the test needs a real second one.
    """
    engine = create_engine(DATABASE_URL)
    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        engine.dispose()


def _document(protocol_id: int, **overrides: Any) -> ScoreDocument:
    base: dict[str, Any] = dict(
        protocol_id=protocol_id,
        model_version=MODEL_VERSION,
        computed_at=datetime.now(timezone.utc),
        trigger=SCORE_TRIGGER_MANUAL,
        perimeter_state=PERIMETER_SETTLED,
        grade_state=GRADE_STATE_NOT_DETERMINED,
        grade_lambda=None,
        grade_exposure=None,
        confidence_pct=None,
        findings=[],
        earned_negatives=[],
        warnings=[],
        model_parameters={"sev_scale": 60},
        provenance={"population": {"signals": 0}},
    )
    base.update(overrides)
    return ScoreDocument(**base)


# --------------------------------------------------------------------------
# The end-of-effects hook
# --------------------------------------------------------------------------


def _effects_worker(monkeypatch):
    """An ``EffectsWorker`` whose selection is empty, so no wire is ever touched.

    Selection is not what this file tests; the hook after it is. Forcing the
    zero-candidate branch keeps the test offline AND exercises the inert path,
    which distils too — a contract whose job planned nothing still owns the
    claims the policy stage wrote for it.
    """
    from workers.effects_worker import EffectsWorker

    monkeypatch.setattr(EffectsWorker, "_select", lambda self, session, job: [])
    return EffectsWorker()


def test_effects_completion_persists_signals_and_marks_dirty(fx, monkeypatch):
    contract = fx.contract()
    fx.function(contract)
    worker = _effects_worker(monkeypatch)

    worker._process(fx.session, fx.job)
    fx.session.commit()

    signals = fx.signals()
    assert signals, "effects completion wrote no score signals"
    assert {s.contract_id for s in signals} == {contract.id}
    assert all(s.job_id == fx.job.id for s in signals), "job_id is the provenance column and must be stamped"
    mark = fx.queued_row()
    assert mark is not None and mark.reason == SCORE_DIRTY_EFFECTS


def test_effects_replaces_rather_than_accumulates(fx, monkeypatch):
    """A second pass over the same contract must not double the population."""
    contract = fx.contract()
    fx.function(contract)
    worker = _effects_worker(monkeypatch)

    worker._process(fx.session, fx.job)
    fx.session.commit()
    first = len(fx.signals())
    assert first

    worker._process(fx.session, fx.job)
    fx.session.commit()
    assert len(fx.signals()) == first


def test_poisoned_distillation_does_not_fail_the_job(fx, monkeypatch, caplog):
    """Effects never emits ``failed_terminal``; a scoring bug must not change that."""
    contract = fx.contract()
    fx.function(contract)
    worker = _effects_worker(monkeypatch)

    import services.scoring.distill as distill_module

    def _boom(session, job):
        raise RuntimeError("distillation exploded")

    monkeypatch.setattr(distill_module, "distill_job_signals", _boom)

    with caplog.at_level(logging.WARNING, logger="workers.effects_worker"):
        worker._process(fx.session, fx.job)
    fx.session.commit()

    assert fx.signals() == []
    assert fx.queued_row() is None, "nothing was distilled, so nothing was invalidated"
    messages = [r.getMessage() for r in caplog.records]
    assert any("score-signal distillation failed" in m for m in messages), messages
    assert any(str(fx.job.id) in m for m in messages), "the failure must carry job context"


def test_claims_bridge_survives_a_distillation_failure(fx, monkeypatch):
    """The hook runs inside the job's transaction, so its failure must be contained.

    A raise outside a SAVEPOINT would abort the transaction the effects stage's
    own writes are sitting in, and the job would die at commit — fail-forward
    defeated by the transaction rather than by an exception.
    """
    contract = fx.contract()
    function = fx.function(contract)
    worker = _effects_worker(monkeypatch)

    import services.scoring.distill as distill_module

    def _bad_sql(session, job):
        session.execute(__import__("sqlalchemy").text("SELECT * FROM table_that_does_not_exist"))
        return {}

    monkeypatch.setattr(distill_module, "distill_job_signals", _bad_sql)

    function.function_name = "renamedByTheStage"
    worker._process(fx.session, fx.job)
    fx.session.commit()

    fx.session.expire_all()
    assert fx.session.get(EffectiveFunction, function.id).function_name == "renamedByTheStage"


def test_partial_persist_keeps_the_contracts_that_succeeded(fx, monkeypatch, caplog):
    """Contract N failing does not discard contracts 1..N-1 — each was a whole replace."""
    first = fx.contract()
    second = fx.contract()
    fx.function(first)
    fx.function(second)
    worker = _effects_worker(monkeypatch)

    import services.scoring.population as population_module

    real = population_module.replace_contract_signals

    def _fail_on_second(session, *, contract_id, signals, job_id=None):
        if contract_id == second.id:
            raise RuntimeError("persist exploded")
        return real(session, contract_id=contract_id, signals=signals, job_id=job_id)

    monkeypatch.setattr(population_module, "replace_contract_signals", _fail_on_second)

    with caplog.at_level(logging.WARNING, logger="workers.effects_worker"):
        worker._process(fx.session, fx.job)
    fx.session.commit()

    persisted = {s.contract_id for s in fx.signals()}
    assert persisted == {first.id}, "the surviving contract's complete signal set must stand"
    assert fx.queued_row() is not None, "a partial pass still changed the population"
    assert any(str(second.id) in r.getMessage() for r in caplog.records), "the failing contract must be named"


def test_retracting_every_signal_for_a_contract_is_logged(fx, monkeypatch, caplog):
    """A wholesale replace by an EMPTY set is fail-open by construction.

    It is correct when the functions genuinely went away and wrong when anything
    upstream merely failed to produce them, and the row count cannot tell the
    two apart — so the retraction is named rather than left silent.
    """
    contract = fx.contract()
    fx.function(contract)
    worker = _effects_worker(monkeypatch)
    worker._process(fx.session, fx.job)
    fx.session.commit()
    assert fx.signals()

    import services.scoring.distill as distill_module

    monkeypatch.setattr(distill_module, "distill_job_signals", lambda session, job: {contract.id: []})

    with caplog.at_level(logging.WARNING, logger="workers.effects_worker"):
        worker._process(fx.session, fx.job)
    fx.session.commit()

    assert fx.signals() == []
    assert any("retracted all" in r.getMessage() and str(contract.id) in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------
# The double-replace guard, under the savepoint shape the hook actually uses
# --------------------------------------------------------------------------


def _signal_for(fx, contract: Contract, selector: str) -> FunctionSignal:
    return FunctionSignal(
        job_id=fx.job.id,
        protocol_id=fx.protocol.id,
        contract_id=contract.id,
        chain="ethereum",
        deployment_address=contract.address,
        selector=selector,
        function_name="pause",
        claim_id="pause.set",
        **not_determined_signal_defaults(),
    )


def _replace_in_savepoint(fx, contract: Contract, selector: str = "0x00000001") -> None:
    """Exactly the effects hook's shape: one savepoint per contract, no commit.

    Carries a real signal so the replace actually INSERTS. That matters: an
    empty replace never flushes pending objects, and it is the flush that opens
    the internal SUBTRANSACTION whose end is the second way this guard can be
    disarmed.
    """
    with fx.session.begin_nested():
        replace_contract_signals(
            fx.session, contract_id=contract.id, signals=[_signal_for(fx, contract, selector)], job_id=fx.job.id
        )


def test_the_double_replace_guard_survives_savepoints(fx):
    """The guard's invariant is per-PASS, so it must outlive the pass's savepoints.

    ``after_commit``/``after_rollback`` also fire on SAVEPOINT release, and a
    plain ``flush`` ends an internal SUBTRANSACTION that reports itself as
    un-nested — either one disarms the guard after every contract, and a caller
    that regrouped its signals finer than ``contract_id`` would then silently
    truncate the contract instead of raising.
    """
    contract = fx.contract()
    _replace_in_savepoint(fx, contract)

    with pytest.raises(ValueError, match="already replaced"):
        _replace_in_savepoint(fx, contract, "0x00000002")


def test_a_failed_contract_does_not_disarm_the_guard(fx):
    """The savepoint rollback path — the other half of the same wiring."""
    contract = fx.contract()
    sibling = fx.contract()
    _replace_in_savepoint(fx, contract)

    with pytest.raises(RuntimeError):
        with fx.session.begin_nested():
            replace_contract_signals(
                fx.session, contract_id=sibling.id, signals=[_signal_for(fx, sibling, "0x00000003")], job_id=fx.job.id
            )
            raise RuntimeError("this contract failed")

    with pytest.raises(ValueError, match="already replaced"):
        _replace_in_savepoint(fx, contract, "0x00000002")


def test_committing_the_pass_disarms_the_guard(fx):
    """Per-pass, not forever: the next job's distillation must be able to replace."""
    contract = fx.contract()
    _replace_in_savepoint(fx, contract)
    fx.session.commit()

    _replace_in_savepoint(fx, contract, "0x00000002")  # a new pass; no raise


# --------------------------------------------------------------------------
# The dirty mark
# --------------------------------------------------------------------------


def test_mark_is_one_row_per_protocol_and_bumps_dirty_at(fx):
    assert mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_MANUAL)
    fx.session.commit()
    first = fx.queued_row().dirty_at

    assert mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    fx.session.commit()
    fx.session.expire_all()
    row = fx.queued_row()

    assert fx.session.query(ProtocolScoreQueue).filter_by(protocol_id=fx.protocol.id).count() == 1
    assert row.dirty_at >= first
    assert row.reason == SCORE_DIRTY_EFFECTS


def test_a_failed_mark_never_breaks_its_host_transaction(fx, caplog):
    """An unmarkable protocol costs latency, not the caller's work."""
    with caplog.at_level(logging.WARNING, logger="services.scoring.dirty"):
        assert mark_protocol_score_dirty(fx.session, 2_000_000_001, SCORE_DIRTY_MANUAL) is False
    assert any("dirty-mark failed" in r.getMessage() for r in caplog.records)

    # The host transaction is still usable — this is the whole point of the guard.
    contract = fx.contract()
    fx.session.commit()
    assert fx.session.get(Contract, contract.id) is not None


def test_non_integer_protocol_is_not_marked(fx):
    assert mark_protocol_score_dirty(fx.session, None, SCORE_DIRTY_MANUAL) is False
    fx.session.commit()
    assert fx.queued_row() is None


def test_coverage_worker_marks_dirty(fx, monkeypatch):
    from workers.coverage_worker import CoverageWorker

    contract = fx.contract()
    monkeypatch.setattr(
        "services.audits.coverage.upsert_coverage_for_contract",
        lambda session, contract_id, verify_source_equivalence=True: 0,
    )
    worker = CoverageWorker()
    monkeypatch.setattr(worker, "update_detail", lambda session, job, detail: None)

    worker.process(fx.session, fx.job)

    assert contract.id
    mark = fx.queued_row()
    assert mark is not None and mark.reason == SCORE_DIRTY_COVERAGE


def _coverage_row(fx, status: str) -> AuditContractCoverage:
    audit = AuditReport(
        protocol_id=fx.protocol.id,
        url="https://example.invalid/a.pdf",
        auditor="Someone",
        title="An audit",
    )
    fx.session.add(audit)
    fx.session.flush()
    contract = fx.contract()
    row = AuditContractCoverage(
        audit_report_id=audit.id,
        contract_id=contract.id,
        protocol_id=fx.protocol.id,
        matched_name="Vault",
        match_type="name",
        match_confidence="medium",
        equivalence_status=status,
    )
    fx.session.add(row)
    fx.session.commit()
    return row


def test_coverage_verify_flip_marks_dirty(fx):
    from services.audits.coverage import _stamp_coverage_row

    row = _coverage_row(fx, "pending")
    _stamp_coverage_row(fx.session, row, status="proven", reason=None, proven=True, matched_commit_sha="abc")
    fx.session.commit()

    mark = fx.queued_row()
    assert mark is not None and mark.reason == SCORE_DIRTY_COVERAGE_VERIFY


def test_coverage_verify_restamp_of_the_same_status_marks_nothing(fx):
    """A re-stamp changed no scored input, so it enqueues no fold."""
    from services.audits.coverage import _stamp_coverage_row

    row = _coverage_row(fx, "proven")
    _stamp_coverage_row(fx.session, row, status="proven", reason=None, proven=True, matched_commit_sha="abc")
    fx.session.commit()

    assert fx.queued_row() is None


def test_reanalysis_marks_dirty(fx):
    from services.monitoring.reanalysis import maybe_queue_reanalysis

    mc = MonitoredContract(
        address="0x" + "cd" * 20,
        chain="ethereum",
        protocol_id=fx.protocol.id,
        contract_type="proxy",
        is_active=True,
    )
    fx.session.add(mc)
    fx.session.commit()

    job = maybe_queue_reanalysis(fx.session, mc, "upgraded")
    assert job is not None

    mark = fx.queued_row()
    assert mark is not None and mark.reason == SCORE_DIRTY_REANALYSIS


# --------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------


def test_dirty_protocol_is_scored_and_its_mark_cleared(fx):
    contract = fx.contract()
    fx.function(contract)
    mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    fx.session.commit()

    due = [d for d in select_due_protocols(fx.session, limit=50) if d.protocol_id == fx.protocol.id]
    assert due and due[0].trigger == SCORE_TRIGGER_DIRTY_LOOP

    score_protocol(fx.session, due[0])

    scores = fx.scores()
    assert len(scores) == 1
    assert scores[0].trigger == SCORE_TRIGGER_DIRTY_LOOP
    assert scores[0].model_version == MODEL_VERSION
    assert fx.queued_row() is None, "a mark the fold accounted for must be cleared"


def test_a_mark_committed_after_selection_is_not_cleared(fx, other_session):
    """The real interleaving, not a hand-fed instant.

    Reproduces the shape the effects stage actually has: ONE long transaction
    whose mark carries ``transaction_timestamp()`` — a stamp from BEFORE the
    loop ran — but whose data only becomes visible when it commits, after the
    loop already selected. A clear keyed on any instant the loop captured would
    delete this mark, and the change it describes would never be folded.
    """
    mark_protocol_score_dirty(other_session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    other_session.flush()  # stamped, still invisible to the loop

    due = [d for d in select_due_protocols(fx.session, limit=500) if d.protocol_id == fx.protocol.id]
    assert due and due[0].trigger == SCORE_TRIGGER_STALENESS_SWEEP, "the uncommitted mark must be invisible"

    other_session.commit()  # the marker's data lands mid-fold

    score_protocol(fx.session, due[0])

    assert fx.queued_row() is not None, "a mark this fold could not have seen must survive"


def test_a_mark_that_lands_during_the_fold_survives(fx, other_session):
    """Selected mark cleared by token equality; a newer mark has a newer token."""
    mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    fx.session.commit()
    due = [d for d in select_due_protocols(fx.session, limit=500) if d.protocol_id == fx.protocol.id][0]
    assert due.dirty_at is not None

    mark_protocol_score_dirty(other_session, fx.protocol.id, SCORE_DIRTY_COVERAGE)
    other_session.commit()
    fx.session.expire_all()
    bumped = fx.queued_row().dirty_at
    assert bumped != due.dirty_at, "two transactions must not share a transaction_timestamp; otherwise a flake"

    score_protocol(fx.session, due)

    survivor = fx.queued_row()
    assert survivor is not None and survivor.reason == SCORE_DIRTY_COVERAGE


def test_scores_accumulate_rather_than_overwrite(fx):
    """Insert-only: a re-fold never destroys the row a consumer already read."""
    for _ in range(2):
        mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
        fx.session.commit()
        score_protocol(fx.session, DueProtocol(fx.protocol.id, SCORE_TRIGGER_DIRTY_LOOP))

    assert len(fx.scores()) == 2


def test_dirty_protocols_are_selected_before_stale_ones(fx, db_session):
    """A witnessed change outranks the mere possibility of one."""
    other = Protocol(name=f"scoreint-stale-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.commit()
    try:
        mark_protocol_score_dirty(db_session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
        db_session.commit()

        due = select_due_protocols(db_session, limit=200)
        ids = [d.protocol_id for d in due]
        assert fx.protocol.id in ids and other.id in ids
        assert ids.index(fx.protocol.id) < ids.index(other.id)
        assert dict((d.protocol_id, d.trigger) for d in due)[other.id] == SCORE_TRIGGER_STALENESS_SWEEP
    finally:
        db_session.query(ProtocolScoreQueue).filter_by(protocol_id=other.id).delete()
        db_session.query(ProtocolScore).filter_by(protocol_id=other.id).delete()
        db_session.query(Protocol).filter_by(id=other.id).delete()
        db_session.commit()


def test_a_dirty_protocol_takes_one_slot_not_two(fx):
    """Selected as dirty, it must not also arrive through the staleness arm."""
    mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    fx.session.commit()

    due = select_due_protocols(fx.session, limit=200)
    assert [d.protocol_id for d in due].count(fx.protocol.id) == 1


def test_a_freshly_scored_protocol_is_not_swept(fx):
    score_protocol(fx.session, DueProtocol(fx.protocol.id, SCORE_TRIGGER_STALENESS_SWEEP))

    due = select_due_protocols(fx.session, limit=200)
    assert fx.protocol.id not in [d.protocol_id for d in due]

    # ...until it ages past the ceiling.
    aged = select_due_protocols(fx.session, limit=200, max_age_s=0)
    assert fx.protocol.id in [d.protocol_id for d in aged]


def test_pass_survives_one_protocol_failing(fx, monkeypatch, caplog):
    mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    fx.session.commit()

    monkeypatch.setattr(
        score_loop,
        "compute_protocol_score",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("fold exploded")),
    )
    beats: list[tuple] = []
    monkeypatch.setattr(score_loop, "emit_monitor_cycle", lambda process, **kw: beats.append((process, kw)))

    with caplog.at_level(logging.WARNING, logger="services.scoring.loop"):
        counters = score_loop.score_due_protocols(fx.session, limit=200)

    assert counters.failures >= 1
    assert beats and beats[0][1]["partial"] is True
    assert fx.queued_row() is not None, "an unscored protocol keeps its mark"


def _poison(monkeypatch):
    monkeypatch.setattr(
        score_loop,
        "compute_protocol_score",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("fold exploded")),
    )
    monkeypatch.setattr(score_loop, "emit_monitor_cycle", lambda process, **kw: None)


def test_a_failing_protocol_backs_off_and_frees_its_pass_slot(fx, monkeypatch):
    """Marks survive a failure and dirty rows sort first, so poison must back off.

    Without this a pass-budget of permanently-failing protocols holds the loop
    forever, and the staleness sweep — the only cover for the invalidation
    events that carry no mark — never runs again.
    """
    mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    fx.session.commit()
    _poison(monkeypatch)

    score_loop.score_due_protocols(fx.session, limit=200)

    fx.session.expire_all()
    row = fx.queued_row()
    assert row is not None and row.attempts == 1 and row.last_failed_at is not None

    inside = select_due_protocols(fx.session, limit=500, backoff_base_s=3600)
    assert fx.protocol.id not in [d.protocol_id for d in inside], "a backed-off protocol takes no slot at all"

    elapsed = select_due_protocols(fx.session, limit=500, backoff_base_s=0)
    assert fx.protocol.id in [d.protocol_id for d in elapsed], "the backoff must expire, never retire the protocol"


def test_a_staleness_failure_arms_the_backoff_too(fx, monkeypatch):
    """A protocol with no queue row would otherwise re-enter through that door.

    A failed fold leaves no score row, so the protocol is permanently stale; if
    only the dirty arm honoured the backoff it would be re-selected every pass
    forever through the sweep.
    """
    _poison(monkeypatch)
    assert fx.queued_row() is None

    score_loop.score_due_protocols(fx.session, limit=500)

    fx.session.expire_all()
    row = fx.queued_row()
    assert row is not None and row.attempts == 1, "the failure needs somewhere to be remembered"
    assert fx.protocol.id not in [d.protocol_id for d in select_due_protocols(fx.session, limit=500)]


def test_repeated_failures_compound_the_backoff_and_are_called_out(fx, monkeypatch, caplog):
    mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    fx.session.commit()
    _poison(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="services.scoring.loop"):
        for _ in range(3):
            score_loop.score_due_protocols(fx.session, limit=500, warn_after=3, backoff_base_s=0)

    fx.session.expire_all()
    assert fx.queued_row().attempts == 3
    assert any("failed 3 consecutive times" in r.getMessage() for r in caplog.records)


def test_a_successful_fold_clears_a_surviving_mark_backoff(fx, monkeypatch):
    """A mark that outlives a SUCCESSFUL fold must not inherit old failures."""
    mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    fx.session.commit()
    _poison(monkeypatch)
    score_loop.score_due_protocols(fx.session, limit=500)
    monkeypatch.undo()

    # A stale-arm fold succeeds while the failed mark is still standing.
    score_protocol(fx.session, DueProtocol(fx.protocol.id, SCORE_TRIGGER_DIRTY_LOOP, dirty_at=None))

    fx.session.expire_all()
    row = fx.queued_row()
    assert row is not None and row.attempts == 0 and row.last_failed_at is None


def test_pass_emits_exactly_one_heartbeat(fx, monkeypatch):
    from db.queue import HEARTBEAT_PROTOCOL_SCORE

    mark_protocol_score_dirty(fx.session, fx.protocol.id, SCORE_DIRTY_EFFECTS)
    fx.session.commit()
    beats: list[tuple] = []
    monkeypatch.setattr(score_loop, "emit_monitor_cycle", lambda process, **kw: beats.append((process, kw)))

    score_loop.score_due_protocols(fx.session, limit=200)

    assert len(beats) == 1
    assert beats[0][0] == HEARTBEAT_PROTOCOL_SCORE
    assert beats[0][1]["extra_detail"]["protocols_scored"] >= 1


def test_score_loop_is_a_supervised_thread():
    from db.queue import HEARTBEAT_PROTOCOL_SCORE
    from services.monitoring.process_meta import PROCESS_META
    from workers.protocol_monitor import _build_default_supervisor

    supervisor = _build_default_supervisor("http://rpc.invalid", 1.0)
    assert HEARTBEAT_PROTOCOL_SCORE in [name for name, _ in supervisor._loops]
    # Without a PROCESS_META entry the loop is invisible to /api/fleet and to
    # the ops watchdog — running but unwatched.
    assert HEARTBEAT_PROTOCOL_SCORE in PROCESS_META


# --------------------------------------------------------------------------
# Perimeter stamping — all three states reach the persisted row
# --------------------------------------------------------------------------


def test_perimeter_is_settled_when_the_queue_is_empty(fx):
    from services.scoring.planes import perimeter_state

    state, detail = perimeter_state(fx.session, fx.protocol.id)
    assert state == PERIMETER_SETTLED
    assert detail["pending_jobs"] == 0


def test_perimeter_is_unsettled_while_jobs_are_in_flight(fx):
    """Ruled: compute anyway and label it. A partial perimeter is a real fact."""
    fx.session.add(Job(id=uuid.uuid4(), protocol_id=fx.protocol.id, status=JobStatus.processing))
    fx.session.commit()

    from services.scoring.planes import perimeter_state

    state, detail = perimeter_state(fx.session, fx.protocol.id)
    assert state == PERIMETER_UNSETTLED
    assert detail["pending_jobs"] == 1

    score_protocol(fx.session, DueProtocol(fx.protocol.id, SCORE_TRIGGER_DIRTY_LOOP))
    assert fx.scores()[-1].perimeter_state == PERIMETER_UNSETTLED


def test_an_unreadable_queue_lands_on_neither_polarity(fx):
    """Stamping "unsettled" on a failed read would be a claim with no witness."""
    from services.scoring.planes import perimeter_state

    class _BrokenSession:
        def query(self, *_args, **_kwargs):
            raise RuntimeError("queue unreadable")

    state, detail = perimeter_state(cast("Session", _BrokenSession()), fx.protocol.id)
    assert state == PERIMETER_NOT_DETERMINED
    assert "error" in detail


def test_the_loop_persists_the_perimeter_it_was_handed(fx, monkeypatch):
    import services.scoring.planes as planes

    monkeypatch.setattr(planes, "perimeter_state", lambda s, p: (PERIMETER_NOT_DETERMINED, {"error": "stubbed"}))
    score_protocol(fx.session, DueProtocol(fx.protocol.id, SCORE_TRIGGER_DIRTY_LOOP))

    assert fx.scores()[-1].perimeter_state == PERIMETER_NOT_DETERMINED


# --------------------------------------------------------------------------
# Document persistence + the MinIO spill
# --------------------------------------------------------------------------


class _FakeStorage:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, key: str, body: bytes, content_type: str, metadata: dict[str, str] | None = None) -> None:
        self.objects[key] = body

    def get(self, key: str) -> bytes:
        return self.objects[key]


def _big_document(protocol_id: int) -> ScoreDocument:
    filler = "x" * 2048
    return _document(
        protocol_id,
        findings=[{"capability": "upgrade.implementation", "note": filler} for _ in range(600)],
    )


def test_a_small_document_stays_inline(fx):
    row = persist_score_document(fx.session, _document(fx.protocol.id))
    fx.session.commit()

    assert row.storage_key is None
    assert row.findings is not None
    assert load_score_document(row)["grade_state"] == GRADE_STATE_NOT_DETERMINED


def test_a_large_document_spills_and_reassembles(fx, monkeypatch):
    storage = _FakeStorage()
    monkeypatch.setattr("db.storage.get_storage_client", lambda: storage)

    document = _big_document(fx.protocol.id)
    assert len(json.dumps(document.document(), default=str).encode()) > INLINE_DOCUMENT_LIMIT_BYTES

    row = persist_score_document(fx.session, document)
    fx.session.commit()

    assert row.findings is None
    assert row.storage_key and row.storage_key in storage.objects
    assert load_score_document(row)["findings"] == document.findings


def test_a_large_document_stays_inline_when_storage_is_unconfigured(fx, monkeypatch):
    """A deployment detail must not discard a computed verdict."""
    monkeypatch.setattr("db.storage.get_storage_client", lambda: None)

    row = persist_score_document(fx.session, _big_document(fx.protocol.id))
    fx.session.commit()

    assert row.storage_key is None
    assert row.findings is not None


def test_inline_and_spilled_are_the_same_bytes(fx, monkeypatch):
    """One document, one encoding, whichever side of the threshold it lands on.

    Two encoders would make the same document two different documents — the
    spilled path's ``default=str`` silently stringifies what the inline path's
    JSONB serializer rejects, so the same fold would publish different values
    depending only on its size.
    """
    storage = _FakeStorage()
    monkeypatch.setattr("db.storage.get_storage_client", lambda: storage)

    document = _document(fx.protocol.id, findings=[{"capability": "pause.set", "n": 1, "f": 0.5}])
    inline_row = persist_score_document(fx.session, document)
    monkeypatch.setattr(score_persist, "INLINE_DOCUMENT_LIMIT_BYTES", 0)
    spilled_row = persist_score_document(fx.session, document)
    fx.session.commit()

    assert inline_row.storage_key is None and spilled_row.storage_key is not None
    inline_bytes = json.dumps(inline_row.findings, sort_keys=True).encode("utf-8")
    assert inline_bytes == storage.objects[spilled_row.storage_key]


def test_a_value_json_cannot_encode_raises_on_both_paths(fx, monkeypatch):
    """A producer bug fails at persist, with the document in hand — never silently.

    The stringifying fallback made a Decimal a number on one path and a string
    on the other; raising is the only answer that is the same on both.
    """
    from decimal import Decimal

    storage = _FakeStorage()
    monkeypatch.setattr("db.storage.get_storage_client", lambda: storage)
    document = _document(fx.protocol.id, findings=[{"exposure": Decimal("1.5")}])

    with pytest.raises(TypeError):
        persist_score_document(fx.session, document)
    fx.session.rollback()

    monkeypatch.setattr(score_persist, "INLINE_DOCUMENT_LIMIT_BYTES", 0)
    with pytest.raises(TypeError):
        persist_score_document(fx.session, document)
    fx.session.rollback()
    assert storage.objects == {}, "nothing may reach the bucket for a document that cannot be encoded"


def test_an_unreadable_spill_is_not_an_empty_document(fx, monkeypatch):
    storage = _FakeStorage()
    monkeypatch.setattr("db.storage.get_storage_client", lambda: storage)
    row = persist_score_document(fx.session, _big_document(fx.protocol.id))
    fx.session.commit()
    storage.objects.clear()

    with pytest.raises(ScoreDocumentUnavailable):
        load_score_document(row)


# --------------------------------------------------------------------------
# GET /api/company/{name}/score
# --------------------------------------------------------------------------

_LEDGER_KEYS = {
    "grade_lambda",
    "grade_exposure",
    "grade_state",
    "findings",
    "earned_negatives",
    "warnings",
    "model_parameters",
    "confidence_pct",
    "perimeter_state",
    "provenance",
}


def test_score_endpoint_serves_the_ledger_payload(fx, api_client):
    persist_score_document(
        fx.session,
        _document(
            fx.protocol.id,
            grade_state=GRADE_STATE_COMPUTED,
            grade_lambda=-12.5,
            grade_exposure=0.42,
            confidence_pct=25.0,
            perimeter_state=PERIMETER_UNSETTLED,
            findings=[{"capability": "upgrade.implementation", "principal_unit": "ethereum::0xabc"}],
            warnings=[{"kind": "unresolved_principal"}],
        ),
    )
    fx.session.commit()

    response = api_client.get(f"/api/company/{fx.protocol.name}/score")
    assert response.status_code == 200
    body = response.json()

    assert _LEDGER_KEYS <= set(body), sorted(_LEDGER_KEYS - set(body))
    assert body["protocol_id"] == fx.protocol.id
    assert body["grade_state"] == GRADE_STATE_COMPUTED
    assert body["grade_lambda"] == -12.5
    assert body["perimeter_state"] == PERIMETER_UNSETTLED
    assert body["findings"][0]["capability"] == "upgrade.implementation"
    assert body["model_version"] == MODEL_VERSION


def test_score_endpoint_serves_the_newest_row(fx, api_client):
    older = _document(fx.protocol.id, computed_at=datetime.now(timezone.utc) - timedelta(hours=1))
    persist_score_document(fx.session, older)
    newest = _document(
        fx.protocol.id,
        computed_at=datetime.now(timezone.utc),
        warnings=[{"kind": "newest"}],
    )
    persist_score_document(fx.session, newest)
    fx.session.commit()

    body = api_client.get(f"/api/company/{fx.protocol.name}/score").json()
    assert body["warnings"] == [{"kind": "newest"}]


def test_a_not_determined_grade_is_served_as_such_not_as_zero(fx, api_client):
    persist_score_document(fx.session, _document(fx.protocol.id))
    fx.session.commit()

    body = api_client.get(f"/api/company/{fx.protocol.name}/score").json()
    assert body["grade_state"] == GRADE_STATE_NOT_DETERMINED
    assert body["grade_lambda"] is None
    assert body["grade_exposure"] is None
    assert body["confidence_pct"] is None


def test_score_endpoint_404s_when_no_score_exists(fx, api_client):
    assert api_client.get(f"/api/company/{fx.protocol.name}/score").status_code == 404


def test_score_endpoint_404s_for_an_unknown_company(api_client):
    assert api_client.get("/api/company/psat-no-such-protocol-xyz/score").status_code == 404


def test_score_endpoint_reassembles_a_spilled_document(fx, api_client, monkeypatch):
    storage = _FakeStorage()
    monkeypatch.setattr("db.storage.get_storage_client", lambda: storage)
    persist_score_document(fx.session, _big_document(fx.protocol.id))
    fx.session.commit()

    body = api_client.get(f"/api/company/{fx.protocol.name}/score").json()
    assert len(body["findings"]) == 600


def test_an_unreadable_document_is_not_reported_as_an_absent_score(fx, api_client, monkeypatch):
    storage = _FakeStorage()
    monkeypatch.setattr("db.storage.get_storage_client", lambda: storage)
    persist_score_document(fx.session, _big_document(fx.protocol.id))
    fx.session.commit()
    storage.objects.clear()

    response = api_client.get(f"/api/company/{fx.protocol.name}/score")
    assert response.status_code == 503, "a body that could not be read is not a missing score"
