"""Effects-stage foundations: enum placement, flag-dynamic transition, worker
scaffolding, and fail-forward semantics (EFFECTS_RESOLUTION_SPEC Phase 1).

The DB-backed cases mirror ``tests/test_baseworker_retry.py`` (real Postgres,
inline-JSONB artifacts, offline-safe). ``PSAT_EFFECTS_STAGE`` is asserted default-
off.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Artifact, EffectVerdict, Job, JobStage, JobStatus  # noqa: E402
from db.queue import create_job  # noqa: E402
from services.effects.config import EFFECT_CLASS_SUPPLY, VERDICT_PROVEN, effects_stage_enabled  # noqa: E402
from services.effects.exceptions import ForkRpcTimeoutError  # noqa: E402
from services.effects.harness import proven  # noqa: E402
from tests.cache_helpers import requires_postgres  # noqa: E402
from tests.support.effects_worker_harness import (  # noqa: E402
    CONTRACT_A,
    CONTRACT_B,
    CONTRACT_C,
    _candidate,
    _make_job,
    _Prober,
    _protocol_with_functions,
    _run,
    _seams,
    clean_effects,  # noqa: F401  (imported so pytest registers the fixture here)
)
from workers.effects_worker import EffectsWorker  # noqa: E402
from workers.policy_worker import PolicyWorker  # noqa: E402


@pytest.fixture()
def test_session_local(monkeypatch):
    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")
    test_engine = create_engine(test_url)
    test_factory = sessionmaker(bind=test_engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("workers.base.SessionLocal", test_factory)
    yield test_factory
    test_engine.dispose()


@pytest.fixture()
def clean_jobs(db_session):
    db_session.query(Artifact).delete()
    db_session.query(Job).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.query(Artifact).delete()
    db_session.query(Job).delete()
    db_session.commit()


# ---------------------------------------------------------------------------
# Enum placement / lifecycle ordering (inv. 11).
# ---------------------------------------------------------------------------


def test_effects_stage_between_policy_and_coverage():
    order = [s.value for s in JobStage]
    assert order.index("policy") < order.index("effects") < order.index("coverage")
    # Full progression is intact.
    assert order == [
        "discovery",
        "dapp_crawl",
        "defillama_scan",
        "selection",
        "static",
        "resolution",
        "policy",
        "effects",
        "coverage",
        "done",
    ]


# ---------------------------------------------------------------------------
# Flag-dynamic transition (§3a.4 / inv. 15).
# ---------------------------------------------------------------------------


def test_flag_defaults_off(monkeypatch):
    monkeypatch.delenv("PSAT_EFFECTS_STAGE", raising=False)
    assert effects_stage_enabled() is False


def test_scoring_tier_translation_resolves_the_string_collision():
    # §0 tier-string collision guard: the stored "tier2" (fork-observed) must map to
    # the OBSERVED scoring tier (scoring Tier 1), never scoring Tier 2. Every effects
    # tier is observation-origin, so all three translate to observed; an unknown
    # string fails closed to None.
    from services.effects.config import (
        SCORING_TIER_OBSERVED,
        SCORING_TIER_STATIC_FALLBACK,
        TIER_CALL,
        TIER_FORK,
        TIER_HISTORICAL,
        scoring_tier_for_effects_tier,
    )

    assert TIER_FORK == "tier2"  # the colliding raw string
    assert SCORING_TIER_OBSERVED != SCORING_TIER_STATIC_FALLBACK
    for stored in (TIER_HISTORICAL, TIER_CALL, TIER_FORK):
        assert scoring_tier_for_effects_tier(stored) == SCORING_TIER_OBSERVED
    # Crucially NOT scoring Tier 2 despite the "tier2" string.
    assert scoring_tier_for_effects_tier(TIER_FORK) != SCORING_TIER_STATIC_FALLBACK
    assert scoring_tier_for_effects_tier(None) is None
    assert scoring_tier_for_effects_tier("tierX") is None


def test_policy_next_stage_flag_off_is_coverage(monkeypatch):
    monkeypatch.delenv("PSAT_EFFECTS_STAGE", raising=False)
    assert PolicyWorker().next_stage == JobStage.coverage


def test_policy_next_stage_flag_on_is_effects(monkeypatch):
    monkeypatch.setenv("PSAT_EFFECTS_STAGE", "1")
    assert PolicyWorker().next_stage == JobStage.effects


# ---------------------------------------------------------------------------
# Worker behavior: inert pass-through + fail-forward (inv. 15).
# ---------------------------------------------------------------------------


class _FailingEffectsWorker(EffectsWorker):
    """Effects worker whose ``process()`` always raises — to drive the
    fail-forward path without a real harness."""

    poll_interval = 0.0

    def __init__(self, exc: BaseException) -> None:
        super().__init__()
        self._exc = exc

    def process(self, session, job):
        raise self._exc


@requires_postgres
def test_flag_on_zero_candidate_passthrough(clean_jobs, test_session_local):
    """The inert ``process()`` advances a job straight to ``coverage`` with no
    error (flag-on, zero candidates)."""
    session = clean_jobs
    job_row = create_job(session, {"address": "0xabc", "name": "effects-passthrough"})

    worker = EffectsWorker()
    worker._execute_job(session, job_row)

    session.expire_all()
    refreshed = session.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.stage == JobStage.coverage
    assert refreshed.status == JobStatus.queued


@requires_postgres
def test_fail_forward_exhaustion_advances_never_terminal(clean_jobs, test_session_local, monkeypatch):
    """inv. 15: on retry exhaustion the effects stage advances to ``coverage``
    (fail-forward) and NEVER emits ``failed_terminal``."""
    monkeypatch.setenv("PSAT_JOB_MAX_RETRIES", "0")  # first failure = exhaustion

    session = clean_jobs
    job_row = create_job(session, {"address": "0xabc", "name": "effects-failforward"})

    worker = _FailingEffectsWorker(ForkRpcTimeoutError("fork RPC down"))
    worker._execute_job(session, job_row)

    session.expire_all()
    refreshed = session.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.status != JobStatus.failed_terminal
    assert refreshed.status == JobStatus.queued
    assert refreshed.stage == JobStage.coverage


@requires_postgres
def test_fail_forward_on_terminal_kind_also_advances(clean_jobs, test_session_local):
    """A deterministically-terminal exception (ValueError) in the effects stage
    must also fail-forward — the stage never terminals a job whose upstream
    artifacts are already complete."""
    session = clean_jobs
    job_row = create_job(session, {"address": "0xabc", "name": "effects-terminal-kind"})

    worker = _FailingEffectsWorker(ValueError("bad candidate"))
    worker._execute_job(session, job_row)

    session.expire_all()
    refreshed = session.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.status != JobStatus.failed_terminal
    assert refreshed.stage == JobStage.coverage


# ---------------------------------------------------------------------------
# §9 direction 2 is a benign metric, not a degradation: a fully-HEALTHY run of
# many proven verdicts files ZERO degraded discrepancies and reports the
# idiom-candidate count as a metric instead.
# ---------------------------------------------------------------------------


@requires_postgres
def test_healthy_multi_proven_run_files_no_degraded_discrepancies(clean_effects, monkeypatch):
    """Selection returns only blank-claim functions, so every proven verdict is a
    §9 direction-2 (static-silent / sim-positive) event. A healthy cold-cache run
    of N such verdicts must NOT flood ``stage_errors`` with ``degraded`` entries —
    ``discrepancies_filed`` stays 0 while ``new_idiom_candidates`` reflects N."""
    session = clean_effects
    addresses = [CONTRACT_A, CONTRACT_B, CONTRACT_C]
    pid, fns = _protocol_with_functions(session, addresses)
    job = _make_job(session, pid, "healthy-multi")

    cands = [_candidate(addr, fns[addr]) for addr in addresses]
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: cands)

    # Distinct kernel hashes → every candidate is a fresh cache miss, so each
    # proven verdict is witnessed anew and files its idiom candidate.
    hashes = {fns[addr]: (f"K{i}", f"S{i}") for i, addr in enumerate(addresses)}
    prober = _Prober(lambda c, ctx: proven(EFFECT_CLASS_SUPPLY, details={"supply_delta_sign": "mint"}))
    worker = EffectsWorker(prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, job))
    errors, metrics = _run(worker, session, job)

    # All N verdicts proven and persisted.
    proven_rows = session.query(EffectVerdict).filter(EffectVerdict.verdict == VERDICT_PROVEN).all()
    assert len(proven_rows) == len(addresses)

    # ZERO degraded stage_errors of any kind on a healthy run.
    assert errors == []
    # Direction-2 events are a benign metric, not discrepancies.
    assert metrics["discrepancies_filed"] == 0
    assert metrics["new_idiom_candidates"] == len(addresses)
