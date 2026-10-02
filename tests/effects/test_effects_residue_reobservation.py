"""State-plane residue on cache hits, and the empty-planning marker.

A verdict whose first write is a cache hit never got per-deployment residue; and a contract that yields no plans
wrote nothing, so every later job re-swept it. The cache still decides the verdict, and nothing observed is
written back to it.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock

import pytest

from db.effect_cache import (
    AUDIT_PASSED,
    upsert_cached_verdict,
)
from db.models import (
    Contract,
    EffectBehaviorCache,
    EffectiveFunction,
    EffectsPlanMarker,
    EffectVerdict,
    Protocol,
)
from db.queue import create_job
from services.effects.config import (
    EFFECT_CLASS_CODE_UPGRADE,
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
    TIER_CALL,
    TIER_HISTORICAL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.harness import proven
from services.effects.orchestrator import ProbePlan
from services.effects.selection import Candidate
from services.effects.simulate import SimCallResult, SimResult
from tests.cache_helpers import requires_postgres
from utils.logging import degraded_errors_var, stage_metrics_var
from workers.effects_worker import (
    _RESIDUE_KEY,
    _RESIDUE_PROBE_MAX_ATTEMPTS,
    EffectsWorker,
    _is_cacheable,
    _residue_observable,
    _Seams,
)

CONTRACT_A = "0x" + "a1" * 20
CONTRACT_B = "0x" + "b2" * 20
DESTINATION = "0x" + "d5" * 20
PRINCIPAL = "0x" + "22" * 20
SELECTOR = "0x40c10f19"
BEHAVIOR_HASH = "kernel_hash_shared"


@pytest.fixture()
def clean_effects(db_session):
    db_session.query(EffectVerdict).delete()
    db_session.query(EffectBehaviorCache).delete()
    db_session.query(EffectsPlanMarker).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.query(EffectVerdict).delete()
    db_session.query(EffectBehaviorCache).delete()
    db_session.query(EffectsPlanMarker).delete()
    db_session.commit()


def _protocol_with_functions(session, addresses: list[str]) -> tuple[int, dict[str, int], dict[str, int]]:
    proto = Protocol(name=f"effects-residue-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    fn_ids: dict[str, int] = {}
    contract_ids: dict[str, int] = {}
    for addr in addresses:
        c = Contract(protocol_id=proto.id, address=addr, chain="ethereum", is_proxy=False)
        session.add(c)
        session.flush()
        contract_ids[addr] = c.id
        fn = EffectiveFunction(
            contract_id=c.id,
            function_name="f",
            selector=SELECTOR,
            authority_public=False,
            effect_targets=["slot0"],
        )
        session.add(fn)
        session.flush()
        fn_ids[addr] = fn.id
    session.commit()
    return proto.id, fn_ids, contract_ids


def _make_job(session, protocol_id: int, name: str, address: str = CONTRACT_A):
    job = create_job(session, {"address": address, "name": name})
    job.protocol_id = protocol_id
    session.commit()
    return job


def _candidate(address: str, function_id: int, contract_id: int) -> Candidate:
    return Candidate(
        function_id=function_id,
        contract_id=contract_id,
        contract_address=address,
        selector=SELECTOR,
        function_name="f",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
        value_at_stake_usd=Decimal("1"),
    )


def _seams(session, job, *, simulate=None):
    from services.effects.preflight import InMemoryCapabilityStore

    sim = (
        simulate
        if simulate is not None
        else MagicMock(return_value=SimResult(calls=(SimCallResult(True, "0x", None),)))
    )
    store = InMemoryCapabilityStore()
    store.set_simulate_support(1, True)
    return _Seams(
        simulate=sim,
        transcript_store=lambda tr: None,
        capability_store=store,
        chain_id=1,
    )


def _run(worker, session, job) -> tuple[list, dict]:
    errors: list = []
    metrics: dict = {}
    etok = degraded_errors_var.set(errors)
    mtok = stage_metrics_var.set(metrics)
    try:
        worker.process(session, job)
    finally:
        degraded_errors_var.reset(etok)
        stage_metrics_var.reset(mtok)
    return errors, metrics


class _CountingProber:
    """``runs`` makes "no extra observation" checkable."""

    def __init__(self, factory, *, effect_class=EFFECT_CLASS_VALUE_OUT, gate_ref="role:X", plans_per_candidate=1):
        self.factory = factory
        self.effect_class = effect_class
        self.gate_ref = gate_ref
        self.plans_per_candidate = plans_per_candidate
        self.runs: list[int] = []

    def __call__(self, session, cand, ctx):
        def run():
            self.runs.append(cand.function_id)
            return self.factory(cand, ctx)

        return [
            ProbePlan(effect_class=self.effect_class, scope=SCOPE_KERNEL, run=run, gate_ref=self.gate_ref)
            for _ in range(self.plans_per_candidate)
        ]


def _seed_cache(session, *, effect_class, verdict=VERDICT_PROVEN, tier=TIER_CALL, gate_ref="role:X", details=None):
    """``audit_status`` set means a plain hit, not a self-audit."""
    row = upsert_cached_verdict(
        session,
        behavior_hash=BEHAVIOR_HASH,
        effect_class=effect_class,
        scope=SCOPE_KERNEL,
        verdict=verdict,
        tier=tier,
        gate_ref=gate_ref,
        details=details or {"destination_shape": "unknown"},
        audit_status=AUDIT_PASSED,
        audit_peer_hash="peer",
    )
    session.commit()
    return row


def _value_out_effect(destination: str | None = DESTINATION):
    concrete = {"destination": destination} if destination else {}
    return proven(
        EFFECT_CLASS_VALUE_OUT,
        gate_ref="role:X",
        reason="value_moved",
        details={"value_moved": True, "destination_shape": "unknown", "shape_proved_by": "none"},
        concrete=concrete,
    )


@requires_postgres
def test_first_write_is_a_hit_and_still_acquires_residue(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-hit")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    cached = _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)

    prober = _CountingProber(lambda c, ctx: _value_out_effect())
    worker = EffectsWorker(
        prober=prober,
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _errors, metrics = _run(worker, session, job)

    row = session.query(EffectVerdict).one()
    assert row.concrete_destination == DESTINATION
    assert (row.verdict, row.tier, row.witness) == (cached.verdict, cached.tier, cached.details)
    assert metrics["cache_hits_kernel"] == 1
    assert metrics["cache_misses"] == 0
    assert metrics["residue_observations"] == 1
    assert prober.runs == [fns[CONTRACT_A]]


@requires_postgres
def test_hit_whose_row_already_has_residue_triggers_no_observation(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-already")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    cached = _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)
    session.add(
        EffectVerdict(
            function_id=fns[CONTRACT_A],
            chain_id=1,
            contract_address=CONTRACT_A.lower(),
            selector=SELECTOR,
            effect_class=EFFECT_CLASS_VALUE_OUT,
            behavior_hash=BEHAVIOR_HASH,
            verdict=VERDICT_PROVEN,
            tier=TIER_CALL,
            concrete_destination=DESTINATION,
        )
    )
    session.commit()

    prober = _CountingProber(lambda c, ctx: pytest.fail("re-observed a row that already had residue"))
    worker = EffectsWorker(
        prober=prober,
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _errors, metrics = _run(worker, session, job)

    assert prober.runs == []
    assert metrics["residue_observations"] == 0
    row = session.query(EffectVerdict).one()
    assert row.concrete_destination == DESTINATION
    assert (row.verdict, row.tier) == (cached.verdict, cached.tier)


@requires_postgres
def test_unknown_value_out_hit_is_not_re_observed(clean_effects, monkeypatch):
    """``value_out`` records a destination only when proven, so probing an unknown hit wastes two simulations."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-unknown")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT, verdict=VERDICT_UNKNOWN)

    prober = _CountingProber(lambda c, ctx: pytest.fail("re-observed an unknown value_out hit"))
    worker = EffectsWorker(
        prober=prober,
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _errors, metrics = _run(worker, session, job)
    assert prober.runs == []
    assert metrics["residue_observations"] == 0
    assert session.query(EffectVerdict).one().verdict == VERDICT_UNKNOWN


def test_code_upgrade_residue_branch_is_unreachable_and_gone():
    """Tier-0 verdicts are never cached, so that arm was dead and removed; this pins the premise."""
    historical = proven(
        EFFECT_CLASS_CODE_UPGRADE,
        tier=TIER_HISTORICAL,
        reason="indexed_upgrade_plus_current_state",
        details={"historical": True, "current_capability": True},
        concrete={"current_check_passed": True},
    )
    assert _is_cacheable(historical) is False

    row = EffectBehaviorCache(
        behavior_hash=BEHAVIOR_HASH,
        effect_class=EFFECT_CLASS_CODE_UPGRADE,
        scope=SCOPE_KERNEL,
        verdict=VERDICT_PROVEN,
        tier=TIER_HISTORICAL,
    )
    assert _residue_observable(row, EFFECT_CLASS_CODE_UPGRADE) is False
    assert EFFECT_CLASS_CODE_UPGRADE not in _RESIDUE_KEY


class _BoomProber:
    def __call__(self, session, cand, ctx):
        raise RuntimeError("prober exploded")


@requires_postgres
@pytest.mark.parametrize(
    ("destination", "jobs", "expected_runs", "expected_destination", "expected_residue"),
    [
        # A cached behavior this deployment can't reproduce stays NULL, so the attempt count bounds re-probing.
        pytest.param(
            None,
            4,
            _RESIDUE_PROBE_MAX_ATTEMPTS,
            None,
            {"destination_probe_attempts": _RESIDUE_PROBE_MAX_ATTEMPTS},
            id="bounded-per-deployment",
        ),
        pytest.param(DESTINATION, 3, 1, DESTINATION, {"destination_probe_attempts": 1}, id="success-stops-immediately"),
    ],
)
def test_residue_reprobe_attempts(
    clean_effects, monkeypatch, destination, jobs, expected_runs, expected_destination, expected_residue
):
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)

    prober = _CountingProber(lambda c, ctx: _value_out_effect(destination=destination))
    for n in range(jobs):
        job = _make_job(session, pid, f"residue-reprobe-{n}")
        worker = EffectsWorker(
            prober=prober,
            hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
            seams=_seams(session, job),
        )
        _run(worker, session, job)
        session.expire_all()

    assert len(prober.runs) == expected_runs
    row = session.query(EffectVerdict).one()
    assert row.concrete_destination == expected_destination
    assert row.observed_residue == expected_residue


@requires_postgres
def test_failed_residue_observation_does_not_disturb_the_cached_verdict(clean_effects, monkeypatch):
    """Fail-forward: a raising probe is recorded degraded."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-boom")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    cached = _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)

    def boom(c, ctx):
        raise RuntimeError("probe exploded")

    worker = EffectsWorker(
        prober=_CountingProber(boom),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    errors, metrics = _run(worker, session, job)
    row = session.query(EffectVerdict).one()
    assert (row.verdict, row.tier, row.witness) == (cached.verdict, cached.tier, cached.details)
    assert row.concrete_destination is None
    assert metrics["cache_hits_kernel"] == 1
    assert any(e.phase == "effects_probe" for e in errors)


def _marker_for(session, contract_id: int) -> EffectsPlanMarker | None:
    return session.query(EffectsPlanMarker).filter(EffectsPlanMarker.contract_id == contract_id).one_or_none()


class _NoPlanProber:
    def __call__(self, session, cand, ctx) -> list[ProbePlan]:
        return []


@requires_postgres
def test_contract_that_yields_no_plans_is_recorded_as_planned(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "marker-empty")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    worker = EffectsWorker(
        prober=_NoPlanProber(),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _errors, metrics = _run(worker, session, job)

    marker = _marker_for(session, cids[CONTRACT_A])
    assert marker is not None
    assert marker.job_id == job.id
    assert marker.candidates_planned == 1
    assert marker.planned_at >= job.created_at
    assert metrics["contracts_planned_empty"] == 1
    assert session.query(EffectVerdict).count() == 0


@requires_postgres
@pytest.mark.parametrize(
    ("prober", "env"),
    [
        pytest.param(_BoomProber(), {}, id="raising-prober"),
        # With Tier 2 off, an empty result is an artefact of the switch.
        pytest.param(_NoPlanProber(), {"PSAT_EFFECTS_FORK": "0"}, id="fork-disabled"),
    ],
)
def test_marker_blocked(clean_effects, monkeypatch, prober, env):
    session = clean_effects
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "marker-blocked")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    worker = EffectsWorker(
        prober=prober,
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _run(worker, session, job)
    assert _marker_for(session, cids[CONTRACT_A]) is None


@requires_postgres
def test_a_partly_unplannable_contract_is_not_marked(clean_effects, monkeypatch):
    session = clean_effects
    proto = Protocol(name=f"effects-residue-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    contract = Contract(protocol_id=proto.id, address=CONTRACT_A, chain="ethereum", is_proxy=False)
    session.add(contract)
    session.flush()
    fns = []
    for sel in ("0x40c10f19", "0x40c10f20"):
        fn = EffectiveFunction(
            contract_id=contract.id,
            function_name=f"f{sel}",
            selector=sel,
            authority_public=False,
            effect_targets=["slot0"],
        )
        session.add(fn)
        session.flush()
        fns.append(fn.id)
    session.commit()
    job = _make_job(session, proto.id, "marker-partial")
    cands = [_candidate(CONTRACT_A, fid, contract.id) for fid in fns]
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: cands)

    resolved: dict[int, Any] = {fns[0]: (BEHAVIOR_HASH, "surface_A"), fns[1]: None}
    worker = EffectsWorker(
        prober=_NoPlanProber(),
        hash_resolver=lambda s, c: resolved[c.function_id],
        seams=_seams(session, job),
    )
    _run(worker, session, job)
    assert _marker_for(session, contract.id) is None
