"""Effects worker: state-plane residue on cache HITS + the empty-planning marker.

Two residual gaps in the effects stage, both about a write that leaves no trace:

1. A verdict row whose FIRST write is a cache hit never gets state-plane residue.
   The hit is the right answer for the code plane (the behavioral cache holds no
   concrete values), but ``concrete_destination`` /
   ``current_check_passed`` describe THIS deployment and a hit carries neither,
   so the row is blank and every later hit keeps it blank.

2. A contract that is swept and yields no plans writes no verdict and, when it
   has no job of its own, no stage artifact either — so effects selection
   re-sweeps it from every subsequent job.

The bar for (1) is that the CACHE still decides the verdict: every test here
asserts the persisted verdict/tier/witness match the cached row, and that
nothing an observation saw is written back into ``effect_behavior_cache``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock

import pytest

from db.effect_cache import (
    AUDIT_PASSED,
    find_verdict_residue_batch,
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
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_CODE_UPGRADE,
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
    TIER_CALL,
    TIER_HISTORICAL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.harness import proven, unknown
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
    """One plan per candidate. ``runs`` counts every ``run()`` so "no extra
    observation" is checkable, not asserted by inspection."""

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
    """A pre-existing, already-audited cache row: the second deployment of a
    behavior another contract cached. ``audit_status`` set ⇒ a PLAIN hit, not the
    self-audit re-simulation."""
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


# ---------------------------------------------------------------------------
# 1. The gap: a hit whose persisted row has no residue acquires it.
# ---------------------------------------------------------------------------


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
    # ...and the VERDICT is still the cache's, not the observation's.
    assert (row.verdict, row.tier, row.witness) == (cached.verdict, cached.tier, cached.details)
    assert metrics["cache_hits_kernel"] == 1
    assert metrics["cache_misses"] == 0
    assert metrics["residue_observations"] == 1
    assert prober.runs == [fns[CONTRACT_A]]


@requires_postgres
def test_residue_observation_never_writes_to_the_behavior_cache(clean_effects, monkeypatch):
    """The observation is per-deployment state. Nothing it saw may enter
    the code-plane cache, and the hit must not be recounted as a miss."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-inv3")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)
    before = {
        (c.behavior_hash, c.effect_class, c.verdict, c.tier, str(c.details))
        for c in session.query(EffectBehaviorCache).all()
    }

    worker = EffectsWorker(
        prober=_CountingProber(lambda c, ctx: _value_out_effect()),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _run(worker, session, job)

    session.expire_all()
    after = {
        (c.behavior_hash, c.effect_class, c.verdict, c.tier, str(c.details))
        for c in session.query(EffectBehaviorCache).all()
    }
    assert after == before
    assert session.query(EffectBehaviorCache).count() == 1
    assert DESTINATION not in str(session.query(EffectBehaviorCache).one().details)


@requires_postgres
def test_hit_whose_row_already_has_residue_triggers_no_observation(clean_effects, monkeypatch):
    """The scoping that keeps this affordable: a row that already carries the
    value needs nothing, so the plan is never run."""
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
    """``value_out`` records a destination only on the proven branch, so probing
    an unknown hit would burn two simulations for a guaranteed NULL."""
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


@requires_postgres
def test_class_without_storable_residue_is_not_re_observed(clean_effects, monkeypatch):
    """``authority_change`` emits no ``concrete`` at all — there is nothing to go
    and get, so it must never pay for a probe."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-noclass")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    _seed_cache(session, effect_class=EFFECT_CLASS_AUTHORITY_CHANGE, details={"gate_mutation": True})

    prober = _CountingProber(
        lambda c, ctx: pytest.fail("re-observed a class with no residue"),
        effect_class=EFFECT_CLASS_AUTHORITY_CHANGE,
    )
    worker = EffectsWorker(
        prober=prober,
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _errors, metrics = _run(worker, session, job)
    assert prober.runs == []
    assert metrics["residue_observations"] == 0


def test_code_upgrade_residue_branch_is_unreachable_and_gone():
    """``_residue_observable``'s ``code_upgrade`` arm required ``TIER_HISTORICAL``,
    but ``_is_cacheable`` refuses to cache Tier-0 verdicts at all — so no
    cached row could ever satisfy it. The arm was dead code and was REMOVED; this
    pins the premise so a change to either side is caught."""
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


def test_a_caller_arbitrary_hit_is_never_re_probed_for_a_destination(clean_effects):
    """Consumer half of the withheld-destination rule. The recipe WITHHOLDS ``concrete_destination`` on a
    ``caller_arbitrary`` shape — whatever a probe sees there is the recipient
    argument the prober supplied. A NULL that is deliberate must not read as "no
    residue yet": otherwise every such deployment spends its whole re-probe budget
    (2 Tier-1 ``eth_simulateV1`` probes) chasing a value this stage refuses to
    store, and each one looks like a gap that never closes.

    The two other shapes stay observable, so this narrows nothing else."""
    session = clean_effects
    arbitrary = _seed_cache(
        session,
        effect_class=EFFECT_CLASS_VALUE_OUT,
        details={"destination_shape": "caller_arbitrary", "shape_proved_by": "simulation"},
    )
    assert _residue_observable(arbitrary, EFFECT_CLASS_VALUE_OUT) is False

    for shape in ("unknown", "immutable_fixed"):
        row = EffectBehaviorCache(
            behavior_hash=BEHAVIOR_HASH,
            effect_class=EFFECT_CLASS_VALUE_OUT,
            scope=SCOPE_KERNEL,
            verdict=VERDICT_PROVEN,
            tier=TIER_CALL,
            details={"destination_shape": shape},
        )
        assert _residue_observable(row, EFFECT_CLASS_VALUE_OUT) is True
    # A details-less row (a class that publishes no shape) keeps the old answer.
    bare = EffectBehaviorCache(
        behavior_hash=BEHAVIOR_HASH,
        effect_class=EFFECT_CLASS_VALUE_OUT,
        scope=SCOPE_KERNEL,
        verdict=VERDICT_PROVEN,
        tier=TIER_CALL,
    )
    assert _residue_observable(bare, EFFECT_CLASS_VALUE_OUT) is True


@requires_postgres
def test_residue_reprobe_is_bounded_per_deployment(clean_effects, monkeypatch):
    """A behavior that is proven IN THE CACHE but that THIS deployment cannot
    reproduce leaves ``concrete_destination`` NULL forever. Re-flagging on "still
    NULL" alone re-probed it on every job of every run; the stored attempt count
    bounds it at ``_RESIDUE_PROBE_MAX_ATTEMPTS``."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)

    prober = _CountingProber(lambda c, ctx: _value_out_effect(destination=None))
    for n in range(4):
        job = _make_job(session, pid, f"residue-bound-{n}")
        worker = EffectsWorker(
            prober=prober,
            hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
            seams=_seams(session, job),
        )
        _run(worker, session, job)
        session.expire_all()

    assert len(prober.runs) == _RESIDUE_PROBE_MAX_ATTEMPTS
    row = session.query(EffectVerdict).one()
    assert row.concrete_destination is None
    assert row.observed_residue == {"destination_probe_attempts": _RESIDUE_PROBE_MAX_ATTEMPTS}


@requires_postgres
def test_residue_reprobe_that_succeeds_stops_immediately(clean_effects, monkeypatch):
    """The bound never costs a real observation: a probe that resolves the
    destination closes the gap on the first attempt and is not re-run."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)

    prober = _CountingProber(lambda c, ctx: _value_out_effect())
    for n in range(3):
        job = _make_job(session, pid, f"residue-closed-{n}")
        worker = EffectsWorker(
            prober=prober,
            hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
            seams=_seams(session, job),
        )
        _run(worker, session, job)
        session.expire_all()

    assert len(prober.runs) == 1
    assert session.query(EffectVerdict).one().concrete_destination == DESTINATION


@requires_postgres
def test_residue_observation_smuggles_nothing_but_its_own_key(clean_effects, monkeypatch):
    """The observation is a whitelist, not a passthrough: a value_out probe may
    contribute a destination and nothing else."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-whitelist")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)

    def factory(c, ctx):
        eff = _value_out_effect()
        eff.concrete["current_check_passed"] = True  # not this class's residue
        return eff

    worker = EffectsWorker(
        prober=_CountingProber(factory),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _run(worker, session, job)
    row = session.query(EffectVerdict).one()
    assert row.concrete_destination == DESTINATION
    assert row.current_check_passed is None


@requires_postgres
def test_observation_that_yields_nothing_leaves_the_verdict_untouched(clean_effects, monkeypatch):
    """A destination the probe could not resolve stays NULL — and must not
    disturb the cached verdict on its way out."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-empty")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    cached = _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)

    worker = EffectsWorker(
        prober=_CountingProber(lambda c, ctx: _value_out_effect(destination=None)),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _errors, metrics = _run(worker, session, job)
    row = session.query(EffectVerdict).one()
    assert row.concrete_destination is None
    assert (row.verdict, row.tier, row.witness) == (cached.verdict, cached.tier, cached.details)
    assert metrics["residue_observations"] == 0


@requires_postgres
def test_failed_residue_observation_does_not_disturb_the_cached_verdict(clean_effects, monkeypatch):
    """Fail-forward: the observation is best-effort. A raising probe is
    recorded degraded and the cached verdict persists exactly as it would have."""
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


@requires_postgres
def test_kill_valve_restores_the_previous_behavior(clean_effects, monkeypatch):
    session = clean_effects
    monkeypatch.setenv("PSAT_EFFECTS_RESIDUE_PROBE", "0")
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-off")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    _seed_cache(session, effect_class=EFFECT_CLASS_VALUE_OUT)

    prober = _CountingProber(lambda c, ctx: _value_out_effect())
    worker = EffectsWorker(
        prober=prober,
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _run(worker, session, job)
    assert prober.runs == []
    assert session.query(EffectVerdict).one().concrete_destination is None


@requires_postgres
def test_audit_path_residue_is_taken_for_free(clean_effects, monkeypatch):
    """A self-audit hit already re-simulated this deployment, so its residue
    costs nothing extra — and the verdict still comes from the cache."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "residue-audit")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    # audit_status left None ⇒ this hit triggers the self-audit re-simulation.
    cached = upsert_cached_verdict(
        session,
        behavior_hash=BEHAVIOR_HASH,
        effect_class=EFFECT_CLASS_VALUE_OUT,
        scope=SCOPE_KERNEL,
        verdict=VERDICT_PROVEN,
        tier=TIER_CALL,
        gate_ref="role:X",
        details={"value_moved": True, "destination_shape": "unknown", "shape_proved_by": "none"},
    )
    cached_verdict, cached_tier, cached_details = cached.verdict, cached.tier, dict(cached.details or {})
    session.commit()

    prober = _CountingProber(lambda c, ctx: _value_out_effect())
    worker = EffectsWorker(
        prober=prober,
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _errors, metrics = _run(worker, session, job)

    row = session.query(EffectVerdict).one()
    assert row.concrete_destination == DESTINATION
    assert (row.verdict, row.tier, row.witness) == (cached_verdict, cached_tier, cached_details)
    assert metrics["cache_hits_kernel"] == 1
    # The audit's own re-simulation — NOT a second, residue-only run.
    assert prober.runs == [fns[CONTRACT_A]]


@requires_postgres
def test_residue_gap_lookup_is_one_query_for_the_whole_worklist(clean_effects):
    """The check that gates the observation must not reintroduce the N+1 the
    ``cache_lookup`` batching just removed."""
    session = clean_effects
    _pid, fns, _cids = _protocol_with_functions(session, [CONTRACT_A, CONTRACT_B])
    for addr in (CONTRACT_A, CONTRACT_B):
        session.add(
            EffectVerdict(
                function_id=fns[addr],
                chain_id=1,
                contract_address=addr.lower(),
                selector=SELECTOR,
                effect_class=EFFECT_CLASS_VALUE_OUT,
                verdict=VERDICT_PROVEN,
                tier=TIER_CALL,
                concrete_destination=DESTINATION if addr == CONTRACT_A else None,
            )
        )
    session.commit()

    seen: list[str] = []
    from sqlalchemy import event as sa_event

    def before_cursor(conn, cursor, statement, params, context, executemany):
        if "effect_verdicts" in statement.lower() and statement.strip().lower().startswith("select"):
            seen.append(statement)

    sa_event.listen(session.get_bind(), "before_cursor_execute", before_cursor)
    try:
        got = find_verdict_residue_batch(
            session,
            chain_id=1,
            identities=[
                (CONTRACT_A, SELECTOR, EFFECT_CLASS_VALUE_OUT),
                (CONTRACT_B, SELECTOR, EFFECT_CLASS_VALUE_OUT),
                ("0x" + "ee" * 20, SELECTOR, EFFECT_CLASS_VALUE_OUT),
            ],
        )
    finally:
        sa_event.remove(session.get_bind(), "before_cursor_execute", before_cursor)

    assert len(seen) == 1
    assert got[(CONTRACT_A.lower(), SELECTOR, EFFECT_CLASS_VALUE_OUT)] == (DESTINATION, None, None)
    assert got[(CONTRACT_B.lower(), SELECTOR, EFFECT_CLASS_VALUE_OUT)] == (None, None, None)
    assert ("0x" + "ee" * 20, SELECTOR, EFFECT_CLASS_VALUE_OUT) not in got


# ---------------------------------------------------------------------------
# 2. The empty-planning marker.
# ---------------------------------------------------------------------------


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
def test_contract_that_yields_plans_is_not_marked(clean_effects, monkeypatch):
    """A contract that produced plans is already marked by the verdicts they
    write. Marking it here would claim coverage for a job that could still die
    before writing them."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "marker-plans")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    worker = EffectsWorker(
        prober=_CountingProber(lambda c, ctx: unknown(EFFECT_CLASS_VALUE_OUT, gate_ref="role:X", reason="x")),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _run(worker, session, job)
    assert _marker_for(session, cids[CONTRACT_A]) is None
    assert session.query(EffectVerdict).count() == 1


@requires_postgres
def test_unresolvable_candidate_blocks_the_marker(clean_effects, monkeypatch):
    """A candidate skipped for a missing behavioral hash is a TRANSIENT failure.
    Marking the contract would suppress the retry — coverage loss disguised as a
    perf win, the one direction this must not have."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "marker-skip")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    worker = EffectsWorker(
        prober=_NoPlanProber(),
        hash_resolver=lambda s, c: None,  # no cached bytecode
        seams=_seams(session, job),
    )
    _errors, metrics = _run(worker, session, job)
    assert _marker_for(session, cids[CONTRACT_A]) is None
    assert metrics["contracts_planned_empty"] == 0


@requires_postgres
def test_a_raising_prober_blocks_the_marker(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "marker-raise")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    class _Boom:
        def __call__(self, session, cand, ctx):
            raise RuntimeError("prober exploded")

    worker = EffectsWorker(
        prober=_Boom(),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _run(worker, session, job)
    assert _marker_for(session, cids[CONTRACT_A]) is None


@requires_postgres
def test_a_partly_unplannable_contract_is_not_marked(clean_effects, monkeypatch):
    """One resolvable candidate yielding nothing does NOT license a marker while
    a sibling candidate on the same contract could not be resolved at all."""
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


@requires_postgres
def test_no_marker_while_the_fork_is_disabled(clean_effects, monkeypatch):
    """With Tier 2 off the pause plans never build, so an empty result is an
    artefact of the switch rather than a fact about the contract."""
    session = clean_effects
    monkeypatch.setenv("PSAT_EFFECTS_FORK", "0")
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "marker-nofork")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    worker = EffectsWorker(
        prober=_NoPlanProber(),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _run(worker, session, job)
    assert _marker_for(session, cids[CONTRACT_A]) is None


@requires_postgres
def test_marker_is_refreshed_by_a_later_empty_pass(clean_effects, monkeypatch):
    """Idempotent by contract: the newest empty pass is the one the freshness
    rule compares against, so a second run refreshes rather than duplicates."""
    session = clean_effects
    pid, fns, cids = _protocol_with_functions(session, [CONTRACT_A])
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A], cids[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    session.add(
        EffectsPlanMarker(
            contract_id=cids[CONTRACT_A],
            candidates_planned=9,
            planned_at=datetime.now(timezone.utc) - timedelta(days=2),
        )
    )
    session.commit()

    job = _make_job(session, pid, "marker-refresh")
    worker = EffectsWorker(
        prober=_NoPlanProber(),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface_A"),
        seams=_seams(session, job),
    )
    _run(worker, session, job)

    session.expire_all()
    markers = session.query(EffectsPlanMarker).filter(EffectsPlanMarker.contract_id == cids[CONTRACT_A]).all()
    assert len(markers) == 1
    assert markers[0].candidates_planned == 1
    assert markers[0].planned_at >= job.created_at
