"""Effects worker end-to-end orchestration (EFFECTS_RESOLUTION_SPEC Phase 3).

Drives the whole stage against STUBBED seams with recorded transcripts (inv. 8):
selection → preflight → cache lookup (kernel vs projection, inv. 3) → probes →
self-audit (§7) → verdict persistence → §9 routing. No live RPC; the
zero-candidate path is asserted to touch no wire.

Covers the Phase-3 required tests:
  - flag-on end-to-end with stubbed seams ⇒ persisted verdicts + transcripts
  - kernel transfers across a twin fixture ⇒ cache hit, no re-sim
  - projection does NOT transfer across different surfaces
  - self-audit catches an injected hash collision (disagreeing kernels ⇒ withhold)
  - both §9 directions (static-pos/sim-neg → warning+discrepancy;
    static-silent/sim-pos → witness + idiom candidate)
  - zero-candidate ⇒ no wire, no rows
"""

from __future__ import annotations

import sys
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import effect_cache  # noqa: E402
from db.models import (  # noqa: E402
    Contract,
    EffectBehaviorCache,
    EffectiveFunction,
    EffectVerdict,
    Protocol,
)
from db.queue import create_job, get_artifact, store_artifact  # noqa: E402
from services.effects.config import (  # noqa: E402
    EFFECT_CLASS_CODE_UPGRADE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
    SCOPE_PROJECTION,
    TIER_HISTORICAL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.harness import Discrepancy, proven, unknown  # noqa: E402
from services.effects.orchestrator import ProbePlan  # noqa: E402
from services.effects.selection import Candidate  # noqa: E402
from services.effects.simulate import (  # noqa: E402
    TRANSFER_TOPIC,  # noqa: E402
    SimCallResult,
    SimLog,
    SimResult,
)
from tests.cache_helpers import requires_postgres  # noqa: E402
from utils.logging import degraded_errors_var, stage_metrics_var  # noqa: E402
from workers.effects_worker import (
    EffectsWorker,  # noqa: E402
    _Seams,  # noqa: E402
)

CONTRACT_A = "0x" + "a1" * 20
CONTRACT_B = "0x" + "b2" * 20
CONTRACT_C = "0x" + "c3" * 20
PRINCIPAL = "0x" + "22" * 20


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def clean_effects(db_session):
    db_session.query(EffectVerdict).delete()
    db_session.query(EffectBehaviorCache).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.query(EffectVerdict).delete()
    db_session.query(EffectBehaviorCache).delete()
    db_session.commit()


def _protocol_with_functions(session, addresses: list[str]) -> tuple[int, dict[str, int]]:
    """Create a protocol + one contract & effective-function per address. Returns
    ``(protocol_id, {address: function_id})`` so candidates can reference real
    ``effective_functions.id`` rows (the ``effect_verdicts`` FK)."""
    proto = Protocol(name=f"effects-it-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    fn_ids: dict[str, int] = {}
    for addr in addresses:
        c = Contract(protocol_id=proto.id, address=addr, chain="ethereum", is_proxy=False)
        session.add(c)
        session.flush()
        fn = EffectiveFunction(
            contract_id=c.id,
            function_name="f",
            selector="0x40c10f19",
            authority_public=False,
            effect_targets=["slot0"],
        )
        session.add(fn)
        session.flush()
        fn_ids[addr] = fn.id
    session.commit()
    return proto.id, fn_ids


def _make_job(session, protocol_id: int, name: str, address: str = CONTRACT_A):
    """A job stamped with ``protocol_id`` so the worker's selection guard passes
    (a contract job with no protocol has nothing to simulate)."""
    job = create_job(session, {"address": address, "name": name})
    job.protocol_id = protocol_id
    session.commit()
    return job


def _candidate(address: str, function_id: int, contract_id: int = 0) -> Candidate:
    return Candidate(
        function_id=function_id,
        contract_id=contract_id,
        contract_address=address,
        selector="0x40c10f19",
        function_name="f",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
        value_at_stake_usd=Decimal("1"),
    )


def _transcript_store(session, job):
    """A REAL transcript store (artifact-backed) so ``transcript_ptr`` resolves."""
    seq = {"n": 0}

    def store(tr: dict[str, Any]) -> str:
        name = f"effect_transcript_{seq['n']}"
        seq["n"] += 1
        store_artifact(session, job.id, name, data=tr)
        return f"{job.id}::{name}"

    return store


def _run(worker, session, job) -> tuple[list, dict]:
    """Run ``process`` under bound warning-channel + metrics accumulators (as
    ``BaseWorker._execute_job`` would), returning (stage_errors, metrics)."""
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


class _Prober:
    """Injectable prober: one plan per candidate whose ``run`` returns a canned
    ObservedEffect from ``factory(candidate)``. Records which candidates ran so
    'no re-sim' is checkable."""

    def __init__(self, factory, *, effect_class=EFFECT_CLASS_SUPPLY, scope=SCOPE_KERNEL, gate_ref="role:MINTER"):
        self.factory = factory
        self.effect_class = effect_class
        self.scope = scope
        self.gate_ref = gate_ref
        self.runs: list[int] = []

    def __call__(self, session, cand, ctx):
        def run():
            self.runs.append(cand.function_id)
            return self.factory(cand, ctx)

        return [ProbePlan(effect_class=self.effect_class, scope=self.scope, run=run, gate_ref=self.gate_ref)]


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
        transcript_store=_transcript_store(session, job),
        capability_store=store,
        chain_id=1,
    )


# ---------------------------------------------------------------------------
# 1. flag-on end-to-end with stubbed seams ⇒ persisted verdicts + transcripts
# ---------------------------------------------------------------------------


@requires_postgres
def test_flag_on_end_to_end_persists_verdicts_and_transcripts(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "supply-e2e")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    # A real supply recipe against a scripted simulate, so a genuine transcript
    # is emitted through the injected store.
    zero = "0x" + "00" * 20

    def mint_log():
        return SimLog(
            address=CONTRACT_A.lower(),
            topics=(TRANSFER_TOPIC, "0x" + zero[2:].rjust(64, "0"), "0x" + PRINCIPAL[2:].rjust(64, "0")),
            data="0x" + (5).to_bytes(32, "big").hex(),
        )

    def factory(c, ctx):
        from services.effects import recipes

        res = SimResult(
            calls=(
                SimCallResult(True, "0x" + (100).to_bytes(32, "big").hex(), None),
                SimCallResult(True, "0x", None, (mint_log(),)),
                SimCallResult(True, "0x" + (105).to_bytes(32, "big").hex(), None),
            )
        )
        return recipes.supply(
            simulate=lambda calls, tag, ov: res,
            store=ctx.transcript_store,
            ctx=ctx.sim_context(),
            token_address=c.contract_address,
            principal=PRINCIPAL,
            mint_calldata="0x40c10f19" + "00" * 64,
            simulate_supported=True,
            gate_ref="role:MINTER",
        )

    prober = _Prober(factory)
    worker = EffectsWorker(
        prober=prober,
        hash_resolver=lambda s, c: ("kernel_hash_A", "surface_A"),
        seams=_seams(session, job),
    )
    errors, metrics = _run(worker, session, job)

    # Code-plane cache row (kernel, empty surface) written.
    cache = session.query(EffectBehaviorCache).one()
    assert cache.behavior_hash == "kernel_hash_A"
    assert cache.scope == SCOPE_KERNEL
    assert cache.contract_surface_hash == ""
    assert cache.verdict == VERDICT_PROVEN
    assert cache.details["supply_delta_sign"] == "mint"
    assert cache.transcript_ptr is not None

    # State-plane residue row written, linked to the function.
    verdict = session.query(EffectVerdict).one()
    assert verdict.function_id == fns[CONTRACT_A]
    assert verdict.verdict == VERDICT_PROVEN
    assert verdict.behavior_hash == "kernel_hash_A"

    # §5.2 call site 1: the proven verdict is minted onto the function row as an
    # observable claim + legacy label (behavioral_observed tier). A mint supply
    # delta ⇒ supply.mint / "mint".
    ef_row = session.query(EffectiveFunction).filter(EffectiveFunction.id == fns[CONTRACT_A]).one()
    observed = [c for c in (ef_row.claims or []) if c["tier"] == "behavioral_observed"]
    assert [c["claim_id"] for c in observed] == ["supply.mint"]
    assert observed[0]["witness"]["effect_verdict_id"] == verdict.id
    assert "mint" in (ef_row.effect_labels or [])

    # Transcript artifact actually persisted and resolvable.
    _job_id, _, name = cache.transcript_ptr.partition("::")
    tr = get_artifact(session, job.id, name)
    assert isinstance(tr, dict) and tr["effect_class"] == EFFECT_CLASS_SUPPLY

    assert metrics["verdicts_written"] == 1
    assert metrics["cache_misses"] == 1
    # static-silent/sim-positive ⇒ a new-idiom candidate is a benign metric
    # (INFO signal), NOT a degraded stage_error.
    assert metrics["new_idiom_candidates"] == 1
    assert not any(e.context and e.context.get("discrepancy_kind", "").startswith("static_silent") for e in errors)


# ---------------------------------------------------------------------------
# 2. zero candidate ⇒ no wire, no rows
# ---------------------------------------------------------------------------


@requires_postgres
def test_zero_candidate_touches_no_wire(clean_effects, monkeypatch):
    session = clean_effects
    job = create_job(session, {"address": CONTRACT_A, "name": "zero-cand"})
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [])

    sim = MagicMock(side_effect=AssertionError("wire touched on the zero-candidate path"))
    hashr = MagicMock(side_effect=AssertionError("hash resolver called with no candidates"))
    worker = EffectsWorker(hash_resolver=hashr, seams=_seams(session, job, simulate=sim))
    _errors, metrics = _run(worker, session, job)

    assert sim.call_count == 0
    assert hashr.call_count == 0
    assert session.query(EffectBehaviorCache).count() == 0
    assert session.query(EffectVerdict).count() == 0
    assert metrics["verdicts_written"] == 0
    assert metrics["candidates_in"] == 0


# ---------------------------------------------------------------------------
# 3. kernel transfers across a twin ⇒ cache hit, no re-sim (after self-audit)
# ---------------------------------------------------------------------------


def _twin_jobs(session, monkeypatch, addresses):
    """One protocol+contract+function+job per address (each contract is its own
    job, as in production — twins are cross-JOB). Returns (jobs, function_ids).
    ``select_candidates`` is keyed by protocol_id so each job sees only its own
    single candidate."""
    jobs = []
    cand_by_pid: dict[int, list] = {}
    fn_ids: dict[str, int] = {}
    for addr in addresses:
        pid, fns = _protocol_with_functions(session, [addr])
        job = _make_job(session, pid, f"twin-{addr[-4:]}", addr)
        jobs.append(job)
        fn_ids[addr] = fns[addr]
        cand_by_pid[pid] = [_candidate(addr, fns[addr])]
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda session, pid, **k: cand_by_pid[pid])
    return jobs, fn_ids


@requires_postgres
def test_kernel_twin_cache_hit_no_resim(clean_effects, monkeypatch):
    """Three deployments (three jobs) share one kernel hash. The first writes
    (miss); the second re-simulates ONCE for the §7 self-audit; the third is a
    free, trusted hit with NO probe."""
    session = clean_effects
    jobs, fns = _twin_jobs(session, monkeypatch, [CONTRACT_A, CONTRACT_B, CONTRACT_C])

    # Same kernel hash for all three (a resolved-behavior twin); distinct surfaces.
    hashes = {fns[CONTRACT_A]: ("K", "sA"), fns[CONTRACT_B]: ("K", "sB"), fns[CONTRACT_C]: ("K", "sC")}
    prober = _Prober(lambda c, ctx: proven(EFFECT_CLASS_SUPPLY, details={"supply_delta_sign": "mint"}))
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, jobs[0])
    )
    hits = misses = 0
    for job in jobs:
        _errors, metrics = _run(worker, session, job)
        hits += metrics["cache_hits_kernel"]
        misses += metrics["cache_misses"]

    # A ran (miss) + B ran (audit); C did NOT run (free hit).
    assert fns[CONTRACT_A] in prober.runs
    assert fns[CONTRACT_B] in prober.runs
    assert fns[CONTRACT_C] not in prober.runs
    assert len(prober.runs) == 2

    # One shared kernel row, audited passed, hit twice (B and C).
    row = session.query(EffectBehaviorCache).one()
    assert row.audit_status == "passed"
    assert misses == 1
    assert hits == 2
    # All three deployments got a state-plane verdict.
    assert session.query(EffectVerdict).count() == 3


# ---------------------------------------------------------------------------
# 3b. Tier-0 (historical) verdicts NEVER transfer across bytecode twins — each
#     deployment's current-state check must run (inv. 13 / §7 state-plane).
# ---------------------------------------------------------------------------


@requires_postgres
def test_tier0_historical_verdict_never_transfers_across_twins(clean_effects, monkeypatch):
    """Three EIP-1967 proxies share a runtime-bytecode kernel hash but DIVERGE in
    current state: A/B are upgraded with a non-zero impl (proven-now), C's impl is
    currently zero (historical-only ⇒ unknown). A cached Tier-0 verdict would let
    C free-hit A's ``proven`` "upgradeable now" though C's own current-state check
    never ran. The fix: Tier-0 is never code-plane cached — so every twin probes
    and each gets its OWN state-plane verdict; no EffectBehaviorCache row exists."""
    session = clean_effects
    jobs, fns = _twin_jobs(session, monkeypatch, [CONTRACT_A, CONTRACT_B, CONTRACT_C])

    # Same kernel hash (twin bytecode); C's current-state check fails.
    hashes = {fns[CONTRACT_A]: ("KUP", "sA"), fns[CONTRACT_B]: ("KUP", "sB"), fns[CONTRACT_C]: ("KUP", "sC")}
    upgraded = {fns[CONTRACT_A]: True, fns[CONTRACT_B]: True, fns[CONTRACT_C]: False}

    def factory(c, ctx):
        if upgraded[c.function_id]:
            return proven(
                EFFECT_CLASS_CODE_UPGRADE,
                tier=TIER_HISTORICAL,
                reason="indexed_upgrade_plus_current_state",
                details={"upgradeable": True},
                concrete={"current_check_passed": True},
            )
        return unknown(
            EFFECT_CLASS_CODE_UPGRADE,
            tier=TIER_HISTORICAL,
            reason="historical_only_current_check_failed",
            concrete={"current_check_passed": False},
        )

    prober = _Prober(factory, effect_class=EFFECT_CLASS_CODE_UPGRADE, gate_ref="proxy:transparent")
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, jobs[0])
    )
    for job in jobs:
        _run(worker, session, job)

    # Every twin re-probed (no free transfer); nothing landed in the code-plane cache.
    assert set(prober.runs) == set(fns.values())
    assert session.query(EffectBehaviorCache).count() == 0

    # Each deployment's state-plane verdict reflects its OWN current-state check.
    verdicts = {v.function_id: v for v in session.query(EffectVerdict).all()}
    assert verdicts[fns[CONTRACT_A]].verdict == VERDICT_PROVEN
    assert verdicts[fns[CONTRACT_B]].verdict == VERDICT_PROVEN
    assert verdicts[fns[CONTRACT_C]].verdict == VERDICT_UNKNOWN


# ---------------------------------------------------------------------------
# 4. projection does NOT transfer across different surfaces
# ---------------------------------------------------------------------------


@requires_postgres
def test_projection_not_transfer_across_surfaces(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns = _protocol_with_functions(session, [CONTRACT_A, CONTRACT_B])
    job = _make_job(session, pid, "proj")
    cands = [_candidate(a, fns[a]) for a in (CONTRACT_A, CONTRACT_B)]
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: cands)

    # Same kernel hash, DIFFERENT surfaces: a projection must re-probe on each.
    hashes = {fns[CONTRACT_A]: ("K", "surfaceA"), fns[CONTRACT_B]: ("K", "surfaceB")}
    prober = _Prober(
        lambda c, ctx: proven(EFFECT_CLASS_FREEZE_PAUSE, scope=SCOPE_PROJECTION, details={"latch_flip": True}),
        effect_class=EFFECT_CLASS_FREEZE_PAUSE,
        scope=SCOPE_PROJECTION,
    )
    worker = EffectsWorker(prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, job))
    _errors, metrics = _run(worker, session, job)

    # Both surfaces probed → two projection rows, zero projection hits.
    assert sorted(prober.runs) == sorted([fns[CONTRACT_A], fns[CONTRACT_B]])
    rows = session.query(EffectBehaviorCache).all()
    assert len(rows) == 2
    assert {r.contract_surface_hash for r in rows} == {"surfaceA", "surfaceB"}
    assert metrics["cache_misses"] == 2
    assert metrics["cache_hits_projection"] == 0


# ---------------------------------------------------------------------------
# 4b. tier-2 probes fold the fork's RSS into peak_anvil_rss_mb
# ---------------------------------------------------------------------------


@requires_postgres
def test_tier2_folds_anvil_rss_into_peak(clean_effects, monkeypatch):
    """A projection (tier-2) probe with a live fork present samples the fork's RSS
    after each probe and records the max as ``peak_anvil_rss_mb`` (was a dead 0)."""
    session = clean_effects
    pid, fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "rss")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    class _FakeAnvil:
        closed = False

        def rss_mb(self) -> int:
            return 137

        def close(self) -> None:
            self.closed = True

    prober = _Prober(
        lambda c, ctx: proven(EFFECT_CLASS_FREEZE_PAUSE, scope=SCOPE_PROJECTION, details={"latch_flip": True}),
        effect_class=EFFECT_CLASS_FREEZE_PAUSE,
        scope=SCOPE_PROJECTION,
    )
    worker = EffectsWorker(prober=prober, hash_resolver=lambda s, c: ("K", "sA"), seams=_seams(session, job))
    fake = _FakeAnvil()
    worker._anvil = fake  # the fork the tier-2 loop samples (memoized in prod)
    _errors, metrics = _run(worker, session, job)

    assert metrics["peak_anvil_rss_mb"] == 137
    assert fake.closed  # fork still closed on the normal exit path (inv. 16)


# ---------------------------------------------------------------------------
# 5. self-audit catches an injected hash collision ⇒ withhold, not propagate
# ---------------------------------------------------------------------------


@requires_postgres
def test_self_audit_catches_hash_collision(clean_effects, monkeypatch):
    """Two deployments share a kernel hash but their kernels actually DISAGREE
    (an injected collision). The self-audit re-sims the second, sees the mismatch,
    withholds (unknown + discrepancy), and never propagates the cached verdict."""
    session = clean_effects
    jobs, fns = _twin_jobs(session, monkeypatch, [CONTRACT_A, CONTRACT_B])

    # A → mint; B → burn (same hash, disagreeing kernels).
    def factory(c, ctx):
        sign = "mint" if c.function_id == fns[CONTRACT_A] else "burn"
        return proven(EFFECT_CLASS_SUPPLY, details={"supply_delta_sign": sign})

    hashes = {fns[CONTRACT_A]: ("K", "sA"), fns[CONTRACT_B]: ("K", "sB")}
    prober = _Prober(factory)
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, jobs[0])
    )
    all_errors = []
    hits = 0
    for job in jobs:
        errors, metrics = _run(worker, session, job)
        all_errors += errors
        hits += metrics["cache_hits_kernel"]

    # The shared kernel row is marked audit-failed; the collision is filed.
    row = session.query(EffectBehaviorCache).one()
    assert row.audit_status == "failed"
    # B's persisted verdict is withheld unknown — NOT A's cached 'mint' proven.
    b_verdict = session.query(EffectVerdict).filter(EffectVerdict.contract_address == CONTRACT_B.lower()).one()
    assert b_verdict.verdict == VERDICT_UNKNOWN
    assert any(e.context and e.context.get("discrepancy_kind") == "kernel_hash_collision" for e in all_errors)
    assert metrics["cache_hits_kernel"] == 0  # the hit was withheld, not counted


# ---------------------------------------------------------------------------
# 6. §9 direction 1 — static-positive / sim-negative → warning + discrepancy
# ---------------------------------------------------------------------------


@requires_postgres
def test_section9_static_pos_sim_neg_routes_to_warning(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "disc")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    # A taint-param sentinel-negative discrepancy attached to an unknown verdict
    # (matcher/probe-soundness hole — direction 1).
    disc = Discrepancy(kind="taint_param_sentinel_negative", effect_class=EFFECT_CLASS_VALUE_OUT)

    def factory(c, ctx):
        eff = unknown(EFFECT_CLASS_VALUE_OUT, reason="no_value_observed")
        eff.discrepancy = disc
        return eff

    prober = _Prober(factory, effect_class=EFFECT_CLASS_VALUE_OUT)
    worker = EffectsWorker(prober=prober, hash_resolver=lambda s, c: ("Kv", "Sv"), seams=_seams(session, job))
    errors, metrics = _run(worker, session, job)

    routed = [e for e in errors if e.context and e.context.get("discrepancy_kind") == "taint_param_sentinel_negative"]
    assert len(routed) == 1
    # Closing-rule bookkeeping present, verdict stayed unknown (penalty side).
    assert "closing_rule" in routed[0].context
    assert session.query(EffectVerdict).one().verdict == VERDICT_UNKNOWN
    assert metrics["discrepancies_filed"] == 1


# ---------------------------------------------------------------------------
# 7. §9 direction 2 — static-silent / sim-positive → witness + idiom candidate
# ---------------------------------------------------------------------------


@requires_postgres
def test_section9_static_silent_sim_pos_files_idiom(clean_effects, monkeypatch, caplog):
    session = clean_effects
    pid, fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "idiom")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    prober = _Prober(lambda c, ctx: proven(EFFECT_CLASS_SUPPLY, details={"supply_delta_sign": "mint"}))
    worker = EffectsWorker(prober=prober, hash_resolver=lambda s, c: ("Ki", "Si"), seams=_seams(session, job))
    import logging

    with caplog.at_level(logging.INFO, logger="services.effects.discrepancies"):
        errors, metrics = _run(worker, session, job)

    # Witness persisted (proven verdict). Direction 2 is an INFORMATIONAL
    # vocabulary-growth signal: it must NOT file a degraded stage_error, and it
    # is counted as a benign ``new_idiom_candidates`` metric (not a discrepancy).
    assert session.query(EffectVerdict).one().verdict == VERDICT_PROVEN
    degraded_idioms = [
        e for e in errors if e.context and e.context.get("discrepancy_kind", "").startswith("static_silent")
    ]
    assert degraded_idioms == []
    assert metrics["new_idiom_candidates"] == 1
    assert metrics["discrepancies_filed"] == 0
    # The candidate stays harvestable from logs, carrying the same context dict
    # (incl. closing-rule bookkeeping) the degraded path used to record.
    idiom_records = [r for r in caplog.records if getattr(r, "discrepancy_kind", "").startswith("static_silent")]
    assert len(idiom_records) == 1
    rec = idiom_records[0]
    assert rec.levelno == logging.INFO
    assert getattr(rec, "closing_rule", None)
    assert getattr(rec, "effect_class", None) == EFFECT_CLASS_SUPPLY


# ---------------------------------------------------------------------------
# 8. Transcript artifact names are collision-free across passes
#
# ``store_artifact`` upserts on (job_id, name), so the old positional counter was
# only unique WITHIN one pass: a second pass over the same job (stale-lease
# reclaim, requeue) restarted at 0 against a different probe order — because the
# first pass turned some misses into hits — and overwrote the artifacts that
# already-persisted ``transcript_ptr``s pointed at.
# ---------------------------------------------------------------------------


@requires_postgres
def test_transcript_names_survive_a_second_pass_over_the_same_job(clean_effects):
    session = clean_effects
    pid, _fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "transcript-collision")
    worker = EffectsWorker()

    value_out = {"effect_class": EFFECT_CLASS_VALUE_OUT, "tier": "tier1", "calls": ["v"], "results": []}
    authority = {"effect_class": "authority_change", "tier": "tier1", "calls": ["a"], "results": []}

    # Pass 1 probes both classes; its value_out pointer is what a cache row keeps.
    pass1 = worker._make_transcript_store(session, job)
    value_ptr = pass1(value_out)
    pass1(authority)

    # Pass 2 re-runs the job with value_out now a cache HIT, so authority_change
    # is the FIRST transcript stored — the exact index reuse that clobbered.
    pass2 = worker._make_transcript_store(session, job)
    pass2(authority)
    session.commit()

    stored_job_id, _, stored_name = value_ptr.partition("::")
    assert stored_job_id == str(job.id)
    assert get_artifact(session, job.id, stored_name) == value_out


@requires_postgres
def test_transcript_name_is_stable_for_identical_content(clean_effects):
    """A replayed probe must not accumulate a duplicate artifact per pass."""
    session = clean_effects
    pid, _fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "transcript-stable")
    worker = EffectsWorker()
    transcript = {"effect_class": EFFECT_CLASS_VALUE_OUT, "tier": "tier1", "calls": [], "results": []}

    first = worker._make_transcript_store(session, job)(transcript)
    second = worker._make_transcript_store(session, job)(transcript)
    assert first == second
    assert EFFECT_CLASS_VALUE_OUT in first


# ---------------------------------------------------------------------------
# 9. The worker scopes selection to its OWN job's contract
# ---------------------------------------------------------------------------


@requires_postgres
def test_select_scopes_to_the_jobs_own_contract(clean_effects):
    """Drives the REAL ``select_candidates`` (no monkeypatch): a job must not plan
    — and therefore must not re-write — a sibling contract's candidates."""
    session = clean_effects
    pid, fns = _protocol_with_functions(session, [CONTRACT_A, CONTRACT_B])
    job_a = _make_job(session, pid, "scoped-a", address=CONTRACT_A)
    _make_job(session, pid, "scoped-b", address=CONTRACT_B)
    session.commit()

    picked = {c.function_id for c in EffectsWorker()._select(session, job_a)}
    assert picked == {fns[CONTRACT_A]}


# ---------------------------------------------------------------------------
# 10. The verdict REASON reaches the persisted witness
#
# Every unknown supply verdict carries the same ``{"observation": "executed"}``
# details, so without the reason the withheld-on-contradiction verdict — the
# strongest safety decision this stage makes — is byte-identical on the row to
# "the call ran and supply did not move". Nothing downstream can count it, and a
# regression that stopped withholding would be invisible in the data.
# ---------------------------------------------------------------------------


@requires_postgres
def test_withheld_supply_sign_is_distinguishable_from_a_plain_non_observation(clean_effects, monkeypatch):
    session = clean_effects
    jobs, fns = _twin_jobs(session, monkeypatch, [CONTRACT_A, CONTRACT_B])
    # Distinct kernel hashes: these are two DIFFERENT behaviors that happen to
    # produce the same structural witness, which is the whole point.
    hashes = {fns[CONTRACT_A]: ("KA", "sA"), fns[CONTRACT_B]: ("KB", "sB")}
    reasons = {
        fns[CONTRACT_A]: "supply_sign_contradicted_by_transfers",
        fns[CONTRACT_B]: "no_supply_delta",
    }

    def factory(c, ctx):
        return unknown(
            EFFECT_CLASS_SUPPLY,
            reason=reasons[c.function_id],
            details={"observation": "executed"},
        )

    worker = EffectsWorker(
        prober=_Prober(factory), hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, jobs[0])
    )
    for job in jobs:
        _run(worker, session, job)

    witnesses = {v.function_id: v.witness for v in session.query(EffectVerdict).all()}
    assert witnesses[fns[CONTRACT_A]]["reason"] == "supply_sign_contradicted_by_transfers"
    assert witnesses[fns[CONTRACT_B]]["reason"] == "no_supply_delta"
    # The discriminator every consumer already joins on is untouched.
    assert witnesses[fns[CONTRACT_A]]["observation"] == "executed"


@requires_postgres
def test_a_cached_reason_is_served_to_the_twin_that_hits_it(clean_effects, monkeypatch):
    """A cacheable non-observation transfers on the behavioral hash, so the twin
    that never probed must still be able to say WHY its verdict is unknown."""
    session = clean_effects
    jobs, fns = _twin_jobs(session, monkeypatch, [CONTRACT_A, CONTRACT_B, CONTRACT_C])
    hashes = {fns[a]: ("K", f"s{a[-2:]}") for a in (CONTRACT_A, CONTRACT_B, CONTRACT_C)}

    def factory(c, ctx):
        return unknown(EFFECT_CLASS_SUPPLY, reason="no_supply_delta", details={"observation": "executed"})

    prober = _Prober(factory)
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, jobs[0])
    )
    for job in jobs:
        _run(worker, session, job)

    # C free-hit the shared kernel row and never probed.
    assert fns[CONTRACT_C] not in prober.runs
    assert session.query(EffectBehaviorCache).one().details["reason"] == "no_supply_delta"
    witnesses = {v.function_id: v.witness for v in session.query(EffectVerdict).all()}
    assert witnesses[fns[CONTRACT_C]]["reason"] == "no_supply_delta"


def test_a_zero_key_hit_is_corroborated_before_it_is_trusted(clean_effects, monkeypatch):
    """§7 AUDIT FLOOR (G6-C1). ``authority_change`` — 49 of 150 local cache rows — carries
    no structural signature key at all, so the audit compared ``('unknown', None x5)``
    with itself and passed unconditionally. A hit like that is no longer trusted on the
    signature: the re-probe must agree on the row's actual assertion (verdict + reason).

    B agrees, so the row is stamped audited and C free-hits it. The twin that DISAGREES
    (below) publishes its own verdict instead of inheriting one.
    """
    session = clean_effects
    jobs, fns = _twin_jobs(session, monkeypatch, [CONTRACT_A, CONTRACT_B, CONTRACT_C])
    hashes = {fns[a]: ("K0", f"s{a[-2:]}") for a in (CONTRACT_A, CONTRACT_B, CONTRACT_C)}

    def factory(c, ctx):
        # No structural key — the shape of every authority_change row.
        return unknown(
            EFFECT_CLASS_SUPPLY,
            reason="no_supply_delta",
            details={"observation": "executed"},
        )

    prober = _Prober(factory)
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, jobs[0])
    )
    for job in jobs:
        _run(worker, session, job)

    # A wrote it; B re-probed to corroborate it (the floor); C hit it for free once the
    # corroboration stamped it.
    assert fns[CONTRACT_A] in prober.runs and fns[CONTRACT_B] in prober.runs
    assert fns[CONTRACT_C] not in prober.runs
    row = session.query(EffectBehaviorCache).one()
    assert row.audit_status == "passed"


def test_a_zero_key_hit_that_disagrees_publishes_its_own_verdict(clean_effects, monkeypatch):
    """The discriminating half: with no structural key to compare, a DIFFERENT reason is
    the only signal there is. The hitting deployment publishes what it re-simulated, and
    the row is left UNAUDITED rather than AUDIT_FAILED — a reason legitimately varies
    between two sightings of one behaviour, so poisoning the key would withhold from
    every future sighting on the strength of a difference that proves nothing."""
    session = clean_effects
    jobs, fns = _twin_jobs(session, monkeypatch, [CONTRACT_A, CONTRACT_B])
    hashes = {fns[a]: ("K1", f"s{a[-2:]}") for a in (CONTRACT_A, CONTRACT_B)}
    reasons = {fns[CONTRACT_A]: "no_supply_delta", fns[CONTRACT_B]: "no_value_observed"}

    def factory(c, ctx):
        return unknown(
            EFFECT_CLASS_SUPPLY,
            reason=reasons[c.function_id],
            details={"observation": "executed"},
        )

    prober = _Prober(factory)
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, jobs[0])
    )
    for job in jobs:
        _run(worker, session, job)

    row = session.query(EffectBehaviorCache).one()
    assert row.audit_status is None  # not trusted, and not poisoned either
    witnesses = {v.function_id: v.witness for v in session.query(EffectVerdict).all()}
    # B published ITS OWN reason, not A's.
    assert witnesses[fns[CONTRACT_B]]["reason"] == "no_value_observed"
    assert witnesses[fns[CONTRACT_A]]["reason"] == "no_supply_delta"


def test_two_identical_runs_differ_only_in_the_declared_non_identity_columns(clean_effects, monkeypatch):
    """G6-C6, pinned rather than papered over. This cache is written on READ
    (``bump_hit`` / ``mark_audited``), so two identical runs over an unchanged chain do
    NOT leave the DB byte-identical — inv. 11/12 hold for this table only MODULO
    ``REPLAY_IDENTITY_EXCLUDED_COLUMNS``.

    The test states the exact size of that gap: every other column is unchanged across a
    second run, and the mutation is confined to the declared set. A new mutating column
    added without declaring it turns this red."""
    session = clean_effects
    jobs, fns = _twin_jobs(session, monkeypatch, [CONTRACT_A, CONTRACT_B])
    hashes = {fns[a]: ("KIDENT", f"s{a[-2:]}") for a in (CONTRACT_A, CONTRACT_B)}

    def factory(c, ctx):
        return proven(
            EFFECT_CLASS_SUPPLY,
            reason="supply_delta",
            details={"observation": "executed", "supply_delta_sign": "mint"},
        )

    prober = _Prober(factory)
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, jobs[0])
    )
    for job in jobs:
        _run(worker, session, job)
    session.expire_all()

    tracked = [
        c.name
        for c in EffectBehaviorCache.__table__.columns
        if c.name not in effect_cache.REPLAY_IDENTITY_EXCLUDED_COLUMNS
    ]
    row = session.query(EffectBehaviorCache).one()
    before = {name: getattr(row, name) for name in tracked}
    before_hits = row.hit_count

    # Re-run the SAME job set over the SAME state: the "no-op re-analysis" case.
    for job in jobs:
        _run(worker, session, job)
    session.expire_all()
    row = session.query(EffectBehaviorCache).one()
    after = {name: getattr(row, name) for name in tracked}

    assert after == before, "a re-run changed a column that is NOT declared non-identity"
    # ...and the mutation really happens, so the exclusion is not vacuous.
    assert row.hit_count > before_hits
