"""The whole effects stage against stubbed seams with recorded transcripts; the zero-candidate path touches no wire."""

from __future__ import annotations

from unittest.mock import MagicMock

from db import effect_cache
from db.models import (
    EffectBehaviorCache,
    EffectiveFunction,
    EffectVerdict,
)
from db.queue import create_job, get_artifact
from services.effects.config import (
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
    SCOPE_PROJECTION,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.harness import Discrepancy, proven, unknown
from services.effects.simulate import (
    TRANSFER_TOPIC,
    SimCallResult,
    SimLog,
    SimResult,
)
from tests.cache_helpers import requires_postgres
from tests.support.effects_worker_harness import (
    CONTRACT_A,
    CONTRACT_B,
    CONTRACT_C,
    PRINCIPAL,
    _candidate,
    _make_job,
    _Prober,
    _protocol_with_functions,
    _run,
    _seams,
    clean_effects,  # noqa: F401  (imported so pytest registers the fixture here)
)
from workers.effects_worker import (
    EffectsWorker,
)


@requires_postgres
def test_flag_on_end_to_end_persists_verdicts_and_transcripts(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "supply-e2e")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

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

    cache = session.query(EffectBehaviorCache).one()
    assert cache.behavior_hash == "kernel_hash_A"
    assert cache.scope == SCOPE_KERNEL
    assert cache.contract_surface_hash == ""
    assert cache.verdict == VERDICT_PROVEN
    assert cache.details["supply_delta_sign"] == "mint"
    assert cache.transcript_ptr is not None

    verdict = session.query(EffectVerdict).one()
    assert verdict.function_id == fns[CONTRACT_A]
    assert verdict.verdict == VERDICT_PROVEN
    assert verdict.behavior_hash == "kernel_hash_A"

    # Claims-bridge call site 1: the proven mint is minted onto the function row.
    ef_row = session.query(EffectiveFunction).filter(EffectiveFunction.id == fns[CONTRACT_A]).one()
    observed = [c for c in (ef_row.claims or []) if c["tier"] == "behavioral_observed"]
    assert [c["claim_id"] for c in observed] == ["supply.mint"]
    assert observed[0]["witness"]["effect_verdict_id"] == verdict.id
    assert "mint" in (ef_row.effect_labels or [])

    _job_id, _, name = cache.transcript_ptr.partition("::")
    tr = get_artifact(session, job.id, name)
    assert isinstance(tr, dict) and tr["effect_class"] == EFFECT_CLASS_SUPPLY

    assert metrics["verdicts_written"] == 1
    assert metrics["cache_misses"] == 1
    # A new-idiom candidate is a benign metric, not a degraded error.
    assert metrics["new_idiom_candidates"] == 1
    assert not any(e.context and e.context.get("discrepancy_kind", "").startswith("static_silent") for e in errors)


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


def _twin_jobs(session, monkeypatch, addresses):
    """Twins are cross-job, as in production."""
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


# ---------------------------------------------------------------------------
# 3b. Tier-0 (historical) verdicts NEVER transfer across bytecode twins — each
#     deployment's current-state check must run.
# ---------------------------------------------------------------------------


@requires_postgres
def test_projection_not_transfer_across_surfaces(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns = _protocol_with_functions(session, [CONTRACT_A, CONTRACT_B])
    job = _make_job(session, pid, "proj")
    cands = [_candidate(a, fns[a]) for a in (CONTRACT_A, CONTRACT_B)]
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: cands)

    hashes = {fns[CONTRACT_A]: ("K", "surfaceA"), fns[CONTRACT_B]: ("K", "surfaceB")}
    prober = _Prober(
        lambda c, ctx: proven(EFFECT_CLASS_FREEZE_PAUSE, scope=SCOPE_PROJECTION, details={"latch_flip": True}),
        effect_class=EFFECT_CLASS_FREEZE_PAUSE,
        scope=SCOPE_PROJECTION,
    )
    worker = EffectsWorker(prober=prober, hash_resolver=lambda s, c: hashes[c.function_id], seams=_seams(session, job))
    _errors, metrics = _run(worker, session, job)

    assert sorted(prober.runs) == sorted([fns[CONTRACT_A], fns[CONTRACT_B]])
    rows = session.query(EffectBehaviorCache).all()
    assert len(rows) == 2
    assert {r.contract_surface_hash for r in rows} == {"surfaceA", "surfaceB"}
    assert metrics["cache_misses"] == 2
    assert metrics["cache_hits_projection"] == 0


@requires_postgres
def test_tier2_folds_anvil_rss_into_peak(clean_effects, monkeypatch):
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
    assert fake.closed  # fork still closed on the normal exit path


@requires_postgres
def test_self_audit_catches_hash_collision(clean_effects, monkeypatch):
    """The self-audit sees the kernels disagree and withholds."""
    session = clean_effects
    jobs, fns = _twin_jobs(session, monkeypatch, [CONTRACT_A, CONTRACT_B])

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
    metrics: dict = {}
    for job in jobs:
        errors, metrics = _run(worker, session, job)
        all_errors += errors
        hits += metrics["cache_hits_kernel"]

    row = session.query(EffectBehaviorCache).one()
    assert row.audit_status == "failed"
    b_verdict = session.query(EffectVerdict).filter(EffectVerdict.contract_address == CONTRACT_B.lower()).one()
    assert b_verdict.verdict == VERDICT_UNKNOWN
    assert any(e.context and e.context.get("discrepancy_kind") == "kernel_hash_collision" for e in all_errors)
    assert metrics["cache_hits_kernel"] == 0  # the hit was withheld, not counted


@requires_postgres
def test_section9_static_pos_sim_neg_routes_to_warning(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "disc")
    cand = _candidate(CONTRACT_A, fns[CONTRACT_A])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])

    # A matcher/probe-soundness hole.
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
    assert "closing_rule" in routed[0].context
    assert session.query(EffectVerdict).one().verdict == VERDICT_UNKNOWN
    assert metrics["discrepancies_filed"] == 1


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

    # Direction 2 is an informational vocabulary-growth signal.
    assert session.query(EffectVerdict).one().verdict == VERDICT_PROVEN
    degraded_idioms = [
        e for e in errors if e.context and e.context.get("discrepancy_kind", "").startswith("static_silent")
    ]
    assert degraded_idioms == []
    assert metrics["new_idiom_candidates"] == 1
    assert metrics["discrepancies_filed"] == 0
    # The candidate stays harvestable from logs.
    idiom_records = [r for r in caplog.records if getattr(r, "discrepancy_kind", "").startswith("static_silent")]
    assert len(idiom_records) == 1
    rec = idiom_records[0]
    assert rec.levelno == logging.INFO
    assert getattr(rec, "closing_rule", None)
    assert getattr(rec, "effect_class", None) == EFFECT_CLASS_SUPPLY


# ``store_artifact`` upserts on (job_id, name), so a positional counter overwrote artifacts across passes.


@requires_postgres
def test_transcript_names_survive_a_second_pass_over_the_same_job(clean_effects):
    session = clean_effects
    pid, _fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "transcript-collision")
    worker = EffectsWorker()

    value_out = {"effect_class": EFFECT_CLASS_VALUE_OUT, "tier": "tier1", "calls": ["v"], "results": []}
    authority = {"effect_class": "authority_change", "tier": "tier1", "calls": ["a"], "results": []}

    pass1 = worker._make_transcript_store(session, job)
    value_ptr = pass1(value_out)
    pass1(authority)

    # value_out is now a hit, so authority_change is stored first: the index reuse that clobbered.
    pass2 = worker._make_transcript_store(session, job)
    pass2(authority)
    session.commit()

    stored_job_id, _, stored_name = value_ptr.partition("::")
    assert stored_job_id == str(job.id)
    assert get_artifact(session, job.id, stored_name) == value_out


@requires_postgres
def test_transcript_name_is_stable_for_identical_content(clean_effects):
    session = clean_effects
    pid, _fns = _protocol_with_functions(session, [CONTRACT_A])
    job = _make_job(session, pid, "transcript-stable")
    worker = EffectsWorker()
    transcript = {"effect_class": EFFECT_CLASS_VALUE_OUT, "tier": "tier1", "calls": [], "results": []}

    first = worker._make_transcript_store(session, job)(transcript)
    second = worker._make_transcript_store(session, job)(transcript)
    assert first == second
    assert EFFECT_CLASS_VALUE_OUT in first


# Every unknown supply verdict has the same details, so without the reason a withheld-on-contradiction verdict is
# indistinguishable from "supply did not move".


@requires_postgres
def test_a_cached_reason_is_served_to_the_twin_that_hits_it(clean_effects, monkeypatch):
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

    assert fns[CONTRACT_C] not in prober.runs
    assert session.query(EffectBehaviorCache).one().details["reason"] == "no_supply_delta"
    witnesses = {v.function_id: v.witness for v in session.query(EffectVerdict).all()}
    assert witnesses[fns[CONTRACT_C]]["reason"] == "no_supply_delta"


def test_a_zero_key_hit_that_disagrees_publishes_its_own_verdict(clean_effects, monkeypatch):
    """A reason legitimately varies, so disagreement leaves the row unaudited rather than audit-failed."""
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
    assert witnesses[fns[CONTRACT_B]]["reason"] == "no_value_observed"
    assert witnesses[fns[CONTRACT_A]]["reason"] == "no_supply_delta"


def test_two_identical_runs_differ_only_in_the_declared_non_identity_columns(clean_effects, monkeypatch):
    """The cache is written on read, so two identical runs differ only in ``REPLAY_IDENTITY_EXCLUDED_COLUMNS``."""
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

    for job in jobs:
        _run(worker, session, job)
    session.expire_all()
    row = session.query(EffectBehaviorCache).one()
    after = {name: getattr(row, name) for name in tracked}

    assert after == before, "a re-run changed a column that is NOT declared non-identity"
    # So the exclusion is not vacuous.
    assert row.hit_count > before_hits
