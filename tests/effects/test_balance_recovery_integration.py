"""Selected collection gaps resume without broadening analysis policy."""

from dataclasses import replace

import pytest
from sqlalchemy import select

from db.models import ContractBalance, ContractBalanceFetch, EffectiveFunction, EffectVerdict, Job, JobStatus
from db.models.balance_work import PendingEffectsWork
from services.effects.balance_dependencies import MAX_ATTEMPTS, finish_work, prepare_work, reconcile_pending_effects
from services.effects.config import EFFECT_CLASS_SUPPLY
from services.effects.harness import proven, unknown
from tests.cache_helpers import requires_postgres
from tests.support.effects_worker_harness import (
    CONTRACT_A,
    _candidate,
    _make_job,
    _Prober,
    _protocol_with_functions,
    _run,
    _seams,
    clean_effects,  # noqa: F401
)
from workers.effects_worker import EffectsWorker


def accepted_empty(session, cid, address=CONTRACT_A):
    row = ContractBalanceFetch(
        contract_id=cid,
        chain_id=1,
        observed_address=address,
        native_status="unattempted",
        asset_set_status="returned_empty",
        asset_set_source="etherscan_pages",
        asset_page_length=0,
        writer="test",
    )
    session.add(row)
    session.flush()
    return row


def setup_candidate(session, monkeypatch):
    pid, ids = _protocol_with_functions(session, [CONTRACT_A])
    fid = ids[CONTRACT_A]
    fn = session.get(EffectiveFunction, fid)
    cand = replace(_candidate(CONTRACT_A, fid, fn.contract_id), restrict_families=frozenset({EFFECT_CLASS_SUPPLY}))
    monkeypatch.setattr("services.effects.balance_dependencies.needs_token_inventory", lambda *_: True)
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **kw: [cand])
    return pid, fn, cand


@requires_postgres
@pytest.mark.parametrize("resume_proven", [True, False])
def test_late_collection_resumes_once_without_gating_original_probes(clean_effects, monkeypatch, resume_proven):
    session = clean_effects
    pid, fn, cand = setup_candidate(session, monkeypatch)
    job = _make_job(session, pid, "balance-prerequisite")
    result = [unknown(EFFECT_CLASS_SUPPLY, reason="no_token_input")]
    prober = _Prober(lambda c, ctx: result[0])
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda *_: ("balance_kernel", "surface"), seams=_seams(session, job)
    )
    _run(worker, session, job)
    session.commit()
    row = session.scalars(select(PendingEffectsWork).where(PendingEffectsWork.function_id == fn.id)).one()
    assert row.state == "pending"
    assert prober.runs == [fn.id]  # Existing getter/seeding/probe paths still run.
    assert session.query(EffectVerdict).filter_by(function_id=fn.id, verdict="unknown").count() == 1
    assert reconcile_pending_effects(session, pid) == 0
    accepted_empty(session, fn.contract_id)
    row.next_attempt_at = None
    session.flush()
    assert reconcile_pending_effects(session, pid) == 1
    session.commit()
    resume = session.get(Job, row.queued_job_id)
    assert resume.request["effects_function_ids"] == [fn.id]
    if resume_proven:
        result[0] = proven(EFFECT_CLASS_SUPPLY, reason="supply_mint", details={"supply_delta_sign": "mint"})
    _run(worker, session, resume)
    session.commit()
    assert row.state == "complete"
    assert prober.runs == [fn.id, fn.id]
    assert session.query(EffectVerdict).filter_by(function_id=fn.id).count() == 1
    fetch = accepted_empty(session, fn.contract_id)
    fetch.asset_set_status = "returned_assets"
    session.add(
        ContractBalance(
            contract_id=fn.contract_id,
            fetch_id=fetch.id,
            token_address="0x" + "87" * 20,
            raw_balance="100",
            decimals=0,
            usd_value=None,
            observed_address=CONTRACT_A,
        )
    )
    session.flush()
    assert reconcile_pending_effects(session, pid) == 0
    assert prepare_work(session, [cand], protocol_id=pid, chain_id=1, job_id=job.id) == {}
    assert row.state == "complete"


@requires_postgres
@pytest.mark.parametrize("ready", ["priced_tokens", "empty_inventory", "independent"])
def test_available_or_independent_inputs_create_no_recovery_work(clean_effects, monkeypatch, ready):
    session = clean_effects
    pid, fn, cand = setup_candidate(session, monkeypatch)
    if ready == "priced_tokens":
        cand = replace(cand, input_token_addresses=("0x" + "11" * 20, "0x" + "22" * 20))
    elif ready == "empty_inventory":
        accepted_empty(session, fn.contract_id)
    else:
        monkeypatch.setattr("services.effects.balance_dependencies.needs_token_inventory", lambda *_: False)
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **kw: [cand])
    job = _make_job(session, pid, "existing-inputs")
    seen = []

    def probe(c, ctx):
        seen.append(c.input_token_addresses)
        return unknown(EFFECT_CLASS_SUPPLY, reason="ordinary_unknown")

    worker = EffectsWorker(
        prober=_Prober(probe), hash_resolver=lambda *_: ("ready_kernel", "surface"), seams=_seams(session, job)
    )
    _run(worker, session, job)
    session.commit()
    assert session.query(PendingEffectsWork).filter_by(protocol_id=pid).count() == 0
    assert seen == [cand.input_token_addresses]


@requires_postgres
def test_interrupted_resume_is_bounded_and_never_rearmed(clean_effects, monkeypatch):
    session = clean_effects
    pid, fn, cand = setup_candidate(session, monkeypatch)
    job = _make_job(session, pid, "interrupted-resume")
    rows = prepare_work(session, [cand], protocol_id=pid, chain_id=1, job_id=job.id)
    finish_work(session, rows, job_id=job.id)
    row = rows[(fn.id, EFFECT_CLASS_SUPPLY)]
    accepted_empty(session, fn.contract_id)
    for attempt in range(1, MAX_ATTEMPTS + 1):
        row.next_attempt_at = None
        session.flush()
        assert reconcile_pending_effects(session, pid) == 1
        owner = row.queued_job_id
        assert reconcile_pending_effects(session, pid) == 0
        assert row.queued_job_id == owner
        session.get(Job, owner).status = JobStatus.failed_terminal
        session.flush()
        assert reconcile_pending_effects(session, pid) == 0
        assert row.attempts == attempt
    assert row.state == "degraded"
    accepted_empty(session, fn.contract_id)
    row.next_attempt_at = None
    session.flush()
    assert reconcile_pending_effects(session, pid) == 0


@requires_postgres
def test_proxy_collection_is_owned_by_observed_deployment_and_chain(clean_effects, monkeypatch):
    import uuid

    from db.models import Contract
    from services.effects.balance_dependencies import balance_owners
    from services.effects.selection import select_candidates

    session = clean_effects
    proxy_a, proxy_b = "0x" + uuid.uuid4().hex + "12" * 4, "0x" + uuid.uuid4().hex + "34" * 4
    pid, ids = _protocol_with_functions(session, [CONTRACT_A, proxy_a, proxy_b])
    code = session.get(EffectiveFunction, ids[CONTRACT_A]).contract_id
    functions = [session.get(EffectiveFunction, ids[address]) for address in (proxy_a, proxy_b)]
    holders = [f.contract_id for f in functions]
    for fn, address in zip(functions, (proxy_a, proxy_b)):
        fn.contract_id = code
        fn.deployment_address = address
    session.add(Contract(protocol_id=pid, address=proxy_a, chain="optimism", is_proxy=True))
    candidates = [
        replace(
            _candidate(CONTRACT_A, fn.id, code),
            deployment_address=address,
            restrict_families=frozenset({EFFECT_CLASS_SUPPLY}),
        )
        for fn, address in zip(functions, (proxy_a, proxy_b))
    ]
    monkeypatch.setattr("services.effects.balance_dependencies.needs_token_inventory", lambda *_: True)
    job = _make_job(session, pid, "proxy-collection")
    rows = prepare_work(session, candidates, protocol_id=pid, chain_id=1, job_id=job.id)
    finish_work(session, rows, job_id=job.id)
    fetch = accepted_empty(session, holders[0], proxy_a)
    assert balance_owners(session, pid, 1, [proxy_a, proxy_b]) == {proxy_a: holders[0], proxy_b: holders[1]}
    assert reconcile_pending_effects(session, pid) == 1
    assert rows[(functions[0].id, EFFECT_CLASS_SUPPLY)].state == "queued"
    assert rows[(functions[1].id, EFFECT_CLASS_SUPPLY)].state == "pending"
    token = "0x" + "87" * 20
    fetch.asset_set_status = "returned_assets"
    session.add(
        ContractBalance(
            contract_id=holders[0],
            fetch_id=fetch.id,
            token_address=token,
            raw_balance="100",
            decimals=0,
            price_usd=1,
            usd_value=100,
            observed_address=proxy_a,
            source="etherscan_pages",
        )
    )
    session.flush()
    monkeypatch.setattr(
        "services.effects.selection._cascade_rows",
        lambda *a, **kw: [
            (fn.id, code, CONTRACT_A, fn.selector, "mint", False, address, None, None)
            for fn, address in zip(functions, (proxy_a, proxy_b))
        ],
    )
    for chain in (None, 1):
        selected = {c.function_id: c for c in select_candidates(session, pid, chain_id=chain)}
        assert selected[functions[0].id].input_token_addresses == (token,)
        assert selected[functions[1].id].input_token_addresses == ()


@requires_postgres
def test_regular_collection_dependencies_preserve_audited_cache_hits(clean_effects, monkeypatch):
    from db.models import EffectBehaviorCache
    from tests.support.effects_worker_harness import CONTRACT_B, CONTRACT_C

    session = clean_effects
    pid, ids = _protocol_with_functions(session, [CONTRACT_A, CONTRACT_B, CONTRACT_C])
    candidates = {
        address: replace(
            _candidate(address, fid, session.get(EffectiveFunction, fid).contract_id),
            restrict_families=frozenset({EFFECT_CLASS_SUPPLY}),
        )
        for address, fid in ids.items()
    }
    monkeypatch.setattr("services.effects.balance_dependencies.needs_token_inventory", lambda *_: True)
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **kw: [candidates[kw["scope"].address]])
    jobs = [_make_job(session, pid, "regular-cache", address) for address in ids]
    prober = _Prober(lambda c, ctx: proven(EFFECT_CLASS_SUPPLY, details={"supply_delta_sign": "mint"}))
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda *_: ("shared_kernel", "surface"), seams=_seams(session, jobs[0])
    )
    metrics = None
    for job in jobs:
        _, metrics = _run(worker, session, job)
        session.commit()
    assert prober.runs == [ids[CONTRACT_A], ids[CONTRACT_B]]  # miss, audit, trusted hit
    assert metrics is not None
    assert metrics["cache_hits_kernel"] == 1
    assert session.query(EffectBehaviorCache).one().audit_status == "passed"
    assert session.query(PendingEffectsWork).filter_by(protocol_id=pid, state="complete").count() == 3
