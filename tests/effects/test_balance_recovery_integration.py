"""Real DB coverage for durable prerequisites and effects queue recovery."""

from dataclasses import replace

from sqlalchemy import select

from db.models import ContractBalanceFetch, EffectiveFunction, EffectVerdict, Job, JobStatus
from db.models.balance_work import PendingEffectsWork
from services.effects.balance_dependencies import prepare_work, reconcile_pending_effects
from services.effects.config import EFFECT_CLASS_SUPPLY
from services.effects.harness import proven
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


def accepted_empty(session, cid):
    row = ContractBalanceFetch(
        contract_id=cid,
        chain_id=1,
        observed_address=CONTRACT_A,
        native_status="unattempted",
        asset_set_status="returned_empty",
        asset_set_source="etherscan_pages",
        asset_page_length=0,
        writer="test",
    )
    session.add(row)
    session.flush()
    return row


@requires_postgres
def test_late_balances_resume_same_probe_and_do_not_claim_early_completion(clean_effects, monkeypatch):
    session = clean_effects
    pid, ids = _protocol_with_functions(session, [CONTRACT_A])
    fid = ids[CONTRACT_A]
    fn = session.get(EffectiveFunction, fid)
    cand = replace(_candidate(CONTRACT_A, fid, fn.contract_id), restrict_families=frozenset({EFFECT_CLASS_SUPPLY}))
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **kw: [cand])
    job = _make_job(session, pid, "balance-prerequisite")
    prober = _Prober(
        lambda c, ctx: proven(EFFECT_CLASS_SUPPLY, reason="supply_mint", details={"supply_delta_sign": "mint"})
    )
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda *_: ("balance_kernel", "surface"), seams=_seams(session, job)
    )
    _run(worker, session, job)
    session.commit()
    row = session.scalars(select(PendingEffectsWork).where(PendingEffectsWork.function_id == fid)).one()
    assert row.state == "pending"
    assert prober.runs == []
    assert session.query(EffectVerdict).filter_by(function_id=fid).count() == 0
    assert reconcile_pending_effects(session, pid) == 0
    fetch = accepted_empty(session, fn.contract_id)
    assert reconcile_pending_effects(session, pid) == 1
    session.commit()
    resume = session.get(Job, row.queued_job_id)
    assert resume.request["effects_function_ids"] == [fid]
    _run(worker, session, resume)
    session.commit()
    assert row.state == "complete"
    assert row.consumed_generation == fetch.id
    assert prober.runs == [fid]
    assert session.query(EffectVerdict).filter_by(function_id=fid).count() == 1
    # A fresh accepted observation with unchanged identities is not a new security probe.
    accepted_empty(session, fn.contract_id)
    assert reconcile_pending_effects(session, pid) == 0


@requires_postgres
def test_resource_cap_deferral_is_durable_without_balance_prerequisite(clean_effects):
    session = clean_effects
    pid, ids = _protocol_with_functions(session, [CONTRACT_A])
    fid = ids[CONTRACT_A]
    fn = session.get(EffectiveFunction, fid)
    cand = replace(_candidate(CONTRACT_A, fid, fn.contract_id), restrict_families=frozenset())
    rows, _ = prepare_work(session, [cand], protocol_id=pid, chain_id=1, selected_ids=set())
    session.commit()
    row = rows[(fid, "candidate_selection")]
    assert row.reason == "resource_cap"
    assert reconcile_pending_effects(session, pid) == 1
    session.commit()
    first = row.queued_job_id
    assert reconcile_pending_effects(session, pid) == 0
    assert row.queued_job_id == first
    # Terminal queue failures remain recoverable without relying on a callback.
    session.get(Job, first).status = JobStatus.failed_terminal
    session.flush()
    assert reconcile_pending_effects(session, pid) == 0
    assert row.reason == "resume_job_interrupted"
    assert row.attempts == 1
    row.next_attempt_at = None
    session.flush()
    assert reconcile_pending_effects(session, pid) == 1
    assert row.queued_job_id != first


@requires_postgres
def test_deferred_identities_survive_newer_snapshot_omission(clean_effects):
    session = clean_effects
    pid, ids = _protocol_with_functions(session, [CONTRACT_A])
    fid = ids[CONTRACT_A]
    fn = session.get(EffectiveFunction, fid)
    token = "0x" + "87" * 20
    cand = replace(
        _candidate(CONTRACT_A, fid, fn.contract_id),
        restrict_families=frozenset({EFFECT_CLASS_SUPPLY}),
        input_token_addresses=(token,),
    )
    rows, _ = prepare_work(session, [cand], protocol_id=pid, chain_id=1, selected_ids={fid})
    session.commit()
    row = rows[(fid, EFFECT_CLASS_SUPPLY)]
    assert row.candidate_tokens == [token]
    accepted_empty(session, fn.contract_id)
    # No appearance on a later indexed page is not a negative on this token.
    prepare_work(session, [replace(cand, input_token_addresses=())], protocol_id=pid, chain_id=1, selected_ids={fid})
    session.commit()
    assert row.candidate_tokens == [token]
    assert row.covered_tokens == []


@requires_postgres
def test_legacy_empty_marker_enqueues_without_any_balance(clean_effects):
    session = clean_effects
    pid, ids = _protocol_with_functions(session, [CONTRACT_A])
    fid = ids[CONTRACT_A]
    fn = session.get(EffectiveFunction, fid)
    row = PendingEffectsWork(
        protocol_id=pid,
        chain_id=1,
        deployment_address=CONTRACT_A,
        contract_id=fn.contract_id,
        function_id=fid,
        effect_family="candidate_selection",
        reason="balance_semantics_changed",
        state="pending",
    )
    session.add(row)
    session.flush()
    assert reconcile_pending_effects(session, pid) == 1
    assert session.get(Job, row.queued_job_id).request["effects_function_ids"] == [fid]


@requires_postgres
def test_proxy_generations_are_owned_by_observed_deployment(clean_effects, monkeypatch):
    from db.models import Contract, ContractBalance
    from services.effects.balance_dependencies import balance_owners
    from services.effects.selection import select_candidates

    session = clean_effects
    import uuid

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
    rows, generations = prepare_work(
        session, candidates, protocol_id=pid, chain_id=1, selected_ids={f.id for f in functions}
    )
    assert all(g == 0 for g in generations.values())
    fetch = accepted_empty(session, holders[0])
    fetch.observed_address = proxy_a
    session.flush()
    assert balance_owners(session, pid, 1, [proxy_a, proxy_b]) == {proxy_a: holders[0], proxy_b: holders[1]}
    assert reconcile_pending_effects(session, pid) == 1
    assert rows[(functions[0].id, EFFECT_CLASS_SUPPLY)].state == "queued"
    assert rows[(functions[1].id, EFFECT_CLASS_SUPPLY)].state == "pending"
    _, generations = prepare_work(session, candidates, protocol_id=pid, chain_id=1, selected_ids=set())
    assert generations == {functions[0].id: fetch.id, functions[1].id: 0}
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
def test_degraded_rearms_only_on_required_quantity_or_quality_progress(clean_effects):
    from db.models import ContractBalance
    from services.effects.balance_dependencies import MAX_ATTEMPTS, finish_work

    session = clean_effects
    pid, ids = _protocol_with_functions(session, [CONTRACT_A])
    fid = ids[CONTRACT_A]
    fn = session.get(EffectiveFunction, fid)
    token = "0x" + "87" * 20
    cand = replace(
        _candidate(CONTRACT_A, fid, fn.contract_id),
        restrict_families=frozenset({EFFECT_CLASS_SUPPLY}),
        input_token_addresses=(token,),
    )

    def publish(raw, price=1, status="returned_assets"):
        fetch = accepted_empty(session, fn.contract_id)
        fetch.asset_set_status = status
        session.add(
            ContractBalance(
                contract_id=fn.contract_id,
                fetch_id=fetch.id,
                token_address=token,
                raw_balance=str(raw),
                decimals=18,
                price_usd=price,
                usd_value=price,
                observed_address=CONTRACT_A,
                source="etherscan_pages",
            )
        )
        session.flush()
        return fetch

    fetch = publish(10)
    rows, _ = prepare_work(session, [cand], protocol_id=pid, chain_id=1, selected_ids={fid})
    row = rows[(fid, EFFECT_CLASS_SUPPLY)]
    for _ in range(MAX_ATTEMPTS):
        finish_work(row, generation=fetch.id, tokens=[token], remaining=(), succeeded=False, job_id=None)
    session.flush()
    for _ in range(3):
        latest = publish(10, price=2)
        assert reconcile_pending_effects(session, pid) == 0
        assert row.state == "degraded" and row.attempts == MAX_ATTEMPTS
        assert row.evidence_generation == latest.id
    changed = publish(20)
    assert reconcile_pending_effects(session, pid) == 1
    assert row.state == "queued" and row.attempts == 0
    assert row.required_generation == changed.id
    session.get(Job, row.queued_job_id).status = JobStatus.completed
    row.queued_job_id = None
    # A retained accepted snapshot must not hide progress within a newer prefix.
    prefix = publish(30, status="at_page_cap")
    prepare_work(session, [cand], protocol_id=pid, chain_id=1, selected_ids={fid})
    for _ in range(MAX_ATTEMPTS):
        finish_work(row, generation=prefix.id, tokens=[token], remaining=(), succeeded=False, job_id=None)
    session.flush()
    publish(30, price=3, status="at_page_cap")
    assert reconcile_pending_effects(session, pid) == 0
    publish(40, status="at_page_cap")
    assert reconcile_pending_effects(session, pid) == 1


@requires_postgres
def test_fixed_self_supply_runs_without_etherscan_inventory(clean_effects, monkeypatch):
    from services.effects.calldata.facts import FunctionFacts

    session = clean_effects
    pid, ids = _protocol_with_functions(session, [CONTRACT_A])
    fid = ids[CONTRACT_A]
    fn = session.get(EffectiveFunction, fid)
    cand = replace(
        _candidate(CONTRACT_A, fid, fn.contract_id),
        restrict_families=frozenset({EFFECT_CLASS_SUPPLY}),
        input_token_addresses=tuple("0x" + f"{i:040x}" for i in range(1, 21)),
    )
    facts = FunctionFacts(
        "mint(address,uint256)",
        cand.selector,
        "mint(address,uint256)",
        {},
        None,
        ({"direction": "in", "token_var": "_privateUnderlying"},),
    )
    monkeypatch.setattr("services.effects.calldata.facts.load_contract_facts", lambda *_: object())
    monkeypatch.setattr("services.effects.calldata.facts.resolve_function", lambda *_: facts)
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **kw: [cand])
    job = _make_job(session, pid, "fixed-self-supply")
    prober = _Prober(
        lambda c, ctx: proven(EFFECT_CLASS_SUPPLY, reason="supply_mint", details={"supply_delta_sign": "mint"})
    )
    worker = EffectsWorker(
        prober=prober, hash_resolver=lambda *_: ("fixed_self_kernel", "surface"), seams=_seams(session, job)
    )
    _run(worker, session, job)
    session.commit()
    row = session.scalars(select(PendingEffectsWork).where(PendingEffectsWork.function_id == fid)).one()
    assert row.state == "complete"
    assert row.consumed_generation == 0
    assert row.candidate_tokens == []
    assert row.covered_tokens == []
    assert reconcile_pending_effects(session, pid) == 0
    assert prober.runs == [fid]
    assert session.query(EffectVerdict).filter_by(function_id=fid).count() == 1
    from db.models import ContractBalance

    # Even a fresh unsolicited holding must not rearm independent calldata.
    fetch = accepted_empty(session, fn.contract_id)
    fetch.asset_set_status = "returned_assets"
    session.add(
        ContractBalance(
            contract_id=fn.contract_id,
            fetch_id=fetch.id,
            token_address="0x" + "87" * 20,
            raw_balance="100",
            decimals=0,
            price_usd=1,
            usd_value=100,
            observed_address=CONTRACT_A,
            source="etherscan_pages",
        )
    )
    session.flush()
    assert reconcile_pending_effects(session, pid) == 0
    assert row.state == "complete"


@requires_postgres
def test_independent_planning_failure_is_bounded_without_inventory(clean_effects, monkeypatch):
    from services.effects.calldata.facts import FunctionFacts

    session = clean_effects
    pid, ids = _protocol_with_functions(session, [CONTRACT_A])
    fid = ids[CONTRACT_A]
    fn = session.get(EffectiveFunction, fid)
    cand = replace(_candidate(CONTRACT_A, fid, fn.contract_id), restrict_families=frozenset({EFFECT_CLASS_SUPPLY}))
    facts = FunctionFacts("mint(address,uint256)", cand.selector, "mint(address,uint256)", {}, None, ())
    monkeypatch.setattr("services.effects.calldata.facts.load_contract_facts", lambda *_: object())
    monkeypatch.setattr("services.effects.calldata.facts.resolve_function", lambda *_: facts)
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **kw: [cand])
    job = _make_job(session, pid, "fixed-self-planning-failure")
    worker = EffectsWorker(
        prober=lambda *_: [], hash_resolver=lambda *_: ("fixed_self_kernel", "surface"), seams=_seams(session, job)
    )
    _run(worker, session, job)
    session.commit()
    row = session.scalars(select(PendingEffectsWork).where(PendingEffectsWork.function_id == fid)).one()
    assert row.state == "pending" and row.reason == "planning_incomplete"
    assert row.attempts == 1 and row.next_attempt_at is not None
    row.next_attempt_at = None
    assert reconcile_pending_effects(session, pid) == 1
