"""Cross-contract ``policy_derived`` claims depend only on stored facts, not on which sibling's job ran first."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.models import Contract, EffectiveFunction, Job, JobStage, JobStatus
from db.queue import get_artifact, store_artifact
from services.policy.cross_contract_enrichment import (
    claims_writer_lock_key,
    fetch_sibling_facts,
    lock_contract_claims,
    merge_claims,
    related_jobs_with_facts,
)
from services.static.claims import Claim
from tests.conftest import DATABASE_URL, requires_postgres
from utils import claim_ids as C
from workers.policy_worker import PolicyWorker

pytestmark = requires_postgres

VAULT = "0x83599937000000000000000000000000000000aa"
TELLER = "0xd445c65e000000000000000000000000000000bb"
TOKEN_A = "0x1a00000000000000000000000000000000000001"
TOKEN_B = "0x1b00000000000000000000000000000000000002"
CALLER = "0xca00000000000000000000000000000000000003"

DENY_ALL = "denyAll(address)"
BULK_WITHDRAW = "bulkWithdraw(address,uint256,uint256,address)"
EXIT = "exit(address,address,uint256,address,uint256)"
SWEEP = "sweep(address)"
TRANSFER = "transfer(address,uint256)"


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _std(claim_id: str) -> dict:
    return {"claim_id": claim_id, "tier": "standard_exact", "witness": {}}


def _sink(target: str, signature: str, sid: str = "s0") -> dict:
    return {"id": sid, "kind": "external_call", "target": target, "selector": _selector(signature), "origin": "body"}


def _vault_effects() -> dict:
    return {
        "functions": {
            "setBeforeTransferHook(address)": {
                "selector": _selector("setBeforeTransferHook(address)"),
                "claims": [
                    {
                        "claim_id": C.CALLEE_POINTER_ROTATE,
                        "tier": "idiom_structural",
                        "witness": {"kind": "use_link", "links": [{"pointer": "hook", "invoked_by": "transfer()"}]},
                    }
                ],
            },
            EXIT: {"selector": _selector(EXIT), "claims": [_std("flow.out")]},
        }
    }


def _teller_effects() -> dict:
    return {
        "functions": {
            DENY_ALL: {
                "selector": _selector(DENY_ALL),
                "state_writes": [
                    {
                        "var": "fromDenyList",
                        "declared_type": "mapping(address => bool)",
                        "hygiene_class": "normal",
                        "origin": "body",
                    }
                ],
                "claims": [],
            },
            BULK_WITHDRAW: {"selector": _selector(BULK_WITHDRAW), "sinks": [_sink("vault.exit", EXIT)], "claims": []},
        }
    }


def _snapshot(values: dict[str, str]) -> dict:
    return {"controller_values": {f"state_variable:{var}": {"value": addr} for var, addr in values.items()}}


def _token_effects() -> dict:
    return {"functions": {TRANSFER: {"selector": _selector(TRANSFER), "claims": [_std("flow.out")]}}}


def _caller_effects(sinks: tuple[str, ...] = ("tokenA", "tokenB")) -> dict:
    return {
        "functions": {
            SWEEP: {
                "selector": _selector(SWEEP),
                "sinks": [_sink(f"{var}.transfer", TRANSFER, f"s{i}") for i, var in enumerate(sinks)],
                "claims": [],
            }
        }
    }


class _Pipeline:
    """Drives the stages that matter here: static+resolution store the facts, policy publishes the
    ``effective_permissions`` artifact and rows, then runs the enrichment step.
    """

    def __init__(self, session, company: str | None) -> None:
        self.session = session
        self.company = company

    def job(self, address: str, *, parent: Job | None = None, status: JobStatus = JobStatus.processing) -> Job:
        job = Job(
            id=uuid.uuid4(),
            address=address,
            company=self.company,
            name=address[:10],
            status=status,
            stage=JobStage.static,
            request={"parent_job_id": str(parent.id)} if parent is not None else {},
        )
        self.session.add(job)
        self.session.commit()
        return job

    def land_facts(self, job: Job, effects: dict, snapshot: dict) -> None:
        store_artifact(self.session, job.id, "effects", data=effects)
        store_artifact(self.session, job.id, "control_snapshot", data=snapshot)

    def run_policy(self, job: Job, effects: dict, snapshot: dict) -> None:
        records = [
            {"function": sig, "abi_signature": sig, "selector": _selector(sig), "claims": []}
            for sig in effects["functions"]
        ]
        contract = self.session.query(Contract).filter(Contract.job_id == job.id).one_or_none()
        if contract is None:
            contract = Contract(job_id=job.id, address=job.address, contract_name=job.name)
            self.session.add(contract)
            self.session.flush()
        self.session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).delete()
        for record in records:
            self.session.add(
                EffectiveFunction(
                    contract_id=contract.id,
                    function_name=record["function"].split("(", 1)[0],
                    selector=record["selector"],
                    abi_signature=record["abi_signature"],
                    effect_labels=[],
                    claims=[],
                )
            )
        self.session.commit()
        ep_data = {"functions": records}
        store_artifact(self.session, job.id, "effective_permissions", data=ep_data)
        job.stage = JobStage.policy
        self.session.commit()
        PolicyWorker()._enrich_cross_contract(
            self.session,
            job,
            {},
            snapshot,
            function_records=records,
            ep_data=ep_data,
            target_effects=effects,
        )

    def row_claims(self, job: Job) -> dict[str, list[dict]]:
        self.session.expire_all()
        contract = self.session.query(Contract).filter(Contract.job_id == job.id).one()
        rows = self.session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).all()
        return {row.abi_signature: list(row.claims or []) for row in rows}

    def artifact_claims(self, job: Job) -> dict[str, list[dict]]:
        payload = get_artifact(self.session, job.id, "effective_permissions")
        assert isinstance(payload, dict)
        return {fn["function"]: list(fn.get("claims") or []) for fn in payload["functions"]}


@pytest.fixture
def pipeline(db_session, monkeypatch):
    monkeypatch.setattr(
        "workers.policy_worker.SessionLocal", sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    )

    def _make(company: str | None = None) -> _Pipeline:
        return _Pipeline(db_session, company if company is not None else f"co-{uuid.uuid4()}")

    return _make


def _ids(claims: list[dict]) -> list[tuple[str, str]]:
    return [(c["claim_id"], c["tier"]) for c in claims]


def _run_teller_vault(p: _Pipeline, order: str) -> tuple[dict, dict]:
    # The vault's resolution discovers the teller, so the vault's facts are stored before the teller job exists.
    vault = p.job(VAULT)
    p.land_facts(vault, _vault_effects(), _snapshot({"hook": TELLER}))
    teller = p.job(TELLER, parent=vault)
    p.land_facts(teller, _teller_effects(), _snapshot({"vault": VAULT}))
    if order == "vault_first":
        p.run_policy(vault, _vault_effects(), _snapshot({"hook": TELLER}))
        vault.status = JobStatus.completed
        p.session.commit()
    # In "teller_first" the vault is still mid-pipeline: its policy waits on the teller's.
    p.run_policy(teller, _teller_effects(), _snapshot({"vault": VAULT}))
    if order == "teller_first":
        p.run_policy(vault, _vault_effects(), _snapshot({"hook": TELLER}))
    return p.row_claims(teller), p.artifact_claims(teller)


@pytest.mark.parametrize("order", ["teller_first", "vault_first"])
def test_teller_gets_vault_derived_claims_whichever_job_finishes_first(pipeline, order):
    rows, artifact = _run_teller_vault(pipeline(), order)

    assert _ids(rows[DENY_ALL]) == [(C.TRANSFER_POLICY_CONFIGURE, "policy_derived")]
    assert rows[DENY_ALL][0]["witness"]["configures"] == VAULT
    assert _ids(rows[BULK_WITHDRAW]) == [("flow.out", "policy_derived")]
    assert rows[BULK_WITHDRAW][0]["witness"]["kind"] == "cross_contract_join"
    assert artifact[DENY_ALL] == rows[DENY_ALL]
    assert artifact[BULK_WITHDRAW] == rows[BULK_WITHDRAW]


def test_teller_claims_are_identical_across_orders(pipeline):
    assert _run_teller_vault(pipeline(), "teller_first") == _run_teller_vault(pipeline(), "vault_first")


def _run_company_siblings(
    p: _Pipeline, order: list[str], sinks: tuple[str, ...] = ("tokenA", "tokenB")
) -> tuple[dict, dict]:
    """The caller and two tokens are company siblings with no parent link, landing in ``order``."""
    caller = p.job(CALLER)
    tokens = {"tokenA": (TOKEN_A, p.job(TOKEN_A)), "tokenB": (TOKEN_B, p.job(TOKEN_B))}
    caller_snapshot = _snapshot({"tokenA": TOKEN_A, "tokenB": TOKEN_B})
    for name in order:
        if name == "caller":
            p.land_facts(caller, _caller_effects(sinks), caller_snapshot)
            p.run_policy(caller, _caller_effects(sinks), caller_snapshot)
        else:
            _addr, token = tokens[name]
            p.land_facts(token, _token_effects(), _snapshot({}))
            p.run_policy(token, _token_effects(), _snapshot({}))
    return p.row_claims(caller), p.artifact_claims(caller)


@pytest.mark.parametrize(
    "order",
    [
        ["caller", "tokenA", "tokenB"],
        ["tokenA", "caller", "tokenB"],
        ["tokenB", "tokenA", "caller"],
        ["caller", "tokenB", "tokenA"],
    ],
)
@pytest.mark.parametrize("sinks", [("tokenA", "tokenB"), ("tokenB", "tokenA")])
def test_a_sibling_that_lands_later_reaches_a_job_that_already_ran(pipeline, order, sinks):
    rows, artifact = _run_company_siblings(pipeline(), order, sinks)
    reference_rows, reference_artifact = _run_company_siblings(pipeline(), ["tokenA", "tokenB", "caller"], sinks)

    assert _ids(rows[SWEEP]) == [("flow.out", "policy_derived")]
    # Two callees each prove flow.out; which witness is kept must not depend on arrival or sink order.
    assert rows == reference_rows
    assert artifact == reference_artifact
    assert artifact[SWEEP] == rows[SWEEP]


def test_enrichment_is_idempotent(pipeline, db_session):
    p = pipeline()
    rows, artifact = _run_company_siblings(p, ["caller", "tokenA", "tokenB"])
    caller = db_session.query(Job).filter(Job.company == p.company, Job.address == CALLER).one()
    token_b = db_session.query(Job).filter(Job.company == p.company, Job.address == TOKEN_B).one()
    contract = db_session.query(Contract).filter(Contract.job_id == caller.id).one()
    row_count = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).count()

    worker = PolicyWorker()
    for _ in range(2):
        payload = get_artifact(db_session, caller.id, "effective_permissions")
        assert isinstance(payload, dict)
        worker._enrich_cross_contract(
            db_session,
            caller,
            {},
            _snapshot({"tokenA": TOKEN_A, "tokenB": TOKEN_B}),
            function_records=payload["functions"],
            ep_data=payload,
            target_effects=_caller_effects(),
        )
        worker._enrich_cross_contract(
            db_session, token_b, {}, _snapshot({}), function_records=[], target_effects=_token_effects()
        )

    assert p.row_claims(caller) == rows
    assert p.artifact_claims(caller) == artifact
    assert db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).count() == (
        row_count
    )


def test_a_job_whose_own_pass_has_not_published_is_left_to_that_pass(pipeline, db_session):
    p = pipeline()
    caller = p.job(CALLER)
    caller_snapshot = _snapshot({"tokenA": TOKEN_A, "tokenB": TOKEN_B})
    p.land_facts(caller, _caller_effects(), caller_snapshot)
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    p.run_policy(token, _token_effects(), _snapshot({}))

    assert get_artifact(db_session, caller.id, "effective_permissions") is None
    p.run_policy(caller, _caller_effects(), caller_snapshot)
    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "policy_derived")]


def test_sibling_scope_is_chain_and_relation_bound(pipeline, db_session):
    p = pipeline()
    target = p.job(CALLER)
    same_company = p.job(TOKEN_A)
    other_chain = p.job(TOKEN_B)
    other_chain.chain_id = 8453
    child_elsewhere = pipeline(f"other-{uuid.uuid4()}").job(VAULT, parent=target)
    unrelated = pipeline(f"other-{uuid.uuid4()}").job(TELLER)
    no_facts = p.job("0x" + "ee" * 20)
    same_address = p.job(CALLER)
    stale = p.job(TOKEN_A)
    stale.created_at = same_company.created_at - timedelta(days=1)
    db_session.commit()
    for job in (stale, same_company, other_chain, child_elsewhere, unrelated, same_address):
        p.land_facts(job, _token_effects(), _snapshot({}))
    store_artifact(db_session, no_facts.id, "effects", data=_token_effects())

    related = related_jobs_with_facts(db_session, target, chain_id=1)

    # ``stale`` shares TOKEN_A with the newer ``same_company`` job; only the newest job per address is read.
    assert {job_id for job_id, _ in related} == {same_company.id, child_elsewhere.id}


def test_sibling_scope_follows_the_parent_link_without_a_company(pipeline, db_session):
    p = pipeline(f"other-{uuid.uuid4()}")
    parent = p.job(VAULT)
    child = pipeline(f"other-{uuid.uuid4()}").job(TELLER, parent=parent)
    sibling = pipeline(f"other-{uuid.uuid4()}").job(TOKEN_A, parent=parent)
    for job in (parent, child, sibling):
        p.land_facts(job, _token_effects(), _snapshot({}))

    assert {job_id for job_id, _ in related_jobs_with_facts(db_session, child, chain_id=1)} == {parent.id, sibling.id}
    assert {job_id for job_id, _ in related_jobs_with_facts(db_session, parent, chain_id=1)} == {child.id, sibling.id}


def test_provenance_runs_without_siblings(pipeline, db_session):
    p = pipeline()
    upgrade = "upgradeTo(address)"
    effects = {"functions": {upgrade: {"selector": _selector(upgrade), "claims": []}}}
    job = p.job(CALLER)
    p.land_facts(job, effects, _snapshot({}))
    store_artifact(
        db_session,
        job.id,
        "classifications",
        data={
            "classifications": {
                CALLER: {"type": "proxy", "proxy_type": "eip1967", "implementation": TOKEN_A},
            }
        },
    )
    p.run_policy(job, effects, _snapshot({}))

    claims = p.row_claims(job)[upgrade]
    assert _ids(claims) == [(C.UPGRADE_IMPLEMENTATION, "policy_derived")]
    assert claims[0]["witness"]["kind"] == "proxy_provenance"


def test_dependent_pass_refreshes_score_signals_when_effects_distil(pipeline, db_session, monkeypatch):
    from db.models import Protocol
    from services.scoring import dirty

    protocol = Protocol(name=f"proto-{uuid.uuid4()}")
    db_session.add(protocol)
    db_session.commit()
    p = pipeline()
    caller = p.job(CALLER)
    caller.protocol_id = protocol.id
    db_session.commit()
    caller_snapshot = _snapshot({"tokenA": TOKEN_A, "tokenB": TOKEN_B})
    p.land_facts(caller, _caller_effects(), caller_snapshot)
    p.run_policy(caller, _caller_effects(), caller_snapshot)

    distilled: list[Any] = []
    marks: list[tuple[Any, str]] = []

    def _distill(session, job):
        distilled.append((job.id, [c["claim_id"] for row in p.row_claims(job).values() for c in row]))
        return {}

    monkeypatch.setenv("PSAT_EFFECTS_STAGE", "1")
    monkeypatch.setattr("services.scoring.distill.distill_job_signals", _distill)
    monkeypatch.setattr(dirty, "mark_protocol_score_dirty", lambda s, pid, reason: marks.append((pid, reason)))

    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    p.run_policy(token, _token_effects(), _snapshot({}))

    assert distilled == [(caller.id, ["flow.out"])]
    assert marks == [(protocol.id, dirty.SCORE_DIRTY_CROSS_CONTRACT)]


def test_claims_writer_lock_excludes_other_writers(db_session):
    contract_id = 424242
    lock_contract_claims(db_session, [contract_id])
    other = create_engine(DATABASE_URL)
    try:
        with other.connect() as conn:
            acquired = conn.execute(
                text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": claims_writer_lock_key(contract_id)}
            ).scalar()
            assert acquired is False
            db_session.commit()
            acquired = conn.execute(
                text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": claims_writer_lock_key(contract_id)}
            ).scalar()
            assert acquired is True
    finally:
        other.dispose()


def test_merge_tie_break_is_order_independent():
    a = Claim(claim_id="flow.out", tier="policy_derived", witness={"callee": TOKEN_A})
    b = Claim(claim_id="flow.out", tier="policy_derived", witness={"callee": TOKEN_B})
    exact = Claim(claim_id="flow.out", tier="standard_exact", witness={})

    assert merge_claims([a], [b]) == merge_claims([b], [a])
    assert merge_claims(merge_claims([], [b]), [a]) == merge_claims(merge_claims([], [a]), [b])
    assert merge_claims([exact], [a, b]) == [exact]


def test_dependent_pass_derives_from_the_target_s_facts_as_stored_under_the_lock(pipeline, db_session, monkeypatch):
    p = pipeline()
    caller = p.job(CALLER)
    wired = _snapshot({"tokenA": TOKEN_A, "tokenB": TOKEN_B})
    p.land_facts(caller, _caller_effects(), wired)
    p.run_policy(caller, _caller_effects(), wired)
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    other_session = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)

    def _fetch_then_rewire(targets, *, session_factory):
        facts = fetch_sibling_facts(targets, session_factory=session_factory)
        # A re-analysis rewires the caller after the token's pass fetched its facts.
        with other_session() as s:
            store_artifact(s, caller.id, "control_snapshot", data=_snapshot({"tokenA": "0x" + "de" * 20}))
        return facts

    monkeypatch.setattr("workers.policy_worker.fetch_sibling_facts", _fetch_then_rewire)
    p.run_policy(token, _token_effects(), _snapshot({}))

    assert p.row_claims(caller)[SWEEP] == []
    assert p.artifact_claims(caller)[SWEEP] == []


def test_effects_bridge_takes_the_claims_lock_and_rereads_rows(pipeline, db_session):
    from workers.effects_worker import EffectsWorker

    p = pipeline()
    job = p.job(CALLER)
    p.land_facts(job, _caller_effects(), _snapshot({}))
    p.run_policy(job, _caller_effects(), _snapshot({}))
    contract = db_session.query(Contract).filter(Contract.job_id == job.id).one()
    row = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).one()
    assert row.claims == []
    db_session.commit()

    other = create_engine(DATABASE_URL)
    try:
        with other.begin() as conn:
            conn.execute(
                text("UPDATE effective_functions SET claims = CAST(:c AS jsonb) WHERE id = :id"),
                {"c": '[{"claim_id": "flow.out", "tier": "policy_derived", "witness": {}}]', "id": row.id},
            )
        EffectsWorker()._lock_claim_writers(db_session, job, function_ids=[row.id])
        with other.connect() as conn:
            acquired = conn.execute(
                text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": claims_writer_lock_key(contract.id)}
            ).scalar()
        assert acquired is False
        assert [c["claim_id"] for c in row.claims] == ["flow.out"]
    finally:
        db_session.rollback()
        other.dispose()


def test_sibling_scope_prefers_the_job_that_owns_the_contract_row(pipeline, db_session):
    p = pipeline()
    target = p.job(CALLER)
    owner = p.job(TOKEN_A)
    newer = p.job(TOKEN_A)
    db_session.add(Contract(job_id=owner.id, address=TOKEN_A, contract_name="Token"))
    db_session.commit()
    for job in (owner, newer):
        p.land_facts(job, _token_effects(), _snapshot({}))

    assert related_jobs_with_facts(db_session, target, chain_id=1) == [(owner.id, TOKEN_A)]


def test_own_pass_keeps_a_dependent_contribution_whose_sibling_it_could_not_fetch(pipeline, db_session, monkeypatch):
    p = pipeline()
    rows, artifact = _run_company_siblings(p, ["caller", "tokenA", "tokenB"])
    caller = db_session.query(Job).filter(Job.company == p.company, Job.address == CALLER).one()
    token_a = db_session.query(Job).filter(Job.company == p.company, Job.address == TOKEN_A).one()
    assert rows[SWEEP][0]["witness"]["callee"] == TOKEN_A

    def _drop_token_a(targets, *, session_factory):
        return fetch_sibling_facts([t for t in targets if t[0] != token_a.id], session_factory=session_factory)

    monkeypatch.setattr("workers.policy_worker.fetch_sibling_facts", _drop_token_a)
    payload = get_artifact(db_session, caller.id, "effective_permissions")
    assert isinstance(payload, dict)
    fresh = {"functions": [{**fn, "claims": []} for fn in payload["functions"]]}
    PolicyWorker()._enrich_cross_contract(
        db_session,
        caller,
        {},
        _snapshot({"tokenA": TOKEN_A, "tokenB": TOKEN_B}),
        function_records=fresh["functions"],
        ep_data=fresh,
        target_effects=_caller_effects(),
    )

    assert p.artifact_claims(caller) == artifact
    assert p.row_claims(caller) == rows
