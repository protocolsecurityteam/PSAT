"""Cross-contract ``policy_derived`` claims, and the stages that consume them, depend only on stored facts, not on
which sibling's job ran first.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import func, select, update
from sqlalchemy.orm import sessionmaker

from db.models import Contract, ControllerValue, EffectiveFunction, IndexerWork, Job, JobStage, JobStatus, Protocol
from db.queue import get_artifact, store_artifact
from services.policy.cross_contract_enrichment import (
    fetch_sibling_facts,
    mark_stale_dependents,
    merge_claims,
    related_jobs_with_facts,
)
from services.policy.effective_permissions_writer import write_effective_function_rows
from services.policy.stale_policy import (
    STALE_POLICY_KIND,
    mark_policy_stale,
    refresh_stale_policy,
)
from services.resolution.indexer_work import WorkPending
from services.static.claims import Claim
from tests.conftest import requires_postgres
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


def _token_effects(*, proves_flow: bool = True) -> dict:
    return {
        "functions": {TRANSFER: {"selector": _selector(TRANSFER), "claims": [_std("flow.out")] if proves_flow else []}}
    }


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
    """Drives the stages that matter here: static+resolution store the facts and run the staleness check; policy
    rewrites the rows with the production writer, publishes ``effective_permissions`` and runs the cross-contract
    step; completion ends the job. ``settle`` plays the reconciliation drain, re-running every job marked stale until
    none is.
    """

    def __init__(self, session, company: str | None, protocol_id: int | None) -> None:
        self.session = session
        self.session_factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
        self.company = company
        self.protocol_id = protocol_id
        self.facts: dict[Any, tuple[dict, dict]] = {}
        self.policy_runs: dict[Any, int] = {}

    def job(self, address: str, *, parent: Job | None = None) -> Job:
        job = Job(
            id=uuid.uuid4(),
            address=address,
            company=self.company,
            protocol_id=self.protocol_id,
            name=address[:10],
            status=JobStatus.processing,
            stage=JobStage.static,
            request={"parent_job_id": str(parent.id)} if parent is not None else {},
        )
        self.session.add(job)
        self.session.commit()
        return job

    def land_facts(self, job: Job, effects: dict, snapshot: dict) -> None:
        """Discovery creates the address's contract row (one per address); static stores ``effects``; resolution
        stores ``control_snapshot``, rewrites the owner's controller values and runs the staleness check.
        """
        replaced = job.id in self.facts
        self.facts[job.id] = (effects, snapshot)
        contract = self.session.query(Contract).filter(Contract.job_id == job.id).one_or_none()
        if contract is None and self.session.query(Contract).filter(Contract.address == job.address).first() is None:
            contract = Contract(job_id=job.id, address=job.address, contract_name=job.name)
            self.session.add(contract)
            self.session.flush()
        store_artifact(self.session, job.id, "effects", data=effects)
        store_artifact(self.session, job.id, "control_snapshot", data=snapshot)
        if contract is not None:
            self.session.query(ControllerValue).filter(ControllerValue.contract_id == contract.id).delete()
            for controller_id, value in snapshot["controller_values"].items():
                self.session.add(
                    ControllerValue(contract_id=contract.id, controller_id=controller_id, value=value["value"])
                )
            self.session.commit()
        mark_stale_dependents(
            self.session, job, chain_id=1, session_factory=self.session_factory, replaced_facts=replaced
        )

    def run_policy(self, job: Job) -> None:
        effects, snapshot = self.facts[job.id]
        records = [
            {"function": sig, "abi_signature": sig, "selector": _selector(sig), "claims": [], "effect_labels": []}
            for sig in effects["functions"]
        ]
        contract = self.session.query(Contract).filter(Contract.job_id == job.id).one_or_none()
        if contract is None:
            contract = Contract(job_id=job.id, address=job.address, contract_name=job.name)
            self.session.add(contract)
            self.session.flush()
        write_effective_function_rows(
            self.session, contract_id=contract.id, function_records=records, capability_by_function={}
        )
        job.stage = JobStage.policy
        job.status = JobStatus.processing
        self.session.commit()
        ep_data = {"functions": records}
        store_artifact(self.session, job.id, "effective_permissions", data=ep_data)
        PolicyWorker()._enrich_cross_contract(
            self.session,
            job,
            {},
            snapshot,
            function_records=records,
            ep_data=ep_data,
            target_effects=effects,
        )
        self.policy_runs[job.id] = self.policy_runs.get(job.id, 0) + 1

    def complete(self, job: Job) -> None:
        job.stage = JobStage.done
        job.status = JobStatus.completed
        self.session.commit()

    def run(self, job: Job) -> None:
        self.run_policy(job)
        self.complete(job)

    def stale(self) -> set[str]:
        self.session.expire_all()
        return set(
            self.session.execute(
                select(IndexerWork.key).where(IndexerWork.kind == STALE_POLICY_KIND, IndexerWork.dirty.is_(True))
            ).scalars()
        )

    def settle(self) -> None:
        for _ in range(5):
            keys = self.stale()
            if not keys:
                return
            for key in sorted(keys):
                job = self.session.get(Job, uuid.UUID(key))
                assert job is not None
                assert refresh_stale_policy(self.session, job.id) == 1
                self.session.commit()
                assert (job.stage, job.status) == (JobStage.policy, JobStatus.queued)
                self.run(job)
        raise AssertionError("stale marks did not converge")

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

    def _make(company: str | None = None, *, protocol: bool = False) -> _Pipeline:
        protocol_id = None
        if protocol:
            row = Protocol(name=f"proto-{uuid.uuid4()}")
            db_session.add(row)
            db_session.commit()
            protocol_id = row.id
        return _Pipeline(db_session, company if company is not None else f"co-{uuid.uuid4()}", protocol_id)

    return _make


def _ids(claims: list[dict]) -> list[tuple[str, str]]:
    return [(c["claim_id"], c["tier"]) for c in claims]


def _run_teller_vault(p: _Pipeline, order: str) -> tuple[dict, dict]:
    # The vault's resolution discovers the teller, so the vault's facts are stored before the teller job exists.
    vault = p.job(VAULT)
    p.land_facts(vault, _vault_effects(), _snapshot({"hook": TELLER}))
    teller = p.job(TELLER, parent=vault)
    p.land_facts(teller, _teller_effects(), _snapshot({"vault": VAULT}))
    # The vault's policy normally waits on the teller's (an authority edge); both orders must agree.
    first, second = (vault, teller) if order == "vault_first" else (teller, vault)
    p.run(first)
    p.run(second)
    p.settle()
    return p.row_claims(teller), p.artifact_claims(teller)


@pytest.mark.parametrize("order", ["teller_first", "vault_first"])
def test_teller_gets_vault_derived_claims_whichever_job_finishes_first(pipeline, order):
    p = pipeline()
    rows, artifact = _run_teller_vault(p, order)

    assert _ids(rows[DENY_ALL]) == [(C.TRANSFER_POLICY_CONFIGURE, "policy_derived")]
    assert rows[DENY_ALL][0]["witness"]["configures"] == VAULT
    assert _ids(rows[BULK_WITHDRAW]) == [("flow.out", "policy_derived")]
    assert rows[BULK_WITHDRAW][0]["witness"]["kind"] == "cross_contract_join"
    assert artifact[DENY_ALL] == rows[DENY_ALL]
    assert artifact[BULK_WITHDRAW] == rows[BULK_WITHDRAW]
    # The vault's facts precede the teller's policy in both orders, so nothing re-runs.
    assert set(p.policy_runs.values()) == {1}


def test_teller_claims_are_identical_across_orders(pipeline):
    assert _run_teller_vault(pipeline(), "teller_first") == _run_teller_vault(pipeline(), "vault_first")


def _run_siblings(p: _Pipeline, order: list[str], sinks: tuple[str, ...] = ("tokenA", "tokenB")) -> tuple[dict, dict]:
    """The caller and two tokens are siblings with no parent link; each lands its facts and runs policy in ``order``."""
    caller = p.job(CALLER)
    jobs = {"caller": caller, "tokenA": p.job(TOKEN_A), "tokenB": p.job(TOKEN_B)}
    for name in order:
        if name == "caller":
            p.land_facts(caller, _caller_effects(sinks), _snapshot({"tokenA": TOKEN_A, "tokenB": TOKEN_B}))
        else:
            p.land_facts(jobs[name], _token_effects(), _snapshot({}))
        p.run(jobs[name])
    p.settle()
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
def test_a_sibling_that_lands_later_re_runs_the_job_that_already_ran(pipeline, order, sinks):
    p = pipeline()
    rows, artifact = _run_siblings(p, order, sinks)
    reference_rows, reference_artifact = _run_siblings(pipeline(), ["tokenA", "tokenB", "caller"], sinks)

    assert _ids(rows[SWEEP]) == [("flow.out", "policy_derived")]
    # Two callees each prove flow.out; which witness is kept must not depend on arrival or sink order.
    assert rows == reference_rows
    assert artifact == reference_artifact
    assert p.stale() == set()
    caller = p.session.query(Job).filter(Job.company == p.company, Job.address == CALLER).one()
    # Its own pass, plus at most one re-run when a later sibling's facts change its claims; a later sibling whose
    # claim loses the tie to the one already held changes nothing.
    assert p.policy_runs[caller.id] <= 2
    if order[0] == "caller":
        assert p.policy_runs[caller.id] == 2


def test_a_contribution_already_held_marks_nothing(pipeline):
    p = pipeline()
    _run_siblings(p, ["tokenA", "tokenB", "caller"])
    token_a = p.session.query(Job).filter(Job.company == p.company, Job.address == TOKEN_A).one()

    p.land_facts(token_a, *p.facts[token_a.id])

    assert p.stale() == set()


def test_a_sibling_whose_policy_never_runs_still_reaches_the_job_that_ran(pipeline):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    # The token's facts are stored and its policy then fails for good.
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    token.status = JobStatus.failed_terminal
    p.session.commit()

    p.settle()

    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "policy_derived")]


def test_a_sibling_whose_facts_no_longer_derive_a_claim_retracts_it(pipeline):
    p = pipeline()
    caller = p.job(CALLER)
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    p.run(token)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "policy_derived")]

    # A re-analysis of the token stores facts that no longer prove a flow.
    p.land_facts(token, _token_effects(proves_flow=False), _snapshot({}))
    assert p.stale() == {str(caller.id)}
    p.settle()

    assert p.row_claims(caller)[SWEEP] == []
    assert p.artifact_claims(caller)[SWEEP] == []


def test_an_observation_superseding_a_derived_claim_marks_nothing(pipeline):
    p = pipeline()
    rows, _ = _run_siblings(p, ["tokenA", "tokenB", "caller"])
    caller = p.session.query(Job).filter(Job.company == p.company, Job.address == CALLER).one()
    token_a = p.session.query(Job).filter(Job.company == p.company, Job.address == TOKEN_A).one()
    contract = p.session.query(Contract).filter(Contract.job_id == caller.id).one()
    row = p.session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).one()
    observed = Claim(claim_id="flow.out", tier="behavioral_observed", witness={"effect_verdict_id": 1})
    row.claims = merge_claims(row.claims, [observed])
    p.session.commit()
    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "behavioral_observed")]

    p.land_facts(token_a, *p.facts[token_a.id])

    assert p.stale() == set()


def test_a_job_that_has_not_published_is_left_to_its_own_pass(pipeline, db_session):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(), _snapshot({"tokenA": TOKEN_A, "tokenB": TOKEN_B}))
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    p.run(token)

    assert get_artifact(db_session, caller.id, "effective_permissions") is None
    assert p.stale() == set()
    p.run(caller)
    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "policy_derived")]


def test_the_own_pass_clears_a_mark_set_before_it_read(pipeline):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(), _snapshot({"tokenA": TOKEN_A, "tokenB": TOKEN_B}))
    mark_policy_stale(p.session, caller.id)
    p.session.commit()
    assert p.stale() == {str(caller.id)}

    p.run(caller)

    assert p.stale() == set()


def test_facts_landing_after_the_own_pass_read_keep_the_mark(pipeline, monkeypatch):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    token = p.job(TOKEN_A)

    def _read_then_land(targets, *, session_factory):
        facts = fetch_sibling_facts(targets, session_factory=session_factory)
        p.land_facts(token, _token_effects(), _snapshot({}))
        return facts

    monkeypatch.setattr("workers.policy_worker.fetch_sibling_facts", _read_then_land)
    p.run_policy(caller)
    monkeypatch.setattr("workers.policy_worker.fetch_sibling_facts", fetch_sibling_facts)
    p.complete(caller)

    assert p.row_claims(caller)[SWEEP] == []
    assert p.stale() == {str(caller.id)}
    p.settle()
    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "policy_derived")]


def _unreadable_for(job_id: Any, exc: BaseException):
    def _get(session, target_id, name):
        if target_id == job_id:
            raise exc
        return get_artifact(session, target_id, name)

    return _get


def test_sibling_facts_not_yet_read_fail_the_own_pass_for_a_retry(pipeline, monkeypatch):
    from db.storage import StorageUnavailable
    from workers.retry_policy import classify

    p = pipeline()
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))

    monkeypatch.setattr(
        "services.policy.cross_contract_enrichment.get_artifact",
        _unreadable_for(token.id, StorageUnavailable("storage unavailable")),
    )
    with pytest.raises(StorageUnavailable) as raised:
        p.run_policy(caller)
    assert classify(raised.value) == "transient"


def test_sibling_facts_proven_absent_are_left_out(pipeline, monkeypatch):
    from db.storage import StorageKeyMissing

    p = pipeline()
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))

    monkeypatch.setattr(
        "services.policy.cross_contract_enrichment.get_artifact",
        _unreadable_for(token.id, StorageKeyMissing("gone")),
    )
    p.run(caller)

    assert p.row_claims(caller)[SWEEP] == []


def test_a_retraction_landing_during_the_own_pass_write_is_not_lost(pipeline, monkeypatch):
    p = pipeline()
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    p.run(token)
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "policy_derived")]

    def _read_then_retract(targets, *, session_factory):
        facts = fetch_sibling_facts(targets, session_factory=session_factory)
        p.land_facts(token, _token_effects(proves_flow=False), _snapshot({}))
        return facts

    monkeypatch.setattr("workers.policy_worker.fetch_sibling_facts", _read_then_retract)
    p.run_policy(caller)
    monkeypatch.setattr("workers.policy_worker.fetch_sibling_facts", fetch_sibling_facts)
    p.complete(caller)

    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "policy_derived")]
    assert p.stale() == {str(caller.id)}
    p.settle()
    assert p.row_claims(caller)[SWEEP] == []


def test_a_failed_check_marks_every_published_sibling(pipeline, monkeypatch):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    other = p.job(TOKEN_B)
    p.land_facts(other, _token_effects(), _snapshot({}))
    p.run(other)
    unpublished = p.job(VAULT)
    p.land_facts(unpublished, _token_effects(), _snapshot({}))
    p.session.query(IndexerWork).delete()
    p.session.commit()

    def _boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr("services.policy.cross_contract_enrichment._mark_stale_dependents", _boom)
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))

    assert p.stale() == {str(caller.id), str(other.id)}


def test_a_first_analysis_marks_no_sibling_mid_policy_for_an_unrelated_prior_job(pipeline):
    p = pipeline()
    pipeline().land_facts(pipeline().job(TOKEN_B), _token_effects(), _snapshot({}))
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    caller.stage = JobStage.policy
    p.session.commit()

    p.land_facts(p.job(TOKEN_B), _token_effects(), _snapshot({}))

    assert p.stale() == set()


def test_a_contract_row_owned_in_another_protocol_does_not_silence_the_sibling_s_holder(pipeline):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    elsewhere = pipeline()
    foreign = elsewhere.job(TOKEN_A)
    elsewhere.land_facts(foreign, _token_effects(), _snapshot({}))
    elsewhere.run(foreign)
    token = p.job(TOKEN_A)

    p.land_facts(token, _token_effects(), _snapshot({}))

    assert p.stale() == {str(caller.id)}
    p.settle()
    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "policy_derived")]


def test_a_sibling_the_check_cannot_read_or_judge_is_marked(pipeline, monkeypatch):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    token = p.job(TOKEN_A)

    def _boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr("services.policy.cross_contract_enrichment.contribution_is_stale", _boom)
    p.land_facts(token, _token_effects(), _snapshot({}))
    assert p.stale() == {str(caller.id)}

    p.session.query(IndexerWork).delete()
    p.session.commit()
    monkeypatch.setattr(
        "services.policy.cross_contract_enrichment.get_artifact", _unreadable_for(caller.id, OSError("unreachable"))
    )
    mark_stale_dependents(p.session, token, chain_id=1, session_factory=p.session_factory)
    assert p.stale() == {str(caller.id)}


def test_only_the_job_whose_facts_are_read_marks_siblings(pipeline):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    owner = p.job(TOKEN_A)
    p.land_facts(owner, _token_effects(proves_flow=False), _snapshot({}))
    p.run(owner)
    # The owner's facts answer the caller's gap on TOKEN_A.
    p.settle()
    # Another job for the same address (another deployment's context) holds different facts, but siblings read the
    # owner's.
    other = p.job(TOKEN_A)

    p.land_facts(other, _token_effects(), _snapshot({}))

    assert p.stale() == set()


def test_sibling_scope_includes_the_protocol_without_a_company(pipeline, db_session):
    p = pipeline(protocol=True)
    target = p.job(CALLER)
    companyless = p.job(TOKEN_A)
    companyless.company = None
    elsewhere = pipeline(protocol=True).job(TOKEN_B)
    db_session.commit()
    for job in (companyless, elsewhere):
        p.land_facts(job, _token_effects(), _snapshot({}))

    assert related_jobs_with_facts(db_session, target, chain_id=1) == [(companyless.id, TOKEN_A)]


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
    recovery = p.job("0x" + "dd" * 20)
    recovery.request = {"effects_resume_work_id": 7}
    stale = p.job(TOKEN_A)
    stale.created_at = same_company.created_at - timedelta(days=1)
    db_session.commit()
    for job in (stale, same_company, other_chain, child_elsewhere, unrelated, same_address, recovery):
        p.land_facts(job, _token_effects(), _snapshot({}))
    store_artifact(db_session, no_facts.id, "effects", data=_token_effects())
    # No job owns a contract row, so the newest job per address holds its facts.
    db_session.query(Contract).delete()
    db_session.commit()

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
        data={"classifications": {CALLER: {"type": "proxy", "proxy_type": "eip1967", "implementation": TOKEN_A}}},
    )
    p.run(job)

    claims = p.row_claims(job)[upgrade]
    assert _ids(claims) == [(C.UPGRADE_IMPLEMENTATION, "policy_derived")]
    assert claims[0]["witness"]["kind"] == "proxy_provenance"


def test_merge_tie_break_is_order_independent():
    a = Claim(claim_id="flow.out", tier="policy_derived", witness={"callee": TOKEN_A})
    b = Claim(claim_id="flow.out", tier="policy_derived", witness={"callee": TOKEN_B})
    exact = Claim(claim_id="flow.out", tier="standard_exact", witness={})

    assert merge_claims([a], [b]) == merge_claims([b], [a])
    assert merge_claims(merge_claims([], [b]), [a]) == merge_claims(merge_claims([], [a]), [b])
    assert merge_claims([exact], [a, b]) == [exact]


def _completed_job(p: _Pipeline, address: str = CALLER) -> Job:
    job = p.job(address)
    p.land_facts(job, _token_effects(), _snapshot({}))
    p.run(job)
    return job


def test_refresh_waits_for_an_in_flight_job(pipeline):
    p = pipeline()
    job = _completed_job(p)
    job.status = JobStatus.processing
    job.stage = JobStage.effects
    p.session.commit()

    with pytest.raises(WorkPending):
        refresh_stale_policy(p.session, job.id)


def test_refresh_waits_while_another_job_holds_the_address(pipeline):
    p = pipeline()
    job = _completed_job(p)
    p.job(CALLER)

    with pytest.raises(WorkPending):
        refresh_stale_policy(p.session, job.id)


def test_refresh_drops_a_failed_or_superseded_job(pipeline):
    p = pipeline()
    failed = _completed_job(p)
    failed.status = JobStatus.failed_terminal
    superseded = _completed_job(p, TOKEN_A)
    p.session.query(Contract).filter(Contract.job_id == superseded.id).update({Contract.job_id: None})
    p.session.commit()

    assert refresh_stale_policy(p.session, failed.id) == 0
    assert refresh_stale_policy(p.session, superseded.id) == 0
    assert refresh_stale_policy(p.session, uuid.uuid4()) == 0


def test_the_reconciliation_drain_re_queues_a_stale_job_once_it_completes(pipeline):
    from services.resolution import indexer_scheduler as scheduler

    p = pipeline()
    job = _completed_job(p)
    job.status = JobStatus.processing
    p.session.commit()
    mark_policy_stale(p.session, job.id)
    p.session.commit()

    scheduler.drain_reconciliation(p.session)
    p.session.expire_all()
    assert p.session.get(Job, job.id).status == JobStatus.processing
    assert p.stale() == {str(job.id)}

    p.complete(job)
    p.session.execute(update(IndexerWork).values(available_at=func.now()))
    p.session.commit()
    scheduler.drain_reconciliation(p.session)
    p.session.expire_all()

    refreshed = p.session.get(Job, job.id)
    assert (refreshed.stage, refreshed.status) == (JobStage.policy, JobStatus.queued)
    assert p.stale() == set()


def test_refresh_waits_for_a_disabled_chain(pipeline, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    p = pipeline()
    job = _completed_job(p)
    job.chain_id = 8453
    p.session.commit()

    with pytest.raises(WorkPending):
        refresh_stale_policy(p.session, job.id)


def test_an_ambiguous_row_is_judged_as_the_own_pass_writes_it(pipeline):
    """The own pass skips a function matching several rows, so the check must not call it stale either."""
    p = pipeline()
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    contract = p.session.query(Contract).filter(Contract.job_id == caller.id).one()
    p.session.add(
        EffectiveFunction(
            contract_id=contract.id,
            function_name="sweep",
            selector=_selector(SWEEP),
            abi_signature=SWEEP,
            effect_labels=[],
            claims=[],
        )
    )
    p.session.commit()

    p.land_facts(token, *p.facts[token.id])

    assert p.stale() == set()


def _gaps(p: _Pipeline, job: Job) -> dict[str, Any]:
    p.session.expire_all()
    contract = p.session.query(Contract).filter(Contract.job_id == job.id).one()
    rows = p.session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).all()
    return {row.abi_signature: row.cross_contract_gaps for row in rows}


def _artifact_gaps(p: _Pipeline, job: Job) -> dict[str, Any]:
    payload = get_artifact(p.session, job.id, "effective_permissions")
    assert isinstance(payload, dict)
    return {fn["function"]: fn.get("cross_contract_gaps") for fn in payload["functions"]}


def test_a_call_into_a_callee_without_facts_is_recorded_as_not_determined(pipeline):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)

    gap = {
        "sink_id": "s0",
        "selector": _selector(TRANSFER),
        "callee": TOKEN_A,
        "reason": "not_analyzed",
        "callee_job_id": None,
    }
    assert p.row_claims(caller)[SWEEP] == []
    assert _gaps(p, caller) == {SWEEP: [gap]}
    assert _artifact_gaps(p, caller) == {SWEEP: [gap]}


@pytest.mark.parametrize(
    ("callee_state", "reason"),
    [
        ("pending", "analysis_pending"),
        ("failed", "analysis_failed"),
        ("no_facts", "facts_not_stored"),
        ("other_scope", "outside_sibling_scope"),
    ],
)
def test_a_gap_names_why_the_callee_had_no_facts(pipeline, callee_state, reason):
    p = pipeline()
    callee = (pipeline() if callee_state == "other_scope" else p).job(TOKEN_A)
    if callee_state == "failed":
        callee.status = JobStatus.failed_terminal
    elif callee_state == "no_facts":
        callee.status = JobStatus.completed
    elif callee_state == "other_scope":
        store_artifact(p.session, callee.id, "effects", data=_token_effects())
        store_artifact(p.session, callee.id, "control_snapshot", data=_snapshot({}))
    p.session.commit()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)

    [gap] = _gaps(p, caller)[SWEEP]
    assert (gap["reason"], gap["callee_job_id"]) == (reason, str(callee.id))


def test_proven_absent_callee_facts_are_a_gap(pipeline, monkeypatch):
    from db.storage import StorageKeyMissing

    p = pipeline()
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    monkeypatch.setattr(
        "services.policy.cross_contract_enrichment.get_artifact", _unreadable_for(token.id, StorageKeyMissing("gone"))
    )
    p.run(caller)

    [gap] = _gaps(p, caller)[SWEEP]
    assert (gap["reason"], gap["callee_job_id"]) == ("facts_unreadable", str(token.id))


@pytest.mark.parametrize("proves_flow", [True, False])
def test_a_gap_heals_when_the_callee_s_facts_land(pipeline, proves_flow):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    assert _gaps(p, caller)[SWEEP]
    token = p.job(TOKEN_A)

    p.land_facts(token, _token_effects(proves_flow=proves_flow), _snapshot({}))
    assert p.stale() == {str(caller.id)}
    p.settle()

    # Determined either way: a derived claim, or a proven absence of one.
    assert _gaps(p, caller) == {SWEEP: []}
    assert _ids(p.row_claims(caller)[SWEEP]) == ([("flow.out", "policy_derived")] if proves_flow else [])
    assert _artifact_gaps(p, caller) == {SWEEP: []}


def test_rows_without_unresolved_calls_are_evaluated_empty(pipeline):
    p = pipeline()
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    p.run(token)

    assert _gaps(p, token) == {TRANSFER: []}


def test_no_gap_for_a_burn_address_or_a_self_call(pipeline):
    p = pipeline()
    caller = p.job(CALLER)
    zero = "0x" + "00" * 20
    p.land_facts(caller, _caller_effects(("tokenA", "tokenB")), _snapshot({"tokenA": zero, "tokenB": CALLER}))
    p.run(caller)

    assert _gaps(p, caller) == {SWEEP: []}


def test_a_callee_landing_during_the_own_pass_does_not_leave_a_permanent_gap(pipeline, monkeypatch):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    token = p.job(TOKEN_A)

    def _read_then_land(targets, *, session_factory):
        facts = fetch_sibling_facts(targets, session_factory=session_factory)
        p.land_facts(token, _token_effects(proves_flow=False), _snapshot({}))
        return facts

    monkeypatch.setattr("workers.policy_worker.fetch_sibling_facts", _read_then_land)
    p.run_policy(caller)
    monkeypatch.setattr("workers.policy_worker.fetch_sibling_facts", fetch_sibling_facts)
    p.complete(caller)

    assert p.stale() == {str(caller.id)}
    p.settle()
    assert _gaps(p, caller) == {SWEEP: []}


def test_a_call_through_a_proxy_names_the_implementation_job(pipeline):
    p = pipeline()
    implementation = p.job(TOKEN_B)
    implementation.request = {"proxy_address": TOKEN_A}
    p.session.commit()
    p.land_facts(implementation, _token_effects(), _snapshot({}))
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)

    [gap] = _gaps(p, caller)[SWEEP]
    assert (gap["reason"], gap["callee_job_id"]) == ("callee_is_proxy", str(implementation.id))


def test_gaps_stay_null_where_nothing_was_evaluated(pipeline):
    p = pipeline()
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    p.run(caller)
    contract = p.session.query(Contract).filter(Contract.job_id == caller.id).one()
    p.session.add(
        EffectiveFunction(
            contract_id=contract.id,
            function_name="unlisted",
            selector=_selector("unlisted()"),
            abi_signature="unlisted()",
            effect_labels=[],
            claims=[],
        )
    )
    p.session.commit()
    payload = get_artifact(p.session, caller.id, "effective_permissions")
    assert isinstance(payload, dict)
    effects, snapshot = p.facts[caller.id]
    PolicyWorker()._enrich_cross_contract(
        p.session,
        caller,
        {},
        snapshot,
        function_records=payload["functions"],
        ep_data=payload,
        target_effects=effects,
    )
    gaps = _gaps(p, caller)
    assert gaps["unlisted()"] is None
    assert gaps[SWEEP] and gaps[SWEEP][0]["callee"] == TOKEN_A

    bare = p.job(TOKEN_B)
    p.session.add(Contract(job_id=bare.id, address=TOKEN_B, contract_name="Bare"))
    p.session.commit()
    contract = p.session.query(Contract).filter(Contract.job_id == bare.id).one()
    write_effective_function_rows(
        p.session,
        contract_id=contract.id,
        function_records=[{"function": SWEEP, "abi_signature": SWEEP, "selector": _selector(SWEEP)}],
        capability_by_function={},
    )
    p.session.commit()
    PolicyWorker()._enrich_cross_contract(p.session, bare, {}, _snapshot({"tokenA": TOKEN_A}))
    assert _gaps(p, bare) == {SWEEP: None}


def test_the_own_pass_reads_only_siblings_it_can_join_with(pipeline, monkeypatch):
    p = pipeline()
    unrelated = p.job(VAULT)
    p.land_facts(unrelated, _token_effects(), _snapshot({}))
    token = p.job(TOKEN_A)
    p.land_facts(token, _token_effects(), _snapshot({}))
    caller = p.job(CALLER)
    p.land_facts(caller, _caller_effects(("tokenA",)), _snapshot({"tokenA": TOKEN_A}))
    read: list[str] = []

    def _record(targets, *, session_factory):
        read.extend(address for _job_id, address in targets)
        return fetch_sibling_facts(targets, session_factory=session_factory)

    monkeypatch.setattr("workers.policy_worker.fetch_sibling_facts", _record)
    p.run(caller)

    assert read == [TOKEN_A]
    assert _ids(p.row_claims(caller)[SWEEP]) == [("flow.out", "policy_derived")]


@pytest.mark.parametrize("order", ["vault_facts_first", "teller_first"])
def test_a_hook_holder_is_read_when_only_its_pointer_names_the_target(pipeline, order):
    """The teller names no vault; only the vault's hook pointer joins them."""
    p = pipeline()
    vault, teller = p.job(VAULT), p.job(TELLER)
    if order == "vault_facts_first":
        p.land_facts(vault, _vault_effects(), _snapshot({"hook": TELLER}))
        p.land_facts(teller, _teller_effects(), _snapshot({}))
        p.run(teller)
        p.run(vault)
    else:
        p.land_facts(teller, _teller_effects(), _snapshot({}))
        p.run(teller)
        p.land_facts(vault, _vault_effects(), _snapshot({"hook": TELLER}))
        p.run(vault)
    p.settle()

    assert _ids(p.row_claims(teller)[DENY_ALL]) == [(C.TRANSFER_POLICY_CONFIGURE, "policy_derived")]


def test_a_hook_holder_read_before_its_controller_rows_exist_still_reaches_the_target(pipeline):
    p = pipeline()
    vault, teller = p.job(VAULT), p.job(TELLER)
    p.land_facts(teller, _teller_effects(), _snapshot({}))
    contract = Contract(job_id=vault.id, address=VAULT, contract_name="Vault")
    p.session.add(contract)
    p.session.commit()
    # Resolution has stored the vault's facts but not yet rewritten its controller-value rows.
    store_artifact(p.session, vault.id, "effects", data=_vault_effects())
    store_artifact(p.session, vault.id, "control_snapshot", data=_snapshot({"hook": TELLER}))
    p.facts[vault.id] = (_vault_effects(), _snapshot({"hook": TELLER}))
    p.run(teller)
    assert p.row_claims(teller)[DENY_ALL] == []

    p.session.add(ControllerValue(contract_id=contract.id, controller_id="state_variable:hook", value=TELLER))
    p.session.commit()
    mark_stale_dependents(p.session, vault, chain_id=1, session_factory=p.session_factory)
    assert p.stale() == {str(teller.id)}
    p.settle()

    assert _ids(p.row_claims(teller)[DENY_ALL]) == [(C.TRANSFER_POLICY_CONFIGURE, "policy_derived")]
