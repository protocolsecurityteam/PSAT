"""PolicyWorker plumbing against real Postgres; the four derivations are unit-tested in
``tests/static/test_cross_contract_effects.py``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from eth_utils.crypto import keccak
from sqlalchemy.orm import sessionmaker

from db.models import Contract, EffectiveFunction, Job, JobStage, JobStatus
from db.queue import store_artifact
from services.static.claims import Claim
from tests.conftest import requires_postgres
from workers.policy_worker import PolicyWorker

pytestmark = requires_postgres

TARGET = "0x33aa000000000000000000000000000000000000"
TOKEN = "0x11bb000000000000000000000000000000000000"

TRANSFER_SELECTOR = "0xa9059cbb"  # transfer(address,uint256)


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _std(claim_id: str) -> dict:
    return {"claim_id": claim_id, "tier": "standard_exact", "witness": {}}


@pytest.fixture
def _repoint_session_local(db_session, monkeypatch):
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    monkeypatch.setattr("workers.policy_worker.SessionLocal", factory)
    return factory


def _make_job(session, *, address: str, company: str, request: dict | None = None) -> Job:
    job = Job(
        id=uuid.uuid4(),
        address=address,
        company=company,
        name="C",
        status=JobStatus.completed,
        stage=JobStage.done,
        request=request or {},
    )
    session.add(job)
    session.commit()
    return job


def _make_target_functions(session, target_job: Job, signatures: list[str]) -> Contract:
    contract = Contract(job_id=target_job.id, address=TARGET, contract_name="Target")
    session.add(contract)
    session.flush()
    for sig in signatures:
        session.add(
            EffectiveFunction(
                contract_id=contract.id,
                function_name=sig.split("(", 1)[0],
                selector=_selector(sig)[:10],
                abi_signature=sig,
                effect_labels=["external_contract_call"],
                claims=None,
            )
        )
    session.commit()
    return contract


def _ef(session, contract: Contract, abi_signature: str) -> EffectiveFunction:
    return (
        session.query(EffectiveFunction)
        .filter(EffectiveFunction.contract_id == contract.id, EffectiveFunction.abi_signature == abi_signature)
        .one()
    )


@requires_postgres
def test_value_flow_claim_propagates_to_effective_function(db_session, _repoint_session_local):
    company = f"co-{uuid.uuid4()}"
    target_job = _make_job(db_session, address=TARGET, company=company)
    sibling_job = _make_job(db_session, address=TOKEN, company=company)

    store_artifact(
        db_session,
        sibling_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {"transfer(address,uint256)": {"selector": TRANSFER_SELECTOR, "claims": [_std("flow.out")]}},
        },
    )
    store_artifact(db_session, sibling_job.id, "control_snapshot", data={"controller_values": {}})

    store_artifact(
        db_session,
        target_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {
                "sweep(address)": {
                    "selector": _selector("sweep(address)"),
                    "sinks": [
                        {
                            "id": "s0",
                            "kind": "external_call",
                            "target": "token.transfer",
                            "selector": TRANSFER_SELECTOR,
                            "origin": "body",
                        }
                    ],
                    "claims": [],
                }
            },
        },
    )

    contract = _make_target_functions(db_session, target_job, ["sweep(address)"])
    control_snapshot = {"controller_values": {"state_variable:token": {"value": TOKEN}}}

    enriched = PolicyWorker()._enrich_cross_contract(db_session, target_job, {}, control_snapshot)

    assert "sweep(address)" in enriched
    claim = enriched["sweep(address)"][0]
    assert claim["claim_id"] == "flow.out"
    assert claim["tier"] == "policy_derived"
    assert claim["witness"]["callee"] == TOKEN

    ef = _ef(db_session, contract, "sweep(address)")
    ids = {c["claim_id"] for c in (ef.claims or [])}
    assert "flow.out" in ids
    assert ef.effect_labels == ["external_contract_call"]


@requires_postgres
def test_no_claims_without_matching_evidence(db_session, _repoint_session_local):
    company = f"co-{uuid.uuid4()}"
    target_job = _make_job(db_session, address=TARGET, company=company)
    sibling_job = _make_job(db_session, address=TOKEN, company=company)
    store_artifact(
        db_session,
        sibling_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {"transfer(address,uint256)": {"selector": TRANSFER_SELECTOR, "claims": [_std("flow.out")]}},
        },
    )
    store_artifact(db_session, sibling_job.id, "control_snapshot", data={"controller_values": {}})
    store_artifact(
        db_session,
        target_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {
                "sweep(address)": {
                    "selector": _selector("sweep(address)"),
                    "sinks": [
                        {
                            "id": "s0",
                            "kind": "external_call",
                            "target": "other.transfer",
                            "selector": TRANSFER_SELECTOR,
                            "origin": "body",
                        }
                    ],
                    "claims": [],
                }
            },
        },
    )
    _make_target_functions(db_session, target_job, ["sweep(address)"])

    enriched = PolicyWorker()._enrich_cross_contract(
        db_session, target_job, {}, {"controller_values": {"state_variable:token": {"value": TOKEN}}}
    )
    assert enriched == {}


def test_apply_cross_contract_claims_merges_and_dedups():
    payload: dict[str, Any] = {
        "functions": [
            {
                "function": "sweep(address)",
                "abi_signature": "sweep(address)",
                "claims": [{"claim_id": "flow.out", "tier": "standard_exact", "witness": {"static": True}}],
            },
            {"function": "noop()", "abi_signature": "noop()", "claims": []},
        ]
    }
    enriched: dict[str, list[Claim]] = {
        "sweep(address)": [{"claim_id": "flow.out", "tier": "policy_derived", "witness": {"policy": True}}],
    }
    PolicyWorker()._apply_cross_contract_claims(payload, enriched)

    sweep = payload["functions"][0]
    assert len(sweep["claims"]) == 1
    assert sweep["claims"][0]["tier"] == "standard_exact"
    assert payload["functions"][1]["claims"] == []


@requires_postgres
def test_the_row_replace_drops_last_run_s_policy_derived_claims(db_session):
    """``policy_derived`` claims land on rows the next run replaces wholesale, carrying only observed-tier claims.

    If that carry widens this goes red, and both merge sites need the bridge's explicit stale-drop.
    """
    from services.policy.effective_permissions_writer import write_effective_function_rows

    company = f"co-{uuid.uuid4()}"
    job = _make_job(db_session, address=TARGET, company=company)
    contract = _make_target_functions(db_session, job, ["sweep(address)"])

    row = _ef(db_session, contract, "sweep(address)")
    row.claims = [
        {"claim_id": "flow.out", "tier": "policy_derived", "witness": {"sink_id": "last-run"}},
        {"claim_id": "upgrade.implementation", "tier": "behavioral_observed", "witness": {"effect_verdict_id": 7}},
    ]
    db_session.commit()

    write_effective_function_rows(
        db_session,
        contract_id=contract.id,
        function_records=[
            {"function": "sweep(address)", "abi_signature": "sweep(address)", "selector": _selector("sweep(address)")}
        ],
        capability_by_function=None,
    )
    db_session.commit()

    tiers = {c["tier"] for c in _ef(db_session, contract, "sweep(address)").claims or []}
    assert "policy_derived" not in tiers
    assert "behavioral_observed" in tiers


@requires_postgres
def test_struct_param_function_still_matches_its_row(db_session, _repoint_session_local):
    """The artifact keys on Slither full_name and the row on the ABI signature, which differ for struct params; the
    selector is what both agree on.
    """
    company = f"co-{uuid.uuid4()}"
    target_job = _make_job(db_session, address=TARGET, company=company)
    sibling_job = _make_job(db_session, address=TOKEN, company=company)

    full_name = "sweepWithPermit(address,IAdapter.PermitInput)"
    canonical = "sweepWithPermit(address,(uint256,uint8,bytes32))"
    selector = _selector(canonical)

    store_artifact(
        db_session,
        sibling_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {"transfer(address,uint256)": {"selector": TRANSFER_SELECTOR, "claims": [_std("flow.out")]}},
        },
    )
    store_artifact(db_session, sibling_job.id, "control_snapshot", data={"controller_values": {}})
    store_artifact(
        db_session,
        target_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {
                full_name: {
                    "selector": selector,
                    "sinks": [
                        {
                            "id": "s0",
                            "kind": "external_call",
                            "target": "token.transfer",
                            "selector": TRANSFER_SELECTOR,
                            "origin": "body",
                        }
                    ],
                    "claims": [],
                }
            },
        },
    )

    contract = Contract(job_id=target_job.id, address=TARGET, contract_name="Target")
    db_session.add(contract)
    db_session.flush()
    db_session.add(
        EffectiveFunction(
            contract_id=contract.id,
            function_name="sweepWithPermit",
            selector=selector,
            abi_signature=canonical,
            effect_labels=["external_contract_call"],
            claims=None,
        )
    )
    db_session.commit()

    control_snapshot = {"controller_values": {"state_variable:token": {"value": TOKEN}}}
    enriched = PolicyWorker()._enrich_cross_contract(
        db_session,
        target_job,
        {},
        control_snapshot,
        function_records=[{"function": full_name, "abi_signature": canonical, "selector": selector}],
    )

    assert full_name in enriched
    ef = _ef(db_session, contract, canonical)
    assert "flow.out" in {c["claim_id"] for c in (ef.claims or [])}


D1 = "0x44cc000000000000000000000000000000000000"
D2 = "0x55dd000000000000000000000000000000000000"


@requires_postgres
def test_enrichment_lands_only_on_this_job_s_deployment(db_session, _repoint_session_local):
    """Claims come from this proxy's storage; a sibling deployment's row would get the wrong wiring, and the unscoped
    read raises.
    """
    company = f"co-{uuid.uuid4()}"
    target_job = _make_job(db_session, address=TARGET, company=company, request={"proxy_address": D1})
    sibling_job = _make_job(db_session, address=TOKEN, company=company)

    store_artifact(
        db_session,
        sibling_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {"transfer(address,uint256)": {"selector": TRANSFER_SELECTOR, "claims": [_std("flow.out")]}},
        },
    )
    store_artifact(db_session, sibling_job.id, "control_snapshot", data={"controller_values": {}})
    store_artifact(
        db_session,
        target_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {
                "sweep(address)": {
                    "selector": _selector("sweep(address)"),
                    "sinks": [
                        {
                            "id": "s0",
                            "kind": "external_call",
                            "target": "token.transfer",
                            "selector": TRANSFER_SELECTOR,
                            "origin": "body",
                        }
                    ],
                    "claims": [],
                }
            },
        },
    )

    contract = Contract(job_id=target_job.id, address=TARGET, contract_name="Target")
    db_session.add(contract)
    db_session.flush()
    for deployment in (D1, D2):
        db_session.add(
            EffectiveFunction(
                contract_id=contract.id,
                deployment_address=deployment,
                function_name="sweep",
                selector=_selector("sweep(address)")[:10],
                abi_signature="sweep(address)",
                effect_labels=["external_contract_call"],
                claims=None,
            )
        )
    db_session.commit()

    control_snapshot = {"controller_values": {"state_variable:token": {"value": TOKEN}}}
    PolicyWorker()._enrich_cross_contract(db_session, target_job, {}, control_snapshot)

    def _claims_for(deployment: str) -> set[str]:
        row = (
            db_session.query(EffectiveFunction)
            .filter(
                EffectiveFunction.contract_id == contract.id,
                EffectiveFunction.deployment_address == deployment,
            )
            .one()
        )
        return {c["claim_id"] for c in (row.claims or [])}

    assert "flow.out" in _claims_for(D1)
    assert _claims_for(D2) == set()


@requires_postgres
def test_ambiguous_row_match_is_skipped_not_raised(db_session, _repoint_session_local, caplog):
    """A claim we can't place is worth losing; the stage isn't."""
    company = f"co-{uuid.uuid4()}"
    target_job = _make_job(db_session, address=TARGET, company=company, request={"proxy_address": D1})
    sibling_job = _make_job(db_session, address=TOKEN, company=company)

    store_artifact(
        db_session,
        sibling_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {"transfer(address,uint256)": {"selector": TRANSFER_SELECTOR, "claims": [_std("flow.out")]}},
        },
    )
    store_artifact(db_session, sibling_job.id, "control_snapshot", data={"controller_values": {}})
    store_artifact(
        db_session,
        target_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {
                "sweep(address)": {
                    "selector": _selector("sweep(address)"),
                    "sinks": [
                        {
                            "id": "s0",
                            "kind": "external_call",
                            "target": "token.transfer",
                            "selector": TRANSFER_SELECTOR,
                            "origin": "body",
                        }
                    ],
                    "claims": [],
                }
            },
        },
    )

    contract = Contract(job_id=target_job.id, address=TARGET, contract_name="Target")
    db_session.add(contract)
    db_session.flush()
    for deployment in (D1, None):
        db_session.add(
            EffectiveFunction(
                contract_id=contract.id,
                deployment_address=deployment,
                function_name="sweep",
                selector=_selector("sweep(address)")[:10],
                abi_signature="sweep(address)",
                effect_labels=["external_contract_call"],
                claims=None,
            )
        )
    db_session.commit()

    control_snapshot = {"controller_values": {"state_variable:token": {"value": TOKEN}}}
    with caplog.at_level("WARNING", logger="workers.policy_worker"):
        enriched = PolicyWorker()._enrich_cross_contract(db_session, target_job, {}, control_snapshot)

    assert "sweep(address)" in enriched
    assert any("matched 2 effective_function rows" in r.getMessage() for r in caplog.records)
    rows = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).all()
    assert [r.claims for r in rows] == [None, None]
