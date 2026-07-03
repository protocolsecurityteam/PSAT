"""Two-contract integration tests for the policy-stage cross-contract path.

Drives ``PolicyWorker._enrich_cross_contract`` end to end against a real
Postgres session: a sibling job whose stored ``effects``/``control_snapshot``
carry Plane-1 claims, a target job whose ``effects``/``classifications`` are
stored, and target ``EffectiveFunction`` rows the derivation must update. The
only wire stubbed is ``SessionLocal`` — repointed at the test engine so the
parallel sibling fetch sees committed rows; the derivations, the registry,
``emit_claim``, precedence resolution, and the DB writes are the production
stack.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from eth_utils.crypto import keccak
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Contract, EffectiveFunction, Job, JobStage, JobStatus
from db.queue import store_artifact
from services.static.claims import Claim
from tests.conftest import requires_postgres
from workers.policy_worker import PolicyWorker

pytestmark = requires_postgres

TARGET = "0x33aa000000000000000000000000000000000000"
TOKEN = "0x11bb000000000000000000000000000000000000"
VAULT = "0x22cc000000000000000000000000000000000000"
IMPL = "0x99dd000000000000000000000000000000000000"

TRANSFER_SELECTOR = "0xa9059cbb"  # transfer(address,uint256)
UPGRADE_TO = "0x3659cfe6"  # upgradeTo(address)


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _std(claim_id: str) -> dict:
    return {"claim_id": claim_id, "tier": "standard_exact", "witness": {}}


@pytest.fixture
def _repoint_session_local(db_session, monkeypatch):
    """Point the worker's ``SessionLocal`` (used by the threaded sibling fetch)
    at the test engine so committed sibling artifacts are visible."""
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


# ---------------------------------------------------------------------------
# Derivation 1: value flow propagates a sibling's standard-tier claim
# ---------------------------------------------------------------------------


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
    # Legacy label column is left exactly as it was — no propagate-every-label.
    assert ef.effect_labels == ["external_contract_call"]


# ---------------------------------------------------------------------------
# Derivation 2: transfer_policy.configure via a sibling hook pointer
# ---------------------------------------------------------------------------


@requires_postgres
def test_transfer_policy_configure_from_sibling_hook(db_session, _repoint_session_local):
    company = f"co-{uuid.uuid4()}"
    target_job = _make_job(db_session, address=TARGET, company=company)
    vault_job = _make_job(db_session, address=VAULT, company=company)

    store_artifact(
        db_session,
        vault_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {
                "setBeforeTransferHook(address)": {
                    "selector": "0xaabbccdd",
                    "claims": [
                        {
                            "claim_id": "callee_pointer.rotate",
                            "tier": "idiom_structural",
                            "witness": {"links": [{"pointer": "hook", "invoked_by": "transfer()"}]},
                        }
                    ],
                }
            },
        },
    )
    # The vault's runtime hook pointer resolves to THIS target — the join edge.
    store_artifact(
        db_session,
        vault_job.id,
        "control_snapshot",
        data={"controller_values": {"state_variable:hook": {"value": TARGET}}},
    )

    store_artifact(
        db_session,
        target_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {
                "allowFrom(address)": {
                    "selector": "0xccddeeff",
                    "state_writes": [
                        {
                            "var": "allowlist",
                            "declared_type": "mapping(address => bool)",
                            "member_path": [],
                            "granularity": "var",
                            "hygiene_class": "normal",
                            "origin": "body",
                        }
                    ],
                    "claims": [],
                }
            },
        },
    )

    contract = _make_target_functions(db_session, target_job, ["allowFrom(address)"])

    enriched = PolicyWorker()._enrich_cross_contract(db_session, target_job, {}, {"controller_values": {}})

    assert "allowFrom(address)" in enriched
    claim = enriched["allowFrom(address)"][0]
    assert claim["claim_id"] == "transfer_policy.configure"
    assert claim["tier"] == "policy_derived"
    assert claim["witness"]["configures"] == VAULT

    ef = _ef(db_session, contract, "allowFrom(address)")
    assert {c["claim_id"] for c in (ef.claims or [])} == {"transfer_policy.configure"}


# ---------------------------------------------------------------------------
# Derivation 4: proxy-verified upgrade provenance via classifications
# ---------------------------------------------------------------------------


@requires_postgres
def test_provenance_upgrade_from_classifications(db_session, _repoint_session_local):
    company = f"co-{uuid.uuid4()}"
    target_job = _make_job(db_session, address=TARGET, company=company, request={"proxy_address": TARGET})
    # A benign sibling so the enrichment pass runs (it early-returns with none).
    sibling_job = _make_job(db_session, address=TOKEN, company=company)
    store_artifact(db_session, sibling_job.id, "effects", data={"schema_version": "semantic-2", "functions": {}})
    store_artifact(db_session, sibling_job.id, "control_snapshot", data={"controller_values": {}})

    store_artifact(
        db_session,
        target_job.id,
        "effects",
        data={
            "schema_version": "semantic-2",
            "functions": {"upgradeTo(address)": {"selector": UPGRADE_TO, "claims": []}},
        },
    )
    store_artifact(
        db_session,
        target_job.id,
        "classifications",
        data={
            "address": TARGET,
            "classifications": {
                TARGET: {"address": TARGET, "type": "proxy", "proxy_type": "eip1967", "implementation": IMPL}
            },
        },
    )

    contract = _make_target_functions(db_session, target_job, ["upgradeTo(address)"])

    enriched = PolicyWorker()._enrich_cross_contract(db_session, target_job, {}, {"controller_values": {}})

    claim = enriched["upgradeTo(address)"][0]
    assert claim["claim_id"] == "upgrade.implementation"
    assert claim["tier"] == "policy_derived"
    assert claim["witness"]["implementation"] == IMPL

    ef = _ef(db_session, contract, "upgradeTo(address)")
    assert any(c["claim_id"] == "upgrade.implementation" for c in (ef.claims or []))


# ---------------------------------------------------------------------------
# Silence when there is no cross-contract evidence
# ---------------------------------------------------------------------------


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
    # Target calls a DIFFERENT (unresolved) contract var.
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


# ---------------------------------------------------------------------------
# _apply_cross_contract_claims merges onto the effective_permissions payload
# ---------------------------------------------------------------------------


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
    # Same claim id at two tiers collapses to the strongest (standard_exact wins).
    assert len(sweep["claims"]) == 1
    assert sweep["claims"][0]["tier"] == "standard_exact"
    assert payload["functions"][1]["claims"] == []
