"""Two-contract integration tests for the policy-stage cross-contract path.

Drives ``PolicyWorker._enrich_cross_contract`` end to end against a real
Postgres session: a sibling job whose stored ``effects``/``control_snapshot``
carry Plane-1 claims, a target job whose ``effects`` are stored, and target
``EffectiveFunction`` rows the derivation must update. The only wire stubbed is
``SessionLocal`` — repointed at the test engine so the parallel sibling fetch
sees committed rows; the derivations, the registry, ``emit_claim``, precedence
resolution, and the DB writes are the production stack.

Scope is the PolicyWorker plumbing only (sibling fetch → derive → EF-row write,
plus the empty-evidence early return). The four typed derivations themselves are
unit-tested in ``tests/test_cross_contract_effects.py``.
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

TRANSFER_SELECTOR = "0xa9059cbb"  # transfer(address,uint256)


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
# Silence when there is no cross-contract evidence
#
# The per-derivation LOGIC (value-flow / transfer-policy hook / beacon / proxy
# provenance) is owned by the pure-facts unit module test_cross_contract_effects;
# this DB module only proves the PolicyWorker plumbing around it (the sibling
# fetch + EF-row write above, and the empty-evidence early return below).
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


# ---------------------------------------------------------------------------
# The equal-tier hazard both merge sites share, and why it cannot fire
# ---------------------------------------------------------------------------


def test_equal_tier_merge_keeps_the_first_claim():
    """Both merge sites are ``resolve_claim_precedence([*existing, *additions])``
    and precedence compares tiers with a strict ``>`` — so at EQUAL tier the
    incumbent wins and a re-derived claim would lose to the one it replaces.

    This is the mechanism that made the effects bridge unable to repair a damaged
    row. Pinned here as a fact about the shape, not a defect at these sites: what
    keeps it harmless is the precondition below."""
    from services.static.claims.registry import resolve_claim_precedence

    stale: Claim = {"claim_id": "flow.out", "tier": "policy_derived", "witness": {"sink_id": "stale"}}
    fresh: Claim = {"claim_id": "flow.out", "tier": "policy_derived", "witness": {"sink_id": "fresh"}}
    survivor = resolve_claim_precedence([stale, fresh])
    assert len(survivor) == 1
    assert survivor[0]["witness"]["sink_id"] == "stale"


@requires_postgres
def test_the_row_replace_drops_last_run_s_policy_derived_claims(db_session):
    """Why the hazard above cannot fire at ``_enrich_cross_contract``'s EF write.

    ``policy_derived`` is minted in one module (``static.cross_contract``) that
    one caller imports (``_enrich_cross_contract``), and that write lands on rows
    the NEXT run replaces wholesale. The replace carries only observed-tier
    claims forward, so last run's policy_derived claim is gone before the
    re-derived one arrives and the two can never collide at equal tier.

    That is a precondition held in a different module, which is exactly the
    coupling that let the effects bridge diverge unnoticed. If the carry is ever
    widened past observed-tier, this goes red and both merge sites need the same
    explicit stale-drop the bridge now uses."""
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
    # ...while the observed claim is the thing the carry exists to preserve.
    assert "behavioral_observed" in tiers
