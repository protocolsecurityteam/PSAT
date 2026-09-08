"""Live gate for the semantic predicate pipeline on a guarded company child."""

from __future__ import annotations

from typing import Any

import pytest

from tests.live.conftest import LiveClient

EXPECTED_CAPABILITY_KINDS = {
    "finite_set",
    "threshold_group",
    "cofinite_blacklist",
    "signature_witness",
    "external_check_only",
    "conditional_universal",
    "unsupported",
    "AND",
    "OR",
}
EXPECTED_AUTHORITY_KINDS = {"public", "entity", "role", "any", "all", "expression"}
PRINCIPAL_CAPABILITY_KINDS = {"finite_set", "threshold_group", "signature_witness"}


def _iter_capabilities(expression: dict[str, Any]):
    yield expression
    for child in expression.get("children", []) or []:
        if isinstance(child, dict):
            yield from _iter_capabilities(child)


def _iter_authorities(authority: dict[str, Any]):
    yield authority
    for child in authority.get("children", []) or []:
        if isinstance(child, dict):
            yield from _iter_authorities(child)


@pytest.fixture(scope="module")
def guarded_contract(analyzed_veda_teller, live_client: LiveClient) -> dict[str, Any]:
    """Exercise canonical policy rows through a stable, known guarded contract."""
    job = analyzed_veda_teller
    raw = live_client.artifact(job["name"], "assessment")
    if not isinstance(raw, dict):
        pytest.fail(f"{job['name']} published no row-shaped Assessment")
    response = live_client._session.get(
        live_client._url(f"/api/contract/{job['address'].lower()}/capabilities"),
        timeout=30,
    )
    assert response.status_code == 200, (
        f"GET capabilities for known guarded contract returned {response.status_code}: {response.text[:400]!r}"
    )
    capabilities = response.json().get("capabilities")
    assert isinstance(capabilities, dict) and capabilities, "known guarded contract returned no capabilities"
    expressions = [
        node
        for capability in capabilities.values()
        if isinstance(capability, dict)
        for node in _iter_capabilities(capability)
    ]
    assert any(node.get("kind") in PRINCIPAL_CAPABILITY_KINDS for node in expressions), (
        "known guarded contract returned no principal-bearing capability"
    )
    claims = raw.get("claims")
    analyses = raw.get("analyses")
    assert isinstance(claims, list) and isinstance(analyses, list), "malformed canonical Assessment rows"
    authority_claims = [row for row in claims if row.get("kind") == "function_authority"]
    assert authority_claims, "known guarded contract published no canonical authority claims"
    return {
        "job": job,
        "assessment": raw,
        "capabilities": capabilities,
        "authority_claims": authority_claims,
    }


def test_policy_outputs_are_linked_in_canonical_assessment(guarded_contract):
    assessment = guarded_contract["assessment"]
    claim_ids = {row["id"] for row in assessment["claims"]}
    policy_runs = [row for row in assessment["analyses"] if row.get("producer") == "policy"]
    assert policy_runs, "guarded child must retain policy analysis receipts"
    outputs = {claim_id for row in policy_runs for claim_id in row.get("outputs", [])}
    assert outputs, "policy analyses must identify their canonical claim outputs"
    assert outputs <= claim_ids, "policy analysis outputs must reference published claim rows"
    assert {row["id"] for row in guarded_contract["authority_claims"]} <= outputs


def test_authority_claims_are_typed_and_proven(guarded_contract):
    assessment = guarded_contract["assessment"]
    subject_ids = {row["id"] for row in assessment["subjects"]}
    evidence_ids = {row["id"] for row in assessment["evidence"]}
    for claim in guarded_contract["authority_claims"]:
        proposition = claim.get("proposition") or {}
        assert proposition.get("kind") == "function_authority"
        assert proposition.get("function") in subject_ids
        assert claim.get("evidence"), "authority claims need an evidence basis"
        assert set(claim["evidence"]) <= evidence_ids
        authority = proposition.get("authority")
        assert isinstance(authority, dict)
        for node in _iter_authorities(authority):
            assert node.get("kind") in EXPECTED_AUTHORITY_KINDS
            entity = node.get("entity")
            if entity is not None:
                assert entity in subject_ids
            assert set(node.get("entities", [])) <= subject_ids


def test_capability_resolution_returns_non_empty(guarded_contract, live_client: LiveClient):
    job = guarded_contract["job"]
    addr = (job.get("address") or "").lower()
    assert addr.startswith("0x"), f"guarded child address missing or malformed: {addr!r}"

    resp = live_client._session.get(
        live_client._url(f"/api/contract/{addr}/capabilities"),
        timeout=30,
    )
    assert resp.status_code == 200, (
        f"GET /api/contract/{addr}/capabilities returned {resp.status_code}: {resp.text[:400]!r}"
    )
    body = resp.json()
    caps = body.get("capabilities")
    assert isinstance(caps, dict), "capabilities response must include a dict keyed on function signature"
    assert caps, "guarded child capability map must be non-empty"

    for fn_sig, cap in caps.items():
        assert isinstance(cap, dict), f"capabilities[{fn_sig}] must be a dict"
        kind = cap.get("kind")
        assert kind in EXPECTED_CAPABILITY_KINDS, (
            f"CapabilityExpr.kind {kind!r} for {fn_sig} not in closed CapKind set ({sorted(EXPECTED_CAPABILITY_KINDS)})"
        )


def test_assessment_permissions_preserve_capabilities_and_principals(guarded_contract):
    capabilities = guarded_contract["capabilities"]
    expressions = [
        node
        for capability in capabilities.values()
        if isinstance(capability, dict)
        for node in _iter_capabilities(capability)
    ]
    assert any(node.get("kind") in PRINCIPAL_CAPABILITY_KINDS for node in expressions)

    assessment = guarded_contract["assessment"]
    claims_by_id = {row["id"]: row for row in assessment["claims"]}
    authority_capabilities = [row for row in assessment["claims"] if row.get("kind") == "authority_capability"]
    for claim in authority_capabilities:
        dependency_kinds = {claims_by_id[key]["kind"] for key in claim.get("claims", []) if key in claims_by_id}
        assert dependency_kinds == {"function_authority", "function_effect"}
    assert guarded_contract["authority_claims"], "principal-bearing capabilities must survive as authority claims"
