"""Live gate for the semantic predicate pipeline on a guarded company child."""

from __future__ import annotations

import time
from typing import Any

import pytest

from db.queue.typed import validate_assessment
from services.assessment import project_permission_index, static_inputs
from tests.live.conftest import DEFAULT_COMPANY_TIMEOUT, DEFAULT_POLL_INTERVAL, LiveClient

EXPECTED_LEAF_KINDS = {
    "membership",
    "equality",
    "comparison",
    "external_bool",
    "signature_auth",
    "unsupported",
}
TYPED_LEAF_KINDS = {"equality", "membership", "external_bool", "signature_auth"}
AUTHORITY_LEAF_ROLES = {"caller_authority", "delegated_authority"}

EXPECTED_AUTHORITY_ROLES = {
    "caller_authority",
    "delegated_authority",
    "time",
    "reentrancy",
    "pause",
    "business",
    "one_shot",
}

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


def _iter_leaves(tree: dict[str, Any]):
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            yield leaf
        return
    for child in tree.get("children", []) or []:
        yield from _iter_leaves(child)


def _leaves_from_artifact(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    trees = artifact.get("trees") or {}
    leaves: list[dict[str, Any]] = []
    for tree in trees.values():
        leaves.extend(_iter_leaves(tree))
    return leaves


@pytest.fixture(scope="module")
def guarded_contract(analyzed_company, live_client: LiveClient) -> dict[str, Any]:
    """Exercise discovery through a guarded descendant, on a fresh preview DB."""
    deadline = time.monotonic() + DEFAULT_COMPANY_TIMEOUT
    descendants: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        jobs = live_client.jobs()
        parents = {analyzed_company["job_id"]}
        descendants = []
        for _ in range(len(jobs)):
            children = [
                job
                for job in jobs
                if (job.get("request") or {}).get("parent_job_id") in parents and job["job_id"] not in parents
            ]
            if not children:
                break
            descendants.extend(children)
            parents.update(job["job_id"] for job in children)
        if all(job["status"] in {"completed", "failed", "failed_terminal"} for job in descendants):
            break
        time.sleep(DEFAULT_POLL_INTERVAL * 2)
    else:
        pytest.fail("Company descendants did not finish before the integration timeout")
    diagnostics = []
    for job in descendants:
        if job.get("status") != "completed" or not job.get("address") or not job.get("name"):
            continue
        raw = live_client.artifact(job["name"], "assessment")
        if raw is None:
            diagnostics.append(f"{job['name']}: no Assessment")
            continue
        assessment = validate_assessment(raw)
        _facts, predicate_trees, _effects = static_inputs(assessment)
        leaves = _leaves_from_artifact(predicate_trees)
        if any(leaf.get("authority_role") in AUTHORITY_LEAF_ROLES for leaf in leaves):
            return {"job": job, "assessment": assessment, "predicate_trees": predicate_trees, "leaves": leaves}
        diagnostics.append(f"{job['name']}: no authority leaves")
    pytest.fail(
        "Company discovery produced no guarded Assessment descendant. "
        "This integration requires a fresh preview DB with eligible discovery candidates; "
        f"descendants={len(descendants)} diagnostics={diagnostics[:10]}"
    )


def test_predicate_trees_are_embedded_in_assessment(guarded_contract):
    artifact = guarded_contract["predicate_trees"]
    trees = artifact.get("trees")

    assert artifact.get("schema_version") == "semantic", (
        f"predicate_trees.schema_version must be 'semantic', got {artifact.get('schema_version')!r}"
    )
    assert isinstance(trees, dict) and trees, "guarded child predicate_trees.trees must be non-empty"


def test_predicate_trees_has_typed_leaves(guarded_contract):
    leaves = guarded_contract["leaves"]
    assert leaves, "guarded child predicate_trees must contain at least one leaf"

    saw_typed_leaf = False
    saw_authority_leaf = False
    for leaf in leaves:
        kind = leaf.get("kind")
        role = leaf.get("authority_role")
        assert kind in EXPECTED_LEAF_KINDS, (
            f"Leaf kind {kind!r} is not in the closed semantic LeafKind set ({sorted(EXPECTED_LEAF_KINDS)})"
        )
        assert role in EXPECTED_AUTHORITY_ROLES, (
            f"Leaf authority_role {role!r} is not in the closed semantic AuthorityRole set "
            f"({sorted(EXPECTED_AUTHORITY_ROLES)})"
        )
        saw_typed_leaf = saw_typed_leaf or kind in TYPED_LEAF_KINDS
        saw_authority_leaf = saw_authority_leaf or role in AUTHORITY_LEAF_ROLES

    assert saw_typed_leaf, f"No leaf with kind in {sorted(TYPED_LEAF_KINDS)} found"
    assert saw_authority_leaf, f"No authority leaf with role in {sorted(AUTHORITY_LEAF_ROLES)} found"


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
    functions = project_permission_index(guarded_contract["assessment"])["functions"]
    assert functions, "Guarded descendant must publish policy evidence in Assessment"
    checked = 0
    for function in functions:
        capability = function.get("capability_expr")
        if not isinstance(capability, dict):
            continue
        principals = [p for controller in function.get("controllers", []) for p in controller.get("principals", [])]
        kind = capability.get("kind")
        if kind == "finite_set":
            assert len(principals) == len(capability.get("members", []))
        elif kind == "threshold_group":
            assert len(principals) == 1
            assert principals[0]["resolved_type"] == "safe"
            assert "threshold" in principals[0].get("details", {})
        elif kind in {"cofinite_blacklist", "external_check_only", "conditional_universal"}:
            assert principals == []
        else:
            continue
        checked += 1
    assert checked, "No Assessment permission contained an asserted capability kind"
