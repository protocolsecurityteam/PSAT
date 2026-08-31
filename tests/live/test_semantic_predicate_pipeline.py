"""Live gate for the semantic predicate pipeline on a guarded company child."""

from __future__ import annotations

import time
from typing import Any

import pytest

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
TERMINAL_STATUSES = {"completed", "failed", "failed_terminal"}


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


def _descendants_of(jobs: list[dict[str, Any]], parent_job_id: str) -> list[dict[str, Any]]:
    by_parent: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        request = job.get("request") or {}
        parent = request.get("parent_job_id")
        if isinstance(parent, str):
            by_parent.setdefault(parent, []).append(job)

    descendants: list[dict[str, Any]] = []
    stack = list(by_parent.get(parent_job_id, []))
    while stack:
        job = stack.pop(0)
        descendants.append(job)
        stack.extend(by_parent.get(job["job_id"], []))
    return descendants


def _poll_descendants_until_done(
    live_client: LiveClient,
    parent_job_id: str,
    timeout: float = DEFAULT_COMPANY_TIMEOUT,
) -> list[dict[str, Any]]:
    deadline = time.time() + timeout
    descendants: list[dict[str, Any]] = []
    while time.time() < deadline:
        descendants = _descendants_of(live_client.jobs(), parent_job_id)
        if descendants and all(job["status"] in TERMINAL_STATUSES for job in descendants):
            return descendants
        time.sleep(DEFAULT_POLL_INTERVAL * 2)
    return descendants


@pytest.fixture(scope="module")
def guarded_company_child(analyzed_company, live_client: LiveClient) -> dict[str, Any]:
    descendants = _poll_descendants_until_done(live_client, analyzed_company["job_id"])
    completed = [job for job in descendants if job.get("status") == "completed" and job.get("name")]
    diagnostics: list[str] = []

    for job in completed:
        artifact = live_client.artifact(job["name"], "predicate_trees")
        if not isinstance(artifact, dict):
            diagnostics.append(f"{job.get('name')} {job.get('address')}: missing predicate_trees")
            continue
        trees = artifact.get("trees")
        if not isinstance(trees, dict) or not trees:
            diagnostics.append(f"{job.get('name')} {job.get('address')}: no guarded trees")
            continue
        leaves = _leaves_from_artifact(artifact)
        if any(leaf.get("authority_role") in AUTHORITY_LEAF_ROLES for leaf in leaves):
            return {"job": job, "predicate_trees": artifact, "leaves": leaves}
        diagnostics.append(f"{job.get('name')} {job.get('address')}: no authority leaves")

    pytest.fail(
        "analyzed_company produced no completed guarded descendant with semantic predicate trees; "
        f"checked={len(completed)} descendants={len(descendants)} diagnostics={diagnostics[:10]}"
    )


def test_predicate_trees_artifact_exists(guarded_company_child):
    artifact = guarded_company_child["predicate_trees"]
    trees = artifact.get("trees")

    assert artifact.get("schema_version") == "semantic", (
        f"predicate_trees.schema_version must be 'semantic', got {artifact.get('schema_version')!r}"
    )
    assert isinstance(trees, dict) and trees, "guarded child predicate_trees.trees must be non-empty"


def test_predicate_trees_has_typed_leaves(guarded_company_child):
    leaves = guarded_company_child["leaves"]
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


def test_capability_resolution_returns_non_empty(guarded_company_child, live_client: LiveClient):
    job = guarded_company_child["job"]
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
