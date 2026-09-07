"""Live gate for the semantic predicate pipeline on a guarded company child."""

from __future__ import annotations

from typing import Any, cast

import pytest

from schemas.assessment import Assessment
from services.assessment import static_inputs
from tests.live.conftest import LiveClient

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
def guarded_contract(analyzed_veda_teller, live_client: LiveClient) -> dict[str, Any]:
    """Load the known-guarded Veda Teller's predicate evidence from Assessment."""

    job = analyzed_veda_teller
    assessment = live_client.artifact(job["name"], "assessment")
    assert isinstance(assessment, dict), "Veda Teller analysis must publish Assessment"
    _static_facts, predicate_trees, _effects = static_inputs(cast(Assessment, assessment))
    trees = predicate_trees.get("trees")
    assert isinstance(trees, dict) and trees, "Veda Teller Assessment must embed guarded predicate trees"
    leaves = _leaves_from_artifact(predicate_trees)
    assert any(leaf.get("authority_role") in AUTHORITY_LEAF_ROLES for leaf in leaves), (
        "Veda Teller predicate evidence must contain an authority leaf"
    )
    return {"job": job, "assessment": assessment, "predicate_trees": predicate_trees, "leaves": leaves}


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
