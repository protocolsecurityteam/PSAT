"""Regression tests for the ``initial_graph`` parameter on ``resolve_control_graph``.

Skips the 2nd walk the policy worker triggers after computing effective_permissions. Codex
warned this is "easy to make incomplete", so the design reuses the SAME BFS path with a
pre-seeded ``processed`` set: only the root (to read the now-populated effective_permissions)
and newly discovered addresses are re-walked. Also pinned: prior nodes/edges carry over
without duplication, and behavior is unchanged without initial_graph (legacy callers).
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import patch

import pytest

from schemas.resolved_control_graph import ResolvedControlGraph
from services.resolution import recursive
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph

ROOT_ADDR = "0x" + "ab" * 20
NESTED_ADDR = "0x" + "cd" * 20
ROLE_PRINCIPAL_EOA = "0x" + "ef" * 20


@pytest.fixture(autouse=True)
def _isolated_caches():
    yield


@pytest.fixture(autouse=True)
def _default_classify(monkeypatch):
    """Default the address classifier to the generic answer.

    Analysed nodes take ``resolved_type`` from the classifier, so every walk classifies its
    root. Tests needing a specific one patch in-body; this keeps the rest off the wire
    (otherwise the offline guard reports blocked ``rpc`` calls).
    """
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}, True),
    )


def _root_artifacts(*, with_role_principals: bool) -> LoadedArtifacts:
    """Root LoadedArtifacts for both walks; ``with_role_principals`` adds effective_permissions
    referencing ROLE_PRINCIPAL_EOA (only the second walk should pick it up)."""
    analysis = {"subject": {"address": ROOT_ADDR, "name": "Root"}, "semantic_control": {}}
    plan = {"contract_address": ROOT_ADDR, "controllers": []}
    snapshot = {"controller_values": {}}
    bundle: dict[str, Any] = {
        "analysis": analysis,
        "tracking_plan": plan,
        "snapshot": snapshot,
    }
    if with_role_principals:
        bundle["effective_permissions"] = {
            "functions": [
                {
                    "function": "setAdmin(address)",
                    "authority_roles": [
                        {
                            "role": 1,
                            "principals": [
                                {
                                    "address": ROLE_PRINCIPAL_EOA,
                                    "resolved_type": "eoa",
                                    "details": {"address": ROLE_PRINCIPAL_EOA},
                                }
                            ],
                        }
                    ],
                    "controllers": [],
                }
            ]
        }
    return cast(LoadedArtifacts, bundle)


def test_first_walk_then_initial_graph_walk_is_no_op_with_no_new_principals():
    with patch(
        "services.resolution.recursive._materialize_contract_artifacts",
        side_effect=AssertionError("must not be called for already-processed contracts"),
    ):
        first_graph, _ = resolve_control_graph(
            root_artifacts=_root_artifacts(with_role_principals=False),
            rpc_url="https://rpc",
            chain_id=1,
            workspace_prefix="test",
        )
        second_graph, _ = resolve_control_graph(
            root_artifacts=_root_artifacts(with_role_principals=False),
            rpc_url="https://rpc",
            chain_id=1,
            workspace_prefix="test",
            initial_graph=first_graph,
        )
    assert first_graph["nodes"] == second_graph["nodes"]
    assert first_graph["edges"] == second_graph["edges"]


def test_initial_graph_walk_projects_new_role_principal():
    materialize_calls: list[str] = []

    def _no_materialize(addr, *_a, **_kw):
        materialize_calls.append(addr)
        raise AssertionError(f"_materialize_contract_artifacts called for {addr}")

    with patch(
        "services.resolution.recursive._materialize_contract_artifacts",
        side_effect=_no_materialize,
    ):
        first_graph, _ = resolve_control_graph(
            root_artifacts=_root_artifacts(with_role_principals=False),
            rpc_url="https://rpc",
            chain_id=1,
            workspace_prefix="test",
        )

        # Second walk WITH role principals; classify is patched so the EOA makes no real RPC calls.
        def _fake_classify(_rpc_url, addr, _block_tag="latest", **_kw):
            return "eoa", {"address": addr.lower()}, True

        with patch(
            "services.resolution.recursive.classify_resolved_address_with_status",
            _fake_classify,
        ):
            second_graph, _ = resolve_control_graph(
                root_artifacts=_root_artifacts(with_role_principals=True),
                rpc_url="https://rpc",
                chain_id=1,
                workspace_prefix="test",
                initial_graph=first_graph,
            )

    role_node_id = recursive._address_node_id(ROLE_PRINCIPAL_EOA)
    assert role_node_id in {n["id"] for n in second_graph["nodes"]}

    root_node_id = recursive._address_node_id(ROOT_ADDR)
    role_edges = [
        e for e in second_graph["edges"] if e.get("from_id") == root_node_id and e.get("relation") == "role_principal"
    ]
    assert len(role_edges) >= 1
    assert any(e["to_id"] == role_node_id for e in role_edges)

    assert materialize_calls == []


def test_initial_graph_skips_re_materialization_of_nested_contracts():
    """Every analyzed nested contract from the prior walk must be in `processed` (the optimization's wall-clock win)."""
    nested_node = {
        "id": recursive._address_node_id(NESTED_ADDR),
        "address": NESTED_ADDR,
        "node_type": "contract",
        "resolved_type": "contract",
        "label": "Nested",
        "contract_name": "Nested",
        "depth": 1,
        "analyzed": True,
        "details": {"address": NESTED_ADDR},
        "artifacts": {},
    }
    root_node = {
        "id": recursive._address_node_id(ROOT_ADDR),
        "address": ROOT_ADDR,
        "node_type": "contract",
        "resolved_type": "contract",
        "label": "Root",
        "contract_name": "Root",
        "depth": 0,
        "analyzed": True,
        "details": {"address": ROOT_ADDR},
        "artifacts": {},
    }
    seed_graph = cast(ResolvedControlGraph, {"nodes": [root_node, nested_node], "edges": []})

    materialize_calls: list[str] = []

    def _record_materialize(addr, *_a, **_kw):
        materialize_calls.append(addr.lower())
        raise AssertionError(f"materialized {addr}")

    with patch(
        "services.resolution.recursive._materialize_contract_artifacts",
        side_effect=_record_materialize,
    ):
        graph, _ = resolve_control_graph(
            root_artifacts=_root_artifacts(with_role_principals=False),
            rpc_url="https://rpc",
            chain_id=1,
            workspace_prefix="test",
            initial_graph=seed_graph,
        )

    assert materialize_calls == [], "no nested contract should be re-materialized"
    assert recursive._address_node_id(NESTED_ADDR) in {n["id"] for n in graph["nodes"]}


def test_initial_graph_re_walks_root_so_new_permissions_are_projected():
    """Root must NOT be in `processed`, or the second walk would miss role principals from its new permissions."""
    seed_graph = {
        "nodes": [
            {
                "id": recursive._address_node_id(ROOT_ADDR),
                "address": ROOT_ADDR,
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Root",
                "contract_name": "Root",
                "depth": 0,
                "analyzed": True,
                "details": {"address": ROOT_ADDR},
                "artifacts": {},
            }
        ],
        "edges": [],
    }

    def _fake_classify(_rpc_url, addr, _block_tag="latest", **_kw):
        return "eoa", {"address": addr.lower()}, True

    with (
        patch(
            "services.resolution.recursive._materialize_contract_artifacts",
            side_effect=AssertionError("root uses preloaded root_artifacts, never materialized"),
        ),
        patch(
            "services.resolution.recursive.classify_resolved_address_with_status",
            _fake_classify,
        ),
    ):
        graph, _ = resolve_control_graph(
            root_artifacts=_root_artifacts(with_role_principals=True),
            rpc_url="https://rpc",
            chain_id=1,
            workspace_prefix="test",
            initial_graph=cast(ResolvedControlGraph, seed_graph),
        )

    role_node_id = recursive._address_node_id(ROLE_PRINCIPAL_EOA)
    assert role_node_id in {n["id"] for n in graph["nodes"]}


def test_initial_graph_dedupes_edges_on_re_walk():
    root_node_id = recursive._address_node_id(ROOT_ADDR)
    nested_node_id = recursive._address_node_id(NESTED_ADDR)
    existing_edge = {
        "from_id": root_node_id,
        "to_id": nested_node_id,
        "relation": "controller_value",
        "label": "admin",
        "source_controller_id": "controller_admin",
        "notes": [],
    }
    seed_graph = {
        "nodes": [
            {
                "id": root_node_id,
                "address": ROOT_ADDR,
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Root",
                "contract_name": "Root",
                "depth": 0,
                "analyzed": True,
                "details": {"address": ROOT_ADDR},
                "artifacts": {},
            },
            {
                "id": nested_node_id,
                "address": NESTED_ADDR,
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Nested",
                "contract_name": "Nested",
                "depth": 1,
                "analyzed": True,
                "details": {"address": NESTED_ADDR},
                "artifacts": {},
            },
        ],
        "edges": [existing_edge],
    }

    with patch(
        "services.resolution.recursive._materialize_contract_artifacts",
        side_effect=AssertionError,
    ):
        graph, _ = resolve_control_graph(
            root_artifacts=_root_artifacts(with_role_principals=False),
            rpc_url="https://rpc",
            chain_id=1,
            workspace_prefix="test",
            initial_graph=cast(ResolvedControlGraph, seed_graph),
        )

    matching = [
        e
        for e in graph["edges"]
        if e["from_id"] == root_node_id and e["to_id"] == nested_node_id and e["relation"] == "controller_value"
    ]
    assert len(matching) == 1


def test_no_initial_graph_preserves_legacy_behavior():
    """Without initial_graph, behavior is unchanged (guards against the new path leaking into legacy callers)."""
    with patch(
        "services.resolution.recursive._materialize_contract_artifacts",
        side_effect=AssertionError("nothing nested in this fixture"),
    ):
        graph, _ = resolve_control_graph(
            root_artifacts=_root_artifacts(with_role_principals=False),
            rpc_url="https://rpc",
            chain_id=1,
            workspace_prefix="test",
        )
    root_node_id = recursive._address_node_id(ROOT_ADDR)
    assert {n["id"] for n in graph["nodes"]} == {root_node_id}
