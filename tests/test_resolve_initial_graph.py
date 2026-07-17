"""Regression tests for the ``initial_graph`` parameter on
``services.resolution.recursive.resolve_control_graph``.

#5 from todo-no-commit-to-gihub.txt — skip the 2nd resolve_control_graph
walk that the policy worker triggers after computing
effective_permissions for the root contract.

Codex flagged this item with: "easy to make incomplete — enumerate every
node/edge type the second walk adds before shipping". The chosen design
sidesteps that risk by reusing the SAME BFS code path with a pre-seeded
``processed`` set, rather than writing a separate projection function.
The BFS only re-walks: (a) the root contract (so the now-populated
effective_permissions is read), and (b) any new addresses discovered
during that re-walk.

What we pin:
1. With initial_graph set, every node + edge from the prior walk is
   carried into the new graph.
2. Every analyzed contract from the prior walk EXCEPT the root is
   marked processed → not re-materialized.
3. The root IS re-walked (so role principals from the new
   effective_permissions get projected).
4. New role principals that are EOA addresses get added as principal
   nodes + role_principal edges, no extra materialization needed.
5. Edges from the prior walk are not duplicated even when the root is
   re-walked (BFS edge-key dedupe).
6. Without initial_graph, behavior is unchanged (legacy callers).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schemas.resolved_control_graph import ResolvedControlGraph
from services.resolution import recursive
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph

ROOT_ADDR = "0x" + "ab" * 20
NESTED_ADDR = "0x" + "cd" * 20
ROLE_PRINCIPAL_EOA = "0x" + "ef" * 20


@pytest.fixture(autouse=True)
def _isolated_caches():
    yield


def _root_artifacts(*, with_role_principals: bool) -> LoadedArtifacts:
    """Root LoadedArtifacts used for both walks. ``with_role_principals``
    adds an effective_permissions block referencing ROLE_PRINCIPAL_EOA —
    the second walk should pick that up; the first should not see it."""
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
    """When the second walk has no new role principals (effective_permissions
    is empty), the resulting graph must be identical to the first walk — no
    new nodes, no new edges, no extra materialization."""
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
        # Second walk with same root, with initial_graph → must be no-op.
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
    """The second walk discovers a role principal from the root's
    newly-populated effective_permissions and adds it as a node + edge."""
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

        # Second walk WITH role principals + initial_graph. The role
        # principal is an EOA so no materialization needed for it either.
        # We patch classify_resolved_address_with_status so we don't make
        # real RPC calls when classifying the EOA.
        def _fake_classify(_rpc_url, addr, _block_tag="latest"):
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

    # Role principal node must be present in the second graph.
    role_node_id = recursive._address_node_id(ROLE_PRINCIPAL_EOA)
    assert role_node_id in {n["id"] for n in second_graph["nodes"]}

    # And a role_principal edge from root → that node.
    root_node_id = recursive._address_node_id(ROOT_ADDR)
    role_edges = [
        e for e in second_graph["edges"] if e.get("from_id") == root_node_id and e.get("relation") == "role_principal"
    ]
    assert len(role_edges) >= 1
    assert any(e["to_id"] == role_node_id for e in role_edges)

    # And no materialize call was made — we should reuse the existing root
    # artifacts (passed via root_artifacts) and skip every other contract.
    assert materialize_calls == []


def test_initial_graph_skips_re_materialization_of_nested_contracts():
    """With initial_graph set, every analyzed nested contract from the
    prior walk must be in `processed` → BFS does NOT re-materialize it.
    This is the primary source of the optimization's wall-clock win."""
    # First walk: build a graph with one nested contract.
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
        # Second walk with no new role principals: should NOT call
        # materialize for either root (preloaded) OR nested (in processed).
        graph, _ = resolve_control_graph(
            root_artifacts=_root_artifacts(with_role_principals=False),
            rpc_url="https://rpc",
            chain_id=1,
            workspace_prefix="test",
            initial_graph=seed_graph,
        )

    assert materialize_calls == [], "no nested contract should be re-materialized"
    # The seed nested node must still be present in the result.
    assert recursive._address_node_id(NESTED_ADDR) in {n["id"] for n in graph["nodes"]}


def test_initial_graph_re_walks_root_so_new_permissions_are_projected():
    """Root must NOT be in `processed` — otherwise the second walk would
    skip it and miss the role principals from its new permissions."""
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

    def _fake_classify(_rpc_url, addr, _block_tag="latest"):
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

    # The role principal from the root's new permissions made it in.
    role_node_id = recursive._address_node_id(ROLE_PRINCIPAL_EOA)
    assert role_node_id in {n["id"] for n in graph["nodes"]}


def test_initial_graph_dedupes_edges_on_re_walk():
    """When the root is re-walked, edges already in the seed graph must
    not be duplicated (BFS uses _edge_key dedupe)."""
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

    # Same edge appears exactly once.
    matching = [
        e
        for e in graph["edges"]
        if e["from_id"] == root_node_id and e["to_id"] == nested_node_id and e["relation"] == "controller_value"
    ]
    assert len(matching) == 1


def test_no_initial_graph_preserves_legacy_behavior():
    """Without initial_graph, behavior is identical to before this change.
    Catches a regression where the new code path leaks into legacy callers."""
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
    # Just the root.
    root_node_id = recursive._address_node_id(ROOT_ADDR)
    assert {n["id"] for n in graph["nodes"]} == {root_node_id}
