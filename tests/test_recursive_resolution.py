import sys
from pathlib import Path
from typing import cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schemas.resolved_control_graph import ResolvedGraphEdge
from services.discovery.classifier import ClassificationIncompleteError
from services.resolution import recursive
from services.resolution.recursive import (
    LoadedArtifacts,
    UnresolvedProxyError,
    _add_edge,
    _mapping_writer_specs_from_predicate_trees,
    _materialize_contract_artifacts,
    resolve_control_graph,
)

# offline: recursive resolution probes bytecode (eth_getCode) and, when a nested
# contract fails to materialize, fetches its name from Etherscan to label the node.
pytestmark = pytest.mark.usefixtures("_stub_rpc_bytecode", "_stub_classifier_rpc")


@pytest.fixture(autouse=True)
def _stub_failed_node_name(monkeypatch):
    """The failed-node name lookup fetches verified source from Etherscan; default
    to None offline (tests that assert a specific name override this in-body)."""
    monkeypatch.setattr("services.resolution.recursive._contract_name_for_address", lambda address: None)


def _bundle(address: str, contract_name: str, *, snapshot: dict, effective_permissions: dict | None = None) -> dict:
    """Build an in-memory ``LoadedArtifacts`` for a contract."""
    plan = {
        "schema_version": "0.1",
        "contract_address": address,
        "contract_name": contract_name,
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [],
    }
    analysis = {
        "subject": {
            "address": address,
            "name": contract_name,
        }
    }
    bundle = {
        "analysis": analysis,
        "tracking_plan": plan,
        "snapshot": snapshot,
    }
    if effective_permissions is not None:
        bundle["effective_permissions"] = effective_permissions
    return bundle


def test_mapping_writer_specs_come_from_predicate_tree_hints():
    artifact = {
        "schema_version": "semantic",
        "trees": {
            "f()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [{"source": "msg_sender"}],
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "wards[msg.sender]",
                    "basis": [],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "storage_var": "wards",
                        "key_sources": [{"source": "msg_sender"}],
                        "enumeration_hint": [
                            {
                                "topic0": "0xaaa",
                                "topics_to_keys": {1: 0},
                                "data_to_keys": {},
                                "direction": "add",
                                "event_signature": "Rely(address)",
                                "event_name": "Rely",
                                "mapping_name": "wards",
                                "key_position": 0,
                                "indexed_positions": [0],
                                "value_position": None,
                                "writer_function": "rely(address)",
                            }
                        ],
                    },
                },
            }
        },
    }

    assert _mapping_writer_specs_from_predicate_trees(artifact) == [
        {
            "mapping_name": "wards",
            "event_signature": "Rely(address)",
            "event_name": "Rely",
            "key_position": 0,
            "indexed_positions": [0],
            "direction": "add",
            "writer_function": "rely(address)",
            "value_position": None,
        }
    ]


def test_mapping_writer_specs_include_check_trees():
    artifact = {
        "schema_version": "semantic",
        "check_trees": {
            "allowed(address,address,bytes4)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "operands": [{"source": "msg_sender"}],
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "users[user]",
                    "basis": [],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "storage_var": "users",
                        "key_sources": [{"source": "parameter", "parameter_index": 0}],
                        "enumeration_hint": [
                            {
                                "topic0": "0xbbb",
                                "topics_to_keys": {1: 0},
                                "data_to_keys": {},
                                "direction": "add",
                                "event_signature": "UserAllowed(address)",
                                "event_name": "UserAllowed",
                                "mapping_name": "users",
                                "key_position": 0,
                                "indexed_positions": [0],
                                "value_position": None,
                                "writer_function": "allow(address)",
                            }
                        ],
                    },
                },
            }
        },
    }

    assert _mapping_writer_specs_from_predicate_trees(artifact) == [
        {
            "mapping_name": "users",
            "event_signature": "UserAllowed(address)",
            "event_name": "UserAllowed",
            "key_position": 0,
            "indexed_positions": [0],
            "direction": "add",
            "writer_function": "allow(address)",
            "value_position": None,
        }
    ]


def test_resolve_control_graph_recurses_to_contract_and_safe(monkeypatch):
    root_address = "0x1111111111111111111111111111111111111111"
    authority_address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    safe_address = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    signer_address = "0xcccccccccccccccccccccccccccccccccccccccc"

    root_bundle = _bundle(
        root_address,
        "Vault",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Vault",
            "block_number": 1,
            "controller_values": {
                "external_contract:authority": {
                    "source": "authority",
                    "value": authority_address,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": authority_address},
                },
                "state_variable:owner": {
                    "source": "owner",
                    "value": "0x0000000000000000000000000000000000000000",
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "zero",
                    "details": {"address": "0x0000000000000000000000000000000000000000"},
                },
            },
        },
    )

    authority_bundle = _bundle(
        authority_address,
        "RolesAuthority",
        snapshot={
            "schema_version": "0.1",
            "contract_address": authority_address,
            "contract_name": "RolesAuthority",
            "block_number": 2,
            "controller_values": {
                "state_variable:owner": {
                    "source": "owner",
                    "value": safe_address,
                    "block_number": 2,
                    "observed_via": "eth_call",
                    "resolved_type": "safe",
                    "details": {
                        "address": safe_address,
                        "owners": [signer_address],
                        "threshold": 1,
                    },
                }
            },
        },
    )

    def fake_materialize(address, rpc_url, *, workspace_prefix):
        assert address == authority_address
        return authority_bundle

    def fake_classify(rpc_url, address, block_tag="latest"):
        if address == signer_address:
            return "eoa", {"address": signer_address}
        return "unknown", {"address": address}

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr("services.resolution.recursive.classify_resolved_address", fake_classify)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest": (*fake_classify(rpc_url, address, block_tag), True),
    )

    graph, nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        max_depth=3,
    )

    nodes = {node["address"]: node for node in graph["nodes"]}
    edges = {(edge["from_id"], edge["relation"], edge["to_id"]) for edge in graph["edges"]}

    assert nodes[root_address]["analyzed"] is True
    assert nodes[root_address]["contract_name"] == "Vault"
    assert nodes[authority_address]["analyzed"] is True
    assert nodes[authority_address]["contract_name"] == "RolesAuthority"
    assert nodes[safe_address]["resolved_type"] == "safe"
    assert nodes[signer_address]["resolved_type"] == "eoa"

    assert (
        "address:0x1111111111111111111111111111111111111111",
        "controller_value",
        "address:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ) in edges
    assert (
        "address:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "controller_value",
        "address:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ) in edges
    assert (
        "address:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "safe_owner",
        "address:0xcccccccccccccccccccccccccccccccccccccccc",
    ) in edges
    # Nested artifact for authority was materialized and returned.
    assert authority_address in nested


def test_resolve_control_graph_dedupes_recursive_contract_addresses(monkeypatch):
    root_address = "0x1111111111111111111111111111111111111111"
    shared_address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    root_bundle = _bundle(
        root_address,
        "Vault",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Vault",
            "block_number": 1,
            "controller_values": {
                "external_contract:authority": {
                    "source": "authority",
                    "value": shared_address,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": shared_address},
                },
                "external_contract:guardian": {
                    "source": "guardian",
                    "value": shared_address,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": shared_address},
                },
            },
        },
    )

    shared_bundle = _bundle(
        shared_address,
        "SharedController",
        snapshot={
            "schema_version": "0.1",
            "contract_address": shared_address,
            "contract_name": "SharedController",
            "block_number": 2,
            "controller_values": {},
        },
    )

    materialize_calls: list[str] = []

    def fake_materialize(address, rpc_url, *, workspace_prefix):
        materialize_calls.append(address)
        return shared_bundle

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest": ("unknown", {"address": address}),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest": ("unknown", {"address": address}, True),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        max_depth=2,
    )

    analyzed_addresses = [node["address"] for node in graph["nodes"] if node.get("analyzed")]
    assert analyzed_addresses.count(shared_address) == 1
    assert materialize_calls == [shared_address]


def test_resolve_control_graph_recurses_into_role_holder_contracts(monkeypatch):
    root_address = "0x1111111111111111111111111111111111111111"
    role_holder_address = "0xdddddddddddddddddddddddddddddddddddddddd"
    safe_address = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    signer_address = "0xcccccccccccccccccccccccccccccccccccccccc"

    root_bundle = _bundle(
        root_address,
        "Vault",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Vault",
            "block_number": 1,
            "controller_values": {},
        },
        effective_permissions={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Vault",
            "functions": [
                {
                    "function": "manage(address,bytes,uint256)",
                    "selector": "0x12345678",
                    "authority_public": False,
                    "authority_roles": [
                        {
                            "role": 1,
                            "principals": [
                                {
                                    "address": role_holder_address,
                                    "resolved_type": "contract",
                                    "details": {"address": role_holder_address},
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )

    role_holder_bundle = _bundle(
        role_holder_address,
        "ManagerContract",
        snapshot={
            "schema_version": "0.1",
            "contract_address": role_holder_address,
            "contract_name": "ManagerContract",
            "block_number": 2,
            "controller_values": {
                "state_variable:owner": {
                    "source": "owner",
                    "value": safe_address,
                    "block_number": 2,
                    "observed_via": "eth_call",
                    "resolved_type": "safe",
                    "details": {
                        "address": safe_address,
                        "owners": [signer_address],
                        "threshold": 1,
                    },
                }
            },
        },
    )

    materialize_calls: list[str] = []

    def fake_materialize(address, rpc_url, *, workspace_prefix):
        materialize_calls.append(address)
        assert address == role_holder_address
        return role_holder_bundle

    def fake_classify(rpc_url, address, block_tag="latest"):
        if address == signer_address:
            return "eoa", {"address": signer_address}
        if address == safe_address:
            return "safe", {"address": safe_address, "owners": [signer_address], "threshold": 1}
        if address == role_holder_address:
            return "contract", {"address": role_holder_address}
        return "unknown", {"address": address}

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr("services.resolution.recursive.classify_resolved_address", fake_classify)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest": (*fake_classify(rpc_url, address, block_tag), True),
    )

    resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        max_depth=3,
    )

    assert materialize_calls == [role_holder_address]


# test_materialize_contract_artifacts_tolerates_slither_cli_failure was
# deleted in commit 438a11c (Slither CLI subprocess rip-out). The
# materialize path no longer invokes the CLI, so the failure-tolerance
# test no longer has a code path to exercise.


def test_materialize_contract_artifacts_builds_effective_permissions(monkeypatch):
    address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    monkeypatch.setattr(
        "services.resolution.recursive.classify_single",
        lambda address, rpc_url: {"address": address, "type": "regular"},
        raising=False,
    )
    monkeypatch.setattr(
        "services.resolution.recursive.fetch",
        lambda _address: {"ContractName": "TestContract"},
    )
    monkeypatch.setattr(
        "services.resolution.recursive.scaffold",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "services.resolution.recursive.collect_contract_analysis_with_artifacts",
        lambda _project_dir: (
            {
                "subject": {"address": address, "name": "TestContract"},
                "semantic_control": {"semantic_functions": []},
            },
            {"schema_version": "semantic", "trees": {}},
            {"schema_version": "semantic", "functions": {}},
        ),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.build_control_tracking_plan",
        lambda _analysis: {
            "schema_version": "0.1",
            "contract_address": address,
            "contract_name": "TestContract",
            "tracking_strategy": "event_first_with_polling_fallback",
            "tracked_controllers": [],
        },
    )
    monkeypatch.setattr(
        "services.resolution.recursive.build_control_snapshot",
        lambda _plan, _rpc: {
            "schema_version": "0.1",
            "contract_address": address,
            "contract_name": "TestContract",
            "block_number": 1,
            "controller_values": {},
        },
    )
    marker = {"schema_version": "0.1", "functions": []}
    monkeypatch.setattr(
        "services.resolution.recursive._build_effective_permissions",
        lambda _analysis, _snapshot: marker,
    )

    loaded = _materialize_contract_artifacts(
        address,
        "http://rpc.example",
        workspace_prefix="recursive",
    )

    assert loaded.get("effective_permissions") is marker


# ---------------------------------------------------------------------------
# #122 — no-impl proxy must fail closed (refuse to analyze the shell);
# #121 coupling — the ClassificationIncompleteError raise must propagate here.
# ---------------------------------------------------------------------------


def test_materialize_contract_artifacts_no_impl_proxy_fails_closed(monkeypatch):
    """#122: a proxy classification with NO resolvable implementation (eip2535
    diamond) must raise UnresolvedProxyError — refusing to analyze the
    delegatecall shell — instead of silently falling through and Slithering the
    proxy stub (whose empty guard set downstream renders as permissionless)."""
    diamond = "0x" + "11" * 20

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url: {
            "address": address,
            "type": "proxy",
            "proxy_type": "eip2535",
            "facets": ["0x" + "ab" * 20, "0x" + "cd" * 20],
        },
    )

    with pytest.raises(UnresolvedProxyError):
        _materialize_contract_artifacts(diamond, "http://rpc.example", workspace_prefix="t")


def test_materialize_contract_artifacts_propagates_classification_incomplete(monkeypatch):
    """#121 coupling: a ClassificationIncompleteError from classify_single must
    PROPAGATE out of _materialize_contract_artifacts (so the BFS records a
    degraded, un-analyzed node), never be swallowed into an analyze-the-shell
    fall-through. This is why the proxy decision lives OUTSIDE the classify
    except block."""

    def _raise(address, rpc_url):
        raise ClassificationIncompleteError("proxy slots unread")

    monkeypatch.setattr("services.discovery.classifier.classify_single", _raise)

    with pytest.raises(ClassificationIncompleteError):
        _materialize_contract_artifacts("0x" + "11" * 20, "http://rpc.example", workspace_prefix="t")


def test_materialize_contract_artifacts_resolved_proxy_retargets_to_impl(monkeypatch):
    """Control for #122: a proxy WITH a resolved implementation still retargets to
    the impl (unchanged path). The fail-closed branch fires only for no-impl."""
    proxy = "0x" + "11" * 20
    impl = "0x" + "22" * 20

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url: {"address": address, "type": "proxy", "implementation": impl},
    )

    captured: dict = {}

    def fake_cache(*, effective_address, bytecode_keccak, workspace_prefix):
        captured["effective_address"] = effective_address
        analysis = {"subject": {"address": effective_address, "name": "Impl"}}
        plan = {"contract_address": effective_address, "controllers": []}
        return "Impl", analysis, plan, None

    monkeypatch.setattr(recursive, "_materialize_with_cross_process_cache", fake_cache)
    monkeypatch.setattr(recursive, "build_control_snapshot", lambda _plan, _rpc: {"controllers": []})
    monkeypatch.setattr(recursive, "_build_effective_permissions", lambda _a, _s: {"functions": []})

    loaded = _materialize_contract_artifacts(proxy, "http://rpc.example", workspace_prefix="t")

    assert captured["effective_address"] == impl  # retargeted to the logic contract
    assert loaded["analysis"]["subject"]["address"] == impl


def test_materialize_contract_artifacts_swallows_generic_classify_error(monkeypatch):
    """The restructure preserves the historical swallow: a *generic* classify
    error (not ClassificationIncompleteError, not a no-impl proxy) degrades to
    analyze-the-address-as-is and never propagates."""
    addr = "0x" + "33" * 20

    def _raise_generic(address, rpc_url):
        raise RuntimeError("classify hiccup")

    monkeypatch.setattr("services.discovery.classifier.classify_single", _raise_generic)

    captured: dict = {}

    def fake_cache(*, effective_address, bytecode_keccak, workspace_prefix):
        captured["effective_address"] = effective_address
        analysis = {"subject": {"address": effective_address, "name": "AsIs"}}
        plan = {"contract_address": effective_address, "controllers": []}
        return "AsIs", analysis, plan, None

    monkeypatch.setattr(recursive, "_materialize_with_cross_process_cache", fake_cache)
    monkeypatch.setattr(recursive, "build_control_snapshot", lambda _plan, _rpc: {"controllers": []})
    monkeypatch.setattr(recursive, "_build_effective_permissions", lambda _a, _s: None)

    loaded = _materialize_contract_artifacts(addr, "http://rpc.example", workspace_prefix="t")

    # Swallowed → analyze the address as-is (no retarget, no raise).
    assert captured["effective_address"] == addr
    assert loaded["analysis"]["subject"]["address"] == addr


def test_resolve_control_graph_no_impl_proxy_controller_is_degraded(monkeypatch):
    """#122 end-to-end: a nested controller that classifies as a no-impl proxy
    (eip2535 diamond) becomes a degraded analyzed=False node with a
    materialize_error — the shell's empty guard set never enters nested_artifacts,
    so nothing it would guard is reported permissionless."""
    root_address = "0x1111111111111111111111111111111111111111"
    diamond_address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    root_bundle = _bundle(
        root_address,
        "Vault",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Vault",
            "block_number": 1,
            "controller_values": {
                "external_contract:authority": {
                    "source": "authority",
                    "value": diamond_address,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": diamond_address},
                }
            },
        },
    )

    # The REAL _materialize_contract_artifacts runs; only classify_single is
    # steered to report the nested controller as a no-impl diamond.
    def fake_classify(address, rpc_url):
        if address.lower() == diamond_address:
            return {"address": address, "type": "proxy", "proxy_type": "eip2535", "facets": ["0x" + "bb" * 20]}
        return {"address": address, "type": "regular"}

    monkeypatch.setattr("services.discovery.classifier.classify_single", fake_classify)

    graph, nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        max_depth=2,
    )

    nodes = {node["address"]: node for node in graph["nodes"]}
    assert nodes[diamond_address]["analyzed"] is False
    assert "materialize_error" in nodes[diamond_address]["details"]
    assert "implementation unresolved" in nodes[diamond_address]["details"]["materialize_error"]
    assert diamond_address not in nested  # shell never entered the artifact map


def test_resolve_control_graph_skips_failed_nested_materialization(monkeypatch):
    root_address = "0x1111111111111111111111111111111111111111"
    nested_address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    root_bundle = _bundle(
        root_address,
        "Vault",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Vault",
            "block_number": 1,
            "controller_values": {
                "external_contract:authority": {
                    "source": "authority",
                    "value": nested_address,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": nested_address},
                }
            },
        },
    )

    monkeypatch.setattr(
        "services.resolution.recursive._materialize_contract_artifacts",
        lambda address, rpc_url, *, workspace_prefix: (_ for _ in ()).throw(RuntimeError("nested compile failed")),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        max_depth=2,
    )

    nodes = {node["address"]: node for node in graph["nodes"]}
    assert nodes[nested_address]["analyzed"] is False
    assert "materialize_error" in nodes[nested_address]["details"]


def test_resolve_control_graph_names_failed_nested_contract_from_metadata(monkeypatch):
    root_address = "0x1111111111111111111111111111111111111111"
    nested_address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    root_bundle = _bundle(
        root_address,
        "Vault",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Vault",
            "block_number": 1,
            "controller_values": {
                "state_variable:pauseRole": {
                    "source": "pauseRole",
                    "value": nested_address,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": nested_address},
                }
            },
        },
    )

    monkeypatch.setattr(
        "services.resolution.recursive._materialize_contract_artifacts",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("materialize failed")),
    )
    monkeypatch.setattr(
        "services.resolution.recursive._contract_name_for_address",
        lambda address: "GateSeal" if address == nested_address else None,
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        max_depth=2,
    )

    nodes = {node["address"]: node for node in graph["nodes"]}
    assert nodes[nested_address]["label"] == "GateSeal"
    assert nodes[nested_address]["contract_name"] == "GateSeal"
    assert "materialize_error" in nodes[nested_address]["details"]


def test_add_edge_dedupes_nested_safe_owner_edges_across_sources():
    edges = {}
    first = {
        "from_id": "address:0xsafe",
        "to_id": "address:0xowner",
        "relation": "safe_owner",
        "label": "safe owner",
        "source_controller_id": "state_variable:owner",
        "notes": ["path=owner"],
    }
    second = {
        "from_id": "address:0xsafe",
        "to_id": "address:0xowner",
        "relation": "safe_owner",
        "label": "safe owner",
        "source_controller_id": None,
        "notes": ["path=role"],
    }

    _add_edge(edges, cast(ResolvedGraphEdge, first))
    _add_edge(edges, cast(ResolvedGraphEdge, second))

    assert len(edges) == 1
    merged = next(iter(edges.values()))
    assert merged["notes"] == ["path=owner", "path=role"]


def test_resolve_control_graph_skips_self_referential_role_principal_edges(monkeypatch):
    root_address = "0x1111111111111111111111111111111111111111"

    root_bundle = _bundle(
        root_address,
        "Voting",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Voting",
            "block_number": 1,
            "controller_values": {},
        },
        effective_permissions={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Voting",
            "functions": [
                {
                    "function": "forward(bytes)",
                    "selector": "0x12345678",
                    "authority_public": False,
                    "authority_roles": [
                        {
                            "role": 1,
                            "principals": [
                                {
                                    "address": root_address,
                                    "resolved_type": "contract",
                                    "details": {"address": root_address},
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )

    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest": ("contract", {"address": address}),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        max_depth=2,
    )

    assert all(edge["from_id"] != edge["to_id"] for edge in graph["edges"])


# ---------------------------------------------------------------------------
# Level-parallel BFS parity: parallel + sequential produce identical graphs.
# ---------------------------------------------------------------------------


def _resolve_parity_helper(monkeypatch, fanout: str):
    """Build a fixture with 2 same-depth nested contracts so the BFS level
    has more than one item to materialize concurrently."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)
    root_address = "0x1111111111111111111111111111111111111111"
    auth_a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    auth_b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    leaf_a = "0xcccccccccccccccccccccccccccccccccccccccc"
    leaf_b = "0xdddddddddddddddddddddddddddddddddddddddd"

    root_bundle = _bundle(
        root_address,
        "Root",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Root",
            "block_number": 1,
            "controller_values": {
                "external_contract:authA": {
                    "source": "authA",
                    "value": auth_a,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": auth_a},
                },
                "external_contract:authB": {
                    "source": "authB",
                    "value": auth_b,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": auth_b},
                },
            },
        },
    )

    def _make_auth_bundle(addr, leaf_addr, leaf_role):
        return _bundle(
            addr,
            f"Auth_{addr[-2:]}",
            snapshot={
                "schema_version": "0.1",
                "contract_address": addr,
                "contract_name": f"Auth_{addr[-2:]}",
                "block_number": 2,
                "controller_values": {
                    "state_variable:owner": {
                        "source": "owner",
                        "value": leaf_addr,
                        "block_number": 2,
                        "observed_via": "eth_call",
                        "resolved_type": leaf_role,
                        "details": {"address": leaf_addr},
                    }
                },
            },
        )

    bundles_by_addr = {
        auth_a: _make_auth_bundle(auth_a, leaf_a, "eoa"),
        auth_b: _make_auth_bundle(auth_b, leaf_b, "eoa"),
    }

    def fake_materialize(address, rpc_url, *, workspace_prefix):
        return bundles_by_addr[address]

    def fake_classify(rpc_url, address, block_tag="latest"):
        return "eoa", {"address": address}

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr("services.resolution.recursive.classify_resolved_address", fake_classify)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest": (*fake_classify(rpc_url, address, block_tag), True),
    )

    graph, nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        max_depth=2,
    )
    return graph, nested


def test_resolve_control_graph_level_parallel_parity(monkeypatch):
    """Level-parallel BFS must produce the same nodes + edges as sequential."""
    seq_graph, seq_nested = _resolve_parity_helper(monkeypatch, "1")
    par_graph, par_nested = _resolve_parity_helper(monkeypatch, "8")

    # Nodes/edges are sorted by ``resolve_control_graph`` before return —
    # equality is meaningful even though materialization order differed.
    assert seq_graph["nodes"] == par_graph["nodes"]
    assert seq_graph["edges"] == par_graph["edges"]
    assert sorted(seq_nested.keys()) == sorted(par_nested.keys())


def test_resolve_control_graph_parallel_handles_partial_materialize_failure(monkeypatch):
    """One nested materialize failure becomes an unanalyzed node; the other
    sibling at the same depth still wires up cleanly."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", "8")
    root_address = "0x1111111111111111111111111111111111111111"
    good_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    bad_addr = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    root_bundle = _bundle(
        root_address,
        "Root",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Root",
            "block_number": 1,
            "controller_values": {
                "external_contract:good": {
                    "source": "good",
                    "value": good_addr,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": good_addr},
                },
                "external_contract:bad": {
                    "source": "bad",
                    "value": bad_addr,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": bad_addr},
                },
            },
        },
    )
    good_bundle = _bundle(
        good_addr,
        "Good",
        snapshot={
            "schema_version": "0.1",
            "contract_address": good_addr,
            "contract_name": "Good",
            "block_number": 2,
            "controller_values": {},
        },
    )

    def fake_materialize(address, rpc_url, *, workspace_prefix):
        if address == bad_addr:
            raise RuntimeError("simulated materialize failure")
        return good_bundle

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest": ("contract", {"address": address}),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest": ("contract", {"address": address}, True),
    )

    graph, nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        max_depth=2,
    )

    by_addr = {(node.get("details") or {}).get("address"): node for node in graph["nodes"]}
    assert good_addr in by_addr
    assert bad_addr in by_addr
    # Failed sibling is recorded as unanalyzed with the materialize_error
    # surfaced on details — same surface as the prior sequential code path.
    assert by_addr[bad_addr]["analyzed"] is False
    assert "materialize_error" in by_addr[bad_addr]["details"]
    assert by_addr[good_addr]["analyzed"] is True
    assert good_addr in nested
    assert bad_addr not in nested
