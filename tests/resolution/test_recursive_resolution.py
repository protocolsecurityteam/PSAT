from typing import cast

import pytest

from schemas.resolved_control_graph import ResolvedGraphEdge, ResolvedGraphNode
from services.resolution import recursive
from services.resolution.recursive import (
    LoadedArtifacts,
    _add_edge,
    _mapping_writer_specs_from_predicate_trees,
    _materialize_contract_artifacts,
    resolve_control_graph,
)

# Offline: stub bytecode probes and the failed-node Etherscan name lookup.
pytestmark = pytest.mark.usefixtures("_stub_rpc_bytecode", "_stub_classifier_rpc")


@pytest.fixture(autouse=True)
def _default_classify(monkeypatch):
    """Every walk classifies its root; tests needing a specific type override in-body."""
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}, True),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}),
    )


@pytest.fixture(autouse=True)
def _stub_failed_node_name(monkeypatch):
    monkeypatch.setattr("services.resolution.recursive._contract_name_for_address", lambda address, chain_id=1: None)


def _bundle(address: str, contract_name: str, *, snapshot: dict, effective_permissions: dict | None = None) -> dict:
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


def _writer_spec_artifact(
    tree_key: str,
    function: str,
    *,
    authority_role: str,
    storage_var: str,
    expression: str,
    key_sources: list,
    topic0: str,
    event_signature: str,
    event_name: str,
    writer_function: str,
) -> dict:
    return {
        "schema_version": "semantic",
        tree_key: {
            function: {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": authority_role,
                    "operands": [{"source": "msg_sender"}],
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": expression,
                    "basis": [],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "storage_var": storage_var,
                        "key_sources": key_sources,
                        "enumeration_hint": [
                            {
                                "topic0": topic0,
                                "topics_to_keys": {1: 0},
                                "data_to_keys": {},
                                "direction": "add",
                                "event_signature": event_signature,
                                "event_name": event_name,
                                "mapping_name": storage_var,
                                "key_position": 0,
                                "indexed_positions": [0],
                                "value_position": None,
                                "writer_function": writer_function,
                            }
                        ],
                    },
                },
            }
        },
    }


@pytest.mark.parametrize(
    "artifact, expected",
    [
        pytest.param(
            _writer_spec_artifact(
                "trees",
                "f()",
                authority_role="caller_authority",
                storage_var="wards",
                expression="wards[msg.sender]",
                key_sources=[{"source": "msg_sender"}],
                topic0="0xaaa",
                event_signature="Rely(address)",
                event_name="Rely",
                writer_function="rely(address)",
            ),
            {
                "mapping_name": "wards",
                "event_signature": "Rely(address)",
                "event_name": "Rely",
                "writer_function": "rely(address)",
            },
            id="from-predicate-tree-hints",
        ),
        pytest.param(
            _writer_spec_artifact(
                "check_trees",
                "allowed(address,address,bytes4)",
                authority_role="delegated_authority",
                storage_var="users",
                expression="users[user]",
                key_sources=[{"source": "parameter", "parameter_index": 0}],
                topic0="0xbbb",
                event_signature="UserAllowed(address)",
                event_name="UserAllowed",
                writer_function="allow(address)",
            ),
            {
                "mapping_name": "users",
                "event_signature": "UserAllowed(address)",
                "event_name": "UserAllowed",
                "writer_function": "allow(address)",
            },
            id="include-check-trees",
        ),
    ],
)
def test_mapping_writer_specs_from_predicate_trees(artifact, expected):
    assert _mapping_writer_specs_from_predicate_trees(artifact) == [
        {
            **expected,
            "key_position": 0,
            "indexed_positions": [0],
            "direction": "add",
            "value_position": None,
        }
    ]


def _membership_tree(*, operator="truthy", authority_role="caller_authority", confidence=None, mapping="registered"):
    leaf = {
        "kind": "membership",
        "operator": operator,
        "operands": [{"source": "msg_sender"}],
        "references_msg_sender": True,
        "parameter_indices": [],
        "expression": f"{mapping}[msg.sender]",
        "basis": [],
        "set_descriptor": {
            "kind": "mapping_membership",
            "storage_var": mapping,
            "key_sources": [{"source": "msg_sender"}],
            "enumeration_hint": [
                {
                    "topic0": "0xaaa",
                    "topics_to_keys": {1: 0},
                    "data_to_keys": {},
                    "direction": "add",
                    "event_signature": "Registered(address)",
                    "event_name": "Registered",
                    "mapping_name": mapping,
                    "key_position": 0,
                    "indexed_positions": [0],
                    "value_position": None,
                    "writer_function": "register(address)",
                }
            ],
        },
    }
    if authority_role is not None:
        leaf["authority_role"] = authority_role
    if confidence is not None:
        leaf["confidence"] = confidence
    return {"schema_version": "semantic", "trees": {"f()": {"op": "LEAF", "leaf": leaf}}}


@pytest.mark.parametrize(
    "shape",
    [
        {"authority_role": "business", "operator": "falsy", "confidence": "low"},
        {"authority_role": "business", "operator": "truthy"},
        {"authority_role": "caller_authority", "operator": "falsy"},
        {"authority_role": "caller_authority", "operator": "truthy", "confidence": "low"},
        {"authority_role": None, "operator": "truthy"},
    ],
    ids=["business_falsy_low", "business_truthy", "authority_falsy", "authority_low_conf", "role_absent"],
)
def test_mapping_writer_specs_skip_non_authority_leaves(shape):
    assert _mapping_writer_specs_from_predicate_trees(_membership_tree(**shape)) == []


def test_mapping_writer_specs_skip_a_mapping_with_only_removals():
    # MasterMinter ``controllers``: adds are value writes, so a present-set replay of the removals names no one.
    artifact = _membership_tree(mapping="controllers")
    hint = artifact["trees"]["f()"]["leaf"]["set_descriptor"]["enumeration_hint"][0]
    hint.update({"direction": "remove", "event_signature": "ControllerRemoved(address)"})
    assert _mapping_writer_specs_from_predicate_trees(artifact) == []


def test_replay_mapping_principals_skips_self_membership(monkeypatch):
    contract = "0x9f26d4c958fd811a1f59b01b86be7dffc9d20761"
    member = "0xcccccccccccccccccccccccccccccccccccccccc"
    monkeypatch.setenv("ENVIO_API_TOKEN", "test-token")
    monkeypatch.setattr(
        "services.resolution.creation_block_floor.resolve_scan_floor",
        lambda address, chain_id: 100,
    )

    def fake_enumerate(address, specs, *, chain, bearer_token, from_block):
        return {
            "principals": [
                {
                    "address": contract.upper().replace("0X", "0x"),
                    "mapping_name": "_roles",
                    "last_seen_block": 123,
                    "direction_history": ["add"],
                },
                {
                    "address": member,
                    "mapping_name": "_roles",
                    "last_seen_block": 124,
                    "direction_history": ["add"],
                },
            ],
            "status": "complete",
            "pages_fetched": 1,
            "last_block_scanned": 200,
        }

    monkeypatch.setattr(
        "services.resolution.mapping_enumerator.enumerate_mapping_allowlist_sync",
        fake_enumerate,
    )

    nodes: dict = {}
    edges: dict = {}
    status = recursive._replay_mapping_principals(
        address=contract,
        mapping_specs=[
            {
                "mapping_name": "_roles",
                "event_signature": "RolesUpdated(address,uint256)",
                "event_name": "RolesUpdated",
                "key_position": 0,
                "key_positions_by_index": {0: 0},
                "indexed_positions": [0],
                "direction": "add",
                "writer_function": "grantRoles(address,uint256)",
                "value_position": None,
            }
        ],
        contract_node_id=f"address:{contract}",
        depth=0,
        nodes=nodes,
        edges=edges,
        chain_id=1,
    )
    assert status.status == "complete"
    assert status.source == "hypersync"
    edge_list = list(edges.values())
    assert [(e["from_id"], e["to_id"], e["relation"]) for e in edge_list] == [
        (f"address:{contract}", f"address:{member}", "mapping_member")
    ]
    assert f"address:{contract}" not in nodes


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
                    # The fixture relied on the old absent-means-controller_value default.
                    "authority_provenance": "caller_gate",
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
                    "authority_provenance": "caller_gate",
                }
            },
        },
    )

    def fake_materialize(address, rpc_url, *, workspace_prefix, chain=None, chain_id=None):
        assert address == authority_address
        return authority_bundle

    def fake_classify(rpc_url, address, block_tag="latest", *, chain_id=None):
        if address == signer_address:
            return "eoa", {"address": signer_address}
        return "unknown", {"address": address}

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr("services.resolution.recursive.classify_resolved_address", fake_classify)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: (*fake_classify(rpc_url, address, block_tag), True),
    )

    graph, nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
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

    def fake_materialize(address, rpc_url, *, workspace_prefix, chain=None, chain_id=None):
        materialize_calls.append(address)
        return shared_bundle

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest", **_kw: ("unknown", {"address": address}),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: ("unknown", {"address": address}, True),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
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

    def fake_materialize(address, rpc_url, *, workspace_prefix, chain=None, chain_id=None):
        materialize_calls.append(address)
        assert address == role_holder_address
        return role_holder_bundle

    def fake_classify(rpc_url, address, block_tag="latest", *, chain_id=None):
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
        lambda rpc_url, address, block_tag="latest", **_kw: (*fake_classify(rpc_url, address, block_tag), True),
    )

    resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=3,
    )

    assert materialize_calls == [role_holder_address]


def test_materialize_contract_artifacts_builds_effective_permissions(monkeypatch):
    address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    monkeypatch.setattr(
        "services.resolution.recursive.classify_single",
        lambda address, rpc_url, **_kw: {"address": address, "type": "regular"},
        raising=False,
    )
    monkeypatch.setattr(
        "services.resolution.recursive.fetch",
        lambda _address, **_kw: {"ContractName": "TestContract"},
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
        lambda _plan, _rpc, **_kw: {
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
        chain="ethereum",
    )

    assert loaded.get("effective_permissions") is marker


# ---------------------------------------------------------------------------
# #122 — no-impl proxy must fail closed; #121 coupling — ClassificationIncompleteError propagates.
# ---------------------------------------------------------------------------


def test_resolve_control_graph_no_impl_proxy_controller_is_degraded(monkeypatch):
    """The shell's empty guard set must never enter nested_artifacts."""
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

    def fake_classify(address, rpc_url, *, chain_id=None):
        if address.lower() == diamond_address:
            return {"address": address, "type": "proxy", "proxy_type": "eip2535", "facets": ["0x" + "bb" * 20]}
        return {"address": address, "type": "regular"}

    monkeypatch.setattr("services.discovery.classifier.classify_single", fake_classify)

    graph, nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=2,
    )

    nodes = {node["address"]: node for node in graph["nodes"]}
    assert nodes[diamond_address]["analyzed"] is False
    assert "materialize_error" in nodes[diamond_address]["details"]
    assert "implementation unresolved" in str(nodes[diamond_address]["details"]["materialize_error"])
    assert diamond_address not in nested


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
        lambda address, chain_id=1: "GateSeal" if address == nested_address else None,
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
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
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=2,
    )

    assert all(edge["from_id"] != edge["to_id"] for edge in graph["edges"])


def _resolve_parity_helper(monkeypatch, fanout: str):
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

    def fake_materialize(address, rpc_url, *, workspace_prefix, chain=None, chain_id=None):
        return bundles_by_addr[address]

    def fake_classify(rpc_url, address, block_tag="latest", *, chain_id=None):
        return "eoa", {"address": address}

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr("services.resolution.recursive.classify_resolved_address", fake_classify)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: (*fake_classify(rpc_url, address, block_tag), True),
    )

    graph, nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=2,
    )
    return graph, nested


def test_resolve_control_graph_level_parallel_parity(monkeypatch):
    seq_graph, seq_nested = _resolve_parity_helper(monkeypatch, "1")
    par_graph, par_nested = _resolve_parity_helper(monkeypatch, "8")

    assert seq_graph["nodes"] == par_graph["nodes"]
    assert seq_graph["edges"] == par_graph["edges"]
    assert sorted(seq_nested.keys()) == sorted(par_nested.keys())


def test_resolve_control_graph_parallel_handles_partial_materialize_failure(monkeypatch):
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

    def fake_materialize(address, rpc_url, *, workspace_prefix, chain=None, chain_id=None):
        if address == bad_addr:
            raise RuntimeError("simulated materialize failure")
        return good_bundle

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}, True),
    )

    graph, nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=2,
    )

    by_addr = {(node.get("details") or {}).get("address"): node for node in graph["nodes"]}
    assert good_addr in by_addr
    assert bad_addr in by_addr
    assert by_addr[bad_addr]["analyzed"] is False
    assert "materialize_error" in by_addr[bad_addr]["details"]
    assert by_addr[good_addr]["analyzed"] is True
    assert good_addr in nested
    assert bad_addr not in nested


def _two_child_root_bundle(root_address, first_addr, second_addr):
    return _bundle(
        root_address,
        "Root",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Root",
            "block_number": 1,
            "controller_values": {
                f"external_contract:{name}": {
                    "source": name,
                    "value": addr,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": addr},
                }
                for name, addr in (("first", first_addr), ("second", second_addr))
            },
        },
    )


@pytest.mark.parametrize("fanout", ["1", "8"])
def test_storage_not_determined_escapes_resolve_control_graph(monkeypatch, fanout):
    """The BFS used to stamp ``analyzed=False`` and return normally on an unreachable bucket."""
    from db.storage import StorageContentNotDetermined

    monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)
    monkeypatch.setenv("PSAT_RESOLUTION_MATERIALIZE_FANOUT", fanout)
    root_address = "0x1111111111111111111111111111111111111111"
    good_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    unread_addr = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

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

    def fake_materialize(address, rpc_url, *, workspace_prefix, chain=None, chain_id=None):
        if address == unread_addr:
            raise StorageContentNotDetermined(
                "bucket unreachable",
                not_determined={"analysis_blob_key": "connection refused"},
            )
        return good_bundle

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}, True),
    )

    with pytest.raises(StorageContentNotDetermined):
        resolve_control_graph(
            root_artifacts=cast(LoadedArtifacts, _two_child_root_bundle(root_address, good_addr, unread_addr)),
            rpc_url="http://rpc.example",
            chain_id=1,
            max_depth=2,
        )


def test_storage_not_determined_from_resolution_is_retryable():
    """``StorageKeyMissing`` / ``StorageContentAbsent`` stay terminal (the bucket answered); ``StorageKeyAbsent`` is
    transient because nothing was asked.
    """
    from db.storage import (
        StorageContentAbsent,
        StorageContentNotDetermined,
        StorageKeyAbsent,
        StorageKeyMissing,
        StorageUnavailable,
    )
    from workers.retry_policy import classify

    assert classify(StorageContentNotDetermined("bucket unreachable")) == "transient"
    assert classify(StorageUnavailable("storage is not configured")) == "transient"
    assert classify(StorageKeyAbsent("row records no key")) == "transient"
    assert classify(StorageKeyMissing("artifacts/j/n")) == "terminal"
    assert classify(StorageContentAbsent("2/2 bodies proven absent")) == "terminal"
    assert not isinstance(StorageContentAbsent("x"), StorageContentNotDetermined)


def test_an_ordinary_materialize_failure_still_degrades_one_node(monkeypatch):
    """Negative control: a compile/RPC failure is about one contract, so the walk still finishes."""
    monkeypatch.setenv("PSAT_RESOLUTION_MATERIALIZE_FANOUT", "2")
    root_address = "0x1111111111111111111111111111111111111111"
    good_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    bad_addr = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

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

    def fake_materialize(address, rpc_url, *, workspace_prefix, chain=None, chain_id=None):
        if address == bad_addr:
            raise RuntimeError("forge build failed")
        return good_bundle

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", fake_materialize)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}, True),
    )

    graph, nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, _two_child_root_bundle(root_address, good_addr, bad_addr)),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=2,
    )

    by_addr = {(node.get("details") or {}).get("address"): node for node in graph["nodes"]}
    assert by_addr[bad_addr]["analyzed"] is False
    assert "forge build failed" in str(by_addr[bad_addr]["details"]["materialize_error"])
    assert by_addr[good_addr]["analyzed"] is True
    assert bad_addr not in nested


def test_callee_provenance_demotes_the_graph_edge(monkeypatch):
    """``call_target`` becomes ``external_call_target``, and a value with no provenance becomes
    ``controller_value_unattributed`` (one merge minted 37 such constants and mappings), excluded from
    ``CONTROL_EDGE_RELATIONS``.
    """
    root_address = "0x1111111111111111111111111111111111111111"
    gate_address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    callee_address = "0xcccccccccccccccccccccccccccccccccccccccc"
    legacy_address = "0xdddddddddddddddddddddddddddddddddddddddd"

    def _cv(source: str, value: str, provenance: str | None) -> dict:
        entry = {
            "source": source,
            "value": value,
            "block_number": 1,
            "observed_via": "eth_call",
            "resolved_type": "unknown",
            "details": {"address": value},
        }
        if provenance is not None:
            entry["authority_provenance"] = provenance
        return entry

    root_bundle = _bundle(
        root_address,
        "Vault",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Vault",
            "block_number": 1,
            "controller_values": {
                "external_contract:roleRegistry": _cv("roleRegistry", gate_address, "caller_gate"),
                "external_contract:eETH": _cv("eETH", callee_address, "call_target"),
                "external_contract:legacy": _cv("legacy", legacy_address, None),
            },
        },
    )

    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest", **_kw: ("unknown", {"address": address}),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: ("unknown", {"address": address}, True),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=1,
    )

    relations = {(edge["from_id"], edge["to_id"]): edge["relation"] for edge in graph["edges"]}
    assert relations[(f"address:{root_address}", f"address:{gate_address}")] == "controller_value"
    assert relations[(f"address:{root_address}", f"address:{callee_address}")] == "external_call_target"
    assert relations[(f"address:{root_address}", f"address:{legacy_address}")] == "controller_value_unattributed"

    notes = {(edge["from_id"], edge["to_id"]): edge["notes"] for edge in graph["edges"]}
    assert "authority_provenance=caller_gate" in notes[(f"address:{root_address}", f"address:{gate_address}")]
    assert "authority_provenance=call_target" in notes[(f"address:{root_address}", f"address:{callee_address}")]
    assert "authority_provenance=not_determined" in notes[(f"address:{root_address}", f"address:{legacy_address}")]

    # Demotion removes the control claim, not the address.
    assert any(node["address"] == callee_address for node in graph["nodes"])
    assert any(node["address"] == legacy_address for node in graph["nodes"])

    from db.models import CONTROL_EDGE_RELATIONS

    carries_authority = {edge["to_id"] for edge in graph["edges"] if edge["relation"] in CONTROL_EDGE_RELATIONS}
    assert f"address:{gate_address}" in carries_authority
    assert f"address:{callee_address}" not in carries_authority
    assert f"address:{legacy_address}" not in carries_authority


def test_analyzed_timelock_keeps_its_type_and_delay(monkeypatch):
    """``_ensure_node`` hardcoded ``contract``, so a timelock's own node lost its type and delay depending on walk
    order.
    """
    timelock_address = "0x1111111111111111111111111111111111111111"
    plain_address = "0x2222222222222222222222222222222222222222"

    plain_bundle = _bundle(
        plain_address,
        "PlainLogic",
        snapshot={
            "schema_version": "0.1",
            "contract_address": plain_address,
            "contract_name": "PlainLogic",
            "block_number": 2,
            "controller_values": {},
        },
    )
    root_bundle = _bundle(
        timelock_address,
        "EtherFiTimelock",
        snapshot={
            "schema_version": "0.1",
            "contract_address": timelock_address,
            "contract_name": "EtherFiTimelock",
            "block_number": 1,
            "controller_values": {
                "external_contract:logic": {
                    "source": "logic",
                    "value": plain_address,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "contract",
                    "details": {"address": plain_address},
                    "authority_provenance": "caller_gate",
                }
            },
        },
    )

    def fake_classify(rpc_url, address, block_tag="latest", **_kw):
        if address == timelock_address:
            return "timelock", {"address": timelock_address, "delay": 259200, "owner": None}
        return "contract", {"address": address}

    monkeypatch.setattr("services.resolution.recursive._materialize_contract_artifacts", lambda *a, **k: plain_bundle)
    monkeypatch.setattr("services.resolution.recursive.classify_resolved_address", fake_classify)
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: (*fake_classify(rpc_url, address, block_tag), True),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=2,
    )
    nodes = {node["address"]: node for node in graph["nodes"]}

    assert nodes[timelock_address]["analyzed"] is True
    assert nodes[timelock_address]["resolved_type"] == "timelock"
    assert nodes[timelock_address]["details"]["delay"] == 259200
    assert nodes[plain_address]["resolved_type"] == "contract"


def test_generic_type_never_overwrites_a_specific_one():
    nodes: dict = {}
    address = "0x1111111111111111111111111111111111111111"

    recursive._ensure_node(nodes, address=address, resolved_type="timelock", label="TL", depth=1, node_type="contract")
    recursive._ensure_node(
        nodes, address=address, resolved_type="contract", label="TL", depth=0, node_type="contract", analyzed=True
    )
    node = nodes[f"address:{address}"]
    assert node["resolved_type"] == "timelock"
    assert node["analyzed"] is True

    recursive._ensure_node(nodes, address=address, resolved_type="unknown", label="TL", depth=1, node_type="contract")
    assert nodes[f"address:{address}"]["resolved_type"] == "timelock"

    other = "0x2222222222222222222222222222222222222222"
    recursive._ensure_node(nodes, address=other, resolved_type="contract", label="C", depth=1, node_type="contract")
    recursive._ensure_node(nodes, address=other, resolved_type="safe", label="C", depth=1, node_type="principal")
    assert nodes[f"address:{other}"]["resolved_type"] == "safe"


def test_analysis_state_splits_the_analyzed_bool():
    """``analyzed=False`` is four populations.

    The field is absent on stored artifacts, so this pins the mapping; reachability binds the next real run.
    """
    max_depth = 6

    def node(**kw) -> ResolvedGraphNode:
        base: dict = {
            "id": "address:0x00",
            "address": "0x00",
            "node_type": "contract",
            "resolved_type": "contract",
            "label": "n",
            "contract_name": None,
            "depth": 1,
            "analyzed": False,
            "details": {},
            "artifacts": {},
        }
        base.update(kw)
        return cast(ResolvedGraphNode, base)

    assert recursive._analysis_state(node(analyzed=True), max_depth) == "analyzed"
    # A ``safe`` is the discriminating case: it is a contract.
    assert recursive._analysis_state(node(resolved_type="eoa"), max_depth) == "not_analyzable"
    assert recursive._analysis_state(node(resolved_type="zero"), max_depth) == "not_analyzable"
    assert recursive._analysis_state(node(resolved_type="safe"), max_depth) == "not_analyzable"
    assert recursive._analysis_state(node(details={"materialize_error": "boom"}), max_depth) == "attempt_failed"
    # A fact about our walk, not the address.
    assert recursive._analysis_state(node(depth=7), max_depth) == "beyond_depth_horizon"
    assert recursive._analysis_state(node(resolved_type="unknown"), max_depth) is None
    # A graph stored before the producer fix may carry ``"None"``.
    assert recursive._analysis_state(node(resolved_type="None"), max_depth) is None
    assert recursive._analysis_state(node(resolved_type=""), max_depth) is None
    assert recursive._analysis_state(node(depth=2), max_depth) is None

    assert (
        recursive._analysis_state(node(depth=7, details={"materialize_error": "boom"}), max_depth) == "attempt_failed"
    )

    for outside in ("eoa", "zero", "safe", "off_chain_witness"):
        assert recursive._analysis_state(node(resolved_type=outside), max_depth) != "not_a_contract"


def test_resolved_graph_stamps_analysis_state_on_every_node(monkeypatch):
    root_address = "0x1111111111111111111111111111111111111111"
    eoa_address = "0x2222222222222222222222222222222222222222"

    root_bundle = _bundle(
        root_address,
        "Root",
        snapshot={
            "schema_version": "0.1",
            "contract_address": root_address,
            "contract_name": "Root",
            "block_number": 1,
            "controller_values": {
                "state_variable:owner": {
                    "source": "owner",
                    "value": eoa_address,
                    "block_number": 1,
                    "observed_via": "eth_call",
                    "resolved_type": "eoa",
                    "details": {"address": eoa_address},
                }
            },
        },
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}, True),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=1,
    )
    states = {node["address"]: node.get("analysis_state") for node in graph["nodes"]}
    assert states[root_address] == "analyzed"
    assert states[eoa_address] == "not_analyzable"


def _role_principal_bundle(root_address: str, principal_address: str, resolved_type) -> dict:
    return _bundle(
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
                                    "address": principal_address,
                                    "resolved_type": resolved_type,
                                    "details": {"address": principal_address},
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )


def test_null_resolved_type_role_principal_is_not_determined_not_not_analyzable(monkeypatch):
    """R1/R4: never ``str(None)`` or a positive ``not_analyzable``."""
    root_address = "0x1111111111111111111111111111111111111111"
    principal_address = "0xcea8039076e35a825854c5c2f85659430b06ec96"

    def fake_classify(rpc_url, address, block_tag="latest", **_kw):
        if address == principal_address:
            return "unknown", {"address": address}
        return "contract", {"address": address}

    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest", **_kw: fake_classify(rpc_url, address, block_tag),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: (*fake_classify(rpc_url, address, block_tag), True),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, _role_principal_bundle(root_address, principal_address, None)),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=3,
    )

    nodes = {node["address"]: node for node in graph["nodes"]}
    principal_node = nodes[principal_address]
    assert principal_node["resolved_type"] == "unknown"
    assert principal_node.get("analysis_state") is None
    assert all(node["resolved_type"] != "None" for node in graph["nodes"])
    assert (
        f"address:{root_address}",
        "role_principal",
        f"address:{principal_address}",
    ) in {(edge["from_id"], edge["relation"], edge["to_id"]) for edge in graph["edges"]}


def test_null_resolved_type_role_principal_recovers_via_classification(monkeypatch):
    """``"None"`` also bypassed classification."""
    root_address = "0x1111111111111111111111111111111111111111"
    principal_address = "0xcccccccccccccccccccccccccccccccccccccccc"

    def fake_classify(rpc_url, address, block_tag="latest", **_kw):
        if address == principal_address:
            return "eoa", {"address": address}
        return "contract", {"address": address}

    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest", **_kw: fake_classify(rpc_url, address, block_tag),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: (*fake_classify(rpc_url, address, block_tag), True),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, _role_principal_bundle(root_address, principal_address, None)),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=3,
    )

    nodes = {node["address"]: node for node in graph["nodes"]}
    principal_node = nodes[principal_address]
    assert principal_node["resolved_type"] == "eoa"
    assert principal_node.get("analysis_state") == "not_analyzable"


def test_initial_graph_preseed_sanitizes_fabricated_none_type(monkeypatch):
    """``"None"`` would rank as a specific type."""
    root_address = "0x1111111111111111111111111111111111111111"
    stale_address = "0xdddddddddddddddddddddddddddddddddddddddd"

    initial_graph = {
        "schema_version": "0.1",
        "root_contract_address": root_address,
        "max_depth": 3,
        "nodes": [
            {
                "id": f"address:{stale_address}",
                "address": stale_address,
                "node_type": "principal",
                "resolved_type": "None",
                "label": "role principal",
                "contract_name": None,
                "depth": 1,
                "analyzed": False,
                "analysis_state": "not_analyzable",
                "details": {"address": stale_address},
                "artifacts": {},
            }
        ],
        "edges": [],
    }

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
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
        max_depth=3,
        initial_graph=cast(recursive.ResolvedControlGraph, initial_graph),
    )

    nodes = {node["address"]: node for node in graph["nodes"]}
    stale_node = nodes[stale_address]
    assert stale_node["resolved_type"] == "unknown"
    assert stale_node.get("analysis_state") is None
