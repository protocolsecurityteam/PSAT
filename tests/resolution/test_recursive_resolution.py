import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schemas.resolved_control_graph import ResolvedGraphEdge, ResolvedGraphNode
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
def _default_classify(monkeypatch):
    """Default the address classifier to the generic answer.

    An analysed contract's node now takes its ``resolved_type`` from the
    classifier instead of a hardcoded ``"contract"``, so every walk classifies
    at least its root. Tests that care about a specific classification override
    this in-body (monkeypatch inside the test wins over an autouse fixture);
    this keeps the rest off the wire — without it the offline guard reports
    blocked ``rpc.example`` calls.
    """
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
    """The failed-node name lookup fetches verified source from Etherscan; default
    to None offline (tests that assert a specific name override this in-body)."""
    monkeypatch.setattr("services.resolution.recursive._contract_name_for_address", lambda address, chain_id=1: None)


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


def _membership_tree(*, operator="truthy", authority_role="caller_authority", confidence=None, mapping="registered"):
    """One-leaf predicate-tree artifact with an enumeration hint, discriminators overridable."""
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
        # A business membership read (NodeOperatorManager's `registered`
        # duplicate-enrolment guard) proves nothing about authority.
        {"authority_role": "business", "operator": "falsy", "confidence": "low"},
        # Role gate alone: business + truthy is still not an authority leaf.
        {"authority_role": "business", "operator": "truthy"},
        # Polarity gate alone: a falsy membership check is an anti-gate
        # (denylist / already-enrolled) — its members are the blocked set.
        {"authority_role": "caller_authority", "operator": "falsy"},
        # Explicit low confidence from the static plane disqualifies.
        {"authority_role": "caller_authority", "operator": "truthy", "confidence": "low"},
        # Absent role is a pre-schema tree: not determined, nothing earned.
        {"authority_role": None, "operator": "truthy"},
    ],
    ids=["business_falsy_low", "business_truthy", "authority_falsy", "authority_low_conf", "role_absent"],
)
def test_mapping_writer_specs_skip_non_authority_leaves(shape):
    assert _mapping_writer_specs_from_predicate_trees(_membership_tree(**shape)) == []


def test_mapping_writer_specs_keep_authority_leaf_with_explicit_confidence():
    # Positive arm of the confidence discriminator: medium/high pass through.
    specs = _mapping_writer_specs_from_predicate_trees(
        _membership_tree(authority_role="caller_authority", operator="truthy", confidence="high")
    )
    assert [spec["mapping_name"] for spec in specs] == ["registered"]


def test_replay_mapping_principals_skips_self_membership(monkeypatch):
    """A contract enumerated as a member of its own mapping (timelock granting
    itself a `_roles` role) must not publish a degenerate X->X control edge."""
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
                # Mixed case on purpose: the skip must normalize.
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
    assert status == "complete"
    edge_list = list(edges.values())
    # Positive arm: the real member IS published.
    assert [(e["from_id"], e["to_id"], e["relation"]) for e in edge_list] == [
        (f"address:{contract}", f"address:{member}", "mapping_member")
    ]
    # The self member neither edges nor re-enters the node map as a principal.
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
                    # A real gating authority carries this from the static stage
                    # (the gate/callee provenance split). The fixture predates it
                    # and was relying on the old absent-means-controller_value
                    # default, since replaced by the honest
                    # ``controller_value_unattributed`` — so the gate this test
                    # is about now has to say it is a gate. The recursion the
                    # test exercises is relation-independent
                    # (``_maybe_queue_address`` keys on resolved_type).
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


# test_materialize_contract_artifacts_tolerates_slither_cli_failure was
# deleted in commit 438a11c (Slither CLI subprocess rip-out). The
# materialize path no longer invokes the CLI, so the failure-tolerance
# test no longer has a code path to exercise.


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
        lambda address, rpc_url, **_kw: {
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

    def _raise(address, rpc_url, *, chain_id=None):
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
        lambda address, rpc_url, **_kw: {"address": address, "type": "proxy", "implementation": impl},
    )

    captured: dict = {}

    def fake_cache(*, effective_address, bytecode_keccak, workspace_prefix, chain=None):
        captured["effective_address"] = effective_address
        analysis = {"subject": {"address": effective_address, "name": "Impl"}}
        plan = {"contract_address": effective_address, "controllers": []}
        return "Impl", analysis, plan, None

    monkeypatch.setattr(recursive, "_materialize_with_cross_process_cache", fake_cache)
    monkeypatch.setattr(recursive, "build_control_snapshot", lambda _plan, _rpc, **_kw: {"controllers": []})
    monkeypatch.setattr(recursive, "_build_effective_permissions", lambda _a, _s: {"functions": []})

    loaded = _materialize_contract_artifacts(proxy, "http://rpc.example", workspace_prefix="t")

    assert captured["effective_address"] == impl  # retargeted to the logic contract
    assert loaded["analysis"]["subject"]["address"] == impl


def test_materialize_contract_artifacts_swallows_generic_classify_error(monkeypatch):
    """The restructure preserves the historical swallow: a *generic* classify
    error (not ClassificationIncompleteError, not a no-impl proxy) degrades to
    analyze-the-address-as-is and never propagates."""
    addr = "0x" + "33" * 20

    def _raise_generic(address, rpc_url, *, chain_id=None):
        raise RuntimeError("classify hiccup")

    monkeypatch.setattr("services.discovery.classifier.classify_single", _raise_generic)

    captured: dict = {}

    def fake_cache(*, effective_address, bytecode_keccak, workspace_prefix, chain=None):
        captured["effective_address"] = effective_address
        analysis = {"subject": {"address": effective_address, "name": "AsIs"}}
        plan = {"contract_address": effective_address, "controllers": []}
        return "AsIs", analysis, plan, None

    monkeypatch.setattr(recursive, "_materialize_with_cross_process_cache", fake_cache)
    monkeypatch.setattr(recursive, "build_control_snapshot", lambda _plan, _rpc, **_kw: {"controllers": []})
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
        lambda address, rpc_url, *, workspace_prefix, chain=None: (_ for _ in ()).throw(
            RuntimeError("nested compile failed")
        ),
    )

    graph, _nested = resolve_control_graph(
        root_artifacts=cast(LoadedArtifacts, root_bundle),
        rpc_url="http://rpc.example",
        chain_id=1,
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
    # Failed sibling is recorded as unanalyzed with the materialize_error
    # surfaced on details — same surface as the prior sequential code path.
    assert by_addr[bad_addr]["analyzed"] is False
    assert "materialize_error" in by_addr[bad_addr]["details"]
    assert by_addr[good_addr]["analyzed"] is True
    assert good_addr in nested
    assert bad_addr not in nested


def test_unreadable_materialization_does_not_become_an_empty_analysis(monkeypatch):
    """Not-determined must never be recorded as proven-absent, at
    ``_materialize_with_cross_process_cache``.

    ``hydrate_*`` returning ``None`` for an unreadable blob met ``or {}``
    here, so a bucket outage produced a contract with no functions, no plan and
    no predicate trees — and that state is what the effects probe is seeded
    from and what gets cached under the witness schema version.

    This pins only the raise. Whether it survives the BFS above is a separate
    question with its own test below; asserting only here is how the previous
    attempt shipped a safety property that did not exist in the running system.
    """
    from db import contract_materializations as cm
    from db.storage import StorageContentNotDetermined

    monkeypatch.setattr(cm, "is_enabled", lambda: True)
    monkeypatch.setattr(cm, "materialize_or_wait", lambda **_kw: SimpleNamespace(contract_name="C"))
    monkeypatch.setattr(
        cm,
        "hydrate_analysis",
        lambda _row: (_ for _ in ()).throw(StorageContentNotDetermined("bucket unreachable")),
    )

    with pytest.raises(StorageContentNotDetermined):
        recursive._materialize_with_cross_process_cache(
            effective_address="0x" + "44" * 20,
            bytecode_keccak="0x" + "aa" * 32,
            workspace_prefix="t",
            chain="ethereum",
        )


def _two_child_root_bundle(root_address, first_addr, second_addr):
    """Root snapshot pointing at two nested contracts, for the BFS tests."""
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
    """The unreadable-materialization failure must escape the BFS, at the
    altitude where the BFS actually handles it.

    ``_materialize_for_pending`` wraps every failure into ``(None, exc)``, and
    the caller turns that into a node stamped ``analyzed=False`` and walks on —
    so ``resolve_control_graph`` returned NORMALLY on an unreachable bucket and
    no stage above it ever saw a failure to retry. A graph that returns
    normally is a finished answer about the protocol's control chain, assembled
    from contracts we could not read.

    Parametrised over serial and fan-out because the two paths handle
    exceptions differently inside ``parallel_map``.
    """
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
    """The other half. Escaping the BFS only helps if the worker
    then re-runs the stage — ``classify`` fell through to ``terminal``, so
    ``BaseWorker`` computed ``will_retry=False`` and the job died on attempt
    one with the same 'we could not read it' state it started with.

    ``StorageKeyMissing`` / ``StorageContentAbsent`` stay terminal on purpose:
    those are determined facts (the bucket was asked and answered), and retrying
    re-asks an answered question. ``StorageContentAbsent`` is the collection-read
    form of the first, and it exists because the collection reads used to raise
    the *transient* class for a proven-absent object — the same key read directly
    classified terminal, so the comment stating this invariant was false one
    layer up.

    ``StorageKeyAbsent`` is transient with the other two not-determined classes.
    It was terminal here while ``db/storage.py`` defined it as *not determined*;
    the row records no key and holds no inline body, so nothing was ever asked
    and only a re-run can produce the answer. The row is written by the inline
    path when the backend is unconfigured — the same condition
    ``StorageUnavailable`` already retried on, one row later.
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
    # The type hierarchy is the discriminator, so pin it: a consumer catching
    # "we could not find out" must not silently absorb "we found out, it's gone".
    assert not isinstance(StorageContentAbsent("x"), StorageContentNotDetermined)


def test_an_ordinary_materialize_failure_still_degrades_one_node(monkeypatch):
    """NEGATIVE CONTROL for the two tests above.

    A compile/RPC/proxy failure is a fact about that one contract, and the walk
    must still record it as an unanalyzed node and finish. If this went red,
    the fix would have converted every per-contract hiccup into a whole-job
    failure — the opposite over-correction.
    """
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
    """A controller value whose static provenance is ``call_target`` is wired as
    ``external_call_target``, not ``controller_value``.

    Positive control (``roleRegistry``, ``caller_gate``) must stay a control
    edge; negative control (``eETH``, ``call_target``) must not.

    THIRD ARM AMENDED: a value with NO provenance
    used to stay ``controller_value``, on the reading that not-determined must
    not demote a real authority. That rule protects a proven authority from
    being relabelled a mere callee — it does not license an authority CLAIM over
    a target for which neither question was answered. Widening the predicate-tree
    surface minted 37 such targets in one merge (pure constants like
    HUNDRED_PERCENT_IN_BPS, non-authority mappings like ``_balances``), and each
    would have persisted as a control edge feeding the authority closure. The
    not-determined input now reaches the not-determined relation
    ``controller_value_unattributed``: published (the address stays visible),
    excluded from ``CONTROL_EDGE_RELATIONS`` (it moves no authority).
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

    # The provenance is stated on the row, including the not-determined case,
    # so a reader of the persisted edge never has to infer it from the relation.
    notes = {(edge["from_id"], edge["to_id"]): edge["notes"] for edge in graph["edges"]}
    assert "authority_provenance=caller_gate" in notes[(f"address:{root_address}", f"address:{gate_address}")]
    assert "authority_provenance=call_target" in notes[(f"address:{root_address}", f"address:{callee_address}")]
    assert "authority_provenance=not_determined" in notes[(f"address:{root_address}", f"address:{legacy_address}")]

    # The callee is still a NODE — it is a real contract the subject calls.
    # Demotion removes the control claim, not the address.
    assert any(node["address"] == callee_address for node in graph["nodes"])
    # ...and so is the unattributed target: the edge is published, it just
    # carries no authority.
    assert any(node["address"] == legacy_address for node in graph["nodes"])

    # The authority-bearing set is the allowlist, so only the proven gate moves
    # value through the closure.
    from db.models import CONTROL_EDGE_RELATIONS

    carries_authority = {edge["to_id"] for edge in graph["edges"] if edge["relation"] in CONTROL_EDGE_RELATIONS}
    assert f"address:{gate_address}" in carries_authority
    assert f"address:{callee_address}" not in carries_authority
    assert f"address:{legacy_address}" not in carries_authority


def test_analyzed_timelock_keeps_its_type_and_delay(monkeypatch):
    """An analysed contract must not be stamped with the generic type.

    ``_ensure_node`` was called with a hardcoded ``resolved_type="contract"``
    for every analysed node, so a timelock's OWN node came back typed
    ``contract`` with its ``delay`` missing. Whether the type survived depended
    on walk order — it did only when the node was later re-ensured as a
    controller of another contract.

    Positive control: the timelock root keeps ``timelock`` + ``delay``.
    Negative control: a plain contract analysed the same way stays
    ``contract`` — the fix must not invent a type the classifier did not give.
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
    """The rank fold, directly: ``contract`` is the generic answer and must not
    replace a classification that says more. Equal ranks keep last-write-wins."""
    nodes: dict = {}
    address = "0x1111111111111111111111111111111111111111"

    recursive._ensure_node(nodes, address=address, resolved_type="timelock", label="TL", depth=1, node_type="contract")
    recursive._ensure_node(
        nodes, address=address, resolved_type="contract", label="TL", depth=0, node_type="contract", analyzed=True
    )
    node = nodes[f"address:{address}"]
    assert node["resolved_type"] == "timelock"
    assert node["analyzed"] is True

    # unknown must not overwrite a real answer either, and a specific type may
    # still replace the generic one (the direction that adds information).
    recursive._ensure_node(nodes, address=address, resolved_type="unknown", label="TL", depth=1, node_type="contract")
    assert nodes[f"address:{address}"]["resolved_type"] == "timelock"

    other = "0x2222222222222222222222222222222222222222"
    recursive._ensure_node(nodes, address=other, resolved_type="contract", label="C", depth=1, node_type="contract")
    recursive._ensure_node(nodes, address=other, resolved_type="safe", label="C", depth=1, node_type="principal")
    assert nodes[f"address:{other}"]["resolved_type"] == "safe"


def test_analysis_state_splits_the_analyzed_bool():
    """``analyzed=False`` is four populations; ``analysis_state`` names which.

    The counts quoted for this field
    — 1,183 analyzed / 1,236 not_analyzable / 28 attempt_failed / 29
    beyond_depth_horizon / 55 not-determined — are a RECOMPUTATION of
    ``_analysis_state`` over the node dicts in the 107 stored
    resolved_control_graph artifacts, not a census of persisted values. The field
    itself is ABSENT on all 2,531 of those artifact nodes and SQL NULL on all
    2,506 ``control_graph_nodes`` rows, because the column is newer than the last
    analysis run. So the numbers say what the producer WOULD emit per branch, and
    nothing about what any stored row currently holds. This test pins the mapping;
    reachability of each branch on re-persisted rows binds the next real run.
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
    # Not an ANALYZABLE type — analysis was never applicable, so its absence
    # says nothing adverse. The token is ``not_analyzable``, never
    # ``not_a_contract``. A ``safe`` is the discriminating case, because a Safe
    # IS a contract (230 of the local corpus) — the old spelling asserted
    # something literally false about it.
    assert recursive._analysis_state(node(resolved_type="eoa"), max_depth) == "not_analyzable"
    assert recursive._analysis_state(node(resolved_type="zero"), max_depth) == "not_analyzable"
    assert recursive._analysis_state(node(resolved_type="safe"), max_depth) == "not_analyzable"
    # A fact about the contract.
    assert recursive._analysis_state(node(details={"materialize_error": "boom"}), max_depth) == "attempt_failed"
    # A fact about OUR walk, not the address. This is the one the bool could
    # never express and the reason graph_max_depth is persisted alongside.
    assert recursive._analysis_state(node(depth=7), max_depth) == "beyond_depth_horizon"
    # Not determined: no classification, so none of the four can be asserted.
    assert recursive._analysis_state(node(resolved_type="unknown"), max_depth) is None
    # An analyzable contract inside the horizon, unanalysed, with no recorded
    # failure: also not determined. Inventing a value here is the exact error
    # this field exists to remove.
    assert recursive._analysis_state(node(depth=2), max_depth) is None

    # A failed materialization outranks the depth check: the walk DID reach it.
    assert (
        recursive._analysis_state(node(depth=7, details={"materialize_error": "boom"}), max_depth) == "attempt_failed"
    )

    # Stated as the negation so a revert of the rename is caught even
    # if some future arm re-introduces the spelling elsewhere: the producer must
    # not mint the old token for ANY resolved_type outside ANALYZABLE_TYPES.
    for outside in ("eoa", "zero", "safe", "off_chain_witness"):
        assert recursive._analysis_state(node(resolved_type=outside), max_depth) != "not_a_contract"


def test_resolved_graph_stamps_analysis_state_on_every_node(monkeypatch):
    """The state reaches the artifact, so the worker can persist it."""
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
    """Root bundle whose effective_permissions grant role 1 to *principal_address*
    with the given ``resolved_type`` value PRESENT in the payload (the shape a
    policy-stage refresh feeds back in)."""
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
                                    # Key PRESENT with the given value — a .get
                                    # default never fires on this shape.
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
    """R1/R4 positive case for the ``str(None)`` -> ``"None"`` ->
    ``not_analyzable`` fabrication: a principal whose ``resolved_type`` is
    PRESENT with value ``None`` and whose classification does not answer must
    publish the not-determined pair (``unknown``, ``analysis_state=None``) —
    never the fabricated token, never the positive ``not_analyzable`` claim."""
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
    # The fabricated token appears nowhere in the published graph.
    assert all(node["resolved_type"] != "None" for node in graph["nodes"])
    # The role edge itself is still published — the fix must not drop the edge.
    assert (
        f"address:{root_address}",
        "role_principal",
        f"address:{principal_address}",
    ) in {(edge["from_id"], edge["relation"], edge["to_id"]) for edge in graph["edges"]}


def test_null_resolved_type_role_principal_recovers_via_classification(monkeypatch):
    """A present-but-null ``resolved_type`` used to mint ``"None"`` which,
    being != "unknown", also BYPASSED classification. Coerced to ``unknown``
    it now reaches the classifier; a determined non-analyzable answer (eoa)
    then legitimately publishes ``not_analyzable`` — the proven-firing control
    for the sentinel."""
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


def test_analysis_state_treats_fabricated_none_token_as_undetermined():
    """Defence in depth: a stored graph written before the producer fix can
    still carry the literal ``"None"`` into the policy refresh's recompute.
    ``_analysis_state`` must read it as undetermined, never as the positive
    ``not_analyzable`` claim — while a genuinely determined non-analyzable
    type still fires the sentinel."""
    node_none = {"analyzed": False, "details": {}, "resolved_type": "None", "depth": 1}
    node_eoa = {"analyzed": False, "details": {}, "resolved_type": "eoa", "depth": 1}
    node_empty = {"analyzed": False, "details": {}, "resolved_type": "", "depth": 1}
    assert recursive._analysis_state(cast(ResolvedGraphNode, node_none), 6) is None
    assert recursive._analysis_state(cast(ResolvedGraphNode, node_empty), 6) is None
    assert recursive._analysis_state(cast(ResolvedGraphNode, node_eoa), 6) == "not_analyzable"


def test_initial_graph_preseed_sanitizes_fabricated_none_type(monkeypatch):
    """The refresh path pre-seeds from the persisted artifact; a pre-fix
    artifact node carrying ``resolved_type="None"`` must come out of the walk
    as the not-determined pair, and must not outrank a later concrete answer
    (`"None"` would have ranked as a specific type)."""
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
    # The recompute at the end of the walk replaces the stale positive claim.
    assert stale_node.get("analysis_state") is None
