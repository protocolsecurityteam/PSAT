from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

slither = pytest.importorskip("slither")

from services.resolution.predicate_evaluator import (  # noqa: E402
    EvaluationContext,
    _bind_callee_parameters,
    evaluate_tree,
)
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
    build_predicate_tree,
)
from tests.support.predicate_trees import _build_pipeline  # noqa: E402
from tests.support.slither_compile import _compile  # noqa: E402


def test_non_caller_or_side_condition_under_and_preserves_principals():
    owner = "0x" + "cd" * 20
    tree = {
        "op": "AND",
        "children": [
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "eq",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "msg_sender"},
                        {"source": "state_variable", "state_variable_name": "owner"},
                    ],
                    "references_msg_sender": True,
                    "expression": "msg.sender == owner",
                    "basis": [],
                },
            },
            {
                "op": "OR",
                "children": [
                    {
                        "op": "LEAF",
                        "leaf": {
                            "kind": "comparison",
                            "operator": "eq",
                            "authority_role": "business",
                            "operands": [],
                            "references_msg_sender": False,
                            "expression": "token transfer returned true",
                            "basis": ["safe_erc20_return_check"],
                        },
                    },
                    {
                        "op": "LEAF",
                        "leaf": {
                            "kind": "unsupported",
                            "operator": "truthy",
                            "authority_role": "business",
                            "operands": [],
                            "unsupported_reason": "solidity_call_abi.decode()_unsupported_as_gate",
                            "references_msg_sender": False,
                            "expression": "abi.decode(returnData, (bool))",
                            "basis": ["safe_erc20_return_check"],
                        },
                    },
                ],
            },
        ],
    }

    cap = evaluate_tree(cast(PredicateTree, tree), EvaluationContext(state_var_values={"owner": owner}))

    assert cap.kind == "finite_set"
    assert cap.members == [owner]
    assert [c.description for c in cap.conditions] == ["token transfer returned true OR abi.decode(returnData, (bool))"]


def test_external_bool_descriptor_populates_check_target_and_selector(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IAuthority {
            function permitted(address who, bytes32 role) external view returns (bool);
        }
        contract C {
            bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
            IAuthority public authority;
            function f() external view {
                require(authority.permitted(msg.sender, OPERATOR_ROLE));
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    authority_addr = "0x" + "12" * 20
    ctx = EvaluationContext(state_var_values={"authority": authority_addr})
    cap = evaluate_tree(trees["f()"], ctx)
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.target_address == authority_addr
    assert cap.check.target_call_selector is not None
    assert cap.check.extra["callee_signature"] == "permitted(address,bytes32)"


def test_state_variable_member_path_equality_uses_projected_controller_value():
    payout = "0x2222222222222222222222222222222222222222"
    tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "operator": "eq",
            "authority_role": "caller_authority",
            "operands": [
                {"source": "msg_sender"},
                {
                    "source": "state_variable",
                    "state_variable_name": "accountantState",
                    "member_path": ["payoutAddress"],
                },
            ],
            "references_msg_sender": True,
            "parameter_indices": [],
            "expression": "msg.sender == accountantState.payoutAddress",
            "basis": [],
        },
    }
    cap = evaluate_tree(
        cast(PredicateTree, tree),
        EvaluationContext(state_var_values={"accountantState.payoutAddress": payout}),
    )
    assert cap.kind == "finite_set"
    assert cap.members == [payout]
    assert cap.membership_quality == "exact"


def test_self_address_equality_resolves_to_contract_principal():
    contract_address = "0x" + "12" * 20
    tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "operator": "eq",
            "authority_role": "caller_authority",
            "operands": [{"source": "msg_sender"}, {"source": "self_address"}],
            "references_msg_sender": True,
            "parameter_indices": [],
            "expression": "msg.sender == address(this)",
            "basis": [],
        },
    }

    cap = evaluate_tree(tree, EvaluationContext(contract_address=contract_address))  # pyright: ignore[reportArgumentType]

    assert cap.kind == "finite_set"
    assert cap.members == [contract_address]
    assert cap.membership_quality == "exact"


def test_inlined_callee_msg_sender_equality_is_call_edge_condition(monkeypatch):
    from eth_utils.crypto import keccak

    import db.queue as queue_mod
    import services.resolution.capability_resolver as resolver_mod
    import services.resolution.external_check_materializer as materializer_mod
    from services.resolution.adapters import AdapterRegistry, CallFrame
    from services.resolution.adapters import EvaluationContext as ResolverContext
    from services.resolution.predicate_evaluator import evaluate_tree_with_registry

    target_addr = "0x" + "11" * 20
    authority_addr = "0x" + "22" * 20
    manager_addr = "0x" + "33" * 20
    root_selector = "0x" + keccak(text="burn(uint256)").hex()[:8]
    burn_selector = "0x" + keccak(text="burnShares(address,uint256)").hex()[:8]

    target_tree = {
        "op": "AND",
        "children": [
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "eq",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "msg_sender"},
                        {"source": "state_variable", "state_variable_name": "manager"},
                    ],
                    "references_msg_sender": True,
                },
            },
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "operands": [{"source": "msg_sender"}, {"source": "parameter", "parameter_index": 0}],
                    "set_descriptor": {
                        "kind": "external_set",
                        "authority_contract": {
                            "address_source": {"source": "state_variable", "state_variable_name": "token"}
                        },
                        "callee_signature": "burnShares(address,uint256)",
                        "callee_selector": burn_selector,
                    },
                    "references_msg_sender": True,
                },
            },
        ],
    }
    authority_artifact = {
        "schema_version": "semantic",
        "contract_name": "RenamedToken",
        "trees": {
            "burnShares(address,uint256)": {
                "op": "AND",
                "children": [
                    {
                        "op": "LEAF",
                        "leaf": {
                            "kind": "equality",
                            "operator": "eq",
                            "authority_role": "caller_authority",
                            "operands": [
                                {"source": "msg_sender"},
                                {"source": "state_variable", "state_variable_name": "liquidityPool"},
                            ],
                            "references_msg_sender": True,
                        },
                    },
                    {
                        "op": "LEAF",
                        "leaf": {
                            "kind": "comparison",
                            "operator": "gte",
                            "authority_role": "business",
                            "operands": [{"source": "parameter", "parameter_index": 1}],
                            "expression": "shares[user] >= amount",
                            "references_msg_sender": False,
                        },
                    },
                ],
            }
        },
    }

    job = SimpleNamespace(id="authority-job", address=authority_addr)
    monkeypatch.setattr(
        resolver_mod,
        "find_analysis_job_for_address",
        lambda *_args, **_kwargs: SimpleNamespace(analysis_job=job, runtime_job=job),
    )
    monkeypatch.setattr(
        resolver_mod, "_load_state_var_values", lambda *_args, **_kwargs: {"liquidityPool": target_addr}
    )
    monkeypatch.setattr(queue_mod, "get_artifact", lambda *_args, **_kwargs: authority_artifact)
    monkeypatch.setattr(
        materializer_mod,
        "materialize_external_check_from_events",
        lambda **_kwargs: pytest.fail("exact call-edge equality should not materialize"),
    )

    ctx = ResolverContext(
        chain_id=1,
        contract_address=target_addr,
        state_var_values={"manager": manager_addr, "token": authority_addr},
        session=object(),
        call_frame=CallFrame.root(
            contract_address=target_addr,
            function_signature="burn(uint256)",
            function_selector=root_selector,
        ),
    )

    cap = evaluate_tree_with_registry(target_tree, AdapterRegistry(), ctx)  # pyright: ignore[reportArgumentType]

    assert cap.kind == "finite_set"
    assert cap.members == [manager_addr]
    assert cap.membership_quality == "exact"


def test_view_call_mapping_key_expands_to_returned_role_members(monkeypatch):
    import services.resolution.predicate_evaluator.membership as evaluator_mod
    from services.resolution.capabilities import CapabilityExpr
    from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree

    admin_role = "0x" + "aa" * 32
    member = "0x" + "44" * 20
    calls = []

    class Adapter:
        _outer_ctx = SimpleNamespace(
            session=object(),
            rpc_url="http://rpc",
            contract_address="0x" + "11" * 20,
            chain_id=1,
            block=None,
        )

        def enumerate(self, descriptor, contract_address):
            calls.append((descriptor, contract_address))
            assert descriptor["key_sources"][0] == {"source": "constant", "constant_value": admin_role}
            return CapabilityExpr.finite_set([member], quality="exact", confidence="enumerable")

    monkeypatch.setattr(
        evaluator_mod,
        "_observed_event_key_words",
        lambda **_kwargs: evaluator_mod.ObservedKeyWords(words=["0x" + "bb" * 32], complete=True),
    )
    monkeypatch.setattr(
        evaluator_mod,
        "_call_unary_bytes32_view",
        lambda **_kwargs: [admin_role],
    )

    tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "membership",
            "operator": "truthy",
            "authority_role": "caller_authority",
            "operands": [
                {"source": "view_call", "callee_signature": "adminOf(bytes32)", "callee_selector": "0x12345678"},
                {"source": "msg_sender"},
            ],
            "set_descriptor": {
                "kind": "mapping_membership",
                "storage_var": "_roles",
                "key_sources": [
                    {"source": "view_call", "callee_signature": "adminOf(bytes32)", "callee_selector": "0x12345678"},
                    {"source": "msg_sender"},
                ],
                "enumeration_hint": [{"topic0": "0x" + "12" * 32, "direction": "add"}],
            },
            "references_msg_sender": True,
            "parameter_indices": [],
        },
    }

    cap = evaluate_tree(tree, EvaluationContext(contract_address="0x" + "11" * 20, adapter=Adapter()))  # pyright: ignore[reportArgumentType]

    assert cap.kind == "finite_set"
    assert cap.members == [member]
    assert calls


def test_delegated_opaque_checker_materializes_with_zero_arg_getter(monkeypatch):
    from eth_utils.crypto import keccak

    import db.queue as queue_mod
    import services.clients.rpc as rpc_mod
    import services.resolution.capability_resolver as resolver_mod
    import services.resolution.external_check_materializer as materializer_mod
    from services.resolution.adapters import AdapterRegistry, CallFrame
    from services.resolution.adapters import EvaluationContext as ResolverContext
    from services.resolution.capabilities import CapabilityExpr
    from services.resolution.predicate_evaluator import evaluate_tree_with_registry

    target_addr = "0x" + "11" * 20
    authority_addr = "0x" + "22" * 20
    member = "0x" + "33" * 20
    role_word = "0x" + "12" * 32
    checker_selector = "0x" + keccak(text="hasRole(bytes32,address)").hex()[:8]
    role_selector = "0x" + keccak(text="PROTOCOL_PAUSER()").hex()[:8]
    root_selector = "0x" + keccak(text="pause()").hex()[:8]

    target_tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "external_bool",
            "operator": "truthy",
            "authority_role": "delegated_authority",
            "operands": [
                {
                    "source": "external_call",
                    "callee": "PROTOCOL_PAUSER",
                    "callee_signature": "PROTOCOL_PAUSER()",
                    "callee_selector": role_selector,
                },
                {"source": "msg_sender"},
            ],
            "set_descriptor": {
                "kind": "external_set",
                "authority_contract": {
                    "address_source": {"source": "state_variable", "state_variable_name": "authority"}
                },
                "callee_signature": "hasRole(bytes32,address)",
                "callee_selector": checker_selector,
            },
            "references_msg_sender": True,
            "parameter_indices": [],
            "expression": "authority.hasRole(authority.PROTOCOL_PAUSER(), msg.sender)",
            "basis": [],
        },
    }
    authority_artifact = {
        "schema_version": "semantic",
        "contract_name": "OpaqueRoleRegistry",
        "trees": {},
        "check_trees": {
            "hasRole(bytes32,address)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "truthy",
                    "authority_role": "business",
                    "operands": [{"source": "computed", "computed_kind": "sload(uint256)"}],
                    "expression": "return hasRole(bytes32,address)",
                    "basis": ["bool-return predicate"],
                },
            }
        },
    }

    job = SimpleNamespace(id="authority-job", address=authority_addr)
    monkeypatch.setattr(
        resolver_mod,
        "find_analysis_job_for_address",
        lambda *_args, **_kwargs: SimpleNamespace(analysis_job=job, runtime_job=job),
    )
    monkeypatch.setattr(resolver_mod, "_load_state_var_values", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(queue_mod, "get_artifact", lambda *_args, **_kwargs: authority_artifact)

    rpc_calls = []

    def fake_rpc_request(_rpc_url, method, params, retries=1, *, chain_id=None):
        rpc_calls.append((method, params, retries))
        assert method == "eth_call"
        assert params[0]["to"] == authority_addr
        assert params[0]["data"] == role_selector
        return role_word

    monkeypatch.setattr(rpc_mod, "rpc_request", fake_rpc_request)

    materialize_calls = []

    def fake_materialize(**kwargs):
        materialize_calls.append(kwargs)
        return CapabilityExpr.finite_set(
            [member],
            quality="lower_bound",
            confidence="partial",
            trace=[{"step": "external_check_materialized"}],
        )

    monkeypatch.setattr(materializer_mod, "materialize_external_check_from_events", fake_materialize)

    ctx = ResolverContext(
        chain_id=1,
        contract_address=target_addr,
        rpc_url="http://rpc",
        state_var_values={"authority": authority_addr},
        session=object(),
        call_frame=CallFrame.root(
            contract_address=target_addr,
            function_signature="pause()",
            function_selector=root_selector,
        ),
    )

    cap = evaluate_tree_with_registry(target_tree, AdapterRegistry(), ctx)  # pyright: ignore[reportArgumentType]

    assert cap.kind == "finite_set"
    assert cap.members == [member]
    assert rpc_calls
    assert materialize_calls
    assert materialize_calls[0]["call_args"] == [
        {"source": "constant", "constant_value": role_word},
        {"source": "root_caller"},
    ]


# An unclassifiable caller gate used to fall through to a business side-condition and default public; denylist and
# claim-once siblings stay open.


def test_caller_equals_external_getter_resolves_gated(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IRegistry { function admin() external view returns (address); }
        contract C {
            IRegistry public registry;
            function f() external view {
                require(msg.sender == registry.admin(), "not admin");
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f()"])
    assert cap.kind == "external_check_only", (
        f"caller==external.getter() must be a gated external check, got {cap.kind} "
        "(a regression to the business→conditional_universal→public false-open)"
    )


def test_caller_keyed_denylist_membership_stays_open(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) registered;
            function f() external {
                require(!registered[msg.sender]);
                registered[msg.sender] = true;
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f()"])
    assert cap.kind == "conditional_universal", (
        f"a falsy claim-once denylist must stay open, got {cap.kind} (over-gating regression)"
    )


def test_observed_event_key_words_hypersync_floors_from_block(monkeypatch):
    import hypersync

    import services.resolution.creation_block_floor as floor_mod
    from services.resolution.predicate_evaluator import _observed_event_key_words_from_hypersync

    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: 7_000_000)

    captured: dict = {}

    def _query(*, from_block, to_block, logs, field_selection):
        captured["from_block"] = from_block
        return SimpleNamespace(from_block=from_block)

    class _Client:
        def __init__(self, *_a, **_k):
            pass

        async def get(self, _query):
            return SimpleNamespace(data=None, logs=[], next_block=None)

    monkeypatch.setattr(hypersync, "Query", _query)
    monkeypatch.setattr(hypersync, "HypersyncClient", _Client)

    event_addr = "0x" + "33" * 20
    descriptor = {"key_sources": [{"source": "msg_sender"}]}
    hints = [{"topic0": "0x" + "ab" * 32, "event_address": event_addr, "topics_to_keys": {1: 0}}]
    outer = SimpleNamespace(meta={}, chain_id=1, block=8_000_000)

    _observed_event_key_words_from_hypersync(
        outer_ctx=outer, descriptor=cast(Any, descriptor), event_hints=hints, key_index=0
    )

    assert captured["from_block"] == 7_000_000 - 1


# Only gate-shaped leaves may be restored to delegated authority after binding.


def _leaves(tree: Any) -> list[dict[str, Any]]:
    if not isinstance(tree, dict):
        return []
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        return [cast(dict[str, Any], leaf)] if isinstance(leaf, dict) else []
    out: list[dict[str, Any]] = []
    for child in tree.get("children") or []:
        out.extend(_leaves(child))
    return out


def test_bound_view_acl_leaf_promotes_to_delegated_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IACL { function isOperator(address who) external view returns (bool); }
        contract Registry {
            IACL public acl;
            function check(address who) external returns (bool) {
                require(acl.isOperator(who), "not operator");
                return true;
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "Registry")
    tree = build_predicate_tree(next(f for f in contract.functions if f.full_name == "check(address)"))
    leaf = _leaves(tree)[0]
    assert (leaf["kind"], leaf["authority_role"], leaf["callee_state_mutability"]) == (
        "external_bool",
        "business",
        "view",
    )
    bound = _bind_callee_parameters(cast(PredicateTree, tree), [{"source": "root_caller"}])
    bound_leaf = _leaves(bound)[0]
    assert bound_leaf["authority_role"] == "delegated_authority"
    assert bound_leaf["references_msg_sender"] is True
