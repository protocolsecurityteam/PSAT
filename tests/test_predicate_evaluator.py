"""End-to-end tests: Solidity source → PredicateTree → CapabilityExpr.

Covers the bridge from week-2 (predicate builder) through week-3
(reentrancy/pause + writer-gate) to week-4 (capability evaluator)."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.resolution.predicate_evaluator import (  # noqa: E402
    EvaluationContext,
    _bind_callee_parameters,
    evaluate_tree,
)
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
    build_predicate_tree,
)
from services.static.contract_analysis_pipeline.reentrancy_pause import (  # noqa: E402
    apply_reentrancy_pause_pass,
)
from services.static.contract_analysis_pipeline.writer_gate import (  # noqa: E402
    apply_writer_gate_pass,
)


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _build_pipeline(contract):
    """Run the full week-1-through-3 pipeline to produce per-function
    PredicateTrees with classification mutations applied."""
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    apply_writer_gate_pass(contract, trees)
    apply_reentrancy_pause_pass(contract, trees)
    return trees


# ---------------------------------------------------------------------------
# End-to-end pipeline tests
# ---------------------------------------------------------------------------


def test_unguarded_function_yields_conditional_universal(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function f() external { x = 1; }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f()"])
    assert cap.kind == "conditional_universal"


def test_caller_equals_state_var_yields_finite_set_placeholder(tmp_path):
    """``require(msg.sender == owner)`` resolves to a finite_set
    placeholder (members empty until week-5 adapter reads
    state_variable on-chain). Confidence=partial reflects the gap."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            function f() external view {
                require(msg.sender == ownerVar);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f()"])
    assert cap.kind == "finite_set"
    assert cap.confidence == "partial"
    assert cap.membership_quality == "lower_bound"


def test_non_caller_unsupported_side_condition_preserves_principals():
    owner = "0x" + "ab" * 20
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
                "op": "LEAF",
                "leaf": {
                    "kind": "unsupported",
                    "operator": "truthy",
                    "authority_role": "business",
                    "operands": [],
                    "unsupported_reason": "opaque_try_catch",
                    "references_msg_sender": False,
                    "expression": "implementation compatibility check",
                    "basis": ["opaque_try_catch"],
                },
            },
        ],
    }

    cap = evaluate_tree(cast(PredicateTree, tree), EvaluationContext(state_var_values={"owner": owner}))

    assert cap.kind == "finite_set"
    assert cap.members == [owner]
    assert [c.description for c in cap.conditions] == ["implementation compatibility check"]


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


def test_renounce_role_self_service_pattern(tmp_path):
    """``require(account == msg.sender)`` — the canonical self-service
    pattern. Resolves to conditional_universal(self_service)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function renounce(address account) external {
                require(account == msg.sender);
                x = 1;
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["renounce(address)"])
    assert cap.kind == "conditional_universal"
    assert any(c.kind == "self_service" for c in cap.conditions)


def test_or_owner_or_business_yields_structural_or(tmp_path):
    """``require(msg.sender == owner || amount > cap)`` → OR root in
    the predicate tree → structural OR in the capability (per v3
    blocker #2 fix: business preserved under OR)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public cap;
            uint256 public x;
            function f(uint256 amount) external {
                require(msg.sender == ownerVar || amount > cap);
                x = amount;
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f(uint256)"])
    assert cap.kind == "OR"
    # finite_set (owner-resolved placeholder) + conditional_universal (business amount cap).
    assert len(cap.children) == 2
    kinds = sorted(c.kind for c in cap.children)
    assert "conditional_universal" in kinds


def test_two_keys_membership_yields_finite_set_lower(tmp_path):
    """``require(_members[role][msg.sender])`` — 2-key direct-promote
    to caller_authority. Without an adapter, the evaluator returns
    a lower_bound finite_set placeholder."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) _members;
            function f(bytes32 role) external view {
                require(_members[role][msg.sender]);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f(bytes32)"])
    assert cap.kind == "finite_set"
    assert cap.confidence == "partial"
    assert cap.membership_quality == "lower_bound"


def test_negated_membership_denylist_yields_cofinite(tmp_path):
    """``require(!_blacklist[msg.sender])`` is a denylist (``if (blacklist[caller])
    revert``): the function proceeds for anyone NOT on the list. With no enumerator,
    the membership branch normalizes the decline to an external check and ``negate``
    yields a lower_bound ``cofinite_blacklist`` — "anyone except an un-enumerated
    exclusion", which the surface projects to ``public``. (Part 2: previously this
    was discarded as ``unsupported(negate_partial_set)`` → under-resolved.)"""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            mapping(address => bool) public _blacklist;
            function setBlacklist(address user, bool val) external {
                require(msg.sender == ownerVar);
                _blacklist[user] = val;
            }
            function someAction() external view {
                require(!_blacklist[msg.sender]);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["someAction()"])
    assert cap.kind == "cofinite_blacklist"
    assert cap.blacklist_quality == "lower_bound"
    # Polarity safety: the SETTER stays gated — only the falsy denylist opens.
    setter = evaluate_tree(trees["setBlacklist(address,bool)"])
    assert setter.kind != "cofinite_blacklist"


def test_external_bool_yields_check_only(tmp_path):
    """``require(authority.canCall(msg.sender))`` →
    external_check_only capability with placeholder check info."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IAuthority {
            function canCall(address) external view returns (bool);
        }
        contract C {
            IAuthority public authority;
            function f() external view {
                require(authority.canCall(msg.sender));
            }
        }
    """,
    )
    # Pick the implementing contract, not the interface.
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f()"])
    assert cap.kind == "external_check_only"


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


def test_reentrancy_yields_conditional_universal(tmp_path):
    """A function with only a reentrancy guard yields
    conditional_universal — anyone, but reentrancy must hold."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 private _status;
            uint256 private constant _NOT_ENTERED = 1;
            uint256 private constant _ENTERED = 2;
            modifier nonReentrant() {
                require(_status != _ENTERED);
                _status = _ENTERED;
                _;
                _status = _NOT_ENTERED;
            }
            function f() external nonReentrant {}
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f()"])
    assert cap.kind == "conditional_universal"
    assert any(c.kind == "reentrancy" for c in cap.conditions)


def test_signature_auth_yields_signature_witness(tmp_path):
    """``require(msg.sender == ecrecover(...))`` → signature_witness
    with the signer being whatever the signature is required to
    match (in this case, msg.sender — odd but valid)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public signerAddr;
            function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) external view {
                require(signerAddr == ecrecover(h, v, r, s));
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f(bytes32,uint8,bytes32,bytes32)"])
    assert cap.kind == "signature_witness"


# ---------------------------------------------------------------------------
# Direct evaluator tests (no Slither needed)
# ---------------------------------------------------------------------------


def test_evaluate_none_tree_yields_conditional_universal():
    cap = evaluate_tree(None)
    assert cap.kind == "conditional_universal"


def test_caller_dependent_unsupported_stays_unsupported():
    """Caller-dependent unknown gates remain fail-closed."""
    tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "unsupported",
            "operator": "truthy",
            "authority_role": "business",
            "operands": [],
            "unsupported_reason": "test_unsupported",
            "references_msg_sender": True,
            "parameter_indices": [],
            "expression": "",
            "basis": [],
        },
    }
    cap = evaluate_tree(tree)  # type: ignore[arg-type]
    assert cap.kind == "unsupported"
    assert cap.unsupported_reason == "test_unsupported"


def test_zero_address_equality_is_empty_principal_set():
    tree = {
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
            "parameter_indices": [],
            "expression": "msg.sender == owner",
            "basis": [],
        },
    }
    cap = evaluate_tree(tree, EvaluationContext(state_var_values={"owner": "0x" + "0" * 40}))  # type: ignore[arg-type]
    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"


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
    )  # type: ignore[arg-type]
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

    cap = evaluate_tree(tree, EvaluationContext(contract_address=contract_address))  # type: ignore[arg-type]

    assert cap.kind == "finite_set"
    assert cap.members == [contract_address]
    assert cap.membership_quality == "exact"


def test_call_frame_normalization_keeps_self_bound_parameters_symbolic():
    from services.resolution.adapters import CallFrame
    from services.resolution.predicate_evaluator import _normalize_tree_for_frame

    operand = {"source": "parameter", "parameter_index": 0, "parameter_name": "role"}
    tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "membership",
            "operator": "truthy",
            "authority_role": "caller_authority",
            "operands": [operand],
        },
    }
    frame = CallFrame(bound_parameters=(operand,))

    normalized = _normalize_tree_for_frame(tree, frame)  # type: ignore[arg-type]

    normalized_leaf = cast(dict[str, Any], normalized.get("leaf"))
    assert normalized_leaf["operands"] == [operand]


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

    cap = evaluate_tree_with_registry(target_tree, AdapterRegistry(), ctx)  # type: ignore[arg-type]

    assert cap.kind == "finite_set"
    assert cap.members == [manager_addr]
    assert cap.membership_quality == "exact"


def test_view_call_mapping_key_expands_to_returned_role_members(monkeypatch):
    import services.resolution.predicate_evaluator as evaluator_mod
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
        lambda **_kwargs: ["0x" + "bb" * 32],
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

    cap = evaluate_tree(tree, EvaluationContext(contract_address="0x" + "11" * 20, adapter=Adapter()))  # type: ignore[arg-type]

    assert cap.kind == "finite_set"
    assert cap.members == [member]
    assert calls


def test_delegated_check_conditional_inline_preserves_structural_result(monkeypatch):
    from eth_utils.crypto import keccak

    import db.queue as queue_mod
    import services.resolution.capability_resolver as resolver_mod
    import services.resolution.external_check_materializer as materializer_mod
    from services.resolution.adapters import AdapterRegistry, CallFrame
    from services.resolution.adapters import EvaluationContext as ResolverContext
    from services.resolution.capabilities import CapabilityExpr
    from services.resolution.predicate_evaluator import evaluate_tree_with_registry

    target_addr = "0x" + "11" * 20
    authority_addr = "0x" + "22" * 20
    member = "0x" + "33" * 20
    selector = "0x" + keccak(text="allowAll(address)").hex()[:8]

    target_tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "external_bool",
            "operator": "truthy",
            "authority_role": "delegated_authority",
            "operands": [
                {"source": "msg_sender"},
                {"source": "self_address"},
                {"source": "computed", "computed_kind": "msg.sig"},
            ],
            "set_descriptor": {
                "kind": "external_set",
                "authority_contract": {
                    "address_source": {"source": "state_variable", "state_variable_name": "authority"}
                },
                "callee_signature": "allowed(address,address,bytes4)",
                "callee_selector": "0x77777777",
            },
            "references_msg_sender": True,
            "parameter_indices": [],
            "expression": "authority.allowed(msg.sender,address(this),msg.sig)",
            "basis": [],
        },
    }
    authority_artifact = {
        "schema_version": "semantic",
        "contract_name": "RenamedAuthority",
        "trees": {},
        "check_trees": {
            "allowed(address,address,bytes4)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "business",
                    "operands": [
                        {"source": "parameter", "parameter_index": 1},
                        {"source": "parameter", "parameter_index": 2},
                    ],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "key_sources": [
                            {"source": "parameter", "parameter_index": 1},
                            {"source": "parameter", "parameter_index": 2},
                        ],
                        "storage_var": "isCapabilityPublic",
                    },
                    "references_msg_sender": False,
                    "parameter_indices": [1, 2],
                    "expression": "isCapabilityPublic[target][sig]",
                    "basis": [],
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
            function_signature="allowAll(address)",
            function_selector=selector,
        ),
    )

    cap = evaluate_tree_with_registry(target_tree, AdapterRegistry(), ctx)  # type: ignore[arg-type]

    assert cap.kind == "conditional_universal"
    assert cap.conditions
    assert cap.conditions[0].description == "isCapabilityPublic[target][sig]"
    assert materialize_calls == []


def test_delegated_opaque_checker_materializes_with_zero_arg_getter(monkeypatch):
    from eth_utils.crypto import keccak

    import db.queue as queue_mod
    import services.resolution.capability_resolver as resolver_mod
    import services.resolution.external_check_materializer as materializer_mod
    import utils.rpc as rpc_mod
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

    cap = evaluate_tree_with_registry(target_tree, AdapterRegistry(), ctx)  # type: ignore[arg-type]

    assert cap.kind == "finite_set"
    assert cap.members == [member]
    assert rpc_calls
    assert materialize_calls
    assert materialize_calls[0]["call_args"] == [
        {"source": "constant", "constant_value": role_word},
        {"source": "root_caller"},
    ]


# ---------------------------------------------------------------------------
# Caller-authority gates whose authority lives in an external contract or a
# caller-keyed allowlist must resolve GATED, never public. These were the
# residual false-opens after the custom-error-require fix: a caller gate the
# evaluator couldn't classify fell through to a ``business`` side-condition and
# the function defaulted to public. Polarity / shape keeps genuinely
# permissionless siblings (denylist / claim-once) open.
# ---------------------------------------------------------------------------


def test_caller_equals_external_getter_resolves_gated(tmp_path):
    """``require(msg.sender == registry.admin())`` — the authority lives in
    another contract. For the ``==`` to type-check, ``registry.admin()`` returns
    ``address``, so this is a caller-authority gate. It must resolve to a gated
    ``external_check_only`` (query the getter), never ``conditional_universal``."""
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


def test_caller_keyed_allowlist_membership_resolves_gated(tmp_path):
    """``require(allowed[msg.sender])`` is a positive caller allowlist — only
    recorded addresses pass. It must resolve gated (``external_check_only``), not
    ``conditional_universal``/public."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) public allowed;
            function f() external view {
                require(allowed[msg.sender]);
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["f()"])
    assert cap.kind == "external_check_only", (
        f"a caller allowlist must be gated, got {cap.kind} (false-open regression)"
    )


def test_caller_keyed_denylist_membership_stays_open(tmp_path):
    """The polarity sibling: ``require(!registered[msg.sender])`` is a denylist /
    claim-once — the default-false caller is ALLOWED, so anyone not yet listed may
    call. This must STAY ``conditional_universal``/public (the self-registration
    path the cofinite refactor preserves); the allowlist gating must not catch it."""
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
    """The view-key-membership HyperSync scan starts at the event address's
    creation block, not genesis — identical key words, no pre-deployment scan."""
    import hypersync

    import services.resolution.creation_block_floor as floor_mod
    from services.resolution.predicate_evaluator import _observed_event_key_words_from_hypersync

    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: 7_000_000)

    captured: dict = {}

    def _query(*, from_block, to_block, logs, field_selection):  # noqa: ARG001
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
    outer = SimpleNamespace(meta={}, chain_id=1, block=None)

    _observed_event_key_words_from_hypersync(
        outer_ctx=outer, descriptor=cast(Any, descriptor), event_hints=hints, key_index=0
    )

    assert captured["from_block"] == 7_000_000 - 1


# ---------------------------------------------------------------------------
# Inlined-frame promotion (_promote_bound_caller_leaf): only gate-shaped
# leaves may be restored to proven delegated authority after binding.
# ---------------------------------------------------------------------------


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


def test_bound_transferfrom_leaf_stays_business(tmp_path):
    """A nonview value-movement external_bool leaf whose subject argument gets
    caller-bound at inlining must stay ``business`` (side condition), never be
    re-promoted to proven ``delegated_authority``: the caller-bound argument
    is the funds subject, not an authorization subject."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        contract Registry {
            IERC20 public token;
            function check(address user) external returns (bool) {
                require(token.transferFrom(user, address(this), 1), "pull failed");
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
        "nonview",
    )
    bound = _bind_callee_parameters(cast(PredicateTree, tree), [{"source": "root_caller"}])
    bound_leaf = _leaves(bound)[0]
    assert bound_leaf["authority_role"] == "business"


def test_bound_view_acl_leaf_promotes_to_delegated_authority(tmp_path):
    """The positive case: a view ACL read on a parameter that gets
    caller-bound at inlining IS a caller gate and must still promote."""
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


def test_bound_equality_leaf_still_promotes(tmp_path):
    """Direct caller compares (equality leaves) keep promoting — the
    gate-shape discriminator applies only to external_bool leaves."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract Registry {
            address public owner;
            uint256 public x;
            function check(address who) external {
                require(who == owner, "not owner");
                x = 1;
            }
        }
    """,
    )
    contract = sl.contracts[0]
    tree = build_predicate_tree(next(f for f in contract.functions if f.full_name == "check(address)"))
    leaf = _leaves(tree)[0]
    assert (leaf["kind"], leaf["authority_role"]) == ("equality", "business")
    bound = _bind_callee_parameters(cast(PredicateTree, tree), [{"source": "root_caller"}])
    bound_leaf = _leaves(bound)[0]
    assert bound_leaf["authority_role"] == "delegated_authority"


def test_unknown_mutability_external_bool_stays_business():
    """Three-state rule: an external_bool leaf whose callee mutability was
    NOT determined (None) must not mint the proven delegated-authority state
    — same treatment as the static discriminator's (None, nonview) arm."""
    from services.resolution.predicate_evaluator import _promote_bound_caller_leaf

    leaf = {
        "kind": "external_bool",
        "authority_role": "business",
        "callee_state_mutability": None,
        "gate_kind": "require",
        "callee_signature": "check(address)",
        "operands": [{"source": "root_caller"}],
    }
    _promote_bound_caller_leaf(leaf)
    assert leaf["authority_role"] == "business"
