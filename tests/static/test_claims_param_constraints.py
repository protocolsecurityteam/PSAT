"""``param_constraints``: does a mandatory revert gate reference this parameter between entry and sink? Hand-built
trees reach branches no corpus contract does. Positive control: ``sweepDust`` (zero-address check plus the value
call's own revert) must stay unconstrained. Negative: ``payAnyone`` has the same shape as three constrained
siblings but no guard.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.static.claims.context import ClaimContext
from services.static.claims.matchers import _facts


def _ctx(
    tree: Any,
    *,
    sinks: list[dict] | None = None,
    flows: list[dict] | None = None,
    parameter_names: list[str] | None = None,
    extra_functions: dict[str, dict] | None = None,
) -> ClaimContext:
    effects = {
        "contract_name": "Subject",
        "functions": {
            "f(address,uint256)": {
                "sinks": sinks or [],
                "value_flows": flows or [],
                # The projection-completeness cross-check needs the declared names.
                "parameter_names": ["to", "amount"] if parameter_names is None else parameter_names,
            },
            **(extra_functions or {}),
        },
    }
    trees = {"trees": {"f(address,uint256)": tree}}
    return ClaimContext(None, effects, trees)


def _leaf(**leaf: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": "equality",
        "operator": "eq",
        "authority_role": "business",
        "operands": [],
        "references_msg_sender": False,
        "parameter_indices": [],
        "expression": "",
        "basis": [],
    }
    base.update(leaf)
    return {"op": "LEAF", "leaf": base}


def _param(index: int, name: str = "to") -> dict[str, Any]:
    return {"source": "parameter", "parameter_index": index, "parameter_name": name}


STATE_VAR = {"source": "state_variable", "state_variable_name": "treasury"}
CONSTANT = {"source": "constant"}
VALUE_SINK = {"kind": "external_call", "target": "token.safeTransfer", "selector": "0xd0c407e1", "origin": "body"}
VALUE_FLOW = {"kind": "callee_erc20_selector", "selector": "0xd0c407e1", "direction": "out", "origin": "body"}


def test_equality_against_storage_is_constrained_and_names_the_guard():
    ctx = _ctx(_leaf(operands=[_param(0), STATE_VAR], parameter_indices=[0]))
    verdict = _facts.param_constraint(ctx, "f(address,uint256)", 0)
    assert verdict["state"] == "constrained"
    assert verdict["guard"] == "equality_vs_storage"
    assert verdict["pins"] is True
    assert verdict["binding"] == "operand"
    assert verdict["leaf_path"] == []


def test_a_denylist_membership_is_recorded_as_a_guard_that_pins_nothing():
    """The recorded guard name stops a consumer crediting a denylist like an allowlist."""
    ctx = _ctx(
        _leaf(
            kind="membership",
            operator="falsy",
            operands=[_param(0)],
            parameter_indices=[0],
            set_descriptor={"kind": "mapping_membership", "storage_var": "denied", "key_sources": [_param(0)]},
        )
    )
    verdict = _facts.param_constraint(ctx, "f(address,uint256)", 0)
    assert verdict["state"] == "constrained"
    assert verdict["guard"] == "denylist"
    assert verdict["pins"] is False


def test_an_allowlist_upgrades_a_denylist_verdict_on_the_same_parameter():
    tree = {
        "op": "AND",
        "children": [
            _leaf(
                kind="membership",
                operator="falsy",
                operands=[_param(0)],
                set_descriptor={"kind": "mapping_membership", "key_sources": [_param(0)]},
            ),
            _leaf(
                kind="membership",
                operator="truthy",
                operands=[_param(0)],
                set_descriptor={"kind": "mapping_membership", "key_sources": [_param(0)]},
            ),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 0)["guard"] == "mapping_allowlist"


def test_an_or_escape_means_the_leaf_is_not_mandatory():
    tree = {
        "op": "OR",
        "children": [
            _leaf(operands=[_param(0), STATE_VAR], parameter_indices=[0]),
            _leaf(operator="truthy", operands=[{"source": "constant", "constant_value": "True", "value_type": "bool"}]),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_a_function_with_no_predicate_tree_is_not_determined_for_every_parameter():
    """G3 classes F and R are caller-gated functions whose tree was never built."""
    effects = {"contract_name": "S", "functions": {"f(address,uint256)": {}}}
    ctx = ClaimContext(None, effects, {"trees": {}})
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


def test_the_value_calls_own_revert_surface_does_not_constrain_its_destination():
    ctx = _ctx(
        _leaf(
            kind="external_bool",
            operator="truthy",
            gate_kind="external_call_revert",
            callee_state_mutability="nonview",
            callee_signature="safeTransfer(IERC20,address,uint256)",
            operands=[_param(0)],
            parameter_indices=[0],
        ),
        sinks=[VALUE_SINK],
        flows=[VALUE_FLOW],
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_an_external_revert_surface_guard_never_claims_to_pin():
    """A blacklist and an allowlist look identical here, so ``pins`` is None; all four real ``constrained`` flow rows
    are this kind and are in fact blacklists.
    """
    ctx = _ctx(
        _leaf(
            kind="external_bool",
            operator="truthy",
            gate_kind="external_call_revert",
            callee_state_mutability="view",
            callee_signature="nonBlacklisted(address)",
            operands=[_param(0)],
            parameter_indices=[0],
        )
    )
    verdict = _facts.param_constraint(ctx, "f(address,uint256)", 0)
    assert verdict["state"] == "constrained"
    assert verdict["guard"] == "external_call_revert"
    assert verdict["pins"] is None


def test_the_l24_misbind_shape_lands_the_omitted_parameter_on_not_determined():
    """``keccak(receiver, nativeWrapper)`` published ``receiver`` and omitted the committed ``depositAsset``."""
    ctx = _ctx(
        _leaf(
            operands=[
                {
                    "source": "computed",
                    "computed_kind": "keccak256(bytes)",
                    "derived_from": [
                        _param(1, "receiver"),
                        {"source": "state_variable", "state_variable_name": "nativeWrapper"},
                    ],
                },
                {"source": "state_variable", "state_variable_name": "commitments"},
            ]
        )
    )
    bound = _facts.param_constraint(ctx, "f(address,uint256)", 1)
    assert bound["state"] == "constrained"
    assert bound["binding"] == "derived_from"
    assert _facts.param_constraint(ctx, "f(address,uint256)", 2) == {"state": "not_determined"}
    assert _facts.param_constraint(ctx, "f(address,uint256)", 3) == {"state": "not_determined"}


@pytest.mark.parametrize(
    "reason",
    [
        "solidity_call_abi.decode()_unsupported_as_gate",
        "solidity_call_tload(uint256)_unsupported_as_gate",
    ],
)
def test_a_returndata_or_slot_gate_cannot_reference_a_parameter_and_does_not_block(reason):
    """``abi.decode`` reads returndata and ``tload`` a slot literal; every other reason keeps blocking."""
    tree = {
        "op": "AND",
        "children": [
            _leaf(operator="ne", operands=[_param(0), CONSTANT], parameter_indices=[0]),
            _leaf(kind="unsupported", operator="truthy", unsupported_reason=reason),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_an_expression_mention_blocks_only_the_dropped_parameter_not_the_accounted_one():
    tree = {
        "op": "AND",
        "children": [
            _leaf(operands=[_param(0, "to"), STATE_VAR], parameter_indices=[0]),
            _leaf(
                operator="truthy",
                operands=[_param(0, "to")],
                parameter_indices=[0],
                expression="check(to,amount)",
            ),
        ],
    }
    ctx = _ctx(tree)
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["state"] == "constrained"
    assert _facts.param_constraint(ctx, "f(address,uint256)", 1) == {"state": "not_determined"}


def test_a_scalar_state_variable_comparison_does_not_trip_the_keyed_collection_block():
    writer = {
        "state_writes": [{"var": "cap", "declared_type": "uint256", "origin": "body"}],
        "parameter_names": [],
    }
    ctx = _ctx(
        _leaf(
            kind="comparison",
            operator="gt",
            operands=[{"source": "state_variable", "state_variable_name": "cap"}, CONSTANT],
        ),
        extra_functions={"setCap(uint256)": writer},
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_an_array_length_read_is_not_an_element_read():
    writer = {
        "state_writes": [{"var": "holders", "declared_type": "address[]", "origin": "body"}],
        "parameter_names": ["who"],
    }
    ctx = _ctx(
        _leaf(
            kind="comparison",
            operator="gt",
            operands=[
                {"source": "state_variable", "state_variable_name": "holders", "member_path": ["length"]},
                CONSTANT,
            ],
        ),
        extra_functions={"addHolder(address)": writer},
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_a_record_without_parameter_names_can_never_mint_the_proof_state():
    """Reachable by construction only; the local corpus has names on 2,415/2,415 functions."""
    tree = {
        "op": "AND",
        "children": [
            _leaf(operands=[_param(0), STATE_VAR], parameter_indices=[0]),
            _leaf(operator="ne", operands=[_param(1), CONSTANT], parameter_indices=[1]),
        ],
    }
    ctx = _ctx(tree, parameter_names=None)  # helper default is a REAL list
    effects = {
        "contract_name": "Subject",
        "functions": {"f(address,uint256)": {"sinks": [], "value_flows": []}},
    }
    bare = ClaimContext(None, effects, {"trees": {"f(address,uint256)": tree}})
    assert _facts.param_constraint(bare, "f(address,uint256)", 0)["state"] == "constrained"
    assert _facts.param_constraint(bare, "f(address,uint256)", 1) == {"state": "not_determined"}
    assert _facts.param_constraint(ctx, "f(address,uint256)", 1)["state"] == "unconstrained_proven"


def _timelock_ctx() -> ClaimContext:
    execute = "execute(address,uint256,bytes,bytes32,bytes32)"
    functions = {
        execute: {
            "abi_signature": execute,
            "parameter_names": ["target", "value", "payload", "predecessor", "salt"],
            "sinks": [{"kind": "external_call", "target": "target.call", "selector": None, "origin": "body"}],
            "value_flows": [
                {
                    "kind": "low_level_value_call",
                    "selector": None,
                    "direction": "out",
                    "origin": "body",
                    "target_kind": {"kind": "param", "tier": "dispositive_ast"},
                    "target_param_index": 0,
                }
            ],
        },
        "getMinDelay()": {"abi_signature": "getMinDelay()"},
        "hashOperation(address,uint256,bytes,bytes32,bytes32)": {
            "abi_signature": "hashOperation(address,uint256,bytes,bytes32,bytes32)"
        },
        "schedule(address,uint256,bytes,bytes32,bytes32,uint256)": {
            "abi_signature": "schedule(address,uint256,bytes,bytes32,bytes32,uint256)"
        },
    }
    # The walk alone would answer not_determined.
    tree = _leaf(
        kind="comparison",
        operator="gt",
        operands=[
            {"source": "state_variable", "state_variable_name": "_timestamps"},
            {"source": "state_variable", "state_variable_name": "_DONE_TIMESTAMP"},
        ],
        expression="require(bool,string)(isOperationReady(id),operation is not ready)",
    )
    return ClaimContext(None, {"contract_name": "Timelock", "functions": functions}, {"trees": {execute: tree}})


def test_the_timelock_standard_gate_commits_every_parameter_of_execute():
    """The walk once minted ``unconstrained_proven`` for the parameter the exec witness proved hash-committed."""
    ctx = _timelock_ctx()
    execute = "execute(address,uint256,bytes,bytes32,bytes32)"
    for index in range(5):
        verdict = _facts.param_constraint(ctx, execute, index)
        assert verdict["state"] == "constrained"
        assert verdict["guard"] == "hash_commitment"
        assert verdict["pins"] is True
        assert verdict["binding"] == "standard_gate"
    assert _facts.param_constraint(ctx, execute, None) == {"state": "not_determined"}


def test_a_timelock_shaped_tree_without_the_standard_gate_is_not_committed():
    execute = "execute(address,uint256,bytes,bytes32,bytes32)"
    functions = {
        execute: {
            "abi_signature": execute,
            "parameter_names": ["target", "value", "payload", "predecessor", "salt"],
            "sinks": [],
            "value_flows": [],
        },
        "record(bytes32)": {
            "state_writes": [{"var": "_timestamps", "declared_type": "mapping(bytes32 => uint256)", "origin": "body"}],
            "parameter_names": ["id"],
        },
    }
    tree = _leaf(
        kind="comparison",
        operator="gt",
        operands=[
            {"source": "state_variable", "state_variable_name": "_timestamps"},
            {"source": "state_variable", "state_variable_name": "_DONE_TIMESTAMP"},
        ],
        expression="require(bool,string)(isOperationReady(id),operation is not ready)",
    )
    ctx = ClaimContext(None, {"contract_name": "NotATimelock", "functions": functions}, {"trees": {execute: tree}})
    assert _facts.standard_destination_commitment(ctx, execute) is None
    assert _facts.param_constraint(ctx, execute, 0) == {"state": "not_determined"}


def _safe_ctx() -> ClaimContext:
    """``execTransaction``'s opaque signature check needs the standard's shape; module exec is gated by
    ``modules[msg.sender]``.
    """
    exec_tx = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
    module_exec = "execTransactionFromModule(address,uint256,bytes,uint8)"
    module_exec_rd = "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)"
    module_params = ["to", "value", "data", "operation"]
    module_record = {
        "parameter_names": list(module_params),
        "sinks": [{"kind": "external_call", "target": "to.call", "selector": None, "origin": "body"}],
        "value_flows": [],
    }
    functions = {
        exec_tx: {
            "abi_signature": exec_tx,
            "parameter_names": [
                "to",
                "value",
                "data",
                "operation",
                "safeTxGas",
                "baseGas",
                "gasPrice",
                "gasToken",
                "refundReceiver",
                "signatures",
            ],
            "sinks": [{"kind": "external_call", "target": "to.call", "selector": None, "origin": "body"}],
            "value_flows": [],
        },
        module_exec: {"abi_signature": module_exec, **module_record},
        module_exec_rd: {"abi_signature": module_exec_rd, **module_record},
        "getThreshold()": {"abi_signature": "getThreshold()"},
        "getOwners()": {"abi_signature": "getOwners()"},
        "enableModule(address)": {
            "abi_signature": "enableModule(address)",
            "parameter_names": ["module"],
            "state_writes": [{"var": "modules", "declared_type": "mapping(address => address)", "origin": "body"}],
        },
    }
    signed_tree = _leaf(
        kind="unsupported",
        unsupported_reason="opaque_try_catch",
        expression="checkSignatures(txHash,signatures)",
    )
    module_tree = _leaf(
        kind="membership",
        operator="truthy",
        operands=[{"source": "state_variable", "state_variable_name": "modules"}],
        set_descriptor={
            "kind": "mapping_membership",
            "storage_var": "modules",
            "key_sources": [{"source": "msg_sender"}],
        },
        expression="require(bool,string)(modules[msg.sender] != address(0),not module)",
    )
    trees = {exec_tx: signed_tree, module_exec: module_tree, module_exec_rd: module_tree}
    return ClaimContext(None, {"contract_name": "SafeWallet", "functions": functions}, {"trees": trees})


def test_safe_abi_alone_does_not_prove_a_signature_commitment():
    ctx = _safe_ctx()
    exec_tx = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
    assert _facts.standard_destination_commitment(ctx, exec_tx) is None
    for index in range(10):
        verdict = _facts.param_constraint(ctx, exec_tx, index, mode="external_call")
        assert verdict == {"state": "not_determined"}
    for module_fn in (
        "execTransactionFromModule(address,uint256,bytes,uint8)",
        "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)",
    ):
        assert _facts.standard_destination_commitment(ctx, module_fn) is None


def test_a_module_exec_gate_pins_the_caller_not_the_destination():
    """The gate proves the destination free; an enabled module calls any target, so never ``pins: True``."""
    ctx = _safe_ctx()
    for module_fn in (
        "execTransactionFromModule(address,uint256,bytes,uint8)",
        "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)",
    ):
        for index in range(4):
            verdict = _facts.param_constraint(ctx, module_fn, index, mode="external_call")
            assert verdict == {"state": "unconstrained_proven"}, (module_fn, index)


def test_the_signed_entry_alone_would_be_opaque_without_the_standard():
    exec_tx = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
    functions = {
        exec_tx: {
            "abi_signature": exec_tx,
            "parameter_names": [
                "to",
                "value",
                "data",
                "operation",
                "safeTxGas",
                "baseGas",
                "gasPrice",
                "gasToken",
                "refundReceiver",
                "signatures",
            ],
            "sinks": [],
            "value_flows": [],
        },
    }
    tree = _leaf(
        kind="unsupported",
        unsupported_reason="opaque_try_catch",
        expression="checkSignatures(txHash,signatures)",
    )
    ctx = ClaimContext(None, {"contract_name": "NotASafe", "functions": functions}, {"trees": {exec_tx: tree}})
    assert _facts.standard_destination_commitment(ctx, exec_tx) is None
    assert _facts.param_constraint(ctx, exec_tx, 0, mode="external_call") == {"state": "not_determined"}


def test_unknown_constant_is_not_evidence_of_a_public_escape():
    tree = {
        "op": "OR",
        "children": [
            _leaf(operands=[_param(0), STATE_VAR], parameter_indices=[0]),
            _leaf(operator="truthy", operands=[CONSTANT]),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 0)["state"] == "not_determined"
