"""``param_constraints``: does a mandatory revert gate reference this parameter between entry and sink? Hand-built
trees reach branches no corpus contract does. Positive control: ``sweepDust`` (zero-address check plus the value
call's own revert) must stay unconstrained. Negative: ``payAnyone`` has the same shape as three constrained
siblings but no guard.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.static.claims.context import ClaimContext
from services.static.claims.matchers import _facts, flows


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


def test_a_mapping_allowlist_membership_leaf_is_constrained():
    ctx = _ctx(
        _leaf(
            kind="membership",
            operator="truthy",
            operands=[_param(0)],
            parameter_indices=[0],
            set_descriptor={"kind": "mapping_membership", "storage_var": "allowed", "key_sources": [_param(0)]},
        )
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["guard"] == "mapping_allowlist"


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


def test_a_zero_address_check_constrains_nothing_the_sweepdust_positive_control():
    """Excluding one address out of 2^160 doesn't constrain where funds go; reading it as a constraint was the
    overshoot.
    """
    ctx = _ctx(_leaf(operator="ne", operands=[_param(0), CONSTANT], parameter_indices=[0]))
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_an_or_escape_means_the_leaf_is_not_mandatory():
    tree = {
        "op": "OR",
        "children": [
            _leaf(operands=[_param(0), STATE_VAR], parameter_indices=[0]),
            _leaf(operator="truthy", operands=[CONSTANT]),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_a_function_with_no_predicate_tree_is_not_determined_for_every_parameter():
    """G3 classes F and R are caller-gated functions whose tree was never built."""
    effects = {"contract_name": "S", "functions": {"f(address,uint256)": {}}}
    ctx = ClaimContext(None, effects, {"trees": {}})
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


def test_an_unresolved_parameter_index_is_not_determined_never_a_proof():
    ctx = _ctx(_leaf(operator="ne", operands=[_param(0), CONSTANT]))
    assert _facts.param_constraint(ctx, "f(address,uint256)", None) == {"state": "not_determined"}


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


def test_a_view_callee_gate_is_a_genuine_constraint_not_a_blanket_exclusion():
    """A view callee moves nothing, so its revert surface is a real precondition."""
    ctx = _ctx(
        _leaf(
            kind="external_bool",
            operator="truthy",
            gate_kind="external_call_revert",
            callee_state_mutability="view",
            callee_signature="deployedEtherFiNodes(uint256)",
            operands=[_param(0)],
            parameter_indices=[0],
        ),
        sinks=[VALUE_SINK],
        flows=[VALUE_FLOW],
    )
    verdict = _facts.param_constraint(ctx, "f(address,uint256)", 0)
    assert verdict["state"] == "constrained"
    assert verdict["guard"] == "external_call_revert"


def test_an_effectful_callee_that_is_not_the_effect_sink_leaves_the_answer_open():
    """Answering either proof would be a guess."""
    ctx = _ctx(
        _leaf(
            kind="external_bool",
            operator="truthy",
            gate_kind="external_call_revert",
            callee_state_mutability="nonview",
            callee_signature="registerSomething(address)",
            operands=[_param(0)],
            parameter_indices=[0],
        ),
        sinks=[VALUE_SINK],
        flows=[VALUE_FLOW],
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


_ROUTER_LEAF = dict(
    kind="external_bool",
    operator="truthy",
    gate_kind="external_call_revert",
    callee_state_mutability="nonview",
    callee_signature="exit(address,IERC20,uint256,address,uint256)",
    operands=[_param(0)],
    parameter_indices=[0],
)


def test_a_routed_flows_recorded_router_op_is_transparent():
    """The routed flow records the callee's inner selector, so the router call joins only through ``router_ops`` by
    bare name.
    """
    ctx = _ctx(
        _leaf(**_ROUTER_LEAF),
        sinks=[{"kind": "external_call", "target": "vault.exit", "selector": "0x18457e61", "origin": "body"}],
        flows=[
            {
                "kind": "callee_erc20_selector",
                "selector": "0xa9059cbb",
                "direction": "value_router",
                "origin": "body",
                "router_ops": [{"selector": None, "callee": "exit"}],
            }
        ],
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_a_non_router_leaf_on_a_routed_function_blocks():
    """Before router_ops, guarded and guard-free twins published byte-identical negative proofs."""
    ctx = _ctx(
        {
            "op": "AND",
            "children": [
                _leaf(
                    kind="external_bool",
                    operator="truthy",
                    gate_kind="external_call_revert",
                    callee_state_mutability="nonview",
                    callee_signature="checkDestination(address)",
                    operands=[_param(0)],
                    parameter_indices=[0],
                ),
                _leaf(**_ROUTER_LEAF),
            ],
        },
        sinks=[
            {"kind": "external_call", "target": "guard.checkDestination", "selector": "0x691260e0", "origin": "body"},
            {"kind": "external_call", "target": "vault.exit", "selector": "0x18457e61", "origin": "body"},
        ],
        flows=[
            {
                "kind": "callee_erc20_selector",
                "selector": "0xa9059cbb",
                "direction": "value_router",
                "origin": "body",
                "router_ops": [{"selector": None, "callee": "exit"}],
            }
        ],
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


def test_a_routed_flow_without_recorded_router_ops_makes_nothing_transparent():
    """Absence of ``router_ops`` is not a licence to widen."""
    ctx = _ctx(
        _leaf(**_ROUTER_LEAF),
        sinks=[{"kind": "external_call", "target": "vault.exit", "selector": "0x18457e61", "origin": "body"}],
        flows=[
            {"kind": "callee_erc20_selector", "selector": "0xa9059cbb", "direction": "value_router", "origin": "body"}
        ],
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


def _routed_flow(**extra: Any) -> dict[str, Any]:
    return {
        "kind": "callee_erc20_selector",
        "selector": "0xa9059cbb",
        "direction": "value_router",
        "origin": "body",
        "from_is_self": True,
        **extra,
    }


def test_the_recorded_router_op_is_projected_into_the_published_witness():
    """The op is projected verbatim (``callee`` is an intra-unit name, never an on-chain target), and the sink
    cross-reference joins on that identity.
    """
    ctx = _ctx(
        _leaf(**_ROUTER_LEAF),
        sinks=[
            {
                "id": "f(address,uint256):sink0:external_call:vault.exit",
                "kind": "external_call",
                "target": "vault.exit",
                "selector": "0x18457e61",
                "origin": "body",
            }
        ],
        flows=[_routed_flow(router_ops=[{"selector": "0x18457e61", "callee": "exit"}])],
    )
    evidence = flows.value_router(ctx, "f(address,uint256)")
    assert evidence is not None
    assert evidence.witness == {
        "kind": "value_flow",
        "direction": "value_router",
        "flows": [
            {
                "kind": "callee_erc20_selector",
                "selector": "0xa9059cbb",
                "from_is_self": True,
                "router_ops": [{"selector": "0x18457e61", "callee": "exit"}],
            }
        ],
        "sink_ids": ["f(address,uint256):sink0:external_call:vault.exit"],
    }


def test_every_recorded_op_is_projected_in_the_producers_order():
    """Dropping or reordering one would silently narrow the transparency set."""
    ops = [{"selector": "0x39d6ba32", "callee": "enter"}, {"selector": "0x9729bb1e", "callee": "safeTransferFrom"}]
    ctx = _ctx(_leaf(**_ROUTER_LEAF), flows=[_routed_flow(router_ops=list(ops))])
    evidence = flows.value_router(ctx, "f(address,uint256)")
    assert evidence is not None
    assert evidence.witness["flows"][0]["router_ops"] == ops


@pytest.mark.parametrize("recorded", [None, []], ids=["absent", "empty"])
def test_an_unrecorded_router_op_leaves_the_key_absent_and_the_gate_undetermined(recorded):
    """``[]`` would read as "no router" and license the transparency the absence denies."""
    flow = _routed_flow() if recorded is None else _routed_flow(router_ops=recorded)
    ctx = _ctx(
        _leaf(**_ROUTER_LEAF),
        sinks=[{"kind": "external_call", "target": "vault.exit", "selector": "0x18457e61", "origin": "body"}],
        flows=[flow],
    )
    evidence = flows.value_router(ctx, "f(address,uint256)")
    assert evidence is not None
    assert evidence.witness["flows"] == [
        {"kind": "callee_erc20_selector", "selector": "0xa9059cbb", "from_is_self": True}
    ]
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


def test_an_unrouted_flow_never_carries_a_router_op():
    ctx = _ctx(_leaf(**_ROUTER_LEAF), sinks=[{**VALUE_SINK, "id": "s1"}], flows=[VALUE_FLOW])
    evidence = flows.flow_out(ctx, "f(address,uint256)")
    assert evidence is not None
    assert "router_ops" not in evidence.witness["flows"][0]


def test_a_hash_commitment_binds_through_derived_from_and_says_so():
    ctx = _ctx(
        _leaf(
            operands=[
                {"source": "computed", "computed_kind": "keccak256(bytes)", "derived_from": [_param(1, "receiver")]},
                STATE_VAR,
            ]
        )
    )
    verdict = _facts.param_constraint(ctx, "f(address,uint256)", 1)
    assert verdict["state"] == "constrained"
    assert verdict["guard"] == "hash_commitment"
    # Recorded because the binding is flow-insensitive.
    assert verdict["binding"] == "derived_from"
    # A union over branches isn't a proof the guard confines this parameter on every path (``address t = defaultTo; if
    # (cond) t = to;``).
    assert verdict["pins"] is None


def test_a_computed_operand_with_UNDETERMINED_provenance_blocks_the_unconstrained_proof():
    """``None`` (undetermined) differs from ``[]`` (only constants)."""
    ctx = _ctx(
        _leaf(operands=[{"source": "computed", "computed_kind": "keccak256(bytes)", "derived_from": None}, STATE_VAR])
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}
    assert _facts.param_constraint(ctx, "f(address,uint256)", 7) == {"state": "not_determined"}


def test_a_computed_operand_blocks_the_unconstrained_proof_even_with_resolved_provenance():
    """Inverted: the flow-insensitive union can omit a genuine origin, so every ``computed`` operand blocks."""
    for provenance in ([], [_param(1, "receiver")], [STATE_VAR]):
        ctx = _ctx(
            _leaf(
                operands=[
                    {"source": "computed", "computed_kind": "keccak256(bytes)", "derived_from": provenance},
                    STATE_VAR,
                ]
            )
        )
        assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


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


def test_an_absent_derived_from_key_on_a_computed_operand_is_undetermined_not_empty():
    """Pre-provenance artifacts carry no key; 27 of 80 local ``param`` destinations sit here, and fail-closed is
    still correct.
    """
    ctx = _ctx(_leaf(operands=[{"source": "computed", "computed_kind": "sload(uint256)"}, STATE_VAR]))
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


def test_an_unsupported_leaf_blocks_every_unconstrained_proof_by_default():
    """``operands: []`` is unconditional, so it's never evidence."""
    tree = {
        "op": "AND",
        "children": [
            _leaf(operator="ne", operands=[_param(0), CONSTANT], parameter_indices=[0]),
            _leaf(kind="unsupported", operator="truthy", unsupported_reason="opaque_try_catch"),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 0) == {"state": "not_determined"}


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


def test_an_unrecognised_unsupported_reason_still_blocks():
    tree = {
        "op": "AND",
        "children": [
            _leaf(operator="ne", operands=[_param(0), CONSTANT], parameter_indices=[0]),
            _leaf(kind="unsupported", operator="truthy", unsupported_reason="something_new_nobody_has_seen"),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 0) == {"state": "not_determined"}


def test_without_ir_no_effectful_callee_is_transparent_in_exec_mode():
    """Inverted: transparency is now earned per call op from IR, so without Slither the leaf blocks in both modes.

    The positive lives in ``test_claims_upgrade_exec_matchers``.
    """
    leaf = _leaf(
        kind="external_bool",
        operator="truthy",
        gate_kind="external_call_revert",
        callee_state_mutability="nonview",
        callee_signature="exec(address,bytes)",
        operands=[_param(0)],
        parameter_indices=[0],
    )
    ctx = _ctx(leaf, sinks=[{"kind": "external_call", "target": "t.exec", "selector": "0xbe6002c2", "origin": "body"}])
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0, mode="external_call") == {"state": "not_determined"}
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0, mode="value_flow") == {"state": "not_determined"}


def test_a_guard_origin_sink_is_never_part_of_the_transparency_set():
    """The transparency set is built from the function's own body calls proven parameter-destination."""
    ctx = _ctx(
        _leaf(
            kind="external_bool",
            operator="truthy",
            gate_kind="external_call_revert",
            callee_state_mutability="nonview",
            callee_signature="onlyRole(address)",
            operands=[_param(0)],
            parameter_indices=[0],
        ),
        sinks=[{"kind": "external_call", "target": "registry.onlyRole", "selector": "0x71645909", "origin": "guard"}],
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0, mode="external_call") == {"state": "not_determined"}


def test_a_parameter_named_in_the_expression_but_absent_from_the_operands_is_not_determined():
    """CumulativeMerkleDrop.claim projected only ``expectedMerkleRoot``; the expression cross-check stops ``account``
    reading as unconstrained.
    """
    ctx = _ctx(
        _leaf(
            operator="truthy",
            operands=[_param(2, "expectedMerkleRoot")],
            parameter_indices=[2],
            expression="! verify(account,cumulativeAmount,expectedMerkleRoot,merkleProof)",
        ),
        parameter_names=["account", "cumulativeAmount", "expectedMerkleRoot", "merkleProof"],
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}
    assert _facts.param_constraint(ctx, "f(address,uint256)", 1) == {"state": "not_determined"}
    assert _facts.param_constraint(ctx, "f(address,uint256)", 3) == {"state": "not_determined"}


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


def test_a_positive_verdict_from_another_leaf_survives_an_expression_block():
    tree = {
        "op": "AND",
        "children": [
            _leaf(operands=[_param(1, "amount"), STATE_VAR], parameter_indices=[1]),
            _leaf(operator="truthy", operands=[], expression="helper(amount)"),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 1)["state"] == "constrained"


def test_a_bare_mapping_operand_in_a_comparison_blocks_every_unconstrained_proof():
    """EtherFiTimelock: ``isOperationReady(id)`` lost its key, and the dropped key can derive from any parameter."""
    writer = {
        "state_writes": [{"var": "_timestamps", "declared_type": "mapping(bytes32 => uint256)", "origin": "body"}],
        "parameter_names": ["id", "delay"],
    }
    ctx = _ctx(
        _leaf(
            kind="comparison",
            operator="gt",
            operands=[
                {"source": "state_variable", "state_variable_name": "_timestamps"},
                {"source": "state_variable", "state_variable_name": "_DONE_TIMESTAMP"},
            ],
            expression="require(bool,string)(isOperationReady(id),operation is not ready)",
        ),
        extra_functions={"schedule(bytes32,uint256)": writer},
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}
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


def test_a_membership_leaf_with_a_descriptor_accounts_its_keys_and_does_not_trip_the_block():
    writer = {
        "state_writes": [{"var": "allowed", "declared_type": "mapping(address => bool)", "origin": "body"}],
        "parameter_names": ["who", "ok"],
    }
    ctx = _ctx(
        _leaf(
            kind="membership",
            operator="truthy",
            operands=[_param(0, "to")],
            parameter_indices=[0],
            set_descriptor={"kind": "mapping_membership", "storage_var": "allowed", "key_sources": [_param(0, "to")]},
        ),
        extra_functions={"setAllowed(address,bool)": writer},
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["guard"] == "mapping_allowlist"
    assert _facts.param_constraint(ctx, "f(address,uint256)", 1)["state"] == "unconstrained_proven"


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


def test_flow_and_exec_witnesses_publish_the_same_standard_verdict():
    """Both consumers read ``standard_destination_commitment``, so they're equal by construction."""
    ctx = _timelock_ctx()
    execute = "execute(address,uint256,bytes,bytes32,bytes32)"
    standard = _facts.standard_destination_commitment(ctx, execute)
    assert standard is not None
    assert _facts.param_constraint(ctx, execute, 0) == standard


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


def test_the_safe_standard_gate_commits_only_the_signed_exec_entry():
    """Module-exec entries share ``SAFE_EXEC_SELECTORS`` but gate the caller, committing no parameter."""
    ctx = _safe_ctx()
    exec_tx = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
    for index in range(10):
        verdict = _facts.param_constraint(ctx, exec_tx, index, mode="external_call")
        assert verdict["state"] == "constrained"
        assert verdict["guard"] == "signature_witness"
        assert verdict["pins"] is True
        assert verdict["binding"] == "standard_gate"
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
