"""``_facts.param_constraints`` — the A3+A4 mandatory-gate analysis.

The question is *"does a mandatory revert gate reference this parameter between
entry and sink?"*, and the answer has three states that a consumer must be able
to tell apart (R1). These tests drive the analysis on hand-built predicate trees
so every branch — including the ones no corpus contract reaches — is exercised
against a stated input, and on the compiled corpus so the states are reachable
from real compiler output rather than only from a fixture.

The controls this module keeps honest:

* POSITIVE (must stay unconstrained, i.e. keep its caller-chosen flag):
  ``sweepDust``'s shape — a zero-address check plus the value call's own revert
  surface. A prior fix proposal classified it ``constrained``; that is the
  overshoot the tightened rule exists to prevent.
* NEGATIVE (must stay clean): ``payAnyone`` in the corpus — same body, same
  claim, same lattice kind as three constrained siblings, and no guard.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.static.claims.context import ClaimContext
from services.static.claims.matchers import _facts


def _ctx(tree: Any, *, sinks: list[dict] | None = None, flows: list[dict] | None = None) -> ClaimContext:
    effects = {
        "contract_name": "Subject",
        "functions": {"f(address,uint256)": {"sinks": sinks or [], "value_flows": flows or []}},
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


# ---------------------------------------------------------------------------
# The three states, each earned
# ---------------------------------------------------------------------------


def test_equality_against_storage_is_constrained_and_names_the_guard():
    ctx = _ctx(_leaf(operands=[_param(0), STATE_VAR], parameter_indices=[0]))
    verdict = _facts.param_constraint(ctx, "f(address,uint256)", 0)
    assert verdict["state"] == "constrained"
    assert verdict["guard"] == "equality_vs_storage"
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
    """A falsy membership is the ALLOWED form of ``if (denied[x]) revert``. It
    excludes a set; it does not pin the destination, and the recorded guard name
    is what stops a consumer from crediting it like an allowlist."""
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


def test_an_allowlist_upgrades_a_denylist_verdict_on_the_same_parameter():
    """Two guards on one parameter: the pinning one is the answer. A denylist
    never suppresses a real allowlist merely by appearing first."""
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
    """THE POSITIVE CONTROL. ``if (_to == address(0)) revert`` folds to the
    allowed form ``_to != 0``: it excludes exactly one address out of 2^160 and
    is not a constraint on where the funds go. Reading it as one classifies
    ``sweepDust`` — an operator-callable sweep to any address — as guarded, which
    is the overshoot the spec forbids."""
    ctx = _ctx(_leaf(operator="ne", operands=[_param(0), CONSTANT], parameter_indices=[0]))
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_an_or_escape_means_the_leaf_is_not_mandatory():
    """The mandatory-path rule: a guard reachable around via an ``OR`` cannot
    force a revert, so it constrains nothing."""
    tree = {
        "op": "OR",
        "children": [
            _leaf(operands=[_param(0), STATE_VAR], parameter_indices=[0]),
            _leaf(operator="truthy", operands=[CONSTANT]),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 0)["state"] == "unconstrained_proven"


def test_a_function_with_no_predicate_tree_is_not_determined_for_every_parameter():
    """A missing tree is NOT proof that no gate exists (G3 classes F and R are
    caller-gated functions whose tree the extractor never built)."""
    effects = {"contract_name": "S", "functions": {"f(address,uint256)": {}}}
    ctx = ClaimContext(None, effects, {"trees": {}})
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


def test_an_unresolved_parameter_index_is_not_determined_never_a_proof():
    ctx = _ctx(_leaf(operator="ne", operands=[_param(0), CONSTANT]))
    assert _facts.param_constraint(ctx, "f(address,uint256)", None) == {"state": "not_determined"}


# ---------------------------------------------------------------------------
# The tightened rule: the effect's own revert surface is transparent
# ---------------------------------------------------------------------------


def test_the_value_calls_own_revert_surface_does_not_constrain_its_destination():
    """``safeTransfer(_to, balance)`` reverting on failure says nothing about
    whether ``_to`` could be chosen. Without this the positive control classifies
    as constrained on the strength of the transfer it performs."""
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


def test_a_view_callee_gate_is_a_genuine_constraint_not_a_blanket_exclusion():
    """``forwardExternalCall``'s ``deployedEtherFiNodes(...)`` shape: the gate IS
    an ``external_call_revert`` leaf, and it is real — a view callee moves
    nothing, so its revert surface is a precondition rather than the effect's own
    failure mode. Blanket-excluding the leaf kind would drop it."""
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
    """A nonview callee this function's effect does not run through: its revert
    surface may or may not restrict the parameter, and nothing in the tree says
    which. Answering either proof would be a guess."""
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


def test_a_routed_flow_widens_the_transparency_set_to_the_router_call():
    """A ``value_router`` flow records the CALLEE's inner transfer selector, so
    the router call this function makes has no name of its own to join on — and
    the router's revert surface is exactly the effect's. Joined by the callee's
    bare name, because the declared signature (``exit(address,IERC20,…)``) does
    not hash to the selector the sink recorded."""
    ctx = _ctx(
        _leaf(
            kind="external_bool",
            operator="truthy",
            gate_kind="external_call_revert",
            callee_state_mutability="nonview",
            callee_signature="exit(address,IERC20,uint256,address,uint256)",
            operands=[_param(0)],
            parameter_indices=[0],
        ),
        sinks=[{"kind": "external_call", "target": "vault.exit", "selector": "0x18457e61", "origin": "body"}],
        flows=[
            {"kind": "callee_erc20_selector", "selector": "0xa9059cbb", "direction": "value_router", "origin": "body"}
        ],
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0)["state"] == "unconstrained_proven"


# ---------------------------------------------------------------------------
# derived_from: consumed, never trusted as ground truth (WAVE_0 L-24)
# ---------------------------------------------------------------------------


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
    # The binding is recorded because it is flow-INSENSITIVE: on a locally
    # reassigned name it can name one branch's origin and omit another's, so a
    # consumer that must not rest on it can tell.
    assert verdict["binding"] == "derived_from"


def test_a_computed_operand_with_UNDETERMINED_provenance_blocks_the_unconstrained_proof():
    """``derived_from: None`` is *computed, provenance not determined* — a
    different fact from ``[]`` (*determined: only constants*). A parameter's
    absence from a provenance that was never computed is not evidence, so no
    parameter of this function may be called unconstrained."""
    ctx = _ctx(
        _leaf(operands=[{"source": "computed", "computed_kind": "keccak256(bytes)", "derived_from": None}, STATE_VAR])
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}
    assert _facts.param_constraint(ctx, "f(address,uint256)", 7) == {"state": "not_determined"}


def test_a_computed_operand_blocks_the_unconstrained_proof_even_with_resolved_provenance():
    """INVERTED from ``…proven_to_hold_only_constants_blocks_nothing``: the old
    arm read a fully-resolved ``derived_from`` as a COMPLETE account and let the
    leaf support ``unconstrained_proven`` for every unlisted parameter. That is
    the L-24 misbind consumed as ground truth in exactly the direction WAVE_0
    forbids — the flow-insensitive union can OMIT an origin that genuinely feeds
    the value, so a resolved-looking list still proves nothing negatively. Every
    ``computed`` operand blocks; the positive ``derived`` bindings survive."""
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
    """The exact WAVE_0 L-24 shape: ``keccak(receiver, nativeWrapper)`` published
    ``receiver`` (index 1) and OMITTED the genuinely-committed ``depositAsset``
    (index 2). Index 1 keeps its positive ``derived_from`` binding; index 2 —
    the misbind casualty — must be ``not_determined``, never a proof of
    freedom."""
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
    """Artifacts minted before the provenance field existed carry no key at all.
    Reading that as "no parameter reached it" would turn a stale artifact into a
    proof. Measured consequence on the local DB: 27 of the 80 ``param``
    destinations sit here, so this branch is where the fail-closed reading
    actually costs something — and it is still the correct reading."""
    ctx = _ctx(_leaf(operands=[{"source": "computed", "computed_kind": "sload(uint256)"}, STATE_VAR]))
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


# ---------------------------------------------------------------------------
# unsupported leaves — the fail-closed default and its two stated exceptions
# ---------------------------------------------------------------------------


def test_an_unsupported_leaf_blocks_every_unconstrained_proof_by_default():
    """``_unsupported_leaf`` publishes ``operands: []`` unconditionally, so its
    silence about parameters is a construction artifact, never evidence."""
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
    """The two exceptions, and they are exceptions about the gate's INPUTS: an
    ``abi.decode`` gate reads a call's returndata, a ``tload`` gate reads a slot
    literal. Neither can reach an ABI parameter. Every other reason keeps
    blocking, so a new one under-claims rather than over-claims."""
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


# ---------------------------------------------------------------------------
# The modes are not interchangeable
# ---------------------------------------------------------------------------


def test_the_exec_mode_treats_the_arbitrary_call_itself_as_transparent():
    """``exec.arbitrary``'s effect IS an external call, so ``require(ok)`` on
    that call is its own failure mode. Under ``value_flow`` mode the same
    function has no flow to join on and the answer stays open — the two modes
    answer about different effects and must not share a memo entry."""
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
    assert (
        _facts.param_constraint(ctx, "f(address,uint256)", 0, mode="external_call")["state"] == "unconstrained_proven"
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0, mode="value_flow") == {"state": "not_determined"}


def test_a_guard_origin_sink_is_never_part_of_the_transparency_set():
    """The transparency set is body sinks only. A modifier's own authority call
    is not the effect, so its revert surface stays a real gate."""
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
