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
                # The projection-completeness cross-check needs the declared
                # names; a record without them can never mint the proof state.
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


# ---------------------------------------------------------------------------
# Projection completeness — the round-2 rules (a leaf's silence is only
# evidence when its account of what it reads is checkable and complete)
# ---------------------------------------------------------------------------


def test_a_parameter_named_in_the_expression_but_absent_from_the_operands_is_not_determined():
    """The CumulativeMerkleDrop.claim shape: ``! verify(account, cumulativeAmount,
    expectedMerkleRoot, merkleProof)`` projected ONLY ``expectedMerkleRoot``. The
    leaf demonstrably touches ``account``; reading the projection's silence as
    proof published ``unconstrained_proven`` — "freely chosen" — on the audit's
    own named-constrained destination. The expression cross-check lands it on
    ``not_determined``."""
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
    """The block is exact: a parameter the operands DO account for keeps its
    earned verdict, and an untouched parameter keeps the proof state."""
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
    """``blocked`` fills gaps; it never overwrites a constraint some other
    mandatory leaf proved for the same parameter."""
    tree = {
        "op": "AND",
        "children": [
            _leaf(operands=[_param(1, "amount"), STATE_VAR], parameter_indices=[1]),
            _leaf(operator="truthy", operands=[], expression="helper(amount)"),
        ],
    }
    assert _facts.param_constraint(_ctx(tree), "f(address,uint256)", 1)["state"] == "constrained"


def test_a_bare_mapping_operand_in_a_comparison_blocks_every_unconstrained_proof():
    """The EtherFiTimelock shape: ``isOperationReady(id)`` folds to
    ``_timestamps > _DONE_TIMESTAMP`` — the mapping ELEMENT read lost its key
    (``id``, a keccak over every parameter). A comparison cannot read a mapping
    itself, so the bare operand proves the projection dropped the key, and the
    dropped key can be derived from any parameter."""
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
    """The same leaf over a SCALAR variable keeps the proof reachable — the
    block is keyed to the declared type, not to state reads in general."""
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
    """A mapping MEMBERSHIP leaf carries its keys in ``set_descriptor.key_sources``
    — the read is fully accounted, and the allowlist verdict (not a block) is
    the answer."""
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
    """A pre-enrichment artifact carries no ``parameter_names``, so the
    expression cross-check cannot run and no leaf's silence is verifiable.
    Positives still mint; the proof of absence does not. Reachable by
    construction only — the local corpus carries the list on 2,415/2,415
    functions, so this branch has zero realised rows today (a lower bound, not
    a population claim)."""
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
    # The same tree WITH the list keeps the earned proof for the ne-checked param.
    assert _facts.param_constraint(ctx, "f(address,uint256)", 1)["state"] == "unconstrained_proven"


# ---------------------------------------------------------------------------
# Standard-gate pre-pass — one verdict source for flow and exec witnesses
# ---------------------------------------------------------------------------


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
    # The tree deliberately carries the LOSSY isOperationReady fold — the walk
    # alone would answer not_determined; the standard's shape answers for it.
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
    """EtherFiTimelock.execute, review round 2 case (a): the generic walk saw no
    parameter operand in the ``isOperationReady(id)`` fold and minted
    ``unconstrained_proven`` — a proof of absence — for the very parameter the
    exec witness proved hash-committed, and one claims list carried both. The
    standard's own gate is the verdict source now, for every parameter."""
    ctx = _timelock_ctx()
    execute = "execute(address,uint256,bytes,bytes32,bytes32)"
    for index in range(5):
        verdict = _facts.param_constraint(ctx, execute, index)
        assert verdict["state"] == "constrained"
        assert verdict["guard"] == "hash_commitment"
        assert verdict["binding"] == "standard_gate"
    # An unresolved index is still not a proof of anything.
    assert _facts.param_constraint(ctx, execute, None) == {"state": "not_determined"}


def test_flow_and_exec_witnesses_publish_the_same_standard_verdict():
    """The self-contradiction regression: both consumers read
    ``standard_destination_commitment`` (directly or through the pre-pass), so
    the flow's ``target_constraint`` and the exec witness's
    ``destination_constraint`` are equal by construction."""
    ctx = _timelock_ctx()
    execute = "execute(address,uint256,bytes,bytes32,bytes32)"
    standard = _facts.standard_destination_commitment(ctx, execute)
    assert standard is not None
    assert _facts.param_constraint(ctx, execute, 0) == standard


def test_a_timelock_shaped_tree_without_the_standard_gate_is_not_committed():
    """The pre-pass needs the STANDARD's sibling set, not a lookalike selector:
    without ``getMinDelay``/``hashOperation``/``schedule`` the lossy fold blocks
    and the answer stays open — never a commitment, never a proof of freedom."""
    execute = "execute(address,uint256,bytes,bytes32,bytes32)"
    functions = {
        execute: {
            "abi_signature": execute,
            "parameter_names": ["target", "value", "payload", "predecessor", "salt"],
            "sinks": [],
            "value_flows": [],
        },
        # The mapping's declared type is visible the way it is on a real
        # artifact: some sibling writes it and records the type.
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
    # The mapping-element fold (key dropped) blocks the proof for every index.
    assert _facts.param_constraint(ctx, execute, 0) == {"state": "not_determined"}
