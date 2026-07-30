"""``_facts.param_constraints`` — the mandatory-gate analysis.

The question is *"does a mandatory revert gate reference this parameter between
entry and sink?"*, and the answer has three states that a consumer must be able
to tell apart. These tests drive the analysis on hand-built predicate trees
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
    # Proven NON-pinning: the consumer keeps the caller-chosen reading.
    assert verdict["pins"] is False


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
    is the overshoot this analysis must avoid."""
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


def test_an_external_revert_surface_guard_never_claims_to_pin():
    """``external_call_revert`` is another contract's answer: a blacklist
    (``nonBlacklisted``) and an allowlist (``deployedEtherFiNodes``) present the
    identical shape here, so ``pins`` is None — not determined — and a consumer
    must not soften the caller-chosen reading on it (all four real
    ``constrained`` flow rows are this kind and are in fact blacklists)."""
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
    """A ``value_router`` flow records the CALLEE's inner transfer selector, so
    the router call this function makes joins only through the flow's
    ``router_ops`` — the identity the producer recorded at the crossing site.
    Joined here by the callee's bare name, because the declared signature
    (``exit(address,IERC20,…)``) does not hash to the selector the sink
    recorded. The router's revert surface is exactly the effect's, so it must
    not block the negative proof."""
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
    """The sibling of the transparency positive above: a nonview body-call
    leaf that is NOT the recorded router op (``guard.checkDestination(to)``
    beside ``vault.exit(to, …)``) is unevaluable, and the function must fall to
    ``not_determined`` — not fall THROUGH to the ``unconstrained_proven``
    default. Before router_ops, every body call on a routed function was
    transparent and this guard's leaf was swallowed: the guarded function and
    its guard-free twin published byte-identical negative proofs."""
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
    """An artifact produced before ``router_ops`` existed carries a routed flow
    with no router identity. Absence of the record is not a licence to widen:
    the router's own leaf then blocks and the answer stays ``not_determined`` —
    an under-claim, never a minted proof. (Realised on the local DB: both
    persisted ``bulkWithdraw`` param destinations fall from the pre-fix
    ``unconstrained_proven`` to ``not_determined`` until re-analysis records
    the op.)"""
    ctx = _ctx(
        _leaf(**_ROUTER_LEAF),
        sinks=[{"kind": "external_call", "target": "vault.exit", "selector": "0x18457e61", "origin": "body"}],
        flows=[
            {"kind": "callee_erc20_selector", "selector": "0xa9059cbb", "direction": "value_router", "origin": "body"}
        ],
    )
    assert _facts.param_constraint(ctx, "f(address,uint256)", 0) == {"state": "not_determined"}


# ---------------------------------------------------------------------------
# derived_from: consumed, never trusted as ground truth
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
    # ...and BECAUSE it is flow-insensitive, the verdict never claims a proven
    # pin: `pins` is the one field that may soften the caller-chosen reading
    # downstream, and a union over branches is not a proof that the guard
    # confines this parameter on every path (`address t = defaultTo; if (cond)
    # t = to;` — on the `!cond` branch `to` is wholly unconstrained).
    assert verdict["pins"] is None


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
    the misbind consumed as ground truth in exactly the forbidden direction —
    the flow-insensitive union can OMIT an origin that genuinely feeds
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
    """The exact misbind shape: ``keccak(receiver, nativeWrapper)`` published
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


def test_without_ir_no_effectful_callee_is_transparent_in_exec_mode():
    """INVERTED: the old arm pinned exec-mode transparency for ANY
    body call, which is exactly the swallowing that let a mandatory Safe/Zodiac
    transaction-guard leaf publish ``unconstrained_proven`` on a vetted
    destination — byte-identical to a function with no guard at all, a proof of
    absence minted from a leaf the walk chose not to evaluate. Transparency is
    now earned per call op, from an IR proof that the op's own destination is
    parameter-rooted; a context with no Slither subject can prove that for no
    op, so the effectful-callee leaf blocks the negative proof in BOTH modes.
    The transparent positive is pinned where the proof is reachable — on the
    compiled corpus (``test_claims_upgrade_exec_matchers.
    test_the_arbitrary_calls_own_revert_surface_is_still_transparent``)."""
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
    """A modifier's own authority call is not the effect, so its revert surface
    stays a real gate. It can never enter the exec-mode transparency set: that
    set is built from the function's OWN body call ops, proven parameter-
    destination in IR — a guard-origin call is neither."""
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
# Projection completeness (a leaf's silence is only
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
    """EtherFiTimelock.execute: the generic walk saw no
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
        assert verdict["pins"] is True
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


def _safe_ctx() -> ClaimContext:
    """A Safe-gate contract (getThreshold + getOwners + execTransaction) with
    both exec shapes. ``execTransaction``'s tree carries the opaque signature
    check the real contract routes through ``checkSignatures`` — the walk alone
    answers ``not_determined``; the standard's shape answers for it. The
    module-exec tree is the published gate exactly: ``modules[msg.sender] !=
    address(0)``, a membership whose only key is the CALLER."""
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
        # The mapping's declared type is visible the way it is on a real
        # artifact: the module-management sibling writes it.
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
    """``execTransaction`` is the entry whose parameters ride under
    the owners' threshold signatures — every one of its ten indices carries the
    standard commitment. The module-exec entries share ``SAFE_EXEC_SELECTORS``
    and the contract gate, but their guard is ``modules[msg.sender]`` — an
    allowlist on the CALLER that commits nothing about any parameter — so the
    standard helper answers ``None`` for them, never a fabricated
    ``signature_witness``."""
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
    """The published module gate is a complete projection — a membership whose
    every key is ``msg.sender`` — and it references no ABI parameter, so the
    walk PROVES the destination free: ``unconstrained_proven``, the verdict that
    keeps the caller-chosen hazard standing downstream. What it must never be
    is ``pins: True``: no signature commits ``to``, and an enabled module calls
    any target with any calldata."""
    ctx = _safe_ctx()
    for module_fn in (
        "execTransactionFromModule(address,uint256,bytes,uint8)",
        "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)",
    ):
        for index in range(4):
            verdict = _facts.param_constraint(ctx, module_fn, index, mode="external_call")
            assert verdict == {"state": "unconstrained_proven"}, (module_fn, index)


def test_the_signed_entry_alone_would_be_opaque_without_the_standard():
    """The signed tree's ``checkSignatures`` fold is opaque; strip the Safe gate
    siblings (keep only the exec entries) and the pre-pass cannot fire — the
    walk answers ``not_determined``, never a commitment from a lookalike
    selector."""
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
