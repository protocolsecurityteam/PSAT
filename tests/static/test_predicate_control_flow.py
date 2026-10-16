"""Predicate trees state each gate's allowed condition under the control flow it runs in
(``fixtures/contracts/predicates/control_flow_fidelity.sol``).

A bool helper's return keeps the negation of the call that reads it, its own ``require``s keep their polarity, and every
return path carries the guards that reach it. A revert reached only under a path condition gates the function only
under that condition; where the condition can't be stated (a loop, a ``try``), the gate's alternative is unsupported.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")

pytestmark = pytest.mark.compile

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "predicates"
FIXTURE = FIXTURES / "control_flow_fidelity.sol"
SOLC_VERSION = "0.8.27"
# Transient state variables need solc 0.8.28 or later.
TRANSIENT_FIXTURE = FIXTURES / "control_flow_transient.sol"
TRANSIENT_SOLC_VERSION = "0.8.37"


@cache
def _artifacts(
    contract: str, fixture: Path = FIXTURE, solc_version: str = SOLC_VERSION
) -> tuple[dict[str, Any], dict[str, Any]]:
    from slither import Slither

    from services.static.claims import build_claims
    from services.static.contract_analysis_pipeline.effects import build_effects
    from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts
    from services.static.contract_analysis_pipeline.shared import _select_subject_contract
    from tests.support.label_corpus import _solc_select_binary

    solc = _solc_select_binary(solc_version)
    if not solc.exists():  # pragma: no cover - only when the pinned solc is absent
        pytest.skip(f"solc {solc_version} not installed via solc-select")
    subject = _select_subject_contract(Slither(str(fixture), solc=str(solc)), contract)
    assert subject is not None, contract
    trees = build_predicate_artifacts(subject)
    build_claims(subject, build_effects(subject), trees)
    return trees["trees"], trees.get("effect_scopes") or {}


def _shape(tree: Any) -> Any:
    """A tree as nested tuples: ``(op, children...)`` or a leaf ``(kind, operator, operand names...)``."""
    if tree.get("op") != "LEAF":
        return (tree["op"], *(_shape(child) for child in tree.get("children") or []))
    leaf = tree["leaf"]
    if leaf["kind"] == "unsupported":
        return ("unsupported", leaf["unsupported_reason"])
    names = []
    for operand in leaf.get("operands") or []:
        source = operand.get("source")
        if source == "state_variable":
            names.append(operand.get("state_variable_name"))
        elif source == "parameter":
            names.append(operand.get("parameter_name"))
        elif source == "constant":
            names.append(str(operand.get("constant_value")))
        else:
            names.append(source)
    return (leaf["kind"], leaf["operator"], *names)


def _tree(contract: str, signature: str) -> Any:
    return _shape(_artifacts(contract)[0][signature])


def _site(contract: str, signature: str, kind: str, target: str) -> Any:
    sites = _artifacts(contract)[1][signature]
    (site,) = [s for s in sites if s["kind"] == kind and s["target"] == target]
    return _shape(site["predicate"])


PAUSED_OPEN = ("equality", "falsy", "_paused")
PAUSED_CLOSED = ("equality", "truthy", "_paused")
NOT_MEMBER = ("membership", "falsy", "msg_sender")
MEMBER = ("membership", "truthy", "msg_sender")
OWNER = ("equality", "eq", "msg_sender", "owner")


@pytest.mark.parametrize(
    ("signature", "expected"),
    [
        ("ifGetterRevert(uint256)", PAUSED_OPEN),
        ("requireNotGetter(uint256)", PAUSED_OPEN),
        ("ifDirectRevert(uint256)", PAUSED_OPEN),
        ("requireGetter(uint256)", PAUSED_CLOSED),
        ("ifBlacklistedRevert(uint256)", NOT_MEMBER),
        ("requireNotBlacklisted(uint256)", NOT_MEMBER),
        ("directBlacklist(uint256)", NOT_MEMBER),
        ("requireAllowed(uint256)", MEMBER),
        ("ifNotAllowedRevert(uint256)", MEMBER),
    ],
)
def test_a_getter_read_under_a_negated_call_states_the_negated_condition(signature, expected):
    assert _tree("HelperPolarity", signature) == expected


@pytest.mark.parametrize("signature", ["depositV4(uint256)", "depositV5(uint256)"])
def test_openzeppelin_when_not_paused_allows_only_while_unpaused(signature):
    assert _tree("OzPausable", signature) == PAUSED_OPEN


def test_a_getter_through_a_storage_pointer_keeps_the_negation():
    assert _tree("OzPausableUpgradeable", "deposit(uint256)") == ("equality", "falsy", "PausableStorageLocation")


def test_a_negated_helper_keeps_its_require_and_negates_each_return_path():
    halted_clear = HALTED_CLEAR
    assert _tree("HelperPaths", "nonOperatorOnly(uint256)") == (
        "AND",
        halted_clear,
        ("equality", "ne", "msg_sender", "owner"),
        NOT_MEMBER,
    )
    assert _tree("HelperPaths", "operatorOnly(uint256)") == ("AND", halted_clear, ("OR", OWNER, MEMBER))


def test_a_missing_return_is_the_default_false():
    assert _tree("HelperPaths", "unflaggedOnly(uint256)") == NOT_MEMBER


def _eq(variable: str, value: str, operator: str = "eq") -> tuple:
    return ("equality", operator, variable, value)


def test_returns_after_a_join_carry_every_branch_that_reaches_them():
    """Each mode checks only its own list, and the open mode passes anyone."""
    member, nonmember = ("membership", "truthy", "msg_sender"), ("membership", "falsy", "msg_sender")
    assert _tree("HelperJoins", "send(uint256)") == (
        "OR",
        ("AND", _eq("mode", "1"), member),
        ("AND", _eq("mode", "1", "ne"), _eq("mode", "2", "ne")),
        ("AND", _eq("mode", "1", "ne"), _eq("mode", "2"), nonmember),
    )
    assert _tree("HelperJoins", "act(uint256)") == (
        "OR",
        ("AND", ("equality", "falsy", "globalPause"), ("equality", "falsy", "localMode")),
        ("AND", ("equality", "falsy", "globalPause"), ("equality", "truthy", "localMode"), nonmember),
    )


def test_a_revert_in_a_helper_gates_only_where_it_is_reached():
    unless_strict = ("equality", "falsy", "strict")
    not_paused = ("equality", "falsy", "paused")
    flag_set, flag_clear = ("equality", "truthy", "flag"), ("equality", "falsy", "flag")
    assert _tree("HelperJoins", "requireUnderBranch(uint256)") == (
        "AND",
        ("OR", unless_strict, not_paused),
        flag_set,
    )
    assert _tree("HelperJoins", "revertUnderBranch(uint256)") == ("AND", ("OR", unless_strict, not_paused), flag_set)
    assert _tree("HelperJoins", "revertUnderBranchNegated(uint256)") == (
        "AND",
        ("OR", unless_strict, not_paused),
        flag_clear,
    )
    assert _tree("HelperJoins", "ownerUnderBranch(uint256)") == (
        "AND",
        ("OR", unless_strict, OWNER),
        ("membership", "truthy", "msg_sender"),
    )


@pytest.mark.parametrize("signature", ["notListed(uint256)", "listedOnly(uint256)"])
def test_a_helper_return_inside_a_loop_is_not_determined(signature):
    assert _tree("HelperJoins", signature) == ("unsupported", "loop_iteration_not_determined")


def test_every_return_path_of_a_helper_is_read_with_its_guard():
    assert _tree("HelperPaths", "eitherCheck(uint256)") == (
        "OR",
        ("AND", ("comparison", "gt", "x", "100"), OWNER),
        ("AND", ("comparison", "lte", "x", "100"), MEMBER),
    )


HALTED_CLEAR = ("equality", "falsy", "halted")
OPEN_MODE = ("equality", "truthy", "openMode")
LARGE = ("comparison", "lte", "v", "10")


@pytest.mark.parametrize(
    ("signature", "expected"),
    [
        ("condNoEffect(uint256)", ("OR", OPEN_MODE, OWNER)),
        ("condEffectInside(uint256)", ("OR", OPEN_MODE, OWNER)),
        ("condModifier(uint256)", ("OR", OPEN_MODE, OWNER)),
        ("condParam(uint256)", ("OR", LARGE, OWNER)),
        ("conditionalHelper(uint256)", ("OR", LARGE, OWNER)),
        ("earlyReturn(uint256)", ("OR", ("equality", "eq", "v", "0"), OWNER)),
        ("nestedIfRevert(uint256)", ("OR", ("equality", "falsy", "openMode"), OWNER)),
        ("placeholderUnderCondition(uint256)", ("OR", ("equality", "falsy", "live"), OWNER)),
        # The custom error is ``require``'s argument, not a revert ending the branch.
        ("customErrorUnderBranch(uint256)", ("OR", LARGE, OWNER)),
    ],
)
def test_a_revert_under_a_path_condition_gates_only_under_it(signature, expected):
    assert _tree("ConditionalGates", signature) == expected


@pytest.mark.parametrize("signature", ["writeThenBranch(uint256)", "writeInCallThenBranch(uint256)"])
def test_a_branch_on_storage_written_before_it_is_not_determined(signature):
    assert _tree("ConditionalGates", signature) == (
        "OR",
        ("unsupported", "branch_reads_state_written_before"),
        OWNER,
    )


@pytest.mark.parametrize(
    "signature",
    [
        "elementWrite(uint256)",
        "structWrite(uint256)",
        "itemWrite(uint256)",
        "pointerWrite(uint256)",
        "bodyWritesBeforeModifierBranch(uint256)",
        "bodyIncrements(uint256)",
        "innerModifierWrites(uint256)",
    ],
)
def test_a_branch_on_storage_written_before_it_runs_is_not_determined(signature):
    """Element and pointer writes, and a modifier's code after ``_`` reading what the body or an inner modifier
    wrote."""
    reach_or_owner = ("OR", ("unsupported", "branch_reads_state_written_before"), OWNER)
    tree = _tree("WriteBeforeBranch", signature)
    # A library call on storage also publishes its own leaf beside the gate.
    assert tree == reach_or_owner or (tree[0] == "AND" and reach_or_owner in tree[1:]), tree


def test_a_branch_in_a_body_run_more_than_once_is_not_determined():
    assert _tree("WriteBeforeBranch", "bodyRunsTwice(uint256)") == (
        "OR",
        ("unsupported", "body_runs_repeatedly"),
        OWNER,
    )


WRITTEN_BEFORE = ("unsupported", "branch_reads_state_written_before")
OPEN_FLAG = ("equality", "truthy", "open")


def test_a_helper_called_once_keeps_its_reach():
    assert _tree("HelperRunTwice", "viaOnce(uint256)") == ("OR", OPEN_FLAG, OWNER)


@pytest.mark.parametrize("signature", ["viaTwice(uint256)", "viaTwiceIf(uint256)", "viewTwiceBody(uint256)"])
def test_a_helper_read_from_a_body_run_twice_is_not_determined(signature):
    assert _tree("HelperRunTwice", signature) == ("unsupported", "body_runs_repeatedly")


@pytest.mark.parametrize("signature", ["viaDouble(uint256)", "sameIf(uint256)"])
def test_two_calls_in_one_condition_each_may_see_the_others_writes(signature):
    """Only a call's own result orders what else the statement runs, so each call's branch may follow the other call."""
    assert _tree("HelperRunTwice", signature) == ("AND", ("OR", WRITTEN_BEFORE, OWNER), ("OR", WRITTEN_BEFORE, OWNER))


def test_a_transient_store_counts_as_a_write():
    assert _tree("HelperRunTwice", "transientWriteThenBranch(uint256)") == ("OR", WRITTEN_BEFORE, OWNER)


def _transient_tree(signature: str) -> Any:
    return _shape(_artifacts("TransientAliasing", TRANSIENT_FIXTURE, TRANSIENT_SOLC_VERSION)[0][signature])


@pytest.mark.parametrize(
    "signature",
    [
        "namedWriteRawRead(uint256)",
        "helperNamedWriteRawRead(uint256)",
        "rawWriteNamedRead(uint256)",
        "slotWriteNamedRead(uint256)",
        "libWriteNamedRead(uint256)",
    ],
)
def test_a_transient_variable_and_raw_transient_storage_are_one_cell(signature):
    tree = _transient_tree(signature)
    # A library call also publishes its own leaf beside the gate.
    assert tree == ("OR", WRITTEN_BEFORE, OWNER) or (tree[0] == "AND" and ("OR", WRITTEN_BEFORE, OWNER) in tree[1:]), (
        tree
    )


@pytest.mark.parametrize("signature", ["rawWritePersistentRead(uint256)", "namedWritePersistentRead(uint256)"])
def test_a_transient_write_keeps_a_branch_on_persistent_storage(signature):
    assert _transient_tree(signature) == ("OR", OPEN_FLAG, OWNER)


@pytest.mark.parametrize("signature", ["binRight(uint256)", "modPair(uint256)"])
def test_a_call_beside_the_leading_call_may_run_before_it(signature):
    """Solidity leaves the order of operands and arguments open; legacy codegen runs these right to left."""
    assert _tree("CallOrder", signature) == ("OR", WRITTEN_BEFORE, OWNER)


def test_a_call_on_the_leading_calls_result_runs_after_it():
    assert _tree("CallOrder", "straightNested(uint256)") == ("OR", OPEN_FLAG, OWNER)


def test_the_leading_call_is_found_beside_its_phi_callbacks():
    assert _tree("CallOrder", "readAfterCall(uint256)") == ("OR", OPEN_FLAG, OWNER)


@pytest.mark.parametrize(
    "signature",
    [
        "loopNested(uint256)",
        "whileNested(uint256)",
        "doNested(uint256)",
        "loopCall(uint256)",
        "loopGate(uint256)",
    ],
)
def test_a_helper_called_from_a_loop_runs_more_than_once(signature):
    tree = _tree("CallOrder", signature)
    assert ("unsupported", "body_runs_repeatedly") in tree[1:], tree
    assert OPEN_FLAG not in tree[1:], tree


def test_a_helper_called_from_a_connective_return_keeps_its_value():
    tree = _tree("ApprovalChain", "transferFrom(address,address,uint256)")
    leaves = _leaves(_artifacts("ApprovalChain")[0]["transferFrom(address,address,uint256)"])
    assert ("unsupported", "gate_location_not_determined") not in [
        _shape({"op": "LEAF", "leaf": leaf}) for leaf in leaves
    ]
    assert ("membership", "truthy", "view_call", "msg_sender") in tree[1][1], tree


def test_a_helper_called_from_a_connective_return_sees_the_writes_before_its_caller():
    admin = ("equality", "eq", "msg_sender", "admin")
    tree = _tree("ApprovalChain", "closeThenCheck(uint256)")
    assert tree[0] == "AND", tree
    nested = [child for child in tree[1:] if child[0] == "OR" and ("OR", WRITTEN_BEFORE, admin) in child[1:]]
    assert nested, tree
    assert OPEN_FLAG not in [leaf for child in tree[1:] for leaf in _flat(child)], tree


def _flat(shape: Any) -> list[Any]:
    if shape[0] in ("AND", "OR"):
        return [leaf for child in shape[1:] for leaf in _flat(child)]
    return [shape]


ADMIN = ("equality", "eq", "msg_sender", "admin")
OPS = ("membership", "truthy", "msg_sender")


@pytest.mark.parametrize("signature", ["r1()", "r2()", "r3()"])
def test_a_ternarys_operands_may_run_before_its_condition(signature):
    """Slither splits a ternary into a condition and arms, but the statement's other operands may run first."""
    assert _tree("TernarySplit", signature) == ("OR", WRITTEN_BEFORE, ADMIN)


def test_a_helper_return_path_sees_the_writes_before_the_call():
    assert _tree("HelperValueWrites", "closeThenEither(uint256)") == ("OR", WRITTEN_BEFORE, OPS)


@pytest.mark.parametrize("signature", ["deep(uint256)", "deepNeg(uint256)"])
def test_a_nested_helper_return_path_sees_the_writes_before_the_outer_call(signature):
    expected = ("AND", ("equality", "falsy", "paused"), ("OR", OPS, ("OR", WRITTEN_BEFORE, ADMIN)))
    assert _tree("HelperValueWrites", signature) == expected


def test_a_nested_helper_return_path_sees_a_sibling_calls_writes():
    tree = _tree("HelperValueWrites", "deepW(uint256)")
    assert ("OR", WRITTEN_BEFORE, ADMIN) in tree[1:], tree
    assert OPEN_FLAG not in _flat(tree), tree


def test_a_nested_helper_return_path_without_writes_keeps_its_branch():
    expected = ("AND", ("equality", "falsy", "paused"), ("OR", OPS, ("OR", OPEN_FLAG, ADMIN)))
    assert _tree("HelperValueWrites", "deepNoWrite(uint256)") == expected


def test_a_write_to_other_storage_keeps_the_branch():
    assert _tree("ConditionalGates", "unrelatedWriteThenBranch(uint256)") == ("OR", OPEN_MODE, OWNER)


def test_a_modifier_running_the_body_on_both_branches_reaches_it_always():
    assert _tree("ConditionalGates", "bothPlaceholders(uint256)") == (
        "AND",
        OWNER,
        ("OR", OPEN_MODE, ("equality", "eq", "msg_sender", "guardian")),
    )


def test_reach_conditions_are_not_labelled_as_gates():
    trees = _artifacts("ConditionalGates")[0]
    reach_leaves = [
        leaf
        for tree in trees.values()
        for leaf in _leaves(tree)
        if "revert_path_condition" in (leaf.get("basis") or [])
    ]
    assert reach_leaves
    assert not [leaf for leaf in reach_leaves if leaf["authority_role"] in ("pause", "reentrancy", "one_shot")]


@pytest.mark.parametrize("signature", ["act(uint256)", "actTrusted(uint256)"])
def test_an_authority_check_reaching_a_gate_does_not_gate_the_mappings_writer(signature):
    (leaf,) = _leaves(_artifacts("WriterGateReach")[0][signature])
    assert leaf["authority_role"] == "business"
    assert not [basis for basis in leaf.get("basis") or [] if "writer-gate" in basis]


def test_a_writer_gated_on_every_reaching_path_still_promotes_its_mapping():
    (leaf,) = _leaves(_artifacts("WriterGateReach")[0]["actStaff(uint256)"])
    assert leaf["authority_role"] == "caller_authority"


def _leaves(tree: Any) -> list[dict[str, Any]]:
    if tree.get("op") == "LEAF":
        return [tree["leaf"]]
    return [leaf for child in tree.get("children") or [] for leaf in _leaves(child)]


def test_a_gate_in_a_loop_body_is_not_stated_as_unconditional():
    assert _tree("ConditionalGates", "loopGate(address[])") == (
        "OR",
        ("unsupported", "loop_iteration_not_determined"),
        ("membership", "truthy", "accounts"),
    )


def test_a_gate_in_a_try_block_is_not_stated_as_unconditional():
    tree = _tree("ConditionalGates", "tryGate(IPing,uint256)")
    assert ("OR", ("unsupported", "branch_condition_not_determined"), OWNER) in tree[1:]
    assert OWNER not in tree[1:]


@pytest.mark.parametrize(
    ("signature", "expected"),
    [
        ("revertThenRequire(uint256)", ("AND", ("comparison", "lte", "v", "3"), OWNER)),
        ("joinThenRequire(uint256)", OWNER),
        # The helper only returns true, so the branch that skips the require is never taken.
        ("constantBranch(uint256)", OWNER),
    ],
)
def test_a_revert_reached_on_every_path_stays_unconditional(signature, expected):
    assert _tree("ConditionalGates", signature) == expected


def test_an_effect_inside_the_guarded_branch_is_gated_by_the_require():
    assert _site("ConditionalGates", "condEffectInside(uint256)", "state_write", "hook") == (
        "AND",
        OWNER,
        ("equality", "falsy", "openMode"),
    )


@pytest.mark.parametrize(
    ("signature", "expected"),
    [
        ("condModifier(uint256)", ("OR", OPEN_MODE, OWNER)),
        ("conditionalHelper(uint256)", ("OR", LARGE, OWNER)),
        ("condParam(uint256)", ("OR", LARGE, ("AND", ("comparison", "gt", "v", "10"), OWNER))),
    ],
)
def test_an_effect_after_a_conditional_gate_is_reached_without_it(signature, expected):
    assert _site("ConditionalGates", signature, "state_write", "hook") == expected
