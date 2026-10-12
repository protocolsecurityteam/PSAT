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

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "predicates" / "control_flow_fidelity.sol"
SOLC_VERSION = "0.8.27"


@cache
def _artifacts(contract: str) -> tuple[dict[str, Any], dict[str, Any]]:
    from slither import Slither

    from services.static.claims import build_claims
    from services.static.contract_analysis_pipeline.effects import build_effects
    from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts
    from services.static.contract_analysis_pipeline.shared import _select_subject_contract
    from tests.support.label_corpus import _solc_select_binary

    solc = _solc_select_binary(SOLC_VERSION)
    if not solc.exists():  # pragma: no cover - only when the pinned solc is absent
        pytest.skip(f"solc {SOLC_VERSION} not installed via solc-select")
    subject = _select_subject_contract(Slither(str(FIXTURE), solc=str(solc)), contract)
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
    halted_clear = ("equality", "falsy", "halted")
    assert _tree("HelperPaths", "nonOperatorOnly(uint256)") == (
        "AND",
        halted_clear,
        ("equality", "ne", "msg_sender", "owner"),
        NOT_MEMBER,
    )
    assert _tree("HelperPaths", "operatorOnly(uint256)") == (
        "OR",
        ("AND", halted_clear, OWNER),
        ("AND", halted_clear, MEMBER),
    )


def test_a_missing_return_is_the_default_false():
    assert _tree("HelperPaths", "unflaggedOnly(uint256)") == NOT_MEMBER


def test_every_return_path_of_a_helper_is_read_with_its_guard():
    assert _tree("HelperPaths", "eitherCheck(uint256)") == (
        "OR",
        ("AND", ("comparison", "gt", "x", "100"), OWNER),
        ("AND", ("comparison", "lte", "x", "100"), MEMBER),
    )


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
