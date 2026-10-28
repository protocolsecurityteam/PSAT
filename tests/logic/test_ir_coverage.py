"""Dispatch coverage, not a proof of compositional semantics. Chain tests live beside this file."""

import inspect

import services.logic.lower as lower


def test_every_operation_class_is_handled_or_rejected():
    import slither.slithir.operations as operations

    names = {name for name, _ in inspect.getmembers(operations, inspect.isclass)} | {"CodeSize"}
    classified = lower.HANDLED_OPERATIONS | set(lower.REJECTED_OPERATIONS) | lower.ABSTRACT_OPERATIONS
    assert names == classified, f"unclassified: {sorted(names - classified)}, stale: {sorted(classified - names)}"
    assert not lower.HANDLED_OPERATIONS & set(lower.REJECTED_OPERATIONS)


def test_every_binary_and_unary_operator_is_handled():
    from slither.slithir.operations import BinaryType, UnaryType

    handled = set(lower._BINARY) | set(lower._COMPARE) | {BinaryType.ANDAND, BinaryType.OROR}
    assert set(BinaryType) == handled
    assert set(UnaryType) == {UnaryType.BANG, UnaryType.TILD}


def test_every_builtin_is_handled_or_rejected():
    from slither.core.declarations.solidity_variables import SOLIDITY_FUNCTIONS

    names = set(SOLIDITY_FUNCTIONS)
    classified = lower.HANDLED_BUILTINS | set(lower.REJECTED_BUILTINS)
    assert names <= classified, f"unclassified: {sorted(names - classified)}"
    assert not lower.HANDLED_BUILTINS & set(lower.REJECTED_BUILTINS)


def test_every_special_variable_is_handled_or_rejected():
    from slither.core.declarations.solidity_variables import SOLIDITY_VARIABLES, SOLIDITY_VARIABLES_COMPOSED

    names = set(SOLIDITY_VARIABLES) | set(SOLIDITY_VARIABLES_COMPOSED)
    classified = lower.HANDLED_VARIABLES | set(lower.REJECTED_VARIABLES)
    assert names <= classified, f"unclassified: {sorted(names - classified)}"
    assert not lower.HANDLED_VARIABLES & set(lower.REJECTED_VARIABLES)


def test_every_yul_builtin_is_classified_for_the_legacy_reader():
    from slither.solc_parsing.yul.evm_functions import builtins

    sets = (lower.LEGACY_YUL_HANDLED, set(lower.LEGACY_YUL_OPAQUE), lower.LEGACY_YUL_UNSUPPORTED)
    names = set(builtins)
    assert names <= set().union(*sets), f"unclassified: {sorted(names - set().union(*sets))}"
    assert all(not (a & b) for i, a in enumerate(sets) for b in sets[i + 1 :])
