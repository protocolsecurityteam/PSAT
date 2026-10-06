"""Selector computation and ERC-20 selector-evidence discovery."""

from __future__ import annotations

import re
from typing import Any

from eth_utils.crypto import keccak


def _is_fallback_or_receive(fn: Any) -> bool:
    if getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False):
        return True
    return (getattr(fn, "name", "") or "") in ("fallback", "receive")


def _node_irs(node: Any) -> list[Any]:
    return list(getattr(node, "irs", []) or [])


def _function_full_name(fn: Any) -> str:
    name = getattr(fn, "full_name", None) or getattr(fn, "name", None) or "<anonymous>"
    return str(name)


def _selector_for(signature: str | None) -> str | None:
    """keccak256[:4] of a canonical ``name(types)`` signature, or ``None``.

    A string test: ``"fallback()"`` passes, so a function's own selector must go through :func:`_own_selector`.
    """
    if not signature or "(" not in signature or ")" not in signature:
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _own_selector(fn: Any) -> str | None:
    """The selector that reaches ``fn``, or ``None`` for fallback/receive (their name hashes are not dispatches).

    Matches ``db/effect_cache.py``'s empty-string sentinel.
    """
    if _is_fallback_or_receive(fn):
        return None
    from ..predicate_artifacts import _canonical_signature

    return _selector_for(_canonical_signature(fn))


def _callee_signature(ir: Any) -> str | None:
    fn = getattr(ir, "function", None)
    # A resolved sibling call joins on the sibling's canonical selector (``cross_contract``), so lower user-defined
    # types here too; ``addAsset(ERC20)`` would hash wrong. Library calls keep the string form: nothing joins on them.
    if type(ir).__name__ == "HighLevelCall" and fn is not None:
        from ..predicate_artifacts import _canonical_signature

        canonical = _canonical_signature(fn)
        if canonical:
            return canonical
    for attr in ("full_name", "signature_str"):
        value = getattr(fn, attr, None)
        if isinstance(value, str) and "(" in value and value.endswith(")"):
            return value.rsplit(".", 1)[-1]
    value = getattr(ir, "function_name", None)
    if isinstance(value, str) and "(" in value and value.endswith(")"):
        return value.rsplit(".", 1)[-1]
    return None


def _auto_getter_selector(variable: Any) -> str | None:
    """Selector of solc's auto-getter for a ``public`` state variable, or ``None`` when it takes arguments.

    A compiler fact, not a name guess: solc mints it and rejects colliding functions. The signature comes from the
    declared type because they diverge once the getter takes arguments (``uint256[] public amounts`` is
    ``amounts(uint256)``, not ``amounts()``). Parameterised getters need a key, which this plane can't witness.
    """
    from slither.core.variables.state_variable import StateVariable

    if not isinstance(variable, StateVariable) or getattr(variable, "visibility", None) != "public":
        return None
    try:
        _, parameters, _ = variable.signature
        signature = variable.solidity_signature
    except (AttributeError, TypeError, ValueError, KeyError):  # pragma: no cover - slither edge
        return None
    if parameters:
        return None
    return _selector_for(signature)


# Token-first safe-transfer libraries (Solmate/Solady ``SafeTransferLib``, OZ ``SafeERC20``) take the token first, so
# ``(to, amount)`` shift right, their own selectors aren't ERC-20's, and Slither lowers them to library/internal calls
# the selector scan can't see. Identified by the ERC-20 selector the callee body provably issues, only where the
# value-flow walk can't resolve it itself.
_ERC20_TRANSFER_SELECTOR = _selector_for("transfer(address,uint256)")
_ERC20_TRANSFER_FROM_SELECTOR = _selector_for("transferFrom(address,address,uint256)")

# Solmate/Solady and OZ build the selector in the helper itself; deeper would credit a nested helper's transfer to an
# unrelated caller.
_TOKEN_FIRST_BODY_DEPTH = 1


# Fixed-size byte types: a folded ``.selector`` or assembly literal. Dynamic ``bytes`` and ``string`` are excluded
# (revert messages are also ``str``).
_FIXED_BYTES_TYPE = re.compile(r"bytes([1-9]|[12][0-9]|3[0-2])$")


def _selector_of_constant(operand: Any) -> str | None:
    """The selector a constant operand denotes, or ``None``: a folded ``bytes4``
    (``abi.encodeWithSelector(token.transfer.selector, ...)``) or an assembly word with the selector left-aligned.
    ``bytesN`` values arrive as decimal strings, so the declared type is what separates them from revert strings.
    """
    value = getattr(operand, "value", None)
    if isinstance(value, str) and _FIXED_BYTES_TYPE.fullmatch(str(getattr(operand, "type", "") or "")):
        try:
            value = int(value)
        except ValueError:
            return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    if value < 1 << 32:
        return f"0x{value:08x}"
    if value >> 224 and not value & ((1 << 224) - 1):
        return f"0x{value >> 224:08x}"
    return None


def _selector_of_member_access(ir: Any) -> str | None:
    """The selector behind ``<var>.<fn>`` on a contract-typed variable (``abi.encodeCall``), resolved against the
    declared type's functions; ``None`` if overloaded or unresolvable.
    """
    if type(ir).__name__ != "Member":
        return None
    member = getattr(getattr(ir, "variable_right", None), "value", None)
    if not isinstance(member, str) or not member:
        return None
    declared = getattr(getattr(ir, "variable_left", None), "type", None)
    target = getattr(declared, "type", None)
    candidates = [fn for fn in (getattr(target, "functions", None) or []) if (getattr(fn, "name", "") or "") == member]
    if len(candidates) != 1:
        return None
    return _selector_for(_function_full_name(candidates[0]))


def _ir_operands(ir: Any) -> list[Any]:
    """Every value operand of an IR, flattening ``abi.encodeCall``'s nested tuples."""
    operands: list[Any] = []
    for attr in ("rvalue", "variable", "variable_left", "variable_right"):
        value = getattr(ir, attr, None)
        if value is not None:
            operands.append(value)
    for argument in getattr(ir, "arguments", None) or []:
        operands.extend(argument if isinstance(argument, (list, tuple)) else [argument])
    return operands


# EVM call opcodes as Slither names them on a ``SolidityCall`` (language builtins, so a spec fact). Solmate/Solady
# dispatch assembly-built calldata this way.
_EVM_CALL_OPCODES = ("call", "staticcall", "delegatecall", "callcode")


# Deeper than ``_TOKEN_FIRST_BODY_DEPTH``: this only refuses evidence, and OZ SafeERC20 puts three hops between building
# and making the call.
_DISPATCH_SEARCH_DEPTH = 5


def _dispatches_a_call(unit: Any, seen: frozenset[int], depth: int) -> bool:
    if unit is None or depth > _DISPATCH_SEARCH_DEPTH:
        return False
    for node in getattr(unit, "nodes", []) or []:
        for ir in _node_irs(node):
            op = type(ir).__name__
            if op in ("HighLevelCall", "LowLevelCall") or _is_evm_call_opcode(ir):
                return True
            if op in ("InternalCall", "LibraryCall"):
                callee = getattr(ir, "function", None)
                key = id(callee)
                if callee is not None and key not in seen and getattr(callee, "nodes", None):
                    if _dispatches_a_call(callee, seen | {key}, depth + 1):
                        return True
    return False


def _is_evm_call_opcode(ir: Any) -> bool:
    if type(ir).__name__ != "SolidityCall":
        return False
    name = str(getattr(getattr(ir, "function", None), "name", "") or "")
    return name.split("(", 1)[0] in _EVM_CALL_OPCODES


def _erc20_selectors_issued(unit: Any, seen: frozenset[int], depth: int) -> tuple[set[str], set[str]]:
    """``(issued, walk_visible)``: ERC-20 move selectors ``unit``'s body provably issues, and the subset the
    value-flow walk can resolve itself.
    """
    found, visible, _ = _erc20_selector_evidence(unit, seen, depth)
    return found, visible


def _erc20_selector_evidence(unit: Any, seen: frozenset[int], depth: int) -> tuple[set[str], set[str], bool]:
    """``(issued, walk_visible, dispatches)`` for a unit and its helpers.

    Evidence: a resolved call whose canonical signature is an ERC-20 move (walk-visible), a materialized selector value,
    or a compiler-bound member access (the two the walk can't see). Keeping them apart avoids double-counting.

    A materialized selector only counts if a call is actually dispatched (a deny-list or a timelock storing calldata
    mentions it without moving anything). ``dispatches`` is transitive because OZ ``safeTransfer`` builds calldata in
    one frame and calls in ``_callOptionalReturn``.
    """
    found: set[str] = set()
    visible: set[str] = set()
    if unit is None or depth > _TOKEN_FIRST_BODY_DEPTH:
        return found, visible, False
    wanted = {_ERC20_TRANSFER_SELECTOR, _ERC20_TRANSFER_FROM_SELECTOR}
    materialized: set[str] = set()
    dispatches = False
    for node in getattr(unit, "nodes", []) or []:
        for ir in _node_irs(node):
            op = type(ir).__name__
            if op == "HighLevelCall":
                called = _selector_for(_callee_signature(ir))
                if called in wanted:
                    found.add(str(called))
                    visible.add(str(called))
            for operand in _ir_operands(ir):
                selector = _selector_of_constant(operand)
                if selector in wanted:
                    materialized.add(str(selector))
            member = _selector_of_member_access(ir)
            if member in wanted:
                materialized.add(str(member))
            if op in ("InternalCall", "LibraryCall"):
                callee = getattr(ir, "function", None)
                key = id(callee)
                if callee is not None and key not in seen and getattr(callee, "nodes", None):
                    child_found, child_visible, child_dispatches = _erc20_selector_evidence(
                        callee, seen | {key}, depth + 1
                    )
                    found |= child_found
                    visible |= child_visible
                    dispatches = dispatches or child_dispatches
    if materialized and (dispatches or _dispatches_a_call(unit, frozenset({id(unit)}), 0)):
        found |= materialized
        dispatches = True
    return found, visible, dispatches


def _token_first_transfer(ir: Any) -> tuple[str, ...] | None:
    """Classify a token-first library transfer call: ``("send", to, amount)`` or ``("pull", from, to, amount)`` from
    the shifted call-site arguments, or ``None``.

    The callee body must issue exactly one ERC-20 move selector (picks send vs pull), and the trailing argument types
    must match its ABI tail (excluding bare 2/3-arg forms and ERC-721's ``bytes`` tail). Callees issuing it through a
    resolved call are left to the walk, which would otherwise double-count.

    Not applied to ``InternalCall``: this reads ``to``/``amount`` at the call site without proving the callee forwards
    them. Libraries have no storage to redirect through, but a same-contract helper can (``_settle`` looking up
    ``payoutOverride[to]``), and reading it at the call site once published an anyone-redirectable payout as provably
    fixed. The walk reaches the library call inside anyway.
    """
    callee = getattr(ir, "function", None)
    if callee is None or not getattr(callee, "nodes", None):
        return None
    signature = _callee_signature(ir)
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    inner = signature[signature.index("(") + 1 : -1]
    types = [t.strip() for t in inner.split(",")] if inner else []
    args = list(getattr(ir, "arguments", []) or [])
    issued, walk_visible = _erc20_selectors_issued(callee, frozenset({id(callee)}), 0)
    if len(issued) != 1 or walk_visible:
        return None
    selector = next(iter(issued))
    if selector == _ERC20_TRANSFER_SELECTOR and types[1:] == ["address", "uint256"] and len(args) >= 3:
        return ("send", args[1], args[2])
    if selector == _ERC20_TRANSFER_FROM_SELECTOR and types[1:] == ["address", "address", "uint256"] and len(args) >= 4:
        return ("pull", args[1], args[2], args[3])
    return None
