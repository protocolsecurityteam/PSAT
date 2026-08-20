"""Selector computation and ERC-20 selector-evidence discovery."""

from __future__ import annotations

import re
from typing import Any

from eth_utils.crypto import keccak


def _is_fallback_or_receive(fn: Any) -> bool:
    if getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False):
        return True
    return (getattr(fn, "name", "") or "") in ("fallback", "receive")


# ---------------------------------------------------------------------------
# Sink discovery (transitive across internal calls).
# ---------------------------------------------------------------------------


def _node_irs(node: Any) -> list[Any]:
    return list(getattr(node, "irs", []) or [])


def _function_full_name(fn: Any) -> str:
    name = getattr(fn, "full_name", None) or getattr(fn, "name", None) or "<anonymous>"
    return str(name)


def _selector_for(signature: str | None) -> str | None:
    """Compute keccak256[:4] of a canonical ``name(types)`` signature.
    Returns ``None`` if the signature isn't in canonical form.

    Note this is a *string* test: Slither renders a fallback's ``full_name`` as
    ``"fallback()"``, which is canonical-looking and hashes happily. Callers
    passing a function's own name must go through :func:`_own_selector`."""
    if not signature or "(" not in signature or ")" not in signature:
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _own_selector(fn: Any) -> str | None:
    """The 4-byte selector a caller would put in ``msg.sig`` to reach ``fn`` —
    ``None`` for ``fallback`` / ``receive``, which have none by construction.

    ``keccak("fallback()")[:4] = 0x552079dc`` and ``keccak("receive()")[:4] =
    0xa3e76c0f`` are not dispatches: no caller can send them, and a contract
    that did define ``function fallback()`` would own that selector instead.
    ``db/effect_cache.py`` already fixes the empty string as the sentinel for
    this case; this is that convention, not a second one."""
    if _is_fallback_or_receive(fn):
        return None
    return _selector_for(_function_full_name(fn))


def _callee_signature(ir: Any) -> str | None:
    fn = getattr(ir, "function", None)
    # A direct high-level call to a resolved sibling joins on selector against
    # that sibling's OWN canonical selector (``cross_contract`` derivation 1), so
    # lower user-defined parameter types here too — contract/interface → address,
    # enum → uint<N>, struct → tuple. The string ``full_name`` keeps names like
    # ``addAsset(ERC20)`` or ``send(MessagingParams,address)`` whose keccak is not
    # the real EVM selector, and once the callee side is canonical the join would
    # silently drop such a call. A LibraryCall's callee is a library internal with
    # no external selector and nothing joins against it, so it keeps the string
    # form (its selector is notional and ubiquitous — not worth churning).
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
    """The selector of the getter solc mints for a ``public`` state variable,
    or ``None`` when no NULLARY getter exists.

    Why this is a compiler fact and not a name guess: for every ``public``
    state variable solc emits an accessor at a selector it derives itself, and
    it REJECTS a hand-written function that would collide with one — so the
    binding from declaration to selector is 1:1 and enforced by the compiler,
    which ``name + "()"`` is not.

    The signature comes from the DECLARED TYPE (``solidity_signature``, i.e.
    solc's own ``export_nested_types_from_variable`` rule), never from the
    identifier, because the two disagree the moment the getter takes
    arguments: ``uint256[] public amounts`` is read by ``amounts(uint256)``
    (0x45f0a44f) while ``amounts()`` hashes to 0x6beaeeae, and
    ``mapping(address => uint256) public balances`` is ``balances(address)``
    (0x27e235e3) against ``balances()``'s 0x7bb98a68. Both are reachable here:
    a library call's receiver is its FIRST ARGUMENT, which may be any type at
    all. Emitting the minted-from-name value would publish four bytes that
    address no function — a fabricated positive, and four bytes collide.

    A parameterised getter cannot be read without choosing a key, and choosing
    one is not something this plane can witness, so it yields ``None``."""
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


# The token-first safe-transfer library idiom (Solmate / Solady ``SafeTransferLib``,
# OZ ``SafeERC20``): the token is the FIRST argument, so the ``(to, amount)`` /
# ``(from, to, amount)`` slots are shifted one right of the bare ERC-20 selectors.
# Their own canonical signatures — ``safeTransfer(ERC20,address,uint256)`` /
# ``safeTransferFrom(ERC20,address,address,uint256)`` — hash to selectors NOT in
# the bare ERC-20 sets, and Slither lowers them to ``LibraryCall`` (or, when the
# helper is a plain internal, ``InternalCall``), so the value move is invisible to
# the selector scan. What identifies the shape is the ERC-20 selector the callee
# BODY provably issues (below), never the callee's identifier — and only where
# that body issues it in a form the value-flow walk cannot resolve for itself, so
# the recognizer covers the walk's blind spot instead of competing with it.
_ERC20_TRANSFER_SELECTOR = _selector_for("transfer(address,uint256)")
_ERC20_TRANSFER_FROM_SELECTOR = _selector_for("transferFrom(address,address,uint256)")

# How far into the callee to look for the issued selector. Solmate/Solady build
# it in the helper's own assembly and OZ SafeERC20 builds it in the helper's own
# ``abi.encodeCall``, so one extra hop only covers a thin wrapper; going deeper
# would start attributing a nested helper's transfer to an unrelated caller.
_TOKEN_FIRST_BODY_DEPTH = 1


# Fixed-size byte types (``bytes1`` … ``bytes32``). A constant of one of these is
# a numeric word: the compiler folded a ``.selector`` member or an assembly
# literal into it. ``string`` and ``bytes`` (dynamic) are excluded — a revert
# message is also handed back as a Python ``str``, and only the DECLARED type
# separates the two.
_FIXED_BYTES_TYPE = re.compile(r"bytes([1-9]|[12][0-9]|3[0-2])$")


def _selector_of_constant(operand: Any) -> str | None:
    """The 4-byte selector a constant operand denotes, or ``None``.

    Two encodings, both pure value facts:
    ``abi.encodeWithSelector(token.transfer.selector, …)`` folds to a ``bytes4``
    constant equal to the selector; the assembly form
    ``mstore(ptr, 0xa9059cbb00…00)`` folds to a 32-byte word carrying the
    selector left-aligned in its top four bytes and zeros below.

    A ``bytesN`` constant's value arrives as a DECIMAL STRING rather than an
    ``int``, so the numeric word has to be read back through the declared type —
    which is also what keeps a revert-message ``string`` (identically a Python
    ``str``) from being read as a selector. Rejecting the string form outright is
    what made the OZ ``SafeERC20`` idiom, whose selector comes from exactly this
    fold, invisible to the recognizer."""
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
    """The selector behind ``<var>.<fn>`` on a contract/interface-typed variable
    (``abi.encodeCall(token.transfer, …)``), or ``None``.

    The member name is resolved against the DECLARED type's own function list —
    the compiler's binding — and the selector comes from that declaration's
    canonical signature. An overloaded or unresolvable member yields ``None``."""
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
    """Every value operand of one IR, flattening the argument tuples
    ``abi.encodeCall`` nests."""
    operands: list[Any] = []
    for attr in ("rvalue", "variable", "variable_left", "variable_right"):
        value = getattr(ir, attr, None)
        if value is not None:
            operands.append(value)
    for argument in getattr(ir, "arguments", None) or []:
        operands.extend(argument if isinstance(argument, (list, tuple)) else [argument])
    return operands


# The EVM call opcodes, as Slither names them on a ``SolidityCall``. These are
# language builtins, not user identifiers, so keying on them is a published-spec
# fact of the same kind as a selector. Solmate/Solady build their calldata in
# assembly and dispatch it with a raw ``call``, which reaches the IR as one of
# these rather than as a Low/HighLevelCall.
_EVM_CALL_OPCODES = ("call", "staticcall", "delegatecall", "callcode")


# How deep to look for the DISPATCH, as opposed to the selector. Deliberately
# deeper than ``_TOKEN_FIRST_BODY_DEPTH``: that cap bounds selector ATTRIBUTION,
# where reaching further would start crediting a nested helper's transfer to an
# unrelated caller. "Does this call tree ever dispatch a call at all" carries no
# such risk — it only ever REFUSES evidence — and OZ's SafeERC20 puts three hops
# between the two (``safeTransfer`` builds the calldata, ``_callOptionalReturn``
# forwards it, ``Address.functionCall`` makes the call).
_DISPATCH_SEARCH_DEPTH = 5


def _dispatches_a_call(unit: Any, seen: frozenset[int], depth: int) -> bool:
    """Whether ``unit`` or a helper it calls ever dispatches an actual call."""
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
    """``(issued, walk_visible)`` — the bare ERC-20 move selectors ``unit``'s body
    provably issues, and the subset it issues in a form the value-flow walk can
    resolve on its own."""
    found, visible, _ = _erc20_selector_evidence(unit, seen, depth)
    return found, visible


def _erc20_selector_evidence(unit: Any, seen: frozenset[int], depth: int) -> tuple[set[str], set[str], bool]:
    """``(issued, walk_visible, dispatches)`` for one unit and the helpers it calls.

    Evidence is a resolved external call whose canonical signature IS an ERC-20
    move, a selector VALUE the body materializes (assembly literal or
    ``abi.encodeWithSelector`` constant), or a member access the compiler bound
    to an ERC-20 declaration (``abi.encodeCall``). None of it reads an identifier
    of the unit itself.

    Only the FIRST form is walk-visible: a resolved ``HighLevelCall`` to
    ``transfer``/``transferFrom`` is a site the ordinary recursion already
    classifies when it descends into this unit. The other two are the whole
    reason the recognizer exists — a selector built in assembly or handed to a
    low-level ``.call`` moves tokens with no IR the walk can see. Keeping them
    apart is what lets the recognizer fire on a same-contract helper without ever
    displacing, or double-counting, a move the walk already resolves.

    A MATERIALIZED selector counts only if the body actually DISPATCHES a call —
    mentioning a selector is not issuing one. A deny-list
    (``require(sel != IERC20.transfer.selector)``) and a timelock that builds
    calldata to store for later both materialize the constant while moving
    nothing, and both would otherwise publish a fabricated ``flow.out``.

    ``dispatches`` is TRANSITIVE, and it has to be: OZ's ``SafeERC20.safeTransfer``
    materializes the selector in its own frame (``abi.encodeCall``) and hands it
    to ``_callOptionalReturn``, which is where the ``.call`` actually happens.
    Judging each frame alone therefore threw the evidence away exactly on the
    most common safe-transfer library in existence."""
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
    """Classify a token-first library/internal transfer call, or ``None``.

    Returns ``("send", to, amount)`` for ``<helper>(<Token>, to, amount)`` and
    ``("pull", from, to, amount)`` for ``<helper>(<Token>, from, to, amount)`` —
    the operands being the call-site arguments in the SHIFTED positions.

    Two independent facts must agree, and neither is the helper's name. The
    callee's body must provably issue exactly ONE bare ERC-20 move selector,
    which is what picks send vs pull; a body issuing both (or neither) is
    ``None``. The trailing argument types must then match that selector's ABI
    tail, which discriminates the token-first form from the bare
    ``transfer(address,uint256)`` / ``transferFrom(address,address,uint256)``
    (2 / 3 args) the selector scan already handles, and from ERC-721
    ``safeTransferFrom(...,bytes)`` (a ``bytes`` tail). With the token occupying
    the leading slot, the remaining formals are the only type-consistent
    carriers of the ABI tail the callee forwards.

    A callee that issues the selector through a RESOLVED call is not recognized
    here at all: the ordinary recursion descends into it and classifies that site
    itself, so firing would double-count the move — two sites on one flow key,
    folding a resolvable destination to ``indeterminate``. The recognizer is for
    the moves the walk is BLIND to, and nothing else.

    NOT applied to an ``InternalCall``, and the reason is the argument this whole
    function does NOT make: it reads ``to``/``amount`` off the CALL SITE without
    proving the callee forwards them into the selector's slots. For a library
    that assumption is close to definitional — a library holds no mutable storage
    to redirect through, and the token-first wrappers exist precisely to forward.
    An arbitrary same-contract helper matching ``f(T, address, uint256)`` is a
    different animal:

        function _settle(IERC20 token, address to, uint256 amount) internal {
            address dest = payoutOverride[to];      // anyone may set this
            if (dest == address(0)) dest = to;
            SafeTransferLib.safeTransfer(token, dest, amount);
        }

    Reading ``_settle(token, treasury, amount)`` at the call site published
    ``target_kind: immutable`` at ``dispositive_ast`` — and §4.2 promoted it to
    ``immutable_fixed``, a PROVABLY-UNREDIRECTABLE destination — for a payout any
    caller can repoint. The walk reaches the library call inside ``_settle``
    anyway and classifies ``dest`` honestly, so nothing is lost by declining
    here."""
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
