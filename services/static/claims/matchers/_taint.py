"""Parameter-taint evidence for the ``exec.arbitrary`` manage-idiom.

The claim is minted only when a body-origin external call forwards a
caller-supplied destination *and* a caller-supplied calldata blob — the
BoringVault.manage / direct low-level ``target.call(data)`` shape. Proven by
reading Slither IR directly (``ClaimContext.contract``): a call op in the
function body whose read set contains an ``address`` parameter and a dynamic
``bytes`` parameter. That two-parameter requirement is what separates ``manage``
from a plain ``transfer(address,uint256)`` value send (address-tainted
destination, no arbitrary calldata).

**Read-set membership mints the claim; it does not name the binding.** The two
published names answer a narrower question — *which* parameter reaches the call
in the destination position, and *which* one reaches it as the calldata blob —
and that question is answered from the operand positions, never from the read
set. Where the operand position does not resolve to a parameter the name is
``None`` and the accompanying ``*_kind`` says why: a state variable in the
destination position is a proven *absence* of a caller-chosen destination
(``state_var``), which is a different fact from the analysis not settling it
(``not_determined``). A consumer may treat a name as a binding only when the
kind is ``param``.

**Both proof states are load-bearing, so both are earned rather than defaulted
into.** The IR this reads is not in SSA form, so a name the body assigns more
than once carries several candidate values under one variable object; which one
the call sees is a control-flow question, and answering it with either proof
state would be a guess in a proof's clothing — the exact inversion of the
governing rule. Every resolution step that is not forced (a multiply-defined
name, a cycle, a chain past ``_RESOLVE_DEPTH``, a library body that did not
resolve) yields ``not_determined``, which under-claims by construction.

Underscore-prefixed so matcher auto-discovery skips it.
"""

from __future__ import annotations

from typing import Any

from ..context import ClaimContext

# Operand layout of the EVM call opcodes, as inline assembly presents them:
# ``call``/``callcode`` are (gas, address, value, argsOffset, argsSize,
# retOffset, retSize); ``delegatecall``/``staticcall`` drop the value word.
# Solady-class libraries forward in assembly, so these indices are the only
# place their destination and payload are legible at all.
_ASM_FORWARDER_OPERANDS = {
    "call": (1, 3),
    "callcode": (1, 3),
    "delegatecall": (1, 2),
    "staticcall": (1, 2),
}

# The low-level members that carry a caller-chosen calldata blob. ``send`` and
# ``transfer`` are ``LowLevelCall`` too and carry none.
_PAYLOAD_BEARING_CALLS = frozenset({"call", "callcode", "delegatecall", "staticcall"})

# How far an operand may be followed back through temporaries before giving up.
_RESOLVE_DEPTH = 8


def _slither_function(ctx: ClaimContext, signature: str) -> Any | None:
    """The implemented Slither function whose full-name matches ``signature``.
    Returns ``None`` when the contract is absent (degraded) or the function is a
    pure interface declaration with no body."""
    contract = getattr(ctx, "contract", None)
    if contract is None:
        return None
    for function in getattr(contract, "functions", None) or []:
        if getattr(function, "full_name", None) != signature:
            continue
        if getattr(function, "is_constructor", False):
            continue
        if getattr(function, "nodes", None):
            return function
    return None


def _element_type(variable: Any) -> str:
    """The parameter's type with array suffixes stripped.

    A batch executor declares ``address[]``/``bytes[]`` where a scalar one
    declares ``address``/``bytes``, and the call op forwards one ELEMENT of each.
    The element type is therefore what decides taint — an exact match on the
    declared type silently excluded every batch executor. ``bytes32[]`` still
    reduces to ``bytes32`` and is still rejected."""
    type_name = str(getattr(variable, "type", ""))
    while type_name.endswith("]"):
        open_bracket = type_name.rfind("[")
        if open_bracket == -1:
            break
        type_name = type_name[:open_bracket]
    return type_name


def _is_dynamic_bytes(variable: Any) -> bool:
    # ``bytes`` (dynamic) taints as arbitrary calldata; ``bytes32`` etc. do not.
    return _element_type(variable) == "bytes"


def _is_address(variable: Any) -> bool:
    return _element_type(variable) == "address"


def _is_array(variable: Any) -> bool:
    return str(getattr(variable, "type", "")).strip() != _element_type(variable)


def _origin(variable: Any) -> Any:
    """The variable a read ultimately refers to.

    An element access (``targets[i]``) reaches the call op as a Slither
    ``ReferenceVariable``, never as the parameter itself, so an identity test
    against the parameter list matches nothing inside a batch loop. Slither
    already resolves the reference chain; asking it is the whole of the fix, and
    no points-to analysis of our own is involved. Non-reference variables have no
    such attribute and stand for themselves."""
    return getattr(variable, "points_to_origin", None) or variable


class _Undetermined:
    """The resolver reached a point where the operand has more than one candidate.

    Deliberately NOT a Slither variable: it matches no parameter identity and is
    an instance of no Slither class, so every caller that asks "is this a
    parameter / is this a state variable" answers no and degrades to
    ``not_determined`` without a branch of its own. The three published states
    stay distinguishable (R1) precisely because this value cannot be mistaken for
    either proof."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return "<undetermined>"


UNDETERMINED = _Undetermined()


def _definitions(function: Any) -> dict[int, Any]:
    """``id(lvalue) -> defining IR``, or ``UNDETERMINED`` where more than one
    definition reaches that name.

    Keyed by identity and only ever read by direct lookup. Slither's variable
    classes inherit ``object.__hash__``, so any container of them that gets
    ITERATED orders by allocation address — not by ``PYTHONHASHSEED``, and so
    not pinnable by any determinism gate built the obvious way.

    These IRs are NOT in SSA form: ``address t = fallbackRoute; if (flag) t = a;``
    gives both assignments the same ``LocalVariable`` object, so a
    one-IR-per-name map answers with whichever appears first in source order —
    and the answer is then published as one of the two PROOF states. Counting is
    what separates "this name holds one value" from "the call sees one of
    several, and which one is a control-flow question this analysis does not
    answer"; only the first is a binding.

    A parameter arrives already holding the caller's value and a state variable
    already holding storage's, so for those a SINGLE assignment in the body is
    the second definition of the name, not the first."""
    from slither.core.variables.state_variable import StateVariable

    counts: dict[int, int] = {}
    first: dict[int, Any] = {}
    lvalues: dict[int, Any] = {}
    for node in getattr(function, "nodes", None) or []:
        for ir in getattr(node, "irs", None) or []:
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None:
                continue
            key = id(lvalue)
            counts[key] = counts.get(key, 0) + 1
            lvalues[key] = lvalue
            first.setdefault(key, ir)
    parameter_ids = {id(parameter) for parameter in getattr(function, "parameters", None) or []}
    return {
        key: (
            UNDETERMINED if count > 1 or key in parameter_ids or isinstance(lvalues[key], StateVariable) else first[key]
        )
        for key, count in counts.items()
    }


def _root_variable(variable: Any, definitions: dict[int, Any]) -> Any:
    """The variable an operand ultimately names, or ``UNDETERMINED``.

    Slither routes ``ISwapper(swapper).swap(…)`` through a temporary, so the call
    op's ``destination`` is a ``TemporaryVariable`` and the state variable behind
    it is reachable only through the defining ``TypeConversion``. Without this
    walk every interface-typed destination reads as unresolvable.

    The walk answers with a variable only where every step of it was forced. A
    multiply-defined name, a cycle, and a chain longer than ``_RESOLVE_DEPTH``
    are all cases where it was not, and each returns ``UNDETERMINED`` rather than
    whatever variable the walk happened to be holding — publishing that would be
    a guess wearing a proof's clothes."""
    from slither.slithir.operations import Assignment, TypeConversion

    seen: set[int] = set()
    for _ in range(_RESOLVE_DEPTH):
        if variable is None:
            return None
        variable = _origin(variable)
        if id(variable) in seen:
            return UNDETERMINED
        seen.add(id(variable))
        ir = definitions.get(id(variable))
        if ir is UNDETERMINED:
            return UNDETERMINED
        if isinstance(ir, TypeConversion):
            variable = getattr(ir, "variable", None)
        elif isinstance(ir, Assignment):
            variable = getattr(ir, "rvalue", None)
        else:
            return variable
    return UNDETERMINED


def _parameter_index(variable: Any, parameters: list[Any]) -> int | None:
    for index, parameter in enumerate(parameters):
        if parameter is variable:
            return index
    return None


def _operand_parameter_indices(variable: Any, definitions: dict[int, Any], parameters: list[Any]) -> list[int] | None:
    """Every parameter index the operand is built from, ascending, or ``None``
    when the walk crossed a name the body defines more than once.

    An assembly forwarder passes ``add(data, 0x20)`` rather than ``data``, so the
    payload sits one arithmetic step away from the parameter supplying it.
    Returns a sorted list: a set of Slither objects may never decide an output.

    ``None`` and ``[]`` are different facts and the caller must not merge them —
    an enumeration that walked past a multiply-defined name has seen one branch's
    sources, so a single index in it is not evidence that it is the only one."""
    found: set[int] = set()
    seen: set[int] = set()
    stack: list[tuple[Any, int]] = [(variable, 0)]
    while stack:
        current, depth = stack.pop()
        if current is None or depth > _RESOLVE_DEPTH:
            continue
        current = _origin(current)
        if id(current) in seen:
            continue
        seen.add(id(current))
        index = _parameter_index(current, parameters)
        if index is not None:
            found.add(index)
            continue
        ir = definitions.get(id(current))
        if ir is UNDETERMINED:
            return None
        if ir is None:
            continue
        for read in getattr(ir, "read", None) or []:
            stack.append((read, depth + 1))
    return sorted(found)


def _forwarded_operand_indices(callee: Any) -> tuple[int, int] | None:
    """``(destination_index, payload_index)`` into ``callee``'s OWN parameter
    list, when its body forwards a call assembled from those parameters.

    ``using Address for address`` and ``LibCall.callContract(to, 0, data)`` both
    put the library in the call op's destination and the real target in argument
    position. The library body says which argument that is — the OZ shape as a
    ``LowLevelCall`` on a parameter, the Solady shape as an assembly ``call``
    whose second operand is a parameter — so one level of indirection is all it
    takes to answer a question that was previously guessed from the read set.

    One level only, deliberately: a forwarder that itself calls another forwarder
    is not resolved, and the caller emits ``not_determined`` rather than a name."""
    from slither.slithir.operations import LowLevelCall, SolidityCall

    parameters = list(getattr(callee, "parameters", None) or [])
    if not parameters:
        return None
    definitions = _definitions(callee)
    for node in getattr(callee, "nodes", None) or []:
        for ir in getattr(node, "irs", None) or []:
            arguments = list(getattr(ir, "arguments", None) or [])
            if isinstance(ir, LowLevelCall):
                if str(getattr(ir, "function_name", "")) not in _PAYLOAD_BEARING_CALLS or not arguments:
                    continue
                destination_operand, payload_operand = getattr(ir, "destination", None), arguments[0]
            elif isinstance(ir, SolidityCall):
                opcode = str(getattr(getattr(ir, "function", None), "name", "")).split("(", 1)[0]
                layout = _ASM_FORWARDER_OPERANDS.get(opcode)
                if layout is None or len(arguments) <= max(layout):
                    continue
                destination_operand, payload_operand = arguments[layout[0]], arguments[layout[1]]
            else:
                continue
            destination_index = _parameter_index(_root_variable(destination_operand, definitions), parameters)
            payload_sources = _operand_parameter_indices(payload_operand, definitions, parameters)
            if destination_index is None or payload_sources is None:
                continue
            payload_indices = [index for index in payload_sources if _is_dynamic_bytes(parameters[index])]
            if len(payload_indices) != 1:
                continue
            return destination_index, payload_indices[0]
    return None


def _call_positions(ir: Any, definitions: dict[int, Any]) -> tuple[Any, str, Any, str, str | None]:
    """``(destination_operand, destination_state, payload_operand, payload_state,
    basis)`` for one call op.

    ``payload_state`` separates three genuinely different facts: the op has a
    calldata blob and here it is (``operand``); the op is a typed call whose
    selector is fixed, so it carries no caller-chosen blob at all (``none``); or
    the op forwards through a library whose body did not resolve (``unknown``)."""
    from slither.slithir.operations import LibraryCall, LowLevelCall

    if isinstance(ir, LibraryCall):
        indices = _forwarded_operand_indices(getattr(ir, "function", None))
        arguments = list(getattr(ir, "arguments", None) or [])
        if indices is None or max(indices) >= len(arguments):
            return None, "unknown", None, "unknown", None
        return arguments[indices[0]], "operand", arguments[indices[1]], "operand", "library_forwarder"
    destination = getattr(ir, "destination", None)
    if isinstance(ir, LowLevelCall):
        arguments = list(getattr(ir, "arguments", None) or [])
        if str(getattr(ir, "function_name", "")) in _PAYLOAD_BEARING_CALLS and arguments:
            return destination, "operand", arguments[0], "operand", "call_destination"
        return destination, "operand", None, "none", "call_destination"
    # A typed high-level call: the callee's selector is fixed, so no argument of
    # it is a caller-chosen calldata blob.
    return destination, "operand", None, "none", "call_destination"


def _classify_destination(
    operand: Any, state: str, definitions: dict[int, Any], parameters: list[Any]
) -> tuple[str | None, str]:
    """``(name, kind)`` for the destination operand.

    Both proof states are earned here and nothing falls into them by default:
    ``param`` needs an identity match against the parameter list and
    ``state_var`` needs the root to BE a state variable. ``UNDETERMINED`` — what
    ``_root_variable`` answers where the value depends on which branch ran — is
    neither, so it lands on ``not_determined`` without a test of its own."""
    from slither.core.variables.state_variable import StateVariable

    if state != "operand":
        return None, "not_determined"
    root = _root_variable(operand, definitions)
    index = _parameter_index(root, parameters)
    if index is not None:
        return (getattr(parameters[index], "name", "") or ""), "param"
    if isinstance(root, StateVariable):
        return None, "state_var"
    return None, "not_determined"


def arbitrary_exec_taint(ctx: ClaimContext, signature: str) -> dict[str, Any] | None:
    """Return a witness fragment when ``signature`` forwards a parameter-tainted
    destination and calldata on a body call op, else ``None``.

    Whether the fragment is returned at all is decided exactly as before — by
    read-set membership. What changed is what the fragment SAYS: the two names
    are read off the destination and payload operand positions, so a name is
    published only where the IR puts that parameter in that position."""
    function = _slither_function(ctx, signature)
    if function is None:
        return None
    parameters = list(getattr(function, "parameters", None) or [])
    address_params = {p for p in parameters if _is_address(p)}
    bytes_params = {p for p in parameters if _is_dynamic_bytes(p)}
    if not address_params or not bytes_params:
        return None
    # An address in the call's READ set is only in argument position, which is
    # not the same as being the destination — ``fixedSink.execute(users[i],
    # payloads[i])`` reads an address parameter while calling a fixed contract.
    # For a SCALAR parameter that conflation is load-bearing: the library-mediated
    # ``target.functionCallWithValue(data, value)`` puts the library in the
    # destination and the real target in argument position, and separating the two
    # needs the library's body. An ARRAY parameter has no such excuse — a genuine
    # batch executor calls the element, so its destination resolves to the array
    # itself and the direct test below already proves it. Admitting arrays here
    # bought one library-mediated batch shape and a false arbitrary-call badge on
    # every fixed-destination batch forwarder.
    argument_address_params = {p for p in address_params if not _is_array(p)}

    # Import locally so a missing slither install degrades the matcher (isolated
    # by build_claims) instead of breaking package import.
    from slither.slithir.operations import HighLevelCall, LibraryCall, LowLevelCall

    definitions = _definitions(function)
    for node in getattr(function, "nodes", None) or []:
        for ir in getattr(node, "irs", None) or []:
            if not isinstance(ir, (LowLevelCall, HighLevelCall, LibraryCall)):
                continue
            reads = {_origin(v) for v in getattr(ir, "read", None) or []}
            destination = _origin(getattr(ir, "destination", None))
            dest_tainted = destination in address_params or bool(reads & argument_address_params)
            data_tainted = bool(reads & bytes_params)
            if not (dest_tainted and data_tainted):
                continue
            dest_operand, dest_state, data_operand, data_state, basis = _call_positions(ir, definitions)
            dest_param, dest_kind = _classify_destination(dest_operand, dest_state, definitions, parameters)
            if data_state == "operand":
                index = _parameter_index(_root_variable(data_operand, definitions), parameters)
                data_param = (getattr(parameters[index], "name", "") or "") if index is not None else None
                data_kind = "param" if index is not None else "not_determined"
            elif data_state == "none":
                # Proven-absent rather than undetermined only if a tainting bytes
                # parameter really is sitting in an argument slot of this op.
                argument_roots = {
                    id(_root_variable(argument, definitions)) for argument in getattr(ir, "arguments", None) or []
                }
                carried = any(id(p) in argument_roots for p in bytes_params)
                data_param, data_kind = None, ("call_argument" if carried else "not_determined")
            else:
                data_param, data_kind = None, "not_determined"
            return {
                "destination_param": dest_param,
                "destination_kind": dest_kind,
                "destination_basis": basis if dest_kind == "param" else None,
                "calldata_param": data_param,
                "calldata_kind": data_kind,
                "calldata_basis": basis if data_kind == "param" else None,
            }
    return None
