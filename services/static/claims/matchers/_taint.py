"""Parameter-taint evidence for the ``exec.arbitrary`` manage idiom: a body call op whose read set contains an
``address`` parameter and a dynamic ``bytes`` parameter (``target.call(data)``), which a plain
``transfer(address,uint256)`` lacks.

Read-set membership mints the claim; the published names come from operand positions. A name is ``None`` unless its
``*_kind`` is ``param``: ``state_var`` is a proven absence of a caller-chosen destination, ``not_determined`` is
unsettled. The IR is not SSA, so any unforced resolution step (multiply-defined name, cycle, depth limit, unresolved
library) yields ``not_determined``.
"""

from __future__ import annotations

from typing import Any

from ..context import ClaimContext

# EVM call opcode operand layout in inline assembly (``delegatecall``/``staticcall`` drop the value word); the only
# place Solady-style assembly forwarders expose destination and payload.
_ASM_FORWARDER_OPERANDS = {
    "call": (1, 3),
    "callcode": (1, 3),
    "delegatecall": (1, 2),
    "staticcall": (1, 2),
}

# ``send``/``transfer`` are low-level calls too but carry no calldata.
_PAYLOAD_BEARING_CALLS = frozenset({"call", "callcode", "delegatecall", "staticcall"})

_RESOLVE_DEPTH = 8


def _slither_function(ctx: ClaimContext, signature: str) -> Any | None:
    """The implemented Slither function for ``signature``; ``None`` if the contract is absent or it's a bodiless
    interface declaration.
    """
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
    """The parameter type without array suffixes: batch executors forward one element of ``address[]``/``bytes[]``."""
    type_name = str(getattr(variable, "type", ""))
    while type_name.endswith("]"):
        open_bracket = type_name.rfind("[")
        if open_bracket == -1:
            break
        type_name = type_name[:open_bracket]
    return type_name


def _is_dynamic_bytes(variable: Any) -> bool:
    return _element_type(variable) == "bytes"


def _is_address(variable: Any) -> bool:
    return _element_type(variable) == "address"


def _is_array(variable: Any) -> bool:
    return str(getattr(variable, "type", "")).strip() != _element_type(variable)


def _origin(variable: Any) -> Any:
    """The variable a read refers to: element accesses arrive as ``ReferenceVariable``s, so resolve through Slither's
    reference chain.
    """
    return getattr(variable, "points_to_origin", None) or variable


class _Undetermined:
    """Sentinel for an operand with several candidate values.

    Matches no parameter and no Slither class, so every check degrades to ``not_determined``.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return "<undetermined>"


UNDETERMINED = _Undetermined()


def _definitions(function: Any) -> dict[int, Any]:
    """``id(lvalue) -> defining IR``, or ``UNDETERMINED`` where more than one definition reaches the name.

    Keyed by identity and only looked up, never iterated (Slither variables hash by address). The IR is not SSA, so one
    variable object can carry several assignments; counting separates a binding from a control-flow question. Parameters
    and state variables start with a value, so one body assignment is already their second definition.
    """
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

    Walks through temporaries (``ISwapper(swapper).swap(...)`` goes via a conversion); any unforced step returns
    ``UNDETERMINED``.
    """
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
    """Sorted parameter indices the operand is built from, or ``None`` if the walk crossed a multiply-defined name
    (then any index seen may not be the only one). Assembly forwarders pass ``add(data, 0x20)``.
    """
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
    """``(destination_index, payload_index)`` into ``callee``'s own parameters when its body forwards a call built
    from them (OZ ``Address`` as a ``LowLevelCall`` on a parameter, Solady ``LibCall`` as an assembly ``call``).
    One level only; deeper forwarders give ``not_determined``.
    """
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


def proven_param_destination_call_identities(ctx: ClaimContext, signature: str) -> tuple[set[str], set[str]] | None:
    """``(selectors, bare callee names)`` of body calls whose destination is proven parameter-rooted: the
    transparency set for ``exec``-mode constraint walks.

    A caller-chosen receiver can't vet the caller's choice; a fixed receiver (a Safe/Zodiac guard) is a real
    precondition. An identity is withheld if any op sharing it has a fixed or unresolved destination, since a leaf can't
    say which op it describes. Low-level calls are skipped (their check carries no callee identity). ``None`` means
    nobody looked (no Slither subject), distinct from empty.
    """
    function = _slither_function(ctx, signature)
    if function is None:
        return None
    # Computed as the effects producer computes sink selectors, so it joins against tree leaves the same way.
    from slither.slithir.operations import HighLevelCall, LibraryCall, LowLevelCall

    from ...contract_analysis_pipeline.effects import _callee_signature, _selector_for

    parameters = list(getattr(function, "parameters", None) or [])
    definitions = _definitions(function)
    param_selectors: set[str] = set()
    param_names: set[str] = set()
    withheld_selectors: set[str] = set()
    withheld_names: set[str] = set()
    for node in getattr(function, "nodes", None) or []:
        for ir in getattr(node, "irs", None) or []:
            if isinstance(ir, LowLevelCall) or not isinstance(ir, (HighLevelCall, LibraryCall)):
                continue
            destination_operand, destination_state, _payload, _payload_state, _basis = _call_positions(ir, definitions)
            _name, destination_kind = _classify_destination(
                destination_operand, destination_state, definitions, parameters
            )
            proven = destination_kind == "param"
            selector = _selector_for(_callee_signature(ir))
            if selector:
                (param_selectors if proven else withheld_selectors).add(selector)
            callee_name = getattr(ir, "function_name", None)
            if callee_name is not None and str(callee_name):
                (param_names if proven else withheld_names).add(str(callee_name))
    return param_selectors - withheld_selectors, param_names - withheld_names


def _call_positions(ir: Any, definitions: dict[int, Any]) -> tuple[Any, str, Any, str, str | None]:
    """``(destination_operand, destination_state, payload_operand, payload_state, basis)`` for one call op.

    ``payload_state``: ``operand`` (a blob), ``none`` (typed call with fixed selector), or ``unknown`` (unresolved
    library).
    """
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
    # A typed call's selector is fixed, so no argument is a caller-chosen blob.
    return destination, "operand", None, "none", "call_destination"


def _classify_destination(
    operand: Any, state: str, definitions: dict[int, Any], parameters: list[Any]
) -> tuple[str | None, str]:
    """``(name, kind)`` for the destination operand.

    ``param`` needs an identity match and ``state_var`` needs the root to be a state variable; ``UNDETERMINED`` falls to
    ``not_determined``.
    """
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
    """A witness fragment when ``signature`` forwards a parameter-tainted destination and calldata on a body call,
    else ``None``.

    Whether it's returned is decided by read-set membership. Its contents come from the most adverse candidate op
    (``param`` over ``not_determined`` over ``state_var``), so a ``state_var`` result holds for every op. A first-op
    answer used to lose the real call in a Safe-guard body (``guard.checkTransaction(target, data)`` then
    ``target.call(data)``).
    """
    function = _slither_function(ctx, signature)
    if function is None:
        return None
    parameters = list(getattr(function, "parameters", None) or [])
    address_params = {p for p in parameters if _is_address(p)}
    bytes_params = {p for p in parameters if _is_dynamic_bytes(p)}
    if not address_params or not bytes_params:
        return None
    # An address in the read set may only be an argument (``fixedSink.execute(users[i], payloads[i])``). Scalar
    # parameters still count, because library forwarders put the real target in argument position; arrays don't, since a
    # real batch executor's destination resolves to the array directly.
    argument_address_params = {p for p in address_params if not _is_array(p)}

    # Local import so a missing slither only disables this matcher.
    from slither.slithir.operations import HighLevelCall, LibraryCall, LowLevelCall

    definitions = _definitions(function)
    fragments: list[dict[str, Any]] = []
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
                # Proven-absent only if a tainting bytes parameter really is in an argument slot.
                argument_roots = {
                    id(_root_variable(argument, definitions)) for argument in getattr(ir, "arguments", None) or []
                }
                carried = any(id(p) in argument_roots for p in bytes_params)
                data_param, data_kind = None, ("call_argument" if carried else "not_determined")
            else:
                data_param, data_kind = None, "not_determined"
            fragments.append(
                {
                    "source_site": {"declaration": function.canonical_name, "node": node.node_id},
                    "destination_param": dest_param,
                    "destination_kind": dest_kind,
                    "destination_basis": basis if dest_kind == "param" else None,
                    "calldata_param": data_param,
                    "calldata_kind": data_kind,
                    "calldata_basis": basis if data_kind == "param" else None,
                }
            )
    if not fragments:
        return None
    # The most adverse op speaks for the function, so ``state_var`` survives only if every op resolved to it. Ties rank
    # the calldata slot the same way, then body order.
    dest_rank = {"param": 2, "not_determined": 1, "state_var": 0}
    data_rank = {"param": 2, "not_determined": 1, "call_argument": 0}
    result = max(
        fragments,
        key=lambda f: (dest_rank.get(f["destination_kind"], 1), data_rank.get(f["calldata_kind"], 1)),
    )
    return {**result, "source_sites": [f["source_site"] for f in fragments]}
