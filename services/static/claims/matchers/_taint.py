"""Parameter-taint evidence for the ``exec.arbitrary`` manage-idiom.

The claim is minted only when a body-origin external call forwards a
caller-supplied destination *and* a caller-supplied calldata blob — the
BoringVault.manage / direct low-level ``target.call(data)`` shape. Proven by
reading Slither IR directly (``ClaimContext.contract``): a call op in the
function body whose read set contains an ``address`` parameter and a dynamic
``bytes`` parameter. That two-parameter requirement is what separates ``manage``
from a plain ``transfer(address,uint256)`` value send (address-tainted
destination, no arbitrary calldata).

Underscore-prefixed so matcher auto-discovery skips it.
"""

from __future__ import annotations

from typing import Any

from ..context import ClaimContext


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


def arbitrary_exec_taint(ctx: ClaimContext, signature: str) -> dict[str, str] | None:
    """Return a witness fragment when ``signature`` forwards a parameter-tainted
    destination and calldata on a body call op, else ``None``."""
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

    for node in getattr(function, "nodes", None) or []:
        for ir in getattr(node, "irs", None) or []:
            if not isinstance(ir, (LowLevelCall, HighLevelCall, LibraryCall)):
                continue
            reads = {_origin(v) for v in getattr(ir, "read", None) or []}
            destination = _origin(getattr(ir, "destination", None))
            dest_tainted = destination in address_params or bool(reads & argument_address_params)
            data_tainted = bool(reads & bytes_params)
            if dest_tainted and data_tainted:
                dest_param = next((p for p in address_params if p is destination), None) or next(
                    iter(reads & argument_address_params), None
                )
                data_param = next(iter(reads & bytes_params), None)
                return {
                    "destination_param": getattr(dest_param, "name", "") or "",
                    "calldata_param": getattr(data_param, "name", "") or "",
                }
    return None
