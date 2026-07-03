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


def _is_dynamic_bytes(variable: Any) -> bool:
    # ``bytes`` (dynamic) taints as arbitrary calldata; ``bytes32`` etc. do not.
    return str(getattr(variable, "type", "")) == "bytes"


def _is_address(variable: Any) -> bool:
    return str(getattr(variable, "type", "")) == "address"


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

    # Import locally so a missing slither install degrades the matcher (isolated
    # by build_claims) instead of breaking package import.
    from slither.slithir.operations import HighLevelCall, LibraryCall, LowLevelCall

    for node in getattr(function, "nodes", None) or []:
        for ir in getattr(node, "irs", None) or []:
            if not isinstance(ir, (LowLevelCall, HighLevelCall, LibraryCall)):
                continue
            reads = set(getattr(ir, "read", None) or [])
            destination = getattr(ir, "destination", None)
            dest_tainted = destination in address_params or bool(reads & address_params)
            data_tainted = bool(reads & bytes_params)
            if dest_tainted and data_tainted:
                dest_param = next((p for p in address_params if p is destination), None) or next(
                    iter(reads & address_params), None
                )
                data_param = next(iter(reads & bytes_params), None)
                return {
                    "destination_param": getattr(dest_param, "name", "") or "",
                    "calldata_param": getattr(data_param, "name", "") or "",
                }
    return None
