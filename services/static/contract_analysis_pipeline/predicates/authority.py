"""Authority-role classification rules for predicate leaves."""

from __future__ import annotations

from ..predicate_types import (
    AuthorityRole,
    LeafKind,
    LeafPredicate,
    Operand,
    SetDescriptor,
)

_CALLER_SOURCES = ("msg_sender", "tx_origin", "signature_recovery")
# Sources that can carry an address, used only to qualify the other side of ``msg.sender == X``. ``computed``, ``top``
# and ``block_context`` are opaque, not authorities.
_ADDRESS_TYPED_SOURCES = (
    "state_variable",
    "view_call",
    # ``msg.sender == registry.unpauser()``: Solidity forces the return to be ``address``, so it is a caller gate whose
    # authority lives in another contract. Excluding it made every registry pattern read public.
    "external_call",
    "parameter",
    "signature_recovery",
    # ``msg.sender == address(this)``: only the contract itself (e.g. via a queued timelock call).
    "self_address",
)


def _classify_authority_equality(leaf: LeafPredicate, kind: LeafKind) -> AuthorityRole:
    """Rule A: an ``eq`` equality with one caller-source operand and an address-typed other side is caller authority
    (so ``msg.sender == block.timestamp`` isn't). A ``block_context`` comparison with no caller operand is a time
    gate.
    """
    operands = leaf.get("operands", [])
    if not operands:
        return "business"
    has_caller = any(o.get("source") in _CALLER_SOURCES for o in operands)
    has_block_context = any(o.get("source") == "block_context" for o in operands)
    if has_block_context and not has_caller:
        return "time"
    if kind == "equality" and leaf.get("operator") == "eq" and has_caller:
        non_caller = [o for o in operands if o.get("source") not in _CALLER_SOURCES]
        # Unreachable today; a caller-only operand leaf stays auth.
        if not non_caller:
            return "caller_authority"
        if all(_operand_is_address_typed(o) for o in non_caller):
            return "caller_authority"
    return "business"


def _operand_is_address_typed(operand: Operand) -> bool:
    source = operand.get("source")
    if source in _ADDRESS_TYPED_SOURCES:
        return True
    if source == "constant":
        if operand.get("value_type") == "address":
            return True
        value = operand.get("constant_value")
        return isinstance(value, str) and value.startswith("0x") and len(value) == 42
    return False


def _classify_authority_membership(leaf: LeafPredicate, descriptor: SetDescriptor) -> AuthorityRole:
    """Rule B: truthy/falsy membership with ``msg.sender`` as a key.

    Two or more keys is a permission table; single-key needs the writer-gate pass, so defaults to business.
    """
    keys = descriptor.get("key_sources", [])
    if not keys:
        return "business"
    has_caller_key = any(k["source"] in ("msg_sender", "tx_origin", "signature_recovery") for k in keys)
    if not has_caller_key:
        return "business"
    if len(keys) >= 2:
        return "caller_authority"
    # Single caller key: business until the writer-gate pass promotes it.
    return "business"
