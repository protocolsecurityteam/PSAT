"""Authority-role classification rules for predicate leaves."""

from __future__ import annotations

from ..predicate_types import (
    AuthorityRole,
    LeafKind,
    LeafPredicate,
    Operand,
    SetDescriptor,
)

# ---------------------------------------------------------------------------
# Authority classification (v5/v6 round-2 fix; minimal cut)
# ---------------------------------------------------------------------------


_CALLER_SOURCES = ("msg_sender", "tx_origin", "signature_recovery")
# Sources that can plausibly carry an Ethereum address, used ONLY to qualify the
# non-caller side of a ``msg.sender == X`` equality as an authorization gate.
# ``computed``, ``top``, and ``block_context`` stay excluded — those are genuinely
# opaque (``msg.sender == keccak(...)`` / arithmetic), not authorities.
_ADDRESS_TYPED_SOURCES = (
    "state_variable",
    "view_call",
    # An external call result (``msg.sender == pauserRegistry.unpauser()`` /
    # ``== avsOperators[id].avsNodeRunner()``): for the ``==`` to type-check,
    # Solidity forces the call's return to be ``address``, so it is necessarily
    # address-typed AND a caller-authority gate (the authority just lives in
    # another contract). Excluding it lowered these to ``business`` →
    # ``conditional_universal`` → public — a false-open on every registry /
    # cross-contract-authority pattern. The resolver renders an unread external
    # getter as ``external_check_only`` (gated), never public.
    "external_call",
    "parameter",
    "signature_recovery",
    # ``address(this)`` self-call gate. Used by Compound Timelock
    # setDelay / setPendingAdmin and many module patterns. Self-call
    # is auth (``msg.sender == address(this)`` allows only the
    # contract calling itself, e.g. through a queued timelock
    # transaction).
    "self_address",
)


def _classify_authority_equality(leaf: LeafPredicate, kind: LeafKind) -> AuthorityRole:
    """Rule A (caller equality): kind=="equality", op=="eq", one
    operand is msg_sender/tx_origin/signature_recovery, the OTHER is
    address-typed (state/view/parameter/sig/constant). Otherwise
    business.

    The "other operand must be address-typed" check (v6 round-5 #1
    expansion) prevents misclassifying weird shapes like
    ``require(msg.sender == block.timestamp)`` or
    ``require(msg.sender == keccak256(x))`` as caller_authority just
    because msg.sender appears.

    Time gate: at least one operand sources from block_context AND
    no operand sources from msg.sender/tx.origin/signature_recovery
    (the caller takes priority — ``require(block.timestamp >
    cooldown[msg.sender])`` is still primarily a caller-keyed check).
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
        # Single-operand truthy/falsy paths don't reach here, but
        # defend anyway: a leaf with only a caller-source operand
        # is shape-tight (someone-else-implicit) and stays auth.
        if not non_caller:
            return "caller_authority"
        # Every non-caller operand must look address-typed. A leaf
        # like ``require(msg.sender == 0xabc...`` (address literal), ``==
        # ownerVar`` (state_variable), ``== auth.admin()``
        # (view_call), or ``== adminParam`` (parameter) all qualify.
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
    """Rule B (auth-shaped membership): membership op=truthy/falsy,
    msg.sender as a key, multi-key direct-promote (>=2 keys is a
    permission table by structure). 1-key requires the writer-key
    two-pass (week 3 deliverable) — until then default to business.
    """
    keys = descriptor.get("key_sources", [])
    if not keys:
        return "business"
    has_caller_key = any(k["source"] in ("msg_sender", "tx_origin", "signature_recovery") for k in keys)
    if not has_caller_key:
        return "business"
    if len(keys) >= 2:
        # Multi-key with caller as one key: permission table.
        return "caller_authority"
    # 1-key caller-only: needs writer-key analysis (week 3).
    # For now, default to business so we don't over-admit. The
    # writer-key two-pass will promote when applicable.
    return "business"
