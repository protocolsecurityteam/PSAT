"""Caller-taint default: "public" is an earned verdict, not a fallback.

A revert gate whose proceed condition depends on the caller's identity is an authorization unless it matches a known
permissionless shape. Authority has unbounded shapes; permissionlessness has few, so unrecognised caller gates fail
closed (``external_check_only``). The structural exclusions:

  - exclusion polarity (``falsy`` / ``ne``): denylists, claim-once, ``!=`` guards;
  - caller-keyed quantity thresholds (``balances[msg.sender] >= amount``), except deny-by-default time allowlists
(``is_caller_keyed_time_allowlist``);
  - self-service equality: the caller vs caller-derived values (``tx.origin``, ``ecrecover``) or the caller's own
argument;
  - effectful external bool calls (``require(token.transferFrom(msg.sender, …))``), by callee mutability; a view/pure
caller-gated bool is an ACL.

Gated by ``PSAT_AUTHORITY_EARNED_PUBLIC``; the legacy path keeps the E3/E4 point fixes this subsumes.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

# Self-auth is handled by the equality arm; permits resolve via ``signature_auth``.
from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_TAINT_SOURCES
from services.static.contract_analysis_pipeline.predicate_types import LeafPredicate


def earned_public_enabled() -> bool:
    """The caller-taint default, on by default; ``PSAT_AUTHORITY_EARNED_PUBLIC=0`` reverts to the legacy E3/E4 path."""
    return os.getenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1").lower() in ("1", "true", "yes")


def is_public_registration(leaf: LeafPredicate) -> bool:
    """The writer pass proved an unconditional, externally callable registration path."""
    return (
        leaf.get("kind") == "membership"
        and leaf.get("authority_role") == "business"
        and "unconditional public address registration" in (leaf.get("basis") or [])
        and ((leaf.get("set_descriptor") or {}).get("value_predicate") or {})
        .get("value_type", "")
        .startswith("address")
    )


def leaf_is_caller_tainted(leaf: LeafPredicate) -> bool:
    """Whether the leaf depends on the caller's identity (caller-sourced operand or membership key).

    Reads operand sources, not ``references_msg_sender``, since inlining rewrites the frame's ``msg.sender``.
    """
    return _leaf_has_direct_caller_source(leaf) or leaf_caller_taint_is_collapsed(leaf)


def _leaf_has_direct_caller_source(leaf: LeafPredicate) -> bool:
    """Caller taint stated directly, so ``is_permissionless_caller_shape`` can classify it."""
    for op in leaf.get("operands") or []:
        if (op or {}).get("source") in _CALLER_TAINT_SOURCES:
            return True
    descriptor = leaf.get("set_descriptor") or {}
    for key in descriptor.get("key_sources") or []:
        if (key or {}).get("source") in _CALLER_TAINT_SOURCES:
            return True
    return False


def leaf_caller_taint_is_collapsed(leaf: LeafPredicate) -> bool:
    """Whether this is an un-lowered bare-bool gate whose only caller evidence is its collapsing operand's
    ``derived_from`` (A1 Part B).

    This is the taint an assembly-backed role read (Solady ``hasRole``) hashes away, which let
    ``RoleRegistry.upgradeTo`` publish as public over a timelock gate.

    The shape gate is narrow because ``derived_from`` is transitive: the broad rule tainted 25 corpus leaves, 23 wrongly
    (value bounds, deploy checks, self-auth, value movement). Requires exactly one ``view_call`` / ``computed`` operand,
    operator ``truthy`` / ``falsy``, and kind ``equality``. Absent ``derived_from`` makes no claim.
    """
    if _leaf_has_direct_caller_source(leaf):
        return False
    if leaf.get("kind") != "equality" or leaf.get("operator") not in ("truthy", "falsy"):
        return False
    operands = leaf.get("operands") or []
    if len(operands) != 1:
        return False
    operand = operands[0] or {}
    if operand.get("source") not in ("view_call", "computed"):
        return False
    return any((origin or {}).get("source") in _CALLER_TAINT_SOURCES for origin in operand.get("derived_from") or [])


def is_permissionless_caller_shape(leaf: LeafPredicate) -> bool:
    """Whether a caller-tainted gate matches a known permissionless shape (see module docstring).

    Callers must establish taint first.

    A leaf whose taint is visible only through ``derived_from`` is never permissionless: its comparison was never
    lowered, so claiming a shape would be absence-as-proof (A1 Part B).
    """
    if is_public_registration(leaf):
        return True
    if leaf_caller_taint_is_collapsed(leaf):
        return False
    operator = leaf.get("operator")
    kind = leaf.get("kind")

    # Exclusion polarity: the default caller proceeds.
    if operator in ("falsy", "ne"):
        return True

    if kind == "comparison":
        # Caller-keyed quantity thresholds are self-service, except deny-by-default time allowlists.
        return not is_caller_keyed_time_allowlist(leaf)

    if kind == "equality":
        operands = leaf.get("operands") or []
        others = [op for op in operands if (op or {}).get("source") not in _CALLER_TAINT_SOURCES]
        # All operands caller-derived: a binary self-comparison is permissionless, but a single-operand truthy is a
        # folded caller-keyed flag (an allowlist) unless it's an effectful-call result.
        if not others:
            if operator == "eq" and len(operands) >= 2:
                return True
            return leaf.get("callee_state_mutability") not in (None, "view", "pure")
        # Caller vs its own argument (``account == _msgSender()``): self-service.
        if all((op or {}).get("source") == "parameter" for op in others):
            return True
        # No address-typed counterpart means a folded value comparison (``!hasPod(msg.sender)``, ``status[msg.sender][x]
        # == REGISTERED``): claim-once/own-status, not an authority.
        if not any(_operand_address_plausible(op) for op in others):
            return True
        return False

    if kind == "external_bool":
        # Effectful external calls move the caller's own state (permissionless); view/pure are ACLs; effectful library
        # calls consume the contract's own storage (authority). Absent mutability stays permissionless so old trees
        # don't gain false gates.
        if leaf.get("callee_state_mutability") not in (None, "nonview"):
            return False
        # A void call consuming a caller-supplied bytes32[] hash path is a merkle membership check against a contract
        # root (an allowlist). Permits, result-checked requires and witness-free void calls stay permissionless.
        if leaf.get("gate_kind") in ("external_call_revert", "try_catch_revert"):
            signature = leaf.get("callee_signature") or (leaf.get("set_descriptor") or {}).get("callee_signature") or ""
            if "bytes32[]" in signature:
                return False
        return True

    # Membership, signature_auth and unknown kinds aren't permissionless.
    return False


def _operand_address_plausible(op: Mapping[str, Any]) -> bool:
    """Whether an operand could hold an address, so equality with the caller could be an identity test.

    Reads qualify; constants and computed values need explicit address typing. Mirrors the static
    ``_operand_is_address_typed``.
    """
    source = (op or {}).get("source")
    if source in ("state_variable", "view_call", "external_call", "self_address"):
        return True
    if source == "constant":
        if op.get("value_type") == "address":
            return True
        value = op.get("constant_value")
        return isinstance(value, str) and value.startswith("0x") and len(value) == 42
    return (op or {}).get("value_type") == "address"


# Every tag ``caller_gate_basis`` can stamp. Only these checks may suppress a sibling public path; downstream-call
# probes keep folding as side conditions.
CALLER_GATE_BASIS_TAGS = frozenset(
    {
        "caller_tainted_authority_unresolved",
        "caller_keyed_time_allowlist",
        "caller_keyed_membership_allowlist",
    }
)


def caller_gate_basis(leaf: LeafPredicate) -> str:
    """Basis tag for a fail-closed caller gate; the subsumed point-fix shapes keep their historical tags."""
    if is_caller_keyed_time_allowlist(leaf):
        return "caller_keyed_time_allowlist"
    if is_caller_keyed_membership_allowlist(leaf):
        return "caller_keyed_membership_allowlist"
    return "caller_tainted_authority_unresolved"


def is_caller_keyed_time_allowlist(leaf: LeafPredicate) -> bool:
    """Whether the leaf is a deny-by-default caller-keyed time allowlist: ``if (allowedUntil[msg.sender] <
    block.timestamp) revert``. Unset callers (0) are denied, so it's an authorization.

    The discriminator is a lower-bound proceed relation against ``block.timestamp``. It excludes share locks
    (``shareUnlockTime[from] > now``, default allowed) and balance checks (compared to a parameter).
    """
    if leaf.get("kind") != "comparison":
        return False
    operands = leaf.get("operands") or []
    if len(operands) != 2:
        return False
    caller_idx = next((i for i, o in enumerate(operands) if o.get("source") in _CALLER_TAINT_SOURCES), None)
    time_idx = next(
        (
            i
            for i, o in enumerate(operands)
            if o.get("source") == "block_context" and o.get("block_context_kind") == "timestamp"
        ),
        None,
    )
    if caller_idx is None or time_idx is None:
        return False
    op = leaf.get("operator")
    # Lower bound on the caller value: caller LHS with gt/gte, or caller RHS with lt/lte.
    if caller_idx < time_idx:
        return op in ("gt", "gte")
    return op in ("lt", "lte")


def is_caller_keyed_time_denylist(leaf: LeafPredicate) -> bool:
    """Whether the leaf is a deny-by-exception caller-keyed time denylist (``blacklistedUntil[msg.sender] >
    block.timestamp`` reverts), the inverse of the allowlist. Unset callers are allowed, so it resolves to
    ``cofinite_blacklist``.
    """
    if leaf.get("kind") != "comparison":
        return False
    operands = leaf.get("operands") or []
    if len(operands) != 2:
        return False
    caller_idx = next((i for i, o in enumerate(operands) if o.get("source") in _CALLER_TAINT_SOURCES), None)
    time_idx = next(
        (
            i
            for i, o in enumerate(operands)
            if o.get("source") == "block_context" and o.get("block_context_kind") == "timestamp"
        ),
        None,
    )
    if caller_idx is None or time_idx is None:
        return False
    op = leaf.get("operator")
    # Upper bound on the caller value: caller LHS with lt/lte, or caller RHS with gt/gte.
    if caller_idx < time_idx:
        return op in ("lt", "lte")
    return op in ("gt", "gte")


def is_caller_keyed_membership_allowlist(leaf: LeafPredicate) -> bool:
    """Whether the leaf is a truthy caller-keyed membership (``require(allowed[msg.sender])``): an allowlist that
    must stay gated.

    Not caught: falsy denylists/claim-once (open by design) and non-caller-keyed memberships (business preconditions).
    One-key caller memberships are ``business`` statically (see ``_classify_authority_membership``) and reach here;
    multi-key tables resolve through the membership branch.
    """
    if leaf.get("kind") != "membership":
        return False
    if leaf.get("operator") != "truthy":
        return False
    descriptor = leaf.get("set_descriptor") or {}
    keys = descriptor.get("key_sources") or []
    return any(k.get("source") in _CALLER_TAINT_SOURCES for k in keys)
