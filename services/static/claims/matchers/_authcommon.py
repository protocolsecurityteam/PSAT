"""Shared Plane-0 fact readers for the auth-family matchers.

Underscore-prefixed so matcher auto-discovery skips it (it registers no
claim); the ``ownership`` / ``authorized_caller`` / ``roles`` / ``authority``
modules import from here. Everything reads the tolerant :class:`ClaimContext`
facts view — canonical selectors, predicate-tree leaves, and the hardened
``state_writes`` hygiene facts — so a matcher never reaches into
``effects.py`` / ``summaries.py`` internals.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from eth_utils.crypto import keccak

from ..context import ClaimContext

# --- canonical 4-byte selectors (interface/enum params normalized) ----------
# Auth-family entry points, keyed by the canonical ``name(types)`` selector so a
# rename can't dodge detection and an interface-typed param (``setAuthority``'s
# raw selector differs from its canonical ``setAuthority(address)`` one) resolves
# correctly.
TRANSFER_OWNERSHIP = "0xf2fde38b"  # transferOwnership(address)
RENOUNCE_OWNERSHIP = "0x715018a6"  # renounceOwnership()
ACCEPT_OWNERSHIP = "0x79ba5097"  # acceptOwnership()                 Ownable2Step
REQUEST_HANDOVER = "0x25692962"  # requestOwnershipHandover()        Solady
COMPLETE_HANDOVER = "0xf04e283e"  # completeOwnershipHandover(address) Solady
BEGIN_DEFAULT_ADMIN = "0x634e93da"  # beginDefaultAdminTransfer(address) DAR
ACCEPT_DEFAULT_ADMIN = "0xcefc1429"  # acceptDefaultAdminTransfer()      DAR

GRANT_ROLE = "0x2f2ff15d"  # grantRole(bytes32,address)          OZ AccessControl
REVOKE_ROLE = "0xd547741f"  # revokeRole(bytes32,address)         OZ AccessControl
SET_USER_ROLE = "0x67aff484"  # setUserRole(address,uint8,bool)   Solmate
SET_ROLE_CAPABILITY = "0x7d40583d"  # setRoleCapability(uint8,address,bytes4,bool)
SET_PUBLIC_CAPABILITY = "0xc6b0263e"  # setPublicCapability(address,bytes4,bool)
RELY = "0x65fae35e"  # rely(address)                              Maker wards
DENY = "0x9c52a7f1"  # deny(address)                              Maker wards
SET_AUTHORITY = "0x7a9e5e4b"  # setAuthority(address)             Solmate Auth/DSAuth


def selector_of(signature: str | None) -> str | None:
    """keccak256[:4] of a canonical ``name(types)`` signature, else ``None``."""
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def canonical_selector(ctx: ClaimContext, function: str) -> str | None:
    """The function's selector computed from its canonical signature (enum/struct
    params normalized), falling back to the full-name signature."""
    return selector_of(ctx.canonical_signature(function) or function)


# --- predicate-tree leaf reading --------------------------------------------


def _iter_leaves(tree: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            yield leaf
        return
    for child in tree.get("children") or []:
        yield from _iter_leaves(child)


def _leaf_is_caller_authority(leaf: dict[str, Any]) -> bool:
    return leaf.get("authority_role") in ("caller_authority", "delegated_authority")


def function_has_caller_authority_leaf(ctx: ClaimContext, function: str) -> bool:
    """True iff ``function``'s own predicate tree is gated by a caller-authority
    (or delegated-authority) leaf — i.e. the function is access-controlled by the
    caller's identity. Distinguishes an owner-gated rotate setter from a one-shot
    ``initialize`` (latched, no caller-authority leaf)."""
    return any(_leaf_is_caller_authority(leaf) for leaf in _iter_leaves(ctx.predicate_tree(function)))


def _caller_authority_equality_operands(leaf: dict[str, Any]) -> list[str]:
    """State-var operand names of a ``msg.sender == <var>`` caller-authority
    equality leaf (empty for membership leaves, or when no caller operand)."""
    if leaf.get("kind") != "equality" or leaf.get("authority_role") != "caller_authority":
        return []
    operands = [o for o in leaf.get("operands") or [] if isinstance(o, dict)]
    if not any(o.get("source") in ("msg_sender", "tx_origin", "signature_recovery") for o in operands):
        return []
    return [
        o["state_variable_name"]
        for o in operands
        if o.get("source") == "state_variable" and isinstance(o.get("state_variable_name"), str)
    ]


def _clean_scalar_write_types(ctx: ClaimContext) -> dict[str, str]:
    """``var -> declared_type`` over every function's hygiene-clean scalar
    (``granularity == var``) state write. The hygiene filter drops the OZ v5 /
    Solady slot-pseudo ghosts (``OwnableStorageLocation``, ``_OWNER_SLOT``) and
    reentrancy guards, so only real, writable state vars remain."""
    out: dict[str, str] = {}
    for signature in ctx.function_signatures():
        for write in ctx.effect_record(signature).get("state_writes") or []:
            if not isinstance(write, dict):
                continue
            if write.get("hygiene_class") != "normal" or write.get("granularity") != "var":
                continue
            var = write.get("var")
            if isinstance(var, str) and var:
                out.setdefault(var, str(write.get("declared_type") or ""))
    return out


def clean_scalar_writes(ctx: ClaimContext, function: str) -> set[str]:
    """Names of the hygiene-clean scalar state vars ``function`` writes."""
    out: set[str] = set()
    for write in ctx.effect_record(function).get("state_writes") or []:
        if not isinstance(write, dict):
            continue
        if write.get("hygiene_class") != "normal" or write.get("granularity") != "var":
            continue
        var = write.get("var")
        if isinstance(var, str) and var:
            out.add(var)
    return out


def writes_state_var(ctx: ClaimContext, function: str, name: str) -> bool:
    return name in clean_scalar_writes(ctx, function)


def _cache(ctx: ClaimContext) -> dict[str, Any]:
    cache = getattr(ctx, "_auth_family_cache", None)
    if cache is None:
        cache = {}
        try:
            ctx._auth_family_cache = cache  # type: ignore[attr-defined]
        except Exception:
            pass
    return cache


def caller_authority_scalar_vars(ctx: ClaimContext) -> dict[str, str]:
    """``var -> establishing function`` for every state var that a
    ``msg.sender == <var>`` caller-authority *equality* leaf names, restricted to
    hygiene-clean scalar **address**-typed vars actually written somewhere in the
    contract.

    This is the ghost-immune "caller-authority scalar" set: membership leaves
    (LayerZero ``composeQueue``) contribute nothing (equality only), and the
    slot-pseudo owner ghosts are dropped because they are never a clean
    ``address`` scalar write. The establishing function is the witness anchor."""
    cache = _cache(ctx)
    if "ca_scalar_vars" in cache:
        return cache["ca_scalar_vars"]

    write_types = _clean_scalar_write_types(ctx)
    established: dict[str, str] = {}
    for signature in ctx.function_signatures():
        for leaf in _iter_leaves(ctx.predicate_tree(signature)):
            for var in _caller_authority_equality_operands(leaf):
                if write_types.get(var) == "address" and var not in established:
                    established[var] = signature
    cache["ca_scalar_vars"] = established
    return established


def canonical_owner_vars(ctx: ClaimContext) -> set[str]:
    """The subset of :func:`caller_authority_scalar_vars` written by a function
    bearing a canonical ownership selector (``transferOwnership`` /
    ``renounceOwnership``) — i.e. the contract-ownership pointer that
    ``ownership.*`` already carries, so ``authorized_caller.rotate`` excludes it."""
    scalar_vars = set(caller_authority_scalar_vars(ctx))
    owners: set[str] = set()
    for signature in ctx.function_signatures():
        if canonical_selector(ctx, signature) in (TRANSFER_OWNERSHIP, RENOUNCE_OWNERSHIP):
            owners |= clean_scalar_writes(ctx, signature) & scalar_vars
    return owners


# --- contract-level standard gates ------------------------------------------


def writes_owner_scalar(ctx: ClaimContext, function: str) -> bool:
    """Owner-var write identity: ``function`` writes a hygiene-clean caller-
    authority scalar. Corroborates the ownership selector on a Solmate-style Auth
    whose ``owner`` is a public var with no ``owner()`` getter in the ABI set."""
    return bool(clean_scalar_writes(ctx, function) & set(caller_authority_scalar_vars(ctx)))


def is_ownable(ctx: ClaimContext) -> bool:
    return ctx.has_functions("owner")


def solady_handover_gate(ctx: ClaimContext) -> bool:
    return ctx.has_functions("requestOwnershipHandover", "completeOwnershipHandover", "owner")


def default_admin_rules_gate(ctx: ClaimContext) -> bool:
    return ctx.has_functions("defaultAdmin", "beginDefaultAdminTransfer", "acceptDefaultAdminTransfer")


def oz_access_control_gate(ctx: ClaimContext) -> bool:
    return ctx.has_functions("hasRole", "getRoleAdmin")


def solmate_roles_gate(ctx: ClaimContext) -> bool:
    return ctx.has_functions("setUserRole", "setRoleCapability", "setPublicCapability", "canCall")


def maker_wards_gate(ctx: ClaimContext) -> bool:
    return ctx.has_functions("rely", "deny") and "wards" in _clean_scalar_write_types_or_mappings(ctx)


def _clean_scalar_write_types_or_mappings(ctx: ClaimContext) -> set[str]:
    """Every state-var name written (any granularity/hygiene) — the wards ACL is a
    ``mapping`` write, so the scalar-only view would miss it."""
    out: set[str] = set()
    for signature in ctx.function_signatures():
        for write in ctx.effect_record(signature).get("state_writes") or []:
            if isinstance(write, dict) and isinstance(write.get("var"), str):
                out.add(write["var"])
    return out
