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

from ..context import ClaimContext, abi_selector

# --- canonical 4-byte selectors (interface/enum params normalized) ----------
# Auth-family entry points, keyed by the canonical ``name(types)`` selector so a
# rename can't dodge detection and an interface-typed param (``setAuthority``'s
# raw selector differs from its canonical ``setAuthority(address)`` one) resolves
# correctly.
TRANSFER_OWNERSHIP = abi_selector("transferOwnership(address)")  # 0xf2fde38b
RENOUNCE_OWNERSHIP = abi_selector("renounceOwnership()")  # 0x715018a6
ACCEPT_OWNERSHIP = abi_selector("acceptOwnership()")  # Ownable2Step
REQUEST_HANDOVER = abi_selector("requestOwnershipHandover()")  # Solady
COMPLETE_HANDOVER = abi_selector("completeOwnershipHandover(address)")  # Solady
BEGIN_DEFAULT_ADMIN = abi_selector("beginDefaultAdminTransfer(address)")  # DAR
ACCEPT_DEFAULT_ADMIN = abi_selector("acceptDefaultAdminTransfer()")  # DAR
DEFAULT_ADMIN = abi_selector("defaultAdmin()")  # DAR
OWNER = abi_selector("owner()")  # OZ Ownable / Solady / DSAuth

GRANT_ROLE = abi_selector("grantRole(bytes32,address)")  # OZ AccessControl
REVOKE_ROLE = abi_selector("revokeRole(bytes32,address)")  # OZ AccessControl
HAS_ROLE = abi_selector("hasRole(bytes32,address)")  # OZ AccessControl
GET_ROLE_ADMIN = abi_selector("getRoleAdmin(bytes32)")  # OZ AccessControl
SET_ROLE = abi_selector("setRole(address,uint256,bool)")  # Solady EnumerableRoles
HAS_ROLE_ENUMERABLE = abi_selector("hasRole(address,uint256)")  # Solady EnumerableRoles
ROLE_HOLDERS = abi_selector("roleHolders(uint256)")  # Solady EnumerableRoles
SET_USER_ROLE = abi_selector("setUserRole(address,uint8,bool)")  # Solmate
SET_ROLE_CAPABILITY = abi_selector("setRoleCapability(uint8,address,bytes4,bool)")
SET_PUBLIC_CAPABILITY = abi_selector("setPublicCapability(address,bytes4,bool)")
CAN_CALL = abi_selector("canCall(address,address,bytes4)")  # Solmate Authority
RELY = abi_selector("rely(address)")  # Maker wards
DENY = abi_selector("deny(address)")  # Maker wards
SET_AUTHORITY = abi_selector("setAuthority(address)")  # Solmate Auth/DSAuth


def canonical_selector(ctx: ClaimContext, function: str) -> str | None:
    """The function's selector computed from its canonical signature (enum/struct
    params normalized)."""
    return ctx.canonical_selector(function)


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
    """The contract publishes ``owner()`` — the getter every recognized ownership
    standard mandates. A ``public`` owner variable publishes it too."""
    return ctx.has_selectors(OWNER)


def solady_handover_gate(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(REQUEST_HANDOVER, COMPLETE_HANDOVER, OWNER)


def default_admin_rules_gate(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(DEFAULT_ADMIN, BEGIN_DEFAULT_ADMIN, ACCEPT_DEFAULT_ADMIN)


def oz_access_control_gate(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(HAS_ROLE, GET_ROLE_ADMIN)


def solady_enumerable_roles_gate(ctx: ClaimContext) -> bool:
    """Solady ``EnumerableRoles``: the role-keyed setter, view and enumeration
    that library publishes.

    A registry can wear OZ's ``grantRole``/``revokeRole`` names over this scheme
    while publishing no ``getRoleAdmin`` — a role here is a flat ``uint256`` in a
    set, so there IS no per-role admin to expose and ``oz_access_control_gate``
    is right to refuse. This gate proves what OZ's pair proves: that the mutators
    touch a role-membership scheme and not a caller-keyed data map.

    Keyed on the library's surface rather than on ``grantRole``/``revokeRole``,
    which are the selectors being claimed — a gate that admits the thing it is
    meant to qualify proves nothing. ``roleHolders`` is the enumerable half and
    is what separates the standard from any contract that merely owns a
    ``setRole``; note ``hasRole`` alone cannot serve, since the OZ and Solady
    signatures differ and a registry may publish both."""
    return ctx.has_selectors(SET_ROLE, HAS_ROLE_ENUMERABLE, ROLE_HOLDERS)


def solmate_roles_gate(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(SET_USER_ROLE, SET_ROLE_CAPABILITY, SET_PUBLIC_CAPABILITY, CAN_CALL)


def maker_wards_gate(ctx: ClaimContext) -> bool:
    """Maker ``wards``. The ``rely``/``deny`` halves are canonical selectors, but
    the ACL itself has no published standard: nothing about the *shape* of a
    caller-keyed ``uint256`` map distinguishes an authorization list from a
    balance ledger, so the discriminator can only be the variable's name.
    Consumers must therefore treat a wards-derived claim as an idiom, never as a
    standard proof (see the tier in ``roles.py``)."""
    return ctx.has_selectors(RELY, DENY) and "wards" in _written_var_names(ctx)


def _written_var_names(ctx: ClaimContext) -> set[str]:
    """Every state-var name written (any granularity/hygiene) — the wards ACL is a
    ``mapping`` write, so the scalar-only view would miss it."""
    out: set[str] = set()
    for signature in ctx.function_signatures():
        for write in ctx.effect_record(signature).get("state_writes") or []:
            if isinstance(write, dict) and isinstance(write.get("var"), str):
                out.add(write["var"])
    return out


def delegated_authority_vars(ctx: ClaimContext) -> set[str]:
    """State variables the contract's guards hold their *external authority* in.

    Read straight off the predicate trees: a ``delegated_authority`` leaf records
    the address source of the contract it consults (``authority.canCall(...)`` →
    ``authority``). That makes "this function replaces the authority pointer" an
    IR fact about the variable the gate actually reads, with no reliance on what
    the variable is called."""
    cache = _cache(ctx)
    if "delegated_authority_vars" in cache:
        return cache["delegated_authority_vars"]

    found: set[str] = set()
    for signature in ctx.function_signatures():
        for leaf in _iter_leaves(ctx.predicate_tree(signature)):
            if leaf.get("authority_role") != "delegated_authority":
                continue
            descriptor = leaf.get("set_descriptor")
            if not isinstance(descriptor, dict):
                continue
            contract = descriptor.get("authority_contract")
            source = contract.get("address_source") if isinstance(contract, dict) else None
            name = source.get("state_variable_name") if isinstance(source, dict) else None
            if isinstance(name, str) and name:
                found.add(name)
    cache["delegated_authority_vars"] = found
    return found
