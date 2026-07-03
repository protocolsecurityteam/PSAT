"""Shared contract-level gate predicates for the upgrade/exec matcher family.

A gate answers "does this contract present the structural corroboration a
standard mandates" (sibling views/selectors, marker events, a delegatecall
fallback). Matchers pass the relevant gate to ``@claim_matcher`` so a claim is
minted only inside a contract the standard actually shapes — the discriminator
that keeps the per-function selector check from firing on a name collision.

Underscore-prefixed so matcher auto-discovery skips it; matcher modules import
it directly.
"""

from __future__ import annotations

from ..context import ClaimContext

# ERC-1822/1967 upgrade entry selectors (fixed by the standard).
UPGRADE_TO = "0x3659cfe6"  # upgradeTo(address)
UPGRADE_TO_AND_CALL = "0x4f1ef286"  # upgradeToAndCall(address,bytes)
UPGRADE_SELECTORS = frozenset({UPGRADE_TO, UPGRADE_TO_AND_CALL})
CHANGE_ADMIN = "0x8f283970"  # changeAdmin(address)


def has_event(ctx: ClaimContext, name: str) -> bool:
    """True when the subject contract declares or inherits an event named
    ``name`` (a standard's marker, e.g. ``Upgraded`` / ``AdminChanged``)."""
    contract = getattr(ctx, "contract", None)
    events = getattr(contract, "events", None) or []
    return any(getattr(event, "name", None) == name for event in events)


def has_delegatecall_fallback(ctx: ClaimContext) -> bool:
    """True when ``fallback``/``receive`` reaches a body-origin delegatecall —
    the proxy-shell (zos / transparent) gate that recovers wBETH-class proxies
    whose upgrade entries live on the shell rather than a UUPS impl."""
    for signature in ("fallback()", "receive()"):
        if any(sink.get("kind") == "delegatecall" and sink.get("origin") == "body" for sink in ctx.sinks(signature)):
            return True
    return False


def is_uups_gate(ctx: ClaimContext) -> bool:
    """ERC-1822 UUPS: the ``proxiableUUID()`` sibling is the standard marker."""
    return ctx.has_functions("proxiableUUID")


def is_proxy_shell_gate(ctx: ClaimContext) -> bool:
    return has_delegatecall_fallback(ctx)


def is_upgrade_gate(ctx: ClaimContext) -> bool:
    """Any recognized upgrade shape: UUPS impl, 1967 ``Upgraded`` marker, or a
    delegatecall-fallback proxy shell. The per-function selector check narrows
    it to the actual upgrade entry."""
    return is_uups_gate(ctx) or has_event(ctx, "Upgraded") or is_proxy_shell_gate(ctx)


def is_admin_change_gate(ctx: ClaimContext) -> bool:
    """Proxy admin rotation: an ``AdminChanged`` marker event or a proxy shell."""
    return has_event(ctx, "AdminChanged") or is_proxy_shell_gate(ctx)


def is_safe_gate(ctx: ClaimContext) -> bool:
    """Gnosis Safe: the getThreshold + getOwners + execTransaction sibling
    triple. h3sim measured 0 false claims on this gate."""
    return ctx.has_functions("getThreshold", "getOwners", "execTransaction")


def is_oz_timelock_gate(ctx: ClaimContext) -> bool:
    """OZ TimelockController: getMinDelay + schedule + execute siblings plus the
    ``hashOperation`` marker."""
    return ctx.has_functions("getMinDelay", "schedule", "execute", "hashOperation")


def function_name(signature: str) -> str:
    return signature.split("(", 1)[0]
