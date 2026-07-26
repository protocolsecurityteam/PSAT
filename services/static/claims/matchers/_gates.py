"""Shared contract-level gate predicates for the upgrade/exec matcher family.

A gate answers "does this contract present the structural corroboration a
standard mandates" (sibling selectors, marker event topics, a delegatecall
fallback). Matchers pass the relevant gate to ``@claim_matcher`` so a claim is
minted only inside a contract the standard actually shapes — the discriminator
that keeps the per-function selector check from firing on a selector collision.

Every constant here is derived from a *published* signature: the selector the
chain dispatches on, or the ``topic0`` it logs. Nothing keys on an identifier
name, so a contract that merely borrows a standard's vocabulary earns no claim.

Underscore-prefixed so matcher auto-discovery skips it; matcher modules import
it directly.
"""

from __future__ import annotations

from ..context import ClaimContext, abi_selector, abi_topic0, selectors_of

# ERC-1822/1967 upgrade entry selectors (fixed by the standard).
UPGRADE_TO = abi_selector("upgradeTo(address)")  # 0x3659cfe6
UPGRADE_TO_AND_CALL = abi_selector("upgradeToAndCall(address,bytes)")  # 0x4f1ef286
UPGRADE_SELECTORS = frozenset({UPGRADE_TO, UPGRADE_TO_AND_CALL})
CHANGE_ADMIN = abi_selector("changeAdmin(address)")  # 0x8f283970

# EIP-1967 marker logs. The standard fixes the event ARGUMENTS as well as the
# name, so topic0 — not the name — is what a 1967 proxy provably emits.
UPGRADED_TOPIC0 = abi_topic0("Upgraded(address)")
ADMIN_CHANGED_TOPIC0 = abi_topic0("AdminChanged(address,address)")

# ERC-1822 UUPS marker view.
PROXIABLE_UUID = abi_selector("proxiableUUID()")

# Gnosis Safe published ABI (Safe v1.3+/L2). ``execTransaction``'s fourth
# parameter is the ``Enum.Operation`` enum, which the canonical lowering renders
# as ``uint8``.
SAFE_EXEC_TRANSACTION = abi_selector(
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
)
SAFE_GATE_SELECTORS = frozenset(selectors_of("getThreshold()", "getOwners()") | {SAFE_EXEC_TRANSACTION})
SAFE_SIGNER_SELECTORS = selectors_of(
    "addOwnerWithThreshold(address,uint256)",
    "removeOwner(address,address,uint256)",
    "swapOwner(address,address,address)",
    "changeThreshold(uint256)",
)
SAFE_MODULE_SELECTORS = selectors_of("enableModule(address)", "disableModule(address,address)")
SAFE_SET_GUARD = abi_selector("setGuard(address)")
SAFE_EXEC_SELECTORS = frozenset(
    {SAFE_EXEC_TRANSACTION}
    | selectors_of(
        "execTransactionFromModule(address,uint256,bytes,uint8)",
        "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)",
    )
)

# OpenZeppelin TimelockController published ABI.
TIMELOCK_SCHEDULE_SELECTORS = selectors_of(
    "schedule(address,uint256,bytes,bytes32,bytes32,uint256)",
    "scheduleBatch(address[],uint256[],bytes[],bytes32,bytes32,uint256)",
)
TIMELOCK_EXECUTE_SELECTORS = selectors_of(
    "execute(address,uint256,bytes,bytes32,bytes32)",
    "executeBatch(address[],uint256[],bytes[],bytes32,bytes32)",
)
TIMELOCK_CANCEL = abi_selector("cancel(bytes32)")
TIMELOCK_UPDATE_DELAY = abi_selector("updateDelay(uint256)")
OZ_TIMELOCK_GATE_SELECTORS = frozenset(
    selectors_of("getMinDelay()", "hashOperation(address,uint256,bytes,bytes32,bytes32)")
    | selectors_of("schedule(address,uint256,bytes,bytes32,bytes32,uint256)")
    | selectors_of("execute(address,uint256,bytes,bytes32,bytes32)")
)


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
    return ctx.has_selectors(PROXIABLE_UUID)


def is_proxy_shell_gate(ctx: ClaimContext) -> bool:
    return has_delegatecall_fallback(ctx)


def is_upgrade_gate(ctx: ClaimContext) -> bool:
    """Any recognized upgrade shape: UUPS impl, the EIP-1967 ``Upgraded`` log, or
    a delegatecall-fallback proxy shell. The per-function selector check narrows
    it to the actual upgrade entry."""
    return is_uups_gate(ctx) or ctx.has_event_topic(UPGRADED_TOPIC0) or is_proxy_shell_gate(ctx)


def is_admin_change_gate(ctx: ClaimContext) -> bool:
    """Proxy admin rotation: the EIP-1967 ``AdminChanged`` log or a proxy shell."""
    return ctx.has_event_topic(ADMIN_CHANGED_TOPIC0) or is_proxy_shell_gate(ctx)


def is_safe_gate(ctx: ClaimContext) -> bool:
    """Gnosis Safe: the getThreshold + getOwners + execTransaction sibling
    triple, matched on the published selectors."""
    return ctx.has_selectors(*SAFE_GATE_SELECTORS)


def is_oz_timelock_gate(ctx: ClaimContext) -> bool:
    """OZ TimelockController: getMinDelay + schedule + execute siblings plus the
    ``hashOperation`` marker, matched on the published selectors."""
    return ctx.has_selectors(*OZ_TIMELOCK_GATE_SELECTORS)
