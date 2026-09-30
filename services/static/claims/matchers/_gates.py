"""Contract-level gates for the upgrade/exec matchers: does the contract present the structure a standard mandates
(sibling selectors, marker topics, a delegatecall fallback)?

A claim only mints inside a contract the standard shapes, which keeps a per-function selector check from firing on a
collision. Constants come from published signatures, never identifier names.
"""

from __future__ import annotations

from ..context import ClaimContext, abi_selector, abi_topic0, selectors_of

UPGRADE_TO = abi_selector("upgradeTo(address)")  # 0x3659cfe6
UPGRADE_TO_AND_CALL = abi_selector("upgradeToAndCall(address,bytes)")  # 0x4f1ef286
UPGRADE_SELECTORS = frozenset({UPGRADE_TO, UPGRADE_TO_AND_CALL})
CHANGE_ADMIN = abi_selector("changeAdmin(address)")  # 0x8f283970

# EIP-1967 fixes the event arguments too, so topic0 is what a 1967 proxy provably emits.
UPGRADED_TOPIC0 = abi_topic0("Upgraded(address)")
ADMIN_CHANGED_TOPIC0 = abi_topic0("AdminChanged(address,address)")

PROXIABLE_UUID = abi_selector("proxiableUUID()")

# Safe v1.3+ ABI; the ``Enum.Operation`` param lowers to ``uint8``.
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
    """True when fallback/receive reaches a delegatecall: the proxy-shell gate for proxies whose upgrade entries live
    on the shell.
    """
    for signature in ("fallback()", "receive()"):
        if any(sink.get("kind") == "delegatecall" and sink.get("origin") == "body" for sink in ctx.sinks(signature)):
            return True
    return False


def is_uups_gate(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(PROXIABLE_UUID)


def is_proxy_shell_gate(ctx: ClaimContext) -> bool:
    return has_delegatecall_fallback(ctx)


def is_upgrade_gate(ctx: ClaimContext) -> bool:
    """Any upgrade shape: UUPS impl, EIP-1967 ``Upgraded`` log, or a delegatecall-fallback shell."""
    return is_uups_gate(ctx) or ctx.has_event_topic(UPGRADED_TOPIC0) or is_proxy_shell_gate(ctx)


def is_admin_change_gate(ctx: ClaimContext) -> bool:
    return ctx.has_event_topic(ADMIN_CHANGED_TOPIC0) or is_proxy_shell_gate(ctx)


def is_safe_gate(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(*SAFE_GATE_SELECTORS)


def is_oz_timelock_gate(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(*OZ_TIMELOCK_GATE_SELECTORS)
