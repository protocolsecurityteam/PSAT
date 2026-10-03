"""Registered claim ids (``services.static.claims``), named once so consumers never spell one.

A leaf module: db models and ``utils`` name claim ids too and can't import ``services``. The registry tests pin
:data:`ALL_CLAIM_IDS` to the registered set.
"""

from __future__ import annotations

AUTHORITY_GRANT = "authority.grant"
AUTHORITY_REPLACE = "authority.replace"
AUTHORIZED_CALLER_ROTATE = "authorized_caller.rotate"
CALLEE_POINTER_ROTATE = "callee_pointer.rotate"
CONTRACT_DEPLOYMENT = "contract_deployment"
DELEGATECALL_EXECUTE = "delegatecall.execute"
ERC20_APPROVE = "erc20.approve"
ERC20_TRANSFER = "erc20.transfer"
ERC20_TRANSFER_FROM = "erc20.transfer_from"
EXEC_ARBITRARY = "exec.arbitrary"
FLOW_IN = "flow.in"
FLOW_OUT = "flow.out"
GOV_DELEGATE = "gov.delegate"
LZ_OAPP_SET_DELEGATE = "lz_oapp.set_delegate"
LZ_OAPP_SET_PEER = "lz_oapp.set_peer"
OWNERSHIP_ACCEPT = "ownership.accept"
OWNERSHIP_RENOUNCE = "ownership.renounce"
OWNERSHIP_TRANSFER = "ownership.transfer"
PAUSE_SET = "pause.set"
PAUSE_UNSET = "pause.unset"
PROXY_ADMIN_CHANGE = "proxy.admin_change"
RATE_LIMIT_CONSUME = "rate_limit.consume"
ROLES_CONFIGURE = "roles.configure"
ROLES_GRANT = "roles.grant"
ROLES_REVOKE = "roles.revoke"
SAFE_MODULE_MGMT = "safe.module_mgmt"
SAFE_SET_GUARD = "safe.set_guard"
SAFE_SIGNER_MGMT = "safe.signer_mgmt"
SUPPLY_BURN = "supply.burn"
SUPPLY_MINT = "supply.mint"
TIMELOCK_CANCEL = "timelock.cancel"
TIMELOCK_EXECUTE = "timelock.execute"
TIMELOCK_SCHEDULE = "timelock.schedule"
TIMELOCK_SET_DELAY = "timelock.set_delay"
TRANSFER_POLICY_CONFIGURE = "transfer_policy.configure"
UPGRADE_IMPLEMENTATION = "upgrade.implementation"
VALUE_ROUTER = "value_router"
WETH_DEPOSIT = "weth.deposit"
WETH_WITHDRAW = "weth.withdraw"

ALL_CLAIM_IDS: frozenset[str] = frozenset(
    {
        AUTHORITY_GRANT,
        AUTHORITY_REPLACE,
        AUTHORIZED_CALLER_ROTATE,
        CALLEE_POINTER_ROTATE,
        CONTRACT_DEPLOYMENT,
        DELEGATECALL_EXECUTE,
        ERC20_APPROVE,
        ERC20_TRANSFER,
        ERC20_TRANSFER_FROM,
        EXEC_ARBITRARY,
        FLOW_IN,
        FLOW_OUT,
        GOV_DELEGATE,
        LZ_OAPP_SET_DELEGATE,
        LZ_OAPP_SET_PEER,
        OWNERSHIP_ACCEPT,
        OWNERSHIP_RENOUNCE,
        OWNERSHIP_TRANSFER,
        PAUSE_SET,
        PAUSE_UNSET,
        PROXY_ADMIN_CHANGE,
        RATE_LIMIT_CONSUME,
        ROLES_CONFIGURE,
        ROLES_GRANT,
        ROLES_REVOKE,
        SAFE_MODULE_MGMT,
        SAFE_SET_GUARD,
        SAFE_SIGNER_MGMT,
        SUPPLY_BURN,
        SUPPLY_MINT,
        TIMELOCK_CANCEL,
        TIMELOCK_EXECUTE,
        TIMELOCK_SCHEDULE,
        TIMELOCK_SET_DELAY,
        TRANSFER_POLICY_CONFIGURE,
        UPGRADE_IMPLEMENTATION,
        VALUE_ROUTER,
        WETH_DEPOSIT,
        WETH_WITHDRAW,
    }
)
