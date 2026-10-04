"""Claim ids downstream consumers name individually, beyond a grant class. CI asserts they stay within the registry and
that every id a consumer names is listed here.
"""

from __future__ import annotations

from utils import claim_ids as C

CONSUMER_REFERENCED_CLAIM_IDS: frozenset[str] = frozenset(
    {
        C.AUTHORITY_GRANT,
        C.AUTHORITY_REPLACE,
        C.AUTHORIZED_CALLER_ROTATE,
        C.CALLEE_POINTER_ROTATE,
        C.CONTRACT_DEPLOYMENT,
        C.DELEGATECALL_EXECUTE,
        C.ERC20_APPROVE,
        C.ERC20_TRANSFER,
        C.ERC20_TRANSFER_FROM,
        C.EXEC_ARBITRARY,
        C.FLOW_IN,
        C.FLOW_OUT,
        C.GOV_DELEGATE,
        C.LZ_OAPP_SET_DELEGATE,
        C.LZ_OAPP_SET_PEER,
        C.OWNERSHIP_ACCEPT,
        C.OWNERSHIP_RENOUNCE,
        C.OWNERSHIP_TRANSFER,
        C.PAUSE_SET,
        C.PAUSE_UNSET,
        C.PROXY_ADMIN_CHANGE,
        C.RATE_LIMIT_CONSUME,
        C.ROLES_CONFIGURE,
        C.ROLES_GRANT,
        C.ROLES_REVOKE,
        C.SAFE_MODULE_MGMT,
        C.SAFE_SET_GUARD,
        C.SAFE_SIGNER_MGMT,
        C.SUPPLY_BURN,
        C.SUPPLY_MINT,
        C.TIMELOCK_CANCEL,
        C.TIMELOCK_EXECUTE,
        C.TIMELOCK_SCHEDULE,
        C.TIMELOCK_SET_DELAY,
        C.TRANSFER_POLICY_CONFIGURE,
        C.UPGRADE_IMPLEMENTATION,
        C.VALUE_ROUTER,
    }
)
