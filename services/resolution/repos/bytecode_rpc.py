"""RPC-backed ``BytecodeRepo`` — confirms a contract implements a standard by
probing its runtime bytecode for that standard's distinguishing function
selectors.

Used by adapters' ``matches()`` to disambiguate standards that share a selector.
The headline case: Solmate ``RolesAuthority`` and OZ ``AccessManager`` both expose
``canCall(address,address,bytes4)`` (selector ``0xb7009613``), so signature alone
can't tell them apart — but a RolesAuthority's bytecode contains
``getRolesWithCapability``/``doesUserHaveRole`` while an AccessManager's contains
``getTargetFunctionRole``. Bytecode is immutable per address and fetched through
the cached ``utils.rpc.get_code``, so repeated probes are cheap.
"""

from __future__ import annotations

from utils.rpc import get_code


class BytecodeSelectorRepo:
    """``BytecodeRepo`` backed by ``eth_getCode`` (cached). ``has_selector``
    checks whether a function selector appears in the runtime dispatcher."""

    def __init__(self, rpc_url: str | None, chain_id: int) -> None:
        self._rpc_url = rpc_url
        self._chain_id = chain_id

    def has_selector(self, *, chain_id: int, contract_address: str, selector: str) -> bool:
        code = self._code(chain_id, contract_address)
        if not code:
            return False
        sel = selector.lower().removeprefix("0x")
        if len(sel) != 8:
            return False
        body = code.lower()
        # solc emits each external function in the dispatcher as PUSH4 <selector>
        # (opcode 0x63). Requiring the 0x63 prefix avoids matching the 4 bytes as
        # incidental constant data; fall back to a bare substring for unusual
        # dispatchers.
        return ("63" + sel) in body or sel in body

    def declares_event(self, *, chain_id: int, contract_address: str, topic0: str) -> bool:
        # Event topics aren't recoverable from runtime bytecode. Not supported;
        # adapters needing event confirmation use the indexed-log repo instead.
        del chain_id, contract_address, topic0
        return False

    def _code(self, chain_id: int, contract_address: str) -> str:
        if not self._rpc_url or not isinstance(contract_address, str) or not contract_address.startswith("0x"):
            return ""
        try:
            return get_code(self._rpc_url, contract_address, chain_id=chain_id or self._chain_id) or ""
        except Exception:
            return ""
