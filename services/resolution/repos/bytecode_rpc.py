"""RPC-backed ``BytecodeRepo``: confirms a standard by looking for its selectors in runtime bytecode.

Disambiguates standards sharing a selector, e.g. Solmate ``RolesAuthority`` vs OZ ``AccessManager`` (both have
``canCall``, 0xb7009613). Uses the cached ``services.clients.rpc.get_code``.
"""

from __future__ import annotations

from services.clients.rpc import get_code


class BytecodeSelectorRepo:
    """``BytecodeRepo`` backed by cached ``eth_getCode``."""

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
        # solc dispatches via PUSH4 <selector> (0x63), which avoids matching incidental data; bare substring as a
        # fallback.
        return ("63" + sel) in body or sel in body

    def declares_event(self, *, chain_id: int, contract_address: str, topic0: str) -> bool:
        # Event topics aren't recoverable from bytecode; use the indexed-log repo.
        del chain_id, contract_address, topic0
        return False

    def _code(self, chain_id: int, contract_address: str) -> str:
        if not self._rpc_url or not isinstance(contract_address, str) or not contract_address.startswith("0x"):
            return ""
        try:
            return get_code(self._rpc_url, contract_address, chain_id=chain_id or self._chain_id) or ""
        except Exception:
            return ""
