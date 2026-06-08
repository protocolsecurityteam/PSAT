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

import logging

from utils.rpc import get_code, require_configured_erpc_url, require_supported_chain_id

logger = logging.getLogger(__name__)


class BytecodeSelectorRepo:
    """``BytecodeRepo`` backed by ``eth_getCode`` (cached). ``has_selector``
    checks whether a function selector appears in the runtime dispatcher."""

    def __init__(self, rpc_url: str, chain_id: int) -> None:
        self._chain_id = require_supported_chain_id(chain_id=chain_id, context="BytecodeSelectorRepo")
        self._rpc_url = require_configured_erpc_url(
            rpc_url,
            context="BytecodeSelectorRepo",
            chain_id=self._chain_id,
        )

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
        if (
            not isinstance(contract_address, str)
            or not contract_address.startswith("0x")
            or len(contract_address) != 42
        ):
            logger.error("Bytecode selector lookup requires a 20-byte address, got %r", contract_address)
            raise RuntimeError(f"bytecode selector lookup requires a 20-byte address, got {contract_address!r}")
        try:
            int(contract_address[2:], 16)
        except ValueError as exc:
            logger.error("Bytecode selector lookup requires a hex address, got %r", contract_address)
            raise RuntimeError(f"bytecode selector lookup requires a hex address, got {contract_address!r}") from exc
        effective_chain_id = require_supported_chain_id(chain_id=chain_id, context="bytecode selector lookup")
        if effective_chain_id != self._chain_id:
            logger.error(
                "Bytecode selector lookup chain mismatch repo_chain_id=%s requested_chain_id=%s address=%s",
                self._chain_id,
                effective_chain_id,
                contract_address,
            )
            raise RuntimeError(
                "bytecode selector lookup chain mismatch: "
                f"repo_chain_id={self._chain_id} requested_chain_id={effective_chain_id}"
            )
        try:
            return get_code(self._rpc_url, contract_address, chain_id=effective_chain_id) or ""
        except Exception as exc:
            logger.error(
                "Bytecode selector lookup failed for chain_id=%s address=%s: %s",
                effective_chain_id,
                contract_address,
                exc,
            )
            raise RuntimeError(
                f"bytecode selector lookup failed for chain_id={effective_chain_id} address={contract_address}"
            ) from exc
