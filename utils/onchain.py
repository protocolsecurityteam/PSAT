"""eRPC-backed on-chain helpers and explicit fail-fast unsupported indexed paths."""

from __future__ import annotations

import logging

from utils.rpc import default_rpc_url, require_supported_chain_id, rpc_request

logger = logging.getLogger(__name__)


def get_contract_creation_block(address: str, *, chain_id: int) -> int:
    """Block in which *address* first had deployed code.

    Used to seed event-log cursors at the contract's birth instead of block 0.
    This is intentionally eRPC-only: it checks current code, then binary-searches
    historical ``eth_getCode``. If the configured eRPC route cannot serve the
    needed historical reads, the address is invalid, or no deployed code exists
    on the explicit chain, the failure is logged and raised instead of falling
    back to an explorer or a guessed block.
    """
    if not isinstance(address, str) or not address.startswith("0x") or len(address) != 42:
        logger.error("contract creation lookup requires a 20-byte address, got %r", address)
        raise RuntimeError(f"contract creation lookup requires a 20-byte address, got {address!r}")
    try:
        int(address[2:], 16)
    except ValueError as exc:
        logger.error("contract creation lookup requires a hex address, got %r", address)
        raise RuntimeError(f"contract creation lookup requires a hex address, got {address!r}") from exc

    chain_id = require_supported_chain_id(chain_id=chain_id, context=f"contract creation lookup for {address}")

    def _has_code_at(block_number: int) -> bool:
        block_tag = hex(block_number)
        try:
            code = rpc_request(rpc_url, "eth_getCode", [address, block_tag], chain_id=chain_id)
        except Exception as exc:
            logger.error(
                "contract creation eth_getCode failed for chain_id=%s address=%s block=%s: %s",
                chain_id,
                address,
                block_tag,
                exc,
            )
            raise RuntimeError(
                f"contract creation eth_getCode failed for chain_id={chain_id} address={address} block={block_tag}"
            ) from exc
        if not isinstance(code, str) or not code.startswith("0x"):
            logger.error(
                "contract creation eth_getCode returned invalid payload for chain_id=%s address=%s block=%s: %r",
                chain_id,
                address,
                block_tag,
                code,
            )
            raise RuntimeError(
                f"contract creation eth_getCode returned invalid payload for chain_id={chain_id} address={address}"
            )
        code = code.lower()
        if code in {"0x", "0x0"}:
            return False
        try:
            bytes.fromhex(code[2:])
        except ValueError as exc:
            logger.error(
                "contract creation eth_getCode returned malformed hex for chain_id=%s address=%s block=%s",
                chain_id,
                address,
                block_tag,
            )
            raise RuntimeError(
                f"contract creation eth_getCode returned malformed hex for chain_id={chain_id} address={address}"
            ) from exc
        return True

    rpc_url = default_rpc_url(chain_id=chain_id)
    try:
        head_raw = rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)
    except Exception as exc:
        logger.error("contract creation head lookup failed for chain_id=%s address=%s: %s", chain_id, address, exc)
        raise RuntimeError(f"contract creation head lookup failed for chain_id={chain_id} address={address}") from exc
    if not isinstance(head_raw, str) or not head_raw.startswith("0x"):
        logger.error(
            "contract creation head lookup returned invalid payload for chain_id=%s address=%s: %r",
            chain_id,
            address,
            head_raw,
        )
        raise RuntimeError(f"contract creation head lookup returned invalid payload for chain_id={chain_id}")

    try:
        head = int(head_raw, 16)
    except ValueError as exc:
        logger.error(
            "contract creation head lookup returned malformed hex for chain_id=%s address=%s: %r",
            chain_id,
            address,
            head_raw,
        )
        raise RuntimeError(f"contract creation head lookup returned malformed hex for chain_id={chain_id}") from exc
    if head < 0 or not _has_code_at(head):
        logger.error(
            "contract creation lookup found no deployed code for chain_id=%s address=%s at head=%s",
            chain_id,
            address,
            head,
        )
        raise RuntimeError(f"contract creation lookup found no deployed code for chain_id={chain_id} address={address}")

    low = 0
    high = head
    while low < high:
        mid = (low + high) // 2
        if _has_code_at(mid):
            high = mid
        else:
            low = mid + 1
    return low


def get_eth_balance(address: str, *, chain_id: int) -> int:
    """Return the native ETH balance of *address* in wei via eRPC."""
    resolved_chain_id = require_supported_chain_id(chain_id=chain_id, context=f"ETH balance for {address}")
    rpc_url = default_rpc_url(chain_id=resolved_chain_id)
    raw = rpc_request(rpc_url, "eth_getBalance", [address, "latest"], retries=1, chain_id=resolved_chain_id)
    if not isinstance(raw, str) or not raw.startswith("0x"):
        logger.error(
            "eth_getBalance returned invalid payload for chain_id=%s address=%s: %r",
            resolved_chain_id,
            address,
            raw,
        )
        raise RuntimeError(f"Unexpected eth_getBalance result for {address}: {raw!r}")
    try:
        return int(raw, 16)
    except ValueError as exc:
        logger.error(
            "eth_getBalance returned malformed hex for chain_id=%s address=%s: %r",
            resolved_chain_id,
            address,
            raw,
        )
        raise RuntimeError(f"Unexpected malformed eth_getBalance result for {address}") from exc


def get_eth_price(*, chain_id: int) -> float:
    """Fail fast: native asset USD pricing is not available through eRPC."""
    resolved_chain_id = require_supported_chain_id(chain_id=chain_id, context="native asset price lookup")
    logger.error(
        "Native asset price lookup for chain_id=%s requires a price oracle/indexer; Etherscan ethprice is disabled",
        resolved_chain_id,
    )
    raise RuntimeError(
        f"native asset price lookup for chain_id={resolved_chain_id} is unsupported in eRPC-only mode"
    )


def get_token_balances(address: str, *, chain_id: int) -> list[dict]:
    """Enumerating all ERC-20 balances is not supported in eRPC-only mode."""
    resolved_chain_id = require_supported_chain_id(
        chain_id=chain_id,
        context=f"token balance enumeration for {address}",
    )
    logger.error(
        "Token balance enumeration for %s on chain_id=%s requires an indexed token universe; "
        "Etherscan addresstokenbalance is disabled",
        address,
        resolved_chain_id,
    )
    raise RuntimeError(
        f"token balance enumeration for {address} on chain_id={resolved_chain_id} is unsupported in eRPC-only mode"
    )
