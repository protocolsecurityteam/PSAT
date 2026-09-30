"""Per-chain RPC URL and chain-id resolution for the monitoring daemons.

Mainnet returns the caller's URL verbatim so injected (local/stub) URLs still flow through; other chains resolve their
own route from the registry.
"""

from __future__ import annotations

from services.clients.rpc import default_rpc_url
from utils.chains import UnknownChainError, chain_by_name


def chain_id_for(chain: str | None, *, default: int = 1) -> int:
    """Chain name to numeric chain id; unknown or empty chains fall back to *default*."""
    if not chain:
        return default
    try:
        return chain_by_name(chain).chain_id
    except UnknownChainError:
        return default


def rpc_for_chain(chain: str | None, fallback_rpc_url: str) -> str:
    """RPC URL for *chain*. Mainnet and unresolvable chains keep *fallback_rpc_url*; a local fallback URL still wins on
    other chains.
    """
    chain_id = chain_id_for(chain)
    if chain_id == 1:
        return fallback_rpc_url
    return default_rpc_url(chain_id=chain_id, explicit_rpc_url=fallback_rpc_url) or fallback_rpc_url
