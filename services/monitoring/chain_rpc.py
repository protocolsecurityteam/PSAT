"""Per-chain RPC / chain-id resolution for the monitoring daemons.

The scan / poll / enrollment / TVL loops run as one process but each works on
contracts that carry their own chain-name string (``MonitoredContract.chain``,
``Contract.chain``). They are handed a single mainnet-seed ``rpc_url``; these
helpers turn a contract's chain name into that chain's own eRPC route and
numeric id (invariants 7, 10, 11 of ``MULTICHAIN_INVARIANTS.md``).

Mainnet is byte-for-byte unchanged: chain 1 returns the caller's incoming URL
verbatim, so the explicit (often local / stubbed) URL tests inject still flows
through untouched. A second chain resolves its own route from the registry,
with a local (Anvil/test) fallback URL still allowed to win exactly as
:func:`services.clients.rpc.default_rpc_url` lets it everywhere else.
"""

from __future__ import annotations

from services.clients.rpc import default_rpc_url
from utils.chains import UnknownChainError, chain_by_name


def chain_id_for(chain: str | None, *, default: int = 1) -> int:
    """Resolve a chain-name string to its numeric chain id via the registry.

    Unknown / empty chains fall back to *default* (mainnet) so behavior on
    mainnet and on legacy rows is unchanged; the M1.2 fail-loud flip replaces
    this tolerance with an explicit raise.
    """
    if not chain:
        return default
    try:
        return chain_by_name(chain).chain_id
    except UnknownChainError:
        return default


def rpc_for_chain(chain: str | None, fallback_rpc_url: str) -> str:
    """RPC URL to use for a monitored *chain*.

    Mainnet (and any chain the registry can't resolve) keeps
    *fallback_rpc_url* verbatim, so mainnet behavior — including the explicit
    URL the loops are seeded with and the URLs tests inject — is unchanged. A
    second chain resolves its own eRPC route from the registry, with a local
    fallback URL still allowed to win.
    """
    chain_id = chain_id_for(chain)
    if chain_id == 1:
        return fallback_rpc_url
    return default_rpc_url(chain_id=chain_id, explicit_rpc_url=fallback_rpc_url) or fallback_rpc_url
