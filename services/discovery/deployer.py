"""Deployer-based contract discovery.

Automatic deployer expansion requires an address transaction index: identify
seed contract creators, then enumerate every contract each deployer created.
PSAT runs on-chain calls through eRPC only, and plain JSON-RPC does not expose
that index. This module therefore fails explicitly instead of querying explorer
``getcontractcreation`` / ``txlist`` endpoints or silently skipping expansion.
"""

from __future__ import annotations

import logging
from typing import Any

from services.discovery.inventory_domain import _debug_log
from utils.rpc import require_supported_chain_id

logger = logging.getLogger(__name__)


def expand_from_deployers(
    seed_addresses: list[str],
    *,
    chain_id: int,
    resolve_names: bool = True,
    min_seed_count: int = 3,
    min_seed_share: float = 0.05,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Fail fast for automatic deployer expansion in eRPC-only mode."""
    del resolve_names, min_seed_count, min_seed_share
    resolved_chain_id = require_supported_chain_id(chain_id=chain_id, context="deployer expansion")
    if not seed_addresses:
        return []

    message = (
        f"deployer expansion on chain_id={resolved_chain_id} requires an eRPC-backed deployer transaction index; "
        "explorer getcontractcreation/txlist is disabled"
    )
    logger.error("%s", message)
    _debug_log(debug, message)
    raise RuntimeError(message)
