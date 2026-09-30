"""Deployer-based contract discovery.

From known seed addresses, find their deployers via Etherscan ``getcontractcreation``, fetch every contract each
deployer created, optionally resolve names, and return standard inventory entries for ``_build_contracts()``.

A deployer qualifies only if it created at least ``min_seed_count`` seeds (default 3) and those are at least
``min_seed_share`` (default 5%) of resolved seed→deployer mappings. This filters out factories, multisigs and deploy
services (e.g. a wallet with 1 of 79 seeds among 50 deployments).
"""

from __future__ import annotations

import contextvars
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from services.clients import etherscan
from services.discovery.inventory_domain import _debug_log
from services.discovery.static_dependencies import normalize_address
from utils.chains import chain_by_id

logger = logging.getLogger(__name__)


def _explorer_base(chain_id: int) -> str:
    """Explorer origin for display links, falling back to Etherscan; cosmetic only."""
    try:
        return chain_by_id(chain_id).explorer_base_url.rstrip("/")
    except Exception:  # noqa: BLE001 - display-only, never fail loud
        return "https://etherscan.io"


_MIN_SEED_COUNT = 3

_MIN_SEED_SHARE = 0.05


def _batch_get_creators(
    addresses: list[str],
    batch_size: int = 5,
    debug: bool = False,
    chain_id: int = 1,
) -> dict[str, str]:
    """Contract creators in batches, as ``{contract_address: creator_address}``."""
    creators: dict[str, str] = {}
    for i in range(0, len(addresses), batch_size):
        batch = addresses[i : i + batch_size]
        try:
            data = etherscan.get(
                "contract",
                "getcontractcreation",
                chain_id=chain_id,
                contractaddresses=",".join(batch),
            )
            for item in data.get("result", []):
                contract_addr = normalize_address(item["contractAddress"])
                creator_addr = normalize_address(item["contractCreator"])
                creators[contract_addr] = creator_addr
        except RuntimeError:
            _debug_log(debug, f"getcontractcreation batch failed for {len(batch)} address(es)")
    return creators


def _get_deployed_contracts(deployer: str, debug: bool = False, chain_id: int = 1) -> list[str]:
    try:
        data = etherscan.get(
            "account",
            "txlist",
            chain_id=chain_id,
            address=deployer,
            startblock="0",
            endblock="99999999",
            sort="asc",
        )
    except RuntimeError:
        _debug_log(debug, f"txlist failed for deployer {deployer}")
        return []

    deployed: list[str] = []
    for tx in data.get("result", []):
        if tx.get("to") == "" and tx.get("contractAddress"):
            deployed.append(normalize_address(tx["contractAddress"]))
    _debug_log(debug, f"Deployer {deployer} created {len(deployed)} contract(s)")
    return deployed


def _get_one_name(addr: str, chain_id: int) -> tuple[str, str | None]:
    return addr, etherscan.get_contract_name(addr, chain_id=chain_id)


def _batch_get_names(
    addresses: list[str],
    debug: bool = False,
    *,
    chain_id: int,
) -> dict[str, str]:
    if not addresses:
        return {}

    names: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=4) as executor:
        # Copy context per submission so trace ids survive.
        futures: dict = {}
        for addr in addresses:
            ctx = contextvars.copy_context()
            futures[executor.submit(ctx.run, _get_one_name, addr, chain_id)] = addr
        for future in as_completed(futures):
            try:
                addr, name = future.result()
                if name:
                    names[addr] = name
            except Exception as exc:
                logger.debug(
                    "name resolution failed for %s",
                    futures[future],
                    extra={"address": futures[future], "exc_type": type(exc).__name__},
                )

    _debug_log(debug, f"Resolved names for {len(names)}/{len(addresses)} address(es)")
    return names


def _filter_deployers(
    creators: dict[str, str],
    min_seed_count: int = _MIN_SEED_COUNT,
    min_seed_share: float = _MIN_SEED_SHARE,
    debug: bool = False,
) -> list[str]:
    """Deployers meeting both *min_seed_count* and *min_seed_share*."""
    deployer_seed_counts = Counter(creators.values())
    total_resolved = len(creators)
    if total_resolved == 0:
        return []

    qualified: list[str] = []
    for deployer, count in deployer_seed_counts.most_common():
        share = count / total_resolved
        if count >= min_seed_count and share >= min_seed_share:
            _debug_log(
                debug,
                f"Deployer {deployer} ACCEPTED: seeds={count}/{total_resolved} ({share:.0%})",
            )
            qualified.append(deployer)
        else:
            _debug_log(
                debug,
                f"Deployer {deployer} REJECTED: seeds={count}/{total_resolved} ({share:.0%})",
            )

    return qualified


def expand_from_deployers(
    seed_addresses: list[str],
    resolve_names: bool = True,
    min_seed_count: int = _MIN_SEED_COUNT,
    min_seed_share: float = _MIN_SEED_SHARE,
    debug: bool = False,
    chain_id: int = 1,
) -> list[dict[str, Any]]:
    """Discover more contracts by tracing deployer wallets:

    1. find deployers via batched ``getcontractcreation``;
    2. filter by seed count and share;
    3. fetch every creation per qualified deployer;
    4. resolve names for new addresses;
    5. return inventory entries (``kind="deployer_expansion"``, ``chain="unknown"``).

    Seeds are emitted too so ``_build_contracts()`` can corroborate them.
    """
    if not seed_addresses:
        return []

    normalized_seeds = sorted({normalize_address(a) for a in seed_addresses})
    _debug_log(debug, f"Deployer expansion: {len(normalized_seeds)} seed address(es)")

    creators = _batch_get_creators(normalized_seeds, debug=debug, chain_id=chain_id)
    if not creators:
        _debug_log(debug, "No deployer wallets identified")
        return []

    qualified_deployers = _filter_deployers(
        creators,
        min_seed_count=min_seed_count,
        min_seed_share=min_seed_share,
        debug=debug,
    )
    if not qualified_deployers:
        _debug_log(debug, "No deployers met the qualification thresholds")
        return []

    _debug_log(
        debug,
        f"Qualified {len(qualified_deployers)} of {len(set(creators.values()))} unique deployer(s)",
    )

    seed_set = set(normalized_seeds)
    all_deployed: dict[str, set[str]] = {}  # address → deployers that created it
    for deployer in qualified_deployers:
        deployed = _get_deployed_contracts(deployer, debug=debug, chain_id=chain_id)
        for addr in deployed:
            all_deployed.setdefault(addr, set()).add(deployer)

    _debug_log(
        debug,
        f"Qualified deployers created {len(all_deployed)} total contract(s), {len(all_deployed.keys() - seed_set)} new",
    )

    new_addresses = sorted(all_deployed.keys() - seed_set)
    names: dict[str, str] = {}
    if resolve_names and new_addresses:
        names = _batch_get_names(new_addresses, debug=debug, chain_id=chain_id)

    # Explorer links use the chain the expansion ran on.
    explorer_base = _explorer_base(chain_id)
    entries: list[dict[str, Any]] = []
    for address, deployers in sorted(all_deployed.items()):
        deployer = sorted(deployers)[0]  # deterministic pick
        entries.append(
            {
                "name": names.get(address),
                "address": address,
                "chain": "unknown",
                "kind": "deployer_expansion",
                "url": f"{explorer_base}/address/{deployer}",
                "explorer_url": f"{explorer_base}/address/{address}",
                "chain_from_hint": False,
            }
        )

    _debug_log(debug, f"Deployer expansion produced {len(entries)} entry/entries")
    return entries
