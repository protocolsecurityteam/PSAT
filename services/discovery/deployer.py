"""Deployer-based contract discovery.

Given a set of known contract addresses (e.g. from the Tavily pipeline), this
module identifies the deployer wallets via Etherscan's ``getcontractcreation``
API, fetches every contract each deployer has ever created, optionally resolves
contract names, and returns entries in the standard inventory entry format so
they can be merged with Tavily-sourced entries in ``_build_contracts()``.

Deployer filtering
------------------
Not every deployer wallet that created a seed contract is a trustworthy
protocol deployer.  A wallet that deployed 1 out of 79 seeds but has 50 total
deployments is likely a shared service or unrelated actor.  We filter deployers
with two thresholds:

- **Minimum seed count** (``min_seed_count``, default 3): the deployer must
  have created at least this many of the known seed contracts.
- **Minimum seed share** (``min_seed_share``, default 0.05 = 5%): the seeds
  created by this deployer must represent at least this fraction of all
  resolved seed→deployer mappings.

Both conditions must be met for a deployer to be considered a protocol
deployer.  This filters out factory contracts, multisig wallets, and
deploy-as-a-service providers while keeping genuine protocol ops wallets.
"""

from __future__ import annotations

import contextvars
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from services.discovery.inventory_domain import _debug_log
from services.discovery.static_dependencies import normalize_address
from utils import etherscan

logger = logging.getLogger(__name__)

# A deployer must have created at least this many seed contracts.
_MIN_SEED_COUNT = 3

# A deployer's seed contracts must be at least this share of all resolved seeds.
_MIN_SEED_SHARE = 0.05


# -- Etherscan helpers -------------------------------------------------------


def _batch_get_creators(
    addresses: list[str],
    batch_size: int = 5,
    debug: bool = False,
) -> dict[str, str]:
    """Look up contract creators in batches.

    Returns ``{contract_address: creator_address}`` (both normalised).
    """
    creators: dict[str, str] = {}
    for i in range(0, len(addresses), batch_size):
        batch = addresses[i : i + batch_size]
        try:
            data = etherscan.get(
                "contract",
                "getcontractcreation",
                contractaddresses=",".join(batch),
            )
            for item in data.get("result", []):
                contract_addr = normalize_address(item["contractAddress"])
                creator_addr = normalize_address(item["contractCreator"])
                creators[contract_addr] = creator_addr
        except RuntimeError:
            # Address(es) may not be contracts or Etherscan returned no data.
            _debug_log(debug, f"getcontractcreation batch failed for {len(batch)} address(es)")
    return creators


def _get_deployed_contracts(deployer: str, debug: bool = False) -> list[str]:
    """Return all contract addresses created by *deployer* via ``txlist``."""
    try:
        data = etherscan.get(
            "account",
            "txlist",
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
        # Contract-creation txs have an empty ``to`` and a ``contractAddress``.
        if tx.get("to") == "" and tx.get("contractAddress"):
            deployed.append(normalize_address(tx["contractAddress"]))
    _debug_log(debug, f"Deployer {deployer} created {len(deployed)} contract(s)")
    return deployed


def _get_one_name(addr: str) -> tuple[str, str | None]:
    """Fetch the contract name for a single address (rate-limited centrally by etherscan.get)."""
    return addr, etherscan.get_contract_name(addr)


def _batch_get_names(
    addresses: list[str],
    debug: bool = False,
) -> dict[str, str]:
    """Best-effort contract name lookup using a thread pool.  Returns ``{address: name}``."""
    if not addresses:
        return {}

    names: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=4) as executor:
        # Per-submission context copy so each rate-limited Etherscan call
        # inherits the caller's trace_id / job_id contextvars.
        futures: dict = {}
        for addr in addresses:
            ctx = contextvars.copy_context()
            futures[executor.submit(ctx.run, _get_one_name, addr)] = addr
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
    """Return deployer addresses that meet the protocol-deployer thresholds.

    A deployer qualifies only if it created at least *min_seed_count* seeds
    AND those seeds represent at least *min_seed_share* of all resolved seeds.
    """
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


# -- Public API --------------------------------------------------------------


def expand_from_deployers(
    seed_addresses: list[str],
    resolve_names: bool = True,
    min_seed_count: int = _MIN_SEED_COUNT,
    min_seed_share: float = _MIN_SEED_SHARE,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Discover additional contracts by tracing deployer wallets.

    1. Batch-query ``getcontractcreation`` to identify deployer wallets.
    2. Filter to deployers that meet the seed-count and seed-share thresholds.
    3. For each qualified deployer, fetch all creation transactions.
    4. Resolve contract names for newly-discovered addresses.
    5. Return entries in the standard inventory entry format
       (``kind="deployer_expansion"``, ``chain="unknown"``).

    Addresses already present in *seed_addresses* are still emitted so that
    ``_build_contracts()`` can corroborate them with Tavily evidence.
    """
    if not seed_addresses:
        return []

    normalized_seeds = sorted({normalize_address(a) for a in seed_addresses})
    _debug_log(debug, f"Deployer expansion: {len(normalized_seeds)} seed address(es)")

    # Step 1 — find deployer wallets
    creators = _batch_get_creators(normalized_seeds, debug=debug)
    if not creators:
        _debug_log(debug, "No deployer wallets identified")
        return []

    # Step 2 — filter to trusted protocol deployers
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

    # Step 3 — collect every contract each qualified deployer has created
    seed_set = set(normalized_seeds)
    all_deployed: dict[str, set[str]] = {}  # address → deployers that created it
    for deployer in qualified_deployers:
        deployed = _get_deployed_contracts(deployer, debug=debug)
        for addr in deployed:
            all_deployed.setdefault(addr, set()).add(deployer)

    _debug_log(
        debug,
        f"Qualified deployers created {len(all_deployed)} total contract(s), {len(all_deployed.keys() - seed_set)} new",
    )

    # Step 4 — name resolution for new addresses
    new_addresses = sorted(all_deployed.keys() - seed_set)
    names: dict[str, str] = {}
    if resolve_names and new_addresses:
        names = _batch_get_names(new_addresses, debug=debug)

    # Step 5 — build inventory entries
    entries: list[dict[str, Any]] = []
    for address, deployers in sorted(all_deployed.items()):
        deployer = sorted(deployers)[0]  # deterministic pick
        entries.append(
            {
                "name": names.get(address),
                "address": address,
                "chain": "unknown",
                "kind": "deployer_expansion",
                "url": f"https://etherscan.io/address/{deployer}",
                "explorer_url": f"https://etherscan.io/address/{address}",
                "chain_from_hint": False,
            }
        )

    _debug_log(debug, f"Deployer expansion produced {len(entries)} entry/entries")
    return entries
