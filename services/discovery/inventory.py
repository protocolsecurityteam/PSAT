"""Orchestrator for protocol contract inventory discovery.

Given a company/protocol name or domain, this module:
  1. Identifies the official domain via explicit search + LLM (inventory_domain.py)
  2. Selects pages likely to contain contract inventories     (inventory_domain.py)
  3. Extracts contract entries from those pages               (inventory_extract.py)
  4. Scores, deduplicates, and ranks the results
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from typing import Any

from utils.rpc import require_supported_chain_id

from .deployer import expand_from_deployers
from .inventory_domain import (
    CHAIN_IDS,
    CHAIN_SORT_ORDER,
    SearchFn,
    _debug_log,
    _discover_contract_inventory_pages,
    _domain_candidates_from_results,
    _llm_select_domain,
    _maybe_domain,
)
from .inventory_extract import extract_inventory_entries_from_pages
from .ranking import score_inventory_evidence

logger = logging.getLogger(__name__)

_CHAIN_LABEL_BY_ID = {chain_id: label for label, chain_id in CHAIN_IDS.items()}


def _collect_source_urls(evidence: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Extract deduplicated page URLs and explorer URLs from evidence."""
    page_urls: list[str] = []
    explorer_urls: list[str] = []
    seen_pages: set[str] = set()
    seen_explorers: set[str] = set()

    for item in evidence:
        page_url = str(item.get("url", "")).strip()
        if page_url and page_url not in seen_pages:
            seen_pages.add(page_url)
            page_urls.append(page_url)
        explorer_raw = item.get("explorer_url")
        explorer_url = str(explorer_raw).strip() if explorer_raw else ""
        if explorer_url and explorer_url not in seen_explorers:
            seen_explorers.add(explorer_url)
            explorer_urls.append(explorer_url)

    return page_urls[:3], explorer_urls[:2]


def _register_sources(
    sources_map: dict[str, str],
    page_urls: list[str],
    explorer_urls: list[str],
) -> list[str]:
    """Register URLs in the top-level sources map and return their IDs."""
    source_ids: list[str] = []
    for url in page_urls + explorer_urls:
        if url not in sources_map:
            sid = f"s{len(sources_map) + 1}"
            sources_map[url] = sid
        source_ids.append(sources_map[url])
    return source_ids


def _group_entries_by_address(entries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group evidence per address without guessing a chain for unknown evidence."""
    by_address: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        by_address[entry["address"]].append(entry)
    return by_address


def _chain_sort_key(chain_id: int) -> tuple[int, int]:
    label = _CHAIN_LABEL_BY_ID.get(chain_id)
    return (CHAIN_SORT_ORDER.get(label or "unknown", 50), chain_id)


def _chain_label_for_chain_id(chain_id: int | None) -> str | None:
    if chain_id is None:
        return None
    return _CHAIN_LABEL_BY_ID.get(chain_id)


def _select_chain_ids(evidence: list[dict[str, Any]]) -> list[int]:
    chain_ids: list[int] = []
    for item in evidence:
        raw_chain_id = item.get("chain_id")
        if raw_chain_id is None:
            continue
        chain_id = require_supported_chain_id(
            chain_id=raw_chain_id,
            context=f"inventory discovery evidence for {item.get('address')}",
        )
        if chain_id not in chain_ids:
            chain_ids.append(chain_id)
    chain_ids.sort(key=_chain_sort_key)
    return chain_ids


def _select_name(evidence: list[dict[str, Any]]) -> tuple[str | None, list[str]]:
    names = [str(item["name"]).strip() for item in evidence if item.get("name")]
    if not names:
        return None, []
    counts = Counter(names)
    primary = max(counts, key=lambda name: (counts[name], len(name)))
    aliases = sorted(name for name in counts if name != primary)
    return primary, aliases


def _determine_sources(evidence: list[dict[str, Any]]) -> list[str]:
    """Derive the source list from evidence kinds present for an address."""
    _KIND_TO_SOURCE = {
        "official_inventory_table": "ai_inventory",
        "official_inventory_link": "ai_inventory",
        "official_inventory_text": "ai_inventory",
        "exa_deep_research": "exa_deep_research",
        "deployer_expansion": "deployer_expansion",
    }
    sources: list[str] = []
    seen: set[str] = set()
    for item in evidence:
        source = _KIND_TO_SOURCE.get(item.get("kind", ""), "ai_inventory")
        if source not in seen:
            seen.add(source)
            sources.append(source)
    return sources


def _build_contracts(entries: list[dict[str, Any]], limit: int) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Build the contract list and a top-level sources map.

    Returns (contracts, sources_map) where sources_map is ``{url: id}``
    and each contract references source IDs instead of full URLs.
    """
    grouped = _group_entries_by_address(entries)
    sources_map: dict[str, str] = {}  # url → id
    contracts: list[dict[str, Any]] = []
    for address, evidence in grouped.items():
        chain_ids = _select_chain_ids(evidence)
        name, aliases = _select_name(evidence)
        confidence, evidence_counts = score_inventory_evidence(chain_ids[0] if chain_ids else None, evidence)
        page_urls, explorer_urls = _collect_source_urls(evidence)
        if not page_urls and not explorer_urls:
            continue
        source_types = _determine_sources(evidence)
        # Drop unnamed deployer-only contracts — without a name they can't be
        # catalogued or fed into the analysis pipeline (which needs verified source).
        if not name and source_types == ["deployer_expansion"]:
            continue
        source_ids = _register_sources(sources_map, page_urls, explorer_urls)
        contract: dict[str, Any] = {
            "name": name,
            "address": address,
            "chain_ids": chain_ids,
            "confidence": confidence,
            "source": source_types,
            "evidence": evidence_counts,
            "source_ids": source_ids,
        }
        if aliases:
            contract["aliases"] = aliases
        contracts.append(contract)

    sorted_contracts = sorted(
        contracts,
        key=lambda item: (
            -float(item["confidence"]),
            item["name"] is None,
            str(item.get("name") or ""),
            _chain_sort_key(item["chain_ids"][0]) if item["chain_ids"] else (50, 0),
            item["address"],
        ),
    )[:limit]
    return sorted_contracts, sources_map


def _group_multi_deployments(contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group contracts that share the same name and appear on multiple chains.

    Contracts with the same name but different addresses across chains are
    collapsed into a single entry with a ``deployments`` array.
    """
    # Index by lowercase name — only group named contracts.
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    ungroupable: list[dict[str, Any]] = []
    for contract in contracts:
        name = contract.get("name")
        if not name:
            ungroupable.append(contract)
            continue
        by_name[name.lower()].append(contract)

    result: list[dict[str, Any]] = []
    for _key, group in by_name.items():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Check if these are actually different addresses (multi-chain deploys).
        unique_addresses = {c["address"] for c in group}
        if len(unique_addresses) == 1:
            # Same address listed multiple times — just keep the best one.
            result.append(group[0])
            continue

        # Group into a single entry with deployments array.
        # Use the highest-confidence entry as the base.
        group.sort(key=lambda c: -c.get("confidence", 0))
        base = group[0].copy()
        all_chain_ids: list[int] = []
        seen_chain_ids: set[int] = set()
        deployments: list[dict[str, Any]] = []
        all_source_ids: list[str] = []
        seen_source_ids: set[str] = set()
        max_confidence = 0.0

        for contract in group:
            dep: dict[str, Any] = {"address": contract["address"]}
            dep_chain_ids = [
                require_supported_chain_id(
                    chain_id=chain_id,
                    context=f"inventory grouping for {contract['address']}",
                )
                for chain_id in contract.get("chain_ids", [])
            ]
            dep["chain_ids"] = dep_chain_ids
            for chain_id in dep_chain_ids:
                if chain_id not in seen_chain_ids:
                    all_chain_ids.append(chain_id)
                    seen_chain_ids.add(chain_id)
            if contract.get("activity"):
                dep["activity"] = contract["activity"]
            if contract.get("rank_score") is not None:
                dep["rank_score"] = contract["rank_score"]
            deployments.append(dep)
            max_confidence = max(max_confidence, contract.get("confidence", 0))
            for sid in contract.get("source_ids", []):
                if sid not in seen_source_ids:
                    all_source_ids.append(sid)
                    seen_source_ids.add(sid)

        base["chain_ids"] = sorted(all_chain_ids, key=_chain_sort_key)
        base["confidence"] = max_confidence
        base["source_ids"] = all_source_ids
        base["deployments"] = deployments
        # Remove single-address field — use deployments instead.
        base.pop("address", None)
        result.append(base)

    result.extend(ungroupable)
    # Re-sort after grouping.
    result.sort(
        key=lambda item: (
            -float(item.get("rank_score", item.get("confidence", 0))),
            item.get("name") is None,
            str(item.get("name") or ""),
            _chain_sort_key(item["chain_ids"][0]) if item.get("chain_ids") else (50, 0),
            item.get("address", ""),
        ),
    )
    return result


def search_protocol_inventory(
    company: str,
    *,
    search_fn: SearchFn,
    chain_id: int | None = None,
    limit: int = 500,
    max_queries: int = 4,
    run_deployer: bool = True,
    debug: bool = False,
) -> dict[str, Any]:
    clean_company = company.strip()
    if not clean_company:
        raise ValueError("company must not be empty")
    if limit < 1:
        raise ValueError("limit must be >= 1")

    requested_chain_id = (
        require_supported_chain_id(chain_id=chain_id, context=f"inventory discovery for {clean_company}")
        if chain_id is not None
        else None
    )
    requested_chain = _chain_label_for_chain_id(requested_chain_id)
    if requested_chain_id is not None and requested_chain is None:
        message = (
            f"inventory discovery for {clean_company} requires a known discovery label for "
            f"chain_id={requested_chain_id}"
        )
        logger.error(message)
        raise RuntimeError(message)
    errors: list[dict[str, Any]] = []
    notes: list[str] = []
    queries_used = [0]
    broad_results: list[dict[str, Any]] = []

    _debug_log(
        debug,
        (
            "Starting inventory discovery: "
            f"company={clean_company!r}, chain_id={requested_chain_id or 'any'}, "
            f"limit={limit}, max_queries={max_queries}"
        ),
    )

    # Always run broad search + LLM domain selection. A domain-shaped input
    # (e.g. ``"ether.fi"``) is kept as an input hint, but we prefer the
    # LLM's choice so companion docs/github hosts (``etherfi.gitbook.io``,
    # ``github.com/etherfi-protocol``) can become the primary when they're
    # the real contract-inventory source.
    hint_domain = _maybe_domain(clean_company)
    broad_results = search_fn(
        f'"{clean_company}" protocol smart contract addresses deployments docs',
        max_results=10,
        queries_used=queries_used,
        max_queries=max_queries,
        errors=errors,
        debug=debug,
    )
    domain_candidates = _domain_candidates_from_results(broad_results)
    if hint_domain and hint_domain not in domain_candidates:
        domain_candidates.insert(0, hint_domain)
    if domain_candidates:
        notes.append(f"Domain candidates: {', '.join(domain_candidates[:5])}")
    official_domain, extra_domains = _llm_select_domain(broad_results, clean_company, debug=debug)
    if not official_domain:
        message = f"Inventory discovery could not identify an official domain for {clean_company}"
        logger.error("%s; candidates=%s", message, domain_candidates[:5])
        raise RuntimeError(message)
    # Ensure the hint is at least a companion so site-scoped search still
    # covers the provided domain, even if the LLM preferred a gitbook/github host.
    if official_domain and hint_domain and hint_domain != official_domain:
        extras = list(extra_domains or [])
        if hint_domain not in extras:
            extras.insert(0, hint_domain)
        extra_domains = extras

    notes.append(f"Official domain: {official_domain}")
    page_results, selected_urls = _discover_contract_inventory_pages(
        official_domain,
        clean_company,
        broad_results,
        queries_used,
        max_queries,
        errors,
        search_fn,
        extra_domains=extra_domains if "extra_domains" in locals() else None,
        debug=debug,
    )

    considered_urls = [
        str(result.get("url", "")).strip() for result in page_results if str(result.get("url", "")).strip()
    ]
    if not selected_urls:
        message = f"Inventory discovery selected no contract inventory pages for {clean_company}"
        logger.error("%s; considered=%s", message, considered_urls[:5])
        raise RuntimeError(message)

    if selected_urls:
        notes.append(f"Selected pages: {len(selected_urls)}")
    page_entries = extract_inventory_entries_from_pages(selected_urls, requested_chain, debug=debug)

    deployer_entries: list[dict[str, Any]] = []
    if run_deployer and page_entries:
        seeds_by_chain_id: dict[int, set[str]] = defaultdict(set)
        for entry in page_entries:
            raw_chain_id = entry.get("chain_id") if entry.get("chain_id") is not None else requested_chain_id
            if raw_chain_id is None:
                continue
            seed_chain_id = require_supported_chain_id(
                chain_id=raw_chain_id,
                context=f"deployer expansion seed for {entry.get('address')}",
            )
            seeds_by_chain_id[seed_chain_id].add(entry["address"])

        if not seeds_by_chain_id:
            notes.append("Deployer expansion skipped: no chain-specific seed contracts")
        sorted_seed_groups = sorted(seeds_by_chain_id.items(), key=lambda item: _chain_sort_key(item[0]))
        for chain_id, seed_set in sorted_seed_groups:
            seed_addresses = sorted(seed_set)
            _debug_log(
                debug,
                f"Running deployer expansion on chain_id={chain_id} with {len(seed_addresses)} seed(s)",
            )
            try:
                chain_entries = expand_from_deployers(
                    seed_addresses,
                    chain_id=chain_id,
                    debug=debug,
                )
                deployer_entries.extend(chain_entries)
                notes.append(f"Deployer expansion (chain_id={chain_id}): {len(chain_entries)} contract(s)")
            except Exception as exc:
                logger.error("Deployer expansion failed for chain_id=%s: %s", chain_id, exc)
                _debug_log(debug, f"Deployer expansion failed for chain_id={chain_id}: {exc!r}")
                raise

    entries = page_entries + deployer_entries
    contracts, sources_map = _build_contracts(entries, limit=limit)

    # Activity ranking intentionally does NOT run here. The worker
    # pipeline runs the single authoritative ranking in the selection
    # stage (see ``services/discovery/ranking.rank_contract_rows``),
    # which sees contracts from every source — inventory, DApp crawl,
    # DefiLlama — on equal footing. Doing it here would re-rank
    # inventory contracts the selection stage is about to rank again.

    # Group multi-chain deployments of the same contract.
    contracts = _group_multi_deployments(contracts)

    if not contracts:
        notes.append("No inventory contracts extracted from selected pages")
    notes.append(f"Search queries used: {queries_used[0]}/{max_queries}")
    _debug_log(
        debug,
        (
            f"Completed inventory discovery: pages={len(selected_urls)}, "
            f"entries={len(entries)}, contracts={len(contracts)}, "
            f"queries_used={queries_used[0]}/{max_queries}, errors={len(errors)}"
        ),
    )

    # Invert sources map for output: {id: url}.
    sources_by_id = {sid: url for url, sid in sources_map.items()}

    return {
        "company": clean_company,
        "chain_id": requested_chain_id,
        "official_domain": official_domain,
        "domain_candidates": domain_candidates,
        "pages_considered": considered_urls[:10],
        "pages_selected": selected_urls[:5],
        "sources": sources_by_id,
        "contracts": contracts,
        "errors": errors[:12],
        "notes": notes[:12],
        "warning": (
            "Inventory discovery extracts officially published contract addresses from "
            "selected protocol pages but may miss contracts or mislabel entries. Always "
            "verify critical addresses against the protocol's canonical documentation."
        ),
    }
