"""Orchestrator for protocol contract inventory discovery.

Given a company/protocol name or domain, this module:
  1. Identifies the official domain via Tavily search + LLM  (inventory_domain.py)
  2. Selects pages likely to contain contract inventories     (inventory_domain.py)
  3. Extracts contract entries from those pages               (inventory_extract.py)
  4. Scores, deduplicates, and ranks the results
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from typing import Any

from utils.chains import canonical_chain, canonical_chain_list
from utils.logging import record_degraded

from .chain_resolver import resolve_unknown_chains, validate_claimed_chains
from .deployer import expand_from_deployers
from .inventory_domain import (
    CHAIN_SORT_ORDER,
    _debug_log,
    _discover_contract_inventory_pages,
    _domain_candidates_from_results,
    _llm_select_domain,
    _maybe_domain,
    _tavily_search,
)
from .inventory_extract import extract_inventory_entries_from_pages
from .ranking import score_inventory_evidence

logger = logging.getLogger(__name__)


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


def _collapse_unknown_chain_entries(entries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Merge unknown-chain evidence per address while preserving multi-chain evidence."""
    by_address: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        chain = canonical_chain(entry.get("chain")) or "unknown"
        by_address[entry["address"]].append({**entry, "chain": chain})

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for address, items in by_address.items():
        specific = {item["chain"] for item in items if item["chain"] != "unknown"}
        remapped_chain = next(iter(specific)) if len(specific) == 1 else None
        for item in items:
            chain = item["chain"]
            if chain == "unknown" and remapped_chain:
                chain = remapped_chain
            grouped[address].append({**item, "chain": chain})
    return grouped


def _sorted_chains(chains: set[str]) -> list[str]:
    return sorted(chains, key=lambda chain: (CHAIN_SORT_ORDER.get(chain, 50), chain))


def _select_chain_summary(evidence: list[dict[str, Any]]) -> tuple[str, list[str]]:
    specific = _sorted_chains(
        {chain for item in evidence if (chain := (canonical_chain(item.get("chain")) or "unknown")) != "unknown"}
    )
    if specific:
        if len(specific) == 1:
            return specific[0], specific
        return "multiple", specific

    if any(item.get("chain") == "unknown" for item in evidence):
        return "unknown", ["unknown"]
    return "unknown", []


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
    grouped = _collapse_unknown_chain_entries(entries)
    sources_map: dict[str, str] = {}  # url → id
    contracts: list[dict[str, Any]] = []
    for address, evidence in grouped.items():
        _chain, chains = _select_chain_summary(evidence)
        name, aliases = _select_name(evidence)
        confidence, evidence_counts = score_inventory_evidence(_chain, evidence)
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
            "chains": chains,
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
            CHAIN_SORT_ORDER.get(item["chains"][0] if item["chains"] else "unknown", 50),
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
        all_chains: list[str] = []
        seen_chains: set[str] = set()
        deployments: list[dict[str, Any]] = []
        all_source_ids: list[str] = []
        seen_source_ids: set[str] = set()
        max_confidence = 0.0

        for contract in group:
            dep: dict[str, Any] = {"address": contract["address"]}
            dep_chains = canonical_chain_list(contract.get("chains", ["unknown"])) or ["unknown"]
            dep["chains"] = dep_chains
            for ch in dep_chains:
                if ch not in seen_chains:
                    all_chains.append(ch)
                    seen_chains.add(ch)
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

        base["chains"] = canonical_chain_list(all_chains) or []
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
            CHAIN_SORT_ORDER.get(item["chains"][0] if item.get("chains") else "unknown", 50),
            item.get("address", ""),
        ),
    )
    return result


def search_protocol_inventory(
    company: str,
    chain: str | None = None,
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

    requested_chain = canonical_chain(chain) if isinstance(chain, str) and chain.strip() else None
    errors: list[dict[str, Any]] = []
    notes: list[str] = []
    queries_used = [0]
    broad_results: list[dict[str, Any]] = []

    _debug_log(
        debug,
        (
            "Starting inventory discovery: "
            f"company={clean_company!r}, chain={requested_chain or 'any'}, "
            f"limit={limit}, max_queries={max_queries}"
        ),
    )

    # Always run broad Tavily + LLM domain selection. A domain-shaped input
    # (e.g. ``"ether.fi"``) is kept as a fallback hint, but we prefer the
    # LLM's choice so companion docs/github hosts (``etherfi.gitbook.io``,
    # ``github.com/etherfi-protocol``) can become the primary when they're
    # the real contract-inventory source.
    hint_domain = _maybe_domain(clean_company)
    broad_results = _tavily_search(
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
        if hint_domain:
            official_domain = hint_domain
            extra_domains = [d for d in domain_candidates if d != hint_domain][:3]
            notes.append(f"LLM didn't select a domain; using provided domain: {official_domain}")
        elif len(domain_candidates) == 1:
            official_domain = domain_candidates[0]
            extra_domains = []
            notes.append(f"Falling back to sole domain candidate: {official_domain}")
    # Ensure the hint is at least a companion so site-scoped search still
    # covers the provided domain, even if the LLM preferred a gitbook/github host.
    if official_domain and hint_domain and hint_domain != official_domain:
        extras = list(extra_domains or [])
        if hint_domain not in extras:
            extras.insert(0, hint_domain)
        extra_domains = extras

    if not official_domain:
        notes.append("Could not identify an official domain")
        notes.append(f"Tavily queries used: {queries_used[0]}/{max_queries}")
        return {
            "company": clean_company,
            "chain": requested_chain or "any",
            "official_domain": None,
            "domain_candidates": domain_candidates if "domain_candidates" in locals() else [],
            "pages_considered": [],
            "pages_selected": [],
            "contracts": [],
            "errors": errors[:12],
            "notes": notes[:12],
        }

    notes.append(f"Official domain: {official_domain}")
    page_results, selected_urls = _discover_contract_inventory_pages(
        official_domain,
        clean_company,
        broad_results,
        queries_used,
        max_queries,
        errors,
        extra_domains=extra_domains if "extra_domains" in locals() else None,
        debug=debug,
    )

    considered_urls = [
        str(result.get("url", "")).strip() for result in page_results if str(result.get("url", "")).strip()
    ]
    if not selected_urls:
        selected_urls = considered_urls[:3]
        if selected_urls:
            notes.append("LLM page selection unavailable; fell back to top in-domain page candidates")

    if selected_urls:
        notes.append(f"Selected pages: {len(selected_urls)}")
    tavily_entries = extract_inventory_entries_from_pages(selected_urls, requested_chain, debug=debug)

    deployer_entries: list[dict[str, Any]] = []
    if run_deployer and tavily_entries:
        seed_addresses = sorted({e["address"] for e in tavily_entries})
        _debug_log(debug, f"Running deployer expansion with {len(seed_addresses)} seed(s)")
        try:
            deployer_entries = expand_from_deployers(seed_addresses, debug=debug)
            notes.append(f"Deployer expansion: {len(deployer_entries)} contract(s)")
        except Exception as exc:
            logger.warning(
                "Deployer expansion failed; corroboration source dropped",
                extra={"phase": "deployer_expansion", "exc_type": type(exc).__name__, "seeds": len(seed_addresses)},
            )
            record_degraded(phase="deployer_expansion", exc=exc, context={"seeds": len(seed_addresses)})
            notes.append(f"Deployer expansion failed: {exc}")

    entries = tavily_entries + deployer_entries
    contracts, sources_map = _build_contracts(entries, limit=limit)

    # Resolve unknown chains before activity ranking (activity needs correct chain_id).
    def _primary_chain(c: dict[str, Any]) -> str:
        chains = c.get("chains", [])
        return (canonical_chain(chains[0]) if chains else None) or "unknown"

    unknown_count = sum(1 for c in contracts if _primary_chain(c) == "unknown")
    if unknown_count:
        _debug_log(debug, f"Resolving chain for {unknown_count} unknown-chain contract(s)")
        try:
            contracts = resolve_unknown_chains(contracts, debug=debug)
            resolved = unknown_count - sum(1 for c in contracts if _primary_chain(c) == "unknown")
            notes.append(f"Chain resolution: resolved {resolved}/{unknown_count} unknown chain(s)")
        except Exception as exc:
            logger.warning(
                "Chain resolution failed; %d contract(s) left on unknown chain",
                unknown_count,
                extra={"phase": "chain_resolution", "exc_type": type(exc).__name__, "unknown_count": unknown_count},
            )
            record_degraded(phase="chain_resolution", exc=exc, context={"unknown_count": unknown_count})
            notes.append(f"Chain resolution failed: {exc}")

    if any("exa_deep_research" in (c.get("source") or []) for c in contracts):
        try:
            contracts = validate_claimed_chains(contracts, source_names=("exa_deep_research",), debug=debug)
        except Exception as exc:
            logger.warning(
                "Claimed-chain sanity check failed",
                extra={"phase": "claimed_chain_validation", "exc_type": type(exc).__name__},
            )
            record_degraded(phase="claimed_chain_validation", exc=exc, context={"company": company})
            notes.append(f"Claimed-chain sanity check failed: {exc}")

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
    notes.append(f"Tavily queries used: {queries_used[0]}/{max_queries}")
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
        "chain": requested_chain or "any",
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


# ---------------------------------------------------------------------------
# Inventory merge (append-only with confidence decay)
# ---------------------------------------------------------------------------

# Confidence decay factor applied to contracts not rediscovered on re-run.
CONFIDENCE_DECAY = 0.8

# Confidence floor — entries below this are dropped entirely.
CONFIDENCE_FLOOR = 0.1


def merge_inventory(prev: dict, new: dict) -> dict:
    """Merge a previous inventory with a new one (append-only with confidence decay).

    Contracts present in both use the new entry but keep the higher confidence.
    Contracts only in the previous inventory are retained with decayed confidence
    (multiplied by :data:`CONFIDENCE_DECAY` each time they are not rediscovered).
    Contracts that decay below :data:`CONFIDENCE_FLOOR` are dropped.
    """
    prev_contracts = {c["address"].lower(): c for c in prev.get("contracts", []) if c.get("address")}
    new_contracts = {c["address"].lower(): c for c in new.get("contracts", []) if c.get("address")}

    merged: dict[str, dict] = {}

    # Addresses in new (possibly also in prev)
    for addr, entry in new_contracts.items():
        if addr not in prev_contracts:
            merged[addr] = entry
        else:
            # In both — use new entry, keep higher confidence
            prev_conf = prev_contracts[addr].get("confidence", 0) or 0
            new_conf = entry.get("confidence", 0) or 0
            merged_entry = dict(entry)
            merged_entry["confidence"] = max(prev_conf, new_conf)
            merged[addr] = merged_entry

    # Addresses only in prev — decay confidence
    for addr, entry in prev_contracts.items():
        if addr not in new_contracts:
            decayed_entry = dict(entry)
            prev_conf = entry.get("confidence", 0) or 0
            decayed_conf = prev_conf * CONFIDENCE_DECAY
            if decayed_conf < CONFIDENCE_FLOOR:
                continue
            decayed_entry["confidence"] = decayed_conf
            merged[addr] = decayed_entry

    sorted_contracts = sorted(merged.values(), key=lambda c: c.get("confidence", 0) or 0, reverse=True)

    result: dict = {
        "contracts": sorted_contracts,
        "company": new.get("company", prev.get("company")),
        "chain": new.get("chain", prev.get("chain")),
        "official_domain": new.get("official_domain") or prev.get("official_domain"),
        "errors": new.get("errors"),
        "notes": new.get("notes"),
    }

    # Union pages by URL
    for key in ("pages_considered", "pages_selected"):
        prev_pages = prev.get(key, []) or []
        new_pages = new.get(key, []) or []
        seen_urls: set[str] = set()
        deduped: list = []
        for page in new_pages + prev_pages:
            url = page.get("url", "") if isinstance(page, dict) else str(page)
            if url not in seen_urls:
                seen_urls.add(url)
                deduped.append(page)
        result[key] = deduped

    # Merge sources dicts
    prev_sources = prev.get("sources") or {}
    new_sources = new.get("sources") or {}
    if isinstance(prev_sources, dict) and isinstance(new_sources, dict):
        result["sources"] = {**prev_sources, **new_sources}
    else:
        result["sources"] = new_sources or prev_sources

    return result
