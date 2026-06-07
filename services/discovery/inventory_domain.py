"""Domain selection, page discovery, and shared utilities for contract inventory.

This module provides the infrastructure layer for the inventory discovery pipeline:
  - Shared constants: regex patterns, blockchain explorer mappings, trust lists
  - Utility helpers: domain matching, chain inference, address extraction, page fetching
  - Explicit search backend integration with query budget management
  - LLM-based official domain identification and page selection
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import urlparse

import requests as _requests

from utils import llm

from .static_dependencies import normalize_address as _normalize_address

# -- Constants ---------------------------------------------------------------

ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+$", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")

EXPLORER_CHAINS = {
    "etherscan.io": "ethereum",
    "eth.blockscout.com": "ethereum",
    "arbiscan.io": "arbitrum",
    "arbitrum.blockscout.com": "arbitrum",
    "optimistic.etherscan.io": "optimism",
    "optimism.blockscout.com": "optimism",
    "polygonscan.com": "polygon",
    "polygon.blockscout.com": "polygon",
    "basescan.org": "base",
    "base.blockscout.com": "base",
}

LOW_TRUST_DOMAINS = {
    "coingecko.com",
    "coinmarketcap.com",
    "defillama.com",
    "x.com",
    "twitter.com",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "wikipedia.org",
    "reddit.com",
}

CHAIN_SORT_ORDER = {"ethereum": 0, "arbitrum": 1, "optimism": 2, "polygon": 3, "base": 4, "unknown": 99}

# Etherscan v2 chain IDs for chains the inventory pipeline can discover.
CHAIN_IDS: dict[str, int] = {
    "ethereum": 1,
    "arbitrum": 42161,
    "optimism": 10,
    "polygon": 137,
    "base": 8453,
    "avalanche": 43114,
    "bsc": 56,
    "linea": 59144,
    "scroll": 534352,
    "zksync": 324,
    "blast": 81457,
}


class SearchFn(Protocol):
    """Search callable used by discovery functions."""

    def __call__(
        self,
        query: str,
        max_results: int,
        queries_used: list[int],
        max_queries: int,
        errors: list[dict[str, Any]],
        debug: bool = False,
    ) -> list[dict[str, Any]]: ...


class RateLimiter:
    """Thread-safe rate limiter enforcing a minimum interval between calls."""

    def __init__(self, calls_per_second: float):
        import threading

        self._min_interval = 1.0 / calls_per_second
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self) -> None:
        import time

        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_call = time.monotonic()


# -- Utility helpers ---------------------------------------------------------


def _debug_log(enabled: bool, message: str) -> None:
    if enabled:
        ts = datetime.now().isoformat(timespec="seconds")
        print(f"[{ts}] [debug] {message}", file=sys.stderr, flush=True)


def _get_domain(url: str) -> str:
    try:
        domain = urlparse(url).netloc.lower()
    except ValueError:
        return ""
    return domain[4:] if domain.startswith("www.") else domain


def _domain_matches(domain: str, known: str) -> bool:
    return domain == known or domain.endswith(f".{known}")


def _is_explorer_domain(domain: str) -> bool:
    return any(_domain_matches(domain, k) for k in EXPLORER_CHAINS)


def _is_low_trust_domain(domain: str) -> bool:
    return any(_domain_matches(domain, k) for k in LOW_TRUST_DOMAINS)


def _is_allowed_domain(domain: str, allowed: list[str]) -> bool:
    return any(_domain_matches(domain, a) for a in allowed)


def _extract_addresses(*values: str) -> set[str]:
    out: set[str] = set()
    for value in values:
        if value:
            for match in ADDRESS_RE.findall(value):
                out.add(_normalize_address(match))
    return out


def _infer_chain(url: str, text: str) -> str:
    domain = _get_domain(url)
    for known, chain in EXPLORER_CHAINS.items():
        if _domain_matches(domain, known):
            return chain
    lowered = text.lower()
    if "arbitrum" in lowered:
        return "arbitrum"
    if "optimism" in lowered or "optimistic" in lowered:
        return "optimism"
    if "polygon" in lowered or "matic" in lowered:
        return "polygon"
    if "base" in lowered:
        return "base"
    if "ethereum" in lowered or "mainnet" in lowered:
        return "ethereum"
    return "unknown"


def _resolve_chain(inferred: str, requested: str | None) -> tuple[str | None, bool]:
    if not requested:
        return inferred, False
    if inferred not in {requested, "unknown"}:
        return None, False
    return requested, inferred == "unknown"


def _fetch_page(url: str, debug: bool = False) -> str | None:
    """Fetch a page via HTTP and return its text, or None on failure."""
    try:
        resp = _requests.get(url, timeout=30, headers={"User-Agent": "PSAT/0.1"})
        if resp.status_code == 200:
            _debug_log(debug, f"Fetched {url} ({len(resp.text)} chars)")
            return resp.text
        _debug_log(debug, f"Fetch {url}: HTTP {resp.status_code}")
    except _requests.RequestException as exc:
        _debug_log(debug, f"Fetch {url} failed: {exc!r}")
    return None


# -- Domain selection & page discovery ---------------------------------------


def _maybe_domain(value: str) -> str | None:
    clean = value.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if clean.startswith("www."):
        clean = clean[4:]
    if " " in clean or not DOMAIN_RE.match(clean) or _is_explorer_domain(clean):
        return None
    return clean


def _llm_select_domain(
    results: list[dict],
    company: str,
    debug: bool = False,
) -> tuple[str | None, list[str]]:
    """Ask the LLM to identify the best domain(s) for finding deployed contract addresses.

    Returns ``(primary_domain, extra_domains)`` where *extra_domains* are
    secondary docs sites (e.g. gitbook) that should also be searched.
    """
    if not results:
        return None, []

    # Collect unique non-explorer, non-low-trust domains with their URLs/titles
    domain_info: dict[str, list[str]] = defaultdict(list)
    for r in results:
        url = str(r.get("url", "")).strip()
        title = str(r.get("title", "")).strip()
        if not url:
            continue
        domain = _get_domain(url)
        if not domain or _is_explorer_domain(domain) or _is_low_trust_domain(domain):
            continue
        domain_info[domain].append(title or url)

    if not domain_info:
        return None, []

    # Present as numbered choices (more reliable across LLM models)
    sorted_domains = sorted(domain_info.keys(), key=lambda d: -len(domain_info[d]))
    choices = "\n".join(
        f"{i + 1}. {domain} (pages: {', '.join(titles[:2])})"
        for i, (domain, titles) in enumerate((d, domain_info[d]) for d in sorted_domains)
    )

    prompt = (
        f"Which of these domains contain official documentation or deployed "
        f"smart contract addresses for the {company} protocol?\n"
        f"Many protocols use a separate docs site (e.g. gitbook, readthedocs, "
        f"notion) alongside their main website.\n\n{choices}\n\n"
        f"Reply with the number(s), comma-separated if more than one. "
        f"Put the most important domain first."
    )

    try:
        response = llm.chat(
            [{"role": "user", "content": prompt}],
            max_tokens=32,
            temperature=0.0,
        )
        nums = [int(m) - 1 for m in re.findall(r"\d+", response.strip())]
        selected: list[str] = []
        for idx in nums:
            if 0 <= idx < len(sorted_domains) and sorted_domains[idx] not in selected:
                selected.append(sorted_domains[idx])
        if selected:
            _debug_log(debug, f"LLM selected domain(s): {selected}")
            return selected[0], selected[1:]
        _debug_log(debug, f"LLM returned unparseable response: {response!r}")
    except (_requests.RequestException, json.JSONDecodeError, RuntimeError) as exc:
        _debug_log(debug, f"LLM domain selection failed: {exc!r}")
    return None, []


def _domain_candidates_from_results(results: list[dict[str, Any]]) -> list[str]:
    """Return ordered non-explorer, non-low-trust domains seen in search results."""
    domain_info: dict[str, list[str]] = defaultdict(list)
    for result in results:
        url = str(result.get("url", "")).strip()
        title = str(result.get("title", "")).strip()
        if not url:
            continue
        domain = _get_domain(url)
        if not domain or _is_explorer_domain(domain) or _is_low_trust_domain(domain):
            continue
        domain_info[domain].append(title or url)
    return sorted(domain_info.keys(), key=lambda d: (-len(domain_info[d]), d))


def _collect_in_domain_pages(results: list[dict[str, Any]], domain: str) -> list[dict[str, str]]:
    """Collect unique page URLs, titles, and snippets for a domain."""
    seen_urls: set[str] = set()
    page_info: list[dict[str, str]] = []
    for result in results:
        url = str(result.get("url", "")).strip()
        title = str(result.get("title", "")).strip()
        snippet = str(result.get("content", "")).strip()
        if not url or url in seen_urls:
            continue
        if not _is_allowed_domain(_get_domain(url), [domain]):
            continue
        seen_urls.add(url)
        page_info.append({"url": url, "title": title, "snippet": snippet})
    return page_info


def _llm_select_pages(
    page_info: list[dict[str, str]],
    company: str,
    domain_label: str,
    prompt: str,
    allowed_domains: list[str],
    debug: bool = False,
) -> list[str]:
    """Ask the LLM to choose the most relevant in-domain pages from a candidate list."""
    if not page_info:
        return []

    page_list = "\n".join(
        (f"- {page['title'] or '(untitled)'}: {page['url']}\n  Snippet: {(page['snippet'] or 'none')[:240]}")
        for page in page_info
    )

    try:
        response = llm.chat(
            [{"role": "user", "content": prompt.format(company=company, domain=domain_label, page_list=page_list)}],
            max_tokens=2048,
            temperature=0.0,
        )
        recommended: list[str] = []
        seen: set[str] = set()
        for url_match in URL_RE.findall(response):
            clean_url = url_match.rstrip(".,;:!?)")
            if clean_url in seen:
                continue
            if _is_allowed_domain(_get_domain(clean_url), allowed_domains):
                seen.add(clean_url)
                recommended.append(clean_url)
        _debug_log(debug, f"LLM recommended {len(recommended)} in-domain URL(s)")
        return recommended
    except (_requests.RequestException, json.JSONDecodeError, RuntimeError) as exc:
        _debug_log(debug, f"LLM page selection failed: {exc!r}")
        return []


def _dedupe_results_by_url(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge search results by URL, preferring richer snippets."""
    by_url: dict[str, dict[str, Any]] = {}
    for result in results:
        url = str(result.get("url", "")).strip()
        if not url:
            continue
        prev = by_url.get(url)
        if prev is None:
            by_url[url] = result
            continue
        prev_content = str(prev.get("content", "")).strip()
        new_content = str(result.get("content", "")).strip()
        if len(new_content) > len(prev_content):
            merged = dict(prev)
            merged.update(result)
            by_url[url] = merged
    return list(by_url.values())


def _discover_contract_inventory_pages(
    domain: str,
    company: str,
    broad_results: list[dict[str, Any]],
    queries_used: list[int],
    max_queries: int,
    errors: list[dict],
    search_fn: SearchFn,
    extra_domains: list[str] | None = None,
    debug: bool = False,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Discover pages that likely contain official multi-contract inventory information."""
    all_domains = [domain] + sorted(set(extra_domains or []) - {domain})
    _debug_log(debug, f"Inventory page discovery on domain(s)={all_domains}")

    site_results: list[dict[str, Any]] = []
    for d in all_domains:
        site_results.extend(
            search_fn(
                f"site:{d} {company} contract addresses deployments smart contracts",
                max_results=12,
                queries_used=queries_used,
                max_queries=max_queries,
                errors=errors,
                debug=debug,
            )
        )

    combined = _dedupe_results_by_url(
        [r for r in broad_results if _is_allowed_domain(_get_domain(str(r.get("url", ""))), all_domains)] + site_results
    )
    if not combined:
        _debug_log(debug, "No inventory page candidates returned")
        return [], []

    page_info: list[dict[str, str]] = []
    for d in all_domains:
        page_info.extend(_collect_in_domain_pages(combined, d))
    # Dedupe by URL in case of overlap
    seen: set[str] = set()
    unique_page_info: list[dict[str, str]] = []
    for p in page_info:
        if p["url"] not in seen:
            seen.add(p["url"])
            unique_page_info.append(p)
    page_info = unique_page_info

    if not page_info:
        _debug_log(debug, "No in-domain inventory page candidates available")
        return combined, []

    domain_label = " / ".join(all_domains)
    prompt = (
        "Below are pages from the {company} documentation or official website ({domain}).\n"
        "Which of these pages are most likely to contain an authoritative inventory of deployed "
        "smart contract addresses for the protocol?\n"
        "Prefer pages that enumerate multiple contracts, chains, or deployments. Avoid blog posts, "
        "news, governance posts, and pages about only one isolated contract unless they clearly link to "
        "a broader contract inventory.\n\n"
        "{page_list}\n\n"
        "Reply with ONLY the best URL(s), one per line — nothing else."
    )
    recommended = _llm_select_pages(
        page_info,
        company,
        domain_label,
        prompt,
        allowed_domains=all_domains,
        debug=debug,
    )
    return combined, recommended
