"""HTML parsing and contract entry extraction for the inventory pipeline.

Fetches official protocol pages and extracts contract records (name, address,
chain) from tables, lists, explorer links, and prose text.  Called by
inventory.py after inventory_domain.py identifies the pages.
"""

from __future__ import annotations

import html as _html
import re
from typing import Any

from .inventory_domain import (
    ADDRESS_RE,
    TAG_RE,
    URL_RE,
    _debug_log,
    _extract_addresses,
    _fetch_page,
    _get_domain,
    _infer_chain,
    _is_explorer_domain,
    _resolve_chain,
)
from .static_dependencies import normalize_address as _normalize_address

_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style|noscript|svg)\b.*?</\1>")
_ANCHOR_RE = re.compile(r"""(?is)<a\b[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""")
_HEADING_RE = re.compile(r"(?is)<h([1-6])\b[^>]*>(.*?)</h\1>")
_BLOCK_CLOSE_RE = re.compile(r"(?i)</(tr|li|p|div|section|article|ul|ol|pre|code|table|dd|dt)>")
_CELL_CLOSE_RE = re.compile(r"(?i)</(td|th)>")
_BREAK_RE = re.compile(r"(?i)<br\s*/?>")
_MULTISPACE_RE = re.compile(r"\s+")
_GENERIC_LABELS = {
    "address",
    "addresses",
    "contract",
    "contracts",
    "smart contract",
    "smart contracts",
    "deployment",
    "deployments",
    "official contracts",
    "contract addresses",
    "smart contract addresses",
}
_HEADER_ROLE_BY_LABEL = {
    "contract": "name",
    "contracts": "name",
    "claim": "name",
    "asset": "name",
    "token": "name",
    "name": "name",
    "chain": "chain",
    "network": "chain",
    "address": "address",
    "contract address": "address",
    "token address": "address",
}
_CHAIN_ALIASES = {
    "mainnet": "ethereum",
    "ethereum": "ethereum",
    "arbitrum": "arbitrum",
    "optimism": "optimism",
    "polygon": "polygon",
    "base": "base",
    "avalanche": "avalanche",
    "blast": "blast",
    "berachain": "berachain",
    "bsc": "bsc",
    "binance smart chain": "bsc",
    "hyperevm": "hyperevm",
    "ink": "ink",
    "katana": "katana",
    "linea": "linea",
    "mode": "mode",
    "monad": "monad",
    "morph": "morph",
    "scroll": "scroll",
    "sonic": "sonic",
    "swell": "swell",
    "unichain": "unichain",
    "zksync": "zksync",
    "zk sync": "zksync",
    "corn": "corn",
}
_GENERIC_SECTION_HEADINGS = {
    "deployed contracts",
    "cross-chain token contracts",
    "cash contracts",
    "claim contracts",
    "liquid vault contracts",
    "contracts and integrations",
}


def _anchor_to_text(match: re.Match[str]) -> str:
    href = match.group(1).strip()
    text = TAG_RE.sub(" ", match.group(2))
    text = _MULTISPACE_RE.sub(" ", text).strip()
    if text:
        return f"{text} {href} "
    return f"{href} "


def _html_to_lines(page_text: str) -> list[str]:
    """Convert HTML into line-oriented text while preserving headings and links."""
    cleaned = _SCRIPT_STYLE_RE.sub(" ", page_text)
    cleaned = _HEADING_RE.sub(
        lambda m: f"\n__HEADING__ {TAG_RE.sub(' ', m.group(2))}\n",
        cleaned,
    )
    cleaned = _ANCHOR_RE.sub(_anchor_to_text, cleaned)
    cleaned = _BREAK_RE.sub("\n", cleaned)
    cleaned = _CELL_CLOSE_RE.sub(" | ", cleaned)
    cleaned = _BLOCK_CLOSE_RE.sub("\n", cleaned)
    cleaned = TAG_RE.sub(" ", cleaned)
    cleaned = _html.unescape(cleaned)

    lines: list[str] = []
    for raw_line in cleaned.splitlines():
        line = _MULTISPACE_RE.sub(" ", raw_line).strip(" \t\r\n|-:;")
        if line:
            lines.append(line)
    return lines


def _looks_like_chain_label(value: str) -> bool:
    text = value.strip().lower()
    if not text:
        return False
    if not _parse_chain_values(text):
        return False
    return len(text.split()) <= 3


def _clean_label(value: str) -> str | None:
    text = value
    for raw_url in URL_RE.findall(text):
        text = text.replace(raw_url, " ")
    text = ADDRESS_RE.sub(" ", text)
    text = re.sub(r"\b(contract addresses?|smart contracts?|addresses?|deployments?)\b", " ", text, flags=re.IGNORECASE)
    text = _MULTISPACE_RE.sub(" ", text).strip(" \t\r\n|:-,.;")
    if not text or len(text) < 3 or len(text) > 120:
        return None
    if not re.search(r"[A-Za-z]", text):
        return None
    if text.lower() in _GENERIC_LABELS:
        return None
    if _looks_like_chain_label(text):
        return None
    return text


def _label_score(value: str) -> tuple[int, int]:
    words = value.split()
    alpha_count = sum(ch.isalpha() for ch in value)
    return (
        1 if 1 <= len(words) <= 8 else 0,
        alpha_count,
    )


def _normalize_label(value: str) -> str:
    return _MULTISPACE_RE.sub(" ", value.strip().lower())


def _header_role(value: str) -> str | None:
    return _HEADER_ROLE_BY_LABEL.get(_normalize_label(value))


def _parse_chain_values(value: str) -> list[str]:
    text = _normalize_label(value)
    if not text:
        return []

    chains: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[,/]| and ", text):
        clean = _normalize_label(part)
        if not clean:
            continue
        chain = _CHAIN_ALIASES.get(clean)
        if not chain:
            inferred = _infer_chain("", clean)
            chain = inferred if inferred != "unknown" else None
        if chain and chain not in seen:
            seen.add(chain)
            chains.append(chain)

    if chains:
        return chains

    inferred = _infer_chain("", text)
    return [inferred] if inferred != "unknown" else []


def _default_name_from_heading(heading: str | None) -> str | None:
    if not heading:
        return None
    clean = _normalize_label(heading)
    if not clean or clean in _GENERIC_SECTION_HEADINGS:
        return None
    return heading


def _resolve_candidate_chains(
    chain_value: str | None,
    line_chain: str,
    requested_chain: str | None,
) -> list[tuple[str, bool]]:
    explicit = _parse_chain_values(chain_value or "")
    candidates = explicit or ([line_chain] if line_chain != "unknown" else [])
    if not candidates:
        candidates = ["unknown"]

    resolved: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for candidate in candidates:
        final_chain, hinted = _resolve_chain(candidate, requested_chain)
        if final_chain is None or final_chain in seen:
            continue
        seen.add(final_chain)
        resolved.append((final_chain, hinted))
    return resolved


def _build_entries_from_table_row(
    schema_roles: list[str],
    row_cells: list[str],
    url: str,
    current_heading: str | None,
    current_chain: str,
    requested_chain: str | None,
) -> list[dict[str, Any]]:
    cell_by_role: dict[str, list[str]] = {"name": [], "chain": [], "address": []}
    for role, cell in zip(schema_roles, row_cells):
        cell_by_role.setdefault(role, []).append(cell)

    address_blob = " ".join(cell_by_role.get("address", []))
    addresses, explorer_links = _extract_addresses_and_links(address_blob)
    if not addresses:
        return []

    name = next(
        (clean for clean in (_clean_label(cell) for cell in cell_by_role.get("name", [])) if clean),
        _default_name_from_heading(current_heading),
    )
    chain_value = " ".join(cell_by_role.get("chain", [])) if cell_by_role.get("chain") else None
    resolved_chains = _resolve_candidate_chains(chain_value, current_chain, requested_chain)

    entries: list[dict[str, Any]] = []
    for address in addresses:
        explorer_url = next((link for link in explorer_links if address in _extract_addresses(link)), None)
        for resolved, chain_from_hint in resolved_chains:
            entries.append(
                {
                    "name": name,
                    "address": address,
                    "chain": resolved,
                    "kind": "official_inventory_table",
                    "url": url,
                    "explorer_url": explorer_url,
                    "chain_from_hint": chain_from_hint,
                }
            )
    return entries


def _extract_name_from_line(line: str) -> str | None:
    """Extract the most likely contract label from a line containing one or more addresses."""
    candidates: list[str] = []
    segments = [seg.strip() for seg in line.split("|") if seg.strip()]
    for segment in segments:
        clean = _clean_label(segment)
        if clean:
            candidates.append(clean)

    if not candidates:
        split_candidates = re.split(r"\s[-:]\s", line, maxsplit=1)
        for segment in split_candidates:
            clean = _clean_label(segment)
            if clean:
                candidates.append(clean)

    if not candidates:
        first_addr = ADDRESS_RE.search(line)
        first_url = next((u for u in URL_RE.findall(line) if _is_explorer_domain(_get_domain(u))), None)
        cutoff = len(line)
        if first_addr:
            cutoff = min(cutoff, first_addr.start())
        if first_url:
            cutoff = min(cutoff, line.find(first_url))
        if cutoff > 0:
            clean = _clean_label(line[:cutoff])
            if clean:
                candidates.append(clean)

    if not candidates:
        return None
    return max(set(candidates), key=_label_score)


def _extract_addresses_and_links(line: str) -> tuple[list[str], list[str]]:
    explorer_links: list[str] = []
    seen_links: set[str] = set()
    addresses: set[str] = set(_normalize_address(match) for match in ADDRESS_RE.findall(line))

    for raw_url in URL_RE.findall(line):
        clean_url = raw_url.rstrip(".,;:!?)")
        if not _is_explorer_domain(_get_domain(clean_url)):
            continue
        if clean_url not in seen_links:
            seen_links.add(clean_url)
            explorer_links.append(clean_url)
        addresses.update(_extract_addresses(clean_url))

    return sorted(addresses), explorer_links


def _entry_kind(line: str, explorer_links: list[str]) -> str:
    if "|" in line:
        return "official_inventory_table"
    if explorer_links:
        return "official_inventory_link"
    return "official_inventory_text"


def _line_is_only_locator(line: str) -> bool:
    text = line
    for raw_url in URL_RE.findall(text):
        text = text.replace(raw_url, " ")
    text = ADDRESS_RE.sub(" ", text)
    text = _MULTISPACE_RE.sub(" ", text).strip(" \t\r\n|:-,.;")
    return not text


def extract_inventory_entries_from_page_text(
    url: str,
    page_text: str,
    requested_chain: str | None,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Extract address records from a single official page."""
    lines = _html_to_lines(page_text)
    plain_page = TAG_RE.sub(" ", page_text)
    page_chain = _infer_chain(url, plain_page[:4000])
    current_chain = page_chain
    current_heading: str | None = None
    pending_label: str | None = None
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str | None, str, str]] = set()
    schema_roles: list[str] | None = None
    i = 0

    while i < len(lines):
        line = lines[i]
        if line.startswith("__HEADING__ "):
            heading = line[len("__HEADING__ ") :].strip()
            current_heading = heading
            heading_chain = _infer_chain("", heading)
            if heading_chain != "unknown":
                current_chain = heading_chain
            schema_roles = None
            pending_label = None
            i += 1
            continue

        if schema_roles is None:
            header_roles: list[str] = []
            j = i
            while j < len(lines):
                if lines[j].startswith("__HEADING__ "):
                    break
                role = _header_role(lines[j])
                if not role:
                    break
                header_roles.append(role)
                j += 1
            if len(header_roles) >= 2 and "address" in header_roles:
                schema_roles = header_roles
                i = j
                pending_label = None
                continue

        if schema_roles is not None:
            row_len = len(schema_roles)
            if i + row_len <= len(lines):
                row_cells = lines[i : i + row_len]
                if not any(cell.startswith("__HEADING__ ") for cell in row_cells):
                    row_entries = _build_entries_from_table_row(
                        schema_roles,
                        row_cells,
                        url,
                        current_heading,
                        current_chain,
                        requested_chain,
                    )
                    if row_entries:
                        for entry in row_entries:
                            signature = (
                                entry["chain"],
                                entry["address"],
                                entry["name"],
                                entry["kind"],
                                entry["url"],
                            )
                            if signature in seen:
                                continue
                            seen.add(signature)
                            entries.append(entry)
                        pending_label = None
                        i += row_len
                        continue
                    # Stay in schema mode for malformed or incomplete rows so later
                    # rows in the same table still parse with the correct columns.
                    if not any(_header_role(cell) for cell in row_cells):
                        pending_label = None
                        i += row_len
                        continue
            schema_roles = None

        addresses, explorer_links = _extract_addresses_and_links(line)
        if not addresses:
            context_chains = _parse_chain_values(line)
            if context_chains and any(token in line.lower() for token in ("deploy", "mainnet", "chain")):
                current_chain = context_chains[0]
                pending_label = None
                i += 1
                continue
            clean_label = _clean_label(line)
            if clean_label:
                pending_label = clean_label
            i += 1
            continue

        line_chain = current_chain
        if explorer_links:
            linked_chain = _infer_chain(explorer_links[0], "")
            if linked_chain != "unknown":
                line_chain = linked_chain
        if line_chain == "unknown":
            inferred = _infer_chain("", line)
            if inferred != "unknown":
                line_chain = inferred

        name = _extract_name_from_line(line)
        if not name and pending_label and _line_is_only_locator(line):
            name = pending_label
        kind = _entry_kind(line, explorer_links)
        if name and pending_label == name and _line_is_only_locator(line):
            kind = "official_inventory_table"
        pending_label = None

        for address in addresses:
            explorer_url = next((link for link in explorer_links if address in _extract_addresses(link)), None)
            for resolved, chain_from_hint in _resolve_candidate_chains(None, line_chain, requested_chain):
                signature = (resolved, address, name, kind, url)
                if signature in seen:
                    continue
                seen.add(signature)
                entries.append(
                    {
                        "name": name,
                        "address": address,
                        "chain": resolved,
                        "kind": kind,
                        "url": url,
                        "explorer_url": explorer_url,
                        "chain_from_hint": chain_from_hint,
                    }
                )

        i += 1

    _debug_log(debug, f"Inventory page {url} produced {len(entries)} extracted record(s)")
    return entries


def extract_inventory_entries_from_pages(
    urls: list[str],
    requested_chain: str | None,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Fetch selected pages and aggregate extracted inventory entries.

    Page fetches happen concurrently — each URL is an independent HTTP call
    to a different host so there's no shared rate limit to respect. Iteration
    over results stays in input order so downstream entry ordering is stable.
    """
    from services.concurrency import parallel_map

    fetch_results = parallel_map(lambda u: _fetch_page(u, debug=debug), urls, max_workers=8)
    out: list[dict[str, Any]] = []
    for url, page_text in zip(urls, [r for _u, r in fetch_results]):
        if isinstance(page_text, BaseException):
            _debug_log(debug, f"Fetch {url} raised: {page_text!r}")
            continue
        if not page_text:
            continue
        out.extend(extract_inventory_entries_from_page_text(url, page_text, requested_chain, debug=debug))
    return out
