"""
Stores and manages captured DApp interactions (transactions, signatures,
contract addresses) discovered during crawling.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class CapturedInteraction:
    """A single interaction a DApp tried to initiate with our wallet."""

    type: str  # sendTransaction, signTypedData, personal_sign, etc.
    url: str
    timestamp: int
    to: str | None = None  # contract address (for transactions)
    value: str | None = None  # ETH value
    data: str | None = None  # calldata
    method_selector: str | None = None  # first 4 bytes of calldata
    typed_data: dict | None = None  # for signTypedData
    is_permit: bool = False
    message: str | None = None  # for personal_sign
    raw: dict | None = None  # full raw capture


@dataclass
class InteractionLog:
    """Collection of all captured interactions from a crawl session."""

    interactions: list[CapturedInteraction] = field(default_factory=list)
    session_start: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add(self, raw_entry: dict):
        """Add a raw interaction entry from the browser."""
        interaction = CapturedInteraction(
            type=raw_entry.get("type", "unknown"),
            url=raw_entry.get("url", ""),
            timestamp=raw_entry.get("timestamp", 0),
            to=raw_entry.get("to"),
            value=raw_entry.get("value"),
            data=raw_entry.get("data"),
            method_selector=raw_entry.get("data", "")[:10] if raw_entry.get("data") else None,
            typed_data=raw_entry.get("typedData"),
            is_permit=raw_entry.get("isPermit", False),
            message=raw_entry.get("message"),
            raw=raw_entry,
        )
        self.interactions.append(interaction)

    def get_contract_addresses(self) -> list[str]:
        """Extract unique contract addresses from captured transactions."""
        addresses = set()
        for i in self.interactions:
            if i.to:
                addresses.add(i.to.lower())
        return sorted(addresses)

    def get_address_details(self) -> list[dict]:
        """Extract unique contract addresses with source context.

        Each entry includes the page URLs where the address was found,
        the discovery method (page-text, js-runtime, explorer link, etc.),
        and inferred chain from block explorer links.
        """
        EXPLORER_CHAINS = {
            "etherscan": "ethereum",
            "arbiscan": "arbitrum",
            "basescan": "base",
            "polygonscan": "polygon",
            "bscscan": "bsc",
            "scrollscan": "scroll",
            "optimistic.etherscan": "optimism",
            "snowtrace": "avalanche",
        }

        by_addr: dict[str, dict] = {}
        for i in self.interactions:
            if not i.to:
                continue
            addr = i.to.lower()
            if addr not in by_addr:
                by_addr[addr] = {"source_urls": set(), "sources": set(), "chains": set()}
            entry = by_addr[addr]
            if i.url:
                entry["source_urls"].add(i.url)
            source = i.data or ""
            if source:
                entry["sources"].add(source)
            # Infer chain from any URL-like field — i.url is always a URL, and
            # for scraped page addresses i.data sometimes holds the full explorer
            # href. Calldata (hex) can't contain explorer domain names anyway.
            for candidate in (i.url, source):
                if not candidate or not candidate.startswith(("http://", "https://")):
                    continue
                for explorer, chain in EXPLORER_CHAINS.items():
                    if explorer in candidate:
                        entry["chains"].add(chain)

        return [
            {
                "address": addr,
                "source_urls": sorted(info["source_urls"]),
                "sources": sorted(info["sources"]),
                "chain": sorted(info["chains"])[0] if info["chains"] else None,
            }
            for addr, info in sorted(by_addr.items())
        ]
