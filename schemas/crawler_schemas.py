"""Schemas owned by crawler services."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class CapturedInteraction:
    type: str
    url: str
    timestamp: int
    to: str | None = None
    value: str | None = None
    data: str | None = None
    method_selector: str | None = None
    typed_data: dict | None = None
    is_permit: bool = False
    message: str | None = None
    raw: dict | None = None


@dataclass
class InteractionLog:
    interactions: list[CapturedInteraction] = field(default_factory=list)
    session_start: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add(self, raw_entry: dict) -> None:
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
        addresses = set()
        for item in self.interactions:
            if item.to:
                addresses.add(item.to.lower())
        return sorted(addresses)

    def get_address_details(self) -> list[dict]:
        explorer_chains = {
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
        for item in self.interactions:
            if not item.to:
                continue
            addr = item.to.lower()
            if addr not in by_addr:
                by_addr[addr] = {"source_urls": set(), "sources": set(), "chains": set()}
            entry = by_addr[addr]
            if item.url:
                entry["source_urls"].add(item.url)
            source = item.data or ""
            if source:
                entry["sources"].add(source)
            for candidate in (item.url, source):
                if not candidate or not candidate.startswith(("http://", "https://")):
                    continue
                for explorer, chain in explorer_chains.items():
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

    def get_permits(self) -> list[CapturedInteraction]:
        return [item for item in self.interactions if item.is_permit]

    def get_transactions(self) -> list[CapturedInteraction]:
        return [item for item in self.interactions if item.type == "sendTransaction"]


__all__ = ["CapturedInteraction", "InteractionLog"]
