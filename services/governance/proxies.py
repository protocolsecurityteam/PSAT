"""Display-name resolution and proxy/impl entry merging."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from schemas.api_responses import AnalysisListEntry

GENERIC_PROXY_NAMES = {
    "uupsproxy",
    "erc1967proxy",
    "transparentupgradeableproxy",
    "proxy",
    "beaconproxy",
    "ossifiableproxy",
    "withdrawalsmanagerproxy",
    "upgradeablebeacon",
}


def _display_name(entry: "Mapping[str, Any]") -> str:
    chain = str(entry.get("chain") or "").strip()

    def with_chain(name: str) -> str:
        if not name:
            return name
        if not chain:
            return name
        suffix = f" ({chain})"
        return name if name.endswith(suffix) else f"{name}{suffix}"

    explicit = str(entry.get("display_name") or "").strip()
    if explicit:
        return with_chain(explicit)
    contract_name = str(entry.get("contract_name") or "").strip()
    if contract_name and contract_name.lower() not in GENERIC_PROXY_NAMES:
        return with_chain(contract_name)
    return with_chain(str(entry.get("run_name") or contract_name or "").strip())


def _merge_proxy_impl_entries(entries: "list[AnalysisListEntry]") -> "list[AnalysisListEntry]":
    # Key the proxy↔impl fold by (coalesced-chain, address) so a CREATE2 twin's
    # impl folds only into the proxy on its own chain (inv. 12) — a bare address
    # match would attach one chain's impl to the other chain's proxy.
    from services.aggregations.company_overview import _coalesce_chain

    impl_by_proxy: dict[tuple[str, str], AnalysisListEntry] = {}
    merged_proxies: set[tuple[str, str]] = set()

    for entry in entries:
        proxy_address = str(entry.get("proxy_address") or "").lower()
        if proxy_address:
            impl_by_proxy[(_coalesce_chain(entry.get("chain")), proxy_address)] = entry

    merged: list[AnalysisListEntry] = []
    for entry in entries:
        proxy_address = str(entry.get("proxy_address") or "").lower()
        if proxy_address:
            continue

        address = str(entry.get("address") or "").lower()
        chain_key = _coalesce_chain(entry.get("chain"))
        impl = impl_by_proxy.get((chain_key, address))
        if entry.get("is_proxy") and entry.get("implementation_address") and impl:
            merged.append(
                {
                    **impl,
                    "company": entry.get("company") or impl.get("company"),
                    "chain": entry.get("chain") or impl.get("chain"),
                    "rank_score": entry.get("rank_score")
                    if entry.get("rank_score") is not None
                    else impl.get("rank_score"),
                    "proxy_address": entry.get("address"),
                    "proxy_address_display": entry.get("address"),
                    "proxy_type_display": entry.get("proxy_type"),
                    "display_name": impl.get("contract_name") or _display_name(entry),
                }
            )
            merged_proxies.add((chain_key, address))
            continue

        merged.append({**entry, "display_name": _display_name(entry)})

    for entry in entries:
        proxy_address = str(entry.get("proxy_address") or "").lower()
        if proxy_address and (_coalesce_chain(entry.get("chain")), proxy_address) not in merged_proxies:
            merged.append({**entry, "display_name": _display_name(entry)})

    return merged
