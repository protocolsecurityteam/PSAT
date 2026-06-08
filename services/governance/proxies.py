"""Display-name resolution and proxy/impl entry merging."""

from __future__ import annotations

from schemas.governance_schemas import AnalysisListEntry

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


def _display_name(entry: AnalysisListEntry) -> str:
    explicit = str(entry.get("display_name") or "").strip()
    if explicit:
        return explicit
    contract_name = str(entry.get("contract_name") or "").strip()
    if contract_name and contract_name.lower() not in GENERIC_PROXY_NAMES:
        return contract_name
    return str(entry.get("run_name") or contract_name or "").strip()


def _require_same_chain_id(proxy_entry: AnalysisListEntry, impl_entry: AnalysisListEntry) -> int:
    proxy_chain_id = proxy_entry.get("chain_id")
    impl_chain_id = impl_entry.get("chain_id")
    if proxy_chain_id is None or impl_chain_id is None:
        raise RuntimeError(
            "proxy/implementation analysis merge requires chain_id on both entries "
            f"proxy={proxy_entry.get('address')} impl={impl_entry.get('address')}"
        )
    try:
        proxy_chain_id_int = int(proxy_chain_id)
        impl_chain_id_int = int(impl_chain_id)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "proxy/implementation analysis merge requires numeric chain_id on both entries "
            f"proxy={proxy_entry.get('address')} impl={impl_entry.get('address')}"
        ) from exc
    if proxy_chain_id_int != impl_chain_id_int:
        raise RuntimeError(
            "proxy/implementation analysis merge chain_id mismatch "
            f"proxy={proxy_entry.get('address')} chain_id={proxy_chain_id_int} "
            f"impl={impl_entry.get('address')} chain_id={impl_chain_id_int}"
        )
    return proxy_chain_id_int


def _merge_proxy_impl_entries(entries: list[AnalysisListEntry]) -> list[AnalysisListEntry]:
    impl_by_proxy: dict[str, AnalysisListEntry] = {}
    merged_proxies: set[str] = set()

    for entry in entries:
        proxy_address = str(entry.get("proxy_address") or "").lower()
        if proxy_address:
            impl_by_proxy[proxy_address] = entry

    merged: list[AnalysisListEntry] = []
    for entry in entries:
        proxy_address = str(entry.get("proxy_address") or "").lower()
        if proxy_address:
            continue

        address = str(entry.get("address") or "").lower()
        impl = impl_by_proxy.get(address)
        if entry.get("is_proxy") and entry.get("implementation_address") and impl:
            chain_id = _require_same_chain_id(entry, impl)
            merged.append(
                {
                    **impl,
                    "company": entry.get("company") or impl.get("company"),
                    "chain_id": chain_id,
                    "rank_score": entry.get("rank_score")
                    if entry.get("rank_score") is not None
                    else impl.get("rank_score"),
                    "proxy_address": entry.get("address"),
                    "proxy_address_display": entry.get("address"),
                    "proxy_type_display": entry.get("proxy_type"),
                    "display_name": impl.get("contract_name") or _display_name(entry),
                }
            )
            merged_proxies.add(address)
            continue

        merged.append({**entry, "display_name": _display_name(entry)})

    for entry in entries:
        proxy_address = str(entry.get("proxy_address") or "").lower()
        if proxy_address and proxy_address not in merged_proxies:
            merged.append({**entry, "display_name": _display_name(entry)})

    return merged
