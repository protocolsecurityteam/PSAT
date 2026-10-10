"""Upgrade-history merge helpers. Persisting stays in ``static_worker`` because tests patch ``store_artifact`` there."""

from __future__ import annotations

from schemas.upgrade_history import UPGRADE_FETCH_ERROR


def _same_upgrade_log(a: dict, b: dict) -> bool:
    """Whether two events are copies of one log.

    Two indexed logs are the same log only at the same index. An event without ``log_index`` (rebuilt from
    ``upgrade_events`` rows) is a copy only of an event it can't be told apart from: same block, transaction, type
    and every recorded field.
    """
    if (a.get("block_number", 0), a.get("tx_hash", ""), a.get("event_type", "")) != (
        b.get("block_number", 0),
        b.get("tx_hash", ""),
        b.get("event_type", ""),
    ):
        return False
    a_index, b_index = a.get("log_index"), b.get("log_index")
    if isinstance(a_index, int) and isinstance(b_index, int):
        return a_index == b_index
    shared = (set(a) & set(b)) - {"log_index"}
    return all(a[key] == b[key] for key in shared)


def _merged_fetch_status(prev_proxy: dict, new_proxy: dict) -> dict:
    """The new fetch's status, which covers everything from the block the previous history resumed at.

    An errored fetch keeps the earliest block either side still has to re-read, so the next refresh repeats it.
    """
    if new_proxy.get("fetch_status") != UPGRADE_FETCH_ERROR:
        return {key: new_proxy[key] for key in ("fetch_status",) if key in new_proxy}
    resume = [
        proxy["refetch_from_block"]
        for proxy in (prev_proxy, new_proxy)
        if proxy.get("fetch_status") == UPGRADE_FETCH_ERROR and isinstance(proxy.get("refetch_from_block"), int)
    ]
    return {
        "fetch_status": UPGRADE_FETCH_ERROR,
        "fetch_errors": sorted(set(prev_proxy.get("fetch_errors") or []) | set(new_proxy.get("fetch_errors") or [])),
        "refetch_from_block": min(resume) if resume else 0,
    }


def _merge_upgrade_history(prev: dict, new: dict) -> dict:
    """Append-only merge; copies of one log are kept once (:func:`_same_upgrade_log`) and timelines rebuilt."""
    from services.discovery.upgrade_history import _build_implementation_timeline

    merged_proxies: dict[str, dict] = {}

    all_proxy_addrs = set(prev.get("proxies", {}).keys()) | set(new.get("proxies", {}).keys())

    total_upgrades = 0
    for addr in all_proxy_addrs:
        prev_proxy = prev.get("proxies", {}).get(addr)
        new_proxy = new.get("proxies", {}).get(addr)

        if prev_proxy and not new_proxy:
            merged_proxies[addr] = prev_proxy
            total_upgrades += prev_proxy.get("upgrade_count", 0)
            continue
        if new_proxy and not prev_proxy:
            merged_proxies[addr] = new_proxy
            total_upgrades += new_proxy.get("upgrade_count", 0)
            continue

        prev_events = prev_proxy.get("events", [])
        new_events = new_proxy.get("events", [])

        merged_events: list[dict] = []
        for event in prev_events + new_events:
            if not any(_same_upgrade_log(event, kept) for kept in merged_events):
                merged_events.append(event)

        merged_events.sort(key=lambda e: (e.get("block_number", 0), e.get("log_index", 0)))

        current_impl = new_proxy.get("current_implementation") or prev_proxy.get("current_implementation")
        implementations = _build_implementation_timeline(merged_events, current_impl)
        upgrade_events = [e for e in merged_events if e["event_type"] == "upgraded"]

        merged_proxies[addr] = {
            "proxy_address": addr,
            "proxy_type": new_proxy.get("proxy_type") or prev_proxy.get("proxy_type"),
            "current_implementation": current_impl,
            "upgrade_count": len(upgrade_events),
            "first_upgrade_block": upgrade_events[0]["block_number"] if upgrade_events else None,
            "last_upgrade_block": upgrade_events[-1]["block_number"] if upgrade_events else None,
            "implementations": implementations,
            "events": merged_events,
            **_merged_fetch_status(prev_proxy, new_proxy),
        }
        total_upgrades += len(upgrade_events)

    return {
        "schema_version": new.get("schema_version") or prev.get("schema_version", "0.1"),
        "target_address": new.get("target_address") or prev.get("target_address"),
        "proxies": merged_proxies,
        "total_upgrades": total_upgrades,
    }


def _from_block_for_upgrade_history(prev_uh: dict | None) -> int:
    """One past the last stored event, unless a proxy's last fetch errored: then the block that fetch started from."""
    if not prev_uh or not prev_uh.get("proxies"):
        return 0
    unread = [
        proxy.get("refetch_from_block")
        for proxy in prev_uh["proxies"].values()
        if proxy.get("fetch_status") == UPGRADE_FETCH_ERROR
    ]
    if unread:
        return min(block if isinstance(block, int) else 0 for block in unread)
    max_block = 0
    for proxy_info in prev_uh["proxies"].values():
        for event in proxy_info.get("events", []):
            block = event.get("block_number", 0)
            if block > max_block:
                max_block = block
    return max_block + 1 if max_block > 0 else 0


def _apply_known_names_to_uh(uh: dict, unified: dict) -> None:
    """The parallel ``build_upgrade_history`` ran with empty deps, so backfill names from the unified deps to avoid
    per-impl Etherscan lookups.
    """
    known_names: dict[str, str] = {}
    for addr, info in unified.get("dependencies", {}).items():
        if isinstance(info, dict) and info.get("contract_name"):
            known_names[addr] = info["contract_name"]
        impl = info.get("implementation") if isinstance(info, dict) else None
        if isinstance(impl, dict) and impl.get("contract_name"):
            known_names[impl["address"]] = impl["contract_name"]

    for proxy_info in uh.get("proxies", {}).values():
        for impl in proxy_info.get("implementations", []):
            if impl.get("contract_name"):
                continue
            name = known_names.get(impl["address"])
            if name:
                impl["contract_name"] = name
