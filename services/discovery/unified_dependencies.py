"""Helpers for merging and enriching dependency-discovery outputs."""

from __future__ import annotations

import logging

from .static_dependencies import normalize_address

logger = logging.getLogger(__name__)

_CLS_KEYS = ("proxy_type", "implementation", "beacon", "admin", "proxies", "facets", "needs_polling")


def build_unified_dependencies(
    address: str,
    static_deps: dict | None,
    dynamic_deps: dict | None,
    classifications: dict | None,
    target_classification: dict | None = None,
) -> dict:
    """Merge static deps, dynamic deps, and classifications into one output.

    *target_classification* carries an explicit result from an earlier
    ``classify_single`` call.  That preserves the target's proxy type when
    dependency classification is not part of the current pass.
    """
    target = normalize_address(address)

    dep_sources: dict[str, set[str]] = {}
    if static_deps:
        for dep in static_deps.get("dependencies", []):
            dep_sources.setdefault(normalize_address(dep), set()).add("static")
    if dynamic_deps:
        for dep in dynamic_deps.get("dependencies", []):
            dep_sources.setdefault(normalize_address(dep), set()).add("dynamic")

    cls_map = (classifications or {}).get("classifications", {})

    def _dep_entry(addr: str, sources: list[str]) -> dict:
        entry: dict = {"type": "regular", "source": sources}
        if addr in cls_map:
            classification = cls_map[addr]
            entry["type"] = classification.get("type", "regular")
            for key in _CLS_KEYS:
                if key in classification:
                    entry[key] = classification[key]
        return entry

    deps = {addr: _dep_entry(addr, sorted(sources)) for addr, sources in sorted(dep_sources.items())}

    discovered = (classifications or {}).get("discovered_addresses", [])
    for addr in discovered:
        addr = normalize_address(addr)
        if addr not in deps:
            deps[addr] = _dep_entry(addr, ["classification"])

    impl_to_remove: set[str] = set()
    for addr, info in deps.items():
        if info.get("type") != "proxy":
            continue
        impl_addr = info.get("implementation")
        if not isinstance(impl_addr, str) or impl_addr not in deps:
            continue
        impl_entry = deps[impl_addr].copy()
        impl_entry.pop("proxies", None)
        impl_entry["address"] = impl_addr
        info["implementation"] = impl_entry
        impl_to_remove.add(impl_addr)
    for addr in impl_to_remove:
        del deps[addr]

    output: dict = {"address": target, "dependencies": deps}

    effective_target_cls = cls_map.get(target) or target_classification
    if effective_target_cls and effective_target_cls.get("type", "regular") != "regular":
        info = {"type": effective_target_cls["type"]}
        for key in ("proxy_type", "implementation", "beacon", "admin"):
            if key in effective_target_cls:
                info[key] = effective_target_cls[key]
        output["target_classification"] = info

    if dynamic_deps:
        raw_graph = dynamic_deps.get("dependency_graph", [])
        keyed_graph: dict[str, list[dict]] = {}
        for edge in raw_graph:
            if not isinstance(edge, dict):
                continue
            from_addr = edge.get("from")
            to_addr = edge.get("to")
            if not isinstance(from_addr, str) or not isinstance(to_addr, str):
                continue
            key = f"{from_addr}|{to_addr}"
            entry: dict = {"op": edge["op"], "provenance": edge.get("provenance", [])}
            if edge.get("selector"):
                entry["selector"] = edge["selector"]
            if edge.get("function_name"):
                entry["function_name"] = edge["function_name"]
            keyed_graph.setdefault(key, []).append(entry)
        output["dependency_graph"] = keyed_graph
        output["transactions_analyzed"] = dynamic_deps.get("transactions_analyzed", [])
        output["trace_methods"] = dynamic_deps.get("trace_methods", [])
        output["trace_errors"] = dynamic_deps.get("trace_errors", [])

    if static_deps and static_deps.get("network"):
        output["network"] = static_deps["network"]

    return output


def enrich_dependency_metadata(
    unified: dict,
    *,
    chain_id: int,
    info_cache: dict[str, tuple[str | None, dict[str, str]]] | None = None,
) -> dict:
    """Apply already-known contract names and selectors to a unified dependency output.

    ``info_cache`` is intentionally read-only here. Earlier versions fetched
    missing dependency metadata from an explorer; eRPC-only mode leaves unknown
    names/selectors absent instead of making a non-eRPC enrichment call.
    """
    del chain_id
    deps = unified.get("dependencies", {})
    if not isinstance(deps, dict) or not deps:
        return unified

    keyed_graph = unified.get("dependency_graph", {})

    info_cache = info_cache or {}

    for addr, info in deps.items():
        if not isinstance(info, dict):
            continue
        contract_name = info_cache.get(addr, (None, {}))[0]
        if contract_name:
            info["contract_name"] = contract_name
        implementation = info.get("implementation")
        if isinstance(implementation, dict):
            impl_name = info_cache.get(implementation["address"], (None, {}))[0]
            if impl_name:
                implementation["contract_name"] = impl_name

    if isinstance(keyed_graph, dict):
        for key, edges in keyed_graph.items():
            parts = key.split("|", 1)
            if len(parts) != 2:
                continue
            target_addr = parts[1]
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                selector = edge.get("selector")
                if not selector or selector == "0x":
                    continue
                function_name = info_cache.get(target_addr, (None, {}))[1].get(selector)
                if not function_name:
                    implementation = deps.get(target_addr, {}).get("implementation")
                    impl_addr = implementation["address"] if isinstance(implementation, dict) else implementation
                    if impl_addr:
                        function_name = info_cache.get(impl_addr, (None, {}))[1].get(selector)
                if function_name:
                    edge["function_name"] = function_name

    return unified
