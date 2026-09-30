"""Build a visualization graph from ``services.discovery.unified_dependencies.build_unified_dependencies`` output."""

from __future__ import annotations

from typing import Any


def _shorten(address: str) -> str:
    if len(address) >= 12:
        return f"{address[:6]}...{address[-4:]}"
    return address


def _derive_discovered(unified: dict) -> list[str]:
    result: list[str] = []
    for addr, info in unified.get("dependencies", {}).items():
        if "classification" in info.get("source", []):
            result.append(addr)
        impl = info.get("implementation")
        if isinstance(impl, dict) and "classification" in impl.get("source", []):
            result.append(impl["address"])
    return sorted(result)


def _build_nodes(
    target: str,
    target_label: str,
    unified: dict,
    proxy_address: str | None = None,
    proxy_name: str | None = None,
    proxy_type: str | None = None,
) -> list[dict]:
    nodes: list[dict] = []

    # Context node when the target is an implementation.
    if proxy_address:
        nodes.append(
            {
                "id": f"addr:{proxy_address}",
                "address": proxy_address,
                "label": proxy_name or _shorten(proxy_address),
                "type": "proxy",
                "proxy_type": proxy_type,
                "is_target": False,
                "is_proxy_context": True,
                "source": [],
            }
        )

    target_cls = unified.get("target_classification", {})
    default_type = "implementation" if proxy_address else "target"
    nodes.append(
        {
            "id": f"addr:{target}",
            "address": target,
            "label": target_label or _shorten(target),
            "type": target_cls.get("type", default_type),
            "proxy_type": target_cls.get("proxy_type"),
            "is_target": True,
            "source": [],
        }
    )

    deps = unified.get("dependencies", {})
    for addr in sorted(deps):
        info = deps[addr]
        impl = info.get("implementation")
        impl_addr = impl["address"] if isinstance(impl, dict) else impl

        nodes.append(
            {
                "id": f"addr:{addr}",
                "address": addr,
                "label": info.get("contract_name") or _shorten(addr),
                "type": info.get("type", "regular"),
                "proxy_type": info.get("proxy_type"),
                "implementation": impl_addr,
                "beacon": info.get("beacon"),
                "admin": info.get("admin"),
                "is_target": False,
                "source": info.get("source", []),
            }
        )

        if isinstance(impl, dict):
            nodes.append(
                {
                    "id": f"addr:{impl['address']}",
                    "address": impl["address"],
                    "label": impl.get("contract_name") or _shorten(impl["address"]),
                    "type": impl.get("type", "implementation"),
                    "proxy_type": None,
                    "implementation": None,
                    "beacon": None,
                    "admin": None,
                    "is_target": False,
                    "source": impl.get("source", []),
                }
            )

    return nodes


def _build_edges(
    target: str,
    unified: dict,
    node_ids: set[str],
    proxy_address: str | None = None,
) -> list[dict]:
    edges: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()

    def _add(
        src: str,
        dst: str,
        op: str,
        provenance: list | None = None,
        selector: str | None = None,
        function_name: str | None = None,
    ) -> None:
        key = (src, dst, op, selector or "")
        if key in seen:
            return
        if src not in node_ids or dst not in node_ids:
            return
        seen.add(key)
        entry: dict = {
            "from": src,
            "to": dst,
            "op": op,
            "provenance": provenance or [],
        }
        if selector and selector != "0x":
            entry["selector"] = selector
        if function_name:
            entry["function_name"] = function_name
        edges.append(entry)

    # Supports keyed dict (new) and flat list (old) formats.
    dep_graph = unified.get("dependency_graph", {})
    if isinstance(dep_graph, dict):
        for graph_key, edge_list in dep_graph.items():
            parts = graph_key.split("|")
            from_addr, to_addr = parts[0], parts[1]
            for edge in edge_list:
                _add(
                    f"addr:{from_addr}",
                    f"addr:{to_addr}",
                    edge["op"],
                    edge.get("provenance", []),
                    selector=edge.get("selector"),
                    function_name=edge.get("function_name"),
                )
    elif isinstance(dep_graph, list):
        for edge in dep_graph:
            _add(
                f"addr:{edge['from']}",
                f"addr:{edge['to']}",
                edge["op"],
                edge.get("provenance", []),
                selector=edge.get("selector"),
                function_name=edge.get("function_name"),
            )

    # Implicit target edges for static-bytecode deps; classification-only deps are reached via their proxy's edge.
    deps_with_edges: set[str] = set()
    if isinstance(dep_graph, dict):
        for graph_key in dep_graph:
            deps_with_edges.add(graph_key.split("|")[1])
    elif isinstance(dep_graph, list):
        for edge in dep_graph:
            deps_with_edges.add(edge["to"])
    deps = unified.get("dependencies", {})
    for addr in sorted(deps):
        if addr in deps_with_edges:
            continue
        source = deps[addr].get("source", [])
        if source == ["classification"]:
            continue
        static_root = proxy_address if proxy_address else target
        _add(f"addr:{static_root}", f"addr:{addr}", "STATIC_REF")

    for addr, info in deps.items():
        impl = info.get("implementation")
        if isinstance(impl, dict):
            _add(f"addr:{addr}", f"addr:{impl['address']}", "DELEGATES_TO")
        elif isinstance(impl, str) and impl:
            _add(f"addr:{addr}", f"addr:{impl}", "DELEGATES_TO")
        if info.get("beacon"):
            _add(f"addr:{addr}", f"addr:{info['beacon']}", "BEACON")

    if proxy_address:
        _add(f"addr:{proxy_address}", f"addr:{target}", "DELEGATES_TO")

    return edges


def build_dependency_visualization(
    unified: dict,
    *,
    target_label: str = "",
    proxy_address: str | None = None,
    proxy_name: str | None = None,
    proxy_type: str | None = None,
) -> dict:
    """Build a visualization graph (``nodes``, ``edges``, ``metadata``) from a unified dependency dict.

    *proxy_address* adds a proxy node and DELEGATES_TO edge. With no dependencies, returns an empty graph with
    ``metadata.error``.
    """
    if not unified or not unified.get("dependencies"):
        return {"nodes": [], "edges": [], "metadata": {"error": "no dependency data found"}}

    target = unified.get("address", "")

    nodes = _build_nodes(target, target_label, unified, proxy_address, proxy_name, proxy_type)
    node_ids = {n["id"] for n in nodes}
    edges = _build_edges(target, unified, node_ids, proxy_address)

    metadata: dict[str, Any] = {
        "target": target,
        "proxy_address": proxy_address,
        "network": unified.get("network"),
        "transactions_analyzed": unified.get("transactions_analyzed", []),
        "trace_methods": unified.get("trace_methods", []),
        "trace_errors": unified.get("trace_errors", []),
        "discovered_addresses": _derive_discovered(unified),
    }

    return {"nodes": nodes, "edges": edges, "metadata": metadata}
