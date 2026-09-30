"""Dynamic-dependency merge helpers.

The artifact read stays in ``static_worker`` because tests patch ``get_artifact`` there.
"""

from __future__ import annotations


def _merge_dynamic_deps(prev: dict, new: dict) -> dict:
    """Append-only merge of previous and new dynamic dependency results."""
    prev_deps = set(prev.get("dependencies", []))
    new_deps = set(new.get("dependencies", []))
    merged_deps = sorted(prev_deps | new_deps)

    merged_provenance: dict[str, list[dict]] = {}
    for prov_dict in [prev.get("provenance", {}), new.get("provenance", {})]:
        for addr, records in prov_dict.items():
            existing = merged_provenance.setdefault(addr, [])
            for record in records:
                if record not in existing:
                    existing.append(record)

    seen_edges: set[tuple[str, str, str, str]] = set()
    merged_graph: list[dict] = []
    for graph_list in [prev.get("dependency_graph", []), new.get("dependency_graph", [])]:
        for edge in graph_list:
            key = (edge["from"], edge["to"], edge["op"], edge.get("selector", ""))
            if key in seen_edges:
                for existing_edge in merged_graph:
                    existing_key = (
                        existing_edge["from"],
                        existing_edge["to"],
                        existing_edge["op"],
                        existing_edge.get("selector", ""),
                    )
                    if existing_key == key:
                        for prov in edge.get("provenance", []):
                            if prov not in existing_edge.get("provenance", []):
                                existing_edge.setdefault("provenance", []).append(prov)
                        break
                continue
            seen_edges.add(key)
            merged_graph.append(dict(edge))

    seen_tx_hashes: set[str] = set()
    merged_txs: list[dict] = []
    for tx_list in [prev.get("transactions_analyzed", []), new.get("transactions_analyzed", [])]:
        for tx in tx_list:
            tx_hash = tx.get("tx_hash", "")
            if tx_hash not in seen_tx_hashes:
                seen_tx_hashes.add(tx_hash)
                merged_txs.append(tx)

    merged_methods = sorted(set(prev.get("trace_methods", [])) | set(new.get("trace_methods", [])))

    seen_error_hashes: set[str] = set()
    merged_errors: list[dict] = []
    for err_list in [prev.get("trace_errors", []), new.get("trace_errors", [])]:
        for err in err_list:
            err_hash = err.get("tx_hash", "")
            if err_hash not in seen_error_hashes:
                seen_error_hashes.add(err_hash)
                merged_errors.append(err)

    return {
        "address": new.get("address") or prev.get("address"),
        "transactions_analyzed": merged_txs,
        "trace_methods": merged_methods,
        "dependencies": merged_deps,
        "provenance": merged_provenance,
        "dependency_graph": merged_graph,
        "trace_errors": merged_errors,
    }


def _start_block_from_prev_dyn(prev_dyn: dict | None) -> int | None:
    if not prev_dyn:
        return None
    prev_txs = prev_dyn.get("transactions_analyzed", [])
    last_block = max((tx.get("block_number") or 0 for tx in prev_txs), default=0)
    return last_block + 1 if last_block > 0 else None
