"""Build frontend-friendly principal labels from effective permissions and resolved control graphs."""

from __future__ import annotations

import logging
import re
import threading
from collections import defaultdict
from typing import Any

from schemas.principal_labels import PrincipalLabels, PrincipalPermission, PrincipalProfile
from services.resolution.tracking import classify_resolved_address_with_status
from utils.concurrency import parallel_map
from utils.logging import record_stage_metric

logger = logging.getLogger(__name__)


def _safe_role_int(role: Any) -> int | None:
    """Coerce a role identifier to int, returning None for non-int shapes.

    Role-name strings and Condition-mapping shapes cannot be represented as
    numeric policy roles. Callers decide whether to skip-with-warning or
    surface ``role=None`` on a typed permission while preserving the
    original identifier in the controller bucket.
    """
    try:
        return int(role)
    except (TypeError, ValueError):
        return None


def _slug(value: str) -> str:
    lowered = value.lower()
    lowered = re.sub(r"[^a-z0-9]+", "_", lowered)
    return lowered.strip("_")


def _display_from_type(resolved_type: str) -> str:
    return {
        "safe": "Safe",
        "timelock": "Timelock",
        "proxy_admin": "Proxy admin",
        "eoa": "Externally owned account",
        "contract": "Contract",
        "zero": "Zero address",
        "unknown": "Unknown principal",
    }.get(resolved_type, "Unknown principal")


def _node_display_name(node: dict[str, Any] | None) -> str:
    if not isinstance(node, dict):
        return ""
    for candidate in (node.get("contract_name"), node.get("label")):
        name = str(candidate or "").strip()
        if not name:
            continue
        if _slug(name) in {"contract", "role_principal", "roleprincipal", "principal"}:
            continue
        return name
    return ""


def _collect_permissions(
    effective_permissions: dict[str, Any],
) -> tuple[dict[str, list[PrincipalPermission]], dict[str, str]]:
    by_address: dict[str, list[PrincipalPermission]] = defaultdict(list)
    contract_name = effective_permissions["contract_name"]
    contract_slug = _slug(contract_name)
    permission_labels: dict[str, set[str]] = defaultdict(set)

    for function in effective_permissions.get("functions", []):
        function_name = str(function.get("function", ""))
        effect_labels = [str(label) for label in function.get("effect_labels", [])]
        authority_public = bool(function.get("authority_public", False))
        effect_labels_set = set(effect_labels)
        direct_owner = function.get("direct_owner")
        if direct_owner:
            address = direct_owner["address"].lower()
            if not address.startswith("0x") or len(address) != 42:
                continue
            permission: PrincipalPermission = {
                "function": function_name,
                "effect_labels": effect_labels,
                "authority_public": authority_public,
                "role": None,
                "controller": "owner",
            }
            by_address[address].append(permission)
            permission_labels[address].update({f"{contract_slug}_direct_owner", f"{contract_slug}_controlled"})

        for role_grant in function.get("authority_roles", []):
            raw_role = role_grant.get("role")
            role = _safe_role_int(raw_role)
            if role is None:
                logger.debug(
                    "principal_enrichment: skipping int-coercion for non-int role %r on %s",
                    raw_role,
                    function_name,
                )
            controller_role_label = str(role) if role is not None else str(raw_role)
            for principal in role_grant.get("principals", []):
                address = principal["address"].lower()
                if not address.startswith("0x") or len(address) != 42:
                    continue
                permission: PrincipalPermission = {
                    "function": function_name,
                    "effect_labels": effect_labels,
                    "authority_public": authority_public,
                    "role": role,
                    "controller": f"role_{controller_role_label}",
                }
                by_address[address].append(permission)
                permission_labels[address].update(
                    {
                        f"{contract_slug}_controlled",
                        f"{contract_slug}_role_{controller_role_label}_holder",
                    }
                )
                if "arbitrary_external_call" in effect_labels_set:
                    permission_labels[address].add(f"{contract_slug}_manager")
                if effect_labels_set.intersection({"asset_pull", "asset_send", "mint", "burn"}):
                    permission_labels[address].add(f"{contract_slug}_operator")
                if effect_labels_set.intersection(
                    {
                        "authority_update",
                        "ownership_transfer",
                        "hook_update",
                        "implementation_update",
                        "role_management",
                    }
                ):
                    permission_labels[address].add(f"{contract_slug}_admin")

        for controller in function.get("controllers", []):
            controller_label = str(controller.get("label") or controller.get("source") or "controller")
            controller_slug = _slug(controller_label)
            for principal in controller.get("principals", []):
                address = principal["address"].lower()
                if not address.startswith("0x") or len(address) != 42:
                    continue
                permission = {
                    "function": function_name,
                    "effect_labels": effect_labels,
                    "authority_public": authority_public,
                    "role": None,
                    "controller": controller_label,
                }
                by_address[address].append(permission)
                permission_labels[address].update(
                    {
                        f"{contract_slug}_controlled",
                        f"{contract_slug}_controller_{controller_slug}",
                    }
                )
                if "arbitrary_external_call" in effect_labels_set:
                    permission_labels[address].add(f"{contract_slug}_manager")
                if effect_labels_set.intersection(
                    {
                        "authority_update",
                        "ownership_transfer",
                        "hook_update",
                        "implementation_update",
                        "role_management",
                        "timelock_operation",
                    }
                ):
                    permission_labels[address].add(f"{contract_slug}_admin")

    return by_address, {address: ",".join(sorted(labels)) for address, labels in permission_labels.items()}


def _incoming_edges(graph: dict) -> dict[str, list[dict]]:
    incoming: dict[str, list[dict]] = defaultdict(list)
    for edge in graph.get("edges", []):
        incoming[edge["to_id"]].append(edge)
    return incoming


def _outgoing_edges(graph: dict) -> dict[str, list[dict]]:
    outgoing: dict[str, list[dict]] = defaultdict(list)
    for edge in graph.get("edges", []):
        outgoing[edge["from_id"]].append(edge)
    return outgoing


def _node_by_id(graph: dict) -> dict[str, dict]:
    return {node["id"]: node for node in graph.get("nodes", [])}


def _graph_labels_for_node(
    node: dict, incoming_edges: list[dict], node_index: dict[str, dict]
) -> tuple[set[str], list[str]]:
    labels = {node.get("resolved_type", "unknown")}
    context: list[str] = []
    if node.get("resolved_type") == "safe":
        labels.add("safe_multisig")
    elif node.get("resolved_type") == "eoa":
        labels.add("likely_eoa")
    elif node.get("resolved_type") == "contract":
        labels.add("contract_controller")
    elif node.get("resolved_type") == "zero":
        labels.add("zero_address")

    for edge in incoming_edges:
        source_node = node_index.get(edge["from_id"], {})
        source_contract_name = source_node.get("contract_name") or source_node.get("label") or "contract"
        source_slug = _slug(str(source_contract_name))
        relation = edge["relation"]
        edge_label = _slug(edge.get("label") or relation)
        context.append(f"{source_contract_name}:{edge.get('label') or relation}")
        if relation == "controller_value":
            labels.add("controller_value")
            labels.add(f"{source_slug}_{edge_label}")
            labels.add(f"controller_{edge_label}")
            if edge_label == "authority":
                labels.add("authority_controller")
            if edge_label == "owner":
                labels.add("owner_controller")
        elif relation == "safe_owner":
            labels.add("safe_signer")
        elif relation == "timelock_owner":
            labels.add("timelock_owner")
        elif relation == "proxy_admin_owner":
            labels.add("proxy_admin_owner")
        elif relation == "role_principal":
            labels.add("role_principal")

    return labels, sorted(set(context))


def _display_name(
    address: str,
    resolved_type: str,
    labels: set[str],
    graph_context: list[str],
    permissions: list[PrincipalPermission],
    contract_name: str,
    node_name: str = "",
) -> tuple[str, str]:
    contract_slug = _slug(contract_name)
    permission_effects = {effect for permission in permissions for effect in permission.get("effect_labels", [])}
    permission_controllers = sorted(
        {
            str(permission.get("controller", "")).strip()
            for permission in permissions
            if str(permission.get("controller", "")).strip()
        }
    )

    if resolved_type == "zero":
        return "Zero address", "high"
    if f"{contract_slug}_admin" in labels:
        if resolved_type == "safe":
            return f"{contract_name} admin Safe", "high"
        if resolved_type == "contract":
            return f"{contract_name} admin contract", "high"
        return f"{contract_name} admin", "high"
    if f"{contract_slug}_manager" in labels:
        if resolved_type == "contract":
            return f"{contract_name} manager contract", "high"
        return f"{contract_name} manager", "high"
    if f"{contract_slug}_operator" in labels:
        function_names = sorted({permission["function"].split("(", 1)[0] for permission in permissions})
        if len(function_names) <= 2 and function_names:
            joined = "/".join(function_names)
            if resolved_type == "contract":
                return f"{contract_name} {joined} contract", "medium"
            return f"{contract_name} {joined} operator", "medium"
        if resolved_type == "contract":
            return f"{contract_name} operator contract", "medium"
        return f"{contract_name} operator", "medium"
    if "authority_controller" in labels:
        return f"{contract_name} authority", "high"
    if "owner_controller" in labels and resolved_type == "safe":
        owner_of = graph_context[0].split(":", 1)[0] if graph_context else contract_name
        return f"{owner_of} owner Safe", "high"
    if permission_controllers:
        controller_name = permission_controllers[0]
        suffix = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", controller_name).replace("_", " ")
        if resolved_type == "contract" and node_name:
            return f"{node_name} ({contract_name} {suffix})", "medium"
        if resolved_type == "contract":
            return f"{contract_name} {suffix} contract", "medium"
        return f"{contract_name} {suffix}", "medium"
    if "safe_signer" in labels:
        return "Safe signer", "high"
    if permission_effects:
        return f"{contract_name} controlled principal", "medium"
    if resolved_type == "contract" and node_name:
        return node_name, "medium"
    if resolved_type == "contract" and graph_context:
        source_name, _, relation = graph_context[-1].partition(":")
        source_name = source_name.strip()
        relation = relation.strip()
        if source_name and relation and _slug(relation) not in {"role_principal", "controller_value"}:
            return f"{source_name} {relation}", "medium"
        if source_name:
            return f"{source_name} contract", "medium"
    return _display_from_type(resolved_type), "high" if resolved_type != "unknown" else "low"


def build_principal_labels(
    effective_permissions: dict,
    *,
    resolved_control_graph: dict | None = None,
    rpc_url: str | None = None,
    classify_cache: dict[str, tuple[str, dict[str, object]]] | None = None,
) -> PrincipalLabels:
    """Construct principal records for every authority address.

    ``classify_cache`` is mutated in place. When supplied, classification
    results from prior pipeline stages (resolution, policy graph refresh)
    are reused and any new classifications discovered here are added to
    the same dict — so a caller threading the same cache through the whole
    job sees fan-out of 6-10 RPCs per address collapse to one lookup.
    """
    nodes_by_id = _node_by_id(resolved_control_graph or {})
    nodes_by_address = {node["address"].lower(): node for node in (resolved_control_graph or {}).get("nodes", [])}
    incoming_by_id = _incoming_edges(resolved_control_graph or {})
    outgoing_by_id = _outgoing_edges(resolved_control_graph or {})
    permissions_by_address, permission_label_hints = _collect_permissions(effective_permissions)

    addresses = set(nodes_by_address)
    addresses.update(permissions_by_address)

    target_address = effective_permissions["contract_address"].lower()
    contract_name = effective_permissions["contract_name"]
    # The per-job classify_cache is shared read+write across worker threads.
    # Fast path is the cache hit (artifact pre-populated by resolution stage),
    # so the lock is uncontended in the common case.
    classify_cache_lock = threading.Lock()
    # Cache effectiveness is the dominant perf signal here (labeling re-runs
    # classify_resolved_address = 6-10 RPCs on a miss; the memory note records a
    # 14+ min etherfi LP-impl labeling pass). A hit-rate collapse run-over-run is
    # the regression to watch.
    classify_stats: dict[str, int] = {"hits": 0, "misses": 0}

    def _per_address(address: str) -> PrincipalProfile | None:
        if not address.startswith("0x") or len(address) != 42:
            return None
        if address == target_address:
            return None
        node = nodes_by_address.get(address)
        resolved_type = str(node.get("resolved_type", "unknown")) if node else "unknown"
        details = dict(node.get("details", {})) if node else {}

        if resolved_type == "unknown" and rpc_url:
            cache_key = address.lower()
            cached: tuple[str, dict[str, object]] | None = None
            if classify_cache is not None:
                with classify_cache_lock:
                    cached = classify_cache.get(cache_key)
            if cached is not None:
                with classify_cache_lock:
                    classify_stats["hits"] += 1
                resolved_type, cached_details = cached
                details = dict(cached_details)
            else:
                with classify_cache_lock:
                    classify_stats["misses"] += 1
                resolved_type, details, cacheable = classify_resolved_address_with_status(rpc_url, address)
                # Skip per-job cache write if any underlying probe errored —
                # otherwise a transient blip during labeling would persist
                # a wrong "contract" classification for the rest of the job.
                if classify_cache is not None and cacheable:
                    with classify_cache_lock:
                        classify_cache[cache_key] = (resolved_type, dict(details))

        if resolved_type == "contract" and node:
            if str(details.get("controller_label", "")).strip() == "permissionController":
                return None
            outgoing_edges = outgoing_by_id.get(node.get("id", ""), [])
            if any(edge.get("to_id") != node.get("id") for edge in outgoing_edges):
                return None

        labels, graph_context = _graph_labels_for_node(
            node or {"resolved_type": resolved_type}, incoming_by_id.get((node or {}).get("id", ""), []), nodes_by_id
        )
        hint_string = permission_label_hints.get(address)
        if hint_string:
            labels.update(hint_string.split(","))

        permissions = sorted(
            permissions_by_address.get(address, []),
            key=lambda item: (item["function"], -1 if item["role"] is None else item["role"]),
        )
        display_name, confidence = _display_name(
            address,
            resolved_type,
            labels,
            graph_context,
            permissions,
            contract_name,
            _node_display_name(node),
        )

        return {
            "address": address,
            "resolved_type": resolved_type,  # type: ignore[typeddict-item]
            "display_name": display_name,
            "labels": sorted(label for label in labels if label),
            "confidence": confidence,  # type: ignore[typeddict-item]
            "details": details,
            "graph_context": graph_context,
            "controller_context": sorted(
                {
                    str(permission.get("controller", "")).strip()
                    for permission in permissions
                    if str(permission.get("controller", "")).strip()
                }
            ),
            "permissions": permissions,
        }

    sorted_addresses = sorted(addresses)
    results = parallel_map(_per_address, sorted_addresses, max_workers=8)
    principals: list[PrincipalProfile] = []
    for _addr, outcome in results:
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome is not None:
            principals.append(outcome)

    logger.info(
        "principal labels: %d principals (classify %d hit / %d miss)",
        len(principals),
        classify_stats["hits"],
        classify_stats["misses"],
        extra={
            "phase": "principal_labels_detail",
            "principal_count": len(principals),
            "classify_hits": classify_stats["hits"],
            "classify_misses": classify_stats["misses"],
        },
    )
    record_stage_metric("label_classify_hits", classify_stats["hits"])
    record_stage_metric("label_classify_misses", classify_stats["misses"])

    return {
        "schema_version": "0.1",
        "contract_address": effective_permissions["contract_address"],
        "contract_name": contract_name,
        "principals": principals,
    }
