"""Recursively resolve contract control chains into a reusable graph artifact."""

from __future__ import annotations

import copy
import logging
import os
import re
import tempfile
import threading
from collections import deque
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from schemas.common import Contract as ContractSchema
from schemas.common import make_contract
from schemas.control_tracking import ControlSnapshot
from services.discovery.fetch import fetch, scaffold
from services.policy.effective_permissions import build_effective_permissions
from services.resolution.types import (
    LoadedArtifacts,
    PendingContract,
    ResolvedControlGraph,
    ResolvedGraphEdge,
    ResolvedGraphNode,
    ResolvedNodeType,
    RolePrincipal,
    RolePrincipalAccumulator,
)
from services.static.contract_analysis_pipeline.analysis_types import ContractAnalysis
from services.static.contract_analysis_pipeline.core import collect_contract_analysis_with_artifacts
from services.static.contract_analysis_pipeline.pipeline_types import WriterEventSpec
from utils.logging import record_degraded, record_stage_metric, stage_metrics_var
from utils.rpc import require_configured_erpc_url, require_supported_chain_id

from .tracking import (
    build_control_snapshot,
    classify_resolved_address,
    classify_resolved_address_with_status,
)
from .tracking_plan import build_control_tracking_plan

logger = logging.getLogger(__name__)

ANALYZABLE_TYPES = {"contract", "timelock", "proxy_admin"}
DEFAULT_RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))

_MATERIALIZE_METRIC_LOCK = threading.Lock()


def _bump_materialize_metric(key: str) -> None:
    """Thread-safe +1 to a stage metric from the parallel materialize fan-out.
    ``record_stage_metric`` overwrites, but the build-vs-cache-hit fold needs an
    increment — and ``_materialize_with_cross_process_cache`` runs inside the
    ``parallel_map`` worker threads, which inherit ``stage_metrics_var`` via
    copy_context — so guard the read-modify-write. A cache-hit-rate collapse
    here is the canonical cause of a resolution stage silently multiplying its
    forge/Slither spend run-over-run. No-op outside a worker job context."""
    metrics = stage_metrics_var.get()
    if metrics is None:
        return
    with _MATERIALIZE_METRIC_LOCK:
        metrics[key] = metrics.get(key, 0) + 1


def _address_node_id(address: str) -> str:
    return f"address:{address.lower()}"


def _sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "_", value).strip("_")
    return cleaned or "contract"


def _workspace_name(contract_name: str, address: str, prefix: str) -> str:
    return f"{_sanitize_name(prefix)}_{_sanitize_name(contract_name)}_{address.lower()[2:10]}"


def _require_subject_chain_id(
    subject: Mapping[str, Any],
    *,
    expected_chain_id: int,
    address: str,
    context: str,
) -> int:
    raw_chain_id = subject.get("chain_id")
    if raw_chain_id is None:
        logger.error("%s subject missing chain_id address=%s subject=%r", context, address, subject)
        raise RuntimeError(f"{context} subject missing chain_id for {address}")
    subject_chain_id = require_supported_chain_id(
        chain_id=raw_chain_id,
        context=f"{context} subject {address}",
    )
    if subject_chain_id != expected_chain_id:
        logger.error(
            "%s subject chain_id mismatch address=%s subject_chain_id=%s expected_chain_id=%s",
            context,
            address,
            subject_chain_id,
            expected_chain_id,
        )
        raise RuntimeError(
            f"{context} subject chain_id mismatch for {address}: "
            f"subject_chain_id={subject_chain_id} expected_chain_id={expected_chain_id}"
        )
    return subject_chain_id


def _build_effective_permissions(
    analysis: dict[str, Any],
    snapshot: ControlSnapshot,
) -> dict[str, Any]:
    """Compute the effective-permissions payload for nested resolution."""
    try:
        return cast(
            dict,
            build_effective_permissions(
                analysis,
                target_snapshot=cast(dict, snapshot),
                principal_resolution={"status": "no_authority", "reason": "No non-zero authority found"},
            ),
        )
    except Exception as exc:
        address = str((analysis.get("subject") or {}).get("address", "")) or "<unknown>"
        record_degraded(
            phase="recursive_effective_permissions",
            exc=exc,
            context={"address": address},
        )
        logger.error(
            "Recursive resolve: effective_permissions build failed for %s: %s",
            address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        raise RuntimeError(f"recursive effective_permissions build failed for {address}") from exc


def _build_static_artifacts(
    effective_address: str,
    workspace_prefix: str,
    *,
    chain_id: int,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Run the expensive forge+Slither+predicate pipeline for *effective_address*.

    Returns ``(contract_name, analysis, tracking_plan, predicate_trees)``.
    ``effects`` is also produced by the predicate pipeline but is not
    plumbed back here: the recursive resolver doesn't consume it, and
    the policy stage reads the per-job ``effects`` artifact written by
    the static worker, so the materialization cache has no consumer for it.

    Pulled out of ``_materialize_contract_artifacts`` so the cross-process
    cache can call this exact closure when it needs to populate the
    persistent row. The tempdir is cleaned up at function exit.
    """
    result = fetch(effective_address, chain_id=chain_id)
    contract_name = str(result.get("ContractName", "Contract"))
    project_name = _workspace_name(contract_name, effective_address, workspace_prefix)

    with tempfile.TemporaryDirectory(prefix=f"psat_{workspace_prefix}_") as tmp:
        project_dir = Path(tmp) / project_name
        scaffold(effective_address, result, project_dir, chain_id=chain_id)
        analysis, predicate_trees, _effects = collect_contract_analysis_with_artifacts(project_dir)

    plan = cast(dict, build_control_tracking_plan(cast(ContractAnalysis, analysis)))
    return contract_name, cast(dict[str, Any], analysis), plan, predicate_trees


def _materialize_with_cross_process_cache(
    *,
    effective_address: str,
    bytecode_keccak: str | None,
    workspace_prefix: str,
    chain_id: int,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Consult the persistent contract_materializations table; build on miss.

    Returns ``(contract_name, analysis, tracking_plan, predicate_trees)``.
    ``predicate_trees`` round-trips through the cache so mapping-writer
    enumeration stays functional on cache hits (pre-c1d2e3f4a5b6 the
    builder dropped it and downstream silently disabled enumeration).
    """
    if not bytecode_keccak:
        _bump_materialize_metric("materialize_builds")
        return _build_static_artifacts(effective_address, workspace_prefix, chain_id=chain_id)

    from db import contract_materializations as cm

    if not cm.is_enabled():
        # Operator-controlled kill switch (PSAT_CONTRACT_MATERIALIZATIONS=0)
        # for prod incidents. Bypasses the persistent layer entirely so a
        # broken table or hot-spot lock contention can't fail-stop the
        # pipeline.
        _bump_materialize_metric("materialize_builds")
        return _build_static_artifacts(effective_address, workspace_prefix, chain_id=chain_id)

    built = {"ran": False}

    def _builder() -> Mapping[str, Any]:
        built["ran"] = True
        _bump_materialize_metric("materialize_builds")
        name, analysis, plan, predicate_trees = _build_static_artifacts(
            effective_address,
            workspace_prefix,
            chain_id=chain_id,
        )
        return {
            "contract_name": name,
            "analysis": analysis,
            "tracking_plan": plan,
            "predicate_trees": predicate_trees,
        }

    row = cm.materialize_or_wait(
        chain_id=chain_id,
        address=effective_address,
        bytecode_keccak=bytecode_keccak,
        builder=_builder,
    )

    if not built["ran"]:
        # materialize_or_wait returned without invoking our builder — served from
        # the persistent cache (or a sibling process built it); either way this
        # process did not pay the forge/Slither cost.
        _bump_materialize_metric("materialize_cache_hits")

    # ``hydrate_*`` reads blob-backed rows from storage and inline-only rows from
    # JSONB. The blob path's ``json.loads`` already returns a fresh dict per
    # call, but the inline path returns the SQLAlchemy JSONB-cached dict, so the
    # deepcopy is still required to avoid downstream mutations leaking back into
    # the ORM identity map.
    analysis = copy.deepcopy(cm.hydrate_analysis(row) or {})
    plan = copy.deepcopy(cm.hydrate_tracking_plan(row) or {})
    # ``predicate_trees`` is absent on rows written before the
    # c1d2e3f4a5b6 migration; hydrate returns None in that case and
    # ``_mapping_writer_specs_from_predicate_trees`` short-circuits.
    predicate_trees_cached = cm.hydrate_predicate_trees(row)
    predicate_trees = copy.deepcopy(predicate_trees_cached) if predicate_trees_cached else None
    contract_name = row.contract_name or "Contract"
    return contract_name, analysis, plan, predicate_trees

def _materialize_contract_artifacts(
    address: str,
    rpc_url: str,
    *,
    chain_id: int,
    workspace_prefix: str,
) -> LoadedArtifacts:
    """Build analysis + plan + snapshot + effective permissions in memory (tempdir cleaned up before return)."""
    effective_chain_id = require_supported_chain_id(
        chain_id=chain_id,
        context=f"recursive materialization for {address}",
    )
    rpc_url = require_configured_erpc_url(
        rpc_url,
        context=f"recursive materialization for {address}",
        chain_id=effective_chain_id,
    )
    chain_id = effective_chain_id

    # Proxy check — analyze the implementation but read storage from the proxy.
    effective_address = address
    snapshot_address = address
    try:
        from services.discovery.classifier import classify_single

        classification = classify_single(address, rpc_url, chain_id=chain_id)
        if classification.get("type") == "proxy":
            impl = classification.get("implementation")
            if impl:
                logger.info("Recursive resolve: %s is a proxy, using impl %s", address, impl)
                effective_address = impl
    except Exception as exc:
        logger.error("Recursive resolve: proxy check failed for %s chain_id=%s: %s", address, chain_id, exc)
        raise RuntimeError(f"recursive proxy classification failed for {address} chain_id={chain_id}") from exc

    # Resolve bytecode_keccak so the persistent contract_materializations
    # row is keyed on byte-exact code match: identical-bytecode contracts
    # at different addresses share one row.
    try:
        from utils.rpc import get_code_with_keccak

        _code, bytecode_keccak = get_code_with_keccak(rpc_url, effective_address, chain_id=chain_id)
    except Exception as exc:
        logger.error(
            "Recursive resolve: get_code_with_keccak failed for %s chain_id=%s: %s",
            effective_address,
            chain_id,
            exc,
        )
        raise RuntimeError(f"recursive bytecode lookup failed for {effective_address} chain_id={chain_id}") from exc

    # Cross-process cache: consult contract_materializations before paying
    # the forge+Slither cost. Two impl jobs in the same protocol — or a
    # re-run of a previously-analysed protocol on a different day — hit
    # this layer and skip the build. The advisory-lock-coalescing inside
    # ``materialize_or_wait`` ensures concurrent same-bytecode requests
    # across processes only run the builder once; the loser blocks on the
    # lock and reads the result.
    contract_name, analysis, plan, predicate_trees = _materialize_with_cross_process_cache(
        effective_address=effective_address,
        bytecode_keccak=bytecode_keccak,
        workspace_prefix=workspace_prefix,
        chain_id=chain_id,
    )
    # Address-mismatch retarget: when the persistent row was populated for
    # a different address that shares this bytecode, the cached
    # plan["contract_address"] points at the OTHER address. Stamp it for
    # THIS call so build_control_snapshot reads from the right contract.
    if isinstance(analysis.get("subject"), dict):
        analysis["subject"]["address"] = effective_address.lower()
    plan["contract_address"] = effective_address
    if isinstance(plan.get("contract"), dict):
        plan["contract"] = {**plan["contract"], "address": effective_address.lower()}
    if snapshot_address != effective_address:
        if isinstance(analysis.get("subject"), dict):
            raw_subject_implementations = analysis["subject"].get("implementation_addresses")
            subject_implementation_addresses: list[str] = []
            for candidate in [
                effective_address,
                *(raw_subject_implementations if isinstance(raw_subject_implementations, list) else []),
            ]:
                if not isinstance(candidate, str):
                    continue
                normalized = candidate.lower()
                if normalized == snapshot_address.lower() or normalized in subject_implementation_addresses:
                    continue
                subject_implementation_addresses.append(normalized)
            analysis["subject"] = {
                **analysis["subject"],
                "address": snapshot_address.lower(),
                "is_proxy": True,
                "proxy_address": snapshot_address.lower(),
                "implementation_addresses": subject_implementation_addresses,
            }
        plan_contract = plan.get("contract")
        if isinstance(plan_contract, dict):
            raw_implementations = plan_contract.get("implementation_addresses")
            implementation_addresses: list[str] = []
            for candidate in [
                effective_address,
                *(raw_implementations if isinstance(raw_implementations, list) else []),
            ]:
                if not isinstance(candidate, str):
                    continue
                normalized = candidate.lower()
                if normalized == snapshot_address.lower() or normalized in implementation_addresses:
                    continue
                implementation_addresses.append(normalized)
            plan_contract = {
                **plan_contract,
                "address": snapshot_address.lower(),
                "is_proxy": True,
                "proxy_address": snapshot_address.lower(),
                "implementation_addresses": implementation_addresses,
            }
        plan = {
            **plan,
            "contract_address": snapshot_address,
            **({"contract": plan_contract} if isinstance(plan_contract, dict) else {}),
        }

    snapshot = build_control_snapshot(cast(Any, plan), rpc_url)
    effective_permissions = _build_effective_permissions(cast(dict, analysis), snapshot)

    return {
        "analysis": cast(dict, analysis),
        "tracking_plan": plan,
        "snapshot": snapshot,
        "predicate_trees": predicate_trees,
        "effective_permissions": effective_permissions,
    }


def _ensure_node(
    nodes: dict[str, ResolvedGraphNode],
    *,
    address: str,
    resolved_type: str,
    label: str,
    depth: int,
    node_type: ResolvedNodeType,
    contract_name: str | None = None,
    contract: ContractSchema | None = None,
    analyzed: bool = False,
    details: dict[str, object] | None = None,
    artifacts: dict[str, str] | None = None,
) -> str:
    normalized = address.lower()
    node_id = _address_node_id(normalized)
    current = nodes.get(node_id)
    payload: ResolvedGraphNode = {
        "id": node_id,
        "address": normalized,
        "node_type": node_type,
        "resolved_type": resolved_type,  # type: ignore[typeddict-item]
        "label": label,
        "contract_name": contract_name,
        **({"contract": contract} if contract is not None else {}),
        "depth": depth,
        "analyzed": analyzed,
        "details": details or {},
        "artifacts": artifacts or {},
    }
    if current is None:
        nodes[node_id] = payload
        return node_id

    current["depth"] = min(current.get("depth", depth), depth)
    if contract_name:
        current["contract_name"] = contract_name
    if contract is not None:
        current["contract"] = contract
    if analyzed:
        current["analyzed"] = True
        current["node_type"] = "contract"
    if resolved_type != "unknown" or not current.get("resolved_type"):
        current["resolved_type"] = resolved_type  # type: ignore[typeddict-item]
    if label:
        current["label"] = label
    if details:
        merged_details = dict(current.get("details", {}))
        merged_details.update(details)
        current["details"] = merged_details
    if artifacts:
        merged_artifacts = dict(current.get("artifacts", {}))
        merged_artifacts.update(artifacts)
        current["artifacts"] = merged_artifacts
    return node_id


def _edge_key(edge: ResolvedGraphEdge) -> tuple:
    relation = edge["relation"]
    # Nested holder edges often appear via multiple upstream controller paths; keep one edge and merge notes.
    if relation in {"safe_owner", "timelock_owner", "proxy_admin_owner"}:
        return (
            edge["from_id"],
            edge["to_id"],
            relation,
            edge.get("label"),
        )
    return (
        edge["from_id"],
        edge["to_id"],
        relation,
        edge.get("label"),
        edge.get("source_controller_id"),
    )


def _add_edge(edges: dict[tuple, ResolvedGraphEdge], edge: ResolvedGraphEdge) -> None:
    key = _edge_key(edge)
    if key in edges:
        existing_notes = set(edges[key].get("notes", []))
        existing_notes.update(edge.get("notes", []))
        edges[key]["notes"] = sorted(existing_notes)
        return
    edges[key] = edge


def _nested_principals_for_details(resolved_type: str, details: dict[str, object]) -> list[tuple[str, str, str]]:
    principals: list[tuple[str, str, str]] = []
    if resolved_type == "safe":
        owners = details.get("owners")
        for owner in owners if isinstance(owners, list) else []:
            if isinstance(owner, str) and owner.startswith("0x"):
                principals.append((owner.lower(), "safe_owner", "safe owner"))
    elif resolved_type == "timelock":
        owner = details.get("owner")
        if isinstance(owner, str) and owner.startswith("0x"):
            principals.append((owner.lower(), "timelock_owner", "timelock owner"))
    elif resolved_type == "proxy_admin":
        owner = details.get("owner")
        if isinstance(owner, str) and owner.startswith("0x"):
            principals.append((owner.lower(), "proxy_admin_owner", "proxy admin owner"))
    return principals


def _safe_role_int(role: Any) -> int | None:
    """Coerce a role identifier to int, returning None for non-int shapes.

    Role-name strings and Condition-mapping shapes cannot be represented
    in the recursive resolver's ``set[int]`` accumulator; callers must skip
    those grants entirely.
    """
    try:
        return int(role)
    except (TypeError, ValueError):
        return None


def _role_principals_from_effective_permissions(effective_permissions: dict[str, Any]) -> list[RolePrincipal]:
    principals: dict[str, RolePrincipalAccumulator] = {}
    for function in effective_permissions.get("functions", []):
        if not isinstance(function, dict):
            continue
        function_signature = str(function.get("function", ""))
        for role_grant in function.get("authority_roles", []):
            if not isinstance(role_grant, dict):
                continue
            role = _safe_role_int(role_grant.get("role"))
            if role is None:
                logger.debug(
                    "recursive: skipping non-int role %r on %s",
                    role_grant.get("role"),
                    function_signature,
                )
                continue
            for principal in role_grant.get("principals", []):
                if not isinstance(principal, dict):
                    continue
                address = str(principal.get("address", "")).lower()
                if not address.startswith("0x"):
                    continue
                details_raw = principal.get("details", {})
                details = dict(details_raw) if isinstance(details_raw, dict) else {}
                payload = principals.setdefault(
                    address,
                    {
                        "address": address,
                        "resolved_type": str(principal.get("resolved_type", "unknown")),
                        "details": details,
                        "roles": set(),
                        "functions": set(),
                    },
                )
                payload["roles"].add(role)
                if function_signature:
                    payload["functions"].add(function_signature)
                if payload.get("resolved_type") in {None, "", "unknown"} and principal.get("resolved_type"):
                    payload["resolved_type"] = str(principal.get("resolved_type"))
                merged_details = dict(payload["details"])
                merged_details.update(details)
                payload["details"] = merged_details

        for controller in function.get("controllers", []):
            if not isinstance(controller, dict):
                continue
            controller_label = str(controller.get("label") or controller.get("source") or "controller")
            for principal in controller.get("principals", []):
                if not isinstance(principal, dict):
                    continue
                address = str(principal.get("address", "")).lower()
                if not address.startswith("0x"):
                    continue
                details_raw = principal.get("details", {})
                details = dict(details_raw) if isinstance(details_raw, dict) else {}
                payload = principals.setdefault(
                    address,
                    {
                        "address": address,
                        "resolved_type": str(principal.get("resolved_type", "unknown")),
                        "details": details,
                        "roles": set(),
                        "functions": set(),
                    },
                )
                if function_signature:
                    payload["functions"].add(function_signature)
                if payload.get("resolved_type") in {None, "", "unknown"} and principal.get("resolved_type"):
                    payload["resolved_type"] = str(principal.get("resolved_type"))
                merged_details = dict(payload["details"])
                merged_details.update(details)
                merged_details.setdefault("controller_label", controller_label)
                payload["details"] = merged_details

    serialized: list[RolePrincipal] = []
    for payload in principals.values():
        serialized.append(
            {
                "address": payload["address"],
                "resolved_type": payload["resolved_type"],
                "details": dict(payload["details"]),
                "roles": sorted(payload["roles"]),
                "functions": sorted(payload["functions"]),
            }
        )
    return sorted(serialized, key=lambda item: str(item["address"]))


def _mapping_writer_specs_from_predicate_trees(predicate_trees: Mapping[str, Any] | None) -> list[WriterEventSpec]:
    if not isinstance(predicate_trees, Mapping):
        return []
    tree_maps = [
        tree_map
        for tree_map in (predicate_trees.get("trees"), predicate_trees.get("check_trees"))
        if isinstance(tree_map, Mapping)
    ]
    if not tree_maps:
        return []

    specs: list[WriterEventSpec] = []
    seen: set[tuple[Any, ...]] = set()

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") != "LEAF":
            for child in node.get("children") or []:
                visit(child)
            return

        leaf = node.get("leaf")
        if not isinstance(leaf, dict):
            return
        descriptor = leaf.get("set_descriptor")
        if not isinstance(descriptor, dict):
            return
        storage_var = descriptor.get("storage_var")
        for hint in descriptor.get("enumeration_hint") or []:
            if not isinstance(hint, dict) or hint.get("direction") not in {"add", "remove"}:
                continue
            mapping_name = hint.get("mapping_name")
            if not isinstance(mapping_name, str) or not mapping_name:
                mapping_name = storage_var if isinstance(storage_var, str) else ""
            if not mapping_name:
                continue
            event_signature = hint.get("event_signature")
            event_name = hint.get("event_name")
            key_position = hint.get("key_position")
            if not isinstance(event_signature, str) or not isinstance(event_name, str):
                continue
            if not isinstance(key_position, int):
                continue
            identity = (
                mapping_name,
                event_signature,
                hint.get("direction"),
                key_position,
                hint.get("value_position"),
            )
            if identity in seen:
                continue
            seen.add(identity)
            specs.append(
                cast(
                    WriterEventSpec,
                    {
                        "mapping_name": mapping_name,
                        "event_signature": event_signature,
                        "event_name": event_name,
                        "key_position": key_position,
                        "indexed_positions": list(hint.get("indexed_positions") or []),
                        "direction": hint.get("direction"),
                        "writer_function": hint.get("writer_function") or "",
                        "value_position": hint.get("value_position"),
                    },
                )
            )

    for tree_map in tree_maps:
        for tree in tree_map.values():
            visit(tree)
    return specs


def _maybe_queue_address(
    queue: deque[PendingContract], queued: set[str], address: str, depth: int, max_depth: int
) -> None:
    if address in queued or depth > max_depth:
        return
    queue.append({"address": address, "depth": depth})
    queued.add(address)


def _add_nested_principals(
    *,
    nodes: dict[str, ResolvedGraphNode],
    edges: dict[tuple, ResolvedGraphEdge],
    queue: deque[PendingContract],
    queued: set[str],
    rpc_url: str,
    chain_id: int,
    from_node_id: str,
    source_controller_id: str | None,
    resolved_type: str,
    details: dict[str, object],
    depth: int,
    max_depth: int,
    classify_fn: Any | None = None,
) -> None:
    for nested_address, relation, label in _nested_principals_for_details(resolved_type, details):
        classify = classify_fn or (lambda addr: classify_resolved_address(rpc_url, addr, chain_id=chain_id))
        nested_type, nested_details = classify(nested_address)
        nested_node_type = "contract" if nested_type in ANALYZABLE_TYPES else "principal"
        nested_node_id = _ensure_node(
            nodes,
            address=nested_address,
            resolved_type=nested_type,
            label=label,
            depth=depth + 1,
            node_type=nested_node_type,
            details=nested_details,
        )
        _add_edge(
            edges,
            {
                "from_id": from_node_id,
                "to_id": nested_node_id,
                "relation": relation,  # type: ignore[typeddict-item]
                "label": label,
                "source_controller_id": source_controller_id,
                "notes": [],
            },
        )
        if nested_type in ANALYZABLE_TYPES:
            _maybe_queue_address(queue, queued, nested_address, depth + 1, max_depth)


def resolve_control_graph(
    *,
    root_artifacts: LoadedArtifacts,
    rpc_url: str,
    chain_id: int,
    max_depth: int = DEFAULT_RECURSION_MAX_DEPTH,
    workspace_prefix: str = "recursive",
    nested_artifacts_override: dict[str, LoadedArtifacts] | None = None,
    classify_cache: dict[str, tuple[str, dict[str, object]]] | None = None,
    initial_graph: ResolvedControlGraph | None = None,
    heartbeat: Callable[[], None] | None = None,
) -> tuple[ResolvedControlGraph, dict[str, LoadedArtifacts]]:
    """BFS the control chain.

    The returned ``nested_artifacts_by_address`` contains only contracts found
    below the root. The root's artifacts are already owned by the current job's
    static/resolution outputs, so persisting it as ``recursive.<root>.*`` makes
    policy treat the root as a nested materialization.
    """
    effective_chain_id = require_supported_chain_id(
        chain_id=chain_id,
        context="recursive control graph",
    )
    rpc_url = require_configured_erpc_url(
        rpc_url,
        context="recursive control graph",
        chain_id=effective_chain_id,
    )
    chain_id = effective_chain_id

    root_analysis = root_artifacts["analysis"]
    root_subject_obj = root_analysis.get("subject", {})
    root_subject = root_subject_obj if isinstance(root_subject_obj, dict) else {}
    root_address = str(root_subject.get("address", "")).lower()

    root_pending: PendingContract = {
        "address": root_address,
        "depth": 0,
        "artifacts": root_artifacts,
    }
    if root_subject:
        subject_chain_id = _require_subject_chain_id(
            root_subject,
            expected_chain_id=chain_id,
            address=root_address,
            context="recursive root",
        )
        root_pending["contract"] = make_contract(
            address=str(root_subject.get("address") or root_address),
            chain_id=subject_chain_id,
            name=root_subject.get("name"),
            label=root_subject.get("label"),
            is_proxy=bool(root_subject.get("is_proxy")),
            proxy_address=root_subject.get("proxy_address"),
            implementation_addresses=root_subject.get("implementation_addresses"),
            admin_addresses=root_subject.get("admin_addresses"),
            beacon_addresses=root_subject.get("beacon_addresses"),
            deployer_address=root_subject.get("deployer_address"),
            proxy_type=root_subject.get("proxy_type"),
        )
    queue: deque[PendingContract] = deque([root_pending])
    queued = {root_address}
    processed: set[str] = set()
    _classify_cache: dict[str, tuple[str, dict[str, object]]] = classify_cache if classify_cache is not None else {}
    nested_artifacts: dict[str, LoadedArtifacts] = {
        addr.lower(): artifacts
        for addr, artifacts in (nested_artifacts_override or {}).items()
        if addr.lower() != root_address
    }

    classify_stats: dict[str, int] = {"hits": 0, "misses": 0}

    def _cached_classify(addr: str) -> tuple[str, dict[str, object]]:
        key = addr.lower()
        if key in _classify_cache:
            classify_stats["hits"] += 1
            return _classify_cache[key]
        classify_stats["misses"] += 1
        kind, details, cacheable = classify_resolved_address_with_status(rpc_url, addr, chain_id=chain_id)
        if cacheable:
            _classify_cache[key] = (kind, details)
        return kind, details

    nodes: dict[str, ResolvedGraphNode] = {}
    edges: dict[tuple, ResolvedGraphEdge] = {}

    # Pre-seed the graph from a prior walk so the policy refresh path skips re-analyzing already-processed nested
    # contracts.
    if initial_graph is not None:
        for node in initial_graph.get("nodes", []):
            if not isinstance(node, dict):
                continue
            node_id = node.get("id")
            if isinstance(node_id, str):
                nodes[node_id] = cast(ResolvedGraphNode, dict(node))
        for edge in initial_graph.get("edges", []):
            if not isinstance(edge, dict):
                continue
            edges[_edge_key(cast(ResolvedGraphEdge, edge))] = cast(ResolvedGraphEdge, dict(edge))
        # Mark already-analyzed nested contracts as processed; the root must re-walk so freshly-computed role principals
        # get projected.
        for node in initial_graph.get("nodes", []):
            if not isinstance(node, dict) or not node.get("analyzed"):
                continue
            node_address = (node.get("details") or {}).get("address")
            if isinstance(node_address, str):
                addr = node_address.lower()
                if addr and addr != root_address:
                    processed.add(addr)

    from utils.concurrency import parallel_map

    def _materialize_for_pending(pending: PendingContract) -> tuple[LoadedArtifacts | None, BaseException | None]:
        """Materialize one pending contract's artifacts. Returns
        ``(artifacts, error)`` so the caller wires the success and error
        branches deterministically on the main thread."""
        address = pending["address"]
        preloaded = pending.get("artifacts")
        if preloaded is not None:
            return preloaded, None
        if address in nested_artifacts:
            return nested_artifacts[address], None
        try:
            artifacts = _materialize_contract_artifacts(
                address,
                rpc_url,
                chain_id=chain_id,
                workspace_prefix=workspace_prefix,
            )
            return artifacts, None
        except Exception as exc:
            return None, exc

    _levels = 0
    while queue:
        # BFS guarantees ``queue`` is depth-ordered. Drain every pending entry
        # at the current minimum depth into one level so they materialize
        # concurrently; new entries appended during wiring land at a strictly
        # greater depth and roll into the next iteration.
        target_depth = queue[0]["depth"]
        level_pending: list[PendingContract] = []
        while queue and queue[0]["depth"] == target_depth:
            entry = queue.popleft()
            if entry["address"] in processed or entry["depth"] > max_depth:
                continue
            level_pending.append(entry)

        if not level_pending:
            continue

        _levels += 1
        logger.info(
            "recursive level depth=%d contracts=%d",
            target_depth,
            len(level_pending),
            extra={"phase": "recursive_level", "depth": target_depth, "level_size": len(level_pending)},
        )

        # Parallel materialization. ``_materialize_contract_artifacts``
        # consults ``contract_materializations`` (cheap on a hit) and runs
        # Slither + ``forge build`` in a fresh tempdir on a miss. The miss
        # path is **CPU-bound** (Slither's IR build + solc + foundry compile
        # are not GIL-friendly), so the cap has to track host vCPU count
        # rather than the I/O-bound RPC fan-out ceiling — running
        # ``max_workers=8`` on a shared-cpu-2x VM thrashes the load average
        # to >5 and wedges sibling workers (observed on psat-pr-60 at
        # 2026-05-02). Default 2 matches the smallest worker VM size;
        # bumpable via env for performance-2x / shared-cpu-4x.
        materialize_fanout = max(1, int(os.getenv("PSAT_RESOLUTION_MATERIALIZE_FANOUT", "2")))
        materialized = parallel_map(
            _materialize_for_pending,
            level_pending,
            max_workers=materialize_fanout,
            heartbeat=heartbeat,
        )

        for pending, (_pending, outcome) in zip(level_pending, materialized):
            if isinstance(outcome, BaseException):
                # ``_materialize_for_pending`` already converts every internal
                # failure to ``(None, exc)`` — anything reaching here is a
                # genuine bug, surface it.
                raise outcome
            artifacts, mat_exc = outcome
            address = pending["address"]
            depth = pending["depth"]

            if mat_exc is not None or artifacts is None:
                err_text = str(mat_exc) if mat_exc is not None else "no artifacts produced"
                record_degraded(
                    phase="recursive_materialize",
                    exc=mat_exc if mat_exc is not None else RuntimeError(err_text),
                    context={"address": address, "depth": depth},
                )
                logger.error(
                    "Recursive resolve: failed to materialize nested contract %s at depth %s: %s",
                    address,
                    depth,
                    err_text,
                )
                raise RuntimeError(f"recursive materialization failed for {address} depth={depth}: {err_text}")

            if depth > 0 and address not in nested_artifacts:
                nested_artifacts[address] = artifacts

            processed.add(address)
            analysis = artifacts["analysis"]
            snapshot = artifacts["snapshot"]
            effective_permissions = artifacts.get("effective_permissions")
            subject = analysis.get("subject", {})
            subject_mapping = subject if isinstance(subject, dict) else {}
            contract_name = str(subject_mapping.get("name", address))
            subject_chain_id = (
                _require_subject_chain_id(
                    subject_mapping,
                    expected_chain_id=chain_id,
                    address=address,
                    context="recursive nested",
                )
                if subject_mapping
                else chain_id
            )
            contract = (
                make_contract(
                    address=str(subject_mapping.get("address") or address),
                    chain_id=subject_chain_id,
                    name=subject_mapping.get("name"),
                    label=subject_mapping.get("label"),
                    is_proxy=bool(subject_mapping.get("is_proxy")),
                    proxy_address=subject_mapping.get("proxy_address"),
                    implementation_addresses=subject_mapping.get("implementation_addresses"),
                    admin_addresses=subject_mapping.get("admin_addresses"),
                    beacon_addresses=subject_mapping.get("beacon_addresses"),
                    deployer_address=subject_mapping.get("deployer_address"),
                    proxy_type=subject_mapping.get("proxy_type"),
                )
                if subject_mapping
                else make_contract(address=address, chain_id=chain_id, name=contract_name)
            )
            node_details: dict[str, object] = {"address": address}
            contract_node_id = _ensure_node(
                nodes,
                address=address,
                resolved_type="contract",
                label=contract_name,
                depth=depth,
                node_type="contract",
                contract_name=contract_name,
                contract=contract,
                analyzed=True,
                details=node_details,
                artifacts={"data_key": f"recursive:{address.lower()}"},
            )

            # Replay semantic mapping-writer event hints into principal nodes;
            # bounded enumeration surfaces truncation via the `status` field.
            mapping_specs = _mapping_writer_specs_from_predicate_trees(artifacts.get("predicate_trees"))
            enumerated: list[Any] = []
            enumeration_status = "skipped"
            if mapping_specs:
                logger.info(
                    "mapping_enumerator: %s has %d writer-event specs",
                    address,
                    len(mapping_specs),
                )

                from services.resolution.mapping_enumerator import enumerate_mapping_allowlist_sync

                try:
                    result = enumerate_mapping_allowlist_sync(
                        address,
                        mapping_specs,
                        chain_id=chain_id,
                    )
                except Exception as exc:
                    record_degraded(
                        phase="mapping_enumerator",
                        exc=exc,
                        context={"address": address, "chain_id": chain_id},
                    )
                    logger.error(
                        "mapping_enumerator failed for chain_id=%s address=%s: %s",
                        chain_id,
                        address,
                        exc,
                        extra={"exc_type": type(exc).__name__},
                    )
                    raise RuntimeError(f"mapping_enumerator failed for {address} chain_id={chain_id}") from exc

                enumerated = list(result["principals"])
                enumeration_status = result["status"]
                if enumeration_status != "complete":
                    logger.error(
                        "mapping_enumerator incomplete for chain_id=%s address=%s status=%s pages=%d last_block=%d",
                        chain_id,
                        address,
                        enumeration_status,
                        result["pages_fetched"],
                        result["last_block_scanned"],
                    )
                    raise RuntimeError(
                        f"mapping_enumerator incomplete for {address} chain_id={chain_id} status={enumeration_status}"
                    )
                logger.info(
                    "mapping_enumerator: %s returned %d principals (status=%s)",
                    address,
                    len(enumerated),
                    enumeration_status,
                )
                for principal in enumerated:
                    member_addr = principal["address"]
                    _ensure_node(
                        nodes,
                        address=member_addr,
                        resolved_type="unknown",
                        label=principal["mapping_name"],
                        depth=depth + 1,
                        node_type="principal",
                        analyzed=False,
                        details={
                            "address": member_addr,
                            "controller_label": principal["mapping_name"],
                            "mapping_name": principal["mapping_name"],
                            "last_seen_block": principal["last_seen_block"],
                            "direction_history": principal["direction_history"],
                        },
                    )
                    _add_edge(
                        edges,
                        {
                            "from_id": contract_node_id,
                            "to_id": _address_node_id(member_addr),
                            "relation": "mapping_member",
                            "label": principal["mapping_name"],
                            "source_controller_id": f"mapping:{principal['mapping_name']}",
                            "notes": [],
                        },
                    )
                # Surface enumeration status on the node so downstream stages can flag incomplete allowlists.
                if mapping_specs and contract_node_id in nodes:
                    nodes[contract_node_id]["details"]["mapping_enumeration_status"] = enumeration_status

            for controller_id, controller_value in snapshot.get("controller_values", {}).items():
                controller_address = str(controller_value.get("value", "")).lower()
                if not controller_address.startswith("0x") or len(controller_address) != 42:
                    continue
                resolved_type = str(controller_value.get("resolved_type", "unknown"))
                details = dict(controller_value.get("details", {}))
                controller_label = str(controller_value.get("source", controller_id))
                controller_node_type = "contract" if resolved_type in ANALYZABLE_TYPES else "principal"
                controller_node_id = _ensure_node(
                    nodes,
                    address=controller_address,
                    resolved_type=resolved_type,
                    label=controller_label,
                    depth=depth + 1,
                    node_type=controller_node_type,
                    details=details,
                )
                _add_edge(
                    edges,
                    {
                        "from_id": contract_node_id,
                        "to_id": controller_node_id,
                        "relation": "controller_value",
                        "label": controller_label,
                        "source_controller_id": controller_id,
                        "notes": [f"resolved_type={resolved_type}"],
                    },
                )

                if resolved_type in ANALYZABLE_TYPES:
                    _maybe_queue_address(queue, queued, controller_address, depth + 1, max_depth)

                _add_nested_principals(
                    nodes=nodes,
                    edges=edges,
                    queue=queue,
                    queued=queued,
                    rpc_url=rpc_url,
                    chain_id=chain_id,
                    from_node_id=controller_node_id,
                    source_controller_id=controller_id,
                    resolved_type=resolved_type,
                    details=details,
                    depth=depth + 1,
                    max_depth=max_depth,
                    classify_fn=_cached_classify,
                )

            for principal_value in _role_principals_from_effective_permissions(effective_permissions or {}):
                principal_address = str(principal_value["address"]).lower()
                if principal_address == address:
                    continue
                resolved_type = str(principal_value.get("resolved_type", "unknown"))
                details = dict(principal_value["details"])
                if resolved_type == "unknown":
                    resolved_type, classified_details = _cached_classify(principal_address)
                    merged_details = dict(details)
                    merged_details.update(classified_details)
                    details = merged_details

                node_type = "contract" if resolved_type in ANALYZABLE_TYPES else "principal"
                principal_node_id = _ensure_node(
                    nodes,
                    address=principal_address,
                    resolved_type=resolved_type,
                    label="role principal",
                    depth=depth + 1,
                    node_type=node_type,
                    details=details,
                )
                roles = principal_value["roles"]
                functions = principal_value["functions"]
                _add_edge(
                    edges,
                    {
                        "from_id": contract_node_id,
                        "to_id": principal_node_id,
                        "relation": "role_principal",
                        "label": f"roles {','.join(str(role) for role in roles)}" if roles else "role principal",
                        "source_controller_id": None,
                        "notes": [f"functions={len(functions)}", *(f"role={role}" for role in roles)],
                    },
                )
                if resolved_type in ANALYZABLE_TYPES:
                    _maybe_queue_address(queue, queued, principal_address, depth + 1, max_depth)
                _add_nested_principals(
                    nodes=nodes,
                    edges=edges,
                    queue=queue,
                    queued=queued,
                    rpc_url=rpc_url,
                    chain_id=chain_id,
                    from_node_id=principal_node_id,
                    source_controller_id=None,
                    resolved_type=resolved_type,
                    details=details,
                    depth=depth + 1,
                    max_depth=max_depth,
                    classify_fn=_cached_classify,
                )

    # Aggregate profile for the BFS orchestration. The per-contract static cost
    # is already visible via the nested ``pipeline_profile`` lines; this surfaces
    # the orchestration shape (levels walked, contracts processed, classify cache
    # effectiveness) that was previously opaque inside the ``recursive_graph``
    # phase. ``record_stage_metric`` is a no-op outside a worker job context.
    _mat_metrics = stage_metrics_var.get() or {}
    _mat_builds = _mat_metrics.get("materialize_builds", 0)
    _mat_hits = _mat_metrics.get("materialize_cache_hits", 0)
    logger.info(
        "recursive graph profile: levels=%d processed=%d builds=%d cache_hits=%d "
        "classify_hits=%d classify_misses=%d nodes=%d edges=%d",
        _levels,
        len(processed),
        _mat_builds,
        _mat_hits,
        classify_stats["hits"],
        classify_stats["misses"],
        len(nodes),
        len(edges),
        extra={
            "profile_kind": "recursive_profile",
            "levels": _levels,
            "processed": len(processed),
            "materialize_builds": _mat_builds,
            "materialize_cache_hits": _mat_hits,
            "classify_hits": classify_stats["hits"],
            "classify_misses": classify_stats["misses"],
            "nodes": len(nodes),
            "edges": len(edges),
        },
    )
    record_stage_metric("recursive_levels", _levels)
    record_stage_metric("recursive_classify_hits", classify_stats["hits"])
    record_stage_metric("recursive_classify_misses", classify_stats["misses"])

    graph: ResolvedControlGraph = {
        "schema_version": "0.1",
        "root_contract_address": root_address,
        "max_depth": max_depth,
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges.values(), key=lambda item: (item["from_id"], item["relation"], item["to_id"])),
    }
    return graph, nested_artifacts
