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
from typing import Any, TypedDict, cast

from typing_extensions import NotRequired

from db.models import (
    EDGE_RELATION_CONTROLLER_VALUE,
    EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED,
    EDGE_RELATION_EXTERNAL_CALL_TARGET,
)
from db.storage import StorageContentIncomplete, StorageUnavailable
from schemas.contract_analysis import ContractAnalysis, ControllerProvenance
from schemas.control_tracking import (
    ControlSnapshot,
    ControlTrackingPlan,
    ResolvedControllerType,
    coerce_resolved_controller_type,
)
from schemas.resolved_control_graph import (
    ResolvedAnalysisState,
    ResolvedControlGraph,
    ResolvedEdgeRelation,
    ResolvedGraphEdge,
    ResolvedGraphNode,
    ResolvedNodeType,
)
from services.discovery.classifier import ClassificationIncompleteError
from services.discovery.fetch import fetch, scaffold
from services.static.contract_analysis_pipeline.core import collect_contract_analysis_with_artifacts
from services.static.contract_analysis_pipeline.mapping_events import WriterEventSpec
from utils.logging import record_degraded, record_stage_metric, stage_metrics_var

from .tracking import (
    build_control_snapshot,
    classify_resolved_address,
    classify_resolved_address_with_status,
    probe_declared_vault_backlink,
)
from .tracking_plan import build_control_tracking_plan

logger = logging.getLogger(__name__)


class UnresolvedProxyError(RuntimeError):
    """A proxy with no resolvable single implementation (diamonds, failed beacons, short-bytecode ``unknown``
    proxies).

    Analysing the delegatecall shell yields an empty guard set that reads as permissionless, so materialization fails
    closed and the BFS records a degraded node.
    """


ANALYZABLE_TYPES = {"contract", "timelock", "proxy_admin"}
DEFAULT_RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))

# Typed against the schema vocabulary so pyright catches drift.
_PROVENANCE_CALL_TARGET: ControllerProvenance = "call_target"
_PROVENANCE_CALLER_GATE: ControllerProvenance = "caller_gate"


def _coerce_resolved_type(value: object) -> ResolvedControllerType:
    """Coerce an undetermined ``resolved_type`` to ``"unknown"``.

    A present ``None`` becomes the literal ``"None"`` via ``str()`` (also possible from a stored graph), which
    downstream reads as a concrete type. Anything outside ``RESOLVED_CONTROLLER_TYPES`` is likewise undetermined.
    """
    return coerce_resolved_controller_type(value)


_MATERIALIZE_METRIC_LOCK = threading.Lock()


def _bump_materialize_metric(key: str) -> None:
    """Thread-safe +1 to a stage metric from the parallel materialize fan-out.

    ``record_stage_metric`` overwrites, and worker threads share ``stage_metrics_var`` via copy_context. No-op outside a
    worker job.
    """
    _bump_stage_metric(key)


def _bump_stage_metric(key: str, n: int = 1) -> None:
    """Thread-safe ``+n`` to a per-job stage metric (see :func:`_bump_materialize_metric`)."""
    metrics = stage_metrics_var.get()
    if metrics is None:
        return
    with _MATERIALIZE_METRIC_LOCK:
        metrics[key] = metrics.get(key, 0) + n


class LoadedArtifacts(TypedDict):
    analysis: dict[str, Any]
    tracking_plan: dict[str, Any]
    snapshot: ControlSnapshot
    predicate_trees: NotRequired[dict[str, Any] | None]
    effective_permissions: NotRequired[dict[str, Any] | None]


class PendingContract(TypedDict):
    address: str
    depth: int
    artifacts: NotRequired[LoadedArtifacts]


class RolePrincipalAccumulator(TypedDict):
    address: str
    resolved_type: ResolvedControllerType
    details: dict[str, object]
    roles: set[int]
    functions: set[str]


class RolePrincipal(TypedDict):
    address: str
    resolved_type: ResolvedControllerType
    details: dict[str, object]
    roles: list[int]
    functions: list[str]


def _address_node_id(address: str) -> str:
    return f"address:{address.lower()}"


def _sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "_", value).strip("_")
    return cleaned or "contract"


def _workspace_name(contract_name: str, address: str, prefix: str) -> str:
    return f"{_sanitize_name(prefix)}_{_sanitize_name(contract_name)}_{address.lower()[2:10]}"


def _contract_name_for_address(address: str, chain_id: int) -> str | None:
    try:
        result = fetch(address, chain_id=chain_id)
    except Exception:
        return None
    if not isinstance(result, dict):
        return None
    # ``or ""``: a present ``None`` would otherwise become the name "None".
    name = str(result.get("ContractName") or "").strip()
    return name or None


def _build_effective_permissions(
    analysis: dict[str, Any],
    snapshot: ControlSnapshot,
) -> dict[str, Any] | None:
    # Function-scope import breaks the policy/resolution import cycle, which crashed policy_worker on boot.
    from services.policy.effective_permissions import build_effective_permissions

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
        # A failed build silently drops the node's role principals, so record it as degraded. ``or ""`` keeps ``address:
        # None`` from reading as "None".
        address = str((analysis.get("subject") or {}).get("address") or "") or "<unknown>"
        record_degraded(
            phase="recursive_effective_permissions",
            exc=exc,
            context={"address": address},
        )
        logger.warning(
            "Recursive resolve: effective_permissions build failed for %s: %s",
            address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return None


def _build_static_artifacts(
    effective_address: str,
    workspace_prefix: str,
    *,
    chain_id: int,
) -> tuple[str, ContractAnalysis, ControlTrackingPlan, dict[str, Any] | None]:
    """Run the forge+Slither+predicate pipeline for *effective_address*.

    Returns ``(contract_name, analysis, tracking_plan, predicate_trees)``. ``effects`` isn't returned: the policy stage
    reads the static worker's per-job artifact instead. Separate so the cross-process cache can call it as its builder.
    """
    result = fetch(effective_address, chain_id=chain_id)
    contract_name = str(result.get("ContractName") or "Contract")
    project_name = _workspace_name(contract_name, effective_address, workspace_prefix)

    with tempfile.TemporaryDirectory(prefix=f"psat_{workspace_prefix}_") as tmp:
        project_dir = Path(tmp) / project_name
        scaffold(effective_address, result, project_dir)
        analysis, predicate_trees, _effects = collect_contract_analysis_with_artifacts(project_dir)

    plan = build_control_tracking_plan(analysis)
    return contract_name, analysis, plan, predicate_trees


def _chain_name_for_materialization(chain_id: int) -> str:
    """Canonical chain name for the ``contract_materializations`` cache key (mainnet is ``"ethereum"``).

    Unregistered ids fail loud rather than key under mainnet.
    """
    from utils.chains import require_chain

    return require_chain(chain_id, context="materialization chain name").name


def _widen_built(
    built: tuple[str, ContractAnalysis, ControlTrackingPlan, dict[str, Any] | None],
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Widen a fresh build to the mixed-provenance cache shape (persisted rows are unverified JSONB)."""
    name, analysis, plan, predicate_trees = built
    return name, cast("dict[str, Any]", analysis), cast("dict[str, Any]", plan), predicate_trees


def _materialize_with_cross_process_cache(
    *,
    effective_address: str,
    bytecode_keccak: str | None,
    workspace_prefix: str,
    chain: str | None = None,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Consult the persistent contract_materializations table; build on miss.

    Returns ``(contract_name, analysis, tracking_plan, predicate_trees)``; ``predicate_trees`` round-trips so mapping
    enumeration works on cache hits. Builds directly when ``bytecode_keccak`` is None or the DB layer raises.
    """
    # A chainless call is a data bug; fail loud rather than default to mainnet.
    from utils.chains import require_chain

    build_chain_id = require_chain(chain=chain, context="contract materialization").chain_id

    if not bytecode_keccak:
        _bump_materialize_metric("materialize_builds")
        return _widen_built(_build_static_artifacts(effective_address, workspace_prefix, chain_id=build_chain_id))

    try:
        from db import contract_materializations as cm
    except Exception as exc:
        logger.debug("contract_materializations unavailable, falling back to direct build: %s", exc)
        _bump_materialize_metric("materialize_builds")
        return _widen_built(_build_static_artifacts(effective_address, workspace_prefix, chain_id=build_chain_id))

    if not cm.is_enabled():
        # PSAT_CONTRACT_MATERIALIZATIONS=0 kill switch bypasses the persistent layer during incidents.
        _bump_materialize_metric("materialize_builds")
        return _widen_built(_build_static_artifacts(effective_address, workspace_prefix, chain_id=build_chain_id))

    built = {"ran": False}

    def _builder() -> Mapping[str, Any]:
        built["ran"] = True
        _bump_materialize_metric("materialize_builds")
        name, analysis, plan, predicate_trees = _build_static_artifacts(
            effective_address, workspace_prefix, chain_id=build_chain_id
        )
        return {
            "contract_name": name,
            "analysis": analysis,
            "tracking_plan": plan,
            "predicate_trees": predicate_trees,
        }

    def _source_hash_fn() -> str | None:
        # Cross-chain reuse key; ``get_source`` is cached, so the build path shares the fetch.
        from services.discovery.fetch import source_content_hash

        result = fetch(effective_address, chain_id=build_chain_id)
        return source_content_hash(result)

    try:
        row = cm.materialize_or_wait(
            chain=chain,
            address=effective_address,
            bytecode_keccak=bytecode_keccak,
            builder=_builder,
            source_hash_fn=_source_hash_fn,
        )
    except Exception as exc:
        # Builder failures propagate for the stage's own retry classification; DB-layer failures fall back to a direct
        # build.
        if _is_builder_exception(exc):
            raise
        record_degraded(
            phase="materialize_or_wait",
            exc=exc,
            context={"chain": chain, "address": effective_address},
        )
        logger.warning("contract_materializations.materialize_or_wait failed, falling back: %s", exc)
        _bump_materialize_metric("materialize_builds")
        return _widen_built(_build_static_artifacts(effective_address, workspace_prefix, chain_id=build_chain_id))

    if not built["ran"]:
        # Served from the cache or a sibling process's build.
        _bump_materialize_metric("materialize_cache_hits")

    # Deepcopy because the inline-JSONB path returns the ORM-cached dict.
    #
    # ``StorageContentIncomplete`` propagates on purpose (transient when undetermined, terminal when proven absent), so
    # ``or {}`` only applies to a row that stored nothing. An unreadable payload treated as ``{}`` would seed and cache
    # a witness built on nothing.
    analysis = copy.deepcopy(cm.hydrate_analysis(row) or {})
    plan = copy.deepcopy(cm.hydrate_tracking_plan(row) or {})
    # ``None`` on rows before c1d2e3f4a5b6; the mapping-writer extraction short-circuits. That extraction is the only
    # reader and never mutates, so the two maps it reads are projected out without copying the ORM-cached blob.
    predicate_trees_cached = cm.hydrate_predicate_trees(row)
    predicate_trees = (
        {k: predicate_trees_cached[k] for k in ("trees", "check_trees") if k in predicate_trees_cached}
        if predicate_trees_cached
        else None
    )
    contract_name = row.contract_name or "Contract"
    return contract_name, analysis, plan, predicate_trees


def _is_builder_exception(exc: BaseException) -> bool:
    """Did *exc* come from the builder rather than the DB cache layer? Anything from sqlalchemy counts as DB-layer."""
    mod = type(exc).__module__ or ""
    return not (mod.startswith("sqlalchemy") or mod.startswith("psycopg2"))


def _materialize_contract_artifacts(
    address: str,
    rpc_url: str,
    *,
    workspace_prefix: str,
    chain: str | None = None,
    chain_id: int | None = None,
) -> LoadedArtifacts:
    """Build analysis, plan, snapshot and effective permissions in memory (tempdir cleaned up before return)."""
    # Analyse the implementation but read storage from the proxy.
    effective_address = address
    snapshot_address = address

    # Own try so a classify hiccup degrades to analysing the address as-is, while the fail-closed
    # ``UnresolvedProxyError`` and ``ClassificationIncompleteError`` still propagate.
    classification: dict | None = None
    try:
        from services.discovery.classifier import classify_single

        classification = classify_single(address, rpc_url, chain_id=chain_id)
    except ClassificationIncompleteError:
        # #121: proxy slots unreadable (transient RPC). Propagate so the node is degraded and retried, not analysed as a
        # clean contract.
        raise
    except Exception as exc:
        logger.debug("Recursive resolve: proxy check failed for %s: %s", address, exc)

    if classification is not None and classification.get("type") == "proxy":
        impl = classification.get("implementation")
        if impl:
            # Per-nested-proxy, so DEBUG plus a ``proxies_redirected`` count.
            logger.debug(
                "Recursive resolve: proxy redirect to impl",
                extra={"address": address, "implementation": impl},
            )
            _bump_stage_metric("proxies_redirected")
            effective_address = impl
        else:
            # #122: no resolvable implementation; the address is a delegatecall shell whose empty guard set would read
            # as permissionless. Fail closed.
            _bump_stage_metric("proxies_unresolved")
            raise UnresolvedProxyError(
                f"proxy {address} (type={classification.get('proxy_type')}) implementation "
                "unresolved; refusing to analyze the proxy shell"
            )

    # Keyed on bytecode so identical code at different addresses shares a row.
    bytecode_keccak: str | None = None
    try:
        from services.clients.rpc import get_code_with_keccak

        _code, bytecode_keccak = get_code_with_keccak(rpc_url, effective_address)
    except Exception as exc:
        logger.debug("Recursive resolve: get_code_with_keccak failed for %s: %s", effective_address, exc)

    # ``materialize_or_wait``'s advisory lock ensures concurrent same-bytecode requests across processes build once.
    contract_name, analysis, plan, predicate_trees = _materialize_with_cross_process_cache(
        effective_address=effective_address,
        bytecode_keccak=bytecode_keccak,
        workspace_prefix=workspace_prefix,
        chain=chain,
    )
    # A row built for another address with the same bytecode has that address in the plan; restamp it.
    if isinstance(analysis.get("subject"), dict):
        analysis["subject"]["address"] = effective_address
    plan["contract_address"] = effective_address
    if snapshot_address != effective_address:
        plan = {**plan, "contract_address": snapshot_address}

    snapshot = build_control_snapshot(cast(Any, plan), rpc_url, chain_id=chain_id)
    effective_permissions = _build_effective_permissions(cast(dict, analysis), snapshot)

    return {
        "analysis": cast(dict, analysis),
        "tracking_plan": plan,
        "snapshot": snapshot,
        "predicate_trees": predicate_trees,
        "effective_permissions": effective_permissions,
    }


def _analysis_state(node: ResolvedGraphNode, max_depth: int) -> ResolvedAnalysisState | None:
    """Why this node is (or is not) analysed.

    ``analyzed=False`` conflates never-a-candidate, failed materialization, cut off by depth, and unknown. Derived here
    because only the end of the walk has ``max_depth`` with every node. Returns ``None`` for an unanalysed in-horizon
    contract with no recorded failure.
    """
    if node.get("analyzed"):
        return "analyzed"
    details = node.get("details")
    if isinstance(details, dict) and details.get("materialize_error"):
        return "attempt_failed"
    resolved_type = node.get("resolved_type")
    if resolved_type in ANALYZABLE_TYPES:
        if int(node.get("depth") or 0) > max_depth:
            return "beyond_depth_horizon"
        return None
    if resolved_type and resolved_type not in {"unknown", "None"}:
        # ``not_analyzable``: Safes are contracts too, just not analyzable. ``"None"`` (a leaked ``str(None)`` from old
        # stored graphs) and ``"unknown"`` are undetermined, which proves nothing about applicability.
        return "not_analyzable"
    return None


def _resolved_type_rank(resolved_type: str | None) -> int:
    """How much a ``resolved_type`` claims; more specific may replace vaguer, not the reverse.

    ``"contract"`` is generic. Stamping it unconditionally used to overwrite types like ``timelock`` (and their
    ``delay``) depending on walk order. Equal ranks keep last-write-wins.
    """
    if not resolved_type:
        return -1
    if resolved_type == "unknown":
        return 0
    if resolved_type == "contract":
        return 1
    return 2


def _ensure_node(
    nodes: dict[str, ResolvedGraphNode],
    *,
    address: str,
    resolved_type: ResolvedControllerType,
    label: str,
    depth: int,
    node_type: ResolvedNodeType,
    contract_name: str | None = None,
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
        "resolved_type": resolved_type,
        "label": label,
        "contract_name": contract_name,
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
    if analyzed:
        current["analyzed"] = True
        current["node_type"] = "contract"
    if _resolved_type_rank(resolved_type) >= _resolved_type_rank(current.get("resolved_type")):
        current["resolved_type"] = resolved_type
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
    # Nested holder edges arrive via several upstream paths; keep one and merge notes.
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


def _nested_principals_for_details(
    resolved_type: ResolvedControllerType, details: dict[str, object]
) -> list[tuple[str, ResolvedEdgeRelation, str]]:
    principals: list[tuple[str, ResolvedEdgeRelation, str]] = []
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


# Marks a principal the policy stage projected from a witnessed role grant (``services/policy/capability_surface.py``).
# Read from ``details``, never ``label``.
ROLE_GRANT_SOURCE = "semantic_capability:role_grant"


def _maybe_probe_backlink(
    rpc_url: str,
    *,
    principal_address: str,
    gated_contract_address: str,
    details: Mapping[str, Any],
    node_type: str,
    chain_id: int | None,
) -> dict[str, Any] | None:
    """The ``vault()`` back-link witness for a role-granted contract principal.

    Gated on provenance so other nodes pay nothing; failures don't fail the walk.
    """
    if node_type != "contract" or details.get("source") != ROLE_GRANT_SOURCE:
        return None
    if not gated_contract_address or principal_address == gated_contract_address:
        return None
    try:
        return probe_declared_vault_backlink(
            rpc_url,
            principal_address,
            gated_contract_address,
            chain_id=chain_id,
        )
    except Exception as exc:
        logger.debug("recursive: back-link probe failed for %s: %s", principal_address, exc)
        return None


def _safe_role_int(role: Any) -> int | None:
    """Coerce a role identifier to int, or None for role-name strings and Condition shapes (callers skip those)."""
    try:
        return int(role)
    except (TypeError, ValueError):
        return None


def _role_principals_from_effective_permissions(effective_permissions: dict[str, Any]) -> list[RolePrincipal]:
    principals: dict[str, RolePrincipalAccumulator] = {}
    for function in effective_permissions.get("functions", []):
        if not isinstance(function, dict):
            continue
        function_signature = str(function.get("function") or "")
        # ``or []``: the key can be present as ``None`` (undetermined role), which contributes nothing.
        for role_grant in function.get("authority_roles") or []:
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
                        "resolved_type": _coerce_resolved_type(principal.get("resolved_type")),
                        "details": details,
                        "roles": set(),
                        "functions": set(),
                    },
                )
                payload["roles"].add(role)
                if function_signature:
                    payload["functions"].add(function_signature)
                if payload.get("resolved_type") in {None, "", "unknown"} and principal.get("resolved_type"):
                    payload["resolved_type"] = _coerce_resolved_type(principal.get("resolved_type"))
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
                        "resolved_type": _coerce_resolved_type(principal.get("resolved_type")),
                        "details": details,
                        "roles": set(),
                        "functions": set(),
                    },
                )
                if function_signature:
                    payload["functions"].add(function_signature)
                if payload.get("resolved_type") in {None, "", "unknown"} and principal.get("resolved_type"):
                    payload["resolved_type"] = _coerce_resolved_type(principal.get("resolved_type"))
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


# Leaf roles proving mapping membership confers authority; matches ``_AUTHORITY_LEAF_ROLES`` in
# services/static/contract_analysis_pipeline/tracking.py.
_MAPPING_HARVEST_AUTHORITY_ROLES = frozenset({"caller_authority", "delegated_authority"})


def _mapping_leaf_confers_authority(leaf: Mapping[str, Any]) -> bool:
    """Does *leaf* prove that membership in its mapping confers authority?

    Harvested members become ``mapping_member`` control edges, so this mustn't out-claim the static leaf:

    - ``authority_role`` must be authority-bearing (absent means pre-schema, undetermined);
    - ``operator == "falsy"`` is a denylist, whose members are the blocked population;
    - an explicit ``"low"`` confidence disqualifies; absent doesn't.
    """
    if leaf.get("authority_role") not in _MAPPING_HARVEST_AUTHORITY_ROLES:
        return False
    if leaf.get("operator") == "falsy":
        return False
    if leaf.get("confidence") == "low":
        return False
    return True


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
        if not _mapping_leaf_confers_authority(leaf):
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


def _replay_mapping_principals(
    *,
    address: str,
    mapping_specs: list[WriterEventSpec],
    contract_node_id: str,
    depth: int,
    nodes: dict[str, ResolvedGraphNode],
    edges: dict[tuple, ResolvedGraphEdge],
    chain_id: int,
) -> str:
    """Replay mapping-writer events for *address* into principal nodes and edges; returns the enumeration status.

    Floored at the deploy block (no events before it). With no known floor it defers (``deferred_no_floor``) instead of
    scanning from genesis, which 429-storms HyperSync; enrolled addresses fill in on a later policy pass.
    """
    hypersync_token = os.getenv("ENVIO_API_TOKEN") or ""
    logger.info(
        "mapping_enumerator: writer-event specs collected",
        extra={
            "address": address,
            "spec_count": len(mapping_specs),
            "token": "present" if hypersync_token else "missing",
        },
    )
    if not hypersync_token:
        return "skipped"

    from services.resolution.creation_block_floor import resolve_scan_floor

    scan_floor = resolve_scan_floor(address, chain_id)
    if scan_floor is None:
        logger.info(
            "mapping_enumerator: deferring replay (no scan floor resolved)",
            extra={"address": address, "decision": "deferred_no_floor"},
        )
        return "deferred_no_floor"

    from services.resolution.mapping_enumerator import enumerate_mapping_allowlist_sync

    try:
        result = enumerate_mapping_allowlist_sync(
            address,
            mapping_specs,
            # Chain from the walk, not a mainnet default.
            chain=str(chain_id),
            bearer_token=hypersync_token,
            from_block=scan_floor,
        )
    except Exception as exc:
        # Bounds are handled inside; raises here are unexpected (auth, load).
        record_degraded(phase="mapping_enumerator", exc=exc, context={"address": address})
        logger.warning(
            "mapping_enumerator UNEXPECTED FAILURE for %s: %s — treating as truncated",
            address,
            exc,
        )
        return "error"

    enumerated = list(result["principals"])
    enumeration_status = result["status"]
    if enumeration_status != "complete":
        # A truncated scan silently omits members past the bound; record it as degraded with a count.
        record_degraded(
            phase="mapping_enum_incomplete",
            exc=RuntimeError(f"mapping enumeration {enumeration_status}"),
            context={
                "address": address,
                "status": enumeration_status,
                "pages_fetched": result["pages_fetched"],
                "last_block_scanned": result["last_block_scanned"],
            },
        )
        _bump_stage_metric("mapping_enum_incomplete")
        logger.warning(
            "mapping_enumerator: incomplete enumeration (principal set may be missing entries)",
            extra={
                "address": address,
                "enumeration_status": enumeration_status,
                "pages_fetched": result["pages_fetched"],
                "last_block_scanned": result["last_block_scanned"],
            },
        )
    logger.info(
        "mapping_enumerator: enumeration complete",
        extra={"address": address, "principals": len(enumerated), "enumeration_status": enumeration_status},
    )

    for principal in enumerated:
        member_addr = principal["address"]
        if member_addr.lower() == address.lower():
            # Skip self-membership edges (e.g. a timelock granted a role on itself): X->X asserts nothing, and
            # ``_ensure_node`` would clobber the contract's label with the mapping name.
            logger.debug(
                "mapping_enumerator: skipping self-membership edge",
                extra={"address": address, "mapping_name": principal["mapping_name"]},
            )
            continue
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
    return enumeration_status


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
    from_node_id: str,
    source_controller_id: str | None,
    resolved_type: ResolvedControllerType,
    details: dict[str, object],
    depth: int,
    max_depth: int,
    classify_fn: Any | None = None,
    chain_id: int | None = None,
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
                "relation": relation,
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
    """BFS the control chain. Returns ``(graph, nested_artifacts_by_address)``; mutates classify_cache.

    ``chain_id`` scopes the materialization cache key and the mapping-writer scan floor.
    """
    chain_name = _chain_name_for_materialization(chain_id)
    root_analysis = root_artifacts["analysis"]
    root_subject = root_analysis.get("subject", {})
    root_address = str(root_subject.get("address", "")).lower()

    queue: deque[PendingContract] = deque(
        [
            {
                "address": root_address,
                "depth": 0,
                "artifacts": root_artifacts,
            }
        ]
    )
    queued = {root_address}
    processed: set[str] = set()
    _classify_cache: dict[str, tuple[str, dict[str, object]]] = classify_cache if classify_cache is not None else {}
    nested_artifacts: dict[str, LoadedArtifacts] = dict(nested_artifacts_override or {})

    classify_stats: dict[str, int] = {"hits": 0, "misses": 0}

    def _cached_classify(addr: str) -> tuple[ResolvedControllerType, dict[str, object]]:
        key = addr.lower()
        if key in _classify_cache:
            classify_stats["hits"] += 1
            kind, details = _classify_cache[key]
            # The cache may be pre-seeded from a stored artifact, so coerce.
            return _coerce_resolved_type(kind), details
        classify_stats["misses"] += 1
        kind, details, cacheable = classify_resolved_address_with_status(rpc_url, addr, chain_id=chain_id)
        # Don't cache transient RPC errors, or the "contract" fallback gets persisted.
        if cacheable:
            _classify_cache[key] = (kind, details)
        return kind, details

    nodes: dict[str, ResolvedGraphNode] = {}
    edges: dict[tuple, ResolvedGraphEdge] = {}

    # Pre-seed from a prior walk so the policy refresh skips already-processed nested contracts.
    if initial_graph is not None:
        for node in initial_graph.get("nodes", []):
            if not isinstance(node, dict):
                continue
            node_id = node.get("id")
            if isinstance(node_id, str):
                seeded = dict(node)
                # Old stored graphs can carry the fabricated ``"None"``; coerce so it can't win a rank merge.
                seeded["resolved_type"] = _coerce_resolved_type(seeded.get("resolved_type"))
                nodes[node_id] = cast(ResolvedGraphNode, seeded)
        for edge in initial_graph.get("edges", []):
            if not isinstance(edge, dict):
                continue
            edges[_edge_key(cast(ResolvedGraphEdge, edge))] = cast(ResolvedGraphEdge, dict(edge))
        # Analysed nested contracts are processed; the root re-walks so fresh role principals get projected.
        for node in initial_graph.get("nodes", []):
            if not isinstance(node, dict) or not node.get("analyzed"):
                continue
            node_address = (node.get("details") or {}).get("address")
            if isinstance(node_address, str):
                addr = node_address.lower()
                if addr and addr != root_address:
                    processed.add(addr)

    from services.concurrency import parallel_map

    def _materialize_for_pending(pending: PendingContract) -> tuple[LoadedArtifacts | None, BaseException | None]:
        """Materialize one pending contract.

        Returns ``(artifacts, error)`` so the main thread wires both branches deterministically.

        Storage failures propagate instead: they're about us, not the contract, and would hit every sibling. Degrading
        would let the walk finish so nothing retries; ``workers/retry_policy`` treats them as transient.
        """
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
                workspace_prefix=workspace_prefix,
                chain=chain_name,
                chain_id=chain_id,
            )
            return artifacts, None
        except (StorageContentIncomplete, StorageUnavailable):
            raise
        except Exception as exc:
            return None, exc

    _levels = 0
    while queue:
        # The queue is depth-ordered; drain the current depth as one concurrent level.
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

        # Cache misses are CPU-bound (Slither/solc/forge), so the cap tracks host vCPUs; 8 workers wedged a
        # shared-cpu-2x VM. Default 2 matches the smallest worker.
        materialize_fanout = max(1, int(os.getenv("PSAT_RESOLUTION_MATERIALIZE_FANOUT", "2")))
        materialized = parallel_map(
            _materialize_for_pending,
            level_pending,
            max_workers=materialize_fanout,
            heartbeat=heartbeat,
        )

        for pending, (_pending, outcome) in zip(level_pending, materialized):
            if isinstance(outcome, BaseException):
                # Only bugs and storage outages arrive here; both must reach the retrying stage.
                raise outcome
            artifacts, mat_exc = outcome
            address = pending["address"]
            depth = pending["depth"]

            if mat_exc is not None or artifacts is None:
                err_text = str(mat_exc) if mat_exc is not None else "no artifacts produced"
                contract_name = _contract_name_for_address(address, chain_id)
                record_degraded(
                    phase="recursive_materialize",
                    exc=mat_exc if mat_exc is not None else RuntimeError(err_text),
                    context={"address": address, "depth": depth},
                )
                logger.warning(
                    "Recursive resolve: failed to materialize nested contract %s at depth %s: %s",
                    address,
                    depth,
                    err_text,
                )
                _ensure_node(
                    nodes,
                    address=address,
                    resolved_type="contract",
                    label=contract_name or address,
                    depth=depth,
                    node_type="contract",
                    analyzed=False,
                    contract_name=contract_name,
                    details={"address": address, "materialize_error": err_text},
                )
                processed.add(address)
                continue

            if address not in nested_artifacts:
                nested_artifacts[address] = artifacts

            processed.add(address)
            analysis = artifacts["analysis"]
            snapshot = artifacts["snapshot"]
            effective_permissions = artifacts.get("effective_permissions")
            subject = analysis.get("subject", {})
            contract_name = str(subject.get("name") or address)
            # Use the classifier's answer, not a hardcoded "contract", so analysed timelocks keep their type and
            # ``delay`` (a scoring input). Usually a cache hit.
            analyzed_type, analyzed_details = _cached_classify(address)
            node_details: dict[str, object] = {"address": address}
            if analyzed_type in {"", "unknown"}:
                # Generic rank, so it can't overwrite a specific type set elsewhere.
                analyzed_type = "contract"
            else:
                node_details.update(analyzed_details)
            contract_node_id = _ensure_node(
                nodes,
                address=address,
                resolved_type=analyzed_type,
                label=contract_name,
                depth=depth,
                node_type="contract",
                contract_name=contract_name,
                analyzed=True,
                details=node_details,
                artifacts={"data_key": f"recursive:{address.lower()}"},
            )

            # Bounded enumeration reports truncation via ``status``.
            mapping_specs = _mapping_writer_specs_from_predicate_trees(artifacts.get("predicate_trees"))
            if mapping_specs:
                enumeration_status = _replay_mapping_principals(
                    address=address,
                    mapping_specs=mapping_specs,
                    contract_node_id=contract_node_id,
                    depth=depth,
                    nodes=nodes,
                    edges=edges,
                    chain_id=chain_id,
                )
                # So downstream can flag incomplete allowlists.
                if contract_node_id in nodes:
                    nodes[contract_node_id]["details"]["mapping_enumeration_status"] = enumeration_status

            for controller_id, controller_value in snapshot.get("controller_values", {}).items():
                controller_address = str(controller_value.get("value", "")).lower()
                if not controller_address.startswith("0x") or len(controller_address) != 42:
                    continue
                resolved_type = _coerce_resolved_type(controller_value.get("resolved_type"))
                details = dict(controller_value.get("details", {}))
                controller_label = str(controller_value.get("source") or controller_id)
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
                # Called-only slots aren't controllers. Absent provenance gets the unattributed relation:
                # ``controller_value`` would claim unproven authority (constants and non-authority mappings got enrolled
                # this way) and ``external_call_target`` the opposite. This isn't demoting a proven authority.
                provenance = controller_value.get("authority_provenance")
                if provenance == _PROVENANCE_CALL_TARGET:
                    relation = EDGE_RELATION_EXTERNAL_CALL_TARGET
                elif provenance == _PROVENANCE_CALLER_GATE:
                    relation = EDGE_RELATION_CONTROLLER_VALUE
                else:
                    relation = EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED
                _add_edge(
                    edges,
                    {
                        "from_id": contract_node_id,
                        "to_id": controller_node_id,
                        "relation": relation,
                        "label": controller_label,
                        "source_controller_id": controller_id,
                        "notes": [
                            f"resolved_type={resolved_type}",
                            f"authority_provenance={provenance or 'not_determined'}",
                        ],
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
                    from_node_id=controller_node_id,
                    source_controller_id=controller_id,
                    resolved_type=resolved_type,
                    details=details,
                    depth=depth + 1,
                    max_depth=max_depth,
                    classify_fn=_cached_classify,
                    chain_id=chain_id,
                )

            for principal_value in _role_principals_from_effective_permissions(effective_permissions or {}):
                principal_address = str(principal_value["address"]).lower()
                if principal_address == address:
                    continue
                resolved_type = _coerce_resolved_type(principal_value.get("resolved_type"))
                details = dict(principal_value["details"])
                if resolved_type == "unknown":
                    resolved_type, classified_details = _cached_classify(principal_address)
                    merged_details = dict(details)
                    merged_details.update(classified_details)
                    details = merged_details

                node_type = "contract" if resolved_type in ANALYZABLE_TYPES else "principal"
                backlink = _maybe_probe_backlink(
                    rpc_url,
                    principal_address=principal_address,
                    gated_contract_address=address,
                    details=details,
                    node_type=node_type,
                    chain_id=chain_id,
                )
                if backlink is not None:
                    details = {**details, "gated_contract_backlink": backlink}
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
                    from_node_id=principal_node_id,
                    source_controller_id=None,
                    resolved_type=resolved_type,
                    details=details,
                    depth=depth + 1,
                    max_depth=max_depth,
                    classify_fn=_cached_classify,
                    chain_id=chain_id,
                )

    # Orchestration profile (levels, contracts, classify cache); per-contract static cost is in ``pipeline_profile``.
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

    for _node in nodes.values():
        _node["analysis_state"] = _analysis_state(_node, max_depth)

    graph: ResolvedControlGraph = {
        "schema_version": "0.1",
        "root_contract_address": root_address,
        "max_depth": max_depth,
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges.values(), key=lambda item: (item["from_id"], item["relation"], item["to_id"])),
    }
    return graph, nested_artifacts
