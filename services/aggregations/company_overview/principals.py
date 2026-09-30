from __future__ import annotations

from typing import Any

from db.models import Contract, ControlGraphNode, ControllerValue
from schemas.control_tracking import MonitoredContractType, ResolvedControllerType

_PRINCIPAL_TYPES: frozenset[ResolvedControllerType] = frozenset({"contract", "safe", "timelock", "eoa", "proxy_admin"})
_PRINCIPAL_TYPES_SQL = tuple(sorted(_PRINCIPAL_TYPES))

# Excludes ``contract`` (a way-point) and not-determined arms.
_SETTLED_CONTROLLER_TYPES: frozenset[ResolvedControllerType] = frozenset({"safe", "timelock", "eoa", "proxy_admin"})
# Governance mechanisms that are contracts; ``eoa`` can control but can't enroll. ``proxy_admin`` enrolls as
# ``"proxy"``.
_MONITORED_TYPE_FOR_CONTROLLER: dict[ResolvedControllerType, MonitoredContractType] = {
    "safe": "safe",
    "timelock": "timelock",
    "proxy_admin": "proxy",
}
_MONITORED_TYPE_LOOKUP: dict[str, MonitoredContractType] = {k: v for k, v in _MONITORED_TYPE_FOR_CONTROLLER.items()}
_PASSTHROUGH_CONTROLLER_TYPES: frozenset[ResolvedControllerType] = frozenset({"timelock", "proxy_admin"})

# Exact whitelist: the old ``"owner" in id`` substring matched ``pendingOwner`` etc., and Ownable2Step contracts latched
# the pending owner.
_ACTIVE_OWNER_CONTROLLER_IDS = frozenset(
    {
        "owner",
        "_owner",
        "state_variable:owner",
        "state_variable:_owner",
    }
)


def _is_active_owner_controller(controller_id: str | None) -> bool:
    return (controller_id or "").lower() in _ACTIVE_OWNER_CONTROLLER_IDS


def _trim_control_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Drop mapping-entry leaf nodes and edges to them.

    The frontend walker (``controlGraph.js``) shows any non-contract edge target as an indirect principal; mapping
    contents (validator addresses in ``EtherFiNodesManager``) are data, not principals, and cost ~900 KB. A node is
    dropped iff it isn't a principal type and never sources an edge.
    """
    sources = {(e.get("from") or "").lower() for e in edges}
    dropped: set[str] = set()
    kept_nodes: list[dict[str, Any]] = []
    for n in nodes:
        addr = (n.get("address") or "").lower()
        if (n.get("type") in _PRINCIPAL_TYPES) or (addr in sources):
            kept_nodes.append(n)
        else:
            dropped.add(addr)
    if not dropped:
        return {"nodes": nodes, "edges": edges}
    kept_edges = [e for e in edges if (e.get("to") or "").lower() not in dropped]
    return {"nodes": kept_nodes, "edges": kept_edges}


def _has_timelock_delay(details: Any) -> bool:
    if not isinstance(details, dict):
        return False
    for key in ("delay", "delay_seconds", "min_delay"):
        value = details.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and value > 0:
            return True
        if isinstance(value, str) and value.isdigit() and int(value) > 0:
            return True
    return False


def _principal_lookup_type(resolved_type: str | None, details: Any) -> str | None:
    normalized = (resolved_type or "").lower()
    if normalized in _SETTLED_CONTROLLER_TYPES:
        return normalized
    if _has_timelock_delay(details):
        return "timelock"
    if normalized == "contract":
        return "contract"
    return None


def _principal_type_priority(resolved_type: str | None) -> int:
    if resolved_type in _SETTLED_CONTROLLER_TYPES:
        return 3
    if resolved_type == "contract":
        return 1
    return 0


def _record_principal_lookup(
    lookup: dict[str, dict[str, Any]],
    *,
    address: str | None,
    resolved_type: str | None,
    label: str | None,
    details: Any,
) -> None:
    if not address or not address.startswith("0x"):
        return
    details_dict = dict(details) if isinstance(details, dict) else {}
    principal_type = _principal_lookup_type(resolved_type, details_dict)
    if not principal_type:
        return

    addr = address.lower()
    current = lookup.setdefault(addr, {"resolved_type": principal_type, "details": {}})
    current_priority = _principal_type_priority(current.get("resolved_type"))
    principal_priority = _principal_type_priority(principal_type)
    if principal_priority > current_priority:
        current["resolved_type"] = principal_type
    if label and not current.get("label"):
        current["label"] = label

    merged_details = dict(current.get("details") or {})
    if principal_priority >= current_priority:
        merged_details.update(details_dict)
    merged_details.setdefault("address", addr)
    current["details"] = merged_details


def _build_principal_lookup(
    contracts_by_job_id: dict[Any, Contract],
    controller_values_by_cid: dict[int, list[ControllerValue]],
    cgn_by_cid: dict[int, list[ControlGraphNode]],
    terminal_walk_by_address: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    seen_contract_ids: set[int] = set()

    for contract in contracts_by_job_id.values():
        if not contract or contract.id in seen_contract_ids:
            continue
        seen_contract_ids.add(contract.id)
        summary = contract.summary
        # Only a proven timelock earns the settled ``timelock`` type; NULL falls to the weak ``contract`` way-point.
        contract_type = "timelock" if summary is not None and summary.has_timelock is True else "contract"
        _record_principal_lookup(
            lookup,
            address=contract.address,
            resolved_type=contract_type,
            label=contract.contract_name,
            details={},
        )

    for values in controller_values_by_cid.values():
        for cv in values:
            _record_principal_lookup(
                lookup,
                address=cv.value,
                resolved_type=cv.resolved_type,
                label=cv.source or cv.controller_id,
                details=cv.details,
            )

    for nodes in cgn_by_cid.values():
        for node in nodes:
            _record_principal_lookup(
                lookup,
                address=node.address,
                resolved_type=node.resolved_type,
                label=node.contract_name or node.label,
                details=node.details,
            )

    # Forward the terminal-controller walk from ``principal_labels`` for ``terminalControllerNote``. Deliberately
    # narrow:
    #
    # * Only ``terminal_principal``: forwarding ``terminal`` could publish a settled key beside a ``resolved_type``
    # still saying ``contract``.
    # * Only addresses the lookup already carries, so the principal set doesn't widen.
    # * ``setdefault``, so a record arriving with a CGN/CV row wins.
    #
    # Status vocabulary lives in ``services.governance.principals``; pre-fix rows may carry ``no_controller``, which
    # renders as unresolved too.
    for address, record in (terminal_walk_by_address or {}).items():
        entry = lookup.get(address)
        if entry is None:
            continue
        details = dict(entry.get("details") or {})
        details.setdefault("terminal_principal", record)
        entry["details"] = details

    return lookup


def _principal_lookup_meta(
    principal_lookup: dict[str, dict[str, Any]],
    address: str | None,
    details: Any = None,
) -> dict[str, Any]:
    lookup = principal_lookup.get((address or "").lower(), {})
    merged_details = dict(lookup.get("details") or {})
    if isinstance(details, dict):
        merged_details.update(details)
    return {
        "resolved_type": lookup.get("resolved_type"),
        "label": lookup.get("label"),
        "details": merged_details,
    }


def _claim_ids_list(claims: Any) -> list[str]:
    if not isinstance(claims, list):
        return []
    out: list[str] = []
    for claim in claims:
        if isinstance(claim, dict):
            cid = claim.get("claim_id")
            if isinstance(cid, str) and cid:
                out.append(cid)
    return out
