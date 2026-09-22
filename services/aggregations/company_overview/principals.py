"""Governance principal vocabulary + principal-lookup assembly."""

from __future__ import annotations

from typing import Any

from db.models import Contract, ControlGraphNode, ControllerValue
from schemas.observations import MonitoredContractType, ResolvedControllerType

_PRINCIPAL_TYPES: frozenset[ResolvedControllerType] = frozenset({"contract", "safe", "timelock", "eoa", "proxy_admin"})
_PRINCIPAL_TYPES_SQL = tuple(sorted(_PRINCIPAL_TYPES))

# Settled controlling-key kinds: a concrete controller identity. Excludes
# ``contract`` (a way-point whose ultimate key is unestablished) and the
# not-determined arms.
_SETTLED_CONTROLLER_TYPES: frozenset[ResolvedControllerType] = frozenset({"safe", "timelock", "eoa", "proxy_admin"})
# Governance mechanisms that are themselves CONTRACTS. Excludes ``eoa``
# deliberately: a bare key can control, but it is not an enrollable contract.
# ``proxy_admin`` enrolls under the historical ``"proxy"`` contract_type.
_MONITORED_TYPE_FOR_CONTROLLER: dict[ResolvedControllerType, MonitoredContractType] = {
    "safe": "safe",
    "timelock": "timelock",
    "proxy_admin": "proxy",
}
# str-keyed view: governance principal dicts are untyped at this boundary.
_MONITORED_TYPE_LOOKUP: dict[str, MonitoredContractType] = {k: v for k, v in _MONITORED_TYPE_FOR_CONTROLLER.items()}
# Mechanisms that interpose on a governed call path (delay / admin hop) —
# a passthrough entity is attributed to what sits behind it.
_PASSTHROUGH_CONTROLLER_TYPES: frozenset[ResolvedControllerType] = frozenset({"timelock", "proxy_admin"})

# ControllerValue.controller_id values that denote a contract's *active*
# owner. The substring heuristic ``"owner" in controller_id.lower()`` used
# to drive this and false-positives on ``pendingOwner``, ``previousOwner``,
# ``roleOwner``, ``ownerFee``, etc. Combined with last-write-wins
# assignment in the CV iteration, OZ Ownable2Step contracts (both
# ``owner()`` and ``pendingOwner()`` tracked) routinely latched the
# not-yet-accepted pending owner — and the wrong owner cascaded into the
# ownership hierarchy and the controls/controls_value fund flow.
#
# Exact whitelist instead. Covers the canonical Ownable variants: bare
# state-var name (``owner`` / ``_owner``) and the prefixed
# ``state_variable:`` form the tracker emits today.
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
    """Drop mapping-entry leaf nodes (and edges pointing at them) from a
    contract's local control_graph.

    The frontend walker in ``site/src/surface/layout/controlGraph.js``
    emits any non-contract ``to`` of an edge from a reachable source as
    an "indirect principal" in the function inspector. Contracts like
    ``EtherFiNodesManager`` store hundreds of validator addresses in a
    mapping; those addresses end up as nodes of ``type:"unknown"`` with
    labels like ``"deployedEtherFiNodes"``. They are not principals —
    they are stored EVM data — and they balloon the payload (~900 KB
    on ether.fi) while filling the inspector with noise.

    A node is dropped iff its type is not a recognised principal AND it
    never appears as the source of any edge in this contract's local
    edges list (so the walker can never recurse out of it). All edges
    targeting a dropped node are dropped with it so the walker never
    emits a ghost entry.
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
        # ``is True``: the column is three-state, and only a proven timelock earns
        # the strong ``timelock`` type (priority 3, a settled key for
        # ``terminalControllerNote``). A NULL or a missing row falls to
        # ``contract`` — the WEAK, non-terminal way-point type — so the
        # not-determined case cannot be promoted into a settled controller.
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

    # The terminal-controller walk, forwarded from ``principal_labels`` — the only
    # place it is persisted. Its one correct consumer,
    # ``claimsVocab.terminalControllerNote`` (rendered by ``InspectorCard``),
    # handles all six statuses and could never receive the data.
    #
    # Deliberately narrow, and it is the narrowness that keeps this attributable:
    #
    # * ONLY ``terminal_principal`` is forwarded. ``principal_labels.details`` also
    #   carries ``terminal``, ``signer_overlap`` and ``shared_deployer``, and
    #   forwarding ``terminal`` would let one plane's typing publish a SETTLED key
    #   (``terminalControllerNote`` returns null on ``terminal === true``) beside a
    #   ``resolved_type`` from another plane that still says ``contract`` — an
    #   inconsistent record, and in the reassuring direction. The other two are
    #   attribution facts with their own hedged copy and their own review.
    # * only addresses the lookup ALREADY carries are annotated. Admitting new
    #   addresses would widen the published principal set, which is a different
    #   change from connecting the renderer.
    # * ``setdefault``, so a record already merged in from a CGN/CV ``details``
    #   payload wins — this pass adds the fact where it is missing, never
    #   overwrites one that arrived with the row.
    #
    # Status vocabulary: see ``services.governance.principals`` (the single
    # declaration point). Non-terminated statuses all render through
    # ``terminalControllerNote``'s honest "unresolved (<status>)" fall-through,
    # including ``controllers_not_determined`` — the canonical-getter-silence
    # state that replaced the refuted ``no_controller`` proven-absence claim
    # (persisted pre-fix rows may still carry the old token until the next
    # policy run rewrites them; the renderer folds it into the same unresolved
    # copy, so no reader can mistake either for a settled key).
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
    """``claim_id`` strings from a stored ``EffectiveFunction.claims`` JSONB list
    (``[{claim_id, tier, witness}, ...]``); anything else reads as empty."""
    if not isinstance(claims, list):
        return []
    out: list[str] = []
    for claim in claims:
        if isinstance(claim, dict):
            cid = claim.get("claim_id")
            if isinstance(cid, str) and cid:
                out.append(cid)
    return out
