from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from db.models import EffectiveFunction, FunctionPrincipal
from schemas.control_tracking import ResolvedControllerType

# ``contract`` and unresolved types are non-terminal way-points; reading them as settled principals was the over-claim
# bug.
TERMINAL_PRINCIPAL_TYPES: frozenset[ResolvedControllerType] = frozenset(
    {"safe", "eoa", "zero", "timelock", "proxy_admin", "cross_chain_authority"}
)

# Deeper chains signal loops or pathological factories; stop at ``unknown``.
DEFAULT_TERMINAL_MAX_DEPTH = 4

# Owner/authority/admin. Bounds branching to stay linear; a plane that forks again fails closed.
_MAX_CONTROLLER_PLANES = 3

# Getters the resolver probes (a test pins them to ``tracking._CONTROLLER_GETTER_SIGS``); the basis of
# ``controllers_not_determined``. Their silence proves nothing: PauserRegistry (``unpauser()``), stETH (``kernel()``),
# Curve admins and ERC-1967 proxies are invisible to them.
CANONICAL_CONTROLLER_GETTERS: tuple[str, ...] = ("owner", "authority", "admin")


def is_terminal_principal_type(resolved_type: str | None) -> bool:
    """``contract`` and unresolved types must never read as a resolved key."""
    return (resolved_type or "").lower() in TERMINAL_PRINCIPAL_TYPES


def resolve_terminal_principal(
    start_address: str,
    start_type: str | None,
    *,
    resolve_controllers: Callable[[str], Sequence[Mapping[str, Any]] | None],
    max_depth: int = DEFAULT_TERMINAL_MAX_DEPTH,
) -> dict[str, Any]:
    """Walk a ``resolved_type=contract`` principal to its ultimate Safe/EOA.

    ``resolve_controllers(address)`` returns classified controllers, ``[]`` when every canonical getter named none
    (silence, not absence), or ``None`` on probe error. It's the only wire, so the walk is pure.

    Returns ``{terminal, resolved_type, address, chain, status}``. Every non-``terminated`` outcome fails closed to
    ``terminal=False`` / ``resolved_type="unknown"``. Statuses:

    * ``terminated`` — reached a ``TERMINAL_PRINCIPAL_TYPES`` member.
    * ``cycle`` / ``depth_exceeded`` — bounded-walk outcomes.
    * ``multi_plane`` / ``ambiguous_controllers`` — parallel control planes (below).
    * ``controllers_not_determined`` — all canonical getters silent at ``undetermined_at`` (basis in ``probes_silent``).
    Retryable only with a wider probe basis.
    * ``unknown_unfetched`` — probe error or unusable steps; retryable.
    * ``no_controller`` — proven absence. Declared but unmintable: no available basis can prove it (WETH9 looks like a
    non-canonically-governed contract). Nothing may mint it until a real proof basis exists.

    Multiple distinct controllers (Solmate ``Auth``: ``owner`` and ``authority``) yield ``multi_plane`` with each plane
    walked separately in ``planes``, never collapsed (that's the scorer's call). A plane that forks again fails
    ``ambiguous_controllers``, keeping work linear.
    """
    start = (start_address or "").lower()
    if is_terminal_principal_type(start_type):
        return {
            "terminal": True,
            "resolved_type": str(start_type),
            "address": start or None,
            "chain": [start] if start else [],
            "status": "terminated",
        }

    # Shared ceiling so branching can't blow up total work.
    budget = [max(1, max_depth) * (1 + _MAX_CONTROLLER_PLANES)]
    return _walk_terminal(
        start,
        resolve_controllers,
        seen={start} if start else set(),
        chain=[start] if start else [],
        max_depth=max_depth,
        budget=budget,
        allow_branch=True,
    )


def _distinct_controllers(steps: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    distinct: dict[str, Mapping[str, Any]] = {}
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        addr = str(step.get("address", "")).lower()
        if addr.startswith("0x") and len(addr) == 42:
            distinct.setdefault(addr, step)
    return distinct


def _walk_terminal(
    current: str,
    resolve_controllers: Callable[[str], Sequence[Mapping[str, Any]] | None],
    *,
    seen: set[str],
    chain: list[str],
    max_depth: int,
    budget: list[int],
    allow_branch: bool,
) -> dict[str, Any]:
    """``allow_branch`` permits the one multi-plane branch at top level; inside a plane a fork fails closed."""

    def _unknown(status: str, **extra: Any) -> dict[str, Any]:
        return {
            "terminal": False,
            "resolved_type": "unknown",
            "address": None,
            "chain": chain,
            "status": status,
            **extra,
        }

    for _ in range(max(1, max_depth)):
        if budget[0] <= 0:
            return _unknown("depth_exceeded")
        budget[0] -= 1
        steps = resolve_controllers(current)
        if steps is None:
            return _unknown("unknown_unfetched")
        if not steps:
            # Silence, not absence (see the status taxonomy). Attributed to the silent hop: earlier hops may carry real
            # controllers.
            return _unknown(
                "controllers_not_determined",
                probes_silent=list(CANONICAL_CONTROLLER_GETTERS),
                undetermined_at=current,
            )
        distinct = _distinct_controllers(steps)
        if not distinct:
            return _unknown("unknown_unfetched")
        if len(distinct) > 1:
            controllers = list(distinct.keys())
            if not allow_branch:
                return _unknown("ambiguous_controllers", controllers=controllers)
            return _branch_planes(distinct, resolve_controllers, seen, chain, max_depth, budget)

        next_address, step = next(iter(distinct.items()))
        next_type = str(step.get("resolved_type", "unknown") or "unknown")
        if next_address in seen:
            chain.append(next_address)
            return _unknown("cycle")
        seen.add(next_address)
        chain.append(next_address)
        if is_terminal_principal_type(next_type):
            return {
                "terminal": True,
                "resolved_type": next_type,
                "address": next_address,
                "chain": chain,
                "status": "terminated",
            }
        if next_type != "contract":
            return _unknown("unknown_unfetched")
        current = next_address

    return _unknown("depth_exceeded")


def _branch_planes(
    distinct: dict[str, Mapping[str, Any]],
    resolve_controllers: Callable[[str], Sequence[Mapping[str, Any]] | None],
    parent_seen: set[str],
    parent_chain: list[str],
    max_depth: int,
    budget: list[int],
) -> dict[str, Any]:
    planes: list[dict[str, Any]] = []
    for controller_address, step in distinct.items():
        controller_type = str(step.get("resolved_type", "unknown") or "unknown")
        if is_terminal_principal_type(controller_type):
            record: dict[str, Any] = {
                "terminal": True,
                "resolved_type": controller_type,
                "address": controller_address,
                "chain": [controller_address],
                "status": "terminated",
            }
        elif controller_type == "contract":
            # Per-plane seen-set so a plane detects cycles into the prefix but two planes converging isn't a cycle.
            record = _walk_terminal(
                controller_address,
                resolve_controllers,
                seen=set(parent_seen) | {controller_address},
                chain=[controller_address],
                max_depth=max_depth,
                budget=budget,
                allow_branch=False,
            )
        else:
            record = {
                "terminal": False,
                "resolved_type": "unknown",
                "address": None,
                "chain": [controller_address],
                "status": "unknown_unfetched",
            }
        planes.append({"controller": controller_address, "terminal_record": record})

    return {
        "terminal": False,
        "resolved_type": "unknown",
        "address": None,
        "chain": parent_chain,
        "status": "multi_plane",
        "controllers": list(distinct.keys()),
        "planes": planes,
    }


def _function_principal_payload(
    fp: FunctionPrincipal,
    principal_lookup: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    address = fp.address
    lookup = principal_lookup.get(address.lower()) if principal_lookup and address else None
    resolved_type = fp.resolved_type
    details = dict(lookup.get("details") or {}) if lookup else {}
    if isinstance(fp.details, dict):
        details.update(fp.details)

    if lookup:
        lookup_type = lookup.get("resolved_type")
        if lookup_type and resolved_type in (None, "", "unknown", "contract"):
            resolved_type = str(lookup_type)

    payload = {
        "address": fp.address,
        "resolved_type": resolved_type,
        "source_controller_id": fp.origin,
        "principal_type": fp.principal_type,
        "details": details,
        # ``terminal_principal`` is a dormant passthrough: the walk persists only on ``principal_labels.details`` today.
        "terminal": is_terminal_principal_type(resolved_type),
    }
    terminal_principal = details.get("terminal_principal")
    if isinstance(terminal_principal, Mapping):
        payload["terminal_principal"] = dict(terminal_principal)
    if lookup and lookup.get("label"):
        payload["label"] = lookup["label"]
    return payload


def _is_generic_authority_contract_principal(principal: dict[str, Any]) -> bool:
    details = principal.get("details")
    return (
        principal.get("resolved_type") == "contract"
        and isinstance(details, dict)
        and bool(details.get("authority_kind"))
    )


def _role_value_from_origin(origin: str | None) -> int | str:
    prefix = "role "
    if not origin:
        return "?"
    if origin.startswith(prefix):
        suffix = origin[len(prefix) :]
        if suffix.isdigit():
            return int(suffix)
        return suffix or "?"
    return origin


def _enriched_role_grant(grant: Mapping[str, Any], classified_by_address: Mapping[str, Mapping[str, Any]]) -> dict:
    """One ``authority_roles`` grant with principals filled from this row's classified FP payload.

    Consumers dedup by address keeping the first record (``protocolScore.collectPrincipals`` reads grants first), so a
    bare grant would make the principal look less resolved.

    ``details`` merges key-wise with classified keys on top: the grant always carries a ``source`` marker, and wholesale
    override erased Safe ``owners``/``threshold`` and timelock ``delay``, dropping the principal to the 0.55 unknown
    floor.
    """
    principals: list[Any] = []
    for principal in grant.get("principals") or []:
        if not isinstance(principal, dict):
            principals.append(principal)
            continue
        classified = classified_by_address.get(str(principal.get("address", "")).lower())
        if not classified:
            principals.append(dict(principal))
            continue
        merged = dict(classified)
        merged.update({key: value for key, value in principal.items() if value is not None and key != "details"})
        grant_details = principal.get("details")
        classified_details = classified.get("details")
        if isinstance(grant_details, dict) and isinstance(classified_details, dict):
            merged["details"] = {**grant_details, **classified_details}
        elif classified_details is not None:
            merged["details"] = classified_details
        elif grant_details is not None:
            merged["details"] = grant_details
        principals.append(merged)
    return {**dict(grant), "principals": principals}


def _build_company_function_entry(
    ef: EffectiveFunction,
    principals: list[FunctionPrincipal],
    principal_lookup: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    direct_owner = None
    controllers_by_label: dict[str, dict[str, Any]] = {}
    authority_roles_by_key: dict[str, dict[str, Any]] = {}
    signature_witnesses: list[dict[str, Any]] = []

    for fp in principals:
        principal_dict = _function_principal_payload(fp, principal_lookup)

        if fp.principal_type == "direct_owner":
            if direct_owner is None:
                direct_owner = principal_dict
            continue

        if fp.principal_type == "signature_witness":
            signature_witnesses.append(principal_dict)
            continue

        if fp.principal_type == "authority_role":
            role_value = _role_value_from_origin(fp.origin)
            role_entry = authority_roles_by_key.setdefault(
                str(role_value),
                {
                    "role": role_value,
                    "principals": [],
                },
            )
            role_entry["principals"].append(principal_dict)
            continue

        label = fp.origin or "controller"
        controller_entry = controllers_by_label.setdefault(
            label,
            {
                "label": label,
                "controller_id": label,
                "source": label,
                "principals": [],
            },
        )
        controller_entry["principals"].append(principal_dict)

    # The column decides all three states (principal_type is always ``controller``). Seeding with a list published the
    # column's ``None`` as ``[]``: /functions served 0 nulls where the pool held 324, contradicting /api/analyses.
    authority_roles: Any
    witnessed_roles = list(authority_roles_by_key.values())
    if witnessed_roles:
        authority_roles = witnessed_roles
    elif ef.authority_roles:
        classified_by_address: dict[str, dict[str, Any]] = {}
        for controller_entry in controllers_by_label.values():
            for principal in controller_entry.get("principals", []):
                address = str((principal or {}).get("address", "")).lower()
                if address:
                    classified_by_address.setdefault(address, principal)
        enriched = [
            _enriched_role_grant(grant, classified_by_address)
            for grant in ef.authority_roles
            if isinstance(grant, dict)
        ]
        # Non-empty but unreadable is not determined, not proven absent.
        authority_roles = enriched or None
    else:
        authority_roles = ef.authority_roles

    controllers = list(controllers_by_label.values())
    has_more_specific_controller = any(
        any(not _is_generic_authority_contract_principal(principal) for principal in entry.get("principals", []))
        for entry in controllers
    )
    if has_more_specific_controller:
        controllers = [
            entry
            for entry in controllers
            if not entry.get("principals")
            or not all(_is_generic_authority_contract_principal(principal) for principal in entry["principals"])
        ]

    # Function-level: ``services.aggregations`` imports ``company_overview``, which imports this module (pinned by
    # test_policy_first_import_order).
    from services.aggregations.action_summary import describe_action

    _action_summary_text, _action_summary_kind, _action_summary_note = describe_action(
        ef.action_summary, getattr(ef, "claims", None), ef.effect_labels
    )
    entry: dict[str, Any] = {
        "function": ef.abi_signature or ef.function_name,
        "selector": ef.selector,
        "effect_labels": list(ef.effect_labels or []),
        "effect_targets": list(ef.effect_targets or []),
        "claims": list(getattr(ef, "claims", None) or []),
        # See services/aggregations/action_summary.
        "action_summary": _action_summary_text,
        "action_summary_kind": _action_summary_kind,
        "action_summary_note": _action_summary_note,
        "authority_public": ef.authority_public,
        # Null when the row predates the column.
        "authority_openness": getattr(ef, "authority_openness", None),
        "controllers": controllers,
        # Same three states analysis_detail publishes; see the fold above.
        "authority_roles": authority_roles,
        "direct_owner": direct_owner,
        "signature_witnesses": signature_witnesses,
    }

    capability_expr = getattr(ef, "capability_expr", None)
    if capability_expr is not None:
        entry["capability_expr"] = capability_expr
    conditions = getattr(ef, "conditions", None)
    if conditions is not None:
        entry["conditions"] = conditions
    status = getattr(ef, "status", None)
    if status is not None:
        entry["status"] = status

    return entry
