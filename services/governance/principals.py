"""Principal/effective-function shaping for governance views."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from db.models import EffectiveFunction, FunctionPrincipal
from schemas.observations import ResolvedControllerType

# A principal is *terminal* when its resolved_type names a settled controlling
# key or a recognized governance primitive (Safe / EOA / zero / timelock /
# proxy_admin / cross-chain authority). A plain ``contract`` — and any unresolved
# (``unknown``/``None``) — is NON-terminal: a way-point whose ultimate controlling
# key is not yet established. Marking these non-terminal is the guard against the
# over-claim bug where a ``resolved_type=contract`` row reads as a *settled*
# principal to a consumer when the real key is still unknown: the absence of a
# proven positive is never itself a proven fact.
TERMINAL_PRINCIPAL_TYPES: frozenset[ResolvedControllerType] = frozenset(
    {"safe", "eoa", "zero", "timelock", "proxy_admin", "cross_chain_authority"}
)

# Depth bound for the contract-principal terminal walk. A control chain deeper
# than this in practice signals a loop or a pathological factory graph; we stop
# and emit ``unknown`` rather than spin. Cycles are caught independently by the
# seen-set, so this only bounds genuinely-long acyclic chains.
DEFAULT_TERMINAL_MAX_DEPTH = 4

# Owner/authority/admin — the maximum number of parallel control planes a single
# contract step can expose. Bounds the shared step budget so multi-plane
# branching stays linear (pre-branch hops + one bounded walk per plane), never
# exponential: a plane that itself forks fails closed instead of re-branching.
_MAX_CONTROLLER_PLANES = 3

# The canonical control getters the production resolver probes
# (services/resolution/tracking._CONTROLLER_GETTER_SIGS derives its signatures
# from these names; a test pins the two in sync). Named here because the walk
# publishes them as the BASIS of a ``controllers_not_determined`` record:
# silence from this finite probe set is evidence that THESE getters named
# nothing — never proof that no controller exists. Chain-verified
# counterexamples with the same silent-probes outcome: a PauserRegistry
# controlled via ``unpauser()``, Lido's stETH via ``kernel()``, Curve admin
# planes via ``ownership_admin()``/``emergency_admin()``, and transparent
# proxies via the ERC-1967 admin slot — all invisible to this set.
CANONICAL_CONTROLLER_GETTERS: tuple[str, ...] = ("owner", "authority", "admin")


def is_terminal_principal_type(resolved_type: str | None) -> bool:
    """Whether *resolved_type* names a settled controlling key / recognized
    governance primitive (see ``TERMINAL_PRINCIPAL_TYPES``). ``contract`` and
    any unresolved type are non-terminal — they must never read as a resolved
    key to a grade-bearing consumer."""
    return (resolved_type or "").lower() in TERMINAL_PRINCIPAL_TYPES


def resolve_terminal_principal(
    start_address: str,
    start_type: str | None,
    *,
    resolve_controllers: Callable[[str], Sequence[Mapping[str, Any]] | None],
    max_depth: int = DEFAULT_TERMINAL_MAX_DEPTH,
) -> dict[str, Any]:
    """Walk a ``resolved_type=contract`` principal to its ultimate Safe/EOA key.

    ``resolve_controllers(address)`` returns the *controllers* of ``address`` —
    a sequence of already-classified ``{"address", "resolved_type", "details"}``
    mappings (owner/authority/admin order), ``[]`` when every canonical getter
    (``CANONICAL_CONTROLLER_GETTERS``) answered cleanly and named none
    (probe-set SILENCE — see below, not proof of absence), or ``None`` when
    the planes could not be dispositively read (a probe error — not determined).
    The injected callable is the only wire this function
    touches (integration callers back it with on-chain owner reads + classify;
    unit tests stub it), so the walk itself is pure and deterministic.

    Returns a terminal record ``{terminal, resolved_type, address, chain,
    status}``. ``terminal`` is True only when a single-plane walk reached a member
    of ``TERMINAL_PRINCIPAL_TYPES``; every indeterminate outcome fails closed to
    ``terminal=False`` / ``resolved_type="unknown"`` — the ``indeterminate ->
    unknown`` fallback the witness bar requires, never a guessed key.

    **Status taxonomy** (the full vocabulary of ``status``; every consumer of
    ``terminal_principal`` reads from this list):

    * ``terminated`` — the walk reached a ``TERMINAL_PRINCIPAL_TYPES`` member.
    * ``cycle`` / ``depth_exceeded`` — bounded-walk fail-closed outcomes.
    * ``multi_plane`` / ``ambiguous_controllers`` — parallel control planes
      (see below).
    * ``controllers_not_determined`` — the resolver's canonical getters were
      ALL silent at the hop named by ``undetermined_at`` (basis recorded in
      ``probes_silent``). Silence from a finite probe set is evidence those
      getters named nothing, NEVER proof that no controller exists: contracts
      governed via non-canonical getters (``unpauser()``, ``kernel()``,
      Curve's ``*_admin()`` family) or the ERC-1967 admin slot produce exactly
      this outcome while demonstrably controlled. Not determined — retryable
      only with a wider probe basis.
    * ``unknown_unfetched`` — the planes could not be dispositively read (a
      transient probe error, or steps returned without a usable address) —
      not determined, retryable next run.
    * ``no_controller`` — a PROVEN absence of any controlling key. DECLARED
      BUT CURRENTLY UNMINTABLE: no producer exists, because no basis available
      to the resolver can earn it — the canonical-getter probe set can prove
      only what it probed, and a genuinely-ownerless contract (WETH9, the ETH2
      DepositContract) is indistinguishable from a non-canonically-governed
      one on that evidence. The member stays documented so a future producer
      with a real proof basis (and consumers) can adopt it; nothing may mint
      it until then (zero-realised by design).

    Every non-``terminated`` outcome fails closed to ``terminal=False`` /
    ``resolved_type="unknown"``, so nothing downstream can read it as a key.

    When a step exposes MORE THAN ONE distinct controller (Solmate/Solady
    ``Auth`` — ``owner`` AND ``authority`` are parallel live control planes), the
    walk does NOT name one as THE key; instead it walks EACH plane to its own
    terminal and returns ``status="multi_plane"``, ``terminal=False``, a flat
    ``controllers`` list (the immediate distinct controllers), and
    ``planes=[{"controller", "terminal_record"}, ...]`` carrying each plane's own
    walk so a weakest-path scorer can consume every plane. Planes are NOT
    collapsed to one key even when they converge — that's the scorer's call.
    Branching happens at most once: a plane that itself forks fails closed with
    ``status="ambiguous_controllers"`` (no sub-plane recursion), keeping total
    work linear in ``max_depth * (1 + planes)``.
    """
    start = (start_address or "").lower()
    if is_terminal_principal_type(start_type):
        # Already a settled key — nothing to walk.
        return {
            "terminal": True,
            "resolved_type": str(start_type),
            "address": start or None,
            "chain": [start] if start else [],
            "status": "terminated",
        }

    # Shared step ceiling across the pre-branch walk + every plane walk, so
    # branching can never blow up total work.
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
    """Distinct controller steps keyed by lowercased address, preserving the
    owner/authority/admin probe order (case-insensitive dedup)."""
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
    """One single-plane walk. ``allow_branch`` gates the ONE multi-plane branch:
    True on the top-level walk (a fork -> ``multi_plane`` with each plane walked),
    False inside a plane (a fork -> ``ambiguous_controllers`` fail-closed, no
    recursion)."""

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
            # The control planes could not be dispositively read (probe error) —
            # not-determined, retryable next run.
            return _unknown("unknown_unfetched")
        if not steps:
            # Every canonical getter answered cleanly and named nothing —
            # probe-set SILENCE, not proof of absence (see the status taxonomy:
            # unpauser()/kernel()/*_admin()/ERC-1967-admin contracts produce
            # exactly this outcome while demonstrably controlled). Published
            # with its basis, and attributed to the hop whose getters were
            # silent (``undetermined_at``) — on a multi-hop walk the chain may
            # already carry REAL controllers, so the status must not read as a
            # statement about the principal the record is published on.
            return _unknown(
                "controllers_not_determined",
                probes_silent=list(CANONICAL_CONTROLLER_GETTERS),
                undetermined_at=current,
            )
        distinct = _distinct_controllers(steps)
        if not distinct:
            # Steps were returned but none carried a usable address — fetched,
            # unusable: not-determined, never a proven absence.
            return _unknown("unknown_unfetched")
        if len(distinct) > 1:
            controllers = list(distinct.keys())
            if not allow_branch:
                # Nested fork inside a plane — fail this plane closed, do NOT
                # recurse into sub-planes (keeps total work bounded).
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
            # An intermediate that is neither a settled key nor a walkable
            # contract (e.g. an unresolved node) — stop honest, not guessed.
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
    """Walk each parallel control plane to its own terminal and package them for a
    weakest-path scorer — never collapsing to a single "the" key."""
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
            # Each plane gets its own seen-set (a copy of the pre-branch path) so a
            # plane can detect a cycle back into the walked prefix, while two planes
            # reaching the same key independently are NOT treated as a cross-cycle.
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
        # A contract (or unresolved) principal is a non-terminal way-point, not a
        # settled key — consumers must treat it as ``unknown`` terminal, never as
        # the controlling principal. ``terminal_principal`` is a
        # forward-compat passthrough: the terminal walk currently persists its
        # record on ``principal_labels.details`` only (join by address to get the
        # chain); nothing writes it into ``function_principals.details`` yet, so
        # this branch stays dormant until a writer merges it there.
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
    """One ``authority_roles`` grant from the COLUMN, with each principal filled
    in from this row's own classified ``FunctionPrincipal`` payload.

    The column's grants carry the role plus bare member ADDRESSES — the capability
    surface knows who holds the role, not what those addresses are (Safe / EOA /
    timelock). The same addresses are published under ``controllers`` fully
    classified, and every consumer that merges the two dedups by address keeping
    the FIRST record it sees (``protocolScore.collectPrincipals`` reads role
    grants before controllers). Publishing the bare record first would therefore
    make a role-granted principal read LESS resolved than the identical address
    under ``controllers`` — an unresolved-controller reading of an address whose
    type is known. Classified fields win.

    ``details`` is merged KEY-WISE with the classified keys on top, never
    replaced wholesale: the grant's ``details`` is always the non-None
    ``{"source": "semantic_capability:role_grant"}`` marker, so a blanket
    "grant's non-null fields override" erased the classified quorum/delay
    witness (a Safe's ``owners``/``threshold``, a timelock's ``delay``) from
    the exact record ``protocolScore.safeScore`` / ``principalLabel`` read
    first — publishing a recorded threshold as "not recorded" and dropping the
    principal to the 0.55 unknown floor.
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

    # Three states out, and the COLUMN decides all three whenever the principal
    # fold witnesses nothing (``principal_type`` is ``controller`` on 100% of
    # rows, so that is every row): a non-empty list is witnessed role grants,
    # ``None`` is role-gated with the role not determined, ``[]`` is proven not
    # role-gated. ``list(authority_roles_by_key.values())`` is a list on every
    # path, so seeding the result with it published the column's ``None`` as the
    # ``[]`` that NEGATES it — /api/company/{name}/functions served 0 nulls over
    # 1,109 ether.fi rows whose pool holds 324, contradicting
    # /api/analyses/{job} on the same rows. The two frontend coercers
    # (surface/layout/controlGraph.js, protocolScore.js) still fold to ``[]``
    # when they iterate, which is fine — a render loop publishes no verdict —
    # but the payload has to carry the true value for a scorer to read.
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
        # A non-empty column that enriches to nothing was unreadable, not proven
        # absent — the one way this branch could still mint the negating ``[]``.
        # 0 realised: no persisted row carries a non-object grant (measured
        # across every effective_functions row, jsonb_typeof(grant) <> 'object'
        # on 0 of the 210 non-empty ones).
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

    entry: dict[str, Any] = {
        "function": ef.abi_signature or ef.function_name,
        "selector": ef.selector,
        "claims": list(getattr(ef, "claims", None) or []),
        "authority_public": ef.authority_public,
        # See analysis_detail: the three-state verdict rides alongside the bool,
        # null when the row predates the column.
        "authority_openness": getattr(ef, "authority_openness", None),
        "controllers": controllers,
        # Three states, same as analysis_detail publishes for the same row: a
        # non-empty list is witnessed, ``None`` is role-gated with the role not
        # determined, ``[]`` is proven not role-gated. See the fold above.
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
