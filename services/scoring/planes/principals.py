"""The principal plane: who a function_principals row resolves to."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func as sql_func
from sqlalchemy.orm import Session

from services.scoring.planes._shared import _chain_name, _float, _lower
from services.scoring.schema import coalesce_chain, entity_key

# Confined to the I/O-EDGE loaders in this module — the handlers that swallow a
# database error while reading a plane. The resolution work itself publishes
# every refusal into the document (inv. 11/12: the fold must replay from the
# document alone), so nothing on a compute path logs. These WARNINGs carry no
# ``record_degraded`` because no accumulator is bound here today: the fold runs
# on the score loop's monitor thread and under the offline CLI, and the call
# would be a permanent no-op rather than a record of anything.
logger = logging.getLogger("services.scoring.planes")


@dataclass
class PrincipalFacts:
    function_principal_id: int
    chain: str
    address: str
    resolved_type: str | None
    owners: frozenset[str]
    threshold: int | None
    delay_seconds: float | None
    protection_credit_withheld: bool
    protection_basis: str
    resolver_bases: tuple[str, ...]
    role_bindings: tuple[tuple[str, str], ...]

    @property
    def key(self) -> str:
        return entity_key(self.chain, self.address)


def load_principal_plane(session: Session, refs: list[Any]) -> dict[int, PrincipalFacts]:
    """``function_principals`` rows behind the signals' references."""
    from db.models import FunctionPrincipal

    ids = sorted({int(ref.function_principal_id) for ref in refs})
    if not ids:
        return {}
    chain_by_id: dict[int, str] = {}
    for ref in refs:
        chain_by_id.setdefault(int(ref.function_principal_id), ref.chain)
    rows = session.query(FunctionPrincipal).filter(FunctionPrincipal.id.in_(ids)).order_by(FunctionPrincipal.id).all()
    out: dict[int, PrincipalFacts] = {}
    for row in rows:
        details = row.details if isinstance(row.details, dict) else {}
        withheld, basis = _safe_protection_verdict(details)
        out[row.id] = PrincipalFacts(
            function_principal_id=row.id,
            chain=coalesce_chain(chain_by_id.get(row.id)),
            address=_lower(row.address),
            resolved_type=row.resolved_type,
            owners=frozenset(_lower(o) for o in (details.get("owners") or []) if o),
            threshold=_int(details.get("threshold")),
            delay_seconds=_float(details.get("delay")),
            protection_credit_withheld=withheld,
            protection_basis=basis,
            resolver_bases=_resolver_bases(details),
            role_bindings=_role_bindings(details),
        )
    return out


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_protection_verdict(details: dict[str, Any]) -> tuple[bool, str]:
    """Whether the k/n demotion is WITHHELD, and on what basis.

    k/n is an upper bound on protection, and only a PROVEN bypass denies the
    credit: a witnessed module (``protection_is_upper_bound`` true, or an
    enumerated non-empty module set) or a witnessed guard address. Everything
    else — an absent plane, an unreadable head word, a basis that proves nothing
    — leaves the credit standing, annotated. Withholding on an unreadable witness
    would be a demotion claim minted from an absence, which the ruling for this
    plane forbids in both directions.
    """
    protection = details.get("safe_protection")
    if not isinstance(protection, dict):
        return False, "safe_protection_absent(not_determined);credit_stands"
    if protection.get("protection_is_upper_bound") is True:
        return True, "protection_is_upper_bound(proven module)"
    module_set = protection.get("module_set")
    if isinstance(module_set, list) and module_set:
        return True, "module_set_enumerated_non_empty(proven module)"
    if protection.get("guard") == "proven_address":
        return True, "guard_proven_present"
    basis = protection.get("module_set_basis")
    if isinstance(module_set, list) and not module_set and basis == "storage_linked_list_terminated":
        return False, f"module_set_proven_empty@{protection.get('probe_block')}"
    return False, f"module_set_not_determined({basis or 'not_determined'});credit_stands"


def _resolver_bases(details: dict[str, Any]) -> tuple[str, ...]:
    bases: set[str] = set()
    for step in details.get("trace") or []:
        if not isinstance(step, dict):
            continue
        basis = step.get("basis")
        if isinstance(basis, str):
            bases.add(basis)
        elif isinstance(basis, list):
            bases.update(str(b) for b in basis)
    return tuple(sorted(bases))


def _role_bindings(details: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """(registry, role_hash) pairs this principal's resolution is bound to.

    Only a trace step naming exactly ONE role hash binds: a fold that published
    several role labels says which roles the registry has, not which one gates
    this function, and attributing a holder floor on that basis would import a
    different role's breadth.
    """
    out: set[tuple[str, str]] = set()
    for step in details.get("trace") or []:
        if not isinstance(step, dict):
            continue
        registry = _lower(step.get("authority") or step.get("registry"))
        labels = step.get("role_labels")
        if not registry or not isinstance(labels, dict) or len(labels) != 1:
            continue
        out.add((registry, _lower(next(iter(labels)))))
    return tuple(sorted(out))


def load_role_holder_floors(session: Session, protocol_id: int) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Proven holder floors per (chain, registry, role hash), protocol-scoped.

    ``holders`` is a LOWER BOUND and ``len(holders)`` is never a count; the floor
    may raise breadth concern and may never lower it. ``holder_set_exhaustive``
    is always ``not_determined``.

    Scoped to the registries THIS protocol's own resolution names — the
    ``authority``/``registry`` of a ``function_principals`` trace step, which is
    the only key the consumer ever looks a floor up by. ``role_holder_planes`` is
    keyed by ``(chain_id, registry_address, role_hash)`` with no protocol column,
    so an unscoped read makes this plane's population a function of which OTHER
    protocols have been analysed: the same protocol scored twice would carry
    different floors, which is a purity break (inv. 11) before it is anything
    else. Scoping loses no floor the fold could have consumed, because a registry
    no trace names has no binding to join to.
    """
    from db.models import Contract, EffectiveFunction, FunctionPrincipal, RoleHolderPlane

    named: set[tuple[str, str]] = set()
    for details, chain in (
        session.query(FunctionPrincipal.details, Contract.chain)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(FunctionPrincipal.id)
        .all()
    ):
        for step in (details or {}).get("trace") or []:
            if not isinstance(step, dict):
                continue
            registry = _lower(step.get("authority") or step.get("registry"))
            if registry:
                named.add((coalesce_chain(chain), registry))
    if not named:
        return {}

    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    rows = (
        session.query(RoleHolderPlane)
        .filter(sql_func.lower(RoleHolderPlane.registry_address).in_(sorted({address for _, address in named})))
        .order_by(RoleHolderPlane.chain_id, RoleHolderPlane.registry_address, RoleHolderPlane.role_hash)
        .all()
    )
    # A row whose chain id maps to no chain is drift, not an admission rule
    # firing: the registry it names may well be one a trace points at, and the
    # floor it would have carried is lost. Counted apart from the rules below,
    # which are this loader's own scoping and holders-basis tests.
    unknown_chain = 0
    for row in rows:
        chain = _chain_name(row.chain_id)
        if chain is None:
            unknown_chain += 1
            continue
        if (chain, _lower(row.registry_address)) not in named:
            continue
        if not isinstance(row.holders, list) or not row.holders:
            continue
        if row.holders_basis != "pinned_has_role_confirmed":
            continue
        out[(chain, _lower(row.registry_address), _lower(row.role_hash))] = {
            "holders_floor": len(row.holders),
            "as_of_block": row.as_of_block,
            "coverage": row.coverage,
            "holder_set_exhaustive": "not_determined",
        }
    if unknown_chain:
        # This loader's return shape is a floor lookup with nowhere to publish a
        # census, so the drift is announced at the boundary instead of silently
        # shortening the floors a unit resolves on.
        logger.warning(
            "role holder floors dropped %d row(s) whose chain id maps to no chain",
            unknown_chain,
            extra={"protocol_id": protocol_id, "rows_dropped": unknown_chain, "rows_read": len(rows)},
        )
    return out
