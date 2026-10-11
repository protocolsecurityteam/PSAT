"""Writes ``EffectiveFunction`` / ``FunctionPrincipal`` rows from per-function ``CapabilityExpr`` shapes.

  finite_set                    -> N rows, principal_type=controller
  threshold_group (Safe)        -> 1 row,  resolved_type=safe, details.owners[]
  signature_witness(finite)     -> N rows, principal_type=signature_witness
  signature_witness(non-finite) -> 0 rows
  finite_set(empty exact)       -> 0 rows + status='resolved_empty'
  cofinite_blacklist            -> 0 rows
  external_check_only           -> 0 rows
  conditional_universal         -> 0 rows + status='public', authority_public=True
  unsupported                   -> 0 rows + status='unsupported'
  OR with resolved caller/public paths -> resolved path rows/public marker
  AND with caller path + side conditions -> caller rows with conditions
  AND/OR irreducible residuals -> 0 rows + capability_expr=full tree

``FunctionPrincipal.address`` means "can call as itself"; putting blacklists, registries or external-check targets there
produces false authority claims downstream.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import is_dataclass
from typing import Any

from sqlalchemy.orm import Session

from db.deployment import deployment_scope
from db.models import EffectiveFunction, EffectVerdict, FunctionPrincipal
from services.effects import claims_bridge
from services.policy.capability_surface import (
    capability_role_grants,
    capability_surface_openness,
    capability_surface_status,
    project_capability_surface,
)
from services.policy.effective_permissions import MUTABILITY_FIELDS
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from utils.logging import record_degraded

logger = logging.getLogger(__name__)


def _to_dict(cap: CapabilityExpr | dict[str, Any] | None) -> dict[str, Any] | None:
    if cap is None:
        return None
    if is_dataclass(cap):
        return capability_to_dict(cap)
    if isinstance(cap, dict):
        return dict(cap)
    return None


def _principal_rows_for_capability(
    cap_dict: dict[str, Any],
    *,
    safe_address_lookup: dict[str, str] | None = None,
    function_signature: str | None = None,
) -> list[dict[str, Any]]:
    """Principal-row dicts (``address``, ``resolved_type``, ``origin``, ``principal_type``, ``details``) for one
    capability.
    """
    return project_capability_surface(
        cap_dict,
        safe_address_lookup=safe_address_lookup,
        function_signature=function_signature,
    ).principal_rows


def _classify_principal(
    address: str,
    resolver: Callable[[str], tuple[str | None, dict[str, Any] | None]],
    memo: dict[str, tuple[str | None, dict[str, Any] | None]],
    failures: list[BaseException] | None = None,
) -> tuple[str | None, dict[str, Any] | None]:
    """Memoized per call.

    A resolver failure leaves the row untyped and is collected so the caller reports once per contract.
    """
    key = (address or "").lower()
    if key not in memo:
        try:
            memo[key] = resolver(address)
        except Exception as exc:
            memo[key] = (None, None)
            if failures is not None:
                failures.append(exc)
    return memo[key]


def _column_values_for_capability(
    cap_dict: dict[str, Any],
) -> dict[str, Any]:
    surface = project_capability_surface(cap_dict)
    conditions = surface.conditions
    out: dict[str, Any] = {
        "capability_expr": dict(cap_dict),
        "conditions": conditions or None,
        "status": capability_surface_status(cap_dict, surface),
        "authority_public": surface.authority_public,
        "authority_openness": capability_surface_openness(cap_dict, surface),
    }
    return out


def _authority_roles_for(cap_dict: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    """No capability means nothing was read: ``None``, never ``[]``."""
    if cap_dict is None:
        return None
    return capability_role_grants(cap_dict)


def _selector_key(selector: str | None, function_name: str | None = None) -> tuple[str, str]:
    """Carry key ``(selector, function_name)``: fallback and receive both have the ``""`` selector (and ``None``
    collapses there too), so selector alone cross-assigned their observed state.
    """
    return ((selector or "").lower(), (function_name or "").lower())


def _capture_observed_before(
    session: Session,
    contract_id: int,
    deployment_address: str | None,
) -> dict[tuple[str, str], tuple[list[Any], list[Any]]]:
    """Capture this deployment's observed-effect state before the row replace deletes it: ``behavioral_observed``
    claims (or a policy-only re-run would blank them) and proven ``effect_verdicts`` (they survive via SET NULL
    and are relinked).

    Returns ``{(selector, function_name): (carried_observed_claims, proven_verdicts)}``.
    """
    # Stripped test metadata without the claims plane.
    if not hasattr(EffectiveFunction, "claims"):
        return {}
    rows = (
        session.query(
            EffectiveFunction.id,
            EffectiveFunction.selector,
            EffectiveFunction.function_name,
            EffectiveFunction.claims,
        )
        .filter(
            EffectiveFunction.contract_id == contract_id,
            deployment_scope(EffectiveFunction.deployment_address, deployment_address),
        )
        .all()
    )
    if not rows:
        return {}
    observed_by_selector: dict[tuple[str, str], list[Any]] = {}
    id_to_selector: dict[int, tuple[str, str]] = {}
    for row_id, selector, function_name, claims in rows:
        key = _selector_key(selector, function_name)
        id_to_selector[row_id] = key
        for claim in claims or []:
            if isinstance(claim, dict) and claim.get("tier") == claims_bridge.OBSERVED_TIER:
                observed_by_selector.setdefault(key, []).append(claim)

    verdicts_by_selector: dict[tuple[str, str], list[Any]] = {}
    verdicts = (
        session.query(EffectVerdict)
        .filter(
            EffectVerdict.function_id.in_(id_to_selector),
            EffectVerdict.verdict == "proven",
        )
        .all()
    )
    for verdict in verdicts:
        if verdict.function_id is None:
            continue
        key = id_to_selector.get(verdict.function_id)
        if key is not None:
            verdicts_by_selector.setdefault(key, []).append(verdict)

    return {
        key: (observed_by_selector.get(key, []), verdicts_by_selector.get(key, []))
        for key in set(observed_by_selector) | set(verdicts_by_selector)
    }


def write_effective_function_rows(
    session: Session,
    *,
    contract_id: int,
    function_records: list[dict[str, Any]],
    capability_by_function: Mapping[str, CapabilityExpr | dict[str, Any]] | None,
    safe_address_lookup: dict[str, str] | None = None,
    resolve_principal_type: Callable[[str], tuple[str | None, dict[str, Any] | None]] | None = None,
    deployment_address: str | None = None,
) -> int:
    """Replace this contract's ``EffectiveFunction`` / ``FunctionPrincipal`` rows. Returns the principal row count.

    ``resolve_principal_type`` classifies untyped callers so ``resolved_type`` carries Safe/Timelock/EOA/proxy_admin;
    without it, a governance Safe reachable only via per-function authority never surfaces. ``function_records`` come
    from ``build_effective_permissions``. Functions missing from ``capability_by_function`` get no principal rows.
    """
    capability_by_function = capability_by_function or {}

    # Resolve slow external classifications before deleting/flushing any policy rows.
    # Otherwise those RPC calls hold the protocol's write locks for the whole scan.
    type_memo: dict[str, tuple[str | None, dict[str, Any] | None]] = {}
    classify_failures: list[BaseException] = []
    principal_rows_by_signature: dict[str, list[dict[str, Any]]] = {}
    for fn in function_records:
        signature = str(fn.get("function") or fn.get("abi_signature") or "")
        cap_dict = _to_dict(capability_by_function.get(signature))
        if cap_dict is None:
            continue
        rows = project_capability_surface(
            cap_dict, safe_address_lookup=safe_address_lookup, function_signature=signature
        ).principal_rows
        for scope in cap_dict.get("effect_capabilities") or []:
            rows.extend(
                _principal_rows_for_capability(
                    scope["capability"], safe_address_lookup=safe_address_lookup, function_signature=signature
                )
            )
        principal_rows_by_signature[signature] = rows
        if resolve_principal_type is not None:
            for row in rows:
                if row.get("principal_type") != "signature_witness" and row.get("resolved_type") in (
                    None,
                    "",
                    "unknown",
                ):
                    _classify_principal(row["address"], resolve_principal_type, type_memo, failures=classify_failures)

    observed_before = _capture_observed_before(session, contract_id, deployment_address)

    # Principals go via ON DELETE CASCADE.
    session.query(EffectiveFunction).filter(
        EffectiveFunction.contract_id == contract_id,
        deployment_scope(EffectiveFunction.deployment_address, deployment_address),
    ).delete(synchronize_session=False)
    session.flush()

    added_principals = 0
    for fn in function_records:
        fn_signature = str(fn.get("function") or fn.get("abi_signature") or "")
        function_name = fn_signature.split("(")[0] if "(" in fn_signature else fn_signature

        cap = capability_by_function.get(fn_signature)
        cap_dict = _to_dict(cap)
        # Policy-minted capabilities travel on the record, not in ``capability_by_function``; derive projections from
        # them so a row never has NULL beside a capability that answers it.
        record_cap = fn.get("capability_expr")
        if not isinstance(record_cap, dict):
            record_cap = None

        if cap_dict is not None:
            cap_columns = _column_values_for_capability(cap_dict)
        else:
            openness = fn.get("authority_openness")
            if openness is None and record_cap is not None:
                openness = capability_surface_openness(record_cap, project_capability_surface(record_cap))
            cap_columns = {
                "capability_expr": fn.get("capability_expr"),
                "conditions": fn.get("conditions"),
                "status": fn.get("status"),
                "authority_public": bool(fn.get("authority_public", False)),
                # NULL only with nothing to project from, which differs from ``not_determined`` (looked and couldn't
                # decide).
                "authority_openness": openness,
            }
        # ``conditional_universal`` keeps True over a default False.
        if cap_dict is None and "authority_public" in fn and fn.get("authority_public") is not None:
            cap_columns["authority_public"] = bool(fn["authority_public"])
        elif cap_dict is not None and bool(fn.get("authority_public", False)) and not cap_columns["authority_public"]:
            cap_columns["authority_public"] = True
            # Keep openness in lockstep with the bool.
            cap_columns["authority_openness"] = "open"
        if cap_dict is None:
            if fn.get("status") is not None:
                cap_columns["status"] = fn["status"]
            if fn.get("conditions") is not None:
                cap_columns["conditions"] = fn["conditions"]
            if fn.get("capability_expr") is not None:
                cap_columns["capability_expr"] = fn["capability_expr"]

        ef_kwargs: dict[str, Any] = {
            "contract_id": contract_id,
            "deployment_address": deployment_address,
            "function_name": function_name,
            "selector": fn.get("selector"),
            # The canonical signature, from the same dict as the selector: a struct full_name has lost its tuple layout.
            "abi_signature": fn.get("abi_signature") or fn_signature,
            "effect_labels": fn.get("effect_labels", []),
            "effect_targets": fn.get("effect_targets", []),
            "action_summary": fn.get("action_summary"),
            "authority_public": cap_columns["authority_public"],
            # A non-empty upstream list wins; the historical constant ``[]`` isn't an answer, so the capability's own
            # verdict applies and NULL keeps meaning no capability.
            "authority_roles": (
                fn.get("authority_roles")
                if fn.get("authority_roles")
                else _authority_roles_for(cap_dict if cap_dict is not None else record_cap)
            ),
        }
        # Optional columns may be absent in older test metadata.
        for col_name in ("capability_expr", "conditions", "status", "authority_openness"):
            if hasattr(EffectiveFunction, col_name):
                ef_kwargs[col_name] = cap_columns.get(col_name)
        # No default on purpose: a missing key is not determined, not ``[]``/``False``.
        for col_name in MUTABILITY_FIELDS:
            if hasattr(EffectiveFunction, col_name):
                ef_kwargs[col_name] = fn.get(col_name)
        if hasattr(EffectiveFunction, "claims"):
            ef_kwargs["claims"] = fn.get("claims", [])
        ef = EffectiveFunction(**ef_kwargs)
        session.add(ef)
        session.flush()

        # Only rows that had observed state are touched.
        carried = observed_before.get(_selector_key(ef.selector, ef.function_name))
        if carried:
            carried_claims, proven_verdicts = carried
            merged_claims = claims_bridge.merge_observed_claims([*(ef.claims or []), *carried_claims], proven_verdicts)
            ef.claims = merged_claims
            ef.effect_labels = claims_bridge.reproject_effect_labels(ef.effect_labels or [], merged_claims)
            for verdict in proven_verdicts:
                verdict.function_id = ef.id

        # No UNIQUE constraint, so dedup in memory.
        seen: set[tuple] = set()
        from .effect_authority import principal_identity

        if cap_dict is not None:
            semantic_rows = principal_rows_by_signature[fn_signature]
            for row in semantic_rows:
                key = (
                    ef.id,
                    row["address"],
                    row.get("origin") or "",
                    row.get("principal_type") or "",
                    principal_identity(row["address"], row.get("details")),
                )
                if key in seen:
                    continue
                seen.add(key)
                resolved_type = row.get("resolved_type")
                details = row.get("details")
                # Signature witnesses are signers, not callers; skip classification.
                if (
                    resolve_principal_type is not None
                    and row.get("principal_type") != "signature_witness"
                    and (not resolved_type or resolved_type == "unknown")
                ):
                    classified_type, classified_details = _classify_principal(
                        row["address"], resolve_principal_type, type_memo, failures=classify_failures
                    )
                    if classified_type:
                        resolved_type = classified_type
                        if isinstance(classified_details, dict) and classified_details:
                            merged = dict(classified_details)
                            if isinstance(details, dict):
                                merged.update(details)
                            details = merged
                session.add(
                    FunctionPrincipal(
                        function_id=ef.id,
                        address=row["address"],
                        resolved_type=resolved_type,
                        origin=row.get("origin"),
                        principal_type=row.get("principal_type"),
                        details=details,
                    )
                )
                added_principals += 1

    if classify_failures:
        # Once per contract: untyped rows read downstream as "not a Safe" rather than "never classified".
        record_degraded(
            phase="principal_classification",
            exc=classify_failures[0],
            context={"contract_id": contract_id, "failed_addresses": len(classify_failures)},
        )
        logger.warning(
            "Principal classification failed for %d address(es) on contract %s; those rows publish resolved_type NULL",
            len(classify_failures),
            contract_id,
            extra={
                "exc_type": type(classify_failures[0]).__name__,
                "contract_id": contract_id,
                "failed_addresses": len(classify_failures),
            },
        )

    return added_principals
