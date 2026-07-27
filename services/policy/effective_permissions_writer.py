"""Row writer for semantic per-function capabilities.

This module drives ``EffectiveFunction`` and ``FunctionPrincipal`` rows
directly from per-function ``CapabilityExpr`` shapes.

Per-kind row representation:

  finite_set                    -> N rows, principal_type=controller
  threshold_group (Safe)        -> 1 row,  resolved_type=safe, details.owners[]
  signature_witness(finite)     -> N rows, principal_type=signature_witness
  signature_witness(non-finite) -> 0 rows
  finite_set(empty exact)        -> 0 rows + status='resolved_empty'
  cofinite_blacklist            -> 0 rows
  external_check_only           -> 0 rows
  conditional_universal         -> 0 rows + status='public', authority_public=True
  unsupported                   -> 0 rows + status='unsupported'
  OR with resolved caller/public paths -> resolved path rows/public marker
  AND with caller path + side conditions -> caller rows with conditions
  AND/OR irreducible residuals -> 0 rows + capability_expr=full tree

Caller-shaped kinds (``finite_set``, ``threshold_group``,
``signature_witness(finite)``) are the only leaf kinds that produce
``FunctionPrincipal`` rows, either directly or through a composite path.
``FunctionPrincipal.address`` semantically means "this address can call
as itself"; putting blacklists, registry contracts, or external-check
targets there is a category error that produces false-authority claims
downstream
(``ProtocolSurface.jsx:303``, ``protocolScore.js:124``).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import is_dataclass
from typing import Any

from sqlalchemy.orm import Session

from db.deployment import deployment_scope
from db.models import EffectiveFunction, EffectVerdict, FunctionPrincipal
from services.effects import claims_bridge
from services.policy.capability_surface import capability_surface_status, project_capability_surface
from services.policy.effective_permissions import MUTABILITY_FIELDS
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict


def _to_dict(cap: CapabilityExpr | dict[str, Any] | None) -> dict[str, Any] | None:
    """Normalize ``cap`` to its serialized dict form.

    Accepts either a real ``CapabilityExpr`` (e.g. from the resolver) or
    an already-serialized dict (e.g. handed back through a fixture or
    persisted artifact). ``None`` propagates."""
    if cap is None:
        return None
    if is_dataclass(cap):
        return capability_to_dict(cap)  # type: ignore[arg-type]
    if isinstance(cap, dict):
        return dict(cap)
    return None


def _principal_rows_for_capability(
    cap_dict: dict[str, Any],
    *,
    safe_address_lookup: dict[str, str] | None = None,
    function_signature: str | None = None,
) -> list[dict[str, Any]]:
    """Translate a serialized CapabilityExpr to the principal-row tuples
    that should be written for the function.

    Returns a list of dicts with keys ``address``, ``resolved_type``,
    ``origin``, ``principal_type``, ``details``. Caller persists them.
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
) -> tuple[str | None, dict[str, Any] | None]:
    """Resolve one principal address to ``(resolved_type, details)`` via
    *resolver*, memoized per writer call so an address shared across functions
    is classified once. A resolver failure leaves the row untyped rather than
    aborting the whole contract's FunctionPrincipal write."""
    key = (address or "").lower()
    if key not in memo:
        try:
            memo[key] = resolver(address)
        except Exception:
            memo[key] = (None, None)
    return memo[key]


def _column_values_for_capability(
    cap_dict: dict[str, Any],
) -> dict[str, Any]:
    """Compute ``EffectiveFunction`` column overrides from the resolved
    capability. Always populates ``capability_expr``; ``conditions`` /
    ``status`` / ``authority_public`` only set for the kinds that
    require them."""
    surface = project_capability_surface(cap_dict)
    conditions = surface.conditions
    out: dict[str, Any] = {
        "capability_expr": dict(cap_dict),
        "conditions": conditions or None,
        "status": capability_surface_status(cap_dict, surface),
        "authority_public": surface.authority_public,
    }
    return out


def _selector_key(selector: str | None) -> str:
    return (selector or "").lower()


def _capture_observed_before(
    session: Session,
    contract_id: int,
    deployment_address: str | None,
) -> dict[str, tuple[list[Any], list[Any]]]:
    """§5.2 call site 2, capture phase. Read this deployment's *outgoing*
    observed-effect state BEFORE the wholesale row replace deletes it, keyed by
    selector, so the re-created rows can carry it forward.

    Two sources:

    - ``behavioral_observed``-tier claims already on the outgoing rows (minted by
      the effects stage). These are the durable carrier: without carrying the
      claims themselves, any policy-only re-run (one that does not re-run
      effects) would blank the observed labels, which is exactly the regression
      §5.2 exists to kill.
    - Proven ``effect_verdicts`` for those rows, re-merged as the authoritative
      source. The verdict rows survive the replace (FK is ``ON DELETE SET
      NULL``) but come out unlinked; the carry phase relinks them to the
      re-created rows so claim witnesses keep resolving.

    Returns ``{selector_key: (carried_observed_claims, proven_verdicts)}``.
    """
    # Older/stripped test metadata swaps in an EffectiveFunction model without the
    # claims plane; nothing observed can exist there, so there is nothing to carry.
    if not hasattr(EffectiveFunction, "claims"):
        return {}
    rows = (
        session.query(EffectiveFunction.id, EffectiveFunction.selector, EffectiveFunction.claims)
        .filter(
            EffectiveFunction.contract_id == contract_id,
            deployment_scope(EffectiveFunction.deployment_address, deployment_address),
        )
        .all()
    )
    if not rows:
        return {}
    observed_by_selector: dict[str, list[Any]] = {}
    id_to_selector: dict[int, str] = {}
    for row_id, selector, claims in rows:
        key = _selector_key(selector)
        id_to_selector[row_id] = key
        for claim in claims or []:
            if isinstance(claim, dict) and claim.get("tier") == claims_bridge.OBSERVED_TIER:
                observed_by_selector.setdefault(key, []).append(claim)

    verdicts_by_selector: dict[str, list[Any]] = {}
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
    """Replace this contract's ``EffectiveFunction`` rows with semantic
    rows and their associated ``FunctionPrincipal`` rows.

    ``resolve_principal_type`` — optional ``address -> (resolved_type,
    details)`` classifier. The capability surface only knows caller
    *addresses* (finite_set members carry ``resolved_type=None``); when this
    is supplied, each untyped caller row is classified so
    ``function_principals.resolved_type`` carries Safe / Timelock / EOA /
    proxy_admin. That is the signal ``_fp_governance`` and the
    primary-controller assignment key on — without it those rows are NULL and
    a governance Safe reachable only through per-function authority never
    surfaces. Callers pass the same resolver used for principal labels (the
    resolution-stage classify cache + a live ``classify_resolved_address``
    fallback). ``None`` preserves the prior write-time-untyped behavior.

    ``function_records`` is the list of per-function dicts emitted by
    ``build_effective_permissions``. Each must carry at minimum
    ``function`` / ``abi_signature`` and the column overrides
    (``capability_expr``, ``conditions``, ``status``,
    ``authority_public``); optional compatibility fields (``effect_labels``,
    ``effect_targets``, ``action_summary``, ``authority_roles``) ride
    through unchanged.

    ``capability_by_function`` maps function full-name to the resolved
    capability (dict or dataclass). When None / missing for a
    particular function, no principal rows are written for that function.

    Returns the number of FunctionPrincipal rows added.
    """
    capability_by_function = capability_by_function or {}

    # §5.2 call site 2: snapshot the outgoing rows' observed-effect state before
    # the replace destroys it, so the re-created rows carry it forward.
    observed_before = _capture_observed_before(session, contract_id, deployment_address)

    # Replace this deployment's effective_functions wholesale, sweeping any
    # legacy untagged (NULL) rows. FunctionPrincipal rows are removed by the
    # DB-level ON DELETE CASCADE on function_principals.function_id.
    session.query(EffectiveFunction).filter(
        EffectiveFunction.contract_id == contract_id,
        deployment_scope(EffectiveFunction.deployment_address, deployment_address),
    ).delete(synchronize_session=False)
    session.flush()

    added_principals = 0
    # Per-call address→(type, details) memo so a caller shared across many
    # functions is classified once.
    type_memo: dict[str, tuple[str | None, dict[str, Any] | None]] = {}
    for fn in function_records:
        fn_signature = str(fn.get("function") or fn.get("abi_signature") or "")
        function_name = fn_signature.split("(")[0] if "(" in fn_signature else fn_signature

        cap = capability_by_function.get(fn_signature)
        cap_dict = _to_dict(cap)

        # Column values: prefer resolved capability columns; otherwise use
        # explicit per-function compatibility fields.
        if cap_dict is not None:
            cap_columns = _column_values_for_capability(cap_dict)
        else:
            cap_columns = {
                "capability_expr": fn.get("capability_expr"),
                "conditions": fn.get("conditions"),
                "status": fn.get("status"),
                "authority_public": bool(fn.get("authority_public", False)),
            }
        # Per-function explicit override applies when the capability
        # itself didn't pin the column. ``conditional_universal``
        # should keep ``authority_public=True`` even if the per-function dict
        # carries the default ``False``.
        if cap_dict is None and "authority_public" in fn and fn.get("authority_public") is not None:
            cap_columns["authority_public"] = bool(fn["authority_public"])
        elif cap_dict is not None and bool(fn.get("authority_public", False)) and not cap_columns["authority_public"]:
            # Per-function explicit True (e.g. policy_check public capability)
            # ORs in even when the cap shape doesn't say public.
            cap_columns["authority_public"] = True
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
            # The canonical signature, not the Slither full_name it was derived
            # from: ``selector`` on the line above already comes from the same
            # dict, and taking the two from different sources put a signature in
            # the row whose keccak is not that row's own selector. For a struct
            # param the full_name has lost the tuple layout entirely, so nothing
            # downstream can encode a call or recompute the selector from it.
            "abi_signature": fn.get("abi_signature") or fn_signature,
            "effect_labels": fn.get("effect_labels", []),
            "effect_targets": fn.get("effect_targets", []),
            "action_summary": fn.get("action_summary"),
            "authority_public": cap_columns["authority_public"],
            "authority_roles": fn.get("authority_roles"),
        }
        # Optional columns may be absent in older test metadata.
        for col_name in ("capability_expr", "conditions", "status"):
            if hasattr(EffectiveFunction, col_name):
                ef_kwargs[col_name] = cap_columns.get(col_name)
        # State-mutability witness. ``fn.get`` with no default on purpose: a
        # record that never carried the key is not-determined, which is the same
        # answer ``_mutability_fields`` gives for an uncovered signature — and it
        # is NOT ``[]``/``False``, which would assert that the effects stage
        # looked. Every caller that does carry the keys already passed them
        # through ``_mutability_fields``.
        for col_name in MUTABILITY_FIELDS:
            if hasattr(EffectiveFunction, col_name):
                ef_kwargs[col_name] = fn.get(col_name)
        # Plane-1 claims ride through unchanged alongside the legacy effect_labels.
        if hasattr(EffectiveFunction, "claims"):
            ef_kwargs["claims"] = fn.get("claims", [])
        ef = EffectiveFunction(**ef_kwargs)
        session.add(ef)
        session.flush()

        # §5.2 call site 2, carry phase: fold the outgoing row's observed claims
        # (and any surviving proven verdicts) back onto this re-created row so a
        # policy-only rewrite never blanks observed labels. Only touches rows that
        # had observed state — claim-free functions stay byte-identical.
        carried = observed_before.get(_selector_key(ef.selector))
        if carried:
            carried_claims, proven_verdicts = carried
            merged_claims = claims_bridge.merge_observed_claims([*(ef.claims or []), *carried_claims], proven_verdicts)
            ef.claims = merged_claims
            ef.effect_labels = claims_bridge.reproject_effect_labels(ef.effect_labels or [], merged_claims)
            # The replace SET-NULLed the surviving verdicts' function_id; point
            # them at the re-created row so the convenience join stays live.
            for verdict in proven_verdicts:
                verdict.function_id = ef.id

        # Semantic caller-shaped principals. ``ON CONFLICT DO NOTHING`` is
        # implemented at the (function_id, address, origin, principal_type)
        # level via an in-memory dedup set — the row schema has no UNIQUE
        # constraint so we can't lean on Postgres for it.
        seen: set[tuple[int, str, str, str]] = set()

        if cap_dict is not None:
            semantic_rows = _principal_rows_for_capability(
                cap_dict,
                safe_address_lookup=safe_address_lookup,
                function_signature=fn_signature,
            )
            for row in semantic_rows:
                key = (
                    ef.id,
                    row["address"],
                    row.get("origin") or "",
                    row.get("principal_type") or "",
                )
                if key in seen:
                    continue
                seen.add(key)
                resolved_type = row.get("resolved_type")
                details = row.get("details")
                # finite_set rows arrive untyped (the surface only knows the
                # address). Classify callers so resolved_type is populated.
                # signature_witness rows are signers, not callers, and are
                # excluded from the governance/primary-controller consumers —
                # skip the probe for them.
                if (
                    resolve_principal_type is not None
                    and row.get("principal_type") != "signature_witness"
                    and (not resolved_type or resolved_type == "unknown")
                ):
                    classified_type, classified_details = _classify_principal(
                        row["address"], resolve_principal_type, type_memo
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

    return added_principals
