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

import logging
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from sqlalchemy.orm import Session

from db.deployment import deployment_scope
from db.models import EffectiveFunction, EffectVerdict, FunctionPrincipal
from services.policy.capability_surface import (
    project_capability_surface,
)
from services.policy.permission_index import MUTABILITY_FIELDS
from utils.logging import record_degraded

logger = logging.getLogger(__name__)


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
    failures: list[BaseException] | None = None,
) -> tuple[str | None, dict[str, Any] | None]:
    """Resolve one principal address to ``(resolved_type, details)`` via
    *resolver*, memoized per writer call so an address shared across functions
    is classified once. A resolver failure leaves the row untyped rather than
    aborting the whole contract's FunctionPrincipal write; it is appended to
    *failures* so the caller can report the batch once per contract instead of
    once per principal."""
    key = (address or "").lower()
    if key not in memo:
        try:
            memo[key] = resolver(address)
        except Exception as exc:
            memo[key] = (None, None)
            if failures is not None:
                failures.append(exc)
    return memo[key]


def _selector_key(selector: str | None, function_name: str | None = None) -> tuple[str, str]:
    """Identity for carrying observed-effect state across the row replace.

    Keyed on ``(selector, function_name)``, not selector alone: a
    selector-less entry point carries the documented ``""`` sentinel, and BOTH
    ``fallback`` and ``receive`` are selector-less — so a contract declaring both
    produced two rows under one key and the carry cross-assigned one's observed
    claims and proven verdicts to the other. A ``None`` selector (the "could not
    be derived" state) collapses onto the same ``""``, which is a second way in.
    The function name discriminates without affecting any selector-bearing row,
    where the pair is as unique as the selector was.

    Armed population: 0 realised on the local corpus (no analysed contract
    declares both, and every persisted selector-less row predates the ``""``
    sentinel and still carries a fabricated selector) — structural on the first
    contract that declares both once the sentinel is in use."""
    return ((selector or "").lower(), (function_name or "").lower())


def _capture_verdicts_before(
    session: Session,
    contract_id: int,
    deployment_address: str | None,
) -> dict[tuple[str, str], list[Any]]:
    """Capture proven verdict rows solely so the replace can relink their FK."""
    rows = (
        session.query(
            EffectiveFunction.id,
            EffectiveFunction.selector,
            EffectiveFunction.function_name,
        )
        .filter(
            EffectiveFunction.contract_id == contract_id,
            deployment_scope(EffectiveFunction.deployment_address, deployment_address),
        )
        .all()
    )
    if not rows:
        return {}
    id_to_selector: dict[int, tuple[str, str]] = {}
    for row_id, selector, function_name in rows:
        key = _selector_key(selector, function_name)
        id_to_selector[row_id] = key

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

    return verdicts_by_selector


def write_permission_rows(
    session: Session,
    *,
    contract_id: int,
    function_records: Sequence[Mapping[str, Any]],
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
    ``build_permission_index``. Each must carry at minimum
    ``function`` / ``abi_signature`` and the column overrides
    (``capability_expr``, ``conditions``, ``status``,
    ``authority_public``); optional authority fields ride
    through unchanged.

    Returns the number of FunctionPrincipal rows added.
    """

    verdicts_before = _capture_verdicts_before(session, contract_id, deployment_address)

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
    classify_failures: list[BaseException] = []
    for fn in function_records:
        fn_signature = str(fn.get("function") or fn.get("abi_signature") or "")
        function_name = fn_signature.split("(")[0] if "(" in fn_signature else fn_signature

        principal_cap = fn.get("capability_expr")
        cap_columns = {
            field: fn.get(field) for field in ("capability_expr", "conditions", "status", "authority_openness")
        }
        cap_columns["authority_public"] = fn.get("authority_public", False)

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
            "authority_public": cap_columns["authority_public"],
            "authority_roles": fn.get("authority_roles"),
            **cap_columns,
            **{field: fn.get(field) for field in MUTABILITY_FIELDS},
            "claims": fn.get("claims", []),
        }
        ef = EffectiveFunction(**ef_kwargs)
        session.add(ef)
        session.flush()

        # Relink surviving verdict facts without carrying the outgoing row's
        # claims. Claims come only from the validated Assessment projection.
        for verdict in verdicts_before.get(_selector_key(ef.selector, ef.function_name), []):
            verdict.function_id = ef.id

        # Semantic caller-shaped principals. ``ON CONFLICT DO NOTHING`` is
        # implemented at the (function_id, address, origin, principal_type)
        # level via an in-memory dedup set — the row schema has no UNIQUE
        # constraint so we can't lean on Postgres for it.
        seen: set[tuple[int, str, str, str]] = set()

        if principal_cap is not None:
            semantic_rows = _principal_rows_for_capability(
                principal_cap,
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
        # One line per contract, not per principal: a resolver outage fails
        # every address, and the untyped rows it leaves behind are read
        # downstream as "not a Safe/Timelock" rather than "never classified".
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
