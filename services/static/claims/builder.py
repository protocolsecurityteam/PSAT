"""Build the claims artifact and ride it through the facts carrier.

:func:`build_claims` runs every registered matcher over the Plane-0 facts —
contract-level gate, then per-function trigger — and mints each hit through
``emit_claim``, so an unregistered id can't escape a matcher. The result is a
standalone artifact keyed by function full-name (an empty list per function is
valid and common).

:func:`attach_claims_to_effects` merges that artifact back onto the ``effects``
artifact's per-function records. The policy stage already carries ``effects``
end to end, so claims reach ``build_effective_permissions`` with no new
artifact plumbing. Both functions fail soft on a degraded (errored) artifact.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from .context import ClaimContext
from .matchers import discover
from .registry import emit_claim, legacy_projections, registry, resolve_claim_precedence
from .types import SCHEMA_VERSION, ClaimAnalysis, ClaimDiagnostic, ClaimOmission, ClaimProjection, ClaimsArtifact

logger = logging.getLogger(__name__)


def build_claims(contract: Any, effects: Any, predicate_trees: Any) -> ClaimsArtifact:
    """Run all registered matchers over the facts, returning the claims artifact.

    A matcher that raises is isolated: it forfeits only its own claims (logged),
    never the whole pass. Per function the registry precedence rule then keeps
    the strongest tier of each claim; claim ordering is deterministic.
    """
    discover()
    ctx = ClaimContext(contract, effects, predicate_trees)
    signatures = ctx.function_signatures()
    functions: dict[str, list[ClaimProjection]] = {signature: [] for signature in signatures}

    analyses: dict[str, ClaimAnalysis] = {}
    diagnostics: list[ClaimDiagnostic] = []

    for entry in registry().values():
        omissions: list[ClaimOmission] = []
        completed = 0
        try:
            enabled = entry.gate(ctx)
        except Exception as exc:
            logger.warning(
                "claim matcher %s gate failed",
                entry.claim_id,
                extra={"claim_id": entry.claim_id},
                exc_info=True,
            )
            diagnostics.append(
                {
                    "claim_id": entry.claim_id,
                    "function": None,
                    "exc_type": type(exc).__name__,
                    "message": str(exc),
                }
            )
            analyses[entry.claim_id] = {
                "detector": entry.claim_id,
                "status": "failed",
                "targets_total": len(signatures),
                "targets_completed": 0,
                "omissions": [{"function": signature, "reason": "matcher_gate_failed"} for signature in signatures],
            }
            continue

        if not enabled:
            analyses[entry.claim_id] = {
                "detector": entry.claim_id,
                "status": "completed",
                "targets_total": 0,
                "targets_completed": 0,
                "omissions": [],
            }
            continue

        for signature in signatures:
            try:
                evidence = entry.trigger(ctx, signature)
                completed += 1
                if evidence is None:
                    continue
                functions[signature].append(emit_claim(entry.claim_id, evidence.tier, evidence.witness))
            except Exception as exc:
                logger.warning(
                    "claim matcher %s failed for %s",
                    entry.claim_id,
                    signature,
                    extra={"claim_id": entry.claim_id, "function": signature},
                    exc_info=True,
                )
                omissions.append({"function": signature, "reason": "matcher_trigger_failed"})
                diagnostics.append(
                    {
                        "claim_id": entry.claim_id,
                        "function": signature,
                        "exc_type": type(exc).__name__,
                        "message": str(exc),
                    }
                )

        status: Literal["completed", "partial", "failed"]
        if not omissions:
            status = "completed"
        elif completed:
            status = "partial"
        else:
            status = "failed"
        analyses[entry.claim_id] = {
            "detector": entry.claim_id,
            "status": status,
            "targets_total": len(signatures),
            "targets_completed": completed,
            "omissions": omissions,
        }

    for signature in functions:
        functions[signature] = resolve_claim_precedence(functions[signature])

    # The canonical ABI selector per function — the value a caller puts in
    # ``msg.sig``. The effects record's own ``selector`` is keccak of the
    # DECLARED signature, which is NOT a real selector when a parameter is
    # interface/enum/struct-typed (``sweepTo(IERC20,address,uint256)`` →
    # 0x38541c00 vs the dispatched 0x0aeef8c8), and the cross-contract join
    # missed every such callee. Computed here because this is the one
    # pass that holds the canonical-signature map and the Slither fallback
    # (``ctx.canonical_selector``). A signature that cannot be lowered is
    # OMITTED — absence is not-determined, never a proof. ``fallback()`` /
    # ``receive()`` are excluded: they have no selector, and hashing their
    # rendered names manufactures a selector no caller can dispatch.
    abi_selectors = {
        signature: selector
        for signature in signatures
        if signature not in ("fallback()", "receive()") and (selector := ctx.canonical_selector(signature)) is not None
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "contract_name": ctx.contract_name,
        "functions": functions,
        "abi_selectors": abi_selectors,
        "analyses": analyses,
        "diagnostics": diagnostics,
    }


def attach_claims_to_effects(effects: Any, claims_artifact: Any) -> None:
    """Write each function's claims onto its ``effects`` record (in place), so
    the existing effects transport carries them downstream. No-op if either
    artifact is degraded.

    Also stamps ``abi_selector`` — the canonical dispatch selector from the
    claims artifact — beside the record's declared-signature ``selector``, so
    a consumer that must join on the REAL ``msg.sig`` (the cross-contract
    callee map) has it in the artifact it already reads. Absence of the key
    means not-determined (unlowerable signature, fallback/receive, or an
    artifact minted before the field existed) — consumers must fall back, not
    infer."""
    if not isinstance(effects, dict):
        return
    functions = effects.get("functions")
    if not isinstance(functions, dict):
        return
    schema_version = claims_artifact.get("schema_version") if isinstance(claims_artifact, dict) else None
    if isinstance(schema_version, str):
        effects["claims_schema_version"] = schema_version
    analyses = claims_artifact.get("analyses") if isinstance(claims_artifact, dict) else None
    if isinstance(analyses, dict):
        effects["claim_analyses"] = analyses
    diagnostics = claims_artifact.get("diagnostics") if isinstance(claims_artifact, dict) else None
    if isinstance(diagnostics, list):
        effects["claim_diagnostics"] = diagnostics
    by_function = claims_artifact.get("functions") if isinstance(claims_artifact, dict) else None
    if not isinstance(by_function, dict):
        by_function = {}
    abi_selectors = claims_artifact.get("abi_selectors") if isinstance(claims_artifact, dict) else None
    if not isinstance(abi_selectors, dict):
        abi_selectors = {}
    for signature, record in functions.items():
        if isinstance(record, dict):
            record["claims"] = list(by_function.get(signature) or [])
            abi_selector = abi_selectors.get(signature)
            if isinstance(abi_selector, str) and abi_selector.startswith("0x"):
                record["abi_selector"] = abi_selector


def project_effect_labels(effects: Any) -> None:
    """Rewrite each function's legacy ``effect_labels`` as the union of the
    retained fact-tier labels already on the record (value-flow / selector
    facts, sink-kind capabilities, body external calls) and the registry
    ``legacy_projection`` of every claim on the function, then refresh the
    action summary. Runs after :func:`attach_claims_to_effects`; a no-op on a
    degraded artifact or a record without claims.

    An ``upgrade.implementation`` claim suppresses the standalone
    ``delegatecall_execution`` emphasis on the delegatecall sink it explains
    (the sink IS the upgrade mechanism, not a separate capability).
    """
    if not isinstance(effects, dict):
        return
    functions = effects.get("functions")
    if not isinstance(functions, dict):
        return
    # Deferred so importing the claims package never pulls in the static
    # pipeline (the module that defines this summary imports the claims
    # package at build time).
    from ..contract_analysis_pipeline.summaries import _action_summary

    projections = legacy_projections()
    for record in functions.values():
        if not isinstance(record, dict):
            continue
        labels = set(record.get("effect_labels") or [])
        upgrade_explains_delegatecall = False
        for claim in record.get("claims") or []:
            if not isinstance(claim, dict):
                continue
            claim_id = claim.get("claim_id")
            if not isinstance(claim_id, str):
                continue
            projected = projections.get(claim_id)
            if projected:
                labels.add(projected)
            if claim_id == "upgrade.implementation":
                witness = claim.get("witness") or {}
                if isinstance(witness, dict) and witness.get("explained_delegatecall_sink_ids"):
                    upgrade_explains_delegatecall = True
        if upgrade_explains_delegatecall:
            labels.discard("delegatecall_execution")
        # ``external_contract_call`` is the lowest-value fact (a body external
        # call exists, incl. SafeMath library calls); it stays only when no more
        # specific label explains the function, mirroring the build-time
        # downgrade so a claim never co-renders with the bare-call fact.
        if labels - {"external_contract_call"}:
            labels.discard("external_contract_call")
        ordered = sorted(labels)
        record["effect_labels"] = ordered
        record["action_summary"] = _action_summary(ordered, list(record.get("effect_targets") or []))
