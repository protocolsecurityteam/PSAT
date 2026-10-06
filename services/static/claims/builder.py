"""Build the claims artifact and attach it to the effects artifact, which already travels to the policy stage."""

from __future__ import annotations

import logging
from typing import Any

from utils.logging import record_degraded

from .context import ClaimContext
from .matchers import discover
from .registry import emit_claim, legacy_projections, registry, resolve_claim_precedence
from .types import SCHEMA_VERSION, Claim, ClaimsArtifact

logger = logging.getLogger(__name__)


def build_claims(contract: Any, effects: Any, predicate_trees: Any) -> ClaimsArtifact:
    """Run every registered matcher over the facts and return the claims artifact.

    A raising matcher only forfeits its own claims. Each claim keeps its strongest tier; ordering is deterministic.
    """
    if (
        isinstance(effects, dict)
        and not effects.get("effect_scopes_version")
        and getattr(contract, "compilation_unit", None) is not None
    ):
        from ..contract_analysis_pipeline.effect_scopes import attach_effect_scopes

        attach_effect_scopes(contract, predicate_trees, effects)
    discover()
    ctx = ClaimContext(contract, effects, predicate_trees)
    signatures = ctx.function_signatures()
    functions: dict[str, list[Claim]] = {signature: [] for signature in signatures}

    for entry in registry().values():
        pending: dict[str, Claim] = {}
        try:
            if not entry.gate(ctx):
                continue
            for signature in signatures:
                if ctx.effect_record(signature).get("execution_outcome") == "always_reverts":
                    continue
                evidence = entry.trigger(ctx, signature)
                if evidence is None:
                    continue
                sites = ctx.effect_record(signature).get("effect_scopes") or []
                source_sites = evidence.witness.get("source_sites")
                if source_sites:
                    selected = [
                        s for s in sites if {"declaration": s["declaration"], "node": s["node"]} in source_sites
                    ]
                elif evidence.witness.get("sink_ids"):
                    selected = [s for s in sites if set(s.get("sink_ids", [])) & set(evidence.witness["sink_ids"])]
                else:
                    selected = []
                if source_sites and not selected and ctx.effect_record(signature).get("effect_scopes_complete"):
                    continue
                if selected:
                    from ..contract_analysis_pipeline.predicate_types import make_or_node

                    scope_tree = (
                        make_or_node([s["predicate"] for s in selected])
                        if all(s.get("predicate") for s in selected)
                        else None
                    )
                    scoped_predicates = {**(predicate_trees or {}), "trees": {**ctx._trees, signature: scope_tree}}
                    scoped_ctx = ClaimContext(contract, effects, scoped_predicates)
                    refined = entry.trigger(scoped_ctx, signature)
                    if refined is not None:
                        evidence = refined
                    evidence.witness["authority_scope_ids"] = [s["id"] for s in selected]
                elif source_sites:
                    evidence.witness["authority_scope_ids"] = []
                pending[signature] = emit_claim(entry.claim_id, evidence.tier, evidence.witness)
        except Exception as exc:
            record_degraded(phase="claim_matcher", exc=exc, context={"claim_id": entry.claim_id})
            logger.warning(
                "claim matcher %s failed",
                entry.claim_id,
                extra={"claim_id": entry.claim_id},
                exc_info=True,
            )
        else:
            for signature, claim in pending.items():
                functions[signature].append(claim)

    for signature in functions:
        functions[signature] = resolve_claim_precedence(functions[signature])

    # Retain the canonical stamp for consumers of older effects artifacts as well.
    # Unlowerable signatures are omitted; fallback/receive have no selector.
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
    }


def attach_claims_to_effects(effects: Any, claims_artifact: Any) -> None:
    """Write each function's claims, and its canonical ``abi_selector``, onto its ``effects`` record in place.

    No-op on a degraded artifact. A missing ``abi_selector`` means not determined; consumers must fall back.
    """
    if not isinstance(effects, dict):
        return
    functions = effects.get("functions")
    if not isinstance(functions, dict):
        return
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
    """Rebuild each function's legacy ``effect_labels`` from its fact-tier labels plus the ``legacy_projection`` of
    its claims, then refresh the action summary.

    An ``upgrade.implementation`` claim suppresses the ``delegatecall_execution`` emphasis on the sink it explains.
    """
    if not isinstance(effects, dict):
        return
    functions = effects.get("functions")
    if not isinstance(functions, dict):
        return
    # Deferred: the summaries module imports the claims package.
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
        # ``external_contract_call`` only survives when nothing more specific explains the function.
        if labels - {"external_contract_call"}:
            labels.discard("external_contract_call")
        ordered = sorted(labels)
        record["effect_labels"] = ordered
        record["action_summary"] = _action_summary(ordered, list(record.get("effect_targets") or []))
