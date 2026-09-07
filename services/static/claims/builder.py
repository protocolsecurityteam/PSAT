"""Build the claims artifact and ride it through the facts carrier.

:func:`build_claims` runs every registered matcher over the Plane-0 facts —
contract-level gate, then per-function trigger — and mints each hit through
``emit_claim``, so an unregistered id can't escape a matcher. The result is a
standalone artifact keyed by function full-name (an empty list per function is
valid and common).

:func:`attach_claims_to_effects` merges that artifact back onto the ``effects``
artifact's per-function records. The policy stage already carries ``effects``
end to end, so claims reach ``build_permission_index`` with no new
artifact plumbing. Both functions fail soft on a degraded (errored) artifact.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from .context import ClaimContext
from .matchers import discover
from .registry import emit_claim, registry, resolve_claim_precedence
from .types import SCHEMA_VERSION, EffectMatch, MatchAnalysis, MatchDiagnostic, MatchOmission, MatchResults

logger = logging.getLogger(__name__)


def build_claims(contract: Any, effects: Any, predicate_trees: Any) -> MatchResults:
    """Run all registered matchers over the facts, returning the claims artifact.

    A matcher that raises is isolated: it forfeits only its own claims (logged),
    never the whole pass. Per function the registry precedence rule then keeps
    the strongest tier of each claim; claim ordering is deterministic.
    """
    discover()
    ctx = ClaimContext(contract, effects, predicate_trees)
    signatures = ctx.function_signatures()
    functions: dict[str, list[EffectMatch]] = {signature: [] for signature in signatures}

    analyses: dict[str, MatchAnalysis] = {}
    diagnostics: list[MatchDiagnostic] = []

    for entry in registry().values():
        omissions: list[MatchOmission] = []
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
