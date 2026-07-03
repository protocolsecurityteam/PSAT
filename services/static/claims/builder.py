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
from typing import Any

from .context import ClaimContext
from .matchers import discover
from .registry import emit_claim, registry, resolve_claim_precedence
from .types import SCHEMA_VERSION, Claim, ClaimsArtifact

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
    functions: dict[str, list[Claim]] = {signature: [] for signature in signatures}

    for entry in registry().values():
        try:
            if not entry.gate(ctx):
                continue
            for signature in signatures:
                evidence = entry.trigger(ctx, signature)
                if evidence is None:
                    continue
                functions[signature].append(emit_claim(entry.claim_id, evidence.tier, evidence.witness))
        except Exception:
            logger.warning(
                "claim matcher %s failed",
                entry.claim_id,
                extra={"claim_id": entry.claim_id},
                exc_info=True,
            )

    for signature in functions:
        functions[signature] = resolve_claim_precedence(functions[signature])

    return {
        "schema_version": SCHEMA_VERSION,
        "contract_name": ctx.contract_name,
        "functions": functions,
    }


def attach_claims_to_effects(effects: Any, claims_artifact: Any) -> None:
    """Write each function's claims onto its ``effects`` record (in place), so
    the existing effects transport carries them downstream. No-op if either
    artifact is degraded."""
    if not isinstance(effects, dict):
        return
    functions = effects.get("functions")
    if not isinstance(functions, dict):
        return
    by_function = claims_artifact.get("functions") if isinstance(claims_artifact, dict) else None
    if not isinstance(by_function, dict):
        by_function = {}
    for signature, record in functions.items():
        if isinstance(record, dict):
            record["claims"] = list(by_function.get(signature) or [])
