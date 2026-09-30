"""§9 plane-disagreement routing, two directions with different severity.

* Direction 1, static-positive / simulation-negative: a matcher bug or probe-soundness hole. Routed to the warning
channel (``utils.logging.record_degraded`` → ``stage_errors``) with the recipe's
:class:`~services.effects.harness.Discrepancy`; the verdict stays ``unknown`` (a non-observation never refutes, §8 rule
1). Rare.
* Direction 2, static-silent / simulation-positive: the witness stands; a candidate new static idiom. Every proven
verdict on a blank function is one, so it's an INFO log, not a degraded ``StageError``.

Discrepancies close only via a matcher fix, a probe-soundness fix, or a higher-tier witness. ``record_degraded`` is a
no-op outside a worker job.
"""

from __future__ import annotations

import logging
from typing import Any

from services.effects.harness import Discrepancy, ObservedEffect
from utils.logging import record_degraded

logger = logging.getLogger("services.effects.discrepancies")

# Direction 2: a witnessed effect on a static-silent function.
NEW_IDIOM_KIND = "static_silent_sim_positive_new_idiom"

# Direction 3 (§7), the authority plane: only effects calls as a resolved principal, so only it can falsify authority
# resolution.
AUTHORITY_CONTRADICTION_KIND = "authority_exact_member_gate_rejected"

# OpenZeppelin v5 gate-rejection selectors, which name the rejected caller. Selectors only: revert-string or name
# matching produced false positives (§0.0.1/§7).
_GATE_REJECTION_SELECTORS = frozenset(
    {
        "0xe2517d3f",  # AccessControlUnauthorizedAccount(address,bytes32)
        "0x118cdaa7",  # OwnableUnauthorizedAccount(address)
    }
)

_CLOSING_RULE = "matcher_fix | probe_soundness_fix | higher_tier_witness"


def _gate_rejection_selector(revert_data: Any) -> str | None:
    """The canonical gate-rejection selector a revert carries, or ``None``; never a decoded string."""
    if not isinstance(revert_data, str) or len(revert_data) < 10:
        return None
    sel = revert_data[:10].lower()
    return sel if sel in _GATE_REJECTION_SELECTORS else None


def authority_contradiction(
    *,
    effect_class: str,
    transcript: dict[str, Any] | None,
    membership_exact: bool,
    contract_address: str,
    selector: str | None,
    tier: str | None,
    transcript_ptr: str | None,
) -> bool:
    """§7, the third direction on the authority plane. Files a degraded ``StageError`` when:

    1. the principal came from an exact ``finite_set`` capability that named it;
    2. the probe as that principal was rejected with a canonical gate selector (:data:`_GATE_REJECTION_SELECTORS`);
    3. no override explains it (seeding never writes roles or gate flags).

    Then the enumeration named the wrong holder. Only for value/supply classes; ``authority_change`` rejects random
    identities by design.

    Returns whether a discrepancy was filed.
    """
    if not membership_exact:
        return False
    if effect_class not in ("value_out", "supply"):
        return False
    matched: str | None = None
    for result in (transcript or {}).get("results") or ():
        if not isinstance(result, dict) or result.get("success"):
            continue
        sel = _gate_rejection_selector(result.get("return_or_revert"))
        if sel is not None:
            matched = sel
            break
    if matched is None:
        return False
    record_degraded(
        phase="effects_authority_contradiction",
        exc=PlaneDisagreement(f"exact-member gate rejection ({matched}) on {effect_class}"),
        context={
            "discrepancy_kind": AUTHORITY_CONTRADICTION_KIND,
            "effect_class": effect_class,
            "contract_address": contract_address.lower(),
            "selector": selector or "",
            "tier": tier,
            "transcript_ptr": transcript_ptr,
            "gate_rejection_selector": matched,
            "closing_rule": _CLOSING_RULE,
        },
    )
    return True


class PlaneDisagreement(RuntimeError):
    """Carrier for ``record_degraded``; the message and context hold the detail."""


def route_discrepancy(
    disc: Discrepancy,
    *,
    contract_address: str,
    selector: str | None,
    tier: str | None = None,
) -> None:
    """Route a direction-1 discrepancy to the warning channel with the closing rule."""
    context: dict[str, Any] = {
        "discrepancy_kind": disc.kind,
        "effect_class": disc.effect_class,
        "contract_address": contract_address.lower(),
        "selector": selector or "",
        "tier": tier,
        "transcript_ptr": disc.transcript_ptr,
        "detail": disc.detail,
        "closing_rule": _CLOSING_RULE,
    }
    record_degraded(
        phase="effects_discrepancy",
        exc=PlaneDisagreement(f"plane disagreement ({disc.kind}) on {disc.effect_class}"),
        context=context,
    )


def file_new_idiom_candidate(
    effect: ObservedEffect,
    *,
    contract_address: str,
    selector: str | None,
) -> None:
    """Direction 2 (§9): emit an INFO vocabulary-growth signal (not a degraded ``StageError``) for a witnessed effect
    on a blank function; the caller persists the witness.
    """
    context: dict[str, Any] = {
        "discrepancy_kind": NEW_IDIOM_KIND,
        "effect_class": effect.effect_class,
        "contract_address": contract_address.lower(),
        "selector": selector or "",
        "tier": effect.tier,
        "reason": effect.reason,
        "transcript_ptr": effect.transcript_ptr,
        "closing_rule": _CLOSING_RULE,
    }
    logger.info(
        "new static idiom candidate (%s) at %s on %s",
        effect.effect_class,
        effect.tier,
        context["contract_address"],
        extra=context,
    )
