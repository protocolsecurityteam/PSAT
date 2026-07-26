"""§9 plane-disagreement routing — two directions with asymmetric severity.

The two §9 directions are NOT the same kind of signal, and they route to
different surfaces accordingly:

* **direction 1 — static-positive / simulation-negative** (a static fact
  predicted the effect, the transition was not observed): a candidate matcher
  bug or probe-soundness hole, i.e. a *genuine degradation*. Routed into the
  warning channel (``utils.logging.record_degraded`` → the per-job
  ``stage_errors`` artifact, severity ``degraded``, surfaced on the /monitor job
  drill-in) with the recipe-attached :class:`~services.effects.harness.Discrepancy`.
  The verdict stays on the penalty side at a LOWERED confidence tier
  (``unknown``) — the non-observation never refutes the claim (§8 rule 1). This
  is rare (a static prediction that simulation contradicts).

* **direction 2 — static-silent / simulation-positive** (a blank function, the
  transition WAS observed): the simulation witness stands (persisted verdict); a
  candidate new static idiom is an **informational vocabulary-growth signal, not
  a degradation**. Because selection returns ONLY blank-claim functions, every
  proven verdict is a direction-2 event — a fully healthy run produces dozens to
  hundreds of these, so filing them as ``degraded`` would make /monitor advertise
  errors on a healthy job. Direction 2 therefore emits an INFO log (harvestable
  from logs for offline idiom mining) and files NO degraded ``StageError``.

Both carry **closing-rule bookkeeping** — a discrepancy is resolved ONLY by a
matcher fix, a probe-soundness fix, or a higher-tier witness; it is never
auto-dropped and never silently kept.

``record_degraded`` is a no-op outside a worker's job context, so services and
tests import this freely; inside the effects worker it accumulates onto the job.
"""

from __future__ import annotations

import logging
from typing import Any

from services.effects.harness import Discrepancy, ObservedEffect
from utils.logging import record_degraded

logger = logging.getLogger("services.effects.discrepancies")

# Direction-2 discrepancy kind: a witnessed effect on a static-silent function,
# i.e. a candidate new static idiom.
NEW_IDIOM_KIND = "static_silent_sim_positive_new_idiom"

# Direction-3 discrepancy kind (§7): the AUTHORITY plane. Effects is the only
# stage that executes a call AS a resolved principal, so it alone can falsify
# authority resolution — and until now it discarded that signal.
AUTHORITY_CONTRADICTION_KIND = "authority_exact_member_gate_rejected"

# Canonical, PUBLISHED gate-rejection error selectors (OpenZeppelin v5). Both name
# the REJECTED CALLER in their ABI payload, so a revert carrying one is
# unambiguously "this caller is not authorized" — never a state precondition
# (§9.2b's "operation is not ready" is a state error, not one of these). SELECTORS
# ONLY: an ``Error(string)`` "...is missing role..." decoded as text, or a
# protocol-local ``Unauthorized()`` matched by name, is the substring heuristic
# that produced two false positives in this investigation (§0.0.1/§7) and stays
# out. A published standard selector is a proven fact; a revert-string is not.
_GATE_REJECTION_SELECTORS = frozenset(
    {
        "0xe2517d3f",  # AccessControlUnauthorizedAccount(address,bytes32)
        "0x118cdaa7",  # OwnableUnauthorizedAccount(address)
    }
)

# The only three ways a §9 discrepancy is ever closed (never auto-dropped).
_CLOSING_RULE = "matcher_fix | probe_soundness_fix | higher_tier_witness"


def _gate_rejection_selector(revert_data: Any) -> str | None:
    """The canonical gate-rejection selector a revert carries, or ``None``. Keys on
    the 4-byte selector ALONE — never on a decoded revert string."""
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
    """§7 — the third §9 direction, on the AUTHORITY plane. Files a degraded
    ``StageError`` (direction-1 severity, D3) when ALL hold:

    1. the resolved principal came from a ``capability_expr`` the resolver marked
       an EXACT ``finite_set`` — it claims to have enumerated exactly who may call
       F, and it named this principal;
    2. the probe — run AS that principal — was rejected with a CANONICAL, published
       gate-rejection selector (:data:`_GATE_REJECTION_SELECTORS`, selectors only);
    3. no override could account for it — always true here: seeding writes token
       balances only, never roles or gate flags (§7), so the rejection is not an
       artefact of the probe's own state manipulation.

    Then the enumeration named the WRONG holder — a resolution defect effects is
    uniquely placed to catch, filed rather than discarded. Restricted to the
    value/supply classes, whose every probe call is issued as the acting principal;
    ``authority_change`` deliberately rejects RANDOM identities at the same gate, so
    a gate-rejection revert there is the expected behaviour, not a contradiction.

    Returns whether a discrepancy was filed."""
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
    """Carrier passed to ``record_degraded`` for a §9 discrepancy. Type-only
    signalling — the message/context hold the detail, mirroring how
    ``policy_worker`` constructs a bespoke ``RuntimeError`` for the channel."""


def route_discrepancy(
    disc: Discrepancy,
    *,
    contract_address: str,
    selector: str | None,
    tier: str | None = None,
) -> None:
    """Route a recipe-attached §9 discrepancy (direction 1 / static under-
    prediction) into the warning channel with the discrepancy attached and the
    closing rule recorded."""
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
    """Direction 2 (§9): a witnessed effect on a static-silent (blank) function.
    The witness itself is persisted by the caller; this emits an INFO-level
    vocabulary-growth signal (NOT a degraded ``StageError``) so the static
    vocabulary can grow from evidence harvested off the logs. Every proven
    verdict is a direction-2 event, so filing these as degraded would flood a
    healthy job's ``stage_errors`` — this is a benign metric, not a failure."""
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
