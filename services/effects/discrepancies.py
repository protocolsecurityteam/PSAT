"""§9 plane-disagreement routing into the existing warning channel.

The warning channel is the codebase's degraded-but-continuing mechanism
(``utils.logging.record_degraded`` → the per-job ``stage_errors`` artifact,
severity ``degraded``, surfaced on the /monitor job drill-in). §9 reuses it
rather than inventing a new consumer surface — a discrepancy is a "something
needs a human's attention, work continued" signal, exactly what that channel
carries.

Two directions (§9), both routed here with **closing-rule bookkeeping** — a
discrepancy is resolved ONLY by a matcher fix, a probe-soundness fix, or a
higher-tier witness; it is never auto-dropped and never silently kept:

* **static-positive / simulation-negative** (a static fact predicted the effect,
  the transition was not observed): a candidate matcher bug or probe-soundness
  hole. Routed with the recipe-attached :class:`~services.effects.harness.Discrepancy`.
  The verdict stays on the penalty side at a LOWERED confidence tier
  (``unknown``) — the non-observation never refutes the claim (§8 rule 1).
* **static-silent / simulation-positive** (a blank function, the transition WAS
  observed): the simulation witness stands (persisted verdict); a candidate new
  static idiom is filed here for vocabulary growth.

``record_degraded`` is a no-op outside a worker's job context, so services and
tests import this freely; inside the effects worker it accumulates onto the job.
"""

from __future__ import annotations

from typing import Any

from services.effects.harness import Discrepancy, ObservedEffect
from utils.logging import record_degraded

# Direction-2 discrepancy kind: a witnessed effect on a static-silent function,
# i.e. a candidate new static idiom.
NEW_IDIOM_KIND = "static_silent_sim_positive_new_idiom"

# The only three ways a §9 discrepancy is ever closed (never auto-dropped).
_CLOSING_RULE = "matcher_fix | probe_soundness_fix | higher_tier_witness"


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
    The witness itself is persisted by the caller; this files a candidate new
    static idiom into the warning channel so the static vocabulary can grow from
    evidence instead of user-test embarrassment."""
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
    record_degraded(
        phase="effects_new_idiom_candidate",
        exc=PlaneDisagreement(f"new static idiom witnessed ({effect.effect_class}) at {effect.tier}"),
        context=context,
    )
