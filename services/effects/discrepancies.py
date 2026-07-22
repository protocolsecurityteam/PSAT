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
