"""Scoring three-state vocabularies; a leaf module shared by schema, migration CHECKs, distiller and fold.

Unreadable, contradictory or absent witnesses land on ``not_determined``, never a polarity or a default, so every
vocabulary carries it explicitly.
"""

from __future__ import annotations

NOT_DETERMINED = "not_determined"

# No "proven_absent": a proven zero is ``proven`` with 0.0, distinct from unreadable.
SEVERITY_STATE_PROVEN = "proven"
SEVERITY_STATE_NOT_DETERMINED = "not_determined"
SEVERITY_STATES = (SEVERITY_STATE_PROVEN, SEVERITY_STATE_NOT_DETERMINED)

# ``policy_derived`` blocks the static-conjunction arm, so it can't fold into ``not_determined``.
WITNESS_TIER_STANDARD_EXACT = "standard_exact"
WITNESS_TIER_IDIOM_STRUCTURAL = "idiom_structural"
WITNESS_TIER_BEHAVIORAL_OBSERVED = "behavioral_observed"
WITNESS_TIER_POLICY_DERIVED = "policy_derived"
WITNESS_TIER_NOT_DETERMINED = "not_determined"
WITNESS_TIERS = (
    WITNESS_TIER_STANDARD_EXACT,
    WITNESS_TIER_IDIOM_STRUCTURAL,
    WITNESS_TIER_BEHAVIORAL_OBSERVED,
    WITNESS_TIER_POLICY_DERIVED,
    WITNESS_TIER_NOT_DETERMINED,
)

# Three-state counterpart of ``authority_public``, whose ``false`` merges "restricted" with "unknown". Source NULL
# distils to ``not_determined``, never ``restricted``.
OPENNESS_OPEN = "open"
OPENNESS_RESTRICTED = "restricted"
OPENNESS_NOT_DETERMINED = "not_determined"
OPENNESS_STATES = (OPENNESS_OPEN, OPENNESS_RESTRICTED, OPENNESS_NOT_DETERMINED)
OPENNESS_VALUES = frozenset(OPENNESS_STATES)

# ``enumerated`` is a lower bound on callers: may raise breadth concern, never lower it. ``none_required`` is the earned
# negative (a public path was proven).
PRINCIPAL_STATE_ENUMERATED = "enumerated"
PRINCIPAL_STATE_NONE_REQUIRED = "none_required"
PRINCIPAL_STATE_NOT_DETERMINED = "not_determined"
PRINCIPAL_STATES = (
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NONE_REQUIRED,
    PRINCIPAL_STATE_NOT_DETERMINED,
)

# Entity keys, never dollars: the fold MAXes per (entity, asset). A failed balance read is ``not_determined``, never
# zero.
VALUE_STATE_PROVEN_REACH = "proven_reach"
VALUE_STATE_PROVEN_NO_REACH = "proven_no_reach"
VALUE_STATE_NOT_DETERMINED = "not_determined"
VALUE_STATES = (
    VALUE_STATE_PROVEN_REACH,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_NOT_DETERMINED,
)

# A floor may raise the band but is never read as the exact set.
VALUE_BOUND_EXACT = "exact"
VALUE_BOUND_FLOOR = "floor"
VALUE_BOUND_NOT_DETERMINED = "not_determined"
VALUE_BOUNDS = (VALUE_BOUND_EXACT, VALUE_BOUND_FLOOR, VALUE_BOUND_NOT_DETERMINED)

# Grades the dollar figure; ``VALUE_BOUND_*`` grades the entity set. Easily confused.
#
# ``proven_ceiling`` is derived inside the fold and deliberately absent from ``fold.GATE_PROVEN_TOKENS``; a distiller
# stamping it on a gate withholds the row. Nothing reads ``MAGNITUDE_STATES``.
#
#   * ``proven_exact`` — the call's own magnitude was measured.
#   * ``proven_floor`` — truth is at or above.
#   * ``proven_upper_bound`` — attribution path (constant-amount probe credited the holder's whole balance); truth at or
# below.
#   * ``proven_ceiling`` — sheet path (principal can replace the node's code, so its priced sheet bounds from above).
# Kept apart from upper_bound because the provenance differs.
MAGNITUDE_STATE_PROVEN_EXACT = "proven_exact"
MAGNITUDE_STATE_PROVEN_FLOOR = "proven_floor"
MAGNITUDE_STATE_PROVEN_UPPER_BOUND = "proven_upper_bound"
MAGNITUDE_STATE_PROVEN_CEILING = "proven_ceiling"
MAGNITUDE_STATES = (
    MAGNITUDE_STATE_PROVEN_EXACT,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    MAGNITUDE_STATE_PROVEN_CEILING,
)
# States bounding from above, so a sum hasn't earned a ">=" band. A new upper-bounding state joins by registration here.
MAGNITUDE_STATES_UPPER_BOUNDING = (
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    MAGNITUDE_STATE_PROVEN_CEILING,
)

# ``not_applicable`` differs from ``not_determined``: ``pause.set`` has no destination, while an unread
# ``delegatecall.execute`` destination was not proven. Merging them re-enables the banned escalation.
DESTINATION_STATE_CONSTRAINED_PROVEN = "constrained_proven"
DESTINATION_STATE_UNCONSTRAINED_PROVEN = "unconstrained_proven"
DESTINATION_STATE_NOT_APPLICABLE = "not_applicable"
DESTINATION_STATE_NOT_DETERMINED = "not_determined"
DESTINATION_STATES = (
    DESTINATION_STATE_CONSTRAINED_PROVEN,
    DESTINATION_STATE_UNCONSTRAINED_PROVEN,
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_NOT_DETERMINED,
)

# Every state except ``not_determined`` carries a shape, keeping the pairing CHECK a plain biconditional.
DESTINATION_SHAPE_NOT_APPLICABLE = "not_applicable"

# Capabilities that have a destination, so ``not_applicable`` is never truthful for them; the schema CHECK enforces it.
DESTINATION_BEARING_CLAIMS = (
    "flow.out",
    "delegatecall.execute",
    "exec.arbitrary",
)

# The only capabilities a distiller may stamp ``not_applicable`` from; everything outside both tuples is
# ``not_determined``. Membership is justified per member:
DESTINATION_FREE_CLAIMS = (
    "pause.set",
    "pause.unset",
    "ownership.renounce",
    "timelock.set_delay",
    "rate_limit.consume",
)

# ``not_licensed`` is a reachability verdict only; it never types the holder.
REACH_GATE_LICENSED = "licensed"
REACH_GATE_NOT_LICENSED = "not_licensed"
REACH_GATE_NOT_DETERMINED = "not_determined"
REACH_GATE_STATES = (REACH_GATE_LICENSED, REACH_GATE_NOT_LICENSED, REACH_GATE_NOT_DETERMINED)

GRADE_STATE_COMPUTED = "computed"
GRADE_STATE_NOT_DETERMINED = "not_determined"
GRADE_STATES = (GRADE_STATE_COMPUTED, GRADE_STATE_NOT_DETERMINED)

# Whether every published magnitude's proving execution was reachable. Not a ``GRADE_STATES`` member: a fault-degraded
# grade is still computed (``ck_protocol_scores_grade_pairing``).
GRADE_FAULT_DEGRADED = "fault_degraded"

# A failed queue read is ``not_determined``, never claimed settled.
PERIMETER_SETTLED = "settled"
PERIMETER_UNSETTLED = "unsettled"
PERIMETER_NOT_DETERMINED = "not_determined"
PERIMETER_STATES = (PERIMETER_SETTLED, PERIMETER_UNSETTLED, PERIMETER_NOT_DETERMINED)

SCORE_TRIGGER_JOB = "job"
SCORE_TRIGGER_DIRTY_LOOP = "dirty_loop"
SCORE_TRIGGER_STALENESS_SWEEP = "staleness_sweep"
SCORE_TRIGGER_MANUAL = "manual"
SCORE_TRIGGERS = (
    SCORE_TRIGGER_JOB,
    SCORE_TRIGGER_DIRTY_LOOP,
    SCORE_TRIGGER_STALENESS_SWEEP,
    SCORE_TRIGGER_MANUAL,
)

# The two disclosures ride every proven verdict (G7), so excluded rows carry them too.
SELF_SERVICE_STATE_PROVEN = "proven_self_service"
# W2 earned by the clearing write dominating every external call (the verified-guard alternative is a separate proof).
W2_BASIS_CLEAR_DOMINATES_CALLS = "clear_dominates_calls"
SELF_SERVICE_BASIS_BOUNDED = "proven_self_service_bounded"
SELF_SERVICE_DISCLOSE_UPGRADE = "self_service_bound_conditional_on_upgrade_authority"
SELF_SERVICE_DISCLOSE_SIBLING = "self_service_sibling_function_residual_not_proven"

TRACE_STEP_SOLMATE_ROLES_AUTHORITY = "solmate_roles_authority"
TRACE_STEP_ENUMERABLE_ROLE_STORE = "enumerable_role_store"

# Fallback/receive have no selector; same literal as ``effect_verdicts.selector`` to avoid NULL holes in the identity
# constraint.
NO_SELECTOR = ""

# Any constant change bumps it.
MODEL_VERSION = "1.4.1-provisional"
