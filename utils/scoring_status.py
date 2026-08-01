"""Scoring three-state vocabularies.

A leaf module on purpose, mirroring ``utils.balance_status``. The schema
(``db.models``), the CHECK-constraint text in the migration, the distiller and
the fold must all name the same strings; a second copy of any of them is a
divergence vector. Nothing here imports anything, so every layer can depend on
it.

The governing rule: a value is published as a positive fact only when the
evidence proves it. Every unreadable, contradictory or absent witness lands on
``not_determined`` — never on a polarity, in either direction, and never on a
default. Each vocabulary below therefore contains ``not_determined`` as an
explicit member rather than leaving it to a NULL or an omission.
"""

from __future__ import annotations

# --- severity --------------------------------------------------------------
# There is deliberately no "proven_absent" arm. A proven zero severity is
# ``proven`` carrying 0.0 (the ``pause.set`` build-up starts there), which is a
# different fact from "we could not read the severity" and must stay one.
SEVERITY_STATE_PROVEN = "proven"
SEVERITY_STATE_NOT_DETERMINED = "not_determined"
SEVERITY_STATES = (SEVERITY_STATE_PROVEN, SEVERITY_STATE_NOT_DETERMINED)

# --- witness tier ----------------------------------------------------------
# The tier of the claim witness the signal was distilled from. ``policy_derived``
# is a real tier that blocks the static-conjunction arm, so it cannot be folded
# into ``not_determined``.
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

# --- authority openness ----------------------------------------------------
# The three-state counterpart of ``effective_functions.authority_public``, whose
# ``false`` merges "a caller restriction was witnessed" with "the authority could
# not be determined". Carried here NOT NULL so the merge cannot re-enter: the
# source column's NULL (written before it existed) distils to
# ``not_determined``, never to ``restricted``.
OPENNESS_OPEN = "open"
OPENNESS_RESTRICTED = "restricted"
OPENNESS_NOT_DETERMINED = "not_determined"
OPENNESS_STATES = (OPENNESS_OPEN, OPENNESS_RESTRICTED, OPENNESS_NOT_DETERMINED)

# --- principal enumeration -------------------------------------------------
# ``enumerated`` is a PROVEN LOWER BOUND on the caller set and never a count:
# ``role_holder_planes.holders`` is itself a lower bound, so the referenced list
# may raise breadth concern and may never lower it. ``none_required`` is the
# earned negative (a public path was proven) — the opposite pole from
# ``not_determined``, not a coarsening of it.
PRINCIPAL_STATE_ENUMERATED = "enumerated"
PRINCIPAL_STATE_NONE_REQUIRED = "none_required"
PRINCIPAL_STATE_NOT_DETERMINED = "not_determined"
PRINCIPAL_STATES = (
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NONE_REQUIRED,
    PRINCIPAL_STATE_NOT_DETERMINED,
)

# --- value reach -----------------------------------------------------------
# The signal carries entity KEYS, never dollars: the fold does MAX per
# (entity, asset) because only it sees every finding that touches an entity.
# ``proven_no_reach`` is the earned negative (reach was witnessed and reached
# nothing); a failed or absent balance read is ``not_determined`` and is never
# counted as zero.
VALUE_STATE_PROVEN_REACH = "proven_reach"
VALUE_STATE_PROVEN_NO_REACH = "proven_no_reach"
VALUE_STATE_NOT_DETERMINED = "not_determined"
VALUE_STATES = (
    VALUE_STATE_PROVEN_REACH,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_NOT_DETERMINED,
)

# Whether the referenced entity set is the whole reach or a proven floor. A
# floor may raise the band and may never be read as the exact set.
VALUE_BOUND_EXACT = "exact"
VALUE_BOUND_FLOOR = "floor"
VALUE_BOUND_NOT_DETERMINED = "not_determined"
VALUE_BOUNDS = (VALUE_BOUND_EXACT, VALUE_BOUND_FLOOR, VALUE_BOUND_NOT_DETERMINED)

# --- destination lattice ---------------------------------------------------
# ``not_applicable`` is a fourth member and a genuinely different fact from
# ``not_determined``: ``pause.set`` has no destination to constrain, whereas an
# unreadable ``delegatecall.execute`` destination has one that was not proven.
# Collapsing them would make the banned escalation (absence of a constraint
# witness raising severity) representable again.
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

# --- reach gate ------------------------------------------------------------
# The ``gated_contract_backlink`` licence to charge a holder's value through a
# gated function. ``not_licensed`` is a reachability verdict only: it never types
# the holder and a mismatch is not an earned negative.
REACH_GATE_LICENSED = "licensed"
REACH_GATE_NOT_LICENSED = "not_licensed"
REACH_GATE_NOT_DETERMINED = "not_determined"
REACH_GATE_STATES = (REACH_GATE_LICENSED, REACH_GATE_NOT_LICENSED, REACH_GATE_NOT_DETERMINED)

# --- protocol score --------------------------------------------------------
GRADE_STATE_COMPUTED = "computed"
GRADE_STATE_NOT_DETERMINED = "not_determined"
GRADE_STATES = (GRADE_STATE_COMPUTED, GRADE_STATE_NOT_DETERMINED)

# Widened from the strategy's ``perimeter_settled`` bool so a failed queue read
# cannot land on either polarity. The two ruled values are ``settled`` /
# ``unsettled``; a score computed without a readable queue is stamped
# ``not_determined`` rather than claimed settled.
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

# The empty-string selector sentinel for fallback/receive entry points, which
# have no selector. Same literal and same reason as ``effect_verdicts.selector``
# — it keeps the identity constraint portable instead of NULL-holed.
NO_SELECTOR = ""

# The model version every score row is stamped with until a second protocol
# exists to calibrate against. Any constant change bumps it (strategy §7.2).
MODEL_VERSION = "1.0.0-provisional"
