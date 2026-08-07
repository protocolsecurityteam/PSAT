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

# --- magnitude state -------------------------------------------------------
# A DIFFERENT axis from ``VALUE_BOUND_*`` above, and the two are routinely
# confused because both spell "exact" and "floor". ``VALUE_BOUND_*`` grades the
# ENTITY SET — is ``value_entity_keys`` the whole reach or a proven floor over
# it — and is CHECK-constrained in the database. This one grades the DOLLAR
# FIGURE and lives inside the free-form ``gate_inputs->'reach_magnitude_usd'``
# envelope, where it is validated by the fold's own allow-list and nothing else.
#
# Three members, because the second and third are opposite directions:
#   * ``proven_exact`` — the witness measured the call's own magnitude.
#   * ``proven_floor`` — the call moves AT LEAST this much (a partly priced
#     sheet, a gated indeterminate reach). The truth is at or above it.
#   * ``proven_upper_bound`` — the ATTRIBUTION path: a probe moved a
#     compile-time constant amount and the holder's whole priced balance was
#     credited for the pair. The truth is at or BELOW it. It is not exact (no
#     witness says the call moves the whole balance) and it is emphatically not
#     a floor (``proven_floor``'s prose means "at least this much", which this
#     figure does not support in that direction).
MAGNITUDE_STATE_PROVEN_EXACT = "proven_exact"
MAGNITUDE_STATE_PROVEN_FLOOR = "proven_floor"
MAGNITUDE_STATE_PROVEN_UPPER_BOUND = "proven_upper_bound"
MAGNITUDE_STATES = (
    MAGNITUDE_STATE_PROVEN_EXACT,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
)
# The states whose figure bounds the principal from ABOVE and never from below,
# so a row summing them has not earned a ">=" band. Named as a set rather than
# tested against one token, so a future upper-bounding state joins the rule by
# being registered here instead of by being remembered at each consumer.
MAGNITUDE_STATES_ATTRIBUTION_DERIVED = (MAGNITUDE_STATE_PROVEN_UPPER_BOUND,)

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

# The shape payload of the ``not_applicable`` arm. Every state except
# ``not_determined`` carries a shape, so exactly one state means "unread" and the
# pairing CHECK is a plain biconditional instead of a three-way special case.
DESTINATION_SHAPE_NOT_APPLICABLE = "not_applicable"

# The capabilities whose behaviour HAS a destination. For these,
# ``not_applicable`` is never a truthful answer — an unread destination on a
# delegatecall is ``not_determined``, and letting it present as "there is no
# destination here" would launder an unread witness into a non-escalating state,
# which is the prototype's −30λ false positive arriving by a different door. The
# schema CHECK is what makes that unrepresentable rather than merely discouraged.
DESTINATION_BEARING_CLAIMS = (
    "flow.out",
    "delegatecall.execute",
    "exec.arbitrary",
)

# The other half of the same guard, and the only source a distiller may stamp
# ``not_applicable`` from. ``DESTINATION_BEARING_CLAIMS`` names the capabilities
# for which "there is no destination here" is provably false; this names the ones
# for which it is provably TRUE, and everything outside both is
# ``not_determined``. Without it, "not in the bearing tuple" reads as
# "destination-free", which is absence standing in for a witness: ``value_router``
# carries a whole ``flows[]`` array and ``callee_pointer.rotate`` rotates a call
# target, and both would have published "no destination" on that reasoning.
#
# Membership is justified per member, never by default:
#   pause.set / pause.unset      — a latch; there is no operand to redirect
#   ownership.renounce           — takes no argument
#   timelock.set_delay           — a scalar parameter
#   rate_limit.consume           — draws down a counter
DESTINATION_FREE_CLAIMS = (
    "pause.set",
    "pause.unset",
    "ownership.renounce",
    "timelock.set_delay",
    "rate_limit.consume",
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
#
# 1.1.0: reach carries its class and its bounds. A capability that replaces CODE
# and one that replaces a GATE no longer share a reach rule; both are bounded by
# the destination's own caller conditions; and — the change that moves the
# numbers — a reach whose MAGNITUDE no witness proved publishes not_determined
# instead of the reached entity's balance sheet. The finding survives at the
# unpriced band's floor and the missing magnitude is charged to confidence.
# ``site/src/score/gradeBands.js`` carries the matching band table; without an
# entry there the bump would strip the published letter.
MODEL_VERSION = "1.1.0-provisional"
