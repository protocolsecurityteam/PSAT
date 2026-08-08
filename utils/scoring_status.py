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
# FIGURE. Three of the four members ride the free-form
# ``gate_inputs->'reach_magnitude_usd'`` envelope, where they are validated by
# the fold's own allow-list and nothing else.
#
# ``proven_ceiling`` is the exception and does NOT ride that envelope: it is
# derived inside the fold from the ``ValuePlane`` and is deliberately absent
# from the allow-list (``fold.GATE_PROVEN_TOKENS``, the ``reach_magnitude_usd``
# entry — see the comment there). A distiller that stamps it on a gate is not
# adding a state to a vocabulary; it is handing ``_gate`` a token the allow-list
# does not carry, which withholds the row. Adding the state there is the
# decision to take first, and this comment is the only place that says so:
# nothing reads ``MAGNITUDE_STATES`` below, so the tuple can neither admit nor
# refuse anything on its own.
#
# Four members, because the second and the last two are opposite directions:
#   * ``proven_exact`` — the witness measured the call's own magnitude.
#   * ``proven_floor`` — the call moves AT LEAST this much (a partly priced
#     sheet, a gated indeterminate reach). The truth is at or above it.
#   * ``proven_upper_bound`` — the ATTRIBUTION path: a probe moved a
#     compile-time constant amount and the holder's whole priced balance was
#     credited for the pair. The truth is at or BELOW it. It is not exact (no
#     witness says the call moves the whole balance) and it is emphatically not
#     a floor (``proven_floor``'s prose means "at least this much", which this
#     figure does not support in that direction).
#   * ``proven_ceiling`` — the SHEET path: the principal can replace the
#     controlled node's code, so nothing the node's current code does stands
#     between them and what the node holds, and the node's own priced sheet
#     bounds the move from ABOVE. Same direction as ``proven_upper_bound`` and a
#     different provenance — a per-ENTITY balance observation rather than a
#     per-CALL probe attribution — so the two are kept apart here for the same
#     reason the module keeps every other pair of same-shape facts apart: a
#     consumer that must say WHY the figure is a bound cannot read it off a
#     token that merged them.
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
# The states whose figure bounds the principal from ABOVE and never from below,
# so a row summing them has not earned a ">=" band. Named as a set rather than
# tested against one token, so a future upper-bounding state joins the rule by
# being registered here instead of by being remembered at each consumer — which
# is exactly how ``proven_ceiling`` joined it. Membership is the DIRECTION only:
# the members share nothing else, and every consumer that must name the
# provenance behind the bound branches on the state itself.
MAGNITUDE_STATES_UPPER_BOUNDING = (
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    MAGNITUDE_STATE_PROVEN_CEILING,
)

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

# The grade's answer to a question ``grade_state`` does not ask: was every
# published magnitude's proving execution reachable when this document was
# folded. Deliberately NOT a fourth ``GRADE_STATES`` member — a fault-degraded
# grade is still a COMPUTED one (lambda, exposure and confidence are all
# present, and ``ck_protocol_scores_grade_pairing`` binds that token to exactly
# that), so putting it in the same vocabulary would either falsify the
# constraint or force the three figures to null and withhold a grade that was
# computed. It rides its own document field instead, and the two questions stay
# apart.
GRADE_FAULT_DEGRADED = "fault_degraded"

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
#
# 1.2.0: code control gets a magnitude. 1.1.0 left it with none — "which
# function does replacing the whole implementation let you call?" has no answer,
# so every code-control row fell to the unpriced floor and total control of a
# $3.62B proxy ranked below a $90.06 withdrawal. The answer that needs no
# further witness is the controlled node's OWN priced sheet: replacing what that
# node does removes the one thing that stood between the principal and its
# holdings, so the sheet bounds the move from above. It is published as a
# ``proven_ceiling`` — an at-most, never an amount — only at the node the code
# control is over (a downstream node's own code still stands), and only where
# the sheet is priced; dust, unpriced and no-rows sheets stay not_determined,
# and a provably empty sheet is an earned $0 ceiling. Gate control and pause.set
# are untouched. Ceilings move lambda and the ranking; they stay OUT of
# exposure_usd, because an upper bound on a move nobody witnessed is not
# expected loss. Measured on protocol 1: lambda 73.2508 -> 71.7053, letter
# B+ -> B, exposure_usd unchanged at $18,059,003.86, confidence headline
# unchanged at 18.6 with its magnitude term 37.6 -> 40.9.
#
# The gradeBands.js obligation above is LIVE for this bump: it carries a
# 1.2.0-provisional entry that reasons 1.1.0's cut points forward rather than
# recutting them, so the letter drop is published rather than absorbed.
#
# 1.2.0 is also the SETTLING EVENT for one absence this model could not read.
# ``execution_evidence_faults`` (``services/scoring/schema.py``) omits its key
# when the fold walked every published magnitude's proving execution and found
# no fault — absence is meant to be a completed count of zero. But the field
# arrived MID-1.1.0 (PR #172), so on a 1.1.0 document absence cannot tell a
# fault-free fold from one that predates the census, and it has to be read as
# not_determined. Every document stamped 1.2.0-provisional or later ran the
# census unconditionally (``fold.py`` calls it on every fold, before the grade
# is assembled), so from this version on an absent key IS the earned zero. The
# boundary is the version stamp and nothing else: readers join on
# model_version, which is why the settlement is recorded here and republished
# on the migration record rather than left in a spec.
#
# 1.3.0: a truncated asset list no longer ADMITS A SHEET CEILING — that arm and
# no other. The ERC-20 discovery endpoint answers one 100-entry page, so a
# holder with more assets than that is stored as a PREFIX of its holdings — and
# 1.2.0 admitted that prefix as a ceiling, because the sheet's state reads
# ``priced`` whether the list was cut off or not. The plane now carries the
# at-cap fact per entity (``planes.ValuePlane.asset_set_truncated``, off the
# latest ``contract_balance_fetches.asset_set_status``) and ``ceiling_for``
# refuses those sheets under a fifth refusal token, ``asset_list_truncated``,
# which is closed by paging or a chain-derived sweep rather than by a price
# lookup.
#
# What this bump does NOT close, stated because the version stamp is what a
# reader joins on: a sheet caps a figure from above at two other sites — the
# composed-magnitude cap in ``fold._compose`` and the entity-holdings cap in
# ``fold._entity_contribution``, both a ``min(witness, sheet)`` — and
# neither consults ``asset_set_truncated``, so a page-capped sheet still trims a
# composed magnitude on a 1.3.0 document. Live here on
# base::0x86b5780b606940eb59a062aa85a07959518c0161. Registered as open items in
# SHEET_OBSERVATION_SPEC.md; extending the guard to those sites is a separate
# change with its own measured differential.
# Measured on protocol 1: one live ceiling revoked (the $0.05 row on
# base::0x6c240dda…), ceiling entities 11 -> 10, signals credited 21 -> 20,
# refused calls 49 -> 50 (one re-tokenised from unpriced, one new), lambda
# 71.7053 and exposure_usd $18,059,003.86 UNCHANGED, letter B unchanged. The
# gradeBands.js obligation above is live for this bump too: it carries a
# 1.3.0-provisional entry that reasons 1.2.0's cut points forward.
#
# The direction is the point and it is ruled, not tolerated: this bump LOWERS a
# confidence term (see the migration record's invariant-6 exception). Invariant
# 6 governs earning evidence; un-publishing an at-most that was never earned is
# outside it.
#
# 1.4.0: a sheet may now be DETERMINED at $0 by the DELIVERY SHAPE of what
# arrived on it. A (entity, asset) reading is disposed only where every one of
# five conjuncts holds: the protocol's discovered address universe was assembled
# at all (unset ⇒ nothing is disposed anywhere), the asset is not the native
# coin, the reading is unpriced or below the storage column's resolution (a
# PRICED reading is never disposed), the token address is absent from that
# universe tested CHAIN-BLIND, and EVERY observed account contributing to the
# reading carries stored delivery evidence whose every incoming delivery fanned
# out to at least K = 25 same-token recipients in one transaction. Such a sheet
# answers a sixth state (``airdrop_determined``, distinct from ``proven_empty``
# — "what arrived arrived as a mass distribution" is not "nothing ever arrived")
# and an eighth ``ceiling_for`` reason of the same name, in the ADMITTING set.
#
# WHAT IT CLAIMS IS DELIVERY SHAPE AND NEVER WORTH, and that is load-bearing
# rather than decorative: the live run put two REAL tokens into this state on
# this corpus — uniETH (one delivery, fan-out 101) and USDtb (one delivery,
# fan-out 175) — and a third, HEX (199/399/399), carries the same delivery shape
# and is held out of the state only by the protocol-reference conjunct. No
# consumer may rename it spam, scam or worthless: under any such name the
# published claim would be false of all three.
#
# What this bump does NOT close, stated because the version stamp is what a
# reader joins on:
#   * the protocol-reference conjunct is INERT ON BASE — it condemns 1,175 of
#     1,175 base unpriced tokens, so it partitions nothing there and delivery
#     shape carries the claim alone over 1,745 readings; its precision on base
#     is not_determined at n=6.
#   * the asset list a disposition covers is NOT proven whole. The gate refuses
#     only a list read AT the page cap (D1 parity), so the determination is over
#     the readings observed and never over the holdings. That is exactly why the
#     state is BARRED from the two min(witness, sheet) trim sites — the disposed
#     assets are still held, and trimming a witnessed magnitude to $0 there
#     would publish a false zero — and why a disposition alone does not earn
#     asset-set coverage completeness.
#   * the rule is ANTI-MONOTONE in discovery (see the migration record's
#     invariant-6 exception): growing the universe withdraws determinations,
#     which is the safe direction, but this document is NOT stable across
#     discovery growth. HEX is spared by a single effect_verdicts row.
# Measured on protocol 1 at this bump: the delivery-evidence table is EMPTY, so
# entities_determined 0, readings_disposed 0, and every published figure is
# unchanged — confidence_pct 42.5, lambda 71.7053, grade_exposure 99.582,
# exposure_usd $18,061,300.76, letter B. The gradeBands.js obligation is live
# for this bump too: it carries a 1.4.0-provisional entry reasoning 1.3.0's cut
# points forward.
MODEL_VERSION = "1.4.0-provisional"
