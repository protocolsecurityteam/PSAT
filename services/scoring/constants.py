"""The model's constants — one named block, emitted verbatim in every document.

Every number the grade depends on lives here and travels with the score, so a
recalibration is a data change plus a ``model_version`` bump rather than a code
change nobody can see from the published document. The values are the
prototype's, carried over unchanged as **provisional**: there is no second
protocol to calibrate against, so re-deriving them now would only re-fit the one
corpus that produced them.

``UNCALIBRATED_ARMS`` names the rules whose POSITIVE branch has never fired on
any corpus we have measured. They are shipped because the absent branch is
load-bearing, but a consumer must be able to see that the arm is untested, so
the list is published in the document beside the constants.
"""

from __future__ import annotations

from typing import Any

from utils.scoring_status import MODEL_VERSION

# --- the two scale constants ------------------------------------------------
SEV_SCALE = 60.0
LAMBDA = 0.6

# --- value bands ------------------------------------------------------------
# (upper bound exclusive, weight). Above the last bound the weight is
# VALUE_BAND_TOP.
VALUE_BANDS: tuple[tuple[float, float], ...] = (
    (100_000.0, 0.15),
    (1_000_000.0, 0.3),
    (10_000_000.0, 0.5),
    (100_000_000.0, 0.7),
    (1_000_000_000.0, 0.9),
)
VALUE_BAND_TOP = 1.0

# The unpriced branch. A capability whose value could not be priced is a
# confidence gap, not a proven-cheap capability: it keeps the lowest band's
# weight (so the row still scores) and publishes ``value_band: not_determined``.
# Dropping the row instead would let an unpriceable asset buy a clean grade.
UNPRICED_BAND = 0.15

# --- per-capability severity ------------------------------------------------
# A capability-class constant reflects what the claim's PROVEN EXISTENCE
# licenses. It is refined only downward by mitigating witnesses, and is never
# raised by the absence of one.
BASE_SEVERITY: dict[str, float] = {
    "upgrade.implementation": 1.0,
    "authority.replace": 0.75,
    "roles.grant": 0.55,
    "roles.revoke": 0.4,
    "roles.configure": 0.55,
    "authorized_caller.rotate": 0.55,
    "ownership.transfer": 0.55,
    "pause.set": 0.0,  # built up from proven components only
    "transfer_policy.configure": 0.25,
    "timelock.set_delay": 0.3,
    "lz_oapp.set_peer": 0.3,
    "lz_oapp.set_delegate": 0.3,
    "delegatecall.execute": 1.0,
    "exec.arbitrary": 1.0,
    "flow.out": 0.9,
}

# --- destination-bearing severity -------------------------------------------
# These apply ONLY on a proven destination state. An unread destination yields
# no severity at all, so none of these can be reached by absence.
DEST_SEVERITY_UNCONSTRAINED = 1.0
DEST_SEVERITY_HASH_COMMITMENT_PINS = 0.20
DEST_SEVERITY_EXTERNAL_CALL_REVERT = 0.60
DEST_SEVERITY_CONSTRAINED_OTHER = 0.35
# address(this) as a delegatecall target preserves msg.sender, so every batched
# sub-call re-runs its own access control: the capability grants an arbitrary
# caller no incremental authority.
DEST_SEVERITY_DELEGATECALL_SELF = 0.0
# A plain CALL to self is a different fact: msg.sender becomes the contract, so
# a self destination can satisfy an ``address(this)`` gate. Fixed, but not
# benign.
DEST_SEVERITY_EXEC_SELF = 0.35
FLOW_SEVERITY_CALLER_ARBITRARY = 0.9
FLOW_SEVERITY_FIXED_DESTINATION = 0.10
OWNERSHIP_DEFAULT_ADMIN_RULES = 0.35
# The self-gated delay credit is RETIRED, not tuned to zero: it rested on "no
# other caller resolved", and the principal enumeration it read is a documented
# LOWER BOUND. Crediting a capability-class base down to nothing on the absence
# of a second resolved principal is the absence-as-a-witness move with the sign
# flipped, so the arm is withdrawn until an exhaustive caller-set witness exists.
# No constant remains, because a constant would invite the arm back.

# --- freeze ladder ----------------------------------------------------------
# Three rungs, each named for what LICENSES it rather than for the outcome it
# happens to produce:
#
#   FREEZE_CAPABILITY_PROVEN   the proven existence of a freeze capability, and
#                              nothing else. Unconditional, and the rung every
#                              undetermined recovery question stays on — an
#                              unread witness moves this in neither direction.
#   FREEZE_KEYSET_RECOVERABLE  the credited rung, licensed by PROVEN key-set
#                              independence. Equal to the existence rung today,
#                              so proving independence changes the BASIS rather
#                              than the number; the licensing is already correct
#                              if the two ever diverge.
#   FREEZE_SUSTAINABLE         added ONLY on proven key-set DEPENDENCE: this key
#                              set can freeze and also deny the recovery quorum.
#
# No duration term: ``duration_bound_source`` is not_determined wherever it is
# populated, and neither of the two values that would license one has ever
# appeared, so duration moves severity in neither direction.
FREEZE_CAPABILITY_PROVEN = 0.05
FREEZE_KEYSET_RECOVERABLE = 0.05
FREEZE_SUSTAINABLE = 0.20
FREEZE_AUTO_EXPIRY = 0.02
FREEZE_AUTO_EXPIRY_MAX_SECONDS = 30 * 86400

# --- weakness ladder --------------------------------------------------------
WEAKNESS_EOA = 0.9
WEAKNESS_ANYONE = 1.0
WEAKNESS_SAFE_UNCREDITED = 0.55
WEAKNESS_SAFE_SINGLE_SIGNER = 0.85
WEAKNESS_SAFE_MINORITY = 0.55
WEAKNESS_SAFE_MAJORITY = 0.35
WEAKNESS_SAFE_SUPERMAJORITY = 0.2
WEAKNESS_TIMELOCK_UNDETERMINED = 0.55
SAFE_MAJORITY_RATIO = 0.5
SAFE_SUPERMAJORITY_RATIO = 0.67

# A proven holder floor of more than one on the role that gates a capability is
# proven BREADTH: the gate is at most as strong as the weakest of several
# holders, and which one that is has not been resolved. It may only raise.
ROLE_BREADTH_MULTI_HOLDER_WEAKNESS = 0.55

# --- delay discount ---------------------------------------------------------
DELAY_DISCOUNT_FLOOR = 0.25
DELAY_DISCOUNT_SATURATION_DAYS = 30.0

# --- capability classes -----------------------------------------------------
# Capabilities whose reach follows the control closure. Both classes expand
# transitively (inv. 7 makes transitivity mandatory); they differ in WHAT BOUNDS
# the expansion, which is the distinction one table conflated.
#
# CODE control replaces what the node DOES. Controlling A's code lets A be made
# to exercise everything A is authorized to exercise, so the expansion is not
# scoped to any one role's selectors — but it is still not unconditional: a
# downstream hop is walked only where the destination's own conditions do not
# pin their caller to the destination itself (see ``planes.ConditionPlane``).
CODE_CONTROL_CAPABILITIES = frozenset(
    {
        "upgrade.implementation",
        "exec.arbitrary",
        "delegatecall.execute",
    }
)

# GATE control replaces who MAY CALL the node. A's own code still bounds what
# happens next: holding A's gate does not make A call B, it only lets the holder
# use the functions A already has. So the expansion is bounded by what the gate
# confers — at edge-label granularity, an edge whose scope is not determined
# confers nothing anyone can name, and the hop is published as not_determined
# rather than walked. The role -> selector join that narrows a DETERMINED scope
# to the functions a role actually licenses is a separate refinement.
GATE_CONTROL_CAPABILITIES = frozenset(
    {
        "authority.replace",
        "ownership.transfer",
        "roles.grant",
        "roles.configure",
        "authorized_caller.rotate",
    }
)

TRANSITIVE_CAPABILITIES = CODE_CONTROL_CAPABILITIES | GATE_CONTROL_CAPABILITIES

DESTINATION_BEARING_SEVERITY = frozenset({"flow.out", "delegatecall.execute", "exec.arbitrary"})

# Product surface: scored only where permissionlessness is PROVEN. ``claim_id``
# does not prove it, so a ``not_determined`` openness is not product and is
# published as a warning rather than dropped.
PRODUCT_CLAIMS = frozenset(
    {
        "flow.in",
        "erc20.approve",
        "erc20.transfer",
        "erc20.transfer_from",
        "gov.delegate",
        "pause.unset",
        "supply.mint",
        "supply.burn",
        "ownership.accept",
        "ownership.renounce",
        "timelock.execute",
        "timelock.schedule",
        "timelock.cancel",
        "rate_limit.consume",
    }
)

# No severity semantics exists for these; exclusion is not a judgement that the
# capability is benign, so every one of them publishes a warning.
UNMODELLED_CLAIMS = frozenset({"value_router", "contract_deployment", "callee_pointer.rotate"})

# --- static destination lattice --------------------------------------------
FIXED_TARGET_KINDS = frozenset({"immutable", "constant", "storage_no_setter"})
ADMIN_TARGET_KIND = "storage_setter"
TARGET_KIND_RANK: dict[str, int] = {
    "indeterminate": 0,
    "param": 1,
    "msg_sender": 2,
    "caller_controlled": 2,
    "token_owner": 3,
    "self": 4,
    "storage_setter": 5,
    "storage_no_setter": 6,
    "constant": 7,
    "immutable": 7,
}
NATIVE_FLOW_KINDS = frozenset({"native_transfer_send", "low_level_value_call"})
ERC20_FLOW_KINDS = frozenset({"callee_erc20_selector"})

# Resolution-provenance tiers. An UNKNOWN basis maps to the weakest tier: a
# label this scorer cannot recognise is one it cannot vouch for.
RESOLVER_BASIS_TIERS: dict[str, str] = {
    "abi_auto_getter": "abi_forced",
    "auto_getter": "abi_forced",
    "callee_selector": "operand_recorded",
    "standard_namespaced_accessor": "accessor_name_matched",
    "deunderscore_convention": "accessor_name_matched",
    "slot_name_keyword": "accessor_name_matched",
    "internal_accessor_convention": "accessor_name_matched",
}
WEAKEST_RESOLVER_BASIS_TIER = "accessor_name_matched"

# --- uncalibrated arms ------------------------------------------------------
UNCALIBRATED_ARMS: tuple[str, ...] = (
    # B14 population-zero arms, per strategy §7.2.
    "reach_indeterminate_floor",  # W3: the floor key has never been emitted positive
    "target_variable",  # B20.2: 0 of 12 storage_setter flows carry one
    "fixed_target_kind:constant",  # 0 rows
    "fixed_target_kind:storage_no_setter",  # 0 rows
    # Positive arms this build adds whose population is 0 or tiny here.
    "exec_self_destination",  # DEST_SEVERITY_EXEC_SELF: no exec.arbitrary self target observed
    "role_breadth_multi_holder",  # role_holder_planes: 11 keys / 3 registries (B14)
    "restaking_position_value",  # the plane carries no USD column; contributions are unpriced
    "reach_gate_licensed",  # gated_contract_backlink: 20 true rows, 16 distinct V (B14)
    # The uncredited rungs. Both are the value an UNREAD witness lands on, so
    # neither was fitted to anything, and both can sit BELOW the weakness a
    # proven-worst reading would earn — an unread 1-of-n Safe takes 0.55 where a
    # proven 1-of-n takes 0.85. The direction is deliberate (a fabricated k/n is
    # worse than a conservative rung) but the number itself is a model choice.
    "weakness_safe_uncredited",
    "weakness_timelock_undetermined",
    "uncredited_rung_below_proven_worst",
    # Retired for cause rather than calibrated: see the note beside
    # OWNERSHIP_DEFAULT_ADMIN_RULES.
    "retired:timelock_self_gated_delay_credit",
)


def band(usd: float | None) -> float:
    """The band weight. ``None`` is the UNPRICED branch, never a zero."""
    if usd is None:
        return UNPRICED_BAND
    for bound, weight in VALUE_BANDS:
        if usd < bound:
            return weight
    return VALUE_BAND_TOP


def band_label(usd: float | None) -> str:
    if usd is None:
        return "not_determined"
    labels = (
        (1e9, ">$1B"),
        (1e8, "$100M-$1B"),
        (1e7, "$10M-$100M"),
        (1e6, "$1M-$10M"),
        (1e5, "$100k-$1M"),
    )
    for bound, label in labels:
        if usd >= bound:
            return label
    return "<$100k"


def delay_discount(seconds: float | None) -> float | None:
    """f(delay): monotone decreasing, log in days, saturating, floored.

    Published rather than quoted, because a numeric consequence of adopting a
    monotone weakness function may not be stated before the function is defined.
    The witness supplies only the ORDERING of the delays; this mapping is a model
    choice and belongs to ``model_version``.

    A PROVEN ZERO delay returns ``1.0`` — no discount — because zero is an
    answer: the timelock imposes no wait. ``None`` is reserved for a delay that
    could not be read, which is a different fact and must not collect the same
    treatment. A negative value is unreadable, not a negative wait.
    """
    import math

    if seconds is None:
        return None
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    if value == 0:
        return 1.0
    days = value / 86400.0
    frac = math.log10(1.0 + days) / math.log10(1.0 + DELAY_DISCOUNT_SATURATION_DAYS)
    return round(max(DELAY_DISCOUNT_FLOOR, min(1.0, 1.0 - frac)), 4)


def quorum_weakness(
    k: int | None, n: int | None, *, credit_withheld: bool, waive_single_signer_cliff: bool = False
) -> float:
    """k/n as an UPPER BOUND on protection.

    ``credit_withheld`` is the ``safe_protection`` verdict: a proven module or
    guard means the threshold can be bypassed, so the k/n demotion is denied and
    the result cannot fall below the un-credited base. It never raises weakness
    above what k/n alone would have said.

    ``waive_single_signer_cliff`` is the emergency-response design credit for a
    single-signer freeze. It is granted only where the design property — that the
    freeze is recoverable by an independent key set — has been PROVEN, never on
    the capability's name.
    """
    if k is None or not n:
        return WEAKNESS_SAFE_UNCREDITED
    ratio = k / n
    if k == 1 and not waive_single_signer_cliff:
        earned = WEAKNESS_SAFE_SINGLE_SIGNER
    elif ratio < SAFE_MAJORITY_RATIO:
        earned = WEAKNESS_SAFE_MINORITY
    elif ratio < SAFE_SUPERMAJORITY_RATIO:
        earned = WEAKNESS_SAFE_MAJORITY
    else:
        earned = WEAKNESS_SAFE_SUPERMAJORITY
    if credit_withheld:
        return max(earned, WEAKNESS_SAFE_UNCREDITED)
    return earned


def resolver_basis_tier(basis: str | None) -> str:
    return RESOLVER_BASIS_TIERS.get(str(basis or ""), WEAKEST_RESOLVER_BASIS_TIER)


def letter(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def model_parameters() -> dict[str, Any]:
    """The block emitted in every document. Sorted, so two documents diff."""
    return {
        "model_version": MODEL_VERSION,
        "severity_scale": SEV_SCALE,
        "lambda": LAMBDA,
        "value_bands": [list(pair) for pair in VALUE_BANDS] + [[None, VALUE_BAND_TOP]],
        "unpriced_band": UNPRICED_BAND,
        "base_severity": dict(sorted(BASE_SEVERITY.items())),
        "destination_severity": {
            "unconstrained_proven": DEST_SEVERITY_UNCONSTRAINED,
            "hash_commitment_pins": DEST_SEVERITY_HASH_COMMITMENT_PINS,
            "external_call_revert": DEST_SEVERITY_EXTERNAL_CALL_REVERT,
            "constrained_other": DEST_SEVERITY_CONSTRAINED_OTHER,
            "delegatecall_self": DEST_SEVERITY_DELEGATECALL_SELF,
            "exec_self": DEST_SEVERITY_EXEC_SELF,
            "flow_caller_arbitrary": FLOW_SEVERITY_CALLER_ARBITRARY,
            "flow_fixed_destination": FLOW_SEVERITY_FIXED_DESTINATION,
            "note": (
                "these are reachable only on a PROVEN destination state; an unread "
                "destination yields no severity and the row is withheld from the grade"
            ),
        },
        "freeze_ladder": {
            "capability_proven": FREEZE_CAPABILITY_PROVEN,
            "keyset_recoverable": FREEZE_KEYSET_RECOVERABLE,
            "sustainable": FREEZE_SUSTAINABLE,
            "auto_expiry": FREEZE_AUTO_EXPIRY,
            "licensing": (
                "the existence rung is unconditional and every undetermined recovery "
                "question stays on it; SUSTAINABLE is added only on proven key-set "
                "dependence and the RECOVERABLE credit only on proven independence"
            ),
            "note": "no duration term: duration_bound_source is not_determined wherever populated",
        },
        "weakness_ladder": {
            "anyone": WEAKNESS_ANYONE,
            "eoa": WEAKNESS_EOA,
            "safe_uncredited": WEAKNESS_SAFE_UNCREDITED,
            "safe_single_signer": WEAKNESS_SAFE_SINGLE_SIGNER,
            "safe_minority": WEAKNESS_SAFE_MINORITY,
            "safe_majority": WEAKNESS_SAFE_MAJORITY,
            "safe_supermajority": WEAKNESS_SAFE_SUPERMAJORITY,
            "timelock_undetermined": WEAKNESS_TIMELOCK_UNDETERMINED,
            "role_breadth_multi_holder": ROLE_BREADTH_MULTI_HOLDER_WEAKNESS,
        },
        "delay_discount": {
            "form": "1 - log10(1+days)/log10(1+30), clamped [0.25, 1.0]",
            "172800s_2d": delay_discount(172800),
            "432000s_5d": delay_discount(432000),
            "864000s_10d": delay_discount(864000),
        },
        "principal_units": "per (chain, address); no cross-chain collapse (strategy §7.4)",
        "value_reduction": (
            "latest observation per (entity, asset, observed account), summed across DISTINCT "
            "observed accounts; entity = <chain>::<runtime address>, implementation folded onto "
            "its proxy except where two proxies share one. MAX across observation heights is "
            "RETIRED: two readings of one account are one holding read twice, and the maximum "
            "of them is a high-water mark that was already stale when it was written"
        ),
        "reach_classes": {
            "code_control": sorted(CODE_CONTROL_CAPABILITIES),
            "gate_control": sorted(GATE_CONTROL_CAPABILITIES),
            "bound": (
                "both expand over the control closure; code control over the whole closure of "
                "the controlled node, gate control only through edges the gate is WITNESSED TO "
                "CONFER. That is a conferral test, and it replaced the label-presence test that "
                "walked any edge whose label named a scope at all. A 'roles N' edge is conferred "
                "where the role -> selector join (function_principals.details.trace[].selector "
                "joined to effective_functions.selector at the destination) names the functions "
                "role N licenses there; those functions are published per finding as "
                "reach_licensed_functions. A state-variable edge is conferred where the gate's "
                "own witnessed function is observed to REWRITE a variable of that name "
                "(effective_functions.state_writes, origin=body), which is the evidence that the "
                "seized authority and the hop's authority are the same kind and compose down the "
                "chain — ownership.transfer is witnessed rewriting owner/_owner, authority."
                "replace rewriting authority, and none of the five is witnessed rewriting hook, "
                "vault, roleRegistry or endpoint, so hops running on those are no longer walked. "
                "A hop the gate is not witnessed to confer is NOT disproved: whether it composes "
                "depends on the intermediate node's own function surface, which nothing in this "
                "pipeline witnesses. It is published as not_determined rather than walked or "
                "dropped, as are the 55 role edges whose label names no role at all. One "
                "residual is named rather than assumed away: the role branch asks only what the "
                "role licenses at the destination and does not additionally require the seizing "
                "capability to be one that governs role assignment, because the role edge names "
                "a role and not the authority slot that grants it — there is no witness for that "
                "half, so what is published is what the role LICENSES, an upper bound on what "
                "this gate can exercise. Both "
                "classes are bounded by each destination's own caller conditions. "
                "provenance.reach_bounds.hop_census counts how many hops each rule walked and "
                "on what basis, and provenance.reach_bounds.gate_conferral carries the two "
                "joins' own coverage"
            ),
            "magnitude": (
                "membership is not a magnitude: where no witness proves how much value the "
                "reach MOVES, the dollar figure is not_determined and the finding keeps the "
                "unpriced band's floor weight. The entity's balance sheet is never the answer"
            ),
        },
        "model_version_migration": {
            "from": "1.0.1-provisional",
            "reference_corpus": "protocol 1 (etherfi), the only corpus this bump was measured on",
            "grade_lambda": [54.1614, 84.0166],
            "letter": ["C+", "A−"],
            "confidence_pct": [29.0, 18.6],
            "exposure_usd": [1227107593.64, 76.07],
            "what_moved": (
                "a reach whose MAGNITUDE no witness proved stops charging the reached entity's "
                "balance sheet: those rows fall from a value band of 0.5-1.0 to the unpriced "
                "floor of 0.15, so lambda RISES and exposure collapses without any protocol "
                "becoming safer. The band table carries 1.0.1's cut points forward unchanged, so "
                "the letter delta is published rather than absorbed by a recut nobody calibrated"
            ),
            "read_the_confidence_fall_correctly": (
                "(a) the reach-magnitude term does NOT bind the headline on this corpus - the "
                "min() is value_priced_pct 18.6 and the magnitude term sits 15.6pp clear at 34.2; "
                "(b) the strictest magnitude figure published, "
                "reach_magnitude_witnessed_of_reaching_pct 15.3, WOULD bind if it were the term "
                "and this version does not move it at all, because flooring an unwitnessed "
                "magnitude mints no witness - only composing one does; (c) the 29.0 -> 18.6 fall "
                "happened WITHIN 1.0.1, from that version's own reach-magnitude term and "
                "perimeter widening. The letter improvement here was NOT paid for by a "
                "confidence fall in this change; both are real, and neither is the other's price"
            ),
        },
        "uncalibrated_arms": list(UNCALIBRATED_ARMS),
    }
