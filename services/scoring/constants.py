"""The model's constants. ``model_parameters()`` is emitted in every document."""

from __future__ import annotations

from fractions import Fraction
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: scoring reads static's persisted JSON, not its modules
    from services.static.contract_analysis_pipeline.predicate_types import StateVarTargetKind

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

# The unpriced branch: an unpriceable capability keeps the lowest band's weight
# (still scores, publishes ``value_band: not_determined``) — dropping it would
# let an unpriceable asset buy a clean grade.
UNPRICED_BAND = 0.15

# --- per-capability severity ------------------------------------------------
# What the claim's PROVEN EXISTENCE licenses; refined only downward by
# mitigating witnesses, never raised by the absence of one.
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
# Apply ONLY on a proven destination state; an unread destination yields no
# severity at all, so none of these can be reached by absence.
DEST_SEVERITY_UNCONSTRAINED = 1.0
DEST_SEVERITY_HASH_COMMITMENT_PINS = 0.20
DEST_SEVERITY_EXTERNAL_CALL_REVERT = 0.60
DEST_SEVERITY_CONSTRAINED_OTHER = 0.35
# delegatecall to address(this) preserves msg.sender, so every sub-call re-runs
# its own access control; a plain CALL to self makes msg.sender the contract,
# which can satisfy an ``address(this)`` gate — fixed, but not benign.
DEST_SEVERITY_DELEGATECALL_SELF = 0.0
DEST_SEVERITY_EXEC_SELF = 0.35
FLOW_SEVERITY_CALLER_ARBITRARY = 0.9
FLOW_SEVERITY_FIXED_DESTINATION = 0.10
# The three proven-benign payout shapes are 0.0 because the bound is PROVEN
# (the payout moves no position the caller did not just fund), never because a
# witness was unread — an unread witness yields no severity and the row is
# withheld from the grade instead.
FLOW_SEVERITY_MSG_VALUE_SELF_RETURN = 0.0
FLOW_SEVERITY_MSG_VALUE_PASSTHROUGH = 0.0
FLOW_SEVERITY_SELF_SERVICE_BOUNDED = 0.0
OWNERSHIP_DEFAULT_ADMIN_RULES = 0.35

# --- freeze ladder ----------------------------------------------------------
# Each rung is licensed by a proof, not an outcome: existence is unconditional
# (and where every undetermined recovery question stays), RECOVERABLE needs
# proven key-set independence, SUSTAINABLE is added only on proven dependence.
# AUTO_EXPIRY is admitted only under a witnessed duration bound at or below
# FREEZE_AUTO_EXPIRY_MAX_SECONDS.
FREEZE_CAPABILITY_PROVEN = 0.05
FREEZE_KEYSET_RECOVERABLE = 0.05
FREEZE_SUSTAINABLE = 0.20
FREEZE_AUTO_EXPIRY = 0.02
FREEZE_AUTO_EXPIRY_MAX_SECONDS = 30 * 86400

# --- weakness ladder --------------------------------------------------------
WEAKNESS_EOA = 0.9
WEAKNESS_ANYONE = 1.0
# The uncredited rung is what an UNREAD witness lands on, deliberately BELOW
# the proven single-signer worst case: a fabricated k/n would be worse than a
# conservative rung.
WEAKNESS_SAFE_UNCREDITED = 0.55
WEAKNESS_SAFE_SINGLE_SIGNER = 0.85
WEAKNESS_SAFE_MINORITY = 0.55
WEAKNESS_SAFE_MAJORITY = 0.35
WEAKNESS_SAFE_SUPERMAJORITY = 0.2
WEAKNESS_TIMELOCK_UNDETERMINED = 0.55
# Exact rationals, compared exactly, both boundaries INCLUSIVE: 3/6 is a
# majority and 4/6 is the 2/3 supermajority it literally is. A float threshold
# (0.67) silently excluded every exact-two-thirds quorum.
SAFE_MAJORITY_RATIO = Fraction(1, 2)
SAFE_SUPERMAJORITY_RATIO = Fraction(2, 3)

# A proven holder floor >1 on the gating role is proven BREADTH; may only raise.
ROLE_BREADTH_MULTI_HOLDER_WEAKNESS = 0.55

# --- delay discount ---------------------------------------------------------
DELAY_DISCOUNT_FLOOR = 0.25
DELAY_DISCOUNT_SATURATION_DAYS = 30.0

# --- capability classes -----------------------------------------------------
# CODE control replaces what the node DOES: expansion covers the controlled
# node's whole closure (bounded by each destination's own caller conditions).
CODE_CONTROL_CAPABILITIES = frozenset(
    {
        "upgrade.implementation",
        "exec.arbitrary",
        "delegatecall.execute",
    }
)

# GATE control replaces who MAY CALL: expansion only through edges the gate is
# witnessed to confer; an edge whose scope is not determined confers nothing
# and the hop is published as not_determined rather than walked.
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

# Proven-0.0 severity bases that are UNCHARGED PRODUCT SURFACE: kept in the
# population (confidence credit stays), excluded from the finding ledger. The
# fold gates the exclusion on BOTH token AND value 0.0 — never the float alone,
# which would sweep in pause.set's proven build-up-from-zero.
UNCHARGED_PRODUCT_BASES = frozenset(
    {
        "proven_self_service_bounded",
        "proven_msg_value_self_return",
        "proven_msg_value_passthrough",
    }
)

# Product surface: scored only where permissionlessness is PROVEN. A
# not_determined openness is not product and is published as a warning.
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
# capability is benign, so each publishes a warning.
UNMODELLED_CLAIMS = frozenset({"value_router", "contract_deployment", "callee_pointer.rotate"})

# --- static destination lattice --------------------------------------------
FIXED_TARGET_KINDS = frozenset({"immutable", "constant", "storage_no_setter"})
# Annotated against the static plane's Literal (type-only import) so a
# vocabulary drift is a pyright error without a runtime coupling.
ADMIN_TARGET_KIND: "StateVarTargetKind" = "storage_setter"
# Proven caller-relative destinations: priced from the authority witness,
# never from the kind alone (``distill._caller_relative_destination``).
CALLER_RELATIVE_TARGET_KINDS = frozenset({"msg_sender", "token_owner"})
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

# Resolution-provenance tiers. An UNKNOWN basis maps to the weakest tier.
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
# Arms whose positive branch never fired on any corpus the model was measured
# on: exercised by constructed fixtures only, published so a consumer can see
# the arm is untested. An entry whose positive branch fires is removed.
UNCALIBRATED_ARMS: tuple[str, ...] = (
    "reach_indeterminate_floor",
    "target_variable",
    "fixed_target_kind:constant",
    "fixed_target_kind:storage_no_setter",
    "exec_self_destination",
    "role_breadth_multi_holder",
    "restaking_position_value",
    "reach_gate_licensed",
    "weakness_safe_uncredited",
    "weakness_timelock_undetermined",
    "uncredited_rung_below_proven_worst",
    "retired:timelock_self_gated_delay_credit",
    "composition_arm:withheld",
    "composition_arm:not_determined",
    "gate_claim:not_determined",
    "authority_deletability:not_determined",
    "authority_deletability_basis_arm:gating_authority",
    "route_comparison_verdict:route_match",
    "retired:destination_callee_is_restricted_by_the_intermediate",
    "code_control_ceiling_refused:alias_ambiguous",
    "sheet_bound_refused:sheet_determined_by_disposition_does_not_bound",
    "fork:simulation+destination_param",
    "constrained:token_owner+restricted_caller",
    "msg_value_return_refused:amount_fold_disagreed",
    "msg_value_return_refused:amount_not_dispositive_ast",
    "msg_value_return_refused:amount_not_msg_value",
    "msg_value_return_refused:flow_source_not_self",
    "msg_value_return_refused:target_fold_disagreed",
    "msg_value_return_refused:target_not_a_witnessed_arm",
    "msg_value_return_refused:flow_kind_unreadable",
    "msg_value_return_refused:multiple_out_flow_entries",
    "self_service_bound:proven",
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

    A PROVEN ZERO delay returns ``1.0`` — no discount — because zero is an
    answer. ``None`` is reserved for a delay that could not be read; a negative
    value is unreadable, not a negative wait.
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
    single-signer freeze, granted only where recoverability by an independent
    key set has been PROVEN, never on the capability's name.
    """
    if k is None or not n:
        return WEAKNESS_SAFE_UNCREDITED
    ratio = Fraction(k, n)
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
            "flow_msg_value_self_return": FLOW_SEVERITY_MSG_VALUE_SELF_RETURN,
            "flow_msg_value_passthrough": FLOW_SEVERITY_MSG_VALUE_PASSTHROUGH,
            "flow_self_service_bounded": FLOW_SEVERITY_SELF_SERVICE_BOUNDED,
        },
        "freeze_ladder": {
            "capability_proven": FREEZE_CAPABILITY_PROVEN,
            "keyset_recoverable": FREEZE_KEYSET_RECOVERABLE,
            "sustainable": FREEZE_SUSTAINABLE,
            "auto_expiry": FREEZE_AUTO_EXPIRY,
            "auto_expiry_max_seconds": FREEZE_AUTO_EXPIRY_MAX_SECONDS,
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
        "reach_classes": {
            "code_control": sorted(CODE_CONTROL_CAPABILITIES),
            "gate_control": sorted(GATE_CONTROL_CAPABILITIES),
        },
        "uncalibrated_arms": list(UNCALIBRATED_ARMS),
    }
