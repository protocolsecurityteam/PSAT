"""The model's constants. ``model_parameters()`` is emitted in every document."""

from __future__ import annotations

from fractions import Fraction
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: scoring reads static's persisted JSON, not its modules
    from services.static.contract_analysis_pipeline.predicate_types import StateVarTargetKind

from services.static.claims import claim_ids_of_class
from utils import claim_ids as C
from utils.scoring_status import MODEL_VERSION

SEV_SCALE = 60.0
LAMBDA = 0.6

# (upper bound exclusive, weight). Above the last bound the weight is VALUE_BAND_TOP.
VALUE_BANDS: tuple[tuple[float, float], ...] = (
    (100_000.0, 0.15),
    (1_000_000.0, 0.3),
    (10_000_000.0, 0.5),
    (100_000_000.0, 0.7),
    (1_000_000_000.0, 0.9),
)
VALUE_BAND_TOP = 1.0

# Unpriceable capabilities keep the lowest band's weight (``value_band: not_determined``) so unpriceable assets can't
# buy a clean grade.
UNPRICED_BAND = 0.15

# What the claim's proven existence licenses; refined only downward by mitigating witnesses, never raised by their
# absence.
BASE_SEVERITY: dict[str, float] = {
    C.UPGRADE_IMPLEMENTATION: 1.0,
    C.AUTHORITY_REPLACE: 0.75,
    C.ROLES_GRANT: 0.55,
    C.ROLES_REVOKE: 0.4,
    C.ROLES_CONFIGURE: 0.55,
    C.AUTHORIZED_CALLER_ROTATE: 0.55,
    C.OWNERSHIP_TRANSFER: 0.55,
    C.PAUSE_SET: 0.0,  # built up from proven components only
    C.TRANSFER_POLICY_CONFIGURE: 0.25,
    C.TIMELOCK_SET_DELAY: 0.3,
    C.LZ_OAPP_SET_PEER: 0.3,
    C.LZ_OAPP_SET_DELEGATE: 0.3,
    C.DELEGATECALL_EXECUTE: 1.0,
    C.EXEC_ARBITRARY: 1.0,
    C.FLOW_OUT: 0.9,
}

# Only on a proven destination state; an unread destination yields no severity.
DEST_SEVERITY_UNCONSTRAINED = 1.0
DEST_SEVERITY_HASH_COMMITMENT_PINS = 0.20
DEST_SEVERITY_EXTERNAL_CALL_REVERT = 0.60
DEST_SEVERITY_CONSTRAINED_OTHER = 0.35
# delegatecall to address(this) preserves msg.sender, so sub-calls re-run their own access control; a plain CALL to self
# makes msg.sender the contract, which can satisfy an ``address(this)`` gate.
DEST_SEVERITY_DELEGATECALL_SELF = 0.0
DEST_SEVERITY_EXEC_SELF = 0.35
FLOW_SEVERITY_CALLER_ARBITRARY = 0.9
FLOW_SEVERITY_FIXED_DESTINATION = 0.10
# Proven-benign payout shapes: 0.0 because the bound is proven (the payout moves nothing the caller didn't just fund),
# never because a witness was unread.
FLOW_SEVERITY_MSG_VALUE_SELF_RETURN = 0.0
FLOW_SEVERITY_MSG_VALUE_PASSTHROUGH = 0.0
FLOW_SEVERITY_SELF_SERVICE_BOUNDED = 0.0
OWNERSHIP_DEFAULT_ADMIN_RULES = 0.35

# Each rung needs a proof: existence is unconditional, RECOVERABLE needs proven key-set independence, SUSTAINABLE proven
# dependence, AUTO_EXPIRY a witnessed duration bound at or below FREEZE_AUTO_EXPIRY_MAX_SECONDS.
FREEZE_CAPABILITY_PROVEN = 0.05
FREEZE_KEYSET_RECOVERABLE = 0.05
FREEZE_SUSTAINABLE = 0.20
FREEZE_AUTO_EXPIRY = 0.02
FREEZE_AUTO_EXPIRY_MAX_SECONDS = 30 * 86400

WEAKNESS_EOA = 0.9
WEAKNESS_ANYONE = 1.0
# Where an unread witness lands; deliberately below the proven single-signer worst case.
WEAKNESS_SAFE_UNCREDITED = 0.55
WEAKNESS_SAFE_SINGLE_SIGNER = 0.85
WEAKNESS_SAFE_MINORITY = 0.55
WEAKNESS_SAFE_MAJORITY = 0.35
WEAKNESS_SAFE_SUPERMAJORITY = 0.2
WEAKNESS_TIMELOCK_UNDETERMINED = 0.55
# Exact rationals, inclusive boundaries: a float 0.67 excluded exact two-thirds quorums.
SAFE_MAJORITY_RATIO = Fraction(1, 2)
SAFE_SUPERMAJORITY_RATIO = Fraction(2, 3)

# A proven holder floor >1 on the gating role; may only raise.
ROLE_BREADTH_MULTI_HOLDER_WEAKNESS = 0.55

DELAY_DISCOUNT_FLOOR = 0.25
DELAY_DISCOUNT_SATURATION_DAYS = 30.0

# Code control replaces what the node does: expansion covers its whole closure (bounded by each destination's caller
# conditions).
CODE_CONTROL_CAPABILITIES: frozenset[str] = claim_ids_of_class("control.code")

# Gate control replaces who may call: expansion only through edges the gate is witnessed to confer; undetermined scope
# confers nothing and the hop is published as not_determined. The ``control.gate`` claims that hand control to a named
# party; revocation, acceptance and Safe/timelock housekeeping don't.
GATE_CONTROL_CAPABILITIES: frozenset[str] = frozenset(
    {C.AUTHORITY_REPLACE, C.OWNERSHIP_TRANSFER, C.ROLES_GRANT, C.ROLES_CONFIGURE, C.AUTHORIZED_CALLER_ROTATE}
)

TRANSITIVE_CAPABILITIES = CODE_CONTROL_CAPABILITIES | GATE_CONTROL_CAPABILITIES

DESTINATION_BEARING_SEVERITY = frozenset({C.FLOW_OUT, C.DELEGATECALL_EXECUTE, C.EXEC_ARBITRARY})

# Proven-0.0 bases that are uncharged product surface: kept for confidence, excluded from findings. The fold requires
# both token and value 0.0, since ``pause.set`` also starts at zero.
UNCHARGED_PRODUCT_BASES = frozenset(
    {
        "proven_self_service_bounded",
        "proven_msg_value_self_return",
        "proven_msg_value_passthrough",
    }
)

# Scored only where permissionlessness is proven; undetermined openness is warned.
PRODUCT_CLAIMS = frozenset(
    {
        C.FLOW_IN,
        C.ERC20_APPROVE,
        C.ERC20_TRANSFER,
        C.ERC20_TRANSFER_FROM,
        C.GOV_DELEGATE,
        C.PAUSE_UNSET,
        C.SUPPLY_MINT,
        C.SUPPLY_BURN,
        C.OWNERSHIP_ACCEPT,
        C.OWNERSHIP_RENOUNCE,
        C.TIMELOCK_EXECUTE,
        C.TIMELOCK_SCHEDULE,
        C.TIMELOCK_CANCEL,
        C.RATE_LIMIT_CONSUME,
    }
)

# No severity model yet; excluded with a warning, not judged benign.
UNMODELLED_CLAIMS = frozenset({C.VALUE_ROUTER, C.CONTRACT_DEPLOYMENT, C.CALLEE_POINTER_ROTATE})

FIXED_TARGET_KINDS: frozenset[StateVarTargetKind] = frozenset({"immutable", "constant", "storage_no_setter"})
# Type-only import of the static plane's Literal, so vocabulary drift is a pyright error.
ADMIN_TARGET_KIND: "StateVarTargetKind" = "storage_setter"
# Priced from the authority witness, never from the kind (``distill._caller_relative_destination``).
CALLER_RELATIVE_TARGET_KINDS = frozenset({"msg_sender", "token_owner"})
TARGET_KIND_RANK: dict[str, int] = {
    "indeterminate": 0,
    "param": 1,
    "msg_sender": 2,
    "caller_controlled": 2,
    "token_owner": 3,
    "self": 4,
    ADMIN_TARGET_KIND: 5,
    "storage_no_setter": 6,
    "constant": 7,
    "immutable": 7,
}
NATIVE_FLOW_KINDS = frozenset({"native_transfer_send", "low_level_value_call"})
ERC20_FLOW_KINDS = frozenset({"callee_erc20_selector"})

# An unknown basis maps to the weakest tier.
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

# Arms whose positive branch never fired on a measured corpus (fixtures only). Remove an entry once it fires.
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

    A proven zero delay returns ``1.0``. ``None`` means unreadable; negatives are unreadable too.
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
    """k/n as an upper bound on protection.

    ``credit_withheld`` (a proven module or guard can bypass the threshold) denies the k/n demotion but never raises
    weakness above k/n. ``waive_single_signer_cliff`` is granted for a single-signer freeze only where independent-key
    recoverability is proven.
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
    """The block emitted in every document, sorted so documents diff."""
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
