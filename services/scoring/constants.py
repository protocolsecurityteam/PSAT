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
# Target kinds the lattice PROVES outright and which are neither fixed nor a
# gap: the destination is a known function of who calls (``msg_sender``) or of
# who owns the token (``token_owner``). How constrained that is depends on the
# caller gate, so these are priced from the authority witness, never from the
# kind alone (``distill._caller_relative_destination``).
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
    # The execution-witness run's own arms. Each is a NARROWER three-state the
    # run added on purpose, and none of them fired on the corpus the model was
    # calibrated against — so each is exercised only by a constructed fixture and
    # none of the published numbers was fitted to it. Disclosed per arm in
    # UNCALIBRATED_ARM_DISCLOSURES below.
    "composition_arm:withheld",
    "composition_arm:not_determined",
    "gate_claim:not_determined",
    "authority_deletability:not_determined",
    "authority_deletability_basis_arm:gating_authority",
    "route_comparison_verdict:route_match",
    "retired:destination_callee_is_restricted_by_the_intermediate",
    # The code-control ceiling's one remaining zero-carrier arm. THREE came off
    # when the chain-log sweep earned the reference corpus its first proven-empty
    # sheets: ``code_control_ceiling:proven_empty`` and
    # ``sheet_ceiling_bound_direction:ceiling`` gained per-entity carriers, and
    # the row-header ``value_at_stake_bound_direction:ceiling`` — the one that
    # predated this run — gained its first carrying ROW, a subsumed one whose
    # every contributing entity is a proven $0 with no coverage gap. An entry
    # whose positive branch has fired is removed rather than narrowed to whatever
    # scope still reads zero: the register exists to say the model was never
    # fitted to a state the document publishes, and that sentence is now false
    # for all three however the population is sliced.
    #
    # The refusal below still has none, and cannot: the fold refuses a shared
    # implementation before any magnitude branch reads a sheet, so no row can
    # carry it and only a direct call to the resolver reaches it.
    "code_control_ceiling_refused:alias_ambiguous",
    # The disposition run's own zero-carrier arm, and the SIBLING of the two
    # tokens above: it is the trim sites' answer where a sheet exists, IS
    # determined, and still may not bound a witness. The state fired nowhere on
    # this corpus — the 13 determined sheets carry no witnessed magnitude to
    # refuse a bound for — while the states it sits beside on those same two
    # surfaces (``sheet_not_determined``, and the composed arms) are calibrated.
    # Disclosed rather than left flagged, because a consumer branching on
    # ``sheet_bound_refused`` cannot otherwise tell an unfired rule from one the
    # model was fitted to.
    "sheet_bound_refused:sheet_determined_by_disposition_does_not_bound",
    # The destination run's two. The first is the register's paradigm case: the
    # exec arm's PROVEN branch cannot fire on any stored row, because the join
    # key it requires (the parameter the sentinel was substituted into) is not
    # recorded on any verdict — and where a caller_arbitrary verdict does sit
    # beside an exec destination, the two are different parameters. A fixture is
    # the only thing that reaches it.
    #
    # The second is the "0 or tiny" clause. Measured at registration: the
    # caller-relative constrained arm's ``token_owner`` side carries 2 signals at
    # 1 entity, both subsumed, so no published number was fitted to it.
    # Registered per KIND rather than for the arm as a whole, following
    # ``fixed_target_kind:*`` — the ``msg_sender`` side of the same arm carried
    # 15 and is calibrated.
    "fork:simulation+destination_param",
    "constrained:token_owner+restricted_caller",
)

# What each of the run's arms IS, beside the bare token. §8 of
# SCORER_DISCIPLINE_CONTRACT requires the flag; the flag alone does not say which
# state is uncalibrated, where the document publishes it, or what exercises it,
# and a reader cannot check an arm they cannot find.
#
# ⚠ Nothing here counts instances, and that is deliberate rather than an
# omission. This module reads no data, so a population figure authored in it
# would be a claim about a corpus it has never seen — the defect class this run
# exists to remove. ``population_census`` names the field of the scored document
# where the instances ARE counted, and ``null`` there is the honest "this
# document publishes no counter for that state", not a zero.
UNCALIBRATED_ARM_DISCLOSURES: tuple[dict[str, object], ...] = (
    {
        "arm": "composition_arm:withheld",
        "state": "withheld",
        "published_at": "reach_composed_magnitudes_withheld[].arm_taken",
        "population_census": "reach_composition_census.composed_withheld_by_arm",
        "exercised_by": (
            "tests/test_three_arm_composition.py::"
            "test_an_unfetchable_transcript_withholds_even_where_the_join_licenses_it",
        ),
        "note": (
            "the transport-fault arm. Reached BEFORE the route classification and the deletability "
            "join are consulted, so an entry on it can publish a deletability licence beside its own "
            "refusal — which is why it is a separate arm and not a shade of the gate-only one"
        ),
    },
    {
        "arm": "composition_arm:not_determined",
        "state": "not_determined",
        "published_at": "reach_composed_magnitudes_withheld[].arm_taken",
        "population_census": "reach_composition_census.composed_withheld_by_arm",
        "exercised_by": (
            "tests/test_three_arm_composition.py::"
            "test_the_typed_reason_is_read_off_the_traversed_body[neither_conjunct]",
            "tests/test_three_arm_composition.py::"
            "test_the_typed_reason_is_read_off_the_traversed_body[no_flow_witness]",
        ),
        "note": (
            "the fall-through an unrecognised route fails to. There is no fourth arm that publishes, "
            "so this state is what stands between a route nobody classified and a figure"
        ),
    },
    {
        "arm": "gate_claim:not_determined",
        "state": "not_determined",
        "published_at": "reach_composed_magnitudes[].gate_claim.state",
        "population_census": "reach_composition_census.gate_claim_by_state",
        "exercised_by": (
            "tests/test_three_arm_composition.py::test_no_execution_to_compare_a_caller_against_is_its_own_state",
        ),
        "note": (
            "no recorded execution to read a caller off, so the caller conjunct was neither "
            "corroborated nor refused. Distinct from not_corroborated, which is a comparison that ran"
        ),
    },
    {
        "arm": "authority_deletability:not_determined",
        "state": "not_determined",
        "published_at": "reach_composed_magnitudes_withheld[].authority_deletability.{state,reason}",
        "population_census": "reach_composition_census.composed_withheld_by_deletability",
        "exercised_by": (
            "tests/test_deletability_join.py::test_unresolvable_gating_authority_is_not_determined_never_deletable",
            "tests/test_deletability_join.py::test_a_tainted_destination_gate_is_not_determined_even_with_a_named_authority",
            "tests/test_deletability_join.py::test_authority_sources_that_disagree_resolve_to_not_determined",
            "tests/test_deletability_join.py::test_two_selector_scoped_authorities_are_no_answer",
            "tests/test_deletability_join.py::test_a_lower_bound_membership_row_is_not_determined_never_deletable",
        ),
        "note": (
            "the undetermined half of the join, carrying its own reason token. Counted apart from "
            "proven_not_deletable — a join that ran and returned no row is an EARNED negative and an "
            "unresolvable authority is not, and collapsing them is the inv. 1 failure the join exists "
            "to prevent"
        ),
    },
    {
        "arm": "authority_deletability_basis_arm:gating_authority",
        "state": "gating_authority",
        "published_at": "reach_composed_magnitudes[].authority_deletability.basis.arm",
        # No counter: the basis arm is published per entry and rolled up nowhere.
        "population_census": None,
        "exercised_by": (
            "tests/test_deletability_join.py::test_authority_arm_qualifying_row_is_deletable_and_names_its_basis",
            "tests/test_three_arm_composition.py::"
            "test_case3b_two_hops_with_a_qualifying_row_republishes_and_names_it[gating_authority]",
        ),
        "note": (
            "the host arm is asked first, so a principal holding setters at BOTH the host and the "
            "gating authority publishes host and this arm never surfaces. It is the arm's own "
            "sufficiency that is uncalibrated, not its correctness: the join answers on it alone"
        ),
    },
    {
        "arm": "route_comparison_verdict:route_match",
        "state": "route_match",
        "published_at": "reach_composed_magnitudes[].route_comparison.verdict",
        "population_census": None,
        "exercised_by": ("tests/test_execution_record.py::test_route_comparison_has_no_fall_through_arm",),
        "note": (
            "the positive verdict. No composition arm consumes it — a matched route is not a "
            "licence and the figure still turns on the deletability join — so it is a disclosure "
            "and not an input, and it has never been fitted to anything"
        ),
    },
    {
        "arm": "retired:destination_callee_is_restricted_by_the_intermediate",
        "state": "destination_callee_is_restricted_by_the_intermediate",
        # Retired with no producer: the classifier cannot emit it.
        "published_at": None,
        "population_census": None,
        "exercised_by": (
            "tests/test_composition_surfaces.py::test_no_published_route_state_claims_a_restricted_callee",
        ),
        "note": (
            "EXECUTION_WITNESS_SPEC §7.2's second typed reason as originally named. It has no "
            "producer: the route classifier earns its second token from target_constraint, which "
            "constrains the destination call's counterparty ARGUMENT, and no stored witness says an "
            "intermediate restricts the callee SET. A genuine callee-set restriction — the Manager's "
            "merkle verification — is not witnessed in this data and is not claimed"
        ),
    },
    {
        "arm": "code_control_ceiling_refused:alias_ambiguous",
        "state": "alias_ambiguous",
        # No producer through the fold: the shared-implementation guard at the top
        # of _entity_contribution refuses the key before any branch reads a sheet,
        # so the ceiling resolver is never asked about one. The token is real and
        # answerable — it is what planes.ceiling_for returns — and it is reachable
        # only by calling that resolver directly.
        "published_at": None,
        "population_census": None,
        "exercised_by": (
            "tests/test_scoring_redteam.py::test_cc4_a_shared_implementation_earns_no_ceiling",
            "tests/test_value_plane_ceiling.py::test_an_ambiguous_implementation_refuses_however_the_key_was_folded",
        ),
        "note": (
            "the ceiling resolver's refusal for an implementation two proxies share, which no row "
            "can publish: the fold refuses such a key outright before any magnitude branch runs, "
            "so the double guard holds and this token is answerable only where the resolver is "
            "called on its own. Registered so the redundancy is a stated fact — a reader who "
            "removed either guard would otherwise find no record that the other was relied on"
        ),
    },
    {
        "arm": "sheet_bound_refused:sheet_determined_by_disposition_does_not_bound",
        "state": "sheet_determined_by_disposition_does_not_bound",
        # The composed surface publishes the TOKEN under its own key; the
        # entity-holdings surface publishes the same refusal's sentence on an
        # unbounded-floor entry. Both are named, because a consumer joining one
        # of them would otherwise find no record of the other.
        "published_at": (
            "findings[].reach_composed_magnitudes[].sheet_bound_refused, and the same refusal's "
            "sentence at findings[].unbounded_floor_magnitudes[].reading"
        ),
        "population_census": None,
        "exercised_by": (
            "tests/test_asset_disposition.py::test_a_disposed_sheet_refuses_to_bound_a_witness_and_publishes_why",
            "tests/test_asset_disposition.py::test_an_exact_witness_names_the_same_refusal_a_floor_one_does",
        ),
        "note": (
            "the one refusal here that fires where a sheet EXISTS and is determined. A sheet "
            "determined at $0 by delivery shape may not trim a witnessed magnitude — the disposed "
            "assets are still held and delivery shape is not a claim about worth — so the witness "
            "stands alone and the bar is published rather than folded into sheet_not_determined, "
            "which would be false. It has no carrier on this corpus for a measured reason and not "
            "a structural one: the 13 sheets the disposition determined carry no witnessed "
            "magnitude for it to refuse a bound for, so the state is earnable, a constructed fold "
            "earns it, and no row here does"
        ),
    },
    {
        "arm": "fork:simulation+destination_param",
        "state": "unconstrained_proven",
        "published_at": (
            "signals' severity_basis and gate_inputs.destination_basis, and findings[].severity_basis "
            "where such a row enters the grade"
        ),
        "population_census": None,
        "exercised_by": (
            "tests/test_scoring_distill_fold.py::test_fork_caller_arbitrary_is_consumed_on_the_destination_parameter",
        ),
        "note": (
            "the exec arm's consuming branch. It requires the parameter the sentinel was "
            "substituted into to be NAMED on the verdict and to be the parameter the sink calls "
            "through, and no verdict in any measured corpus names one — so the branch cannot fire "
            "on a stored row and only the fixture reaches it. Where a caller_arbitrary verdict does "
            "sit beside an exec destination the join REFUSES: those are arbitrary-call executors "
            "whose sentinel rides the payload parameter while the call target keeps the base "
            "probe's value. The refusing branch is the calibrated one; this one has never fired"
        ),
    },
    {
        "arm": "constrained:token_owner+restricted_caller",
        "state": "constrained_proven",
        "published_at": (
            "signals' destination_shape (constrained:token_owner) and severity_basis, and "
            "findings[].subsumed_capabilities[] where such a row is subsumed"
        ),
        "population_census": None,
        "exercised_by": (
            "tests/test_scoring_distill_fold.py::"
            "test_caller_relative_destination_behind_a_gate_is_the_constrained_convention[token_owner]",
            "tests/test_scoring_distill_fold.py::test_caller_relative_conjunction_takes_the_worst_member",
        ),
        "note": (
            "the tiny-population half of the caller-relative constrained arm. Measured at "
            "registration and not a claim about this document: 2 signals at 1 entity, both "
            "subsumed, so no published number was fitted to it. Registered per KIND, following "
            "fixed_target_kind:* — the msg_sender half of the same arm was not tiny and is "
            "calibrated. "
            "The severity is the model's existing constrained-destination rung, applied to a "
            "constraint of a different kind: the payee is the current owner of a caller-chosen "
            "token id, which the caller gate does not bound. Its open-caller sibling publishes "
            "nothing at all and so is not an arm to register"
        ),
    },
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
            # Both halves of this note were false, in two different ways, and
            # ruling 7's "split rather than rewrite" is what separates them.
            # The second half read "duration_bound_source is not_determined
            # wherever populated" — a universal over the scored data, authored
            # in a module that opens no session and reads no row, so nothing
            # here could have checked it. The FIRST half read "no duration
            # term", which is contradicted by the ``auto_expiry`` rung sitting
            # in this very dict: ``distill.py``'s freeze severity applies it
            # only where a witnessed ``duration_bound_seconds`` is at or below
            # FREEZE_AUTO_EXPIRY_MAX_SECONDS. Duration is a GATE on one rung
            # rather than a term in any of them, and the two thresholds are
            # interpolated so a reader can check the sentence against the
            # constants it describes instead of against a number typed once.
            "note": (
                f"duration is a GATE on one rung and a term in none: the auto_expiry rung "
                f"({FREEZE_AUTO_EXPIRY}) is admitted only where a witnessed duration bound is at "
                f"or below {FREEZE_AUTO_EXPIRY_MAX_SECONDS} seconds, and its size does not vary "
                f"with that bound — a freeze bounded one second under the threshold and one "
                f"bounded a month under it credit identically. No other rung reads a duration at "
                f"all, and no rung is a function of duration_bound_source"
            ),
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
                "reach_licensed_functions. That branch is a positive witness of what the hop "
                "delivers. The state-variable branch is NOT, and is weaker: it is a SAME-KIND "
                "BOUND. The gate's own witnessed function is observed to REWRITE a variable of "
                "that name on ITS OWN contract (effective_functions.state_writes, origin=body), "
                "while the edge's label names the authority slot on the DESTINATION's contract, "
                "so requiring the two to match is a name match across two contracts' storage and "
                "witnesses no composition step — nothing says that seizing A's owner lets its "
                "holder exercise A's ownership of B. What the bound does is REFUSE hops of a "
                "different kind from the one the gate seizes: ownership.transfer is witnessed "
                "rewriting owner/_owner, authority.replace rewriting authority, and none of the "
                "five is witnessed rewriting hook, vault, roleRegistry or endpoint, so hops "
                "running on those are no longer walked. The same-kind hops that survive walk on "
                "no more evidence than the label-presence test gave them. A refused hop is NOT "
                "disproved: whether it composes anyway turns on the intermediate node's own "
                # "the surface usually exists" and "the 55 role edges" were both
                # here: a frequency and a count, over a corpus this module opens
                # no session to read. The claim the refusal actually supports is
                # the one about the join, and it holds whatever the surface turns
                # out to be; the edge population is counted in
                # provenance.reach_bounds.hop_census.scope_not_determined, where
                # a reader can check it.
                "function surface, and this plane DOES NOT CONSULT IT — so a refusal is a join "
                "not performed and is never a witness that is missing, whether or not that "
                "surface is there. The join that would decide it is the intermediate node's own "
                "functions against its outbound targets (effective_functions.sinks/effect_targets "
                "and the external_call_target edges CONTROL_RELATIONS excludes). It is published "
                "as not_determined rather than walked or dropped, as are the role edges whose "
                "label names no role at all — counted under "
                "provenance.reach_bounds.hop_census.scope_not_determined — and "
                "reach_withheld_behind_hops sizes the subtree each withheld frontier hop hides. One "
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
                "unpriced band's floor weight. The entity's balance sheet is not the answer to "
                "how much a GATE moves — seizing who may call a vault leaves the vault's own "
                "code, its share math and its caller conditions all standing between the "
                "principal and the assets, and none of that has been examined. It IS the answer "
                "to how much CODE CONTROL moves, and only at the node the code control is over: "
                "replacing what that node does removes the one thing that stood there, so the "
                "node's own priced sheet bounds the move from above. That figure is published as "
                "a proven CEILING and never as an amount, and it stays out of the exposure "
                "numerator because an at-most is not expected loss"
            ),
        },
        # Three records, not one extended path. 1.0.1 -> 1.1.0, 1.1.0 -> 1.2.0
        # and 1.2.0 -> 1.3.0 are three bumps, and a single list of lambda points
        # spanning them would publish a path no document ever walked — a reader
        # could not tell which bump moved which number, and the bumps move
        # lambda in opposite directions. Each record names the version it moved
        # FROM and the one it moved TO, so a persisted score's model_version
        # joins to exactly one.
        "model_version_migrations": [
            {
                "from": "1.0.1-provisional",
                "to": "1.1.0-provisional",
                "reference_corpus": "protocol 1 (etherfi), the only corpus this bump was measured on",
                # Three points, not two: the version floors an unwitnessed magnitude
                # (lambda RISES) and then composes a witnessed one back (lambda
                # FALLS), and a before/after pair hides that they move opposite ways.
                "grade_lambda": [54.1614, 84.0166, 73.2508],
                "letter": ["C+", "A−", "B+"],
                "grade_lambda_reading": (
                    "shipped 1.0.1 -> magnitudes floored -> destination witnesses composed back; "
                    "only the first and last are published documents, the middle is this version's "
                    "own intermediate and is quoted so the two halves are not read as one move"
                ),
                "confidence_pct": [29.0, 18.6],
                "exposure_usd": [1227107593.64, 18059003.86],
                "what_moved": (
                    "a reach whose MAGNITUDE no witness proved stops charging the reached entity's "
                    "balance sheet: those rows fall from a value band of 0.5-1.0 to the unpriced "
                    "floor of 0.15, so lambda RISES and exposure collapses without any protocol "
                    "becoming safer. The composition pass then gives part of that class a WITNESSED "
                    "magnitude back - the destination function's own flow.out figure, reached along "
                    "a path every hop of which carries an act-as witness - which pushes lambda back "
                    "down from 84.0166 to 73.2508 and exposure back up from $76.07 to $18,059,003.86 "
                    "on witnesses, not on sheets. The band table carries 1.0.1's cut points forward "
                    "unchanged, so the letter delta is published rather than absorbed by a recut "
                    "nobody calibrated"
                ),
                "read_the_confidence_fall_correctly": (
                    "(a) the reach-magnitude term does NOT bind the headline on this corpus - the "
                    "min() is value_priced_pct 18.6 and the magnitude term sits 19.0pp clear at 37.6; "
                    "(b) the strictest magnitude figure published, "
                    "reach_magnitude_witnessed_of_reaching_pct, WOULD bind if it were the term, and "
                    "composition is the only thing in this version that moves it: flooring an "
                    "unwitnessed magnitude mints no witness, and the figure went 15.3 -> 25.6 on the "
                    "40 signals composition was asked of and on nothing else - 28 of them publish a "
                    "composed figure and 12 are withheld under typed refusals since the "
                    "execution-witness pass; (c) the 29.0 -> 18.6 fall "
                    "happened WITHIN 1.0.1 and in the BINDING value_priced term, not the magnitude "
                    "term: the dust third state stopped counting a sheet whose only priced rows are "
                    "storage-rounding zeros as priced (33.7 -> 27.8 alone), and the perimeter became "
                    "discovery-fixed, widening 295 -> 468 entities by admitting every recorded "
                    "discovery endpoint — 108 safe_owner signer wallets and 65 capability_principal "
                    "principals — so the term now answers 'what share of {protocol contracts UNION "
                    "signer wallets} did we price', a strictly harder question than the one 33.7 "
                    "answered. The letter improvement here was NOT paid for by a "
                    "confidence fall in this change; both are real, and neither is the other's price"
                ),
                "what_composition_did_not_recover": (
                    "the spec's Phase-6 coverage claim - 14 of 24 gate-control reached entities "
                    "carrying a flow.out magnitude covering 100% of reached priced value - is "
                    "PARTIALLY REFUTED on this corpus, because it counted the destination witness "
                    "and never the act-as step. Of 64 (hop, licensed selector) pairs the walk "
                    "offered, 27 carry an act-as witness and 19 of those also have a destination "
                    "flow.out witness. At this bump's own measurement "
                    # FROZEN at the 1.1.0 -> 1.2.0 bump. This sentence reports what
                    # was measured while 1.1.0 was CURRENT, and interpolating
                    # MODEL_VERSION here now would restamp a 1.1.0 measurement with
                    # whatever version happens to be shipping — a dated figure
                    # wearing a live label. The record below, which describes the
                    # version that IS current, interpolates instead; freezing this
                    # one is what makes that interpolation honest.
                    "(1.1.0-provisional, before the execution-witness pass) those composed 13 entities "
                    "and $46,164,146.29 across two findings; that pass then made every composed figure "
                    "conditional on its proving execution and the authority-deletability join, and "
                    "what survives is counted in reach_composition_census rather than asserted here. "
                    "The rest stay not_determined and are charged to confidence. The single largest "
                    "refusal class is a call site whose receiver is a PARAMETER, which is the whole "
                    "AtomicSolverV3 family - and it is why SPEC 9.5 case 2 lands on its OTHER "
                    "admissible outcome: the timelock behind RolesAuthority 0x4df6b733 does not "
                    "regain a witnessed magnitude, it and the two EOAs the shipped document "
                    "over-charged all sit at not_determined together"
                ),
                "operational_hazard_the_gate_conferral_test_introduces": (
                    "the state-variable branch reads the gate's OWN function through "
                    "function_score_signals.function_id, which is ON DELETE SET NULL against "
                    "effective_functions - and a re-analysis DELETES and reinserts a contract's "
                    "function rows. So a persisted signal that outlives one re-analysis of its "
                    "contract points at nothing, every one of its state-variable hops degrades to "
                    "capability_state_writes_not_extracted, and the row silently loses reach it held "
                    "the day before. The withhold is counted, but its cause would read as an "
                    "extraction that never ran rather than a stale foreign key. A dangling reference "
                    "therefore falls back to the signal's own (deployment entity, selector), which "
                    "the re-analysis preserves, admitted only where every function under that key "
                    "agrees on what it rewrites; the recovery population and the keys two functions "
                    "disagree under are published in "
                    "provenance.reach_bounds.gate_conferral.stale_function_reference_recovery. "
                    "Operators re-folding a protocol whose signals predate its last re-analysis "
                    "should expect that block to be non-zero and should read it before reading a "
                    "reach delta"
                ),
            },
            {
                "from": "1.1.0-provisional",
                # FROZEN at the 1.2.0 -> 1.3.0 bump, the way the 1.0.1 record
                # above is frozen. Every figure below was measured while 1.2.0
                # was CURRENT, and interpolating MODEL_VERSION here now would
                # restamp a 1.2.0 measurement with whatever is shipping — a
                # dated figure wearing a live label. The record below, which
                # describes the version that IS current, interpolates instead.
                "to": "1.2.0-provisional",
                "reference_corpus": "protocol 1 (etherfi), the only corpus this bump was measured on",
                # Two points, not three: unlike the bump above, this one has no
                # intermediate document. Both halves of the change — the ceiling
                # branch and its confidence credit — ship together, so there is
                # no floored-then-recovered lambda to quote.
                "grade_lambda": [73.2508, 71.7053],
                "letter": ["B+", "B"],
                "confidence_pct": [18.6, 18.6],
                "exposure_usd": [18059003.86, 18059003.86],
                "measured_at": (
                    "every figure in this record is a measurement on protocol 1 (etherfi) taken at "
                    "this bump's own tip (1.2.0-provisional), as the last published "
                    "1.1.0-provisional document read against the first 1.2.0-provisional one. None "
                    "of it is a projection onto a corpus this model has never scored, and there is "
                    "no second corpus these cut points could have been calibrated against"
                ),
                "what_moved": (
                    "code control gains the magnitude path it never had. Replacing a node's "
                    "implementation removes the one thing that stood between the principal and that "
                    "node's own holdings, so the node's own priced sheet is a PROVEN CEILING on what "
                    "the reach can move there - published as an at-most and never as an amount. Gate "
                    "control is untouched: seizing who may call a vault leaves the vault's own code, "
                    "its share math and its caller conditions all standing, so it still needs a "
                    "destination witness and an act-as step. pause.set is untouched: a freeze "
                    "rewrites nothing, and no witness sizes the share of a sheet it immobilises. On "
                    "this corpus 4 published rows gain a band and none appears or vanishes. The two "
                    "that move raw_points are an upgrade.implementation behind a 10-day timelock via "
                    "6/10 over $4,217,100,556.98 of priced hosts (0.9504 -> 6.336) - that figure is "
                    "the SUM of that row's 8 priced hosts, of which the $3,622,582,124.76 proxy is "
                    "the largest, and it is why the row's total exceeds any single sheet while each "
                    "host's own ceiling is still capped by its own sheet - and one behind a "
                    "Safe 4/8 over $1,606,719.06 (4.95 -> 10.5, whose published weakness also "
                    "refines 0.55 -> 0.35, because the per-entity rung was dormant until a ceiling "
                    "populated it; that refinement also RENAMES the row, whose published principal "
                    "flips from 'Safe 3/7 0xa000...cd52' to 'Safe 4/8 0xf46d...e2b5' - same "
                    "principal_unit and the same two principal_addresses, re-derived because the "
                    "rung now names the Safe that gates the priced entity, so a reader diffing the "
                    "row sees a different name for the same holder). lambda FALLS 73.2508 -> 71.7053 "
                    "because total code control over "
                    "billions now outranks a $90.06 withdrawal, which is the defect this version "
                    "corrects. The band table carries 1.1.0's cut points forward unchanged, so the "
                    "letter drop B+ -> B is published rather than absorbed by a recut nobody "
                    "calibrated"
                ),
                "read_the_flat_headline_correctly": (
                    "the headline confidence does not move, and that is the meter working rather "
                    "than the ceiling failing. confidence_pct is the min() of four terms, and on "
                    "this corpus the binding term is value_priced_pct 18.6 - what share of the "
                    "perimeter anyone priced at all - which this change does not touch. What the "
                    "ceiling moves is the magnitude term: reach_magnitude_witnessed_pct 37.6 -> "
                    "40.9, and the strictest magnitude figure published, "
                    "reach_magnitude_witnessed_of_reaching_pct, 25.6 -> 35.6. Credit goes to the 21 "
                    "signals whose ceiling produces a published row and to no others: 38 signals "
                    "pass the admission conjuncts, but crediting the 17 whose rows never enter the "
                    "grade would count an answer no published row carries. "
                    "reach_magnitude_vacuous_credit_pct stays 29.2 - a ceiling credit rests on a "
                    "real balance observation, so it is not vacuous credit. reachability_answered_pct "
                    "59.1 and capability_scored_pct 45.0 are untouched. The credit divides 20 "
                    "upgrade.implementation signals and 1 exec.arbitrary; delegatecall.execute earns "
                    "none here. What this rule refuses is overwhelmingly a BALANCE OBSERVATION gap "
                    "rather than a price-feed one - a sheet with no rows, not a sheet nobody could "
                    "price - and the refusals are counted by reason in "
                    "provenance.sheet_ceilings.calls_refused_by_reason rather than restated here, "
                    "where the figure would drift the first time the pipeline observes one more "
                    "balance"
                ),
                "what_this_version_settles": (
                    "an absence, and it is the version stamp that settles it. execution_evidence_faults "
                    "OMITS its key when the fold walked every published magnitude's proving execution "
                    "and found no fault, so absence is meant to read as a completed count of zero. That "
                    "field arrived MID-1.1.0, which left absence on a 1.1.0 document unable to "
                    "distinguish a fault-free fold from one folded before the census existed - it has "
                    "to be read as not_determined there. Every document stamped 1.2.0-provisional or "
                    "later ran the census unconditionally over the whole published population, so from "
                    "this version on an absent execution_evidence_faults IS the earned zero and may be "
                    "read as one. Join on model_version to decide which rule a document is under; there "
                    "is no other signal in the document that separates the two cases"
                ),
                "what_did_not_move_and_why_that_was_a_ruling": (
                    "exposure_usd stays $18,059,003.86 and grade_exposure stays 99.582, because a "
                    "ceiling is an at-most and not expected loss. Sheet ceilings are kept out of the "
                    "exposure numerator and charge no entity's exposure budget, so the coverage "
                    "disclosure keeps saying what it said before: 1.483% of the tracked total was "
                    "measured. Admitting them would have flipped perimeter_usd_reached_unmeasured "
                    "from $4,218,224,731.61 to $0.00 and tracked_share_measured_pct from 1.483 to "
                    "99.04 - a document built to say almost nothing was measurable would instead "
                    "claim near-total coverage on the strength of upper bounds, which is the "
                    "opposite of what that disclosure exists to say"
                ),
            },
            {
                "from": "1.2.0-provisional",
                # FROZEN at the 1.3.0 -> 1.4.0 bump, the way the two records
                # above are frozen. Every figure below was measured while 1.3.0
                # was CURRENT, and interpolating MODEL_VERSION here now would
                # restamp a 1.3.0 measurement with whatever is shipping — a
                # dated figure wearing a live label. The record below, which
                # describes the version that IS current, interpolates instead.
                "to": "1.3.0-provisional",
                "reference_corpus": "protocol 1 (etherfi), the only corpus this bump was measured on",
                # One point repeated, and that is the measurement rather than a
                # placeholder: this bump REVOKES a $0.05 ceiling, and $0.05 does
                # not move a lambda published to four decimals. The letter is
                # quoted twice for the same reason.
                "grade_lambda": [71.7053, 71.7053],
                "letter": ["B", "B"],
                "confidence_pct": [18.6, 18.6],
                "exposure_usd": [18059003.86, 18059003.86],
                "measured_at": (
                    "every figure in this record is a measurement on protocol 1 (etherfi) taken at "
                    "this bump's own tip (1.3.0-provisional), as the last published "
                    "1.2.0-provisional document read against the first 1.3.0-provisional one. None "
                    "of it is a projection onto a corpus this model has never scored, and there is "
                    "no second corpus these cut points could have been calibrated against"
                ),
                "what_moved": (
                    "a sheet whose asset list was read AT the endpoint's page cap no longer ADMITS "
                    "A SHEET CEILING. That arm and no other, stated narrowly because the scope is "
                    "smaller than the defect: a sheet also caps a figure from above at two OTHER "
                    "sites - the composed-magnitude cap and the entity-holdings cap, both a "
                    "min(witness, sheet) - and NEITHER consults the truncation, so both still cap "
                    "against a page-capped sheet after this bump. That is live on this corpus: the "
                    "composed figure on base::0x86b5780b606940eb59a062aa85a07959518c0161 publishes "
                    "$150,410.13 under bounded_by 'destination sheet' against a $164,041.15 flow.out "
                    "witness, and the sheet that trimmed it is truncated. Those two sites are "
                    "registered as open items and are NOT closed here. "
                    "The ERC-20 discovery endpoint returns one 100-entry page, "
                    "and a holder with more assets than that comes back truncated - the rows stored "
                    "are a PREFIX of the holdings, so their sum is a floor over the sheet. 1.2.0 "
                    "read only the sheet's STATE, which answers priced for a capped list exactly as "
                    "it does for a whole one, so those sheets were published as at-mosts. The plane "
                    "now carries the truncation per entity and ceiling_for refuses them under their "
                    "own token, asset_list_truncated - a refusal closed by paging or by a "
                    "chain-derived sweep, which is a different pipeline from the one that answers "
                    "'nobody priced these rows'. On this corpus 7 protocol-1 contracts are at the "
                    "cap over 5 distinct sheets, and exactly ONE of them was publishing a ceiling: "
                    "base::0x6c240dda6b5c336df09a4d011139beaaa1ea2aa2, the $0.05 row on the Safe 4/7 "
                    "upgrade.implementation finding, which was revoked AT THIS BUMP. The deltas that "
                    "follow are frozen as at-the-bump measurements and are not readings of the "
                    "current document: entities priced from a sheet ceiling fell 11 -> 10 (entity "
                    "meter), signals credited in confidence 21 -> 20 (signal meter), and refused "
                    "calls went 49 -> 50 (call meter), one previously unpriced refusal on "
                    "base::0x566bfa809b88967c994d77ed924bebffe80bd00c being RE-TOKENISED rather than "
                    "added and the revoked call being the new one, so asset_list_truncated read 2 "
                    "while unpriced read 0 and no_rows 36 / below_resolution 12 did not move. The "
                    "other four capped sheets published no ceiling and lost none, and were "
                    "ineligible for one until their lists were completed - which did not stop them "
                    "capping a composed magnitude, per the open items above. SINCE THE BUMP the "
                    "prefix was completed by pagination and the aliased implementation row that "
                    "carried the last truncation flag on that entity was re-observed, so the guard "
                    "no longer fires on it: the rule is unchanged and its input is not, which is "
                    "the whole point of a guard that reads evidence"
                ),
                "the_invariant_6_exception_this_bump_takes": (
                    "invariant 6 says the model is monotone in resolution work - more evidence never "
                    "lowers a term - and this bump LOWERS one: reach_magnitude_witnessed_pct falls "
                    "40.900042 -> 40.852393 (below the document's 1-decimal resolution, so the "
                    "published 40.9 does not move) and the strictest published magnitude figure, "
                    "reach_magnitude_witnessed_of_reaching_pct, falls 35.6 -> 35.5. The exception is "
                    "ruled and narrow: invariant 6 governs EARNING evidence, and nothing here was "
                    "earned and then withdrawn. What is withdrawn is an at-most that was never "
                    "earned in the first place - a prefix of an asset list published as a bound on "
                    "the whole of it - so the fall is the correction and not the cost of one. The "
                    "direction to expect from the rest of this program is the opposite: completing "
                    "those lists, and proving the never-observed sheets empty, only adds evidence "
                    "and only raises terms"
                ),
                "what_did_not_move_and_why_that_was_a_ruling": (
                    "grade_lambda stays 71.7053, grade_exposure stays 99.582 and exposure_usd stays "
                    "$18,059,003.86 - byte-unchanged, and checked field by field rather than "
                    "assumed. A sheet ceiling charges no exposure, so revoking one cannot move the "
                    "exposure figures; and the revoked row's raw_points stays 3.15 because the "
                    "<$100k band and not_determined weight identically at that rung, which is why "
                    "lambda holds through a revocation. The ONE grade-surface figure that moves is "
                    "provenance.sheet_ceilings.ceiling_usd_over_distinct_entities, "
                    "$4,218,707,276.09 -> $4,218,707,276.04, which is the revoked $0.05 and nothing "
                    "else. The band table carries 1.2.0's cut points forward unchanged: no letter "
                    "moved, so nothing here was recut to hold one"
                ),
            },
            {
                "from": "1.3.0-provisional",
                # INTERPOLATED, and that is the point: while this is the CURRENT
                # version the record and the document it describes must not be
                # able to drift apart. The next bump freezes this to its literal
                # — the way the three records above are frozen — and adds its own
                # interpolated record.
                "to": MODEL_VERSION,
                "reference_corpus": "protocol 1 (etherfi), the only corpus this bump was measured on",
                # The pair is [last 1.3.0 document, first 1.4.0 document], both
                # real folds of protocol 1 — not a projection and not a repeat.
                # The rule shipped with a live one-shot behind it: 1,973 readings
                # over 1,264 tokens carry delivery evidence, 13 sheets are
                # determined by it, and confidence is the one published figure
                # that moved. Frozen at the bump: this record states what was
                # measured HERE and is not re-measured afterwards.
                "grade_lambda": [71.7053, 71.7053],
                "letter": ["B", "B"],
                "confidence_pct": [42.5, 43.2],
                "exposure_usd": [18061300.76, 18061300.76],
                "measured_at": (
                    "every figure in this record is a measurement on protocol 1 (etherfi) taken at "
                    f"this bump's own tip ({MODEL_VERSION}), as the last published "
                    f"1.3.0-provisional document read against the first {MODEL_VERSION} one. None "
                    "of it is a projection onto a corpus this model has never scored, and there is "
                    "no second corpus these cut points could have been calibrated against"
                ),
                "what_moved": (
                    "a sheet may now be DETERMINED at $0 by the delivery shape of what arrived on "
                    "it. A reading is disposed only where all of: the protocol's discovered "
                    "address universe was assembled at all, the asset is not the native coin, the "
                    "reading is unpriced or below the storage column's resolution (a PRICED "
                    "reading is never disposed), the token address is absent from that universe "
                    "tested CHAIN-BLIND, and EVERY observed account contributing to the reading "
                    "carries stored delivery evidence whose every incoming delivery arrived in a "
                    "transaction carrying at least K = 25 same-token transfer LOGS. The log count "
                    "is the meter K is calibrated in, and it is an UPPER BOUND on that "
                    "transaction's distinct recipients rather than a count of them. Such a "
                    "sheet answers a sixth state, airdrop_determined, and an eighth ceiling "
                    "reason of the same name in the ADMITTING set. WHAT THE STATE CLAIMS IS "
                    "DELIVERY SHAPE AND NEVER WORTH. It is BARRED from the two min(witness, "
                    "sheet) trim sites: the disposed assets are still held, so trimming a "
                    "witnessed magnitude to $0 there would publish a false zero on a security "
                    "surface. And it does not by itself earn asset-set coverage: a disposition "
                    "says one asset's contribution is nil and says nothing about whether the "
                    "LIST is whole, so a disposed sheet clears the full-coverage conjunct only "
                    "where the chain's own transfer history proves its list - which closes "
                    "SHEET_OBSERVATION_SPEC.md 9.3-addendum item 2. MEASURED AT THIS BUMP, on a "
                    "live one-shot that ran before it shipped: 1,973 readings over 1,264 tokens "
                    "carry delivery evidence and are disposed, 13 sheets are determined by it "
                    "(sheet_states unpriced 19 -> 8 and priced_below_resolution 19 -> 17, "
                    "airdrop_determined 13), one of them publishes a sheet ceiling under the new "
                    "reason (entities_by_ceiling_reason airdrop_determined 1), "
                    "entities_priced_from_a_sheet_ceiling 24 -> 25, "
                    "signals_credited_in_confidence 46 -> 47 and calls_refused_by_reason.unpriced "
                    "6 -> 5. A further 484 readings are disposed by their evidence and REFUSED "
                    "their sheet's determination because one folded account of the sheet was "
                    "never scanned - a named, closable gap, counted rather than absorbed. The arm "
                    "therefore does not ship uncalibrated: it gained carriers inside this run, "
                    "and the register's own rule took the entry back off"
                ),
                "the_invariant_6_exception_this_bump_takes": (
                    "invariant 6 says the model is monotone in resolution work, and the "
                    "protocol-reference conjunct of this rule is ANTI-MONOTONE: growing the "
                    "protocol's discovered universe can move a token INTO it and withdraw a "
                    "determination that was published. The ruling is that withdrawal is the SAFE "
                    "direction - the universe growing means the protocol demonstrably refers to "
                    "that token, and un-condemning it is the correction - so the exception is "
                    "taken deliberately and in one direction only. The consequence a reader must "
                    "carry: THIS DOCUMENT IS NOT STABLE ACROSS DISCOVERY GROWTH, and a "
                    "disposition withdrawn between two folds is not a regression. The class this "
                    "matters for is measured and it is FIVE demonstrably real tokens with a "
                    "fan_out_all delivery shape on this corpus - HEX, WETH and base USDC, which "
                    "the universe spares, and uniETH and USDtb, which it does not. Three named "
                    "single points of failure follow from it, all measured on this corpus. "
                    "(1) HEX (0x2b591e99afe9f32eaa6214f7b7629768c40eeb39), a REAL token whose "
                    "deliveries are genuine mass distributions (fan-out census 199 x13, 399 x14, "
                    "400 x1, 500 x6), is spared "
                    "ONLY by its presence in the universe, and its presence rests on a SINGLE "
                    "effect_verdicts row: if that row moves, a real token is condemned. (1b) THE "
                    "SAME SHAPE A SECOND TIME, which the pre-run analysis did not name: base "
                    "USDC is spared by dapp_interactions ALONE. One source, one anti-monotone "
                    "arm, one real token - and dapp_interactions is the source with no chain "
                    "column at all, which is part of why the universe is read chain-blind. (2) "
                    "uniETH (0xf1376bcef0f78459c0ed0ba5ddce976f1ddf51f4) is a measured, "
                    "unavoidable condemnation of a real token - one delivery, fan-out 101, absent "
                    "from the universe under every variant - and no K spares it without losing "
                    "real airdrop batches (the smallest observed is 48). That is acceptable ONLY "
                    "because the published state is a delivery-shape claim, which is TRUE of "
                    "uniETH: it did arrive by mass distribution. It would be a lie under any "
                    "spam/worthless naming, and no consumer may rename it so. (3) THE LIVE RUN "
                    "FOUND A SECOND MEMBER OF uniETH's CLASS that the pre-run census did not "
                    "predict: USDtb (0xc139190f447e929f090edeb554d95abb8b18ac1c), a real token "
                    "held at three accounts, each by a single delivery carrying 175 same-token "
                    "transfer logs. It is the same true claim under the same naming, and it is "
                    "recorded here because the class is evidently larger than the two tokens the "
                    "pre-run analysis named - a reader must expect real tokens in it, not treat "
                    "each one as a defect. Neither uniETH nor USDtb sits on a sheet this run "
                    "determined: all 13 determined sheets are free of any reading the census "
                    "calls known-real, so no real holding was published as a determined $0"
                ),
                "what_this_bump_does_not_close": (
                    "the protocol-reference conjunct is INERT ON BASE. Measured: it condemns "
                    "1,175 of 1,175 base unpriced tokens and 1,745 of 1,745 base unpriced "
                    "readings, so it partitions nothing there, and its precision on base is "
                    "not_determined - the priced control set is 6 tokens and n=6 is not a "
                    "validation. Base disposition therefore rests on DELIVERY SHAPE ALONE over "
                    "1,745 readings, and base is the bulk of the population. The universe is "
                    "tested chain-blind for a measured reason: chain-scoping it falsely condemns "
                    "$3,272,829.37 of real holdings ($2,203,581.37 on optimism, whose contracts "
                    "carry no dependency, control-graph or signal rows at all, and $1,069,248.00 "
                    "on base) and buys no extra condemnation where the mass-distribution readings "
                    "are. The asset list a disposition covers is also NOT proven whole - the "
                    "gate refuses only a list read AT the page cap - so the determination is over "
                    "the readings observed and never over the holdings"
                ),
                "what_did_not_move_and_why_that_was_a_ruling": (
                    "grade_lambda stays 71.7053, grade_exposure stays 99.582, exposure_usd stays "
                    "$18,061,300.76 and ceiling_usd_over_distinct_entities stays "
                    "$4,218,743,833.16 - byte-unchanged, and checked field by field rather than "
                    "assumed. What DID move is confidence and only confidence: confidence_pct "
                    "42.5 -> 43.2, on value_priced_pct 42.5 -> 45.0 and "
                    "reach_magnitude_witnessed_pct 43.1 -> 43.2, with capability_scored_pct 45.4, "
                    "reachability_answered_pct 59.6 and reach_magnitude_ceiling_pct 62.7 all "
                    "unmoved. The dollar surfaces cannot move on this rule and that is structural "
                    "rather than lucky: a sheet ceiling charges no exposure, the one ceiling this "
                    "rule admitted is $0 so it adds nothing to the ceiling dollars, and the state "
                    "is BARRED from both min(witness, sheet) trim sites, which is the only path "
                    "by which it could have lowered a published magnitude. The band table carries "
                    "1.3.0's cut points forward unchanged: no letter moved, so nothing here was "
                    "recut to hold one"
                ),
            },
        ],
        "uncalibrated_arms": list(UNCALIBRATED_ARMS),
        "uncalibrated_arm_disclosures": {
            "reading": (
                "one entry per uncalibrated arm this run added, saying WHICH state is uncalibrated, "
                "where the document publishes it, and which test constructs it — because the flat "
                "uncalibrated_arms list above is a token and a reader cannot check an arm they "
                "cannot find. An arm is registered when no instance of its state existed in the "
                "corpus the model was calibrated against, so nothing in the published numbers was "
                "fitted to it and its behaviour rests on a constructed fixture alone. This block "
                "counts NOTHING and makes no claim about the population of THIS document: it is "
                "authored where no data is read, and a figure written here would be a claim about a "
                "corpus it has never seen. population_census names the field of this document where "
                "the instances are counted, and null there says this document publishes no counter "
                "for that state — which is not a zero. arms_registered_without_a_disclosure is the "
                "earned remainder: tokens in uncalibrated_arms that predate this shape and carry no "
                "per-arm record, listed rather than left to be inferred from the difference between "
                "two lists"
            ),
            "registered": [dict(entry) for entry in UNCALIBRATED_ARM_DISCLOSURES],
            "arms_registered_without_a_disclosure": [
                arm for arm in UNCALIBRATED_ARMS if arm not in {entry["arm"] for entry in UNCALIBRATED_ARM_DISCLOSURES}
            ],
        },
    }
