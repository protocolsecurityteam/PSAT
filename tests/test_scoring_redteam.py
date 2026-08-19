"""Adversarial regression suite: every attack the red-team landed, pinned.

These drive the fold with hand-built hostile signals and stubbed planes, so they
need no database and no network. Each test names the shape it forbids: a witness
that was never read standing in for one that was, on the weakness axis, the value
axis, the gate envelopes or the published document.
"""

from __future__ import annotations

import itertools
from typing import Any, cast

import pytest

from services.scoring import distill as D
from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.constants import (
    FREEZE_CAPABILITY_PROVEN,
    FREEZE_KEYSET_RECOVERABLE,
    FREEZE_SUSTAINABLE,
    WEAKNESS_SAFE_MAJORITY,
    WEAKNESS_SAFE_MINORITY,
    WEAKNESS_SAFE_SINGLE_SIGNER,
    WEAKNESS_SAFE_SUPERMAJORITY,
    WEAKNESS_SAFE_UNCREDITED,
    WEAKNESS_TIMELOCK_UNDETERMINED,
    delay_discount,
)
from services.scoring.schema import (
    FunctionSignal,
    PrincipalRef,
    Tri,
    entity_key,
    not_determined_signal_defaults,
)
from tests import composition_admission_fixtures as CA
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    EOA,
    HOP1_ACCEPTED,
    HOP1_SELECTOR,
    KEY_C,
    KEY_T,
    KEY_V,
    OWNERS,
    SAFE,
    SCANNED,
    TIE_CALLING_SELECTOR,
    TIE_SELECTOR,
    VAULT,
    C,
    _cc_row,
    _composing_case,
    _composing_principals,
    _composing_signals,
    _gate_row,
    _role_edge,
    _tied_case,
    _tied_signals,
    _two_hop_case,
    act_as_plane,
    bounded_by_sheet,
    closure_of,
    condition_plane,
    conferral_plane,
    facts,
    flow_sig,
    fold,  # noqa: F401  — the fold fixture, moved but still driven from here
    magnitude,
    proven,
    reaches,
    sig,
    value_plane,
)
from utils import execution_record as EX
from utils.scoring_status import (
    DESTINATION_STATE_UNCONSTRAINED_PROVEN,
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    SEVERITY_STATE_NOT_DETERMINED,
    SEVERITY_STATE_PROVEN,
    VALUE_BOUND_EXACT,
    VALUE_BOUND_FLOOR,
    VALUE_STATE_PROVEN_REACH,
)

SAFE2 = "0x" + "5" * 40
TIMELOCK = "0x" + "7" * 40
PROXY = "0x" + "6" * 40
IMPL = "0x" + "9" * 40
KEY_PROXY = entity_key("ethereum", PROXY)
KEY_IMPL = entity_key("ethereum", IMPL)


def pause_sig(**over: Any) -> FunctionSignal:
    gates = {
        "pause_effective": Tri.not_determined().to_json(),
        "freeze_recovery_principals": Tri.not_determined().to_json(),
        "freeze_coverage_fraction": Tri.not_determined().to_json(),
        **over.pop("gates", {}),
    }
    return sig(claim_id="pause.set", gates=gates, **over)


# --------------------------------------------------------------------------
# Weakness axis
# --------------------------------------------------------------------------


def test_f3_unread_owner_set_is_not_a_k_of_k_safe(fold):
    """n backfilled from k publishes the strongest rung out of an absent witness."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", threshold=2)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["weakness"] == WEAKNESS_SAFE_UNCREDITED
    assert "2/2" not in finding["principal"] and "2/2" not in str(finding["weakest_gate"])
    assert any("safe_owner_set_not_determined" in note for note in finding["witness_notes"])


def test_f3_proven_owner_set_still_earns_its_rung(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    assert document.findings[0]["weakness"] == WEAKNESS_SAFE_SUPERMAJORITY
    assert document.findings[0]["weakest_gate"] == "Safe 3/4"


def _pause_document(fold, pauser: P.PrincipalFacts, recovery: P.PrincipalFacts | None):
    entries = [{"function_principal_id": 2, "chain": "ethereum", "address": recovery.address}] if recovery else None
    signal = pause_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", pauser.address),),
        gates=(
            {"freeze_recovery_principals": Tri.proven("enumerated", entries).to_json()} if entries is not None else {}
        ),
        **proven(FREEZE_CAPABILITY_PROVEN, ("freeze_capability_proven",)),
        **reaches(KEY_C),
    )
    principals = {1: pauser}
    if recovery is not None:
        principals[2] = recovery
    return fold([signal], principals=principals, value=value_plane({KEY_C: {"usdc": 5_000_000.0}}))


def test_f2_an_unread_pauser_key_set_moves_severity_in_neither_direction(fold):
    """The freezing key set was never read, so independence is uncomputable.

    Nothing may move on that: not the recoverable credit (which would need proven
    independence) and not the sustainable component (which would need proven
    dependence). The question is published instead.
    """
    document = _pause_document(
        fold,
        facts(1, SAFE, "safe", threshold=1),  # owner set never resolved
        facts(2, SAFE2, "safe", owners=OWNERS, threshold=2),
    )
    finding = document.findings[0]
    assert not any("keyset_independent" in note for note in finding["witness_notes"])
    assert finding["severity_proven"] == FREEZE_CAPABILITY_PROVEN
    # The single-signer cliff is not waived on the strength of a non-witness.
    assert finding["weakness"] == WEAKNESS_SAFE_UNCREDITED
    assert "freeze_recovery_independence_not_determined" in {w["kind"] for w in document.warnings}
    assert "freeze_recovery_independence_not_determined" in finding["severity_basis"]


def test_f2_every_undetermined_recovery_arm_lands_on_the_same_rung(fold):
    """No recovery claim, an unresolved recovery principal and an unread key set."""
    pauser = facts(1, SAFE, "safe", owners=OWNERS, threshold=2)
    arms = [
        _pause_document(fold, pauser, None),
        _pause_document(fold, pauser, facts(2, SAFE2, "contract")),
        _pause_document(fold, facts(1, SAFE, "safe", threshold=2), facts(2, SAFE2, "safe", owners=OWNERS, threshold=2)),
    ]
    assert {document.findings[0]["severity_proven"] for document in arms} == {FREEZE_CAPABILITY_PROVEN}


def test_f2_proven_dependence_adds_the_sustainable_component(fold):
    """The only witness that raises the freeze rung is a PROVEN dependent key set."""
    shared = ("0x" + "1" * 40, "0x" + "2" * 40, "0x" + "3" * 40)
    document = _pause_document(
        fold,
        facts(1, SAFE, "safe", owners=shared, threshold=1),
        facts(2, SAFE2, "safe", owners=shared, threshold=2),
    )
    finding = document.findings[0]
    assert finding["severity_proven"] == FREEZE_SUSTAINABLE
    # And the single-signer cliff stands, because independence was refuted.
    assert finding["weakness"] == WEAKNESS_SAFE_SINGLE_SIGNER
    assert "freeze_keyset_not_independent" in finding["severity_basis"]


def test_f2_an_eoa_pauser_is_its_own_key_set(fold):
    """The address fallback is admissible exactly where the principal IS a key."""
    recovery = [{"function_principal_id": 2, "chain": "ethereum", "address": SAFE2}]
    signal = pause_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"freeze_recovery_principals": Tri.proven("enumerated", recovery).to_json()},
        **proven(FREEZE_KEYSET_RECOVERABLE, ("freeze_capability_proven",)),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE2, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}),
    )
    finding = document.findings[0]
    assert any(note.startswith("keyset_independent") for note in finding["witness_notes"])
    assert finding["severity_proven"] == FREEZE_KEYSET_RECOVERABLE


def test_w3_a_proven_zero_delay_is_not_an_unread_one(fold):
    assert delay_discount(0) == 1.0
    assert delay_discount(None) is None
    assert delay_discount(-1) is None

    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", TIMELOCK),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    zero = fold(
        [signal],
        principals={1: facts(1, TIMELOCK, "timelock", delay=0.0)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    ).findings[0]
    unread = fold(
        [signal],
        principals={1: facts(1, TIMELOCK, "timelock")},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    ).findings[0]

    assert "0d" in str(zero["weakest_gate"])
    assert any("proven_zero" in note for note in zero["witness_notes"])
    assert "not_determined" in str(unread["weakest_gate"])
    assert unread["weakness"] == WEAKNESS_TIMELOCK_UNDETERMINED


def _timelock_population(include_execute: bool) -> list[FunctionSignal]:
    claims = ["timelock.schedule"] + (["timelock.execute"] if include_execute else [])
    population = [
        sig(
            claim_id=claim,
            function_name=claim.split(".")[1],
            deployment_address=TIMELOCK,
            contract_id=2,
            selector=f"0x0000000{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        )
        for index, claim in enumerate(claims)
    ]
    population.append(
        sig(
            function_name="upgradeToC",
            deployment_address=VAULT,
            contract_id=3,
            selector="0x3659cfe6",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", TIMELOCK),),
            **proven(1.0),
            **reaches(KEY_V),
        )
    )
    population.append(
        sig(
            function_name="upgradeToD",
            deployment_address=C,
            contract_id=4,
            selector="0x3659cfe7",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
            **proven(1.0),
            **reaches(KEY_C),
        )
    )
    return population


def test_f8_propose_only_does_not_collapse_a_timelock(fold):
    """The collapse asserts the Safe can ACT AS the timelock: both halves or none."""
    principals = {
        1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2),
        2: facts(2, TIMELOCK, "timelock", delay=172800.0),
    }
    plane = value_plane({KEY_V: {"usdc": 100_000_000.0}, KEY_C: {"usdc": 10_000_000.0}})

    propose_only = fold(_timelock_population(include_execute=False), principals=principals, value=plane)
    both = fold(_timelock_population(include_execute=True), principals=principals, value=plane)

    propose_units = {f["principal_unit"] for f in propose_only.findings}
    assert entity_key("ethereum", TIMELOCK) in propose_units
    timelock_row = next(f for f in propose_only.findings if f["principal_unit"] == entity_key("ethereum", TIMELOCK))
    assert timelock_row["weakness"] == WEAKNESS_TIMELOCK_UNDETERMINED

    # With both halves proven the collapse runs, and the delayed value is still
    # charged at the DISCOUNTED weakness rather than the Safe's direct one.
    collapsed = [
        f for f in both.findings + both.provenance["subsumed_rows"] if f["capability"] == "upgrade.implementation"
    ]
    assert {f["principal_unit"] for f in collapsed} == {entity_key("ethereum", SAFE)}
    weaknesses = sorted(f["weakness"] for f in collapsed)
    assert len(weaknesses) == 2 and weaknesses[0] < weaknesses[1]
    assert both.provenance["principal_units"]["timelock_collapses"]


def test_w4_an_unread_proposer_threshold_cannot_rank_as_the_strongest(fold):
    """inv.5 takes the WEAKEST path, and unread must not win by construction."""
    population = _timelock_population(include_execute=True)
    principals = {
        1: facts(1, SAFE, "safe", owners=OWNERS),  # threshold never read
        2: facts(2, TIMELOCK, "timelock", delay=172800.0),
    }
    document = fold(population, principals=principals, value=value_plane({KEY_V: {"usdc": 100_000_000.0}}))
    rows = document.findings + document.provenance["subsumed_rows"]
    timelock_rows = [f for f in rows if "timelock" in str(f["weakest_gate"])]
    assert timelock_rows, "the timelock row should still be published"
    assert "k not_determined" in str(timelock_rows[0]["weakest_gate"])
    # Uncredited quorum × the proven delay discount — never a fabricated n/n.
    assert timelock_rows[0]["weakness"] == round(WEAKNESS_SAFE_UNCREDITED * (delay_discount(172800) or 1.0), 4)


def test_w6_an_unreadable_module_set_leaves_the_kn_credit_standing():
    """§7.1: only a PROVEN module or guard withholds the demotion."""
    proven_empty = {
        "module_set": [],
        "module_set_basis": "storage_linked_list_terminated",
        "guard": "proven_zero",
        "protection_is_upper_bound": "not_determined",
    }
    unreadable = {"module_set_basis": "not_determined", "protection_is_upper_bound": "not_determined"}
    proven_module = {**proven_empty, "protection_is_upper_bound": True}
    enumerated = {"module_set": ["0x" + "9" * 40], "module_set_basis": "storage_linked_list_terminated"}
    guarded = {**proven_empty, "guard": "proven_address"}

    assert P._safe_protection_verdict({"safe_protection": proven_empty})[0] is False
    assert P._safe_protection_verdict({"safe_protection": unreadable})[0] is False
    assert P._safe_protection_verdict({})[0] is False
    assert P._safe_protection_verdict({"safe_protection": proven_module})[0] is True
    assert P._safe_protection_verdict({"safe_protection": enumerated})[0] is True
    assert P._safe_protection_verdict({"safe_protection": guarded})[0] is True


# --------------------------------------------------------------------------
# Value axis
# --------------------------------------------------------------------------


def test_f1_a_native_only_flow_is_still_bounded_by_its_witness(fold):
    """The fork proved the call moves $10; the entity's sheet is not the answer."""
    plane = value_plane({KEY_C: {"native": 1_000_000_000.0}})
    signal = flow_sig(
        function_name="sweepETH",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={
            "reach_magnitude_usd": Tri.proven("proven_exact", 10.0).to_json(),
            "asset_class": Tri.proven("proven", "native_only").to_json(),
        },
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_EXACT),
    )
    finding = fold([signal], value=plane).findings[0]
    assert finding["value_at_stake_usd"] == 10.0
    assert finding["value_band"] == "<$100k"


def test_f1_a_native_only_flow_with_no_native_row_is_not_determined(fold):
    signal = flow_sig(
        function_name="sweepETH",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"asset_class": Tri.proven("proven", "native_only").to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C),
    )
    finding = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}})).findings[0]
    assert finding["value_at_stake_usd"] is None
    assert finding["undetermined_instances"][0]["why"].startswith("native_only_flow")


def test_f4_an_unpriced_entity_is_never_exposure_zero(fold):
    priced = sig(
        function_name="upgradeToA",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(50_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    unpriced = sig(
        function_name="upgradeToB",
        deployment_address=VAULT,
        contract_id=2,
        selector="0xfeedface",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_V),
    )
    document = fold(
        [priced, unpriced],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    by_unit = {f["principal_unit"]: f for f in document.findings}
    assert by_unit[entity_key("ethereum", EOA)]["exposure_usd"] is not None
    assert by_unit[entity_key("ethereum", SAFE)]["exposure_usd"] is None
    assert document.provenance["exposure_gaps"]


def test_f11_a_withheld_grade_publishes_no_derived_figure(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=value_plane({}))
    served = document.document()

    assert served["grade_state"] == "not_determined"
    assert served["confidence_pct"] is None
    assert "pct" not in served["model_parameters"]["confidence_detail"]
    for finding in served["findings"]:
        assert "net_points_lambda" not in finding
        assert "exposure_usd" not in finding
    withheld = document.provenance["grade_withheld"]
    assert withheld["grade_lambda_computed"] is not None
    assert withheld["per_finding"]


def test_f10_the_transitive_branch_reads_the_signals_value_state(fold):
    """An unwitnessed reach charges no closure, however rich the neighbours."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
    )  # value_state stays not_determined
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        closure={KEY_C: {KEY_V}},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 900_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] is None
    assert finding["value_state"] == "not_determined"
    assert finding["undetermined_instances"]


def test_v3_the_transitive_branch_discloses_unpriced_closure_entities(fold):
    """Every closure entity is NAMED, priced or not — and none is priced by its sheet.

    The transitive branch used to publish the closure's balance sheets as the
    row's value, so the entity that could not be priced was the only one that
    appeared as a gap. Under the magnitude discipline the sheet prices nothing:
    a reach with no magnitude witness is not_determined at BOTH entities, and
    both are named. Membership is untouched — the row still reaches them.

    Asked of GATE control, which is the class the sheet may never price: the
    vault's own code, share math and caller conditions are all still standing
    and none of them has been examined. Code control has one narrow exception —
    its own controlled node — and that exception is pinned separately, with its
    downstream entity still landing here (``test_cc3_*``).
    """
    signal = sig(
        claim_id="authority.replace",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        closure={KEY_C: {KEY_V}},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])
    assert finding["value_at_stake_usd"] is None
    assert finding["value_band"] == "not_determined"
    # The floor flag is about a priced total that under-covers; there is no
    # total here, so it is False rather than a floor over nothing.
    assert finding["value_at_stake_is_floor"] is False
    named = {row["entity"] for row in finding["undetermined_instances"]}
    assert named == {KEY_C, KEY_V}
    priced_gap = next(row for row in finding["undetermined_instances"] if row["entity"] == KEY_C)
    assert priced_gap["why"].startswith("reach_magnitude_not_witnessed")
    assert finding["magnitude_witness_census"]["magnitude_not_witnessed"] == 1


def test_v4_exposure_caps_on_the_entity_contribution_not_the_row_total(fold):
    """A row spread over N entities must not charge its total against each one."""
    signals = [
        flow_sig(
            function_name=f"withdraw{index}",
            deployment_address=address,
            contract_id=index + 1,
            selector=f"0x0000001{index}",
            authority_openness="open",
            principal_state="none_required",
            witness_tier="behavioral_observed",
            gates={"reach_magnitude_usd": Tri.proven("proven_exact", 100.0).to_json()},
            **proven(0.9, ("caller_arbitrary_proven",)),
            **reaches(entity_key("ethereum", address), bound=VALUE_BOUND_EXACT),
        )
        for index, address in enumerate((C, VAULT))
    ]
    document = fold(
        signals,
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 200.0
    assert finding["value_by_entity"] == {KEY_C: 100.0, KEY_V: 100.0}
    # Each entity contributes at most its own $100, never the row's $200.
    assert finding["exposure_usd"] <= 200.0


def test_p0_a_proxy_and_its_implementation_are_one_priced_entity(fold):
    """Reaching both keys of one proxy pair charges one balance, not two.

    The plane folds the implementation's balance onto its proxy, so both keys
    answer with the same dollars; keying the row's contributions on the raw keys
    published a value at stake and an exposure that were both exactly 2x real.
    """
    signal = sig(
        deployment_address=PROXY,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(100_000_000.0),
        **proven(1.0),
        **reaches(KEY_IMPL, KEY_PROXY),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_PROXY: {"usdc": 100_000_000.0}}, alias={KEY_IMPL: KEY_PROXY}),
    )
    finding = document.findings[0]
    assert finding["reach_entities"] == [KEY_PROXY]
    assert finding["value_by_entity"] == {KEY_PROXY: 100_000_000.0}
    assert finding["value_at_stake_usd"] == 100_000_000.0
    assert finding["exposure_entities_charged"] == [KEY_PROXY]
    fraction = finding["severity_proven"] * finding["weakness"]
    assert finding["exposure_usd"] == round(fraction * 100_000_000.0, 2)
    # The denominator holds that same single balance, so charging the pair twice
    # spent more than the protocol tracks and drove the grade negative.
    assert document.grade_exposure == round(100.0 * (1.0 - fraction), 3)


def test_host_entities_name_the_deployments_not_the_reach(fold):
    """The row publishes WHERE its instances live, apart from what they reach.

    A transitive row's reach set can omit the host entirely (the host may be
    unpriced), leaving a consumer no way to name the contract the function is
    actually on. host_entities carries the deployment keys verbatim.
    """
    signal = sig(
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_V),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_V: {"usdc": 1_000.0}}),
    )
    finding = document.findings[0]
    assert finding["host_entities"] == [KEY_C]
    assert finding["reach_entities"] == [KEY_V]
    assert finding["n_entities"] == 1


# --------------------------------------------------------------------------
# Gates and vocabulary
# --------------------------------------------------------------------------


def test_f7_a_withheld_gate_token_publishes_no_earned_negative(fold):
    withheld = Tri.proven("not_earned", {"empty_reason": "members==[] but no served credit"})
    signal = sig(
        claim_id="roles.grant",
        function_name="grantRole",
        gates={"exact_empty_credit": withheld.to_json()},
        **proven(0.55),
        **reaches(KEY_C),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    assert document.earned_negatives == []
    assert "gate_input_malformed" in {w["kind"] for w in document.warnings}


def test_f7_an_earned_credit_beside_resolved_principals_is_refused(fold):
    earned = Tri.proven("earned", {"empty_reason": "owner_read_zero", "block": 21_000_000})
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"exact_empty_credit": earned.to_json()},
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    )
    assert document.earned_negatives == []
    assert "exact_empty_credit_contradicted_by_principals" in {w["kind"] for w in document.warnings}


def test_f7_one_function_publishes_one_earned_negative(fold):
    earned = Tri.proven("earned", {"empty_reason": "owner_read_zero", "block": 21_000_000})
    signals = [
        sig(
            claim_id=claim,
            function_name="initialize",
            selector="0xaabbccdd",
            gates={"exact_empty_credit": earned.to_json()},
        )
        for claim in ("authority.replace", "ownership.transfer", "roles.grant")
    ]
    document = fold(signals, value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    assert len(document.earned_negatives) == 1


def test_probe_a_string_magnitude_never_reaches_the_value_axis(fold):
    signal = flow_sig(
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", "1e12").to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1.0}}))
    assert document.findings == []
    assert "gate_input_malformed" in {w["kind"] for w in document.warnings}


def test_probe_a_poisoned_payload_fails_closed_on_its_own_row(fold):
    poison = flow_sig(
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_exact", {"state": "not_determined", "value": None}).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C),
    )
    healthy = sig(
        function_name="upgradeTo",
        contract_id=9,
        selector="0x3659cfe6",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [poison, healthy],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    )
    # The bad row is withheld; the rest of the protocol still scores.
    assert [f["capability"] for f in document.findings] == ["upgrade.implementation"]
    assert "gate_input_malformed" in {w["kind"] for w in document.warnings}


def test_probe_a_missing_required_gate_withholds_its_row(fold):
    signal = FunctionSignal(
        **{
            **not_determined_signal_defaults(),
            "job_id": None,
            "protocol_id": 1,
            "contract_id": 1,
            "chain": "ethereum",
            "deployment_address": C,
            "function_name": "sweep",
            "claim_id": "flow.out",
            "selector": "0x1",
            "gate_inputs": {"exact_empty_credit": Tri.not_determined().to_json()},
            "severity": Tri.proven(SEVERITY_STATE_PROVEN, 0.9),
            "severity_basis": ("caller_arbitrary_proven",),
            **reaches(KEY_C),
        }
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    assert document.findings == []
    assert "gate_input_malformed" in {w["kind"] for w in document.warnings}


# --------------------------------------------------------------------------
# Name-as-witness, contradictions and published labels
# --------------------------------------------------------------------------


def _contract_facts(**over: Any) -> D._ContractFacts:
    base: dict[str, Any] = dict(contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[])
    base.update(over)
    return D._ContractFacts(**base)


def test_f6_the_registry_escalation_needs_mutator_selectors():
    owner = {"address": SAFE, "resolved_type": "safe", "block": 1}
    entries: list[dict[str, Any]] = [{"claim_id": "authority.replace"}]
    base, _, _ = D._severity(
        _contract_facts(registry_owner=owner),
        None,
        claim_id="authority.replace",
        entries=entries,
        destination=D._UNDETERMINED_DESTINATION,
        openness="restricted",
        deployment_address=C,
    )
    escalated, basis, _ = D._severity(
        _contract_facts(registry_owner=owner, solmate_mutators={"setUserRole(address,uint8,bool)"}),
        None,
        claim_id="authority.replace",
        entries=entries,
        destination=D._UNDETERMINED_DESTINATION,
        openness="restricted",
        deployment_address=C,
    )
    assert base.value == 0.75
    assert escalated.value == 1.0
    assert "registry_owner_self_grant_escalation" in basis


def test_f6_selectors_are_what_the_facts_are_built_from():
    class _Fn:
        def __init__(self, name, selector):
            self.function_name = name
            self.selector = selector

    homonym = _Fn("setUserRole", "0xdeadbeef")
    canonical = _Fn("whateverName", "0x67aff484")
    assert D._lower(homonym.selector) not in D._SOLMATE_MUTATOR_SELECTORS
    assert D._lower(canonical.selector) in D._SOLMATE_MUTATOR_SELECTORS


def test_b5_the_self_gated_delay_credit_is_retired():
    """ "Every resolved principal is the contract" is a lower bound, not closure.

    The enumeration it reads is documented as a proven LOWER BOUND on the caller
    set, so "no other caller resolved" cannot license driving a capability-class
    base to exactly zero. The observation is published; the severity does not
    move on it.
    """
    entries: list[dict[str, Any]] = [{"claim_id": "timelock.set_delay"}]
    self_gated, basis, notes = D._severity(
        _contract_facts(),
        None,
        claim_id="timelock.set_delay",
        entries=entries,
        destination=D._UNDETERMINED_DESTINATION,
        openness="restricted",
        deployment_address=C,
        self_gated=True,
    )
    assert self_gated.value == 0.3
    assert "delay_gate_self_gated_lower_bound" in notes
    assert "delay_change_path_self_gated" not in basis


def test_f6_the_delay_gate_observation_names_which_arm_it_took():
    entries: list[dict[str, Any]] = [{"claim_id": "timelock.set_delay"}]
    ungated, _, notes = D._severity(
        _contract_facts(),
        None,
        claim_id="timelock.set_delay",
        entries=entries,
        destination=D._UNDETERMINED_DESTINATION,
        openness="restricted",
        deployment_address=C,
        self_gated=False,
    )
    gated, basis, _ = D._severity(
        _contract_facts(),
        None,
        claim_id="timelock.set_delay",
        entries=entries,
        destination=D._UNDETERMINED_DESTINATION,
        openness="restricted",
        deployment_address=C,
        self_gated=True,
    )
    assert ungated.value == 0.3
    assert "delay_change_gate_not_self_gated" in notes
    assert gated.value == 0.3
    assert "capability_class_base" in basis


def test_g3_contradictory_destination_witnesses_fail_closed():
    for claim in ("delegatecall.execute", "exec.arbitrary"):
        contradiction = D._exec_destination(
            claim,
            {
                "destination": {"target_kind": "self"},
                "destination_constraint": {"state": "unconstrained_proven", "binding": "destination_operand"},
            },
        )
        assert contradiction.severity is None
        assert not contradiction.tri.is_determined
        assert "destination_witnesses_contradict" in contradiction.notes


def test_g3_destination_operand_does_not_corroborate_self_ness():
    weak = D._exec_destination(
        "delegatecall.execute",
        {"destination": {"target_kind": "self"}, "destination_constraint": {"binding": "destination_operand"}},
    )
    literal = D._exec_destination(
        "delegatecall.execute",
        {"destination": {"target_kind": "self"}, "destination_constraint": {"binding": "literal_self"}},
    )
    assert weak.notes == ()
    assert "destination_self_corroborated_by_literal" in literal.notes


def test_g3_a_priced_destination_with_a_withheld_severity_charges_nothing_and_says_so(fold):
    """A proven destination is not a proven price.

    The row's payee is proven caller-relative and the entity it reaches is
    priced — everything a charge needs except the one witness that says what the
    payout is bounded by. It must land nowhere in the ledger, and the refusal
    must be legible: an excluded row's notes reach no finding, so the warning
    channel is the only surface that can carry the reason.
    """
    signal = flow_sig(
        function_name="unwrap",
        authority_openness="open",
        destination=Tri.proven(DESTINATION_STATE_UNCONSTRAINED_PROVEN, "caller_arbitrary"),
        witness_notes=(
            "destination_msg_sender_with_open_caller_gate",
            "flow_severity_withheld_pending_amount_witness",
        ),
        gates=magnitude(1_000_000.0),
        **reaches(KEY_C),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))

    assert signal.destination.state == DESTINATION_STATE_UNCONSTRAINED_PROVEN
    assert signal.severity.state == SEVERITY_STATE_NOT_DETERMINED
    assert not signal.enters_grade
    assert document.findings == []
    withheld = [w for w in document.warnings if w["kind"] == "flow_severity_withheld_pending_amount_witness"]
    assert [(w["function"], w["capability"]) for w in withheld] == [("unwrap", "flow.out")]


def test_d1_the_published_principal_is_the_one_that_set_the_weakness(fold):
    """The named gate must be the argmax, not whichever row was folded last."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE), PrincipalRef(2, "ethereum", SAFE2)),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={
            1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3),  # supermajority, 0.2
            2: facts(2, SAFE2, "safe", owners=("0x" + "9" * 40,), threshold=1),  # single signer, 0.85
        },
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    top = document.findings[0]
    assert top["weakness"] == WEAKNESS_SAFE_SINGLE_SIGNER
    assert SAFE2 in top["principal"]
    assert "1/1" in str(top["weakest_gate"])


def test_d5_the_document_publishes_its_unit_evidence(fold):
    shared = ("0x" + "1" * 40, "0x" + "2" * 40)
    signals = [
        sig(
            function_name=f"upgradeTo{index}",
            deployment_address=address,
            contract_id=index + 1,
            selector=f"0x0000000{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", safe),),
            **proven(1.0),
            **reaches(entity_key("ethereum", address)),
        )
        for index, (safe, address) in enumerate(((SAFE, C), (SAFE2, VAULT)))
    ]
    document = fold(
        signals,
        principals={
            1: facts(1, SAFE, "safe", owners=shared, threshold=1),
            2: facts(2, SAFE2, "safe", owners=shared, threshold=1),
        },
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    units = document.provenance["principal_units"]["members"]
    merged = document.findings[0]["principal_unit"]
    assert set(units[merged]) == {entity_key("ethereum", SAFE), entity_key("ethereum", SAFE2)}
    assert set(document.findings[0]["unit_members"]) == set(units[merged])
    overlaps = document.provenance["safe_keyset_overlaps"]
    assert overlaps and overlaps[0]["merged"] is True
    # No fabricated sentinel threshold reaches a published structure.
    assert "99" not in str(overlaps)


def test_d5_an_unread_threshold_cannot_merge_two_safes(fold):
    shared = ("0x" + "1" * 40, "0x" + "2" * 40)
    signals = [
        sig(
            function_name=f"upgradeTo{index}",
            deployment_address=address,
            contract_id=index + 1,
            selector=f"0x0000000{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", safe),),
            **proven(1.0),
            **reaches(entity_key("ethereum", address)),
        )
        for index, (safe, address) in enumerate(((SAFE, C), (SAFE2, VAULT)))
    ]
    document = fold(
        signals,
        principals={
            1: facts(1, SAFE, "safe", owners=shared, threshold=1),
            2: facts(2, SAFE2, "safe", owners=shared),  # threshold never read
        },
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    assert len({f["principal_unit"] for f in document.findings}) == 2
    assert document.provenance["safe_keyset_overlaps"][0]["merged"] is False


def test_d4_a_proven_no_reach_is_published_as_an_earned_negative(fold):
    signal = flow_sig(
        function_name="drain",
        value_state="proven_no_reach",
        value_basis="observed_reach_value_usd=0(proven)",
        **proven(0.9, ("caller_arbitrary_proven",)),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    assert [row["state"] for row in document.earned_negatives] == ["proven_no_reach"]


def test_f5_confidence_does_not_rise_when_analysis_is_lost(fold):
    answered = sig(
        function_name="upgradeTo",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=bounded_by_sheet(1_000_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    unanswered = [
        sig(
            claim_id="roles.grant",
            function_name=f"grantRole{index}",
            deployment_address="0x" + str(index) * 40,
            contract_id=10 + index,
            selector=f"0x0000000{index}",
            **proven(0.55),
            **reaches(entity_key("ethereum", "0x" + str(index) * 40)),
        )
        for index in (5, 6, 7)
    ]
    principals = {1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3)}
    plane = value_plane({KEY_C: {"usdc": 1_000_000_000.0}})

    more = fold([answered, *unanswered], principals=principals, value=plane)
    less = fold([answered], principals=principals, value=plane)
    assert less.confidence_pct is not None and more.confidence_pct is not None
    assert less.confidence_pct <= more.confidence_pct


def test_probe_n_functions_counts_distinct_functions(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE), PrincipalRef(2, "ethereum", SAFE2)),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={
            1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3),
            2: facts(2, SAFE2, "safe", owners=OWNERS, threshold=3),
        },
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    assert all(f["n_functions"] == 1 for f in document.findings)


def test_r1_capability_principal_is_not_a_reach_relation():
    assert "capability_principal" not in P.CONTROL_RELATIONS
    # Not walked, and the exclusion carries a stated reason rather than being a
    # relation the walk happens never to mention.
    assert "capability_principal" in P.UNCONSUMED_REACH_REASONS
    # The rationale the register published before 1.1.0 was refuted: the
    # materialization budget never bites, so it cannot be the reason.
    assert "WITHDRAWN" in P.UNCONSUMED_REACH_REASONS["capability_principal"]


def test_g2_the_destination_free_allow_list_is_disjoint_and_conservative():
    from utils.scoring_status import DESTINATION_BEARING_CLAIMS, DESTINATION_FREE_CLAIMS

    assert not set(DESTINATION_BEARING_CLAIMS) & set(DESTINATION_FREE_CLAIMS)
    for claim in ("value_router", "callee_pointer.rotate", "upgrade.implementation"):
        assert claim not in DESTINATION_FREE_CLAIMS


def test_d3_an_unanswerable_signal_outside_the_perimeter_does_not_move_confidence(fold):
    """The denominator is the value plane plus the closure — never the population.

    Injecting a signal that answers nothing, on an entity the value and control
    planes never mention, must leave the published confidence exactly where it
    was: a perimeter that grew with the analysis would let the figure be moved by
    the act of looking.
    """
    answered = sig(
        function_name="upgradeTo",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    injected = sig(
        claim_id="roles.grant",
        function_name="grantRole",
        deployment_address="0x" + "9" * 40,
        contract_id=99,
        selector="0x99999999",
        **proven(0.55),
        **reaches(entity_key("ethereum", "0x" + "9" * 40)),
    )
    principals = {1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3)}
    plane = value_plane({KEY_C: {"usdc": 1_000_000_000.0}})

    before = fold([answered], principals=principals, value=plane)
    after = fold([answered, injected], principals=principals, value=plane)
    assert after.confidence_pct == before.confidence_pct
    detail_before = before.model_parameters["confidence_detail"]
    detail_after = after.model_parameters["confidence_detail"]
    assert detail_after["perimeter_entities"] == detail_before["perimeter_entities"]
    assert detail_after["perimeter_value_weighted_denominator"] == detail_before["perimeter_value_weighted_denominator"]


def test_g5_an_undecidable_asset_identity_falls_to_the_unpriced_branch(fold):
    """Single-asset pricing is licensed by a decidable token identity, not by a sheet."""
    undecidable = flow_sig(
        function_name="withdrawToken",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"asset_class": Tri.proven("proven", "erc20_only").to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C),
    )
    decidable = flow_sig(
        function_name="withdrawToken",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={
            "asset_class": Tri.proven("proven", "erc20_only").to_json(),
            "asset_identity": Tri.proven("resolved", {"asset_address": "0x" + "7" * 40}).to_json(),
            **bounded_by_sheet(50_000_000.0),
        },
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C),
    )
    plane = value_plane({KEY_C: {"usdc": 50_000_000.0}})

    blocked = fold([undecidable], value=plane).findings[0]
    priced = fold([decidable], value=plane).findings[0]

    assert blocked["value_at_stake_usd"] is None
    assert blocked["undetermined_instances"][0]["why"].startswith("token_identity_not_decidable")
    assert priced["value_at_stake_usd"] == 50_000_000.0
    # And the gap is charged to confidence rather than being free.
    assert fold([undecidable], value=plane).model_parameters["confidence_detail"]["value_priced_pct"] is not None


# --------------------------------------------------------------------------
# Round 2: attacking the fixes
# --------------------------------------------------------------------------


def test_b1_subsumption_never_drops_a_units_exclusive_value(fold):
    """Subsumption removes a row's POINTS, never the unit's reach.

    A vault that only a subsumed row reaches is still value the unit provably
    reaches, and dropping it from the exposure accounting publishes a smaller
    exposure for a unit that got no smaller.
    """
    top = sig(
        function_name="upgradeTo",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(1_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    subsumed = sig(
        claim_id="roles.grant",
        function_name="grantRole",
        deployment_address=VAULT,
        contract_id=2,
        selector="0xfeedface",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(14_757_365.89),
        **proven(0.55),
        **reaches(KEY_V),
    )
    plane = value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 14_757_365.89}})
    document = fold([top, subsumed], principals={1: facts(1, EOA, "eoa")}, value=plane)

    finding = document.findings[0]
    assert finding["capability"] == "upgrade.implementation"
    assert KEY_V in finding["subsumed_exclusive_value_by_entity"]
    assert KEY_V in finding["exposure_entities_charged"]
    # The subsumed row's exclusive vault is charged once, at the unit's finding.
    assert finding["exposure_usd"] > 1_000_000.0
    assert finding["subsumed_capabilities"][0]["value_at_stake_usd"] == 14_757_365.89


def test_b1_an_entity_both_rows_reach_is_still_charged_once(fold):
    signals = [
        sig(
            claim_id=claim,
            function_name=f"fn{index}",
            deployment_address=C,
            contract_id=index + 1,
            selector=f"0x0000000{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            gates=bounded_by_sheet(1_000_000.0),
            **proven(severity),
            **reaches(KEY_C),
        )
        for index, (claim, severity) in enumerate((("upgrade.implementation", 1.0), ("roles.grant", 0.55)))
    ]
    plane = value_plane({KEY_C: {"usdc": 1_000_000.0}})
    document = fold(signals, principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert finding["subsumed_exclusive_value_by_entity"] == {}
    assert finding["exposure_usd"] <= 1_000_000.0


@pytest.mark.parametrize(
    "payload",
    [
        [1, 2, 3],
        ["0xabc"],
        {"function_principal_id": 1},
        [{"address": "0x" + "9" * 40, "function_principal_id": "abc"}],
        [{"address": 7, "function_principal_id": 9}],
    ],
)
def test_b2_a_malformed_list_payload_withholds_its_row_and_not_the_fold(fold, payload):
    """One bad JSONB on one function must not cost the protocol its score."""
    hostile = pause_sig(
        function_name="pause",
        deployment_address=VAULT,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates={"freeze_recovery_principals": Tri.proven("enumerated", payload).to_json()},
        **proven(FREEZE_CAPABILITY_PROVEN, ("freeze_capability_proven",)),
        **reaches(KEY_V),
    )
    healthy = sig(
        function_name="upgradeTo",
        contract_id=9,
        selector="0x3659cfe6",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [hostile, healthy],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    assert [f["capability"] for f in document.findings] == ["upgrade.implementation"]
    assert "gate_input_malformed" in {w["kind"] for w in document.warnings}


def test_b2_a_well_formed_recovery_payload_still_reads(fold):
    document = _pause_document(
        fold,
        facts(1, SAFE, "safe", owners=("0x" + "e" * 40, "0x" + "f" * 40), threshold=2),
        facts(2, SAFE2, "safe", owners=OWNERS, threshold=2),
    )
    assert "gate_input_malformed" not in {w["kind"] for w in document.warnings}
    assert any("keyset_independent" in note for note in document.findings[0]["witness_notes"])


def test_b3_a_proven_public_path_refuses_the_earned_negative(fold):
    """``none_required`` is the opposite pole, and the worse contradiction."""
    earned = Tri.proven("earned", {"empty_reason": "owner_read_zero", "block": 21_000_000})
    signal = sig(
        function_name="upgradeTo",
        authority_openness="open",
        principal_state="none_required",
        gates={"exact_empty_credit": earned.to_json()},
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    assert document.earned_negatives == []
    contradiction = [w for w in document.warnings if w["kind"] == "exact_empty_credit_contradicted_by_principals"]
    assert contradiction and contradiction[0]["principal_state"] == "none_required"
    assert document.findings[0]["principal"].startswith("ANYONE")


def test_b4_unresolved_contracts_lower_confidence(fold):
    """An unpriced, unclosured contract still carries its unanswered weight."""
    vault = sig(
        function_name="upgradeTo",
        deployment_address=VAULT,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=bounded_by_sheet(1_000_000_000.0),
        **proven(1.0),
        **reaches(KEY_V),
    )
    unresolved_addresses = tuple("0x" + str(index) * 40 for index in (5, 6, 7))
    unresolved = [
        sig(
            claim_id="roles.grant",
            function_name=f"grantRole{index}",
            deployment_address=address,
            contract_id=10 + index,
            selector=f"0x0000000{index}",
            **proven(0.55),
            **reaches(entity_key("ethereum", address)),
        )
        for index, address in enumerate(unresolved_addresses)
    ]
    plane = value_plane(
        {KEY_V: {"usdc": 1_000_000_000.0}},
        contracts=tuple(entity_key("ethereum", a) for a in unresolved_addresses),
    )
    principals = {1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)}

    answered_only = fold([vault], principals=principals, value=plane)
    with_unresolved = fold([vault, *unresolved], principals=principals, value=plane)

    assert answered_only.confidence_pct is not None
    assert with_unresolved.confidence_pct is not None
    assert with_unresolved.confidence_pct < 100.0
    # Analysing MORE cannot raise the figure above what the perimeter licenses,
    # and the three unresolved contracts are visible in it either way.
    assert with_unresolved.confidence_pct <= answered_only.confidence_pct
    detail = with_unresolved.model_parameters["confidence_detail"]
    assert detail["perimeter_entities"] == 4
    assert detail["signal_entities_outside_perimeter"] == []


def test_b4_an_unpriced_contract_is_in_its_own_denominator(fold):
    """The A5 shape: three unresolved contracts must MATERIALLY lower the figure."""
    vault = sig(
        function_name="upgradeTo",
        deployment_address=VAULT,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=bounded_by_sheet(1_000_000_000.0),
        **proven(1.0),
        **reaches(KEY_V),
    )
    bare = value_plane({KEY_V: {"usdc": 1_000_000_000.0}})
    wide = value_plane(
        {KEY_V: {"usdc": 1_000_000_000.0}},
        contracts=tuple(entity_key("ethereum", "0x" + str(i) * 40) for i in (5, 6, 7)),
    )
    principals = {1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)}
    narrow_doc = fold([vault], principals=principals, value=bare)
    wide_doc = fold([vault], principals=principals, value=wide)
    narrow = narrow_doc.model_parameters["confidence_detail"]
    wide = wide_doc.model_parameters["confidence_detail"]
    assert wide["perimeter_entities"] > narrow["perimeter_entities"]
    assert wide["reachability_answered_pct"] < narrow["reachability_answered_pct"]
    assert wide["capability_scored_pct"] < narrow["capability_scored_pct"]
    assert wide["pct"] <= narrow["pct"]


def test_s8_a_proven_no_reach_instance_is_not_counted_as_undetermined(fold):
    reaching = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_exact", 500.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_EXACT),
    )
    empty = flow_sig(
        function_name="drain",
        selector="0xabababab",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        value_state="proven_no_reach",
        value_basis="observed_reach_value_usd=0(proven)",
        **proven(0.9, ("caller_arbitrary_proven",)),
    )
    document = fold([reaching, empty], value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    finding = document.findings[0]
    assert finding["undetermined_instances"] == []
    assert len(finding["proven_no_reach_instances"]) == 1
    assert "not_determined" not in finding["value_at_stake_basis"]
    assert "proven_no_reach" in finding["value_at_stake_basis"]


def test_s7_the_destination_free_allow_list_exists_in_the_claims_registry():
    """A renamed claim must not silently become 'destination-free'."""
    from services.static.claims.matchers import discover
    from services.static.claims.registry import registry
    from utils.scoring_status import DESTINATION_FREE_CLAIMS

    discover()
    registry_ids = set(registry())
    unknown = [claim for claim in DESTINATION_FREE_CLAIMS if claim not in registry_ids]
    assert unknown == [], f"DESTINATION_FREE_CLAIMS names claims the registry does not define: {unknown}"


def test_r3_subsumed_value_is_charged_at_the_contributing_rows_fraction(fold):
    """The delayed path's value keeps the delayed path's fraction.

    Keying rows by access path separated an undelayed reach from a delayed one;
    charging the subsumed row's value at the TOP row's fraction re-merges them
    inside the exposure term, at up to the full undelayed rate.
    """
    population = [
        sig(
            claim_id=claim,
            function_name=claim.split(".")[1],
            deployment_address=TIMELOCK,
            contract_id=2,
            selector=selector,
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        )
        for claim, selector in (("timelock.schedule", "0x01d5062a"), ("timelock.execute", "0x134008d3"))
    ]
    population.append(
        sig(
            function_name="upgradeDirect",
            deployment_address=C,
            contract_id=4,
            selector="0x3659cfe6",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
    )
    population.append(
        sig(
            function_name="upgradeViaTimelock",
            deployment_address=VAULT,
            contract_id=3,
            selector="0x3659cfe7",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", TIMELOCK),),
            gates=bounded_by_sheet(100_000_000.0),
            **proven(1.0),
            **reaches(KEY_V),
        )
    )
    document = fold(
        population,
        principals={
            1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2),
            2: facts(2, TIMELOCK, "timelock", delay=172800.0),
        },
        value=value_plane(
            {KEY_C: {"usdc": 10_000_000.0}, KEY_V: {"usdc": 100_000_000.0}},
            contracts=(KEY_C, KEY_V, entity_key("ethereum", TIMELOCK)),
        ),
    )
    top = document.findings[0]
    exclusive = top["subsumed_exclusive_value_by_entity"]
    assert KEY_V in exclusive
    subsumed = top["subsumed_capabilities"][0]
    # The carried fraction is the SUBSUMED row's, not the top row's.
    assert exclusive[KEY_V]["fraction"] == round(subsumed["weakness"] * 1.0, 6)
    assert exclusive[KEY_V]["fraction"] < top["severity_proven"] * top["weakness"]

    honest = top["severity_proven"] * top["weakness"] * top["value_at_stake_usd"] + (
        exclusive[KEY_V]["fraction"] * exclusive[KEY_V]["usd"]
    )
    assert abs(top["exposure_usd"] - honest) < 1.0


def _signal_row(**over: Any):
    """A ``FunctionScoreSignal``-shaped row; only the JSONB columns vary."""

    class _Row:
        job_id = None
        protocol_id = 1
        chain = "ethereum"
        deployment_address = C
        contract_id = 1
        function_id = 1
        selector = "0xdeadbeef"
        function_name = "f"
        claim_id = "upgrade.implementation"
        witness_tier = "standard_exact"
        severity_state = "proven"
        severity_proven = 1.0
        severity_basis = ["capability_class_base"]
        authority_openness = "restricted"
        principal_state = "enumerated"
        principal_refs = [{"function_principal_id": 1, "chain": "ethereum", "address": EOA}]
        value_state = "proven_reach"
        value_bound = "floor"
        value_entity_keys = [KEY_C]
        value_basis = "acting_entity"
        destination_state = "not_determined"
        destination_shape = None
        reach_gate_state = "not_determined"
        gate_inputs = {
            "exact_empty_credit": {"state": "not_determined", "value": None},
            "latch_witness": {"state": "not_determined", "value": None},
            "reach_magnitude_usd": {"state": "not_determined", "value": None},
        }
        citations: list[Any] = []
        witness_notes: list[Any] = []
        effect_verdict_id = None

    row = _Row()
    for key, value in over.items():
        setattr(row, key, value)
    return row


@pytest.mark.parametrize(
    ("column", "over"),
    [
        ("principal_refs", {"principal_refs": [1, 2, 3]}),
        ("principal_refs", {"principal_refs": [{}]}),
        ("principal_refs", {"principal_refs": [{"function_principal_id": "abc", "address": EOA}]}),
        ("witness_notes", {"witness_notes": [{"a": 1}]}),
        ("severity_basis", {"severity_basis": [1, "x"]}),
        ("value_entity_keys", {"value_entity_keys": ["0xabc"]}),
        ("citations", {"citations": ["not-a-dict"]}),
    ],
)
def test_r3_a_malformed_persisted_row_withholds_itself(monkeypatch, fold, column, over):
    """One bad column costs its own row, never the protocol's score."""
    from services.scoring import population as POP

    healthy = _signal_row(selector="0x11111111", function_name="healthy")
    hostile = _signal_row(selector="0x22222222", function_name="hostile", **over)
    monkeypatch.setattr(POP, "current_signal_rows", lambda session, protocol_id: [healthy, hostile])

    # ``current_signal_rows`` is stubbed, so the session is never touched.
    signals, faults = POP.current_signals_with_faults(cast(Any, None), 1)
    assert [s.function_name for s in signals] == ["healthy"]
    assert [f["column"] for f in faults] == [column]

    document = fold(None, principals={1: facts(1, EOA, "eoa")}, value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    assert [f["example_functions"] for f in document.findings] == [["healthy"]]
    malformed = [w for w in document.warnings if w["kind"] == "signal_row_malformed"]
    assert malformed and malformed[0]["column"] == column
    assert document.provenance["population"]["rows_withheld_malformed"] == 1


def test_r3_the_gate_shape_table_is_total_over_the_token_vocabulary():
    assert set(FOLD.GATE_PROVEN_TOKENS) - set(FOLD.GATE_PAYLOAD_SHAPES) == set()


# --------------------------------------------------------------------------
# Confidence perimeter admission rules
# --------------------------------------------------------------------------


def test_perimeter_folds_an_implementation_onto_its_proxy(fold):
    """An impl row is the proxy's entity: admitting both hands the impl a second
    copy of the proxy's value band that no signal could ever answer."""
    signal = sig(
        deployment_address=PROXY,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=magnitude(1_000_000_000.0),
        **proven(1.0),
        **reaches(KEY_PROXY),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane(
            {KEY_PROXY: {"usdc": 1_000_000_000.0}},
            contracts=(KEY_PROXY, KEY_IMPL),
            alias={KEY_IMPL: KEY_PROXY},
        ),
    )
    detail = document.model_parameters["confidence_detail"]
    assert detail["implementation_entities_folded"] == 1
    assert detail["perimeter_entities"] == 1
    assert detail["reachability_answered_pct"] == 100.0
    assert detail["capability_scored_pct"] == 100.0
    assert detail["value_priced_pct"] == 100.0
    assert document.confidence_pct == 100.0


def test_zero_address_is_not_a_perimeter_entity(fold):
    """A renounced-ownership 0x0 in the closure is a burn sentinel, not an
    entity whose capabilities could ever be assessed."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=magnitude(50_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}, contracts=(KEY_C,)),
        closure={KEY_C: {entity_key("ethereum", "0x" + "0" * 40)}},
    )
    detail = document.model_parameters["confidence_detail"]
    assert detail["zero_address_entities_excluded"] == 1
    assert detail["perimeter_entities"] == 1
    assert document.confidence_pct == 100.0


def test_a_proven_codeless_eoa_answers_vacuously(fold):
    """With no code there are no functions: the capability question collapses
    into the closure's reach answer — but only on the earned getCode witness,
    and never for the pricing term."""
    key_eoa = entity_key("ethereum", EOA)
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=magnitude(50_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    kwargs: dict = dict(
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}, contracts=(KEY_C,)),
        closure={key_eoa: {KEY_C}},
    )

    unproven = fold([signal], **kwargs)
    witnessed = fold([signal], **kwargs, eoas={key_eoa})

    unproven_detail = unproven.model_parameters["confidence_detail"]
    assert unproven_detail["proven_codeless_answered"] == 0
    assert unproven_detail["capability_scored_pct"] < 100.0

    detail = witnessed.model_parameters["confidence_detail"]
    assert detail["proven_codeless_answered"] == 1
    assert detail["reachability_answered_pct"] == 100.0
    assert detail["capability_scored_pct"] == 100.0
    # Holding value is a question code-lessness does not answer: the unpriced
    # EOA still charges the pricing term, and the headline stays the minimum.
    assert detail["value_priced_pct"] < 100.0
    assert witnessed.confidence_pct == detail["value_priced_pct"]

    # With the EOA's holdings priced, pricing no longer binds, and the earned
    # witness is exactly what separates a full answer from a charged gap.
    priced_kwargs = dict(
        kwargs,
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}, key_eoa: {"usdc": 1_000.0}}, contracts=(KEY_C,)),
    )
    assert fold([signal], **priced_kwargs).confidence_pct < 100.0
    assert fold([signal], **priced_kwargs, eoas={key_eoa}).confidence_pct == 100.0


# --------------------------------------------------------------------------
# Closure edge scope
# --------------------------------------------------------------------------


def test_role_labels_parse_to_the_roles_they_name():
    """A multi-role label licenses every role it names, and the pair is the scope."""
    scope = P.parse_edge_scope("roles 14,16", "role_principal")
    assert (scope.kind, scope.roles) == (P.SCOPE_ROLES, (14, 16))
    assert scope.is_determined
    assert P.parse_edge_scope("roles 12", "role_principal").roles == (12,)


def test_a_label_restating_its_relation_is_not_determined_not_an_empty_scope():
    """A label that only restates its relation names no role.

    Naming no role is not the same fact as licensing none: an empty scope reads
    as "licenses nothing", and the edge has to survive to be published as the
    shortfall it is.
    """
    scope = P.parse_edge_scope("role principal", "role_principal")
    assert scope.kind == P.SCOPE_NOT_DETERMINED
    assert not scope.is_determined
    assert scope.roles == ()
    # The verbatim label is kept: the shortfall is citable, not silently dropped.
    assert scope.label == "role principal"
    assert P.parse_edge_scope(None).kind == P.SCOPE_NOT_DETERMINED


def test_a_getter_name_is_a_state_var_scope_and_never_a_role():
    """``controller_value`` labels name a state variable.

    Reading one as a role would mint a licence out of a getter name.
    """
    scope = P.parse_edge_scope("roleRegistry", "controller_value")
    assert (scope.kind, scope.state_var, scope.roles) == (P.SCOPE_STATE_VAR, "roleRegistry", ())
    assert P.parse_edge_scope("_roles", "mapping_member").state_var == "_roles"


def test_the_closure_answers_adjacency_from_the_edges_it_carries():
    """Scope rides along with reach; it does not replace it."""
    closure = closure_of({KEY_C: {KEY_V, KEY_PROXY}})
    assert closure.principals() == (KEY_C,)
    assert closure.controlled_by(KEY_C) == tuple(sorted((KEY_V, KEY_PROXY)))
    assert closure.controlled_by(KEY_V) == ()
    assert {e.relation for e in closure.edges_from(KEY_C)} == {"controller_value"}


# --------------------------------------------------------------------------
# Value plane: which observation is current, and what a $0.00 reading proves
# --------------------------------------------------------------------------


class _Row:
    """The columns ``_reduce_observations`` reads off a balance row."""

    def __init__(self, usd, *, block=None, fetched=None, rid=0, raw="1000000"):
        self.usd_value = usd
        self.block_number = block
        self.fetched_at = fetched
        self.id = rid
        self.raw_balance = raw


def _reduce(**buckets):
    return P._reduce_observations({("k", "asset"): {a: rows for a, rows in buckets.items()}})


def test_one_account_read_twice_publishes_the_LATER_read_not_the_larger():
    """MAX across two heights of one account is a high-water mark, not a holding.

    The shape that fired on the real corpus: a proxy's live row and its
    implementation's frozen row are the SAME on-chain account read at two
    heights, folded into one bucket by the alias map. Reducing by MAX republishes
    a balance that had already moved when it was written.
    """
    account = "0x" + "1" * 40
    values, states, reduction = _reduce(
        **{account: [_Row(26_404_230.63, block=25_658_048, rid=1), _Row(14_346_384.46, block=25_691_487, rid=2)]}
    )
    assert values["k"]["asset"] == 14_346_384.46
    assert states["k"]["asset"] == P.ASSET_PRICED
    # The drop is disclosed, not silently absorbed.
    assert reduction["stale_high_water_marks_dropped"] == 1
    assert reduction["stale_high_water_usd_dropped"] == round(26_404_230.63 - 14_346_384.46, 2)
    assert reduction["height_witnessed_accounts"] == 1


def test_two_DISTINCT_accounts_are_two_holdings_and_the_entity_holds_their_sum():
    """The account is the discriminator: same account = one holding, two = two.

    Unexercised on the corpus this shipped against (every competing pair observes
    one address), so it is pinned here rather than left to a future reader to
    infer from the code.
    """
    a, b = "0x" + "1" * 40, "0x" + "2" * 40
    values, _, reduction = _reduce(**{a: [_Row(1000.0, block=10, rid=1)], b: [_Row(400.0, block=10, rid=2)]})
    assert values["k"]["asset"] == 1400.0
    assert reduction["multi_account_buckets"] == 1
    assert reduction.get("unwitnessed_account_buckets", 0) == 0


def test_an_unwitnessed_account_identity_is_never_summed():
    """Summing readings that may be one account twice re-mints the double count.

    Where the identity is missing the reduction falls back to MAX and says so,
    rather than inventing a holding out of two readings of an unknown number of
    accounts.
    """
    values, _, reduction = _reduce(**{"": [_Row(1000.0, rid=1)], "0x" + "2" * 40: [_Row(400.0, rid=2)]})
    assert values["k"]["asset"] == 1000.0
    assert reduction["unwitnessed_account_buckets"] == 1


def test_a_read_height_nobody_recorded_falls_back_to_write_order_and_says_so():
    """ERC-20 rows are never height-pinned, so most orderings are write order.

    A fact about this database, not about the chain — counted so the fiat is
    stated rather than passed off as an as-of-block reading.
    """
    import datetime as _dt

    early = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    late = _dt.datetime(2026, 2, 1, tzinfo=_dt.timezone.utc)
    account = "0x" + "1" * 40
    values, _, reduction = _reduce(**{account: [_Row(900.0, fetched=late, rid=1), _Row(100.0, fetched=early, rid=2)]})
    assert values["k"]["asset"] == 900.0
    assert reduction["write_order_accounts"] == 1
    assert reduction.get("height_witnessed_accounts", 0) == 0


def test_a_rounding_floor_reading_is_not_a_proven_zero():
    """``usd_value`` is a scaled decimal column: a holding below its last digit —
    the eighteenth decimal — stores as zero.

    Publishing that as a determined 0.0 mints a proven-empty balance sheet out of
    a price lookup that answered "below the column's resolution".
    """
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(0.0, rid=1, raw="12345")]})
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_BELOW_RESOLUTION
    assert "asset" not in plane.per_asset.get("k", {})
    assert plane.sheet_state("k") == P.SHEET_BELOW_RESOLUTION
    assert plane.total("k") is None


def test_a_sub_resolution_priced_reading_keeps_its_magnitude_through_the_reduction():
    """Pins the ROUNDING guard, and only it.

    A holding worth $2e-9 is a determined NON-ZERO reading — the price answered
    and the quantity is not zero — and the plane's presentation rounding is six
    decimals. A rounding that ran to completion would replace the measured figure
    with 0.0: a bound tighter than anything witnessed, and (with the asset list
    proven whole) the input from which ``sheet_state``'s magnitude arm would read
    an empty sheet. What is asserted here is that the figure SURVIVES; the state
    arm is asserted separately below, because with the magnitude preserved this
    case cannot tell the two guards apart.
    """
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(2e-9, rid=1, raw="1")]})
    plane.asset_set_proven_complete["k"] = SCANNED
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_PRICED
    assert plane.per_asset["k"]["asset"] == 2e-9
    assert plane.sheet_state("k") != P.SHEET_PROVEN_EMPTY
    assert plane.sheet_state("k") == P.SHEET_PRICED
    assert plane.total("k") == 2e-9
    assert plane.proven_empty_refusal("k") is None  # the completeness conjunct is SATISFIED here


def test_a_priced_reading_whose_magnitude_is_zero_is_still_never_a_proven_empty_sheet():
    """Pins the STATE arm, and only it.

    The magnitude is 0.0 here and the asset list is proven whole, so every input
    the magnitude arm can see says "empty" — the exact shape any future rounding,
    truncation or unit change could hand ``sheet_state``. The reading's STATE
    says a price answered on a non-zero quantity, and that is the witness the
    branch is required to read: publishing ``proven_empty`` from this plane would
    assert "every asset's quantity is proven zero" of a sheet whose quantity was
    proven otherwise. The two guards are independent and each closes the hazard
    on its own; this case is what fails if the state arm is dropped.
    """
    plane = value_plane(
        per_asset={"k": {"asset": 0.0}},
        per_asset_state={"k": {"asset": P.ASSET_PRICED}},
        asset_set_proven_complete={"k": SCANNED},
    )
    assert plane.proven_empty_refusal("k") is None  # nothing refuses the empty; only the state stands in its way
    assert plane.sheet_state("k") != P.SHEET_PROVEN_EMPTY
    assert plane.sheet_state("k") == P.SHEET_PRICED


def test_a_proven_zero_QUANTITY_is_the_only_witness_of_an_empty_sheet():
    """The quantity, not the price, is what proves a sheet empty.

    Zero of an asset is worth zero at any price, so this is the one reading under
    which 0.00 is a number. The arm is unexercised on the shipped corpus — no row
    anywhere carries a zero raw balance — so it is pinned here.
    """
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(0.0, rid=1, raw="0")]})
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_PROVEN_ZERO
    # The quantity is half of it. The other half is the SET those quantities
    # cover: without a scan proving the list whole, zeros over an unestablished
    # list are refused and publish unpriced, never a $0.
    assert plane.sheet_state("k") == P.SHEET_UNPRICED
    assert plane.total("k") is None
    plane.asset_set_proven_complete["k"] = SCANNED
    assert plane.sheet_state("k") == P.SHEET_PROVEN_EMPTY
    assert plane.total("k") == 0.0


def test_the_three_ways_of_having_no_total_stay_apart():
    """not_determined is not one state: dust, unpriced and no rows are three."""
    plane = value_plane(
        per_asset={},
        per_asset_state={
            "dust": {"a": P.ASSET_BELOW_RESOLUTION},
            "unpriced": {"a": P.ASSET_UNPRICED},
        },
    )
    assert plane.sheet_state("dust") == P.SHEET_BELOW_RESOLUTION
    assert plane.sheet_state("unpriced") == P.SHEET_UNPRICED
    assert plane.sheet_state("never-seen") == P.SHEET_NO_ROWS
    assert [plane.total(k) for k in ("dust", "unpriced", "never-seen")] == [None, None, None]


def test_a_positive_row_beside_dust_keeps_its_positive_floor():
    """Dust withholds a number only where it is the ONLY answer."""
    plane = value_plane(
        per_asset={"k": {"good": 1000.0}},
        per_asset_state={"k": {"good": P.ASSET_PRICED, "dust": P.ASSET_BELOW_RESOLUTION}},
    )
    assert plane.sheet_state("k") == P.SHEET_PRICED
    assert plane.total("k") == 1000.0


def test_an_all_dust_sheet_charges_no_finding_a_proven_zero_exposure(fold):
    """The published shape R6 forbids: exposure 0.0 beside a proven reach.

    ``value_at_stake 0.0 / proven_reach / exposure 0.0`` reads as "this capability
    is proven to reach nothing" — an earned negative minted by a price lookup that
    answered below its own resolution.
    """
    dust_key = entity_key("base", VAULT)
    plane = value_plane(
        per_asset={KEY_PROXY: {"token": 5_000_000.0}},
        per_asset_state={
            KEY_PROXY: {"token": P.ASSET_PRICED},
            dust_key: {"dust": P.ASSET_BELOW_RESOLUTION},
        },
        contracts=(KEY_C, dust_key, KEY_PROXY),
    )
    dust = sig(
        chain="base",
        deployment_address=VAULT,
        **proven(1.0),
        **reaches(dust_key),
        authority_openness="open",
    )
    priced = sig(
        deployment_address=PROXY,
        function_name="g",
        gates=bounded_by_sheet(5_000_000.0),
        **proven(1.0),
        **reaches(KEY_PROXY),
        authority_openness="open",
    )
    document = fold([dust, priced], value=plane).document()
    row = next(r for r in document["findings"] if r["principal_unit"].startswith("base::"))
    assert row["value_at_stake_usd"] is None
    assert row["exposure_usd"] is None
    assert row["value_band"] == "not_determined"
    # The priced row beside it still scores, so this is the dust entity's own
    # answer and not a withheld grade standing in for one.
    assert document["grade_exposure"] is not None


# --------------------------------------------------------------------------
# Closure admission: the zero address, and the authority it proves absent
# --------------------------------------------------------------------------


def test_a_closure_publishes_a_zero_count_for_a_rule_that_never_fired():
    """An admission rule reports where it did NOT fire, or it discloses nothing."""
    closure = closure_of({KEY_C: {KEY_V}})
    assert closure.refusal_counts() == {
        P.REFUSAL_MALFORMED_NODE_ID: 0,
        P.REFUSAL_SELF_EDGE: 0,
        P.REFUSAL_ZERO_ANCHOR: 0,
        P.REFUSAL_ZERO_PRINCIPAL: 0,
    }
    assert closure.renounced_counts() == {
        "edges": 0,
        "authority_slots": 0,
        "anchors": 0,
        "authority_slots_by_label": {},
    }


def test_a_refused_edge_and_a_renounced_authority_are_counted_apart():
    """Two different facts about the same row, and only one is evidence.

    "We declined to walk an edge to the burn address" says what this scorer did;
    "this authority is held by nobody" says what the protocol is. Collapsing them
    would lose the earned negative inside a housekeeping count.
    """
    zero = entity_key("ethereum", P.ZERO_ADDRESS)
    closure = P.ControlClosure(
        edges=(),
        refusals=(
            P.RefusedEdge(
                rule=P.REFUSAL_ZERO_PRINCIPAL,
                principal=zero,
                anchor=KEY_V,
                relation="controller_value",
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
                edge_id=1,
            ),
        ),
        renounced=(
            P.RenouncedAuthority(
                anchor=KEY_V,
                relation="controller_value",
                scope=P.parse_edge_scope("owner", "controller_value"),
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
                edge_id=1,
            ),
        ),
    )
    assert closure.refusal_counts()[P.REFUSAL_ZERO_PRINCIPAL] == 1
    assert closure.renounced_counts() == {
        "edges": 1,
        "authority_slots": 1,
        "anchors": 1,
        "authority_slots_by_label": {"owner": 1},
    }
    # The refused edge reaches nothing: it is not in the walked graph at all.
    assert closure.principals() == ()
    assert closure.controlled_by(zero) == ()


def test_a_relation_named_after_a_getter_may_not_suppress_that_getters_label():
    """The relation-restatement branch is gone, and this is why.

    It existed to stop a single-token label equal to its own relation from being
    read as a variable of that name. It decided nothing — DB-wide the only labels
    equal to their relation are the multi-word "role principal" and "safe owner",
    which fail the identifier check on their own — and it carried an inversion:
    the day a relation was named after a real getter, every genuine label of that
    name would have been suppressed silently, with no count anywhere. 100
    ``authority`` labels sit behind that hazard today. A rule that decides
    nothing and can invert is deleted, not documented.
    """
    scope = P.parse_edge_scope("authority", "authority")
    assert (scope.kind, scope.state_var) == (P.SCOPE_STATE_VAR, "authority")
    assert P.parse_edge_scope("controller_value", "controller_value").kind == P.SCOPE_STATE_VAR
    # The case the deleted branch was protecting is now decided structurally, by
    # the relation gate: on a role relation the only positive answer is a role.
    assert P.parse_edge_scope("owner", "controller_value").kind == P.SCOPE_STATE_VAR


def test_a_role_relation_never_fabricates_a_state_variable():
    """On ``role_principal`` the answer is a role set or ``not_determined``.

    The identifier reading applied to a role edge minted ``state_var="roles"``
    out of the literal label ``roles`` — a variable no source declares, on a
    relation that asserts a role holding and not a variable at all. No live edge
    carries that label; the fabrication is pinned here so it cannot return.
    """
    scope = P.parse_edge_scope("roles", "role_principal")
    assert (scope.kind, scope.state_var, scope.roles) == (P.SCOPE_NOT_DETERMINED, None, ())
    assert scope.label == "roles"
    assert P.parse_edge_scope("someGetter", "role_principal").kind == P.SCOPE_NOT_DETERMINED
    # A real role label on the same relation is unaffected.
    assert P.parse_edge_scope("roles 12", "role_principal").roles == (12,)


def test_an_unpriced_reading_superseding_a_priced_one_is_counted():
    """A determined value that disappears must not disappear silently.

    The current reading answers no price where an earlier one did: the honest
    total is not_determined, and the rule that withheld it publishes where it
    fired. Unexercised on the shipped corpus, so it is pinned here.
    """
    import datetime as _dt

    early = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    late = _dt.datetime(2026, 2, 1, tzinfo=_dt.timezone.utc)
    account = "0x" + "1" * 40
    values, states, reduction = _reduce(
        **{account: [_Row(900.0, fetched=early, rid=1), _Row(None, fetched=late, rid=2)]}
    )
    assert states["k"]["asset"] == P.ASSET_UNPRICED
    assert "asset" not in values.get("k", {})
    assert reduction["unpriced_supersession_accounts"] == 1


def test_every_reduction_counter_is_published_even_where_it_never_fired():
    """A rule that reports nothing where it never applied is unreadable.

    An absent counter and a zero counter say different things, and only one of
    them is a fact about the corpus.
    """
    _, _, reduction = _reduce(**{"0x" + "1" * 40: [_Row(1000.0, rid=1)]})
    for counter in (
        "multi_account_buckets",
        "unwitnessed_account_buckets",
        "unpriced_supersession_accounts",
        "write_order_decided_accounts",
        "write_order_disagreeing_accounts",
        "stale_high_water_marks_dropped",
        f"assets_{P.ASSET_PROVEN_ZERO}",
        f"assets_{P.ASSET_BELOW_RESOLUTION}",
    ):
        assert reduction[counter] == 0, counter
    assert reduction["write_order_selected_usd"] == 0.0
    assert reduction["write_order_spread_usd"] == 0.0


def test_the_write_order_fallback_sizes_itself_in_accounts_and_dollars():
    """The disclosure has to answer "how much rests on this?", not just "did it".

    An account whose competing readings AGREE was not decided by the ordering in
    any meaningful sense, and an account with one reading was not ordered at all.
    Only the disagreeing set sizes the fiat.
    """
    import datetime as _dt

    early = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    late = _dt.datetime(2026, 2, 1, tzinfo=_dt.timezone.utc)
    disagreeing = "0x" + "1" * 40
    agreeing = "0x" + "2" * 40
    reduction = P._reduce_observations(
        {
            ("k", "a"): {disagreeing: [_Row(100.0, fetched=early, rid=1), _Row(900.0, fetched=late, rid=2)]},
            ("k", "b"): {agreeing: [_Row(50.0, fetched=early, rid=3), _Row(50.0, fetched=late, rid=4)]},
            ("k", "c"): {agreeing: [_Row(7.0, fetched=late, rid=5)]},
        }
    )[2]
    assert reduction["single_reading_accounts"] == 1
    assert reduction["write_order_decided_accounts"] == 2
    assert reduction["write_order_disagreeing_accounts"] == 1
    # The dollars that rest on the ordering, and the range they were chosen from.
    assert reduction["write_order_selected_usd"] == 900.0
    assert reduction["write_order_spread_usd"] == 800.0


def test_a_renounced_slot_is_counted_as_slots_and_as_the_edges_that_witness_it():
    """One authority slot read four times is one renounced authority.

    ``control_graph_edges`` carries a row per witnessed read, so publishing the
    row count as a slot count multiplies the earned negative by how often the
    resolver looked.
    """
    scope = P.parse_edge_scope("owner", "controller_value")
    closure = P.ControlClosure(
        edges=(),
        renounced=tuple(
            P.RenouncedAuthority(
                anchor=anchor,
                relation="controller_value",
                scope=scope,
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
                edge_id=edge_id,
            )
            for anchor, edge_id in ((KEY_V, 1), (KEY_V, 2), (KEY_V, 3), (KEY_C, 4))
        ),
    )
    assert closure.renounced_counts() == {
        "edges": 4,
        "authority_slots": 2,
        "anchors": 2,
        # One label over two anchors: the slot count is per (anchor, label),
        # and this breakdown is per label, so both anchors' ``owner`` slots
        # land on the one key.
        "authority_slots_by_label": {"owner": 2},
    }


# --------------------------------------------------------------------------
# W2b: per-call magnitude, budget honesty, order disclosure, floor flag
# --------------------------------------------------------------------------


def _exact_flow(magnitude: float, *keys: str) -> FunctionSignal:
    """One openly-callable ``flow.out`` call with one exact magnitude witness."""
    return flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_exact", magnitude).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(*keys, bound=VALUE_BOUND_EXACT),
    )


def test_r4_one_exact_witness_is_a_per_call_bound_not_a_per_key_one(fold):
    """A magnitude proven for one call, charged once per reached key, is N x real.

    ``min(held, magnitude)`` per key bounds each key by the witness and then sums
    them, so two keys published twice the one number the witness proved. The
    published sum may never exceed the witness the call carries.
    """
    document = fold(
        [_exact_flow(100.0, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert sum(finding["value_by_entity"].values()) <= 100.0
    # The key left with no room is not_determined: an exhausted budget is not a
    # measurement that the entity holds nothing.
    assert 0.0 not in finding["value_by_entity"].values()
    assert any(row["entity"] == KEY_V for row in finding["undetermined_instances"])
    cap = finding["witnessed_magnitude_caps"][0]
    assert (cap["witnessed_usd"], cap["uncapped_sum_usd"], cap["published_sum_usd"]) == (100.0, 200.0, 100.0)
    assert cap["entities_left_not_determined"] == [KEY_V]
    # The exposure the grade charges is bounded by the same one witness.
    assert finding["exposure_usd"] <= 100.0


def test_r4_a_capped_split_between_keys_is_published_as_order_determined(fold):
    """The cap has to fall somewhere, and where it falls is not evidence."""
    document = fold(
        [_exact_flow(100.0, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 60.0}, KEY_V: {"usdc": 60.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert finding["value_by_entity"] == {KEY_C: 60.0, KEY_V: 40.0}
    cap = finding["witnessed_magnitude_caps"][0]
    assert cap["uncapped_sum_usd"] == 120.0
    assert "not by evidence" in cap["reading"]


def test_r4_a_sub_cent_residual_is_not_a_published_zero(fold):
    """A share that rounds to $0.00 IS a published zero, whatever it was.

    Testing the residual against exact zero let a $0.004 remainder through, and
    every published dollar is rounded to the cent — so the entity reached a
    consumer at $0.00 with a proven-looking figure behind it.
    """
    document = fold(
        [_exact_flow(100.004, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 100.0}, KEY_V: {"usdc": 100.0}}),
    )
    finding = document.findings[0]
    assert finding["value_by_entity"] == {KEY_C: 100.0}
    assert finding["value_at_stake_usd"] == 100.0
    cap = finding["witnessed_magnitude_caps"][0]
    assert cap["entities_left_not_determined"] == [KEY_V]
    assert any(
        row["entity"] == KEY_V and "consumed_by_earlier_keys" in row["why"] for row in finding["undetermined_instances"]
    )


def test_r4_reach_membership_survives_a_magnitude_the_fold_refuses(fold):
    """Reach is membership; the dollars are a separate question with its own answer.

    Reading ``reach_entities`` off the value map deleted a proven membership
    whenever its magnitude was undetermined — so refusing to publish an unproven
    number would have silently emptied the reach sets it is meant to preserve.
    """
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 100.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, KEY_V, bound=VALUE_BOUND_FLOOR),
    )
    document = fold(
        [signal],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    # No magnitude survived the refusal...
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    # ...and the membership did.
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])


def test_r4_a_floor_magnitude_over_two_keys_has_no_apportionment_witness(fold):
    """A floor proves how much moves, never how it divides between holders.

    Charging the floor once per key multiplies it; splitting it between them
    invents a share nobody witnessed. Both are refused, so the call's magnitude
    is not_determined until an apportionment witness exists.
    """
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 100.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, KEY_V, bound=VALUE_BOUND_FLOOR),
    )
    document = fold(
        [signal],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_state"] == "not_determined"
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    assert {row["entity"] for row in finding["undetermined_instances"]} == {KEY_C, KEY_V}
    cap = finding["witnessed_magnitude_caps"][0]
    assert (cap["witness_state"], cap["published_sum_usd"]) == ("proven_floor", None)


def test_r4_one_key_keeps_its_floor_witness_exactly(fold):
    """The N=1 case carries no ambiguity and must not be touched by the rule."""
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 100.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_FLOOR),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert finding["value_by_entity"] == {KEY_C: 100.0}
    assert finding["witnessed_magnitude_caps"] == []


def test_r4_a_floor_magnitude_is_bounded_by_the_entity_it_is_charged_against(fold):
    """A floor witness is not licence to publish more than the entity holds.

    The exact branch has always taken ``min(sheet, witness)``; the floor branch
    returned the witness untouched, so a $28M floor charged against a $1k sheet
    published $28M — the balance-sheet substitution inverted, with the word
    "floor" hiding which direction the error runs in.
    """
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 28_000_000.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_FLOOR),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000.0}}))
    finding = document.findings[0]
    assert finding["value_by_entity"] == {KEY_C: 1_000.0}
    assert finding["value_at_stake_usd"] == 1_000.0
    # Nothing was left unbounded: the sheet did the bounding.
    assert finding["unbounded_floor_magnitudes"] == []


def test_r4_a_floor_against_an_undetermined_sheet_is_disclosed_not_absorbed(fold):
    """No sheet means nothing to bound the floor with, and that is a fact.

    The floor still stands — it is a witness — but it stands ALONE, and a reader
    must be able to tell a figure two witnesses agreed on from one the entity's
    own books never answered.
    """
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 28_000_000.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_FLOOR),
    )
    document = fold([signal], value=value_plane(contracts=(KEY_C,)))
    finding = document.findings[0]
    assert finding["value_by_entity"] == {KEY_C: 28_000_000.0}
    disclosed = finding["unbounded_floor_magnitudes"]
    assert [row["entity"] for row in disclosed] == [KEY_C]
    assert disclosed[0]["witnessed_floor_usd"] == 28_000_000.0


def test_r7_an_exhausted_exposure_budget_is_not_a_measured_zero(fold):
    """Rows that spent an entity's budget leave the next one nothing to measure.

    ``priced_entities`` counted the entity before the budget test, so a row whose
    every entity was already claimed landed in the priced branch with ``mine ==
    0.0`` and published ``exposure_usd: 0.0`` beside a list of charged entities —
    a measured zero out of an accounting that never ran.
    """
    signals = [
        sig(
            claim_id="upgrade.implementation",
            function_name=f"upgradeTo{index}",
            contract_id=index + 1,
            selector=f"0x0000002{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", address),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
        for index, address in enumerate((EOA, SAFE, TIMELOCK))
    ]
    document = fold(
        signals,
        principals={
            1: facts(1, EOA, "eoa"),
            2: facts(2, SAFE, "eoa"),
            3: facts(3, TIMELOCK, "eoa"),
        },
        value=value_plane({KEY_C: {"usdc": 10_000_000.0}}),
    )
    starved = [f for f in document.findings if f["exposure_usd"] is None]
    assert starved, "the third row must find no budget left"
    finding = starved[0]
    assert finding["exposure_entities_charged"] == [KEY_C]
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if g["principal_unit"] == finding["principal_unit"] and g["capability"] == finding["capability"]
    )
    exhausted = gap["budget_exhausted_entities"]
    assert [row["entity"] for row in exhausted] == [KEY_C]
    # The rows that took the budget are NAMED, so the null is attributable.
    claimants = {row["principal_unit"] for row in exhausted[0]["claimed_by"]}
    assert claimants and finding["principal_unit"] not in claimants
    assert round(sum(row["fraction_taken"] for row in exhausted[0]["claimed_by"]), 6) == 1.0
    assert gap["budget_partially_exhausted_entities"] == []


def test_r7_a_partly_charged_row_says_its_figure_is_marginal(fold):
    """A row charged at less than its own fraction publishes an understatement.

    The second row wants its full fraction of the vault and gets whatever the
    first left. The figure is still published — it is real — but reading it as
    this row's exposure to that entity is reading a marginal share as a total,
    and the gap entry is where the difference is named.
    """
    signals = [
        sig(
            claim_id="upgrade.implementation",
            function_name=f"upgradeTo{index}",
            contract_id=index + 1,
            selector=f"0x0000004{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", address),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
        for index, address in enumerate((EOA, SAFE))
    ]
    document = fold(
        signals,
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 10_000_000.0}}),
    )
    later = document.findings[1]
    assert later["exposure_usd"] is not None and later["exposure_usd"] > 0
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if g["principal_unit"] == later["principal_unit"] and g["capability"] == later["capability"]
    )
    trimmed = gap["budget_partially_exhausted_entities"]
    assert [row["entity"] for row in trimmed] == [KEY_C]
    assert trimmed[0]["fraction_taken"] < trimmed[0]["fraction_wanted"]
    assert trimmed[0]["claimed_by"][0]["principal_unit"] == document.findings[0]["principal_unit"]
    # The reading may not describe a published figure as an unmeasured one.
    assert "MARGINAL" in gap["reading"]
    assert "where the exposure is null" not in gap["reading"]


def test_r8_rows_that_tie_publish_that_the_order_decided_the_split(fold):
    """Equal points and capability leave the address string holding the money.

    The tie is broken by ``principal_unit``, and that order is spent on the
    exposure budget: the first row takes the shared entity's fraction and the
    second gets the remainder. The order stays deterministic; what it decided is
    published rather than read as an attribution.
    """
    signals = [
        sig(
            claim_id="upgrade.implementation",
            function_name=f"upgradeTo{index}",
            contract_id=index + 1,
            selector=f"0x0000003{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", address),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
        for index, address in enumerate((EOA, TIMELOCK))
    ]
    document = fold(
        signals,
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, TIMELOCK, "eoa")},
        value=value_plane({KEY_C: {"usdc": 10_000_000.0}}),
    )
    first, second = document.findings[0], document.findings[1]
    assert first["raw_points"] == second["raw_points"]
    assert first["exposure_order_tie"]["tied_with"] == [second["principal_unit"]]
    assert second["exposure_order_tie"]["tied_with"] == [first["principal_unit"]]
    assert first["exposure_order_tie"]["shared_entities"] == [KEY_C]
    assert first["exposure_order_tie"]["position_in_tie"] == 0
    assert "not by evidence" in first["exposure_order_tie"]["reading"]
    # The disclosure is about the arbitrariness, not a reason to reorder.
    assert first["exposure_usd"] > second["exposure_usd"]


def test_s5_an_entity_holding_unpriced_assets_makes_the_value_a_floor(fold):
    """A partly-priced entity is a floor even when every instance answered.

    The flag read whole-instance undetermination only, so a row reaching an
    entity whose priced sheet covers part of what it holds published its total as
    the entity's value rather than as the floor it is.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(5_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane({KEY_C: {"usdc": 5_000_000.0}})
    plane.unpriced_positions = {KEY_C: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 3e19}]}
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert finding["undetermined_instances"] == []
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert finding["value_at_stake_is_floor"] is True
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_band"].startswith(">= ")
    # No contribution came through composition, so the floor is the row's own.
    assert finding["entities_priced_from_a_composed_ceiling"] == []


def test_s5_one_priced_asset_beside_unanswered_ones_is_not_a_priced_entity(fold):
    """The sheet state ranks ``priced`` first; the per-asset map holds the truth.

    An entity with one answered price and a hundred unanswered rows reads as
    ``priced`` at sheet level, so consulting that state published its one
    answered asset as the entity's value. The dominant real shape — balance rows
    whose ``usd_value`` is NULL beside rows that priced — has to make the total a
    floor, and an asset priced at the storage floor is the same shortfall.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        # One call over two keys, so the EXACT witness is a budget across them:
        # set above their sum, it leaves both sheets standing and the subject of
        # this test — the floor flag — is what the assertions read.
        gates=bounded_by_sheet(7_000_000.0),
        **proven(1.0),
        **reaches(KEY_C, KEY_V),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}, KEY_V: {"usdc": 2_000_000.0}},
        per_asset_state={
            KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED},
            KEY_V: {"usdc": P.ASSET_PRICED, "weth": P.ASSET_BELOW_RESOLUTION},
        },
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert plane.sheet_state(KEY_C) == P.SHEET_PRICED
    assert finding["undetermined_instances"] == []
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert finding["value_at_stake_is_floor"] is True
    # A reading at the storage floor is a holding the total does not carry, so
    # it is the same shortfall as one nobody priced.
    assert finding["entities_holding_unpriced_assets"] == sorted([KEY_C, KEY_V])
    assert finding["value_band"].startswith(">= ")
    assert finding["entities_priced_from_a_composed_ceiling"] == []


def test_s5_a_fully_priced_entity_earns_its_hard_band(fold):
    """The flag is an earned negative in the other direction and must stay off.

    Asked of GATE control: the coverage axis is the subject, and the row must
    reach the no-total case to show that ``is_floor`` stays off over an absent
    figure rather than over a small one. Code control over the same sheet now
    publishes a ceiling, which is a different case and is pinned as one.
    """
    signal = sig(
        claim_id="authority.replace",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "weth": P.ASSET_PROVEN_ZERO}},
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert finding["value_at_stake_is_floor"] is False
    assert finding["entities_holding_unpriced_assets"] == []
    assert not finding["value_band"].startswith(">= ")
    # No magnitude witness, so there is no total — and a row with no total
    # claims no direction for it either.
    assert finding["value_at_stake_usd"] is None
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED


def test_b7_two_absent_coverage_signals_do_not_add_up_to_an_exact_total(fold):
    """The fall-through, and why it is not a fourth claim.

    Neither coverage signal fires here: no instance is undetermined and the
    entity's sheet covers everything it holds. That says nothing about the
    DIRECTION of the figures summed — this call's own witness is a proven FLOOR,
    trimmed to the sheet — so publishing "exact" would mint a two-sided claim
    out of the absence of two unrelated signals, which is the B7 defect on a new
    arm. The band carries no qualifier, exactly as it did before this field
    existed, and the direction says what was established: nothing.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 1_000_000.0).to_json()},
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    finding = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert finding["value_at_stake_usd"] == 1_000_000.0
    assert finding["undetermined_instances"] == []
    assert finding["entities_holding_unpriced_assets"] == []
    assert finding["entities_priced_from_a_composed_ceiling"] == []
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert finding["value_at_stake_is_floor"] is False
    assert finding["value_band"] == "$1M-$10M"
    # The fall-through leaves the row's own basis alone: it is not a bound
    # claim, so it is not rewritten into one.
    assert "NEITHER" not in finding["value_at_stake_basis"]
    assert not hasattr(FOLD, "BOUND_DIRECTION_EXACT")


def test_r21_a_reach_key_outside_the_perimeter_is_disclosed(fold):
    """The perimeter disclosure checked deployment keys and never reach keys.

    A reach key absent from the perimeter is value charged into a finding by an
    entity whose unanswered weight is in no denominator — the exact thing the
    disclosure exists to name.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C, KEY_V),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}, contracts=(KEY_C,)),
    )
    detail = document.document()["model_parameters"]["confidence_detail"]
    assert detail["signal_entities_outside_perimeter"] == [KEY_V]


# --------------------------------------------------------------------------
# Merged-unit weakness, the burn sentinel, and confidence completeness (W2c)
# --------------------------------------------------------------------------

MERGE_SHARED = tuple("0x" + c * 40 for c in "1234")
SAFE_MINORITY = "0x" + "e" * 40
SAFE_MAJORITY = "0x" + "d" * 40
KEY_ZERO = entity_key("ethereum", "0x" + "0" * 40)
OUTSIDER = "0x" + "8" * 40
KEY_OUTSIDER = entity_key("ethereum", OUTSIDER)


def _merged_unit_signals(claim: str = "upgrade.implementation"):
    """Two upgrade witnesses on two entities, one per member of a merged Safe unit."""
    return [
        sig(
            function_name=f"upgradeTo{index}",
            deployment_address=address,
            contract_id=index + 1,
            selector=f"0x0000000{index}",
            claim_id=claim,
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", safe),),
            gates=bounded_by_sheet(magnitude_usd),
            **proven(1.0),
            **reaches(entity_key("ethereum", address)),
        )
        for index, (safe, address, magnitude_usd) in enumerate(
            ((SAFE_MINORITY, C, 1_000_000.0), (SAFE_MAJORITY, VAULT, 5_000_000.0))
        )
    ]


def _merged_unit_principals(strong_threshold: int = 4):
    return {
        1: facts(
            1,
            SAFE_MINORITY,
            "safe",
            owners=MERGE_SHARED + tuple("0x" + c * 40 for c in "567"),
            threshold=3,
        ),
        2: facts(
            2,
            SAFE_MAJORITY,
            "safe",
            owners=MERGE_SHARED + tuple("0x" + c * 40 for c in "9abc"),
            threshold=strong_threshold,
        ),
    }


def test_r9_a_merged_units_weakness_is_per_reached_entity(fold):
    """Value only the 4/8 member reaches is not priced at the 3/7 member's rung.

    ``_row_for`` keeps the max weakness over the unit's members while the row
    folds the UNION of their reach. inv. 5's weakest path is the weakest path TO
    THAT ENTITY, and the published union — which no single member reaches — is
    priced at the coalition able to act as every contributing member.
    """
    document = fold(
        _merged_unit_signals(),
        principals=_merged_unit_principals(),
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 5_000_000.0}}),
    )
    assert document.provenance["safe_keyset_overlaps"][0]["merged"] is True
    assert document.provenance["safe_keyset_overlaps"][0]["min_coalition_to_act_as_both"] == 4
    finding = document.findings[0]
    assert finding["weakness_by_entity"] == {KEY_C: WEAKNESS_SAFE_MINORITY, KEY_V: WEAKNESS_SAFE_MAJORITY}
    # The union is priced at the HARDEST rung among the contributing members —
    # no union is charged at a rung some contributing member never has to clear —
    # and the published principal is the member that sets that rung.
    assert finding["weakness"] == WEAKNESS_SAFE_MAJORITY
    assert finding["weakest_gate"] == "Safe 4/8"
    assert SAFE_MAJORITY in finding["principal"]
    # Exposure charges each entity at ITS rung, not the unit's weakest member.
    assert finding["exposure_usd"] == pytest.approx(
        WEAKNESS_SAFE_MINORITY * 1_000_000.0 + WEAKNESS_SAFE_MAJORITY * 5_000_000.0
    )


def test_r9_members_at_one_rung_leave_the_row_untouched(fold):
    """The re-attribution fires on a DISAGREEMENT, never as a blanket rewrite."""
    document = fold(
        _merged_unit_signals(),
        # Both members 4/8-equivalent: 4/8 and 3/7 disagree, 4/8 and 4/8 do not.
        principals={
            1: facts(1, SAFE_MINORITY, "safe", owners=MERGE_SHARED + tuple("0x" + c * 40 for c in "567"), threshold=4),
            2: facts(2, SAFE_MAJORITY, "safe", owners=MERGE_SHARED + tuple("0x" + c * 40 for c in "9abc"), threshold=4),
        },
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 5_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["weakness_by_entity"] == {}
    assert finding["weakness"] == WEAKNESS_SAFE_MAJORITY
    assert finding["exposure_usd"] == pytest.approx(WEAKNESS_SAFE_MAJORITY * 6_000_000.0)


def test_r10_the_burn_sentinel_is_never_charged_a_sheet(fold):
    """A witness that names ``0x0`` has proved no reach, and routes none.

    Ownership renounced to the zero address makes it the single largest fan-out
    in the graph; a repoint witness naming it would otherwise hand one finding
    everything the sentinel "controls". The perimeter refuses it as an entity and
    the fold refuses it as a reach key, so nothing behind it is reachable.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(1_000.0),
        **proven(1.0),
        **reaches(KEY_C, KEY_ZERO),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        # The sentinel as a live control hub: refusing it must also refuse
        # everything only it reaches.
        closure={KEY_ZERO: {KEY_V}},
        value=value_plane(
            {
                KEY_C: {"usdc": 1_000.0},
                KEY_ZERO: {"usdc": 4_000_000_000.0},
                KEY_V: {"usdc": 900_000_000.0},
            }
        ),
    )
    finding = document.findings[0]
    assert finding["reach_entities"] == [KEY_C]
    assert KEY_ZERO not in finding["value_by_entity"] and KEY_V not in finding["value_by_entity"]
    assert finding["value_at_stake_usd"] == 1_000.0
    assert "zero_address_reach_key_refused" in finding["witness_notes"]
    detail = document.model_parameters["confidence_detail"]
    assert detail["zero_address_entities_excluded"] >= 1
    assert not any(key.endswith("::" + "0x" + "0" * 40) for key in detail["signal_entities_outside_perimeter"])


def _magnitude_document(fold, *, witnessed: bool):
    """One reach, with and without a magnitude witness on it.

    GATE control, which is the class whose magnitude question only a witness can
    answer: the unwitnessed document has to publish a genuinely unanswered term,
    and code control over a priced node is answered by its own sheet ceiling.
    """
    gates = (
        {"reach_magnitude_usd": Tri.proven("proven_exact", 250_000.0).to_json()}
        if witnessed
        else {"reach_magnitude_usd": Tri.not_determined().to_json()}
    )
    signal = sig(
        claim_id="authority.replace",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=gates,
        **proven(1.0),
        **reaches(KEY_C),
    )
    return fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    )


def test_r11_a_proven_reach_with_no_magnitude_witness_is_unanswered(fold):
    """The confidence axis grows the term the unknown magnitude belongs in.

    Without it a gate-control reach counts as fully answered, fully scored and
    priced, so "we could not prove how much this moves" had nowhere to land but
    the grade.
    """
    unwitnessed_doc = _magnitude_document(fold, witnessed=False)
    witnessed_doc = _magnitude_document(fold, witnessed=True)
    unwitnessed = unwitnessed_doc.model_parameters["confidence_detail"]
    witnessed = witnessed_doc.model_parameters["confidence_detail"]
    assert unwitnessed["reach_magnitude_witnessed_pct"] == 0.0
    assert witnessed["reach_magnitude_witnessed_pct"] == 100.0
    assert unwitnessed["reach_magnitude_signals"]["proven_reach_in_denominator"] == 1
    assert unwitnessed["reach_magnitude_signals"]["magnitude_witnessed"] == 0
    # Answering the magnitude may only RAISE the term (inv. 6).
    assert witnessed["reach_magnitude_witnessed_pct"] >= unwitnessed["reach_magnitude_witnessed_pct"]

    # The finding SURVIVES its missing magnitude, at the unpriced band's floor:
    # the reach is proven and only its SIZE is not, which inv. 7's floor rule
    # governs. It is the dollar figure that is not_determined, never the row.
    assert unwitnessed_doc.findings[0]["reach_entities"] == [KEY_C]
    assert unwitnessed_doc.findings[0]["value_band"] == "not_determined"
    assert unwitnessed_doc.findings[0]["value_at_stake_usd"] is None
    assert unwitnessed_doc.findings[0]["raw_points"] > 0

    # And the exposure ratio is WITHHELD rather than published as 100. No
    # finding measured a numerator, so the ratio is a quantity nobody computed —
    # publishing "0% of tracked value is exposed" out of it would be the same
    # unproven-number move one axis over. λ is computed and carried in the
    # withheld block; grade, exposure and confidence stand or fall together
    # (ck_protocol_scores_grade_pairing), so the whole triple is not_determined.
    assert unwitnessed_doc.grade_state == GRADE_STATE_NOT_DETERMINED
    withheld = unwitnessed_doc.provenance["grade_withheld"]
    assert 0.0 < withheld["grade_lambda_computed"] < 100.0
    assert witnessed_doc.grade_state == GRADE_STATE_COMPUTED
    assert witnessed["pct"] > 0.0


def test_r11_every_proven_reach_capability_is_in_the_denominator(fold):
    """No capability buys its way out of "how much does this move?".

    A per-capability exclusion list reads as relief for a reach with no magnitude
    concept, but its only live effect is on an entity carrying BOTH an excluded
    and an admitted signal: dropping the excluded one RAISES the term by
    discarding a real unanswered question. Here one witnessed ``flow.out`` and one
    unwitnessed ``timelock.set_delay`` share an entity — the honest answer is 50%,
    and an exclusion list would publish 100%.
    """
    signals = [
        flow_sig(
            function_name="withdraw",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            gates=magnitude(1_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        ),
        sig(
            function_name="setDelay",
            selector="0x00000001",
            claim_id="timelock.set_delay",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            **proven(1.0),
            **reaches(KEY_C),
        ),
    ]
    detail = fold(
        signals,
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    ).model_parameters["confidence_detail"]
    census = detail["reach_magnitude_signals"]
    assert census["proven_reach_in_denominator"] == 2
    assert census["magnitude_witnessed"] == 1
    assert census["by_capability"]["timelock.set_delay"] == [0, 1]
    # 50, not 100: the unwitnessed half is not excused by its capability name.
    assert detail["reach_magnitude_witnessed_pct"] == 50.0
    assert detail["reach_magnitude_witnessed_of_reaching_pct"] == 50.0
    assert detail["reach_magnitude_vacuous_credit_pct"] == 0.0


def _perimeter_signal():
    return sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(1_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )


def test_r12_consuming_a_relation_may_not_raise_confidence(fold):
    """Monotonicity: declining to walk a relation CHARGES confidence, never frees it.

    The perimeter was seeded from the relations the scorer consumed, so entities
    a declined relation proved are principals of gated functions never entered
    the denominator — and the published figure was HIGHER for walking less.
    """
    discovery = {"capability_principal": {KEY_OUTSIDER, KEY_C}}
    shared = dict(
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
        discovery=discovery,
    )
    declined = fold([_perimeter_signal()], **shared).model_parameters["confidence_detail"]
    consumed = fold(
        [_perimeter_signal()],
        closure={KEY_OUTSIDER: {KEY_C}},
        **shared,
    ).model_parameters["confidence_detail"]
    # The entity the declined relation names is in the denominator EITHER WAY.
    assert KEY_OUTSIDER not in declined["signal_entities_outside_perimeter"]
    assert declined["perimeter_entities"] == consumed["perimeter_entities"]
    assert declined["perimeter_value_weighted_denominator"] == consumed["perimeter_value_weighted_denominator"]
    assert consumed["pct"] <= declined["pct"]
    assert declined["discovery_relation_entities_admitted"]["capability_principal"] == 1


def test_r12_a_declined_relations_entities_lower_confidence(fold):
    """The charge is real: the same analysis over a wider proven graph scores lower."""
    shared = dict(
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    )
    blind = fold([_perimeter_signal()], **shared).model_parameters["confidence_detail"]
    seeing = fold(
        [_perimeter_signal()],
        discovery={"capability_principal": {KEY_OUTSIDER}},
        **shared,
    ).model_parameters["confidence_detail"]
    assert seeing["perimeter_entities"] == blind["perimeter_entities"] + 1
    assert seeing["reachability_answered_pct"] < blind["reachability_answered_pct"]


def test_r17_contradictory_owner_sets_are_disclosed_not_silently_arbitrated(fold):
    """Two ``exact`` owner witnesses for one Safe: the disagreement is published."""
    document = fold(
        [_merged_unit_signals()[0]],
        principals={
            1: facts(1, SAFE_MINORITY, "safe", owners=MERGE_SHARED, threshold=2),
            2: facts(2, SAFE_MINORITY, "safe", owners=MERGE_SHARED + ("0x" + "9" * 40,), threshold=4),
        },
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    )
    contradictions = document.provenance["principal_units"]["owner_set_contradictions"]
    assert [row["safe"] for row in contradictions] == [entity_key("ethereum", SAFE_MINORITY)]
    assert len(contradictions[0]["witnesses"]) == 2
    assert contradictions[0]["adopted_k_of_n"] in ("2/4", "4/5")


def test_r9_a_capped_magnitude_does_not_move_per_member_reach(fold):
    """W2b's per-call cap scales what a member is charged, never what it reaches.

    ``_member_weakness`` re-folds each member's own instances to ask which
    entities that member is proven to reach. That re-fold runs through the same
    ``_row_value`` the cap lives in, so a cap that removed an entity from a
    member's reach would silently drop the member from that entity's rung and
    fall back to the unit-level weakness. Reach is read off witnessed membership
    for exactly this reason, and the invariant is pinned here.
    """
    signals = [
        sig(
            function_name="upgradeA",
            deployment_address=C,
            contract_id=1,
            selector="0x00000001",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE_MINORITY),),
            gates=bounded_by_sheet(1_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        ),
        sig(
            function_name="upgradeB",
            deployment_address=VAULT,
            contract_id=2,
            selector="0x00000002",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", SAFE_MAJORITY),),
            # One call, two keys, and a witness that bounds the CALL: the cap
            # fires and trims the published dollars.
            gates={"reach_magnitude_usd": Tri.proven("proven_exact", 5_000_000.0).to_json()},
            **proven(1.0),
            **reaches(KEY_V, KEY_PROXY),
        ),
    ]
    finding = fold(
        signals,
        principals=_merged_unit_principals(),
        value=value_plane(
            {
                KEY_C: {"usdc": 1_000_000.0},
                KEY_V: {"usdc": 5_000_000.0},
                KEY_PROXY: {"usdc": 3_000_000.0},
            }
        ),
    ).findings[0]

    # The cap really fired: the uncapped sum exceeded the one witnessed number.
    caps = finding["witnessed_magnitude_caps"]
    assert caps and caps[0]["uncapped_sum_usd"] > caps[0]["witnessed_usd"]
    # Membership is untouched by it — every reached entity survives the cap.
    assert set(finding["reach_entities"]) == {KEY_C, KEY_V, KEY_PROXY}
    # And the per-member attribution still resolves: the 4/8 member is found as
    # the holder of both of its capped entities, so the safe-fail never fires and
    # they are priced at ITS rung, not at the unit's weakest member's.
    assert finding["weakness_by_entity"] == {
        KEY_C: WEAKNESS_SAFE_MINORITY,
        KEY_PROXY: WEAKNESS_SAFE_MAJORITY,
        KEY_V: WEAKNESS_SAFE_MAJORITY,
    }
    assert finding["weakness"] == WEAKNESS_SAFE_MAJORITY


def _repoint_facts() -> Any:
    facts_ = D._ContractFacts(contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[])
    facts_.protocol_entities = {KEY_C, KEY_V}
    return facts_


@pytest.mark.parametrize(
    ("named", "tier", "why"),
    [
        (P.ZERO_ADDRESS, "behavioral_observed", "zero_address_is_a_burn_sentinel_not_an_entity"),
        (VAULT, "policy_derived", "witness_tier_policy_derived(a static inference, not a value witness)"),
        (OUTSIDER, "behavioral_observed", "named_entity_is_not_a_contract_of_this_protocol_on_this_chain"),
        # The arm a DENYLIST would have admitted: no tier token at all, which
        # resolves to not_determined — a witness that proved nothing, and the
        # easiest of all to pass a "refuse policy_derived" gate with.
        (VAULT, None, "witness_tier_not_determined(not_determined; no tier token this scorer can vouch for)"),
        (
            VAULT,
            "invented_tier",
            "witness_tier_not_determined(not_determined; no tier token this scorer can vouch for)",
        ),
    ],
)
def test_w3_a_repoint_is_admitted_only_on_a_validated_value_witness(named, tier, why):
    """R2 — a repoint adds a foreign entity to a reach set, and must earn it.

    It did the same job as the backlink licence with none of that function's
    checks: no protocol, no chain, no existence, and no check that the witness
    naming the entity proved anything about value. The burn-sentinel arm in
    particular has never fired on any corpus, which is why it is pinned rather
    than observed.

    The tier test is an ALLOWLIST, and the last two cases are why: a denylist of
    ``policy_derived`` passes every tier nobody classified, and an absent or
    unrecognised token resolves to ``not_determined`` — the weakest witness
    there is, admitted by the gate meant to demand the strongest.
    """
    entry: dict[str, Any] = {"witness": {"callee": named}}
    if tier is not None:
        entry["tier"] = tier
    keys, bases, refused = D._repointed_entities(entry, _repoint_facts())
    assert (keys, bases) == ([], [])
    assert [row["why"] for row in refused] == [why]
    assert refused[0]["basis"] == "witness.callee"

    # The positive control: a value witness naming an entity of this protocol on
    # this chain is admitted, so the refusals above are decisions and not a
    # recogniser that never says yes.
    admitted = D._repointed_entities({"tier": "behavioral_observed", "witness": {"callee": VAULT}}, _repoint_facts())
    assert admitted == ([KEY_V], ["witness.callee"], [])


def test_w3_a_repoint_never_upgrades_an_unscored_capability():
    """The second half of R2: naming a callee is not proving a capability.

    Six ``flow.in`` rows were promoted from ``capability_not_scored`` to
    ``proven_reach`` purely because a witness named an address — an upgrade of
    the reach STATE out of a fact about call structure.
    """
    facts_ = _repoint_facts()
    reach = D._reach_for_claim(
        facts_,
        claim_id="flow.in",
        entries=[{"tier": "behavioral_observed", "witness": {"callee": VAULT}}],
        acting_key=KEY_C,
        gates={},
        citations=[],
    )
    assert reach.state != VALUE_STATE_PROVEN_REACH
    assert reach.basis == "capability_not_scored(not_determined)"


# --------------------------------------------------------------------------
# W3: the gate/code split, condition-bounded reach, and the magnitude rule

# --------------------------------------------------------------------------


SOLVER = "0x" + "4" * 40

KEY_SOLVER = entity_key("ethereum", SOLVER)

INITIATOR_GUARD = "initiator != address(this)"


def _queue_signal(claim: str, **over: Any) -> FunctionSignal:
    """One principal over the queue: the shape of the AtomicQueue finding."""
    return sig(
        claim_id=claim,
        function_name="setAuthority",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.75),
        **reaches(KEY_C),
        **over,
    )


def _var_edge(label, principal=None, anchor=None):
    return P.ControlEdge(
        principal=principal or KEY_C,
        anchor=anchor or KEY_V,
        relation="controller_value",
        scope=P.parse_edge_scope(label, "controller_value"),
        witness=P.EDGE_WITNESS_CONTROL_GRAPH,
    )


def test_w4a_gate_control_will_not_walk_an_edge_whose_scope_names_nothing(fold):
    """The scope bound, and the class split that makes it apply to one side only.

    Holding a gate over A gives its holder A's existing functions; whether one of
    them exercises A's authority over B is a question an edge label that names no
    role and no state variable cannot answer. Controlling A's CODE does not ask
    it — the code exercises whatever the code is authorized to exercise.
    """
    unlabelled = P.ControlClosure(edges=(_role_edge("role principal"),))
    assert not unlabelled.edges[0].scope.is_determined
    conditions = condition_plane()
    grant = conferral_plane().grant_for("ownership.transfer", None)

    gate, gate_hops, licensed, _ = FOLD._closure({KEY_C}, unlabelled, conditions, grant=grant)
    code, code_hops, _, _ = FOLD._closure({KEY_C}, unlabelled, conditions, grant=None)
    assert gate == {KEY_C} and code == {KEY_C, KEY_V}
    assert gate_hops[0]["reason"] == FOLD.HOP_REFUSED_SCOPE
    assert gate_hops[0]["conferral"] == P.CONFERRAL_SCOPE_NOT_DETERMINED
    # Withheld, never dropped: the label is cited verbatim on the published gap.
    assert gate_hops[0]["edge_label"] == "role principal"
    assert licensed == {} and code_hops == []


def test_w4a_a_role_confers_only_where_the_join_names_a_function_there(fold):
    """The role -> selector join, positive and negative on the same edge.

    A ``roles N`` edge is walked where the join names functions role N licenses
    AT THAT DESTINATION, and those names travel with the reach — they are the
    answer to "reach to do what", and what a compositional magnitude is later
    attributed to. Where the join names nothing the hop is not_determined: the
    label said "role 77" and no witness says what role 77 may do there.
    """
    closure = P.ControlClosure(edges=(_role_edge("roles 77"),))
    conditions = condition_plane()

    licensing = conferral_plane(role_functions={(KEY_V, 77): (P.LicensedFunction("0xdeadbeef", "exit"),)})
    seen, hops, licensed, _ = FOLD._closure(
        {KEY_C}, closure, conditions, grant=licensing.grant_for("roles.grant", None)
    )
    assert seen == {KEY_C, KEY_V}
    assert hops == []
    assert licensed == {KEY_V: {P.LicensedFunction("0xdeadbeef", "exit")}}

    # Same edge, same label, no witness of what the role licenses there.
    silent = conferral_plane(role_functions={(KEY_V, 78): (P.LicensedFunction("0xdeadbeef", "exit"),)})
    seen, hops, licensed, _ = FOLD._closure({KEY_C}, closure, conditions, grant=silent.grant_for("roles.grant", None))
    assert seen == {KEY_C}
    assert licensed == {}
    assert hops[0]["reason"] == FOLD.HOP_REFUSED_CONFERRAL
    assert hops[0]["conferral"] == P.CONFERRAL_ROLE_NOT_LICENSED
    # Code control does not ask the question at all.
    assert FOLD._closure({KEY_C}, closure, conditions, grant=None)[0] == {KEY_C, KEY_V}


def test_w4a_a_gate_does_not_confer_a_variable_it_is_not_witnessed_to_rewrite(fold):
    """ownership.transfer confers an ``owner`` hop and not a ``hook`` one.

    The evidence is the capability's own ``state_writes``: the gate seizes an
    authority of some kind, the hop runs on an authority of some kind, and the
    seizure composes down the chain when they are the same kind. Where they
    differ the hop is NOT disproved — it is not_determined, because whether the
    seized gate reaches the other authority depends on a function surface
    nothing witnesses.
    """
    conditions = condition_plane()
    owns = conferral_plane(rewrites=("owner", "_owner")).grant_for("ownership.transfer", None)

    owner_hop = P.ControlClosure(edges=(_var_edge("owner"),))
    assert FOLD._closure({KEY_C}, owner_hop, conditions, grant=owns)[0] == {KEY_C, KEY_V}

    hook_hop = P.ControlClosure(edges=(_var_edge("hook"),))
    seen, hops, _, _ = FOLD._closure({KEY_C}, hook_hop, conditions, grant=owns)
    assert seen == {KEY_C}
    assert hops[0]["reason"] == FOLD.HOP_REFUSED_CONFERRAL
    assert hops[0]["conferral"] == P.CONFERRAL_VARIABLE_NOT_REWRITTEN
    assert hops[0]["capability"] == "ownership.transfer"
    # not_determined, never a proven negative: the hop is published, and code
    # control still walks the same edge.
    assert FOLD._closure({KEY_C}, hook_hop, conditions, grant=None)[0] == {KEY_C, KEY_V}


def test_w4a_a_gate_whose_writes_were_never_extracted_confers_nothing():
    """A coverage gap is not an empty answer and is not a licence.

    A function whose ``state_writes`` never ran rewrites nothing anyone read,
    which is a different fact from a function proven to rewrite nothing. Both
    withhold, and the withheld hop says which one it was.
    """
    conditions = condition_plane()
    plane = P.ConferralPlane()
    grant = plane.grant_for("ownership.transfer", None)
    assert not grant.writes_extracted

    closure = P.ControlClosure(edges=(_var_edge("owner"),))
    seen, hops, _, _ = FOLD._closure({KEY_C}, closure, conditions, grant=grant)
    assert seen == {KEY_C}
    assert hops[0]["conferral"] == P.CONFERRAL_WRITES_NOT_EXTRACTED
    # A role hop asks the join, not state_writes, so it is unaffected by the gap.
    roles = P.ControlClosure(edges=(_role_edge("roles 4"),))
    licensing = P.ConferralPlane(role_functions={(KEY_V, 4): (P.LicensedFunction("0xaaaaaaaa", "pull"),)})
    assert FOLD._closure({KEY_C}, roles, conditions, grant=licensing.grant_for("roles.grant", None))[0] == {
        KEY_C,
        KEY_V,
    }


def test_w4a_conferral_may_only_shrink_a_walk_never_grow_it():
    """The monotone property, over every scope shape in one closure.

    Conferral is a bound and bounds do not add reach. Whatever a gate confers,
    its walk is a subset of the label-presence walk it replaced — which is the
    walk code control still performs, since code control asks no scope question.
    """
    conditions = condition_plane()
    closure = P.ControlClosure(
        edges=(
            _var_edge("owner", anchor=KEY_V),
            _var_edge("hook", anchor=KEY_PROXY),
            _role_edge("roles 3", anchor=KEY_IMPL),
            _role_edge("role principal", anchor=entity_key("ethereum", TIMELOCK)),
        )
    )
    unbounded = FOLD._closure({KEY_C}, closure, conditions, grant=None)[0]
    for rewrites in ((), ("owner",), ("hook",), ("owner", "hook"), ("authority",)):
        for roles in (
            {},
            {(KEY_IMPL, 3): (P.LicensedFunction("0xaaaaaaaa", "pull"),)},
            {(KEY_IMPL, 9): (P.LicensedFunction("0xbbbbbbbb", "push"),)},
        ):
            plane = conferral_plane(rewrites=rewrites, role_functions=roles)
            walked = FOLD._closure({KEY_C}, closure, conditions, grant=plane.grant_for("ownership.transfer", None))[0]
            assert walked <= unbounded, (rewrites, roles)


def test_w3_case3_a_freeze_charges_no_sheet_and_keeps_its_finding(fold):
    """Regression case 3 — pause.set leaves the grade.

    ``pause_effective`` proves the latch takes effect. It proves no FRACTION: how
    much of a sheet a freeze immobilises is a quantity nothing in this pipeline
    measures. Charging the whole sheet for it put three quarters of a billion
    dollars of unwitnessed magnitude into the grade.
    """
    freeze = pause_sig(
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"pause_effective": Tri.proven("proven", True).to_json()},
        **proven(0.05),
        **reaches(KEY_C),
    )
    priced = _perimeter_signal()
    document = fold(
        [freeze, priced],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 745_000_000.0}}),
    )
    rows = [f for f in document.findings] + list(document.provenance["subsumed_rows"])
    frozen = next(r for r in rows if r["capability"] == "pause.set")
    assert frozen["value_at_stake_usd"] is None
    assert frozen["value_band"] == "not_determined"
    assert frozen.get("exposure_usd") is None
    # The finding survives: a freeze capability is still a finding.
    assert frozen["raw_points"] > 0
    assert frozen["reach_entities"] == [KEY_C]
    # And the unknown has a home: the reach-magnitude term counts it unanswered.
    detail = document.model_parameters["confidence_detail"]
    census = detail["reach_magnitude_signals"]["by_capability"]
    assert census["pause.set"] == [0, 1]


def test_w3_case4_a_corrected_backlink_licence_carries_no_magnitude(fold):
    """Regression case 4 — the R3 trap.

    Correcting the backlink join makes a licence that had never once fired admit
    a foreign entity into a row's reach. Landing that correction WITHOUT the
    magnitude bound converts a cite/gate object into a dollar figure — the
    measured shape was one row going from $0.00 to $1,411,758.83 off the
    destination's whole sheet. The licence proves REACHABILITY; it proves no
    magnitude, so it supplies none.
    """
    licensed = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        reach_gate_state="licensed",
        **proven(0.75),
        **reaches(KEY_C, KEY_V),
    )
    document = fold(
        [licensed],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000.0}, KEY_V: {"usdc": 1_411_758.83}}),
    )
    finding = document.findings[0]
    # The licence is REACH: the entity is admitted and published.
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])
    # And it is not a magnitude: the destination's sheet is charged nowhere.
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    assert {row["entity"] for row in finding["undetermined_instances"]} == {KEY_C, KEY_V}


def test_w3_a_reach_key_naming_the_burn_sentinel_is_counted_where_it_is_refused(fold):
    """The fold's own count and gap for a reach key that is the burn sentinel.

    Both are unexercised on every corpus measured, which is exactly why they are
    pinned: a rule nobody has seen fire is one nobody has seen report either.
    """
    signal = sig(
        claim_id="roles.grant",
        function_name="grantRole",
        contract_id=2,
        selector="0x22222222",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.55),
        **reaches(KEY_ZERO),
    )
    priced = _perimeter_signal()
    document = fold(
        [signal, priced],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_ZERO: {"usdc": 4_000_000_000.0}}),
    )
    rows = list(document.findings) + list(document.provenance["subsumed_rows"])
    refused = next(r for r in rows if r["zero_address_reach_keys_refused"])
    assert refused["zero_address_reach_keys_refused"] == 1
    assert any(
        row["why"].startswith("every_reach_key_was_the_zero_address") for row in refused["undetermined_instances"]
    )
    assert "zero_address_reach_key_refused" in refused["witness_notes"]
    assert refused["value_at_stake_usd"] is None


def _witnessed_elsewhere(principal_id: int = 2) -> FunctionSignal:
    """One magnitude-witnessed row, so the document has an exposure to publish.

    grade, exposure and confidence are determined together, so a population in
    which NOTHING carries a magnitude witness withholds all three — correctly,
    since the exposure ratio would have no numerator anyone measured. A test
    asserting on a per-finding exposure needs the document to be scored at all.
    """
    return sig(
        claim_id="upgrade.implementation",
        function_name="upgradeTo",
        deployment_address=PROXY,
        contract_id=9,
        selector="0x11111111",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(principal_id, "ethereum", SAFE),),
        gates=bounded_by_sheet(500.0),
        **proven(1.0),
        **reaches(KEY_PROXY),
    )


def test_w3_case1_a_destination_guard_disproves_the_hop_that_carried_the_money(fold):
    """Regression case 1 — AtomicQueue's blocked principal.

    The EOA owns AtomicQueue, AtomicQueue holds a role on AtomicSolverV3, and the
    solver's ``finishSolve`` — the only function the role licenses it — reverts
    unless the initiator is the solver itself. No authority relation makes the
    queue the solver, so the hop is not something this walk can establish, and
    the solver's balance sheet was never the queue owner's to be charged.

    The finding stays ALIVE at the floor: the capability over the queue is
    proven, and it is the SIZE of what it reaches that is not.
    """
    conditions = condition_plane(
        licensed={(KEY_SOLVER, KEY_C): (("finishSolve", 570, (INITIATOR_GUARD,)),)},
        by_entity={
            KEY_SOLVER: (
                ("finishSolve", 570, (INITIATOR_GUARD,)),
                ("p2pSolve", 571, ()),
            )
        },
    )
    plane = value_plane({KEY_C: {"usdc": 1_000.0}, KEY_SOLVER: {"usdc": 1_505_140.39}, KEY_PROXY: {"usdc": 500.0}})
    shared = dict(
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "eoa")},
        closure={KEY_C: {KEY_SOLVER}},
        value=plane,
    )
    population = [_queue_signal("authority.replace"), _witnessed_elsewhere()]

    def queue_row(document):
        return next(f for f in document.findings if f["principal_unit"] == entity_key("ethereum", EOA))

    blocked = queue_row(fold(population, conditions=conditions, **shared))
    unguarded = queue_row(fold(population, **shared))

    # The control graph is identical; only the destination's own conditions differ.
    assert KEY_SOLVER in unguarded["reach_entities"]
    assert blocked["reach_entities"] == [KEY_C]
    hop = blocked["reach_hops_not_determined"][0]
    assert (hop["caller"], hop["destination"]) == (KEY_C, KEY_SOLVER)
    assert hop["reason"] == FOLD.HOP_REFUSED_CONDITION
    assert hop["disproving_conditions"][0]["conditions"] == [INITIATOR_GUARD]
    # Never a proven negative: the principal enumeration behind the licensed
    # surface is a lower bound, so this is not_determined and says so.
    assert "not_determined" in hop["reason"] or hop["reason"] == FOLD.HOP_REFUSED_CONDITION

    # Not charged the solver's sheet — and not charged the queue's either,
    # because no witness proved how much the capability moves.
    assert blocked["value_at_stake_usd"] is None
    assert blocked["value_by_entity"] == {}
    assert blocked["exposure_usd"] is None
    # Alive at the floor: the row still scores.
    assert blocked["value_band"] == "not_determined"
    assert blocked["raw_points"] > 0


def test_w3_case2_both_sides_of_the_inversion_fall_to_not_determined(fold):
    """Regression case 2 — the inversion, at this stage.

    The principal that provably CAN reach the money was published at $0.00 while
    two that provably cannot were charged $1.5M and $0.7M. Composing a witnessed
    magnitude for the reachable one is a later change; what this stage must
    deliver is that the FAKE attribution is gone — neither side carries a dollar
    figure nobody witnessed, so the document no longer asserts the inversion.
    """
    conditions = condition_plane(
        licensed={(KEY_SOLVER, KEY_C): (("finishSolve", 570, (INITIATOR_GUARD,)),)},
    )
    plane = value_plane({KEY_C: {"usdc": 1_000.0}, KEY_SOLVER: {"usdc": 2_229_837.61}, KEY_PROXY: {"usdc": 500.0}})
    blocked = _queue_signal("authority.replace")
    reaching = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        deployment_address=SOLVER,
        contract_id=2,
        selector="0x7a9e5e4b",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", TIMELOCK),),
        **proven(0.75),
        **reaches(KEY_SOLVER),
    )
    document = fold(
        [blocked, reaching, _witnessed_elsewhere(principal_id=3)],
        principals={
            1: facts(1, EOA, "eoa"),
            2: facts(2, TIMELOCK, "timelock", delay=172800.0),
            3: facts(3, SAFE, "eoa"),
        },
        closure={KEY_C: {KEY_SOLVER}},
        value=plane,
        conditions=conditions,
    )
    by_unit = {f["principal_unit"]: f for f in document.findings}
    unreachable = by_unit[entity_key("ethereum", EOA)]
    reachable = by_unit[entity_key("ethereum", TIMELOCK)]

    # The fake attribution: gone. Neither side publishes an unwitnessed dollar.
    assert unreachable["value_at_stake_usd"] is None
    assert reachable["value_at_stake_usd"] is None
    assert unreachable["exposure_usd"] is None
    assert reachable["exposure_usd"] is None
    # And the membership still tells the honest story: only the timelock's row
    # reaches the entity that holds the money.
    assert KEY_SOLVER not in unreachable["reach_entities"]
    assert KEY_SOLVER in reachable["reach_entities"]


def test_w3_a_shared_implementation_folds_onto_no_proxy(fold):
    """R14: two proxies, one implementation, and no coin toss between them.

    Pinning either proxy charges a row that reached only the OTHER proxy's
    implementation with this one's whole sheet, publishes it as an entity nothing
    reached, and spends its exposure budget. Zero shared implementations exist on
    any corpus measured, so the rule is pinned here rather than observed.
    """
    plane = value_plane({KEY_PROXY: {"usdc": 100_000_000.0}})
    plane.alias_ambiguous = {KEY_IMPL}
    signal = sig(
        deployment_address=PROXY,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(100_000_000.0),
        **proven(1.0),
        **reaches(KEY_IMPL),
    )
    finding = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert finding["value_by_entity"] == {}
    assert finding["value_at_stake_usd"] is None
    gap = finding["undetermined_instances"][0]
    assert gap["entity"] == KEY_IMPL
    assert gap["why"] == "shared_implementation_folds_onto_no_proxy(not_determined)"


def test_w3_an_alias_cycle_fails_loud(fold):
    """R15: ``A -> B`` beside ``B -> A`` is a contradiction, not a fold.

    Resolving it by picking a member would publish a canonical entity chosen by
    iteration order, and orphan the other one's balances behind it.
    """
    with pytest.raises(P.AliasCycleError):
        P._alias_fixed_point({KEY_PROXY: KEY_IMPL, KEY_IMPL: KEY_PROXY})
    # And a chain resolves rather than stopping one hop short.
    third = entity_key("ethereum", "0x" + "d" * 40)
    assert P._alias_fixed_point({third: KEY_IMPL, KEY_IMPL: KEY_PROXY}) == {
        third: KEY_PROXY,
        KEY_IMPL: KEY_PROXY,
    }


def test_w3_a_beacon_is_a_code_control_edge_with_its_own_witness():
    """R16: whoever controls the beacon sets the implementation of every proxy.

    The broadest code-control link there is, and the closure carried no
    representation of it at all. It is named by its own column rather than
    borrowing the admin witness — consumers branch on the witness string, and
    ``relation is None`` is a property both columns share.
    """
    assert P.EDGE_WITNESS_BEACON_COLUMN != P.EDGE_WITNESS_ADMIN_COLUMN
    edge = P.ControlEdge(
        principal=KEY_C,
        anchor=KEY_PROXY,
        relation=None,
        scope=P.EdgeScope(P.SCOPE_NOT_DETERMINED),
        witness=P.EDGE_WITNESS_BEACON_COLUMN,
    )
    closure = P.ControlClosure(edges=(edge,))
    conditions = condition_plane()
    assert FOLD._closure({KEY_C}, closure, conditions, grant=None)[0] == {KEY_C, KEY_PROXY}


# --------------------------------------------------------------------------
# W4a — the disclosure items that ride with the conferral test
# --------------------------------------------------------------------------


def test_w4a_the_citation_cap_shows_evidence_before_prose_and_counts_what_it_hid():
    """The cap is a display bound; the order it evicts in must not be arbitrary.

    A prose ``reading`` restating how to read a field is not something a reader
    can check. Two transcript-bearing citations were evicted by one on a shipped
    row. Evidence first, prose last, and the total says how many were not shown.
    """
    prose = [{"field": "reach_gate_state", "reading": "how to read it", "value": i} for i in range(8)]
    evidence = [{"field": "claims[].witness", "transcript_ptr": "t", "verdict": "proven"}]
    plain = [{"field": "gated_contract_backlink", "value": ["k"]}]
    shown = FOLD._cited(prose[:4] + evidence + prose[4:] + plain)
    assert len(shown) == FOLD.CITATION_CAP
    assert shown[0] is evidence[0]
    assert shown[1] is plain[0]
    # Stable within a tier: the population order still decides among equals.
    assert [c["value"] for c in shown[2:]] == [0, 1, 2, 3, 4, 5]
    assert FOLD._cited(prose) == prose[: FOLD.CITATION_CAP]


def test_w4a_a_walked_hop_says_whether_the_surface_was_read_in_full():
    """ "No guard was found" over a surface read in part is not the same fact.

    The old census collapsed both into walked_on_analysed_conditions, so a hop
    resting on one extracted function out of twenty read as a checked hop.
    """
    fully = P.ConditionPlane()
    fully.by_entity = {KEY_V: (P.DestinationFunction(1, "a", (), True), P.DestinationFunction(2, "b", (), True))}
    assert fully.hop(KEY_C, KEY_V).coverage == P.WALKED_ON_ANALYSED_FULLY

    partly = P.ConditionPlane()
    partly.by_entity = {KEY_V: (P.DestinationFunction(1, "a", (), True), P.DestinationFunction(2, "b", (), False))}
    assert partly.hop(KEY_C, KEY_V).coverage == P.WALKED_ON_ANALYSED_PARTLY

    none = P.ConditionPlane()
    none.by_entity = {KEY_V: (P.DestinationFunction(1, "a", (), False),)}
    assert none.hop(KEY_C, KEY_V).coverage == P.WALKED_ON_UNANALYSED
    assert P.ConditionPlane().hop(KEY_C, KEY_V).coverage == P.WALKED_NO_FUNCTION
    assert set(P.WALKED_COVERAGE) == {
        P.WALKED_ON_ANALYSED_FULLY,
        P.WALKED_ON_ANALYSED_PARTLY,
        P.WALKED_ON_UNANALYSED,
        P.WALKED_NO_FUNCTION,
    }


def test_w4a_the_self_pin_recogniser_only_ever_withholds():
    """Its breadth is safe in exactly one direction, and this is that direction.

    Both comparators and every caller-named parameter are read as a pin, because
    the stored description carries no polarity and the name is the whole
    evidence. Every over-read moves a hop from walked to not_determined; nothing
    here can mint a proven-clear. The whole-word guard keeps ``spender`` out.
    """
    pinned = [
        "require(bool)(msg.sender != address(this))",
        "initiator != address(this)",
        "address(this) == _caller",
        "_sender == address(this)",
    ]
    for text in pinned:
        assert P._caller_self_pins([{"description": text}]) == (text,), text
    for text in ("spender != address(this)", "amount != address(this)", "msg.sender != owner"):
        assert P._caller_self_pins([{"description": text}]) == (), text

    plane = P.ConditionPlane()
    plane.by_entity = {KEY_V: (P.DestinationFunction(1, "solve", ("initiator != address(this)",), True),)}
    hop = plane.hop(KEY_C, KEY_V)
    # The strongest thing a pin can say is not_determined — never a proven no.
    assert hop.state == P.HOP_NOT_DETERMINED
    assert hop.state != "proven_no_reach"


def test_w4a_licensed_functions_are_keyed_on_the_entity_the_reach_set_uses(fold):
    """The join key a consumer joins on, not the raw anchor the walk speaks in.

    ``reach_entities`` is canonical — an implementation folded onto its proxy is
    one entity under two raw keys — while the walk names anchors. Publishing the
    licensed functions under the raw anchor would leave every folded destination
    unjoinable, silently, on the field the composition pass consumes.
    """
    closure = P.ControlClosure(edges=(_role_edge("roles 3", principal=KEY_C, anchor=KEY_IMPL),))
    plane = conferral_plane(role_functions={(KEY_IMPL, 3): (P.LicensedFunction("0xaaaaaaaa", "pull"),)})
    doc = fold(
        [_queue_signal("authority.replace")],
        value=value_plane(per_asset={KEY_PROXY: {"usdc": 100.0}}, alias={KEY_IMPL: KEY_PROXY}),
        closure=closure,
        conferral=plane,
        principals={1: facts(1, EOA, "eoa")},
    )
    row = doc.findings[0]
    licensed = row["reach_licensed_functions"]
    assert KEY_PROXY in row["reach_entities"], "the implementation folds onto its proxy"
    assert set(licensed) <= set(row["reach_entities"]), "every licensed key must be a reach key"
    # Structured at the source: the consumer joins on the selector rather than
    # splitting a string on a space a function name is allowed to contain.
    assert licensed == {KEY_PROXY: [{"selector": "0xaaaaaaaa", "name": "pull"}]}
    assert KEY_IMPL not in licensed


def test_w4a_a_withheld_frontier_hop_sizes_the_subtree_it_hides(fold):
    """One published hop can withhold a whole graph, and did.

    A row losing 22 entities behind 2 published hops named 2 destinations and
    said nothing about the other 20. The withheld population is sized against
    the widest walk this fold performs, and it is a size, never a claim.
    """
    a, b, c = KEY_V, KEY_PROXY, KEY_IMPL
    closure = P.ControlClosure(
        edges=(
            _var_edge("hook", principal=KEY_C, anchor=a),
            _var_edge("owner", principal=a, anchor=b),
            _var_edge("owner", principal=b, anchor=c),
        )
    )
    doc = fold(
        [_queue_signal("ownership.transfer")],
        closure=closure,
        conferral=conferral_plane(rewrites=("owner",)),
        principals={1: facts(1, EOA, "eoa")},
    )
    row = doc.findings[0]
    assert row["reach_entities"] == [KEY_C], "the frontier hop runs on an authority of another kind"
    assert len(row["reach_hops_not_determined"]) == 1, "one hop is published"
    behind = row["reach_withheld_behind_hops"]
    # …and it hides three entities, two of which the hop list never names.
    assert (behind["hops"], behind["entities"]) == (1, 3)
    assert behind["entity_keys"] == sorted([a, b, c])
    assert b not in {hop["destination"] for hop in row["reach_hops_not_determined"]}


def test_w4a_a_dangling_function_reference_recovers_on_deployment_and_selector():
    """A stale foreign key must not read as an extraction that never ran.

    ``function_score_signals.function_id`` is ON DELETE SET NULL and a
    re-analysis deletes and reinserts a contract's functions, so a signal that
    outlives one re-analysis points at nothing — and every state-variable hop it
    gates would degrade to writes-not-extracted, losing reach with a counted but
    causeless withhold. The signal's own (deployment, selector) survives that.
    """
    plane = P.ConferralPlane(
        writes_by_function={7: frozenset({"owner"})},
        writes_by_deployment_selector={(KEY_C, "0xabcdef12"): frozenset({"owner"})},
    )
    scope = P.parse_edge_scope("owner", "controller_value")

    live = plane.grant_for("ownership.transfer", 7, entity=KEY_C, selector="0xabcdef12")
    assert live.writes_extracted and "function 7" in live.basis

    recovered = plane.grant_for("ownership.transfer", None, entity=KEY_C, selector="0xABCDEF12")
    assert recovered.writes_extracted, "the selector is matched case-insensitively"
    assert recovered.confers(scope, KEY_V).conferred
    assert "recovered" in recovered.basis and "does not resolve" in recovered.basis

    # A key the recovery index does not carry stays unextracted rather than
    # guessing — the index only holds keys every function agrees under.
    lost = plane.grant_for("ownership.transfer", None, entity=KEY_V, selector="0xabcdef12")
    assert not lost.writes_extracted
    assert lost.confers(scope, KEY_V).outcome == P.CONFERRAL_WRITES_NOT_EXTRACTED


# --------------------------------------------------------------------------
# W4b — compositional gate-control magnitude (Phase 6)
# --------------------------------------------------------------------------


def test_w4b_a_gate_composes_the_destination_functions_own_witness(fold):
    """Phase 6, whole. The dollars are the DESTINATION's witness, not the sheet.

    Three witnesses and the row publishes all three: the role licenses ``exit``
    at the vault, ``exit`` carries its own fork-proven ``flow.out`` magnitude,
    and a restricted authority-gated function of the seized node is witnessed
    calling that selector on a state variable read on-chain holding the vault.
    """
    document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    composed = row["reach_composed_magnitudes"]
    assert [c["entity"] for c in composed] == [KEY_V]
    assert composed[0]["flow_out_witness"] == {
        "state": "proven_exact",
        "usd": 1_000_000.0,
        "function": "exit",
        "entity": KEY_V,
    }
    step = composed[0]["act_as_chain"][0]
    assert (step["caller"], step["destination"], step["calling_function"]) == (KEY_C, KEY_V, "bulkWithdraw")
    assert step["receiver_observed_via"] == "eth_call" and step["receiver_block"] == 25_657_731
    # A composed call is COUNTED as composed, not as carrying no witness: the
    # census key existed and was never incremented, so the rows that composed
    # published a zero where the count belonged.
    census = row["magnitude_witness_census"]
    assert census["magnitude_composed"] == 1
    assert census["magnitude_not_witnessed"] == 0
    assert (
        census["magnitude_composed"] + census["magnitude_not_witnessed"] + census["magnitude_witnessed"]
        == census["instances"]
    )


def test_w4b_no_composed_magnitude_exceeds_the_destinations_own_bound(fold):
    """The anti-composition regression test.

    The destination's witness is the ceiling and the destination's sheet is the
    other ceiling; the published figure clears neither, whichever is lower.
    """
    for sheet, expected in ((5_000_000.0, 1_000_000.0), (250_000.0, 250_000.0)):
        document = fold(
            _composing_signals(),
            principals=_composing_principals(),
            **_composing_case(value=value_plane({KEY_V: {"usdc": sheet}}, contracts=(KEY_C,))),
        )
        row = _gate_row(document)
        composed = row["reach_composed_magnitudes"][0]
        assert composed["published_usd"] == expected
        assert composed["published_usd"] <= composed["flow_out_witness"]["usd"]
        assert composed["published_usd"] <= sheet
        assert row["value_at_stake_usd"] == expected


def test_b7_a_total_composed_from_extraction_ceilings_is_not_published_as_a_floor(fold):
    """The row header published BOTH directions of one bound.

    Every dollar of this row's value is a composed figure, and the row names
    which entities those are. The header said ``value_at_stake_is_floor`` and
    the band said ``">= "``, so the same row published a floor over a sum of
    ceilings — and the UI painted the badge. Ceilings do not become a floor by
    being summed, and the coverage gaps mean the total is not a ceiling on the
    row either.
    """
    document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert row["entities_priced_from_a_composed_ceiling"] == [KEY_V]
    # The per-entry bound label and the caller-holding block are DELETED, not
    # corrected: one asserted a direction the entry never derived, the other was
    # one constant string false on 30% of what carried it.
    entry = row["reach_composed_magnitudes"][0]
    assert "principal_extraction_bound" not in entry
    assert "caller_holding_precondition" not in entry
    assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert row["value_at_stake_is_floor"] is False
    assert row["value_band"] == "$1M-$10M"
    basis = row["value_at_stake_basis"]
    assert "NEITHER" in basis and "CEILING" in basis
    # The basis POINTS at the per-entry disclosure rather than restating it.
    assert "reach_composed_magnitudes[]" in basis
    assert not basis.startswith(">=")


def test_b7_every_contribution_a_ceiling_with_no_coverage_gap_publishes_a_ceiling(fold):
    """The second arm, which the reference corpus never reaches.

    Aliasing the seized node onto the vault leaves the row ONE priced entity,
    whose whole figure is composed: no instance is undetermined and no entity
    holds an unpriced asset, so nothing is missing from the sum and the total
    bounds the principal from above. Implemented and asserted rather than left
    as a branch nobody has executed.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(
            value=value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C,), alias={KEY_C: KEY_V}),
        ),
    )
    row = _gate_row(document)
    assert row["undetermined_instances"] == []
    assert row["entities_holding_unpriced_assets"] == []
    assert row["entities_priced_from_a_composed_ceiling"] == [KEY_V]
    assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert row["value_at_stake_is_floor"] is False
    assert row["value_band"].startswith("<= ")
    assert row["value_at_stake_basis"].startswith("<= ")


def test_b7_a_row_mixing_a_ceiling_with_an_ungraded_figure_claims_neither_bound(fold):
    """The MIXED shape, end to end: one ceiling beside one figure of its own.

    A second call on the same row carries its own magnitude witness, so its
    entity is priced from that and never from composition. The row's total is
    then part extraction ceiling and part figure this fold does not grade for
    direction — an at-most over the sum would claim a bound the second half does
    not support, and the basis has to count which half is which rather than say
    "every one of them".
    """
    witnessed = sig(
        claim_id="authority.replace",
        function_name="setAuthorityAlso",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven("proven_exact", 500_000.0).to_json()},
        **proven(0.75),
        **reaches(KEY_C),
    )
    document = fold(
        [*_composing_signals(), witnessed],
        principals=_composing_principals(),
        **_composing_case(
            value=value_plane({KEY_V: {"usdc": 5_000_000.0}, KEY_C: {"usdc": 3_000_000.0}}, contracts=(KEY_C,)),
        ),
    )
    row = _gate_row(document)
    assert set(row["value_by_entity"]) == {KEY_C, KEY_V}
    assert row["entities_priced_from_a_composed_ceiling"] == [KEY_V]
    assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert row["value_at_stake_is_floor"] is False
    assert not row["value_band"].startswith((">= ", "<= "))
    basis = row["value_at_stake_basis"]
    assert "1 of 2 entity(ies)" in basis
    assert "1 entity(ies) whose figure is not a proven ceiling and is graded in no direction" in basis


def _attributed(usd: float, **over: Any) -> FunctionSignal:
    """A ``flow.out`` instance whose figure came off the ATTRIBUTION path.

    ``proven_upper_bound`` is the constant-amount probe crediting a holder's
    whole priced balance — the live shape behind the reference corpus's rank-1
    finding, and no ceiling to :func:`_ceiling_bearing_basis`, which is exactly
    why its prose used to be written from coverage alone.
    """
    return flow_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven("proven_upper_bound", usd).to_json()},
        **proven(1.0),
        **reaches(KEY_C),
        **over,
    )


def _unwitnessed_elsewhere() -> FunctionSignal:
    """A sibling instance on the same row that answered no magnitude at all."""
    return flow_sig(
        function_name="g",
        selector="0xfeedface",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_V),
    )


def test_f1_an_attribution_derived_total_under_a_gap_names_the_refusal_not_a_floor(fold):
    """The live carrier: the basis said ">= proven floor" beside no floor.

    The string was built from the COVERAGE axis in :func:`_row_value`, where the
    attribution axis is not visible, so a row whose header refused the floor —
    ``bound_direction: not_determined``, ``is_floor: false`` — still published
    floor prose. Both axes are read where the direction is, and the refusal is
    COUNTED off the membership test it was made on rather than asserted.
    """
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    document = fold(
        [_attributed(5_000.0), _unwitnessed_elsewhere()],
        principals={1: facts(1, EOA, "eoa")},
        value=plane,
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 5_000.0
    assert finding["entities_priced_from_a_composed_ceiling"] == []
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert len(finding["undetermined_instances"]) == 1
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert finding["value_at_stake_is_floor"] is False
    basis = finding["value_at_stake_basis"]
    assert not basis.startswith(">= ")
    assert "proven floor" not in basis
    assert basis.startswith("bounded in NEITHER direction: 1 of 1 entity(ies)")
    # Named as what the membership test establishes and no further: a sheet
    # ceiling whose label was withheld reaches this arm too, so the population
    # is "not proven free of" an upper bound, never "is attribution-derived".
    assert "NOT proven free of an upper-bounding witness" in basis
    # Both halves of the coverage gap are still counted — the reason it is not
    # an at-most either — and neither is left for the reader to infer.
    assert "1 instance(s) not_determined" in basis
    assert "1 entity(ies) holding assets the priced sheet does not cover" in basis


def test_f1_a_floor_counts_the_partly_priced_entities_it_was_earned_on(fold):
    """The mirror face, which the reference corpus has no carrier for.

    ``_bound_direction``'s coverage axis reads undetermined instances AND partly
    priced entities; the floor string counted only the first. A floor earned on
    the second alone therefore had no floor prose at all, and one earned on both
    published a count that omitted half of what earned it.
    """
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    floor = flow_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 5_000_000.0).to_json()},
        **proven(1.0),
        **reaches(KEY_C),
    )
    finding = fold([floor], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert finding["undetermined_instances"] == []
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert finding["value_at_stake_is_floor"] is True
    assert (
        finding["value_at_stake_basis"]
        == ">= proven floor over 1 entity(ies); 1 entity(ies) holding assets the priced sheet does not cover"
    )

    # And beside an unanswered instance, both populations appear — the count the
    # old string made of the instances alone is now the whole gap.
    both = fold([floor, _unwitnessed_elsewhere()], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert both["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert both["value_at_stake_basis"] == (
        ">= proven floor over 1 entity(ies); 1 instance(s) not_determined, "
        "1 entity(ies) holding assets the priced sheet does not cover"
    )


def test_b7_a_direction_is_published_only_where_one_was_proven():
    """Two claims and a fall-through, each earned separately.

    ``floor`` needs a coverage gap and NO composed figure; ``ceiling`` needs
    EVERY figure composed and nothing missing from the sum — a gap, a mixed
    contribution or a withheld hop each defeat it, and each for the same reason:
    what is absent from the total can only push the truth up, which an at-least
    survives and an at-most does not.
    """
    both, one = frozenset({KEY_C, KEY_V}), frozenset({KEY_V})
    direction = FOLD._bound_direction

    assert direction(1.0, both, frozenset(), True, False, both) == FOLD.BOUND_DIRECTION_FLOOR
    # A withheld hop is value the row reaches and the sum does not carry: it
    # cannot lower the truth, so the floor stands.
    assert direction(1.0, both, frozenset(), True, True, both) == FOLD.BOUND_DIRECTION_FLOOR
    assert direction(1.0, one, one, False, False, frozenset()) == FOLD.BOUND_DIRECTION_CEILING

    # Every way of failing the ceiling, one at a time.
    assert direction(1.0, one, one, True, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert direction(1.0, one, one, False, True, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # MIXED: one entity's figure is a ceiling and the other's is graded in no
    # direction, so their sum bounds the principal in neither.
    assert direction(1.0, both, one, False, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # Neither signal fired, which is not a proof that the sum is two-sided.
    assert direction(1.0, both, frozenset(), False, False, both) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # No total, no direction — and never a floor over a figure that is absent.
    assert direction(None, frozenset(), frozenset(), True, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # F5: the coverage gap is NOT the whole question. An attribution-derived
    # contribution is itself a ceiling, so a gap over one earns no floor — and a
    # partial grade is as disqualifying as none, because the ungraded entity's
    # figure may be the ceiling.
    assert direction(1.0, both, frozenset(), True, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert direction(1.0, both, frozenset(), True, False, one) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # Only the two proven directions qualify the band.
    assert FOLD._BAND_PREFIX == {FOLD.BOUND_DIRECTION_FLOOR: ">= ", FOLD.BOUND_DIRECTION_CEILING: "<= "}


def test_w4b_an_unwitnessed_act_as_step_leaves_the_magnitude_not_determined(fold):
    """The binding rule. A licence says N MAY call D, never that P can make it.

    Each variant removes exactly one part of the act-as witness and each one is
    enough on its own to withhold the magnitude — including the live corpus
    shape, where the call site takes its callee as a PARAMETER so nothing
    witnesses which address it lands on.
    """
    variants = {
        # the corpus's own AtomicSolverV3 shape: receiver is not a state variable
        "receiver_not_a_state_variable": act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),)},
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 1)},
        ),
        "receiver_never_read": act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)},
        ),
        "receiver_holds_another_address": act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)},
            reads={(KEY_C, "vault"): (KEY_PROXY, "eth_call", 1)},
        ),
        "call_site_is_public": act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "open", "vault", True, CALLING_SELECTOR),)},
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 1)},
        ),
        "gate_is_not_delegated_to_an_authority": act_as_plane(
            call_sites={
                (KEY_C, COMPOSED_SELECTOR): (("receiveFlashLoan", "restricted", "vault", False, CALLING_SELECTOR),)
            },
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 1)},
        ),
        "no_call_site_at_all": act_as_plane(),
    }
    for name, plane in variants.items():
        document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=plane))
        row = _gate_row(document)
        assert row["value_at_stake_usd"] is None, name
        assert row["value_state"] == "not_determined", name
        assert row["reach_composed_magnitudes"] == [], name
        assert row["reach_composition_census"]["act_as_refused"], name
        # ...and the reach itself is untouched: membership never depended on it.
        assert KEY_V in row["reach_entities"], name


def test_w4b_an_empty_licence_map_composes_nothing(fold):
    """A destination reached only through a state-variable hop names no function.

    There is no compositional source for it — nothing said WHICH of its
    functions the gate reaches — and an empty licence must never be read as
    "price the sheet".
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(
            closure=P.ControlClosure(edges=(_var_edge("owner"),)),
            conferral=conferral_plane(rewrites=("owner",)),
        ),
    )
    row = _gate_row(document)
    assert KEY_V in row["reach_entities"]
    assert row["reach_licensed_functions"] == {}
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None


def test_w4b_a_destination_with_no_flow_out_witness_composes_nothing(fold):
    """Composition REUSES a witness; where there is none there is nothing to reuse."""
    gate, _ = _composing_signals()
    unwitnessed = flow_sig(
        deployment_address=VAULT,
        contract_id=2,
        function_name="exit",
        selector=COMPOSED_SELECTOR,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        witness_tier="behavioral_observed",
        **proven(0.9),
        **reaches(KEY_V),
    )
    document = fold([gate, unwitnessed], principals=_composing_principals(), **_composing_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] is None
    assert row["reach_composed_magnitudes"] == []
    assert row["reach_composition_census"]["act_as_witnessed"] == 1
    assert row["reach_composition_census"]["destination_magnitude_witnessed"] == 0


def test_w4b_a_freeze_has_no_compositional_source_and_stays_floored(fold):
    """pause.set is untouched by Phase 6 (§7).

    Nothing composes into "how much a freeze immobilises": the destination
    witness Phase 6 reuses answers how much a CALL MOVES, which is a different
    quantity. Even with every act-as witness in place the freeze row publishes
    no magnitude.
    """
    freeze = pause_sig(
        function_name="pause",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.6),
        **reaches(KEY_C),
    )
    _, destination = _composing_signals()
    document = fold([freeze, destination], principals=_composing_principals(), **_composing_case())
    row = next(f for f in document.findings if f["capability"] == "pause.set")
    assert row["value_at_stake_usd"] is None
    assert row["value_state"] == "not_determined"
    assert row.get("reach_composed_magnitudes") == []


def test_w4b_a_composed_magnitude_answers_the_confidence_term(fold):
    """inv. 6: composing an answer may only raise the term, and only where real.

    The signal whose magnitude composed counts as answered; the unwitnessed
    freeze beside it does not, so the term rises by exactly one signal's worth
    and not to the ceiling.
    """
    signals = _composing_signals()
    without = fold(signals, principals=_composing_principals(), **_composing_case(act_as=act_as_plane()))
    with_ = fold(signals, principals=_composing_principals(), **_composing_case())
    detail_before = without.model_parameters["confidence_detail"]
    detail_after = with_.model_parameters["confidence_detail"]
    before = detail_before["reach_magnitude_signals"]
    after = detail_after["reach_magnitude_signals"]
    assert before["magnitude_witnessed"] == 1 and before.get("magnitude_composed", 0) == 0
    assert after["magnitude_witnessed"] == 2 and after["magnitude_composed"] == 1
    assert after["composed_by_capability"] == {"authority.replace": 1}
    assert detail_after["reach_magnitude_witnessed_pct"] >= detail_before["reach_magnitude_witnessed_pct"]


def test_w4b_case2_a_seed_that_cannot_act_composes_nothing_two_hops_out(fold):
    """§9.5 case 2, as the corpus actually answers it.

    The spec expected the timelock behind RolesAuthority ``0x4df6b733`` to regain
    a witnessed magnitude at Phase 6. It does not, and the shape is this one: the
    seized node is an AUTHORITY, its own outgoing hop names no licensed function,
    and the vault two hops out — which has a ``flow.out`` witness and a caller
    with a full act-as witness — is behind that break. A chain is as strong as
    its weakest step, so the magnitude stays not_determined for the timelock
    exactly as it does for the two EOAs the shipped document over-charged. That
    is §9.5 case 2's OTHER admissible outcome ("both sides fall to
    not_determined"), not its headline one, and this test pins which.
    """
    signals = _composing_signals()
    document = fold(
        signals,
        principals=_composing_principals(),
        **_composing_case(
            closure=P.ControlClosure(
                edges=(
                    # seed -> intermediate, a state-variable hop licensing nothing
                    _var_edge("authority", principal=KEY_C, anchor=KEY_PROXY),
                    # intermediate -> destination, fully licensed and fully act-as witnessed
                    _role_edge("roles 12", principal=KEY_PROXY, anchor=KEY_V),
                )
            ),
            conferral=conferral_plane(
                rewrites=("authority",),
                role_functions={(KEY_V, 12): (P.LicensedFunction(COMPOSED_SELECTOR, "exit"),)},
            ),
            act_as=act_as_plane(
                call_sites={
                    (KEY_PROXY, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)
                },
                reads={(KEY_PROXY, "vault"): (KEY_V, "eth_call", 1)},
            ),
        ),
    )
    row = _gate_row(document)
    assert {KEY_PROXY, KEY_V} <= set(row["reach_entities"])
    assert row["reach_licensed_functions"] == {KEY_V: [{"selector": COMPOSED_SELECTOR, "name": "exit"}]}
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    # ...and the break is NAMED. A licensed hop the walk never offered is not an
    # act-as refusal at that hop — the question was never asked there — and
    # publishing it as an empty refusal map left the unit's most important
    # negative result readable only as silence.
    census = row["reach_composition_census"]
    assert census["licensed_hops"] == 1 and census["licensed_selectors"] == 0
    assert census["act_as_refused"] == {FOLD.ACT_AS_CALLER_UNREACHED: 1}


# --------------------------------------------------------------------------
# W1a — the destination-side ACL as the second act-as witness shape
# --------------------------------------------------------------------------

# The corpus's own AtomicSolverV3 -> Teller shape: a restricted, authority-gated
# function whose callee is a PARAMETER, so no storage of the caller can name the
# destination and the binding lives in the destination's own ACL.
ACL_CALL_SITES = {(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),)}
ACL_ACCEPTED = P.DestinationAcceptance(
    roles=(12,),
    membership_quality="exact",
    destination_function="bulkWithdraw",
    function_principal_id=14279,
)


def _acl_plane(**over: Any) -> P.ActAsPlane:
    case: dict[str, Any] = {
        "call_sites": ACL_CALL_SITES,
        "destination_acl": {(KEY_V, COMPOSED_SELECTOR): {KEY_C: ACL_ACCEPTED}},
    }
    case.update(over)
    return act_as_plane(**case)


def test_w1a_a_parameter_bound_call_site_composes_on_the_destinations_own_acl(fold):
    """The second witness shape, whole.

    The caller's compiled body calls the selector at an address its own caller
    supplies — the shape the state-variable witness is structurally unable to
    satisfy — and the destination's resolved access-control list names the
    caller as an accepted caller of that selector by an enumerated role. Neither
    fact alone witnesses the step; joined they do, and the magnitude composes.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(act_as=_acl_plane()),
    )
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert row["value_state"] == VALUE_STATE_PROVEN_REACH
    assert [c["entity"] for c in row["reach_composed_magnitudes"]] == [KEY_V]
    assert row["reach_composition_census"]["act_as_witnessed"] == 1


def test_w1a_an_acl_admitted_step_publishes_the_witness_shape_that_admitted_it(fold):
    """inv. 16: no abstraction above a witness, and no basis borrowed from one.

    An ACL-admitted step must not be rendered through the state-variable
    sentence — there is no state variable and no on-chain read of one. It names
    the shape, the ``function_principals`` row, the admitting roles and the
    membership quality, and leaves the receiver fields empty because nothing
    filled them.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(act_as=_acl_plane()),
    )
    step = _gate_row(document)["reach_composed_magnitudes"][0]["act_as_chain"][0]
    assert step["witness_kind"] == P.ACT_AS_WITNESS_DESTINATION_ACL
    assert step["destination_acceptance"] == {
        "source": "function_principals",
        "function_principal_id": 14279,
        "destination_function": "bulkWithdraw",
        "accepting_roles": [12],
        "membership_quality": "exact",
    }
    assert (step["receiver_variable"], step["receiver_observed_via"], step["receiver_block"]) == (None, None, None)
    # ...and not through the sentence the other shape earns.
    assert "on its own state variable" not in step["basis"]
    for fragment in ("function_principals row 14279", "role(s) [12]", "membership_quality 'exact'", "parameter-bound"):
        assert fragment in step["basis"], fragment
    # The other shape keeps its own basis, unchanged and unconfusable with it.
    other = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    other_step = _gate_row(other)["reach_composed_magnitudes"][0]["act_as_chain"][0]
    assert other_step["witness_kind"] == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert other_step["destination_acceptance"] is None
    assert "state variable 'vault'" in other_step["basis"]


def test_w1a_the_acl_admission_is_a_magnitude_witness_and_never_a_reach_one(fold):
    """The ACL says D accepts a call from N. It says nothing about who N reaches.

    Reach is decided by the closure walk, which never consults this plane; the
    admission may only turn a not_determined magnitude into a witnessed one on
    entities the row already reached.
    """
    without = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=act_as_plane()))
    with_acl = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=_acl_plane()))
    assert _gate_row(without)["reach_entities"] == _gate_row(with_acl)["reach_entities"]
    assert _gate_row(without)["value_at_stake_usd"] is None
    assert _gate_row(with_acl)["value_at_stake_usd"] == 1_000_000.0


def test_w1a_a_missing_or_unenumerated_acl_row_is_a_typed_refusal_not_a_pass():
    """Absence of the destination's acceptance is refused under its own reason.

    Each variant removes exactly one conjunct. A parameter-bound call site is
    promoted only when the destination's own list names this caller, for this
    selector, on this chain, by a ROLE, with the accepted set ENUMERATED. Each
    shortfall carries its own reason: "the list does not name this caller",
    "it names this caller and no role that admits it" and "it names a role and
    does not bound the accepted set" are three different findings, and a reader
    charged the wrong one is charged a claim the evidence does not support.
    """
    other_chain = entity_key("base", VAULT)
    variants = {
        # nothing on the destination side at all
        "no_acl_at_all": (_acl_plane(destination_acl={}), P.ACT_AS_NO_DESTINATION_ACL),
        # the destination accepts SOMEBODY, and not this caller
        "acl_names_another_caller": (
            _acl_plane(destination_acl={(KEY_V, COMPOSED_SELECTOR): {KEY_PROXY: ACL_ACCEPTED}}),
            P.ACT_AS_NO_DESTINATION_ACL,
        ),
        # the ACL is a fact about one deployment: a same-address destination on
        # another chain is a different contract and admits nothing here
        "acl_is_on_another_chain": (
            _acl_plane(destination_acl={(other_chain, COMPOSED_SELECTOR): {KEY_C: ACL_ACCEPTED}}),
            P.ACT_AS_NO_DESTINATION_ACL,
        ),
        # the destination accepts this caller for a DIFFERENT selector
        "acl_is_for_another_selector": (
            _acl_plane(destination_acl={(KEY_V, "0xdeadbeef"): {KEY_C: ACL_ACCEPTED}}),
            P.ACT_AS_NO_DESTINATION_ACL,
        ),
        # the row is there, and it expresses no role that admits this caller —
        # not the same fact as the destination's list never naming it
        "acl_row_names_no_admitting_role": (
            _acl_plane(
                destination_acl={
                    (KEY_V, COMPOSED_SELECTOR): {KEY_C: P.DestinationAcceptance((), "exact", "bulkWithdraw", 14279)}
                }
            ),
            P.ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE,
        ),
        "membership_is_only_bounded_below": (
            _acl_plane(
                destination_acl={
                    (KEY_V, COMPOSED_SELECTOR): {
                        KEY_C: P.DestinationAcceptance((12,), "lower_bound", "bulkWithdraw", 14279)
                    }
                }
            ),
            P.ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE,
        ),
        # the gate conjuncts are not weakened by the second shape: a call site
        # that needs no gate, or whose gate is not delegated to an authority, is
        # never promoted by an ACL row — and each is refused under the conjunct
        # that ACTUALLY failed. The receiver being parameter-bound is the
        # PRECONDITION for this shape, so naming it as the shortfall would answer
        # a question nobody asked and hide the one that decided the verdict.
        "call_site_needs_no_gate": (
            _acl_plane(call_sites={(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "open", "", True, CALLING_SELECTOR),)}),
            P.ACT_AS_CALL_SITE_IS_PUBLIC,
        ),
        "gate_is_not_delegated": (
            _acl_plane(
                call_sites={(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "restricted", "", False, CALLING_SELECTOR),)}
            ),
            P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED,
        ),
        # the third state of openness, which is neither of the other two: the
        # pipeline did not determine this function's gate. Publishing it as
        # "the call site needs no gate" would mint a proven-absent gate out of an
        # unread field, and publishing it as the receiver binding hides that the
        # only missing fact is a coverage gap.
        "gate_openness_is_not_determined": (
            _acl_plane(
                call_sites={
                    (KEY_C, COMPOSED_SELECTOR): (("boringSolve", "not_determined", "", True, CALLING_SELECTOR),)
                }
            ),
            P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED,
        ),
        # an ACL row alone is a licence to call, never a witness that the
        # caller's code calls anything
        "no_call_site": (_acl_plane(call_sites={}), P.ACT_AS_NO_CALL_SITE),
    }
    for name, (plane, expected) in variants.items():
        verdict = plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
        assert not verdict.witnessed, name
        assert verdict.step is None, name
        assert verdict.outcome == expected, name


def test_w1a_a_state_variable_site_still_reports_its_own_sharper_shortfall():
    """One caller, two call sites, two shapes: report how far the walk GOT.

    A state-variable site that was read and holds somebody else got further than
    a parameter-bound site whose destination never named the caller, and the
    refusal a reader is charged must be the sharper one.
    """
    plane = act_as_plane(
        call_sites={
            (KEY_C, COMPOSED_SELECTOR): (
                ("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),
                ("finishSolve", "restricted", "", True, CALLING_SELECTOR),
            )
        },
        reads={(KEY_C, "vault"): (KEY_PROXY, "eth_call", 1)},
    )
    assert plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS
    # With nothing to consult on either side, the parameter-bound site's own
    # reason is what the reader gets: the destination ACL WAS asked.
    unread = act_as_plane(
        call_sites={(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),)}
    )
    assert unread.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_NO_DESTINATION_ACL


def test_w1a_a_satisfied_state_variable_read_is_still_the_witness_that_admits(fold):
    """Both shapes satisfied at once: the caller's own storage is what is read.

    The state-variable witness is the stronger fact — the caller's own storage
    names the destination, no arm of it depends on the destination's list — so
    it keeps priority, and the published step must be that one and not a second
    shape that also happened to hold. A step admitted on the caller's storage
    carries no ``destination_acceptance``: nothing consulted one.
    """
    both = _acl_plane(
        call_sites={
            (KEY_C, COMPOSED_SELECTOR): (
                ("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),
                ("finishSolve", "restricted", "", True, CALLING_SELECTOR),
            )
        },
        reads={(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
    )
    verdict = both.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
    assert verdict.witnessed
    assert verdict.step is not None
    assert verdict.step.witness_kind == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert verdict.step.acceptance is None

    document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=both))
    step = _gate_row(document)["reach_composed_magnitudes"][0]["act_as_chain"][0]
    assert step["witness_kind"] == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert step["destination_acceptance"] is None
    assert (step["calling_function"], step["receiver_variable"]) == ("bulkWithdraw", "vault")


# --------------------------------------------------------------------------
# W2 — composition over a 2-hop chain: the ceiling, its disclosure, and the
# rule that no hop inherits its predecessor's authority
# --------------------------------------------------------------------------

# bulkDeposit at the teller: a function of the teller nothing on this chain
# admits, used to stand in for every hop the principal cannot drive.
REFUND_SELECTOR = "0x9d574420"


def test_w2_case1_the_two_hop_chain_composes_through_both_links(fold):
    """Regression case 1. Both links witnessed, each by the shape it earns.

    The whole decomposition is published on the entry: the seized gate's row, a
    restricted authority-gated calling function of the seized node, the
    destination's ACL row with the role and the selector it admits, the
    intermediate's resolved pointer, and the destination's own flow.out witness.
    Remove any one and the figure is not_determined.
    """
    document = fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert row["value_state"] == VALUE_STATE_PROVEN_REACH
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert entry["act_as_chain_length"] == 2
    first, second = entry["act_as_chain"]

    # link 1: the seized node's restricted, authority-gated function, admitted
    # at the teller by the teller's OWN list, by role, on an exact membership.
    assert (first["caller"], first["destination"]) == (KEY_C, KEY_T)
    assert first["witness_kind"] == P.ACT_AS_WITNESS_DESTINATION_ACL
    assert first["calling_function"] == "finishSolve"
    assert first["destination_acceptance"] == {
        "source": "function_principals",
        "function_principal_id": 14279,
        "destination_function": "bulkWithdraw",
        "accepting_roles": [12],
        "membership_quality": "exact",
    }
    # link 2: the intermediate's own pointer, read on-chain holding the vault —
    # and it is issued from the very function link 1 admitted.
    assert (second["caller"], second["destination"]) == (KEY_T, KEY_V)
    assert second["witness_kind"] == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert (second["calling_function"], second["receiver_variable"]) == ("bulkWithdraw", "vault")
    assert (second["receiver_observed_via"], second["receiver_block"]) == ("eth_call", 25_657_731)

    # ...and the dollars at the far end are the DESTINATION's own witness.
    assert entry["flow_out_witness"] == {
        "state": "proven_exact",
        "usd": 1_000_000.0,
        "function": "exit",
        "entity": KEY_V,
    }
    assert entry["selector"] == COMPOSED_SELECTOR
    assert row["reach_composition_census"]["longest_composed_chain"] == 2
    # The router is on the path and carries no figure of its own: a chain that
    # died at it would recover nothing, which is why link 1 costs the chain.
    assert KEY_T not in {e["entity"] for e in row["reach_composed_magnitudes"]}


def test_w2_the_composed_figure_carries_no_authored_precondition_block(fold):
    """F3, cut. The block that hedged the figure was one constant string.

    ``caller_holding_precondition`` was 1,222 characters, identical on all forty
    entries of the reference corpus, and its central clause — that the last
    admitted call spends a quantity the caller must hold — is FALSE on the
    twelve whose destination is ``manage``. It is deleted rather than reworded,
    and with it ``principal_extraction_bound``, which named a direction the
    entry derived from nothing. What survives is what the entry can account for:
    the figure, the sheet that bounded it, and the execution that proved it.
    """
    document = fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case())
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert "caller_holding_precondition" not in entry
    assert "principal_extraction_bound" not in entry
    assert not hasattr(FOLD, "_CallerHoldingPrecondition")
    assert not hasattr(FOLD, "COMPOSED_BOUND_CALLER_ARGUMENTS")
    # The witness was READ from one function's row and measures the entity.
    assert entry["witness_granularity"] == "entity"
    # ...and deleting the hedge did not delete the figure or its account.
    assert entry["published_usd"] == 1_000_000.0
    assert entry["proving_execution"]["state"] in ("recorded", "not_determined")


def test_w2_case2_the_condition_disproved_hop_is_not_resurrected_by_composition(fold):
    """Regression case 2. The blocked EOA stays blocked.

    The intermediate's every consulted function pins its caller to the
    destination itself, which the condition plane reads as a disproof INSIDE the
    closure walk — upstream of composition. An admission built on the
    destination's ACL must not reach around it: the walk never offers the hop,
    so nothing composes and the magnitude stays not_determined.
    """
    blocked = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            conditions=condition_plane(by_entity={KEY_T: (("finishSolve", 570, (INITIATOR_GUARD,)),)}),
        ),
    )
    row = _gate_row(blocked)
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    assert row["value_state"] == "not_determined"
    assert KEY_T not in row["reach_entities"]
    hop = next(h for h in row["reach_hops_not_determined"] if h["destination"] == KEY_T)
    assert hop["reason"] == FOLD.HOP_REFUSED_CONDITION
    assert hop["disproving_conditions"][0]["conditions"] == [INITIATOR_GUARD]


def test_w2_case3_composition_admits_a_magnitude_and_never_an_entity(fold):
    """Regression case 3. No row reaches an entity composition put there.

    Reach is decided by the closure walk, which never consults the act-as plane.
    Strip every act-as witness and the same entities are still reached — only
    the dollars go to not_determined.
    """
    with_witness = _gate_row(fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case()))
    without = _gate_row(
        fold(
            _composing_signals(),
            principals=_composing_principals(),
            **_two_hop_case(act_as=act_as_plane()),
        )
    )
    assert with_witness["reach_entities"] == without["reach_entities"]
    assert set(with_witness["reach_entities"]) >= {KEY_C, KEY_T, KEY_V}
    assert without["reach_composed_magnitudes"] == []
    assert without["value_at_stake_usd"] is None
    assert with_witness["value_at_stake_usd"] == 1_000_000.0


def test_w2_case4_a_parameter_bound_link_with_no_acl_row_stays_refused(fold):
    """Regression case 4. The destination-side witness is required, not assumed.

    Hop 1's call site takes its callee as a parameter, so no storage of the
    seized node can name the teller. With the teller's own list silent, nothing
    at either end names the address, and the chain stops at hop 1 under its own
    typed reason — the second hop is never even offered.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
            )
        ),
    )
    row = _gate_row(document)
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    refused = row["reach_composition_census"]["act_as_refused"]
    assert refused[P.ACT_AS_NO_DESTINATION_ACL] == 1
    # The second link was witnessed and is never reached: its caller is not
    # reachable from the seized node, which is a different fact from a refusal
    # at that hop and is counted as one.
    assert refused[FOLD.ACT_AS_CALLER_UNREACHED] == 1
    assert row["reach_composition_census"]["longest_composed_chain"] == 0


def test_w2_case5_no_composed_magnitude_exceeds_the_bound_over_two_hops(fold):
    """Regression case 5. The anti-composition property, re-asserted at length 2.

    Two ceilings and the published figure clears neither: the destination's own
    witness, and the destination's determined sheet. A longer chain can only
    ever make the path harder to witness, never the number larger.
    """
    for sheet, expected in ((5_000_000.0, 1_000_000.0), (250_000.0, 250_000.0)):
        document = fold(
            _composing_signals(),
            principals=_composing_principals(),
            **_two_hop_case(value=value_plane({KEY_V: {"usdc": sheet}}, contracts=(KEY_C, KEY_T))),
        )
        entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
        assert entry["act_as_chain_length"] == 2
        assert entry["published_usd"] == expected
        assert entry["published_usd"] <= entry["flow_out_witness"]["usd"]
        assert entry["published_usd"] <= sheet
        assert _gate_row(document)["value_at_stake_usd"] == expected


def test_w2_case6_a_hop_from_a_function_the_previous_hop_did_not_admit_composes_nothing(fold):
    """Regression case 6. No hop inherits its predecessor's authority.

    The principal seized nothing on the teller. It arrives there as the caller
    the teller's list admitted, able to run exactly the function that list
    admitted — so a second hop issued from some OTHER function of the teller is
    a call nothing witnesses the principal can cause, however well-witnessed the
    teller's pointer to the vault is. Without the rule the chain would stand on
    which function name happened to sort first.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    # the teller reaches the vault from a function of its own
                    # that role 12 never licensed to this caller
                    (KEY_T, COMPOSED_SELECTOR): (("refundDeposit", "restricted", "vault", True, REFUND_SELECTOR),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
            )
        ),
    )
    row = _gate_row(document)
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    census = row["reach_composition_census"]
    assert census["act_as_refused"][P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION] == 1
    # Hop 1 is still witnessed — the chain is refused at the step that is
    # unwitnessed, not at the one before it.
    assert census["act_as_witnessed"] == 1
    # ...and the reach is untouched: membership never depended on the rule.
    assert KEY_V in row["reach_entities"]


def test_w2_an_overloaded_intermediate_name_does_not_stand_in_for_the_admitted_function(fold):
    """A function NAME does not identify a function, and the chain rule needs one.

    The teller reaches the vault from a function it also calls ``bulkWithdraw``
    — a real shape: 32 (entity, name) pairs on the reference corpus carry more
    than one selector, ``manage`` at the composed BoringVaults among them. Its
    selector is not the one hop 1 admitted, so the principal cannot drive it,
    and a rule that compared names would admit the hop and compose the vault.
    """
    overloaded = "0x9d574421"
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    # same NAME as the admitted function, different function
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, overloaded),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
            )
        ),
    )
    row = _gate_row(document)
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    assert row["reach_composition_census"]["act_as_refused"][P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION] == 1


def test_w2_the_admitted_call_site_is_selected_and_never_vetoed_by_a_sibling(fold):
    """The chain rule SELECTS the admitted step; it does not judge an arbitrary one.

    The teller reaches the vault from two of its own functions, and the one the
    principal cannot drive sorts first. A rule that asked the plane for "the"
    step and then vetoed it would refuse the whole chain here — publishing a
    refusal that names a function the previous hop DID admit — so the walk asks
    the narrower question instead and the recovery survives the ordering.
    """
    sites = (
        # sorts before bulkWithdraw, and nothing on this chain admits it
        ("adminRefund", "restricted", "vault", True, REFUND_SELECTOR),
        ("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),
    )
    for ordering in (sites, tuple(reversed(sites))):
        document = fold(
            _composing_signals(),
            principals=_composing_principals(),
            **_two_hop_case(
                act_as=act_as_plane(
                    call_sites={
                        (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                        (KEY_T, COMPOSED_SELECTOR): ordering,
                    },
                    reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                    destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
                )
            ),
        )
        row = _gate_row(document)
        assert row["value_at_stake_usd"] == 1_000_000.0
        entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
        second = entry["act_as_chain"][1]
        assert (second["calling_function"], second["calling_selector"]) == ("bulkWithdraw", HOP1_SELECTOR)
        assert (
            P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION not in row["reach_composition_census"]["act_as_refused"]
        )


def test_w2_the_protocol_rollup_maxes_the_chain_length_and_sums_the_counts(fold):
    """Chain length is a per-row MAXIMUM; every other census key is a count.

    Summed instead, two rows each composing a 2-hop chain would publish a
    corpus with a 4-hop chain — an arithmetic artefact read as the deepest chain
    anyone proved. Asserted over the rollup directly, because one composing row
    cannot tell a max from a sum.
    """
    rows = [
        {
            "reach_composition_census": {"longest_composed_chain": 2, "licensed_selectors": 3},
            "reach_composed_magnitudes": [{"entity": KEY_V, "published_usd": 10.0}],
        },
        {
            "reach_composition_census": {"longest_composed_chain": 2, "licensed_selectors": 4},
            "reach_composed_magnitudes": [{"entity": KEY_PROXY, "published_usd": 5.0}],
        },
    ]
    rolled = FOLD._composition_totals(rows, [])["findings"]
    assert rolled["longest_composed_chain"] == 2, "summed, this would read 4"
    assert rolled["licensed_selectors"] == 7, "a genuine count still sums"
    assert rolled["entities_composed"] == 2

    # ...and the key the rollup maxes is really the one the fold publishes.
    document = fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case())
    census = document.provenance["reach_bounds"]["act_as_composition"]["census"]["findings"]
    assert census["longest_composed_chain"] == 2
    assert _gate_row(document)["reach_composition_census"]["longest_composed_chain"] == 2


def test_w2_a_seed_is_never_constrained_by_a_hop_into_it(fold):
    """Ruling 4 rule 2: the seized gate is spent at hop 1, and every seed IS hop 1.

    Two entities carry the finding's signal, so both are seeds, and one of them
    is also the far end of a witnessed hop from the other. That hop admits one
    of its functions — but a seed does not need admitting: the principal seized
    its gate directly, which is the whole reason it is a seed. Constraining it
    to the function some sibling hop happened to admit would refuse its own
    composable hop and publish a previous-hop reason for a node that has no
    previous hop.
    """
    hub_entry = "0x3e64ce99"
    document = fold(
        [
            sig(
                claim_id="authority.replace",
                function_name="setAuthority",
                authority_openness="restricted",
                principal_state="enumerated",
                principal_refs=(PrincipalRef(1, "ethereum", EOA),),
                **proven(0.75),
                # BOTH seeds: the signal was witnessed on each
                **reaches(KEY_T, KEY_C),
            ),
            _composing_signals()[1],
        ],
        principals=_composing_principals(),
        closure=P.ControlClosure(
            edges=(
                _role_edge("roles 12", principal=KEY_T, anchor=KEY_C),
                _role_edge("roles 12", principal=KEY_C, anchor=KEY_V),
            )
        ),
        conferral=conferral_plane(
            role_functions={
                (KEY_C, 12): (P.LicensedFunction(hub_entry, "route"),),
                (KEY_V, 12): (P.LicensedFunction(COMPOSED_SELECTOR, "exit"),),
            }
        ),
        act_as=act_as_plane(
            call_sites={
                # the sibling seed really can call the other one...
                (KEY_T, hub_entry): (("relay", "restricted", "hub", True, REFUND_SELECTOR),),
                # ...and the constrained seed's own composing site is issued
                # from a different function of its own
                (KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),),
            },
            reads={(KEY_T, "hub"): (KEY_C, "eth_call", 1), (KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
        ),
        value=value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C, KEY_T)),
    )
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    # The seed spends its own gate: one step, from the seed, no inherited entry.
    assert entry["act_as_chain_length"] == 1
    assert entry["act_as_chain"][0]["caller"] == KEY_C
    assert P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION not in row["reach_composition_census"]["act_as_refused"]


def test_w2_a_node_entered_twice_publishes_the_chain_the_hop_was_issued_from(fold):
    """Ruling 4 rule 4: the published chain must BE the path, not a path.

    The intermediate is admitted under two of its own functions by two different
    functions of the seized node. Its hop to the vault is issued from the second
    of them, so the published chain must carry the step that admitted THAT one.
    Publishing whichever entry was witnessed first would name a path this step
    was not issued from, while the census says every step is the one before it
    admitted.
    """
    first_entry, second_entry = "0x11111111", HOP1_SELECTOR
    accepted = P.DestinationAcceptance((12,), "exact", "deposit", 991)
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            closure=P.ControlClosure(
                edges=(
                    _role_edge("roles 12", anchor=KEY_T),
                    _role_edge("roles 12", principal=KEY_T, anchor=KEY_V),
                )
            ),
            conferral=conferral_plane(
                role_functions={
                    (KEY_T, 12): (
                        P.LicensedFunction(first_entry, "deposit"),
                        P.LicensedFunction(second_entry, "bulkWithdraw"),
                    ),
                    (KEY_V, 12): (P.LicensedFunction(COMPOSED_SELECTOR, "exit"),),
                }
            ),
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, first_entry): (("depositSolve", "restricted", "", True, "0xaaaa0001"),),
                    (KEY_C, second_entry): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    # issued from the SECOND admitted function of the teller
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, second_entry),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={
                    (KEY_T, first_entry): {KEY_C: accepted},
                    (KEY_T, second_entry): {KEY_C: HOP1_ACCEPTED},
                },
            ),
        ),
    )
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    first, second = entry["act_as_chain"]
    # ...the step that admitted bulkWithdraw, not the one that admitted deposit.
    assert (first["calling_function"], first["selector"]) == ("finishSolve", second_entry)
    assert second["calling_selector"] == second_entry
    # ...and the chain really is a chain: each step enters the function the next
    # step is issued from.
    assert first["selector"] == second["calling_selector"]


# --------------------------------------------------------------------------
# U1 — the act-as refusal ladder: every reason names the conjunct that failed
# --------------------------------------------------------------------------

# One caller, one selector, one state-variable-bound call site. Each case below
# changes exactly one fact about the receiver read and asserts the reason moves
# with it — a reason that fires on its neighbour's shape is a reason that
# misstates the evidence.
_LADDER_SITES = {(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)}


def _ladder(**over: Any) -> P.ActAsPlane:
    case: dict[str, Any] = {"call_sites": _LADDER_SITES}
    case.update(over)
    return act_as_plane(**case)


def test_u1_a_read_that_reverted_is_not_a_read_that_never_happened():
    """The third state, and the two it must never be spelled as.

    A ``controller_values`` row observed via ``eth_call_error`` is the record of
    a read the pipeline ISSUED and that reverted. Publishing it as
    "never read on chain" asserts a coverage gap of the reader that the row
    itself disproves, and the two facts must reach the consumer apart.
    """
    never = _ladder()
    assert never.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_NOT_READ

    failed = _ladder(read_failures={(KEY_C, "vault"): ("eth_call_error", 25_657_731)})
    assert failed.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_READ_FAILED

    # ...and a failure record NEVER satisfies the receiver test: it carries no
    # address, so it cannot witness that the variable holds the destination.
    assert not failed.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).witnessed

    # A failure recorded for ANOTHER variable does not answer for this one.
    other = _ladder(read_failures={(KEY_C, "authority"): ("eth_call_error", 1)})
    assert other.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_NOT_READ


def test_u1_a_renounced_and_a_codeless_pointer_each_earn_their_own_negative():
    """Two proven-absent classes, kept apart from each other and from the rest.

    ``zero`` is a renounced pointer: the call lands at address(0), which holds no
    code and never can. ``eoa`` is an address proven codeless by an empty
    ``eth_getCode`` — a call there executes nothing today, and CREATE2 can make
    it a contract tomorrow, so it is NOT the same proof. Every other
    classification is a plain address comparison.
    """
    read: dict[tuple[str, str], tuple[str, str, int | None]] = {(KEY_C, "vault"): (KEY_PROXY, "eth_call", 25_657_731)}
    cases = {
        "zero": P.ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS,
        "eoa": P.ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT,
        "safe": P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS,
        "timelock": P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS,
        "contract": P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS,
        "unknown": P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS,
    }
    for kind, expected in cases.items():
        verdict = _ladder(reads=read, read_kinds={(KEY_C, "vault"): kind}).acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
        assert verdict.outcome == expected, kind
        # ...and the refusal carries WHAT it held, so the census can report the
        # class rather than leave a reader to guess it.
        assert verdict.receiver_resolved_type == kind, kind
    # A row with no classification at all is a third state and not 'contract'.
    unclassified = _ladder(reads=read).acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
    assert unclassified.outcome == P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS
    assert unclassified.receiver_resolved_type == "not_determined"


def test_u1_a_label_at_the_pointer_never_refuses_a_read_that_holds_the_destination():
    """The witness is the read and the address comparison, not the label.

    A pointer the resolver classified ``safe`` or ``timelock`` that holds D
    witnesses the step exactly as a ``contract`` one does. Branching admission on
    ``resolved_type`` asks what KIND of thing the address is — a question the
    act-as step never needed — and discards a stored read on the strength of a
    name.
    """
    for kind in ("contract", "safe", "timelock", "unknown", None):
        plane = _ladder(
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
            read_kinds={(KEY_C, "vault"): kind} if kind else {},
        )
        verdict = plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
        assert verdict.witnessed, kind
        assert verdict.step is not None and verdict.step.receiver_variable == "vault"


def test_u1_an_undetermined_gate_openness_is_never_published_as_needing_no_gate():
    """SCORER_DISCIPLINE_CONTRACT §2, at both arms of the plane.

    ``the_call_site_needs_no_gate`` is a POSITIVE claim — this function is open —
    and minting it from an ``authority_openness`` the pipeline did not determine
    publishes an unread field as a proven-absent gate. The third state gets its
    own reason on the state-variable arm exactly as it does on the ACL arm.
    """
    read: dict[tuple[str, str], tuple[str, str, int | None]] = {(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)}
    for openness, expected in (
        ("open", P.ACT_AS_CALL_SITE_IS_PUBLIC),
        ("not_determined", P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED),
        ("", P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED),
        ("public", P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED),
    ):
        plane = act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", openness, "vault", True, CALLING_SELECTOR),)},
            reads=read,
        )
        assert plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == expected, openness


def test_u1_the_parameter_bound_arm_reports_the_conjunct_that_actually_failed():
    """A precondition is not a shortfall.

    The receiver being parameter-bound is what makes the destination-ACL shape
    ADMISSIBLE; it is never the reason a step was refused. With the destination's
    ACL present and the gate the only gap, the reason must name the gate — and
    the ACL reasons stay available for the shortfalls that really are the
    destination's.
    """
    gate_cases = {
        "open": P.ACT_AS_CALL_SITE_IS_PUBLIC,
        "not_determined": P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED,
    }
    for openness, expected in gate_cases.items():
        plane = _acl_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("boringSolve", openness, "", True, CALLING_SELECTOR),)}
        )
        assert plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == expected, openness
    # Two parameter-bound sites, two different shortfalls: the sharpest is
    # published, and it is still a GATE reason rather than the binding.
    both = _acl_plane(
        call_sites={
            (KEY_C, COMPOSED_SELECTOR): (
                ("boringSolve", "not_determined", "", True, CALLING_SELECTOR),
                ("finishSolve", "restricted", "", False, CALLING_SELECTOR),
            )
        }
    )
    assert both.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED
    # ...and a site that clears every conjunct is admitted even when a sibling
    # site fails one, so a shortfall never masks a witness.
    mixed = _acl_plane(
        call_sites={
            (KEY_C, COMPOSED_SELECTOR): (
                ("boringSolve", "not_determined", "", True, CALLING_SELECTOR),
                ("finishSolve", "restricted", "", True, CALLING_SELECTOR),
            )
        }
    )
    admitted = mixed.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
    assert admitted.witnessed and admitted.step is not None
    assert admitted.step.calling_function == "finishSolve"


def test_u1_the_retired_sentinel_is_gone_and_every_reason_is_ranked():
    """``_rank_outcome`` indexes ``_ACT_AS_RANK`` bare: an unregistered outcome
    raises at runtime, not at import. Every reason the plane can publish must be
    in the map, and the retired sentinel must be in neither."""
    assert not hasattr(P, "ACT_AS_RECEIVER_NOT_A_STATE_VARIABLE")
    ranked = P._ACT_AS_RANK
    for name in dir(P):
        if not name.startswith("ACT_AS_") or name.startswith("ACT_AS_WITNESS"):
            continue
        assert getattr(P, name) in ranked, name
    assert len(set(ranked.values())) == len(ranked)


def test_u1_delegation_is_required_at_hop_1_and_not_past_it():
    """B3: past the first hop the licence is the previous hop's admitted selector.

    At hop 1 the principal's leverage IS the seized authority pointer, so only an
    authority-delegated gate is opened by seizing it. Past hop 1 the principal
    has seized nothing on the intermediate and arrives as whoever the previous
    hop admitted — an intermediate gated by a direct ``msg.sender ==`` check is
    exactly the shape such a chain runs through, and refusing it discards a
    witnessed path over a mechanism the principal is not using.
    """
    plane = act_as_plane(
        call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", False, HOP1_SELECTOR),)},
        reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
    )
    # hop 1: the unconstrained question. The delegation witness is required and
    # this call site carries none.
    assert plane.acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED
    # hop >= 2: entered under the selector the previous hop admitted.
    past = plane.acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR, via=frozenset({HOP1_SELECTOR}))
    assert past.witnessed and past.step is not None
    # ...and the relaxation is DISCLOSED, on the step and in its basis, rather
    # than left as a conjunct that silently stopped being applied.
    assert past.step.admitted_without_a_delegation_witness is True
    assert past.step.as_json()["admitted_without_a_delegation_witness"] is True
    assert "was NOT tested" not in past.step.as_json()["basis"]
    assert "no witness that" in past.step.as_json()["basis"]
    # A step that DOES carry the delegation witness publishes false, so the
    # stored fact is recoverable from the published one at every hop.
    delegated = act_as_plane(
        call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),)},
        reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
    ).acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR, via=frozenset({HOP1_SELECTOR}))
    assert delegated.step is not None and delegated.step.admitted_without_a_delegation_witness is False


def test_u1_the_openness_conjunct_is_kept_at_every_hop_and_it_is_attribution():
    """B3, the other half: an OPEN intermediate is refused past hop 1 too.

    Not because the rule is conservative — because it is attribution. A function
    anyone can call moves value that the seized gate did not confer, and charging
    those dollars to this row publishes as gate-conferred a capability the whole
    world already has. It belongs to that function's own finding.
    """
    for openness, expected in (
        ("open", P.ACT_AS_CALL_SITE_IS_PUBLIC),
        ("not_determined", P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED),
    ):
        plane = act_as_plane(
            call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", openness, "vault", True, HOP1_SELECTOR),)},
            reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
        )
        verdict = plane.acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR, via=frozenset({HOP1_SELECTOR}))
        assert verdict.outcome == expected, openness
        assert not verdict.witnessed, openness


def test_u1_case_a_two_hop_chain_composes_through_an_undelegated_intermediate(fold):
    """B3 end to end, on the whole fold: the dollars appear, once.

    The intermediate's calling function is restricted and its gate is a direct
    address check rather than an authority delegation. Hop 1 still requires the
    delegation witness and has it; hop 2 does not require it and does not have
    it, and the chain composes with the relaxation named on the step.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    # the intermediate: gated by msg.sender == solver, no canCall
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", False, HOP1_SELECTOR),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
            )
        ),
    )
    row = _gate_row(document)
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    first, second = entry["act_as_chain"]
    assert first["admitted_without_a_delegation_witness"] is False
    assert second["admitted_without_a_delegation_witness"] is True
    # ...and the same shape at hop 1 still refuses: the seized gate is what the
    # principal holds there, and only a delegated gate is opened by seizing it.
    refused = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", False, CALLING_SELECTOR),)
                },
                reads={(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
            )
        ),
    )
    census = _gate_row(refused)["reach_composition_census"]
    assert census["act_as_refused"] == {P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED: 1}
    assert census["act_as_witnessed"] == 0


def test_u1_case_an_open_intermediate_is_refused_past_hop_1_with_its_reason_named(fold):
    """inv. 13's assertion for the kept conjunct: the lever is not a sink.

    Opening an intermediate's calling function REMOVES this row's charge, so the
    refusal must be published with the attribution reason named rather than left
    as silence a deployer could bank.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "open", "vault", True, HOP1_SELECTOR),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
            )
        ),
    )
    row = _gate_row(document)
    # The vault's $5M is not charged to this row — the teller's own open
    # function is what moves it, and the seized gate conferred nothing there.
    assert [e["entity"] for e in row["reach_composed_magnitudes"]] == []
    # ...and the refusal is NAMED, with the conjunct that decided it.
    assert row["reach_composition_census"]["act_as_refused"][P.ACT_AS_CALL_SITE_IS_PUBLIC] == 1


class _SeedsThatDisownOneMember(set):
    """A ``seeds`` set that enumerates a node and denies membership in it.

    The only way to drive ``_compose``'s frontier to a caller whose ``chains``
    entry is EMPTY: the walk's own bookkeeping cannot produce one (a node enters
    the frontier only after an entry is recorded for it), so the state the
    changed line defends against is reachable only by breaking that bookkeeping
    from outside. ``chains`` and ``frontier`` are built by ENUMERATING seeds
    while the hop-1 test is ``caller in seeds`` — so a member the enumeration
    yields and the membership test denies lands on the frontier, non-seed, with
    no admitted functions.
    """

    def __init__(self, members, disowned):
        super().__init__(members)
        self._disowned = disowned

    def __contains__(self, item) -> bool:
        return item != self._disowned and super().__contains__(item)


def test_u1_an_empty_admitted_set_is_not_the_hop_1_question():
    """``fold._compose``'s fail-open, executed.

    ``_compose`` hands the plane ``frozenset(entries)`` — never
    ``frozenset(entries) or None``. A non-seed node with an EMPTY admitted set
    and a node at hop 1 are different questions, and spelling them identically
    hands the node the UNCONSTRAINED question: the via rule vanishes and the
    finding's seized gate is spent a second time, on a node no hop admitted a
    function of. Empty must reach the plane as a constraint nothing satisfies.
    """
    magnitude = FOLD._DestinationMagnitude(
        state="proven_exact",
        usd=5_000_000.0,
        function="exit",
        execution=EX.not_determined(EX.REASON_NOT_PERSISTED),
    )
    plane = act_as_plane(
        # A call site that WOULD witness at hop 1 — so the old spelling composes
        # the vault's $5M here and the new one refuses it.
        call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),)},
        reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
    )
    admission = FOLD._AdmissionPlanes(CA.admits_every_principal(), P.RouterFlowPlane())
    composed, _census, refused, _withheld = FOLD._compose(
        _SeedsThatDisownOneMember({KEY_C, KEY_T}, KEY_T),
        [
            FOLD._WalkedHop(
                caller=KEY_T, destination=KEY_V, licensed=frozenset({P.LicensedFunction(COMPOSED_SELECTOR, "exit")})
            )
        ],
        plane,
        {(KEY_V, COMPOSED_SELECTOR): magnitude},
        value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C, KEY_T)),
        condition_plane(),
        admission,
        {SAFE},
    )
    assert composed == {}
    assert refused == {P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION: 1}
    # ...and the same node, genuinely a seed, gets the hop-1 question and the
    # $5M — so the refusal above is the empty CONSTRAINT and not a broken case.
    as_seed, _census, _refused, _withheld_seed = FOLD._compose(
        {KEY_C, KEY_T},
        [
            FOLD._WalkedHop(
                caller=KEY_T, destination=KEY_V, licensed=frozenset({P.LicensedFunction(COMPOSED_SELECTOR, "exit")})
            )
        ],
        plane,
        {(KEY_V, COMPOSED_SELECTOR): magnitude},
        value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C, KEY_T)),
        condition_plane(),
        admission,
        {SAFE},
    )
    assert as_seed[KEY_V].usd == 5_000_000.0


# --------------------------------------------------------------------------
# U3 — the composed-candidate tie-break, and the destination's own predicates
# --------------------------------------------------------------------------


def test_u3_a_tied_composed_figure_publishes_the_weakest_witness_state(fold):
    """Two independent calls at one figure: the state published claims the least.

    Both selectors are licensed, both carry a ``flow.out`` witness, and both
    witnesses are the same number. The dollars are therefore not in question and
    the SELECTOR is: whichever candidate wins names the published
    ``witness_state``. Taking the first one offered mints ``proven_exact`` out of
    iteration order while an equally-witnessed candidate at the identical figure
    supports only a floor.
    """
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    row = _gate_row(document)
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert entry["published_usd"] == 1_000_000.0
    # The weaker state wins the tie, although its selector sorts LAST and its
    # candidate is offered second.
    assert entry["selector"] == TIE_SELECTOR
    assert entry["destination_function"] == "manage"
    assert entry["flow_out_witness"]["state"] == "proven_floor"


def test_u3_the_published_chain_is_the_chosen_candidates_own(fold):
    """The whole candidate is selected, never a field of it.

    ``act_as_chain`` is hard-indexed against the function that admitted the
    published selector. A tie-break that changed the selector and left the chain
    behind would publish a path that ends at a different function from the one
    named beside it — with the calling function, the pointer and the block of
    the candidate that lost.
    """
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    (step,) = entry["act_as_chain"]
    assert step["selector"] == entry["selector"]
    assert step["calling_function"] == "manageVaultWithMerkleVerification"
    assert step["calling_selector"] == TIE_CALLING_SELECTOR
    assert (step["receiver_variable"], step["receiver_block"]) == ("vaultPtr", 25_659_227)
    assert "vaultPtr" in step["basis"] and "bulkWithdraw" not in step["basis"]


def test_u3_the_tie_is_disclosed_and_names_every_candidate(fold):
    """An arbitrary rule is only admissible if the document says it ran.

    ``composed_selector_tie`` lists both candidates with the figure and the
    state each supports, marks which one was published, and states the rule.
    Where nothing was decided by the rule it is ``null`` — the proven "one
    candidate" — and never an absent field.
    """
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    tie = entry["composed_selector_tie"]
    assert tie["tied_at_usd"] == 1_000_000.0
    assert tie["candidates"] == [
        {
            "selector": TIE_SELECTOR,
            "destination_function": "manage",
            "witness_state": "proven_floor",
            "witnessed_usd": 1_000_000.0,
            "chosen": True,
        },
        {
            "selector": COMPOSED_SELECTOR,
            "destination_function": "exit",
            "witness_state": "proven_exact",
            "witnessed_usd": 1_000_000.0,
            "chosen": False,
        },
    ]
    assert "weakest witness state" in tie["chosen_by"] and "lowest selector" in tie["chosen_by"]
    assert "not by evidence" in tie["reading"]

    # One candidate: the rule decided nothing, and that is a published fact.
    single = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    assert _gate_row(single)["reach_composed_magnitudes"][0]["composed_selector_tie"] is None


def test_u3_a_candidate_that_loses_on_dollars_is_not_a_tie(fold):
    """The figure is still a MAX: the larger call wins outright and is not tied.

    Two selectors at one entity are two independent calls, so the row publishes
    the best of them. A resolved comparison must not be spelled as a tie —
    ``composed_selector_tie`` names candidates the EVIDENCE could not separate.
    """
    document = fold(_tied_signals(tie_usd=400_000.0), principals=_composing_principals(), **_tied_case())
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert entry["published_usd"] == 1_000_000.0
    assert entry["selector"] == COMPOSED_SELECTOR
    assert entry["flow_out_witness"]["state"] == "proven_exact"
    assert entry["composed_selector_tie"] is None


def _candidate(
    *,
    selector: str = COMPOSED_SELECTOR,
    function: str = "exit",
    state: str = "proven_exact",
    usd: float = 1_000_000.0,
    witnessed_usd: float | None = None,
    steps: tuple[tuple[str, str, str, str, str, int | None], ...] = (
        (KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),
    ),
) -> Any:
    """One composed candidate, every ordering input settable.

    ``steps`` is ``(caller, destination, selector, calling_selector,
    receiver_variable, receiver_block)`` per hop. The DESTINATION is the raw
    anchor the walk landed on, which is not the entity: a proxy and its
    implementation fold to one entity under two anchors, so two candidates can
    carry the same ``entity`` and different step destinations.
    """
    chain = tuple(
        P.ActAsStep(
            caller=caller,
            destination=destination,
            selector=step_selector,
            calling_function=f"call_{calling_selector}",
            calling_function_openness="restricted",
            calling_selector=calling_selector,
            receiver_variable=variable,
            receiver_observed_via="eth_call",
            receiver_block=block,
        )
        for caller, destination, step_selector, calling_selector, variable, block in steps
    )
    return FOLD._ComposedMagnitude(
        entity=KEY_V,
        selector=selector,
        function=function,
        witness_state=state,
        witnessed_usd=usd if witnessed_usd is None else witnessed_usd,
        usd=usd,
        sheet_usd=None,
        chain=chain,
        predicates=P.DestinationPredicates(P.PREDICATES_FUNCTION_NOT_LOCATED, None, None, None, None, 0),
        execution=EX.not_determined(EX.REASON_NOT_PERSISTED),
    )


def _identity(entry: Any) -> tuple[Any, ...]:
    """Everything the published entry is rendered from, chain included.

    The chain is compared through ``as_json`` — the step's whole PUBLISHED
    identity — so this assertion cannot pass by agreeing on a hand-picked subset
    of the fields a reader is shown.
    """
    return (
        entry.usd,
        entry.selector,
        entry.function,
        entry.witness_state,
        tuple(tuple(sorted((k, repr(v)) for k, v in s.as_json().items())) for s in entry.chain),
    )


def test_u3_no_permutation_of_the_candidates_moves_a_dollar():
    """inv. 8 at the composition level: the order is not evidence.

    Seven pools, each tied through the ordering key and separated at exactly ONE
    component, so every component is the deciding one somewhere. Every ordering
    of every pool must select the same entry — same figure, same selector, same
    CHAIN, compared through the step's whole published identity — or some
    published field is a statement about the order the fold happened to build
    the candidates in.
    """
    pools: dict[str, tuple[list[Any], Any]] = {}

    # 1. dollars: the larger call wins outright and is not a tie.
    pools["published_usd"] = (
        [_candidate(usd=900_000.0, selector="0x0a0a0a0a"), _candidate(usd=1_000_000.0)],
        _candidate(usd=1_000_000.0),
    )
    # 2. witness state: the weakest of the tied candidates.
    pools["witness_state"] = (
        [_candidate(state="proven_exact"), _candidate(state="proven_floor", selector=TIE_SELECTOR)],
        _candidate(state="proven_floor", selector=TIE_SELECTOR),
    )
    # 3. selector: lowest, once the state cannot separate them.
    pools["selector"] = (
        [_candidate(selector=TIE_SELECTOR), _candidate(selector=COMPOSED_SELECTOR)],
        _candidate(selector=COMPOSED_SELECTOR),
    )
    # 4. destination function: lowest, once the selector cannot.
    pools["destination_function"] = (
        [_candidate(function="manage"), _candidate(function="exit")],
        _candidate(function="exit"),
    )
    # 5. the chain's calling selectors — the same call site reached under two
    #    different entry functions of the caller.
    pools["calling_selector_chain"] = (
        [
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xbbbb0002", "vault", 1),)),
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
        ],
        _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
    )
    # 6. the chain's own IDENTITY: two different callers whose calling functions
    #    share a selector. Tied through every component above — only the caller,
    #    the pointer and the block differ, and all three are published. The
    #    lowest caller wins: KEY_T is 0x7777..., KEY_C is 0xaaaa....
    pools["chain_identity"] = (
        [
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 11),)),
            _candidate(steps=((KEY_T, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vaultPtr", 22),)),
        ],
        _candidate(steps=((KEY_T, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vaultPtr", 22),)),
    )
    # 7. THE PROXY FOLD. One entity, two raw anchors — an implementation folded
    #    onto its proxy is one entity under two of them — so two candidates
    #    agree on the caller, the selector, the calling selector, the pointer
    #    and the block, and differ only in the step's own ``destination`` and
    #    the basis rendered from it. Both are published; neither is in a
    #    hand-written list of "the fields that identify a step", which is why
    #    the key reads the step's whole published identity instead.
    pools["proxy_folded_destination"] = (
        [
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
            _candidate(steps=((KEY_C, KEY_PROXY, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
        ],
        # KEY_PROXY sorts below KEY_V, and the basis names it first.
        _candidate(steps=((KEY_C, KEY_PROXY, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
    )

    for name, (pool, winner) in pools.items():
        # Every pool must really be tied THROUGH the earlier components, or the
        # case is not testing the component it claims to.
        keys = {FOLD._composed_order(c) for c in pool}
        assert len(keys) == len(pool), name
        expected_ties = sum(1 for c in pool if c.usd == winner.usd) - 1
        selected = [FOLD._select_composed(list(order)) for order in itertools.permutations(pool)]
        assert {_identity(entry) for entry in selected} == {_identity(winner)}, name
        assert {len(entry.tied_with) for entry in selected} == {expected_ties}, name


def test_u3_an_unrankable_witness_state_can_never_win_a_tie():
    """A state the claim map does not know must not be PREFERRED to one it does.

    Ranking an unknown state with the weakest would be the fail-open: "we cannot
    tell what this claims" would beat a state proven to claim little, and an
    unrankable string would be published over a witness. It loses every tie, so
    it reaches the document only where it is the sole candidate — where nothing
    was compared and it is the only thing there is to publish.
    """
    unknown = _candidate(state="not_determined", selector="0x0a0a0a0a")
    for known in (_candidate(state="proven_floor"), _candidate(state="proven_exact")):
        pool = [unknown, known]
        for order in itertools.permutations(pool):
            chosen = FOLD._select_composed(list(order))
            assert chosen.witness_state == known.witness_state
            assert chosen.selector == known.selector
    # Sole candidate: published as it stands, and disclosed as no tie at all.
    alone = FOLD._select_composed([unknown])
    assert alone.witness_state == "not_determined" and alone.tied_with == ()


# --- destination_predicates (B2) -------------------------------------------


AUTH_GUARD = "require(bool,string)(isAuthorized(msg.sender,msg.sig),UNAUTHORIZED)"
TRANSFER_POSTCONDITION = "require(bool,string)(success,TRANSFER_FAILED)"
SSA_MARKER = "safeTransfer(...)"
VAULT_PREDICATES = (AUTH_GUARD, TRANSFER_POSTCONDITION, SSA_MARKER)


def _predicate_plane() -> P.ConditionPlane:
    """The vault's ``exit``, with its stored condition texts and its selector."""
    plane = P.ConditionPlane()
    plane.by_entity = {
        KEY_V: (
            P.DestinationFunction(
                function_id=4242,
                name="exit",
                caller_pinned_to_self=(),
                analysed=True,
                selector=COMPOSED_SELECTOR,
                predicates=VAULT_PREDICATES,
                predicate_entries_stored=len(VAULT_PREDICATES),
            ),
        )
    }
    plane.provenance = {"stub": True}
    return plane


def test_u3_a_composed_entry_publishes_the_destinations_own_predicates(fold):
    """The ceiling claim points at the evidence it was NOT made against.

    The shipped disclosure asserts the destination's own argument semantics went
    unread. Without a pointer that assertion is unfalsifiable by the reader, so
    the entry carries the texts verbatim, in stored order, from the canonical
    column — and says in the same object that it evaluated none of them.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(conditions=_predicate_plane()),
    )
    entry = _gate_row(document)["reach_composed_magnitudes"][0]
    block = entry["destination_predicates"]
    assert block["source"] == "effective_functions.conditions"
    assert block["state"] == P.PREDICATES_EXTRACTED
    assert block["function_id"] == 4242
    assert block["count"] == 3 and block["entries_stored"] == 3
    # Verbatim and in STORED order — not sorted, not deduped, not filtered.
    assert block["descriptions"] == list(VAULT_PREDICATES)
    # Nothing is filtered out by kind: the authorization guard this step's own
    # witness proves satisfied, a transfer post-condition and an SSA call marker
    # all stay, which is why the block is not readable as unmet conditions.
    assert AUTH_GUARD in block["descriptions"] and SSA_MARKER in block["descriptions"]
    assert block["evaluated"] is False
    for fragment in ("WITHOUT POLARITY", "EVALUATES", "authorization guard"):
        assert fragment in block["reading"], fragment
    # The reading's clause (4) pointed at caller_holding_precondition, which is
    # cut — a dangling cross-reference is a claim that a field exists.
    assert "caller_holding_precondition" not in block["reading"]
    assert "bound_kind" not in block


def test_u3_the_predicates_ride_on_both_act_as_witness_shapes(fold):
    """The disclosure is a DESTINATION fact and does not depend on how it was reached.

    An ACL-admitted step and a state-variable step publish the same destination
    function's predicates — the block describes the callee's body, not the
    witness that got there.
    """
    shapes = {
        P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE: _composing_case(conditions=_predicate_plane()),
        P.ACT_AS_WITNESS_DESTINATION_ACL: _composing_case(act_as=_acl_plane(), conditions=_predicate_plane()),
    }
    for kind, case in shapes.items():
        document = fold(_composing_signals(), principals=_composing_principals(), **case)
        entry = _gate_row(document)["reach_composed_magnitudes"][0]
        assert {step["witness_kind"] for step in entry["act_as_chain"]} == {kind}, kind
        assert entry["destination_predicates"]["descriptions"] == list(VAULT_PREDICATES), kind


def test_u3_the_predicate_lookup_keeps_its_three_states():
    """ "No predicate was stored" is three different facts and each keeps its name.

    An extraction that ran and found nothing is a read; a column holding no
    array is an extraction that never ran; and no function under that selector
    is a join that missed. Collapsing any two would publish a coverage gap as a
    proven absence of guards.
    """
    plane = P.ConditionPlane()
    plane.by_entity = {
        KEY_V: (
            P.DestinationFunction(1, "exit", (), True, COMPOSED_SELECTOR, VAULT_PREDICATES, 3),
            P.DestinationFunction(2, "manage", (), True, TIE_SELECTOR, (), 0),
            P.DestinationFunction(3, "sweep", (), False, "0x0a0a0a0a", (), 0),
            P.DestinationFunction(4, "unnamed", (), True, None, ("x == 1",), 1),
        )
    }
    extracted = plane.predicates(KEY_V, COMPOSED_SELECTOR)
    assert extracted.state == P.PREDICATES_EXTRACTED
    assert extracted.descriptions == VAULT_PREDICATES and extracted.functions_matching == 1

    # Extracted and EMPTY: a read that found no predicate, not a missing read.
    empty = plane.predicates(KEY_V, TIE_SELECTOR)
    assert empty.state == P.PREDICATES_EXTRACTED and empty.descriptions == ()

    unextracted = plane.predicates(KEY_V, "0x0a0a0a0a")
    assert unextracted.state == P.PREDICATES_COLUMN_HOLDS_NO_ARRAY
    assert unextracted.descriptions is None and unextracted.entries_stored is None

    for missing in ("0xdeadbeef", ""):
        absent = plane.predicates(KEY_V, missing)
        assert absent.state == P.PREDICATES_FUNCTION_NOT_LOCATED, missing
        assert (absent.function_id, absent.descriptions) == (None, None), missing
    # A function whose own selector was never extracted matches nothing: four
    # bytes nobody recorded do not name a function.
    assert plane.predicates(KEY_V, "0x00000000").state == P.PREDICATES_FUNCTION_NOT_LOCATED
    assert plane.predicates("ethereum::0xnothing", COMPOSED_SELECTOR).state == P.PREDICATES_FUNCTION_NOT_LOCATED


def test_u3_the_predicate_texts_are_read_verbatim_from_the_stored_array():
    """The canonical column, unfiltered — and an entry with no text is counted.

    ``kind`` is not read (the extractor labels everything ``business``), nothing
    is deduped or reordered, and an entry carrying no string ``description``
    raises ``entries_stored`` above the text count instead of disappearing.
    """
    texts, entries = P._stored_predicates(
        [
            {"kind": "business", "description": AUTH_GUARD},
            {"kind": "business", "description": AUTH_GUARD},
            {"kind": "reentrancy", "description": "$._status == ENTERED"},
            {"kind": "business"},
            "not an object",
        ]
    )
    assert texts == (AUTH_GUARD, AUTH_GUARD, "$._status == ENTERED")
    assert entries == 5
    # A column holding no array is an extraction that never ran.
    assert P._stored_predicates(None) == ((), 0)
    assert P._stored_predicates("[]") == ((), 0)


# --------------------------------------------------------------------------
# Code-control sheet ceiling (CC1-CC7)
#
# The defect: code control had no magnitude path at all. "Which function does
# replacing the whole implementation let you call" has no answer, so every
# code-control row fell through to not_determined and the largest capabilities
# in a protocol ranked below a ninety-dollar withdrawal. The fix is not a
# re-admission of the balance sheet — it is one branch, over one entity, under
# one argument: replacing what a node DOES removes the node's own code from
# between the principal and what the node holds, so the node's own priced sheet
# bounds the move from ABOVE. Every case below pins a boundary of that argument.
# --------------------------------------------------------------------------


def test_cc1_code_control_over_a_priced_node_is_priced_at_that_nodes_own_sheet(fold):
    """The branch, whole: a figure, a band, a ceiling and an execution answer.

    The capability is proven over the node the signal was distilled on, and that
    node's sheet is priced. Nothing further has to be witnessed for "how much can
    they move" to have an answer, because the code that would have stood in the
    way is the code being replaced — so the figure is published, banded, and
    typed as an upper bound rather than as an amount.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    finding = _cc_row(document)
    assert finding["value_at_stake_usd"] == 5_000_000.0
    assert finding["value_state"] == VALUE_STATE_PROVEN_REACH
    assert finding["value_by_entity"] == {KEY_C: 5_000_000.0}
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    # SPLIT, never widened: a consumer joining the composed list to
    # reach_composed_magnitudes[] must not find a sheet entity in it.
    assert finding["entities_priced_from_a_composed_ceiling"] == []
    assert finding["reach_composed_magnitudes"] == []
    # The row's one entity is a ceiling, nothing is missing from the sum, and
    # the b7 conjunction is therefore satisfied from the SHEET source — the
    # second producer that direction has ever had.
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert finding["value_at_stake_is_floor"] is False
    assert finding["value_band"] == "<= $1M-$10M"
    assert finding["value_at_stake_basis"].startswith("<= ")
    assert "SHEET CEILING" in finding["value_at_stake_basis"]

    entry = finding["reach_sheet_ceiling_magnitudes"][0]
    assert entry["entity"] == KEY_C
    assert entry["published_usd"] == entry["sheet_usd"] == 5_000_000.0
    assert entry["sheet_state"] == P.SHEET_PRICED
    assert entry["ceiling_reason"] == P.CEILING_ADMITTED
    # The full-coverage carrier of the per-entity direction, which the reference
    # corpus has none of: every asset observed here was priced, so the figure
    # bounds the move from above and the entry says so. The observations it
    # stands on are published beside it — a reading naming evidence the document
    # does not carry is the defect the execution block exists on the far side of.
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert entry["assets_observed"] == entry["assets_priced"] == 1
    assert entry["assets_not_priced"] == []
    assert entry["unpriced_positions"] == 0
    assert entry["per_asset"] == [{"asset": "usdc", "usd": 5_000_000.0, "state": P.ASSET_PRICED}]
    assert "every asset observed at this entity carries a determined reading" in entry["bound_direction_basis"]
    assert finding["reach_sheet_ceiling_magnitudes_withheld"] == []
    # The #170 answer. A sheet ceiling is proven by a BALANCE OBSERVATION, so
    # there is no execution to name — and the reason saying so must never be a
    # fault, which would qualify the whole document off an intact proof.
    execution = entry[EX.PROVING_EXECUTION_KEY]
    assert execution["state"] == EX.EXECUTION_NOT_DETERMINED
    assert execution["reason"] == EX.REASON_NOT_PROVEN_BY_A_CALL
    assert EX.REASON_NOT_PROVEN_BY_A_CALL in EX.NOT_DETERMINED_REASONS
    assert EX.REASON_NOT_PROVEN_BY_A_CALL not in EX.FAULT_REASONS
    # The reason rides a proving_execution key, so the structural census walks
    # it. A fault reason here would qualify the whole document off a proof that
    # is intact, which is why the reason's registration is the load-bearing half.
    assert FOLD._execution_fault_census(document.findings, document.provenance["subsumed_rows"]) is None
    # The census counts it as a third answer. Left in magnitude_not_witnessed it
    # would sit in the population that census says publishes not_determined at
    # the unpriced band's floor, which is the one thing it does not do.
    census = finding["magnitude_witness_census"]
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["magnitude_not_witnessed"] == 0
    assert census["magnitude_composed"] == 0


def test_cc2_gate_control_over_the_same_node_earns_no_ceiling(fold):
    """The anti-regression case, and the whole reason the split exists.

    Same principal, same node, same priced sheet — only the capability class
    differs. Seizing who MAY CALL leaves the node's own code, its share math and
    its caller conditions all standing, none of which has been examined, so the
    sheet is an upper bound on an upper bound and stays not_determined. If this
    row ever earns a figure, the reach-model fix has been undone under a new
    name over a much larger population than the one the ceiling prices.
    """
    plane = value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    principals = {1: facts(1, EOA, "eoa")}
    for capability in sorted(FOLD.K.GATE_CONTROL_CAPABILITIES):
        signal = sig(
            claim_id=capability,
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            **proven(1.0),
            **reaches(KEY_C),
        )
        finding = _cc_row(fold([signal], principals=principals, value=plane), capability)
        assert finding["value_at_stake_usd"] is None, capability
        assert finding["value_state"] == "not_determined", capability
        assert finding["entities_priced_from_a_sheet_ceiling"] == [], capability
        assert finding["reach_sheet_ceiling_magnitudes"] == [], capability
        assert finding["value_band"] == "not_determined", capability


def test_cc3_a_downstream_entity_of_a_code_controlled_node_earns_no_ceiling(fold):
    """§3.2, the constraint that keeps this from undoing the reach-model fix.

    Code control expands over the closure — owning A's code lets A do everything
    A is authorised to do — but for a downstream B that A merely governs you are
    back in the gate-control situation one level down: B's own code is still
    standing. So the ceiling is the CONTROLLED node's and nothing else's, even
    though the row provably reaches both and both are priced.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        closure={KEY_C: {KEY_V}},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 900_000_000.0}}),
    )
    finding = _cc_row(document)
    assert KEY_V in finding["reach_entities"]
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    assert finding["value_by_entity"] == {KEY_C: 1_000_000.0}
    assert finding["value_at_stake_usd"] == 1_000_000.0
    # The downstream entity is DISCLOSED as unmeasured, never dropped and never
    # summed: the row reaches it and no witness says what the reach moves there.
    assert KEY_V in {row["entity"] for row in finding["undetermined_instances"]}


@pytest.mark.parametrize(
    ("per_asset", "state", "reason"),
    [
        ({}, P.SHEET_NO_ROWS, P.CEILING_NO_ROWS),
        ({"usdc": 0.0}, P.SHEET_BELOW_RESOLUTION, P.CEILING_BELOW_RESOLUTION),
        ({}, P.SHEET_UNPRICED, P.CEILING_UNPRICED),
    ],
)
def test_cc4_an_undetermined_sheet_refuses_under_its_own_reason(fold, per_asset, state, reason):
    """The three refusals stay three, and each names the pipeline that owes it.

    A dust sheet, an unpriced one and one nobody ever observed are three
    different facts — the first two have balances and no usable price, the third
    has no balance observation at all — and collapsing them would report a
    price-feed gap as a coverage gap. The figure is not_determined on all three,
    and the row still exists: membership was proven and only the magnitude was
    not.
    """
    states = {
        P.SHEET_BELOW_RESOLUTION: {KEY_C: {"usdc": P.ASSET_BELOW_RESOLUTION}},
        P.SHEET_UNPRICED: {KEY_C: {"usdc": P.ASSET_UNPRICED}},
        P.SHEET_NO_ROWS: {},
    }[state]
    plane = value_plane({KEY_C: per_asset} if per_asset else {}, contracts=(KEY_C,), per_asset_state=states)
    assert plane.sheet_state(KEY_C) == state
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    finding = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] is None
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert finding["reach_sheet_ceiling_magnitudes"] == []
    # The refusal carries its own typed reason into the row's why vocabulary.
    # It is NOT a composition arm: nothing was composed and no arm was taken.
    assert [row["why"] for row in finding["undetermined_instances"]] == [
        f"code_control_sheet_ceiling_refused({reason})"
    ]


def test_cc4_a_proven_empty_sheet_is_a_zero_ceiling_not_a_missing_one(fold):
    """The EARNED NEGATIVE arm, which the reference corpus cannot exercise.

    ``ValuePlane.total`` returns ``0.0`` for a proven-empty sheet, so a naive
    ``total is not None`` check admits it and a naive ``== priced`` check
    silently refuses it. Neither reading is the right one: every asset's
    QUANTITY is witnessed zero here, which is a proof that replacing this node's
    code moves nothing — and publishing not_determined over a proven zero is an
    under-claim by this repo's own discipline. It bands at the floor either way;
    what differs is the STATE, and the state is the whole point.
    """
    plane = value_plane(
        {KEY_C: {"usdc": 0.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY_C: SCANNED},
    )
    assert plane.sheet_state(KEY_C) == P.SHEET_PROVEN_EMPTY
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    finding = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] == 0.0
    assert finding["value_state"] == VALUE_STATE_PROVEN_REACH
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    entry = finding["reach_sheet_ceiling_magnitudes"][0]
    assert entry["ceiling_reason"] == P.CEILING_PROVEN_EMPTY
    assert entry["sheet_state"] == P.SHEET_PROVEN_EMPTY
    assert entry["published_usd"] == 0.0
    # Its own sentence. A proven zero described with the priced sheet's sentence
    # would call an earned negative an observation of holdings.
    assert "PROVEN ZERO" in entry["reading"]
    assert entry["reading"] != FOLD._CEILING_SOURCE_READINGS[(P.CEILING_ADMITTED, True)] + FOLD._CEILING_CLOSING
    # Every observed asset is a witnessed zero and no position carries an absent
    # USD column, so this $0 IS an at-most on the move — the one arm where the
    # coverage conjunct and the earned negative agree.
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert entry["assets_not_priced"] == [] and entry["unpriced_positions"] == 0

    # The CROSS-PLANE gate, which used to be a shade of this arm and is now a
    # refusal. A restaking position at the same node carries no USD column at
    # all, so "every asset is a witnessed zero" is a fact about the PRICED sheet
    # while the node demonstrably holds something — and a $0 published there
    # would contradict a plane already in the same document AND bound a
    # magnitude at zero over holdings nobody priced. The sheet refuses the empty
    # state outright and publishes unpriced, so the entity earns no ceiling at
    # all rather than a $0 one wearing a not_determined direction.
    positions = value_plane(
        {KEY_C: {"usdc": 0.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY_C: SCANNED},
    )
    positions.unpriced_positions = {KEY_C: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 3e19}]}
    assert positions.proven_empty_refusal(KEY_C) == P.EMPTY_REFUSED_UNPRICED_POSITIONS
    assert positions.sheet_state(KEY_C) == P.SHEET_UNPRICED
    assert positions.total(KEY_C) is None
    assert P.ceiling_for(positions, KEY_C) == (None, P.CEILING_UNPRICED)
    partial = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=positions))
    assert partial["reach_sheet_ceiling_magnitudes"] == []
    assert partial["entities_priced_from_a_sheet_ceiling"] == []
    assert f"code_control_sheet_ceiling_refused({P.CEILING_UNPRICED})" in [
        instance["why"] for instance in partial["undetermined_instances"]
    ]


def test_cc4_a_shared_implementation_earns_no_ceiling(fold):
    """The alias conjunct, refused by the guard that runs before every branch.

    An implementation two proxies share folds onto neither — pinning one is a
    coin toss that charges the loser's sheet — and ``_entity_contribution``
    refuses such a key outright, ahead of the witnessed, composed and ceiling
    branches alike. So the ceiling resolver's own ``alias_ambiguous`` token is
    unreachable through the fold, which is why it is registered as an arm with
    no published carrier rather than as one nobody has looked for.
    """
    plane = value_plane({KEY_IMPL: {"usdc": 9_000_000.0}}, contracts=(KEY_PROXY,))
    plane.alias_ambiguous = {KEY_IMPL}
    signal = sig(
        deployment_address=IMPL,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_IMPL),
    )
    finding = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] is None
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert [row["why"] for row in finding["undetermined_instances"]] == [
        "shared_implementation_folds_onto_no_proxy(not_determined)"
    ]
    # The resolver would have answered its own token had it been asked.
    assert P.ceiling_for(plane, KEY_IMPL) == (None, P.CEILING_ALIAS_AMBIGUOUS)


def test_cc5_pause_over_a_priced_node_stays_not_determined(fold):
    """The freeze fraction is untouched, and it is not an oversight.

    Pausing is not code control: you do not get to rewrite anything, and nothing
    in this pipeline witnesses what SHARE of a sheet a pause immobilises. The
    capability reaches the same node as the upgrade row and prices none of it.
    """
    signal = pause_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(FREEZE_CAPABILITY_PROVEN, ("freeze_capability_proven",)),
        **reaches(KEY_C),
    )
    finding = _cc_row(
        fold([signal], principals={1: facts(1, EOA, "eoa")}, value=value_plane({KEY_C: {"usdc": 5_000_000.0}})),
        "pause.set",
    )
    assert finding["value_at_stake_usd"] is None
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert finding["reach_sheet_ceiling_magnitudes"] == []


def test_cc6_two_holders_over_one_ceiling_do_not_flatten(fold):
    """The standing objection: does every upgradeable protocol pin the meter?

    It does not, because value and difficulty are separate axes. Same node, same
    $3.62B-shaped ceiling, two principals at different weakness rungs — the
    ratio of their raw_points is exactly the ratio of their rungs, on a scale
    that now knows there are billions behind the door instead of one that
    scored both at the unpriced floor.
    """
    signals = [
        sig(
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            **proven(1.0),
            **reaches(KEY_C),
        ),
        sig(
            function_name="g",
            selector="0xfeedface",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
            **proven(1.0),
            **reaches(KEY_C),
        ),
    ]
    document = fold(
        signals,
        principals={
            1: facts(1, EOA, "eoa"),
            2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3),
        },
        value=value_plane({KEY_C: {"usdc": 5_000_000_000.0}}),
    )
    rows = {f["principal_unit"]: f for f in document.findings}
    eoa_row = rows[entity_key("ethereum", EOA)]
    safe_row = rows[entity_key("ethereum", SAFE)]
    assert eoa_row["value_at_stake_usd"] == safe_row["value_at_stake_usd"] == 5_000_000_000.0
    assert eoa_row["value_band"] == safe_row["value_band"] == "<= >$1B"
    # Identical severity and band, so the ONLY thing separating them is the rung.
    assert eoa_row["raw_points"] / safe_row["raw_points"] == pytest.approx(eoa_row["weakness"] / safe_row["weakness"])
    assert eoa_row["weakness"] > safe_row["weakness"]


def test_cc7_a_sheet_ceiling_charges_the_exposure_budget_nothing(fold):
    """§6.4. Ceilings are risk-weighted upper bounds, never expected loss.

    Two things go wrong if a sheet ceiling enters the numerator, and only the
    first is obvious. It inflates ``exposure_usd`` off bounds — and the coverage
    disclosure built to say "almost nothing was measurable" would then claim
    near-total coverage on the strength of them. It also SPENDS the entity's
    budget, so a later row that measured a real extraction at the same entity is
    trimmed to its marginal share by a row that measured nothing.

    Here the flow.out row measures a real $2M at the shared entity. The ceiling
    row reaches it too and must leave the budget untouched.
    """
    ceiling_row = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    measured = flow_sig(
        function_name="withdraw",
        selector="0x11112222",
        deployment_address=VAULT,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        gates=bounded_by_sheet(2_000_000.0),
        **proven(0.9),
        **reaches(KEY_C),
    )
    document = fold(
        [ceiling_row, measured],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}),
    )
    upgrade = _cc_row(document)
    flow = _cc_row(document, "flow.out")
    assert upgrade["value_at_stake_usd"] == 5_000_000.0
    # The ceiling row publishes dollars and charges NOTHING.
    assert upgrade["exposure_usd"] is None
    assert upgrade["exposure_entities_charged"] == []
    # The measuring row keeps its whole fraction: the ceiling spent none of it.
    assert flow["exposure_usd"] == pytest.approx(2_000_000.0 * flow["severity_proven"] * flow["weakness"])
    gaps = {(g["principal_unit"], g["capability"]): g for g in document.provenance["exposure_gaps"]}
    ceiling_gap = gaps[(upgrade["principal_unit"], "upgrade.implementation")]
    assert ceiling_gap["ceiling_entities_excluded_from_exposure"] == [KEY_C]
    assert ceiling_gap["budget_exhausted_entities"] == []
    assert ceiling_gap["budget_partially_exhausted_entities"] == []
    assert "ceiling_entities_excluded_from_exposure" in ceiling_gap["reading"]
    # The finding lands in the undetermined bucket of the coverage disclosure,
    # which is what keeps tracked_share_measured_pct honest.
    coverage = document.provenance["exposure_coverage"]
    assert coverage["findings_with_exposure_not_determined"] >= 1
    # The ceiling row's dollars are absent from the charged perimeter: charging
    # them is what would have flipped this disclosure from "almost nothing was
    # measurable" to a near-total coverage claim built out of upper bounds.
    assert coverage["perimeter_usd_charged"] == pytest.approx(5_000_000.0)


def test_cc7_the_ceiling_is_capped_per_key_and_never_per_row(fold):
    """S6. A row's total sums across its priced hosts and may exceed any sheet.

    "Capped by the node's own sheet" is true of every KEY and false of the row —
    the reference corpus publishes $4.217B over eight hosts, more than the
    largest of them — so the invariant is checked per key here. A per-row
    assertion would fire on the correct answer.
    """
    signals = [
        sig(
            deployment_address=address,
            function_name=name,
            selector=selector,
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            **proven(1.0),
            **reaches(key),
        )
        for address, name, selector, key in (
            (C, "f", "0xdeadbeef", KEY_C),
            (VAULT, "g", "0xfeedface", KEY_V),
        )
    ]
    plane = value_plane({KEY_C: {"usdc": 3_000_000.0}, KEY_V: {"usdc": 4_000_000.0}})
    finding = _cc_row(fold(signals, principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] == 7_000_000.0
    for entry in finding["reach_sheet_ceiling_magnitudes"]:
        assert entry["published_usd"] == plane.total(entry["entity"])
        assert entry["published_usd"] < finding["value_at_stake_usd"]


def test_cc_the_ceiling_reason_vocabulary_is_closed_and_ordered():
    """The tokens are document-visible now, so the tuple is pinned literally.

    ``ceiling_reason`` is published on every sheet-ceiling entry and the two
    admitting reasons are what the fold branches on. A token added, renamed or
    reordered here is a change to what a consumer reads, not an internal detail.
    """
    assert P.CEILING_REASONS == (
        "admitted",
        "proven_empty",
        "airdrop_determined",
        "no_rows",
        "below_resolution",
        "unpriced",
        "asset_list_truncated",
        "alias_ambiguous",
    )
    assert P.CEILING_ADMITTING_REASONS == ("admitted", "proven_empty", "airdrop_determined")
    assert set(P.CEILING_ADMITTING_REASONS) < set(P.CEILING_REASONS)
    # The three admits are three PROOFS and stay three tokens: a priced sheet
    # bounds at an observed number, a proven-empty one at a witnessed zero, and
    # an airdrop-determined one at a zero earned from DELIVERY SHAPE. Nothing
    # here may be renamed to a claim about worth.
    assert len(set(P.CEILING_ADMITTING_REASONS)) == 3
    assert not {"spam", "scam", "worthless"} & set(P.CEILING_REASONS)


def test_cc1_a_partly_priced_sheet_bounds_the_priced_portion_and_not_the_move(fold):
    """SHEET_PRICED is a FLOOR over what was priced, so the ceiling is conditional.

    An entity with one priced asset and one nobody priced holds MORE than its
    total, so "at most $X" is false of it — the figure bounds the priced portion
    and says nothing about the rest. Publishing ``ceiling`` on that entry would
    claim an at-most over holdings this fold never observed, and would contradict
    the row header, which refuses a ceiling on exactly this conjunct. Both
    surfaces read the same predicate so they cannot answer it differently.

    The dollars, the band and the admission are untouched: this is what the row
    CLAIMS about its figure, not which figure it publishes.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    finding = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] == 5_000_000.0
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]

    entry = finding["reach_sheet_ceiling_magnitudes"][0]
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert entry["assets_observed"] == 2 and entry["assets_priced"] == 1
    assert entry["assets_not_priced"] == ["wsteth"]
    assert {a["asset"]: a["usd"] for a in entry["per_asset"]} == {"usdc": 5_000_000.0, "wsteth": None}
    assert "DO NOT bound the move" in entry["reading"]
    assert "AT-MOST" not in entry["reading"].split(". Whatever it bounds")[0]
    # The row header refuses on the same fact, from the same predicate.
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # A below-resolution reading is the same shortfall as an unpriced one: a
    # holding of at most half a cent the total does not carry.
    dust = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "weth": P.ASSET_BELOW_RESOLUTION}},
    )
    dusty = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=dust))
    assert dusty["reach_sheet_ceiling_magnitudes"][0]["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # And an unpriced POSITION defeats it with every asset priced: the restaking
    # plane has no USD column at all, so a position there is unpriced by
    # construction and the sheet does not cover the entity either.
    positions = value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    positions.unpriced_positions = {KEY_C: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 3e19}]}
    with_positions = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=positions))
    held = with_positions["reach_sheet_ceiling_magnitudes"][0]
    assert held["unpriced_positions"] == 1
    assert held["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED


def test_cc7_a_subsumed_rows_sheet_ceiling_leaks_into_the_budget_in_neither_direction(fold):
    """The subsumption path, both leaks, on ONE principal unit.

    Subsumption keeps a unit's top row and folds the rest away, but value only a
    subsumed row reaches still charges the top row's exposure. Two things go
    wrong there once a sheet ceiling exists, and they go wrong in opposite
    directions.

    IN: a subsumed row's ceiling at an entity the top row does not price is
    exclusive value, and the exposure skip reads the TOP row's ceiling list —
    which does not name it. The ceiling would charge a budget its own row's copy
    is exempt from.

    OUT: the top row's ceiling at an entity makes the occupancy test treat that
    key as taken, so a subsumed row's genuinely WITNESSED value there is
    discarded — and the top row charges nothing for it either, so measured
    dollars leave the accounting altogether.
    """
    # Top row: upgrade.implementation at C, ceilinged at C's own sheet.
    top = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    # Subsumed, same unit: a witnessed figure at the entity the top row ceilings
    # (the OUT leak), and a ceiling of its own at an entity the top row does not
    # reach (the IN leak).
    witnessed_at_c = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        selector="0x11112222",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(400_000.0),
        **proven(0.5),
        **reaches(KEY_C),
    )
    ceiling_at_v = sig(
        claim_id="exec.arbitrary",
        function_name="execute",
        selector="0x33334444",
        deployment_address=VAULT,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.4),
        **reaches(KEY_V),
    )
    document = fold(
        [top, witnessed_at_c, ceiling_at_v],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}, KEY_V: {"usdc": 900_000.0}}),
    )
    finding = _cc_row(document)
    assert finding["capability"] == "upgrade.implementation"
    assert [r["capability"] for r in finding["subsumed_capabilities"]] == ["authority.replace", "exec.arbitrary"]

    exclusive = finding["subsumed_exclusive_value_by_entity"]
    # OUT: the top row prices C from a ceiling and charges nothing there, so the
    # key is NOT occupied and the subsumed row's witnessed $400k survives.
    assert KEY_C in exclusive and exclusive[KEY_C]["usd"] == 400_000.0
    # IN: the vault arrives as exclusive value AND is named as a ceiling, so the
    # exposure loop can tell it apart from the witnessed figure beside it.
    assert KEY_V in exclusive
    assert finding["subsumed_exclusive_sheet_ceiling_entities"] == [KEY_V]

    # The budget charges the witnessed dollars and only those.
    assert finding["exposure_usd"] == pytest.approx(400_000.0 * exclusive[KEY_C]["fraction"])
    assert finding["exposure_entities_charged"] == [KEY_C]
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if (g["principal_unit"], g["capability"]) == (finding["principal_unit"], "upgrade.implementation")
    )
    # Only the vault. The top row's ceiling at C was skipped and the subsumed
    # row's witnessed figure charged in its place, so nothing at C was lost to a
    # ceiling and nothing is disclosed as excluded there.
    assert gap["ceiling_entities_excluded_from_exposure"] == [KEY_V]
    assert gap["budget_exhausted_entities"] == [] and gap["budget_partially_exhausted_entities"] == []


# --------------------------------------------------------------------------
# The confidence side of the ceiling (CC8)
#
# The reach-magnitude term asks "was this reach's magnitude answered", and it
# credited a signal on exactly two paths: a witness on its own call, or a
# composed destination witness. A sheet ceiling is a THIRD answer — a proven
# bound, from a balance observation — and leaving it uncredited would report a
# question as open that the document answers on its own page. The cases below
# pin what is credited, what is not, and that the credit is not the vacuous kind.
# --------------------------------------------------------------------------


def _magnitude(document) -> dict[str, Any]:
    return document.model_parameters["confidence_detail"]["reach_magnitude_signals"]


def _ceiling_signal(**over: Any) -> FunctionSignal:
    """Code control at ``C``, proven for an EOA, reaching ``C`` itself.

    The overrides are MERGED rather than splatted after the defaults so a case
    can move the signal to another deployment or another reach without the
    keyword colliding with the default it means to replace.
    """
    base: dict[str, Any] = {
        "authority_openness": "restricted",
        "principal_state": "enumerated",
        "principal_refs": (PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    }
    return sig(**{**base, **over})


def test_cc8_a_sheet_ceiling_answers_the_reach_magnitude_question(fold):
    """The third credit path, counted under its own name.

    The signal carries no magnitude witness of its own and composes nothing —
    code control names no destination function — so before this path it was
    counted as an open question while the row beside it published a banded
    figure. The term now credits it, and the credit is counted APART from the
    other two: the three answers are three different proofs of three different
    strengths, and a consumer sizing what the pipeline MEASURED has to be able to
    subtract the one that only bounds.
    """
    document = fold(
        [_ceiling_signal()],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    census = _magnitude(document)
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["sheet_ceiling_by_capability"] == {"upgrade.implementation": 1}
    # Counted as ANSWERED in the term's own census, and by neither of the two
    # older paths.
    assert census["by_capability"]["upgrade.implementation"] == [1, 1]
    assert census["magnitude_witnessed"] == 1
    assert census["magnitude_composed"] == 0
    assert document.model_parameters["confidence_detail"]["reach_magnitude_witnessed_pct"] > 0.0
    # And it has a carrier: the row publishes the figure the credit is for.
    assert _cc_row(document)["entities_priced_from_a_sheet_ceiling"] == [KEY_C]


def test_cc8_a_refused_sheet_ceiling_is_not_credited(fold):
    """No ceiling, no credit. The anti-regression for "reached money, so answered".

    The capability is the same code control over the same key; only the SHEET
    differs. Nothing was observed at the node, so nothing bounds the move, and
    the magnitude question is exactly as open as it was — crediting it here would
    answer it with a number no row publishes, which is the whole failure mode the
    credit population was scoped to avoid.
    """
    plane = value_plane({}, contracts=(KEY_C,), per_asset_state={KEY_C: {}})
    assert plane.sheet_state(KEY_C) == P.SHEET_NO_ROWS
    document = fold([_ceiling_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane)
    census = _magnitude(document)
    assert census["magnitude_sheet_ceiling"] == 0
    assert census["sheet_ceiling_by_capability"] == {}
    assert census["by_capability"]["upgrade.implementation"] == [0, 1]
    assert _cc_row(document)["entities_priced_from_a_sheet_ceiling"] == []


def test_cc8_gate_control_over_a_priced_node_earns_no_ceiling_credit(fold):
    """CC2's anti-regression, one level up.

    The node is priced and the reach is proven; the capability is not code
    control, so the vault's own share math, caps and caller conditions are all
    still standing and none of them has been examined. The row earns no ceiling
    and the term must not credit one either — the two surfaces answer the same
    question and a credit the row cannot show is a credit with no carrier.
    """
    signal = _ceiling_signal(claim_id="authority.replace", function_name="setAuthority", selector="0x11112222")
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    census = _magnitude(document)
    assert census["magnitude_sheet_ceiling"] == 0
    assert census["by_capability"]["authority.replace"] == [0, 1]
    assert _cc_row(document, "authority.replace")["entities_priced_from_a_sheet_ceiling"] == []


def test_cc8_a_ceiling_credit_is_not_vacuous_credit(fold):
    """It carries a witness — the balance observation — so the vacuous share stays put.

    ``reach_magnitude_vacuous_credit_pct`` exists because a proven-codeless
    entity answers this term with no magnitude witness AT ALL, and publishing the
    headline alone would let a perimeter full of EOAs read as answered magnitude.
    A sheet ceiling is the opposite case: the question is answered because
    something was OBSERVED. So the ceiling has to move the witnessed term while
    leaving the vacuous share exactly where it was, and the two figures are read
    together here because subtracting one from the other is what a consumer does.
    """
    # The two documents differ ONLY in the capability, so the perimeter, the
    # denominator and the codeless entity's weight are identical in both and the
    # ceiling credit is the single moving part. Varying the SHEET instead would
    # move the entity's own band and change the denominator underneath the
    # comparison.
    eoa_key = entity_key("ethereum", EOA)

    def _document(**over: Any):
        return fold(
            [_ceiling_signal(**over)],
            principals={1: facts(1, EOA, "eoa")},
            value=value_plane(
                {KEY_C: {"usdc": 5_000_000.0}},
                contracts=(KEY_C, eoa_key),
                per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}},
            ),
            eoas={eoa_key},
        )

    with_ceiling = _document()
    without = _document(claim_id="authority.replace", function_name="setAuthority", selector="0x11112222")
    ceiling_detail = with_ceiling.model_parameters["confidence_detail"]
    plain_detail = without.model_parameters["confidence_detail"]
    assert _magnitude(with_ceiling)["magnitude_sheet_ceiling"] == 1
    assert _magnitude(without)["magnitude_sheet_ceiling"] == 0
    assert ceiling_detail["reach_magnitude_vacuous_credit_pct"] > 0.0
    assert ceiling_detail["reach_magnitude_vacuous_credit_pct"] == plain_detail["reach_magnitude_vacuous_credit_pct"]
    assert ceiling_detail["reach_magnitude_witnessed_pct"] > plain_detail["reach_magnitude_witnessed_pct"]
    # The witness-backed share is what moved.
    assert (
        ceiling_detail["reach_magnitude_witnessed_pct"] - ceiling_detail["reach_magnitude_vacuous_credit_pct"]
        > plain_detail["reach_magnitude_witnessed_pct"] - plain_detail["reach_magnitude_vacuous_credit_pct"]
    )
    # And the term's HEADROOM is a different quantity that neither case moves:
    # the name collision is one field apart and they must not track each other.
    assert ceiling_detail["reach_magnitude_ceiling_pct"] == plain_detail["reach_magnitude_ceiling_pct"]


def test_cc8_every_credited_ceiling_has_a_carrier_in_the_published_document(fold):
    """The S4 population rule, over a document that carries both answers.

    The credited set is the fold's OWN per-entity standing set: the signals whose
    sheet ceiling is the figure a row actually publishes at that entity. That
    rule has two revocations built into it — a ceiling a larger contribution
    displaces, and one the per-key sheet reconciliation withdraws — and neither
    is constructible from this fixture, for a reason worth recording rather than
    working around. Every alternative candidate at the controlled node is
    ``min(held, magnitude)`` against that node's own sheet (``fold._entity_contribution``),
    so a code-control candidate can TIE the sheet and can never beat it, and a
    tie keeps the credit because each tied call did prove the published figure.
    The revocations are guards against a branch that does not exist yet; what is
    testable today is the invariant they exist to hold, which is that no credit
    outruns the rows.
    """
    priced = _ceiling_signal()
    unpriced = _ceiling_signal(
        deployment_address=VAULT,
        function_name="upgradeToVault",
        selector="0x55556666",
        **reaches(KEY_V),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        contracts=(KEY_C, KEY_V),
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}, KEY_V: {}},
    )
    document = fold([priced, unpriced], principals={1: facts(1, EOA, "eoa")}, value=plane)
    census = _magnitude(document)
    carriers = {
        entity
        for row in (*document.findings, *(s for f in document.findings for s in f["subsumed_capabilities"]))
        for entity in (row.get("entities_priced_from_a_sheet_ceiling") or [])
    }
    assert carriers == {KEY_C}
    # One credit, and the entity it names is one a row publishes.
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["by_capability"]["upgrade.implementation"] == [1, 2]


def test_cc8_the_document_rolls_the_ceiling_population_up_with_its_dollars(fold):
    """Step 4's provenance block, derived from the rows and from nothing else.

    These dollars are the one class of published magnitude deliberately absent
    from ``exposure_usd``, so a consumer reading only the grade figures has no
    way to see how much the model bounded from above and then declined to charge.
    The block is the place that says so, and every count in it is taken off what
    the rows published — including the refusals, which are counted by the reason
    the SHEET gave rather than rolled into one number.
    """
    priced = _ceiling_signal()
    refused = _ceiling_signal(
        deployment_address=VAULT,
        function_name="upgradeToVault",
        selector="0x55556666",
        **reaches(KEY_V),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        contracts=(KEY_C, KEY_V),
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}, KEY_V: {}},
    )
    block = fold([priced, refused], principals={1: facts(1, EOA, "eoa")}, value=plane).provenance["sheet_ceilings"]
    assert block["entities_priced_from_a_sheet_ceiling"] == 1
    assert block["ceiling_usd_over_distinct_entities"] == 5_000_000.0
    assert block["entities_by_capability"] == {"upgrade.implementation": 1}
    assert block["entities_in_more_than_one_capability"] == 0
    # Named zeros over the closed vocabularies: a reason absent from the map
    # would read identically as "this rule did not fire here" and "this rule is
    # not in the model", and only the first is a fact about the protocol.
    assert block["entities_by_ceiling_reason"] == {
        P.CEILING_ADMITTED: 1,
        P.CEILING_PROVEN_EMPTY: 0,
        P.CEILING_AIRDROP_DETERMINED: 0,
    }
    assert block["calls_refused_by_reason"] == {
        P.CEILING_NO_ROWS: 1,
        P.CEILING_BELOW_RESOLUTION: 0,
        P.CEILING_UNPRICED: 0,
        P.CEILING_ASSET_LIST_TRUNCATED: 0,
        P.CEILING_ALIAS_AMBIGUOUS: 0,
    }
    assert set(block["calls_refused_by_reason"]) == set(FOLD.CEILING_REFUSAL_REASONS)
    assert block["entities_by_bound_direction"] == {FOLD.BOUND_DIRECTION_NOT_DETERMINED: 0, "ceiling": 1}
    assert block["entities_publishing_more_than_one_figure"] == []
    assert block["entities_withheld_on_sheet_reconciliation"] == 0
    # The confidence pass's own count, not a second derivation of it.
    assert block["signals_credited_in_confidence"] == 1
    assert block["signals_credited_by_capability"] == {"upgrade.implementation": 1}
    assert "must never be rendered as dollars at risk" in block["reading"]


def test_cc8_one_sheet_read_by_two_rows_is_counted_once_in_the_rollup(fold):
    """Dollars per distinct ENTITY, because a sheet ceiling is a fact about a node.

    Two principals with code control over the same node both publish that node's
    sheet, and they publish the SAME number because it is the same sheet.
    Summing over rows would report twice the money that exists. The agreement is
    checked rather than assumed — a disagreement would mean the per-key
    reconciliation let two figures stand under one claim — and it is published as
    a count so a corpus where it happens says so.
    """
    first = _ceiling_signal()
    second = _ceiling_signal(
        function_name="upgradeToAndCall",
        selector="0x77778888",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
    )
    document = fold(
        [first, second],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    block = document.provenance["sheet_ceilings"]
    assert block["rows_publishing_a_sheet_ceiling"]["findings"] == 2
    assert block["entities_priced_from_a_sheet_ceiling"] == 1
    assert block["ceiling_usd_over_distinct_entities"] == 5_000_000.0
    assert block["entities_publishing_more_than_one_figure"] == []
    # Two signals, one sheet: the two meters count different things and both are
    # published, so neither is read as the other.
    assert block["signals_credited_in_confidence"] == 2


def test_cc8_one_node_under_two_code_control_capabilities_counts_once_in_the_population(fold):
    """The capability breakdown counts MEMBERSHIPS and the population counts entities.

    A node reached by two code-control capabilities is priced from its own sheet
    under both, so it sits in two buckets while being one entity holding one
    sheet. The dollars are deduped and the breakdown is not — they answer
    different questions — and a reader summing the buckets would over-count the
    population unless the document says so. It says so with a count, not with a
    caveat.
    """
    upgrade = _ceiling_signal()
    execute = _ceiling_signal(claim_id="exec.arbitrary", function_name="execute", selector="0x33334444")
    document = fold(
        [upgrade, execute],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    block = document.provenance["sheet_ceilings"]
    assert block["entities_by_capability"] == {"exec.arbitrary": 1, "upgrade.implementation": 1}
    # Two memberships, one entity, one sheet's worth of dollars.
    assert sum(block["entities_by_capability"].values()) == 2
    assert block["entities_priced_from_a_sheet_ceiling"] == 1
    assert block["entities_in_more_than_one_capability"] == 1
    assert block["ceiling_usd_over_distinct_entities"] == 5_000_000.0
    assert "sums past the distinct-entity count" in block["reading"]
