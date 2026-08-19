"""Merged-unit weakness, the burn sentinel, and confidence completeness (W2c).

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.scoring import distill as D
from services.scoring import planes as P
from services.scoring.constants import WEAKNESS_SAFE_MAJORITY, WEAKNESS_SAFE_MINORITY
from services.scoring.schema import PrincipalRef, Tri, entity_key
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_PROXY,
    KEY_V,
    KEY_ZERO,
    VAULT,
    C,
    _perimeter_signal,
    bounded_by_sheet,
    facts,
    flow_sig,
    fold,  # noqa: F401  (fold fixture, registered by import)
    magnitude,
    proven,
    reaches,
    sig,
    value_plane,
)
from utils.scoring_status import GRADE_STATE_COMPUTED, GRADE_STATE_NOT_DETERMINED, VALUE_STATE_PROVEN_REACH

MERGE_SHARED = tuple("0x" + c * 40 for c in "1234")
SAFE_MINORITY = "0x" + "e" * 40
SAFE_MAJORITY = "0x" + "d" * 40
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
