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
    KEY_V,
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
    """inv.

    ``_row_for`` keeps the max weakness over members while the row folds the
    UNION of their reach. Each entity's weakest path is the weakest path TO THAT
    ENTITY; the union, which no single member reaches, is priced at the
    coalition able to act as every contributing member.
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
    # The union is priced at the hardest contributing rung, published under the member that sets it.
    assert finding["weakness"] == WEAKNESS_SAFE_MAJORITY
    assert finding["weakest_gate"] == "Safe 4/8"
    assert SAFE_MAJORITY in finding["principal"]
    assert finding["exposure_usd"] == pytest.approx(
        WEAKNESS_SAFE_MINORITY * 1_000_000.0 + WEAKNESS_SAFE_MAJORITY * 5_000_000.0
    )


def test_r9_members_at_one_rung_leave_the_row_untouched(fold):
    document = fold(
        _merged_unit_signals(),
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


def _magnitude_document(fold, *, witnessed: bool):
    """Gate control, so the unwitnessed document publishes a genuinely unanswered term."""
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
    """Without the term, "we couldn't prove how much this moves" had nowhere to land but the grade."""
    unwitnessed_doc = _magnitude_document(fold, witnessed=False)
    witnessed_doc = _magnitude_document(fold, witnessed=True)
    unwitnessed = unwitnessed_doc.model_parameters["confidence_detail"]
    witnessed = witnessed_doc.model_parameters["confidence_detail"]
    assert unwitnessed["reach_magnitude_witnessed_pct"] == 0.0
    assert witnessed["reach_magnitude_witnessed_pct"] == 100.0
    assert unwitnessed["reach_magnitude_signals"]["proven_reach_in_denominator"] == 1
    assert unwitnessed["reach_magnitude_signals"]["magnitude_witnessed"] == 0
    # Answering the magnitude may only RAISE the term.
    assert witnessed["reach_magnitude_witnessed_pct"] >= unwitnessed["reach_magnitude_witnessed_pct"]

    # The finding SURVIVES its missing magnitude, at the unpriced band's floor:
    # the reach is proven and only its SIZE is not, which the unpriced floor rule
    # governs. It is the dollar figure that is not_determined, never the row.
    assert unwitnessed_doc.findings[0]["reach_entities"] == [KEY_C]
    assert unwitnessed_doc.findings[0]["value_band"] == "not_determined"
    assert unwitnessed_doc.findings[0]["value_at_stake_usd"] is None
    assert unwitnessed_doc.findings[0]["raw_points"] > 0

    # No finding measured a numerator, so the exposure ratio is withheld, not 100; grade, exposure and confidence stand
    # or fall together (ck_protocol_scores_grade_pairing).
    assert unwitnessed_doc.grade_state == GRADE_STATE_NOT_DETERMINED
    withheld = unwitnessed_doc.provenance["grade_withheld"]
    assert 0.0 < withheld["grade_lambda_computed"] < 100.0
    assert witnessed_doc.grade_state == GRADE_STATE_COMPUTED
    assert witnessed["pct"] > 0.0


def test_r11_every_proven_reach_capability_is_in_the_denominator(fold):
    """An exclusion list would drop the unwitnessed signal and publish 100% instead of the honest 50%."""
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
    assert detail["reach_magnitude_witnessed_pct"] == 50.0
    assert detail["reach_magnitude_witnessed_of_reaching_pct"] == 50.0
    assert detail["reach_magnitude_vacuous_credit_pct"] == 0.0


def test_r12_consuming_a_relation_may_not_raise_confidence(fold):
    """The perimeter was seeded from consumed relations, so walking less scored higher."""
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
    assert KEY_OUTSIDER not in declined["signal_entities_outside_perimeter"]
    assert declined["perimeter_entities"] == consumed["perimeter_entities"]
    assert declined["perimeter_value_weighted_denominator"] == consumed["perimeter_value_weighted_denominator"]
    assert consumed["pct"] <= declined["pct"]
    assert declined["discovery_relation_entities_admitted"]["capability_principal"] == 1


def test_r17_contradictory_owner_sets_are_disclosed_not_silently_arbitrated(fold):
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
        # What a denylist would admit: no tier token resolves to not_determined.
        (VAULT, None, "witness_tier_not_determined(not_determined; no tier token this scorer can vouch for)"),
        (
            VAULT,
            "invented_tier",
            "witness_tier_not_determined(not_determined; no tier token this scorer can vouch for)",
        ),
    ],
)
def test_w3_a_repoint_is_admitted_only_on_a_validated_value_witness(named, tier, why):
    """R2: a repoint must pass protocol, chain, existence and value-witness checks.

    The tier test is an allowlist, since an unrecognised token resolves to not_determined, the weakest witness.
    """
    entry: dict[str, Any] = {"witness": {"callee": named}}
    if tier is not None:
        entry["tier"] = tier
    keys, bases, refused = D._repointed_entities(entry, _repoint_facts())
    assert (keys, bases) == ([], [])
    assert [row["why"] for row in refused] == [why]
    assert refused[0]["basis"] == "witness.callee"

    admitted = D._repointed_entities({"tier": "behavioral_observed", "witness": {"callee": VAULT}}, _repoint_facts())
    assert admitted == ([KEY_V], ["witness.callee"], [])


def test_w3_a_repoint_never_upgrades_an_unscored_capability():
    """Six ``flow.in`` rows were promoted to ``proven_reach`` just because a witness named an address."""
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


@pytest.mark.parametrize(
    ("stamp", "admitted"),
    [("policy_derived", False), ("standard_exact", True), ("invented_tier", False)],
)
def test_a_carried_named_entity_takes_the_tier_it_was_carried_from(stamp, admitted):
    """An observed claim's ``callee`` was copied from the static claim it superseded, so the observation's tier
    doesn't vouch for it."""
    entry = {"tier": "behavioral_observed", "witness": {"callee": VAULT, "static_tier": stamp}}

    keys, _bases, refused = D._repointed_entities(entry, _repoint_facts())

    assert keys == ([KEY_V] if admitted else [])
    assert bool(refused) is not admitted
