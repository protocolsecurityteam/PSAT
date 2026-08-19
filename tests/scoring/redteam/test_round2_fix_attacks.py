"""Round 2: attacking the fixes.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from services.scoring import fold as FOLD
from services.scoring.constants import FREEZE_CAPABILITY_PROVEN
from services.scoring.schema import PrincipalRef, Tri, entity_key
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_V,
    OWNERS,
    SAFE,
    SAFE2,
    TIMELOCK,
    VAULT,
    C,
    _pause_document,
    bounded_by_sheet,
    facts,
    flow_sig,
    fold,  # noqa: F401  (fold fixture, registered by import)
    pause_sig,
    proven,
    reaches,
    sig,
    value_plane,
)
from utils.scoring_status import VALUE_BOUND_EXACT


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
