from __future__ import annotations

from typing import Any

import pytest

from services.scoring import distill as D
from services.scoring.constants import WEAKNESS_SAFE_SINGLE_SIGNER
from services.scoring.schema import PrincipalRef, Tri, entity_key
from tests.support.scoring_builders import (
    KEY_C,
    KEY_V,
    OWNERS,
    SAFE,
    SAFE2,
    VAULT,
    C,
    bounded_by_sheet,
    facts,
    flow_sig,
    fold,  # noqa: F401  (fold fixture, registered by import)
    proven,
    reaches,
    sig,
    value_plane,
)


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


# The caller enumeration is a lower bound, so "no other caller resolved" cannot zero a capability-class base.
@pytest.mark.parametrize(
    ("self_gated", "expected_notes", "expected_basis", "absent_basis"),
    [
        pytest.param(
            True,
            ("delay_gate_self_gated_lower_bound",),
            ("capability_class_base",),
            ("delay_change_path_self_gated",),
            id="self_gated_credit_is_retired",
        ),
        pytest.param(False, ("delay_change_gate_not_self_gated",), (), (), id="not_self_gated"),
    ],
)
def test_the_delay_gate_observation_names_which_arm_it_took(self_gated, expected_notes, expected_basis, absent_basis):
    entries: list[dict[str, Any]] = [{"claim_id": "timelock.set_delay"}]
    severity, basis, notes = D._severity(
        _contract_facts(),
        None,
        claim_id="timelock.set_delay",
        entries=entries,
        destination=D._UNDETERMINED_DESTINATION,
        openness="restricted",
        deployment_address=C,
        self_gated=self_gated,
    )
    assert severity.value == 0.3
    for note in expected_notes:
        assert note in notes
    for item in expected_basis:
        assert item in basis
    for item in absent_basis:
        assert item not in basis


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


def test_d1_the_published_principal_is_the_one_that_set_the_weakness(fold):
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


def test_g5_an_undecidable_asset_identity_falls_to_the_unpriced_branch(fold):
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
    assert fold([undecidable], value=plane).model_parameters["confidence_detail"]["value_priced_pct"] is not None
