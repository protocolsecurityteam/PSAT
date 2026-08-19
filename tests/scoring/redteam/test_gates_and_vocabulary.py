"""Gates and vocabulary.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from services.scoring.schema import FunctionSignal, PrincipalRef, Tri, not_determined_signal_defaults
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    C,
    facts,
    flow_sig,
    fold,  # noqa: F401  (fold fixture, registered by import)
    proven,
    reaches,
    sig,
    value_plane,
)
from utils.scoring_status import SEVERITY_STATE_PROVEN


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
