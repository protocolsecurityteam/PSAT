"""F6: the proving caller is persisted end to end.

F4: the attribution path is ``proven_upper_bound``, not ``proven_floor``. F5: a coverage gap doesn't earn a floor over
attribution-derived contributions.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from services.effects import claims_bridge, recipes
from services.effects.config import BLOCK_SOURCE_JOB_PIN, VERDICT_PROVEN
from services.effects.harness import SimContext
from services.effects.selection import AssetHolding
from services.effects.simulate import SimCallResult, SimResult
from services.scoring import distill as D
from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import FunctionSignal, PrincipalRef, Tri
from tests.support import scoring_builders as RT
from tests.support.effects_stubs import RecordingStore, transfer_log
from tests.support.scoring_builders import (
    COMPOSED_SELECTOR,
    EOA,
    KEY_C,
    KEY_V,
    SAFE,
    VAULT,
    C,
    facts,
    flow_sig,
    fold,  # noqa: F401  — the fold fixture, reused rather than forked
    proven,
    reaches,
    sig,
    value_plane,
)
from utils import execution_record as EX
from utils.scoring_status import (
    MAGNITUDE_STATE_PROVEN_EXACT,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
)


def test_an_absent_record_is_not_determined_and_never_an_empty_execution():
    record = EX.from_residue(None, transcript_ptr="job::art", effect_verdict_id=7)
    assert record.state == EX.EXECUTION_NOT_DETERMINED
    assert record.reason == EX.REASON_NOT_PERSISTED
    assert record.caller is None and record.target is None
    block = record.as_json()
    assert block["transcript_ptr"] == "job::art"
    assert block["effect_verdict_id"] == 7
    # A full list of nulls would read as an execution whose every field came back empty.
    assert "caller" not in block and "input_seeded" not in block


def test_a_record_naming_no_call_is_not_a_record():
    assert EX.from_residue({"caller": "0xabc"}, transcript_ptr=None, effect_verdict_id=None).reason == (
        EX.REASON_NOT_PERSISTED
    )


def test_the_seeding_qualifiers_are_three_valued_and_absence_is_the_third():
    """Reading absent as ``False`` publishes an unqualified verdict."""
    payload = {"target": "0x" + "a" * 40, "calldata": "0x" + "de" * 4}
    record = EX.from_residue(payload, transcript_ptr=None, effect_verdict_id=None)
    assert record.input_seeded == EX.SEEDING_NOT_DETERMINED
    assert record.contract_balance_seeded == EX.SEEDING_NOT_DETERMINED
    assert record.input_seeded is not False

    seeded = EX.from_residue(
        {**payload, "input_seeded": True, "contract_balance_seeded": False},
        transcript_ptr=None,
        effect_verdict_id=None,
    )
    assert (seeded.input_seeded, seeded.contract_balance_seeded) == (True, False)


def test_the_undetermined_reading_is_derived_from_its_own_reason():
    """One sentence would be false on most reasons, e.g. naming a pointer for a row with none."""
    readings = {reason: EX.undetermined_reading(reason, "job::art") for reason in EX.NOT_DETERMINED_REASONS}
    assert len(set(readings.values())) == len(EX.NOT_DETERMINED_REASONS)

    with_ptr = EX.not_determined(EX.REASON_NOT_PERSISTED, transcript_ptr="job::art").as_json()["reading"]
    without = EX.not_determined(EX.REASON_NOT_PERSISTED).as_json()["reading"]
    assert "transcript_ptr beside this" in with_ptr
    assert "transcript_ptr beside this" not in without

    for reason in (EX.REASON_NO_VERDICT, EX.REASON_VERDICT_NOT_LOCATED):
        reading = EX.not_determined(reason).as_json()["reading"]
        assert "transcript_ptr beside this" not in reading
        assert "is recoverable by reading it" not in reading

    for reading in readings.values():
        assert "must not read this absence as an unseeded probe" in reading


@pytest.mark.parametrize("kwargs", [{"state": EX.EXECUTION_NOT_DETERMINED, "reason": "because"}, {"state": "probably"}])
def test_an_undetermined_record_must_name_a_registered_reason(kwargs):
    with pytest.raises(ValueError):
        EX.ProvingExecution(**kwargs)


def test_an_uncertified_height_is_dropped_rather_than_published():
    payload = EX.residue_payload(
        caller="0xAB",
        target="0xCD",
        calldata="0x" + "de" * 4,
        probe_label="value_probe",
        succeeded=True,
        block_number=1000,
        block_source=None,
        chain_id=1,
        tier="call",
        input_seeded=False,
        contract_balance_seeded=False,
    )
    assert payload["block_number"] is None and payload["block_source"] is None


def test_route_comparison_has_no_fall_through_arm():
    absent = EX.route_comparison(
        EX.not_determined(EX.REASON_NOT_PERSISTED),
        claimed_caller="ethereum::0xaa",
        claimed_target="ethereum::0xbb",
        claimed_selector="0x11111111",
    )
    assert absent["verdict"] == EX.ROUTE_NOT_DETERMINED
    assert absent["caller_matches"] is None

    record = EX.from_residue(
        EX.residue_payload(
            caller="0xAA",
            target="0xBB",
            calldata="0x11111111" + "00" * 32,
            probe_label="value_probe",
            succeeded=True,
            block_number=10,
            block_source="head_pin",
            chain_id=1,
            tier="call",
            input_seeded=False,
            contract_balance_seeded=False,
        ),
        transcript_ptr=None,
        effect_verdict_id=None,
    )
    matched = EX.route_comparison(
        record, claimed_caller="ethereum::0xaa", claimed_target="ethereum::0xbb", claimed_selector="0x11111111"
    )
    assert matched["verdict"] == EX.ROUTE_MATCH
    mismatched = EX.route_comparison(
        record, claimed_caller="ethereum::0xaa", claimed_target="ethereum::0xbb", claimed_selector="0x3e64ce99"
    )
    assert mismatched["verdict"] == EX.ROUTE_MISMATCH
    assert mismatched["selector_matches"] is False


CTX = SimContext(chain_id=1, block=1000, hardfork="prague", block_source=BLOCK_SOURCE_JOB_PIN)
CONTRACT = "0x" + "c0" * 20
PRINCIPAL = "0x" + "22" * 20
PAYEE = "0x" + "33" * 20
TOKEN = "0x" + "7a" * 20
CALLDATA = "0x" + "de" * 4
SEEDED_CALLDATA = "0x" + "ab" * 4


def _value_out(blocks, *, seeding=None):
    remaining = list(blocks)

    def simulate(calls, block_tag=None, overrides=None):
        return remaining.pop(0)

    return recipes.value_out(
        simulate=simulate,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata=CALLDATA,
        simulate_supported=True,
        value_holders=(AssetHolding(CONTRACT, TOKEN, 100.0),),
        acting_balance_usd=100.0,
        seeder=(lambda _req: seeding),
        seeded_calldata={18: SEEDED_CALLDATA},
        target_payable=True,
    )


def _moved() -> SimResult:
    return SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))


def test_the_proving_call_is_recorded_on_the_state_plane():
    """On ``concrete`` so it never rides the behavioral cache onto a twin."""
    eff = _value_out([_moved()])
    assert eff.verdict == VERDICT_PROVEN
    record = eff.concrete[EX.PROVING_EXECUTION_KEY]
    assert record["caller"] == PRINCIPAL.lower()
    assert record["target"] == CONTRACT.lower()
    assert record["selector"] == CALLDATA[:10]
    assert record["calldata"] == CALLDATA
    assert record["succeeded"] is True
    assert (record["block_number"], record["block_source"]) == (1000, BLOCK_SOURCE_JOB_PIN)
    assert record["input_seeded"] is False
    assert record["contract_balance_seeded"] is False
    assert EX.PROVING_EXECUTION_KEY not in eff.details


def test_the_record_names_the_seeded_call_that_landed_not_the_one_that_reverted():
    from services.effects.seeding import Seeding

    reverted = SimResult(calls=(SimCallResult(False, "0x", "0x", ()),))
    eff = _value_out(
        [reverted, _moved()],
        seeding=Seeding(overrides={}, readback_calls=(), readback_expected=(), tokens=(), decimals=18),
    )
    record = eff.concrete[EX.PROVING_EXECUTION_KEY]
    assert eff.verdict == VERDICT_PROVEN
    assert record["calldata"] == SEEDED_CALLDATA
    assert record["succeeded"] is True
    assert record["input_seeded"] is True


class _Verdict:
    def __init__(self, residue):
        self.id = 11
        self.effect_class = "value_out"
        self.verdict = VERDICT_PROVEN
        self.tier = "call"
        self.behavior_hash = "h"
        self.current_check_passed = None
        self.witness = {"value_moved": True}
        self.observed_residue = residue


def test_the_bridge_forwards_the_record_to_the_claim_witness():
    """The bridge is the only boundary the scorer reads across."""
    payload = {"target": CONTRACT, "calldata": CALLDATA, "caller": PRINCIPAL}
    claim = claims_bridge.verdict_to_claim(cast(Any, _Verdict({EX.PROVING_EXECUTION_KEY: payload})))
    assert claim is not None
    assert claim["witness"]["observed"][EX.PROVING_EXECUTION_KEY] == payload
    bare = claims_bridge.verdict_to_claim(cast(Any, _Verdict({})))
    assert bare is not None
    assert EX.PROVING_EXECUTION_KEY not in (bare["witness"].get("observed") or {})


class _Func:
    id = 1
    authority_roles = None


def _facts(verdicts) -> Any:
    return D._ContractFacts(
        contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[], verdicts={1: verdicts}
    )


class _Row:
    def __init__(self, ptr, row_id=5):
        self.id = row_id
        self.transcript_ptr = ptr
        self.verdict = VERDICT_PROVEN


def test_the_distiller_publishes_the_typed_reason_when_no_record_is_stored():
    entries = [{"witness": {"effect_verdict_id": 5, "observed": {}}}]
    gate = D._proving_execution_gate(_facts([_Row("job::art")]), _Func(), entries)
    assert gate.state == EX.GATE_STATE_NOT_RECORDED
    assert isinstance(gate.value, dict)
    assert gate.value["state"] == EX.EXECUTION_NOT_DETERMINED
    assert gate.value["reason"] == EX.REASON_NOT_PERSISTED
    assert gate.value["transcript_ptr"] == "job::art"
    assert gate.value["effect_verdict_id"] == 5


def test_the_distiller_carries_a_stored_record_onto_the_signal():
    payload = {"target": VAULT, "calldata": CALLDATA, "caller": C, "succeeded": True, "input_seeded": True}
    entries = [{"witness": {"effect_verdict_id": 5, "observed": {EX.PROVING_EXECUTION_KEY: payload}}}]
    gate = D._proving_execution_gate(_facts([_Row("job::art")]), _Func(), entries)
    assert gate.state == EX.GATE_STATE_RECORDED
    assert isinstance(gate.value, dict)
    assert gate.value["caller"] == C
    assert gate.value["input_seeded"] is True
    assert gate.value["transcript_ptr"] == "job::art"


def test_the_execution_and_the_published_verdict_id_name_the_same_row():
    """The gate took the first verdict-bearing entry and the signal the last, pairing one verdict's dollars with
    another's caller.
    """
    first = {"witness": {"effect_verdict_id": 5, "observed": {}}}
    second = {
        "witness": {
            "effect_verdict_id": 6,
            "observed": {EX.PROVING_EXECUTION_KEY: {"target": VAULT, "calldata": CALLDATA, "caller": C}},
        }
    }
    entries = [first, second]
    facts_row = _facts([_Row("job::art"), _Row("job::art6", row_id=6)])

    assert D._cited_verdict_entry(entries) is second
    gate = D._proving_execution_gate(facts_row, _Func(), entries)
    assert isinstance(gate.value, dict)
    assert gate.value["effect_verdict_id"] == 6
    assert gate.value["caller"] == C
    assert D._verdict_bearing_entries(entries) == entries


def test_a_claim_with_no_verdict_says_so_rather_than_going_silent():
    gate = D._proving_execution_gate(_facts([]), _Func(), [{"witness": {}}])
    assert gate.state == EX.GATE_STATE_NOT_RECORDED
    assert isinstance(gate.value, dict)
    assert gate.value["reason"] == EX.REASON_NO_VERDICT


def _charged(state: str, usd: float = 5_000.0, *keys: str) -> FunctionSignal:
    return flow_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven(state, usd).to_json()},
        **proven(1.0),
        **reaches(*(keys or (KEY_C,))),
    )


def _eoa_finding(fold, signal: FunctionSignal, plane: P.ValuePlane) -> dict[str, Any]:
    return fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]


def _gapped_row(state: str) -> tuple[FunctionSignal, P.ValuePlane]:
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    return _charged(state), plane


def test_case4_an_attribution_derived_magnitude_publishes_neither_exact_nor_floor():
    """A constant-amount probe credits the holder's whole balance, so neither exact nor floor is earned."""
    reach = D._flow_reach(
        {"reach_determined": True, "observed_reach_value_usd": 1_234.0, "observed_reach_holders": [VAULT]},
        cast(Any, D._ContractFacts(contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[])),
        KEY_C,
    )
    assert reach.magnitude.state == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    assert reach.magnitude.state not in (MAGNITUDE_STATE_PROVEN_EXACT, MAGNITUDE_STATE_PROVEN_FLOOR)
    assert reach.basis == "observed_reach_value_usd(fork-proven)"
    assert reach.bound == "exact"


def test_case4_the_genuine_floor_path_keeps_its_floor():
    """The predicate is the basis, not any observed_reach_* key."""
    reach = D._flow_reach(
        {"observed_reach_priced_usd": 900.0, "observed_reach_priced_holders": [VAULT]},
        cast(Any, D._ContractFacts(contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[])),
        KEY_C,
    )
    assert reach.magnitude.state == MAGNITUDE_STATE_PROVEN_FLOOR
    assert reach.basis == "observed_reach_priced_usd(>= floor)"


def test_case4_the_upper_bound_token_is_readable_by_the_fold(fold):
    """An unregistered state is MALFORMED and would drop every attribution-derived magnitude at once."""
    signal = _charged(MAGNITUDE_STATE_PROVEN_UPPER_BOUND)
    assert FOLD._malformed_gates(signal) == []
    assert FOLD._gate(signal, "reach_magnitude_usd").state == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    finding = _eoa_finding(fold, signal, value_plane({KEY_C: {"usdc": 5_000_000.0}}))
    assert finding["value_at_stake_usd"] == 5_000.0


def test_case5_a_coverage_gap_over_an_attribution_derived_figure_earns_no_floor(fold):
    finding = _eoa_finding(fold, *_gapped_row(MAGNITUDE_STATE_PROVEN_UPPER_BOUND))
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert finding["value_at_stake_is_floor"] is False
    assert not finding["value_band"].startswith(">= ")
    assert finding["value_at_stake_usd"] == 5_000.0


def test_case5_a_genuine_floor_under_the_same_gap_still_earns_it(fold):
    finding = _eoa_finding(fold, *_gapped_row(MAGNITUDE_STATE_PROVEN_FLOOR))
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert finding["value_at_stake_is_floor"] is True
    assert finding["value_band"].startswith(">= ")


def test_case5_holds_on_a_subsumed_row_too(fold):
    """Three investigation passes silently measured findings only."""
    common: dict[str, Any] = dict(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates={"reach_magnitude_usd": Tri.proven(MAGNITUDE_STATE_PROVEN_UPPER_BOUND, 5_000.0).to_json()},
        **reaches(KEY_C),
    )
    weak = sig(claim_id="upgrade.implementation", function_name="weak", selector="0x11111111", **proven(0.5), **common)
    strong = flow_sig(function_name="strong", selector="0x22222222", **proven(1.0), **common)
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    document = fold([weak, strong], principals={1: facts(1, SAFE, "eoa")}, value=plane)
    subsumed = list(document.provenance.get("subsumed_rows") or [])
    assert subsumed, "the case must exercise a subsumed row, not two findings"
    for row in list(document.findings) + subsumed:
        assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED, row["capability"]
        assert not row["value_band"].startswith(">= ")


def _unbounded_row(state: str) -> tuple[FunctionSignal, P.ValuePlane]:
    """Absent from the reference corpus. No priced rows, so ``total`` is None, not zero."""
    return _charged(state), value_plane({}, contracts=(KEY_C,))


def test_an_upper_bound_over_an_unpriced_sheet_is_never_disclosed_as_a_floor(fold):
    """Same arithmetic, opposite claims, and no number moves, so only this assertion catches it."""
    finding = _eoa_finding(fold, *_unbounded_row(MAGNITUDE_STATE_PROVEN_UPPER_BOUND))
    disclosed = finding["unbounded_floor_magnitudes"]
    assert len(disclosed) == 1
    note = disclosed[0]
    assert note["witness_state"] == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    assert note["witnessed_upper_bound_usd"] == 5_000.0
    assert "witnessed_floor_usd" not in note
    assert "ABOVE" in note["reading"]
    assert "at least this much" not in note["reading"]
    assert finding["value_at_stake_usd"] == 5_000.0


def test_a_floor_over_an_unpriced_sheet_keeps_its_own_name_verbatim(fold):
    note = _eoa_finding(fold, *_unbounded_row(MAGNITUDE_STATE_PROVEN_FLOOR))["unbounded_floor_magnitudes"][0]
    assert note["witness_state"] == MAGNITUDE_STATE_PROVEN_FLOOR
    assert note["witnessed_floor_usd"] == 5_000.0
    assert "witnessed_upper_bound_usd" not in note
    assert "the call moves at least this much somewhere" in note["reading"]


def _two_key_row(state: str) -> tuple[FunctionSignal, P.ValuePlane]:
    """signal-525: ``0xf3fef3a3 withdraw``, $28.1M, the only live instance."""
    return _charged(state, 3_000.0, KEY_C, KEY_V), value_plane({KEY_C: {"usdc": 2_000.0}, KEY_V: {"usdc": 2_000.0}})


def test_an_upper_bound_is_refused_across_two_keys_rather_than_apportioned(fold):
    """Split across keys without an apportionment witness, an upper bound would attribute the whole bound at each; no
    corpus number moves, so only this catches it.
    """
    finding = _eoa_finding(fold, *_two_key_row(MAGNITUDE_STATE_PROVEN_UPPER_BOUND))
    assert finding["value_by_entity"] == {}
    assert finding["value_at_stake_usd"] is None
    refusals = {
        gap["entity"]: gap["why"] for gap in finding["undetermined_instances"] if "apportionment" in str(gap.get("why"))
    }
    assert set(refusals) == {KEY_C, KEY_V}
    cap = next(
        c for c in finding["witnessed_magnitude_caps"] if c["witness_state"] == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    )
    assert cap["published_sum_usd"] is None
    assert cap["uncapped_sum_usd"] == 4_000.0


def test_an_exact_witness_over_two_keys_still_apportions(fold):
    finding = _eoa_finding(fold, *_two_key_row(MAGNITUDE_STATE_PROVEN_EXACT))
    assert finding["value_at_stake_usd"] == 3_000.0
    assert set(finding["value_by_entity"]) == {KEY_C, KEY_V}


def test_the_floor_arm_is_not_vacuously_true_on_an_empty_contribution_set():
    """A universal over no contributions is true, which would publish ">= $0"."""
    empty = frozenset()
    assert FOLD._bound_direction(0.0, empty, empty, True, False, empty) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert FOLD._bound_direction(None, empty, empty, True, False, empty) == FOLD.BOUND_DIRECTION_NOT_DETERMINED


def _composing_signals(execution_payload: dict[str, Any] | None) -> list[FunctionSignal]:
    record = (
        Tri.proven(EX.GATE_STATE_RECORDED, execution_payload)
        if execution_payload is not None
        else Tri.proven(
            EX.GATE_STATE_NOT_RECORDED,
            EX.not_determined(EX.REASON_NOT_PERSISTED, transcript_ptr="job::art", effect_verdict_id=9).as_json(),
        )
    )
    gate, destination = RT._composing_signals()
    return [
        gate,
        replace(
            destination,
            gate_inputs={
                **destination.gate_inputs,
                "reach_magnitude_usd": Tri.proven(MAGNITUDE_STATE_PROVEN_UPPER_BOUND, 1_000_000.0).to_json(),
                EX.PROVING_EXECUTION_KEY: record.to_json(),
            },
        ),
    ]


def _composed(fold, payload):
    document = fold(_composing_signals(payload), principals=RT._composing_principals(), **RT._composing_case())
    row = next(f for f in document.findings if f["capability"] == "authority.replace")
    return row["reach_composed_magnitudes"][0]


def test_a_composed_entry_publishes_the_execution_it_has(fold):
    payload = EX.from_residue(
        EX.residue_payload(
            caller=EOA,
            target=VAULT,
            calldata=COMPOSED_SELECTOR + "00" * 32,
            probe_label="seeded_probe",
            succeeded=True,
            block_number=25_657_731,
            block_source="deployment_pin",
            chain_id=1,
            tier="call",
            input_seeded=True,
            contract_balance_seeded=False,
        ),
        transcript_ptr="job::art",
        effect_verdict_id=9,
    ).as_json()
    entry = _composed(fold, payload)

    execution = entry["proving_execution"]
    assert execution["state"] == EX.EXECUTION_RECORDED
    assert execution["caller"] == EOA.lower()
    assert execution["target"] == VAULT.lower()
    assert execution["selector"] == COMPOSED_SELECTOR
    assert execution["calldata"].startswith(COMPOSED_SELECTOR)
    assert execution["input_seeded"] is True
    assert execution["transcript_ptr"] == "job::art"
    # A positional decode off a byte slice is the laundering this record exists to stop.
    assert execution["arguments_decoded"] is None

    route = entry["route_comparison"]
    assert route["target_matches"] is True
    assert route["caller_matches"] is False
    assert route["verdict"] == EX.ROUTE_MISMATCH


def test_a_composed_entry_with_no_record_publishes_the_typed_reason(fold):
    """Every reference-corpus entry is in this state today."""
    entry = _composed(fold, None)
    execution = entry["proving_execution"]
    assert execution["state"] == EX.EXECUTION_NOT_DETERMINED
    assert execution["reason"] == EX.REASON_NOT_PERSISTED
    assert execution["transcript_ptr"] == "job::art"
    assert "caller" not in execution
    assert entry["route_comparison"]["verdict"] == EX.ROUTE_NOT_DETERMINED
    # Not a transport fault, so the deletability join still decides.
    assert entry["arm_taken"] == FOLD.ARM_REPUBLISHED_DIRECT
    assert entry["arm_taken"] in FOLD.COMPOSITION_ARMS


def test_the_destination_magnitude_carries_the_execution_and_its_direction():
    magnitudes = FOLD._destination_magnitudes(_composing_signals(None))
    magnitude = magnitudes[(KEY_V, COMPOSED_SELECTOR)]
    assert magnitude.state == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    assert magnitude.attribution_derived is True
    assert magnitude.execution.state == EX.EXECUTION_NOT_DETERMINED
    assert magnitude.execution.transcript_ptr == "job::art"

    floor = FOLD._DestinationMagnitude(
        state=MAGNITUDE_STATE_PROVEN_FLOOR,
        usd=1.0,
        function="exit",
        execution=EX.not_determined(EX.REASON_NOT_PERSISTED),
    )
    assert floor.attribution_derived is False
