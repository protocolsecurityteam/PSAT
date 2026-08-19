"""The execution record, end to end, and the two labels that depend on it.

Three positive facts that were being published without a witness before:
**F6** the proving caller is persisted (recipe -> ``ObservedEffect.concrete`` ->
claims bridge -> distiller -> fold, beside every composed magnitude); **F4** the
attribution path is not exact, so the state is ``proven_upper_bound`` and
emphatically not ``proven_floor``, whose prose means "at least this much";
**F5** a coverage gap alone does not earn a floor, because a row whose
contributions are attribution-derived is bounded from above.
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

# 1. the shape itself


def test_an_absent_record_is_not_determined_and_never_an_empty_execution():
    """Every verdict written before the record existed carries no key at all, and
    that absence must reach the consumer as its own state — with a reason, the
    pointers to go and look, and no caller."""
    record = EX.from_residue(None, transcript_ptr="job::art", effect_verdict_id=7)
    assert record.state == EX.EXECUTION_NOT_DETERMINED
    assert record.reason == EX.REASON_NOT_PERSISTED
    assert record.caller is None and record.target is None
    block = record.as_json()
    # The pointers survive: a traceable gap, not an untraceable one.
    assert block["transcript_ptr"] == "job::art"
    assert block["effect_verdict_id"] == 7
    # The undetermined form is SHORT. A full field list of nulls would read as an
    # execution whose every field came back empty, which is a stronger claim.
    assert "caller" not in block and "input_seeded" not in block


def test_a_record_naming_no_call_is_not_a_record():
    """``target`` and ``calldata`` are required: a payload with neither describes
    no execution."""
    assert EX.from_residue({"caller": "0xabc"}, transcript_ptr=None, effect_verdict_id=None).reason == (
        EX.REASON_NOT_PERSISTED
    )


def test_the_seeding_qualifiers_are_three_valued_and_absence_is_the_third():
    """An absent ``input_seeded`` conflates "not seeded" with "seeding was never
    a question here"; reading it as ``False`` publishes an unqualified verdict."""
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
    """A single sentence for all seven reasons would be FALSE on most of them:
    "the execution exists in the transcript the pointer names" is untrue of a row
    that has no verdict and therefore no pointer."""
    readings = {reason: EX.undetermined_reading(reason, "job::art") for reason in EX.NOT_DETERMINED_REASONS}
    # Seven reasons, seven distinct sentences: no constant standing in for the lot.
    assert len(set(readings.values())) == len(EX.NOT_DETERMINED_REASONS)

    # The clause that was false on the pointerless reasons is now conditional AND
    # scoped to the one reason it is true of.
    with_ptr = EX.not_determined(EX.REASON_NOT_PERSISTED, transcript_ptr="job::art").as_json()["reading"]
    without = EX.not_determined(EX.REASON_NOT_PERSISTED).as_json()["reading"]
    assert "transcript_ptr beside this" in with_ptr
    assert "transcript_ptr beside this" not in without

    # Neither of the two reasons that ALWAYS carry a null pointer may name one.
    for reason in (EX.REASON_NO_VERDICT, EX.REASON_VERDICT_NOT_LOCATED):
        reading = EX.not_determined(reason).as_json()["reading"]
        assert "transcript_ptr beside this" not in reading
        assert "is recoverable by reading it" not in reading

    # The invariant clause is a field-description and rides every one of them: it
    # says what a consumer may not conclude and asserts nothing about the row.
    for reading in readings.values():
        assert "must not read this absence as an unseeded probe" in reading


@pytest.mark.parametrize("kwargs", [{"state": EX.EXECUTION_NOT_DETERMINED, "reason": "because"}, {"state": "probably"}])
def test_an_undetermined_record_must_name_a_registered_reason(kwargs):
    with pytest.raises(ValueError):
        EX.ProvingExecution(**kwargs)


def test_an_uncertified_height_is_dropped_rather_than_published():
    """``new_transcript`` writes ``block_source`` only for a positive, named pin;
    without one the height is a bystander."""
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
    """With no record nothing was compared, and that is neither a match nor a
    mismatch: a missing conjunct never resolves to ``route_match``."""
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
    # The published route claims a WRAPPER selector the probe never called.
    mismatched = EX.route_comparison(
        record, claimed_caller="ethereum::0xaa", claimed_target="ethereum::0xbb", claimed_selector="0x3e64ce99"
    )
    assert mismatched["verdict"] == EX.ROUTE_MISMATCH
    assert mismatched["selector_matches"] is False


# 2. the producer: services/effects

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
    """F6. The caller is written where a consumer can reach it — and on
    ``concrete``, so it can never ride the behavioral cache onto a twin."""
    eff = _value_out([_moved()])
    assert eff.verdict == VERDICT_PROVEN
    record = eff.concrete[EX.PROVING_EXECUTION_KEY]
    assert record["caller"] == PRINCIPAL.lower()
    assert record["target"] == CONTRACT.lower()
    assert record["selector"] == CALLDATA[:10]
    assert record["calldata"] == CALLDATA
    assert record["succeeded"] is True
    assert (record["block_number"], record["block_source"]) == (1000, BLOCK_SOURCE_JOB_PIN)
    # Earned negatives: the unseeded probe succeeded, so nothing was seeded.
    assert record["input_seeded"] is False
    assert record["contract_balance_seeded"] is False
    # The code plane never sees it.
    assert EX.PROVING_EXECUTION_KEY not in eff.details


def test_the_record_names_the_seeded_call_that_landed_not_the_one_that_reverted():
    """On a seeded retry the unseeded call reverted and proved nothing."""
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
    """The verdict shape the claims bridge reads."""

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
    """The bridge is the only boundary the scorer reads across, so a record that
    stops here is a record the fold can never publish."""
    payload = {"target": CONTRACT, "calldata": CALLDATA, "caller": PRINCIPAL}
    claim = claims_bridge.verdict_to_claim(cast(Any, _Verdict({EX.PROVING_EXECUTION_KEY: payload})))
    assert claim is not None
    assert claim["witness"]["observed"][EX.PROVING_EXECUTION_KEY] == payload
    # Absence stays absence, so the consumer's third state is reachable.
    bare = claims_bridge.verdict_to_claim(cast(Any, _Verdict({})))
    assert bare is not None
    assert EX.PROVING_EXECUTION_KEY not in (bare["witness"].get("observed") or {})


# 3. the consumer: distill and fold


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
    """The negative branch keeps the reason AND the pointers: a gate that dropped
    them would turn "this row predates the record" into an unreadable silence."""
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
    """One selection rule, read once. The gate used to take the FIRST
    verdict-bearing entry and the signal the LAST, so a claim carrying two would
    have paired one verdict's dollars with another's caller."""
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
    # The record read is the SECOND entry's — the same one the signal publishes.
    assert gate.value["effect_verdict_id"] == 6
    assert gate.value["caller"] == C
    assert D._verdict_bearing_entries(entries) == entries


def test_a_claim_with_no_verdict_says_so_rather_than_going_silent():
    gate = D._proving_execution_gate(_facts([]), _Func(), [{"witness": {}}])
    assert gate.state == EX.GATE_STATE_NOT_RECORDED
    assert isinstance(gate.value, dict)
    assert gate.value["reason"] == EX.REASON_NO_VERDICT


# --- fold fixtures ----------------------------------------------------------


def _charged(state: str, usd: float = 5_000.0, *keys: str) -> FunctionSignal:
    """A ``flow.out`` signal whose reach magnitude is witnessed in ``state``."""
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
    """One priced entity holding an unpriced asset beside the priced one — a
    coverage gap by construction — charged by a magnitude in ``state``."""
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    return _charged(state), plane


# --- regression case 4 ------------------------------------------------------


def test_case4_an_attribution_derived_magnitude_publishes_neither_exact_nor_floor():
    """Regression case 4. The attribution path credits a holder's WHOLE priced
    balance off a constant-amount probe, so ``proven_exact`` is unearnable in
    principle and ``proven_floor`` claims the opposite direction."""
    reach = D._flow_reach(
        {"reach_determined": True, "observed_reach_value_usd": 1_234.0, "observed_reach_holders": [VAULT]},
        cast(Any, D._ContractFacts(contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[])),
        KEY_C,
    )
    assert reach.magnitude.state == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    assert reach.magnitude.state not in (MAGNITUDE_STATE_PROVEN_EXACT, MAGNITUDE_STATE_PROVEN_FLOOR)
    assert reach.basis == "observed_reach_value_usd(fork-proven)"
    # The ENTITY-SET bound is a different axis and is untouched.
    assert reach.bound == "exact"


def test_case4_the_genuine_floor_path_keeps_its_floor():
    """The predicate is the BASIS, not "any observed_reach_* key": a partly priced
    reach is a real floor and two composed ties turn on a floor beating an upper
    bound."""
    reach = D._flow_reach(
        {"observed_reach_priced_usd": 900.0, "observed_reach_priced_holders": [VAULT]},
        cast(Any, D._ContractFacts(contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[])),
        KEY_C,
    )
    assert reach.magnitude.state == MAGNITUDE_STATE_PROVEN_FLOOR
    assert reach.basis == "observed_reach_priced_usd(>= floor)"


def test_case4_the_upper_bound_token_is_readable_by_the_fold(fold):
    """Registration, not cosmetics: a state outside ``GATE_PROVEN_TOKENS`` is
    MALFORMED, so leaving the token unregistered would take every
    attribution-derived magnitude out at once and call it a relabel."""
    signal = _charged(MAGNITUDE_STATE_PROVEN_UPPER_BOUND)
    assert FOLD._malformed_gates(signal) == []
    assert FOLD._gate(signal, "reach_magnitude_usd").state == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    finding = _eoa_finding(fold, signal, value_plane({KEY_C: {"usdc": 5_000_000.0}}))
    assert finding["value_at_stake_usd"] == 5_000.0


# --- regression case 5 (and case 7's subsumed parity) -----------------------


def test_case5_a_coverage_gap_over_an_attribution_derived_figure_earns_no_floor(fold):
    """Regression case 5. The row's only contribution bounds the principal from
    ABOVE and a gap in coverage cannot turn that into an at-least."""
    finding = _eoa_finding(fold, *_gapped_row(MAGNITUDE_STATE_PROVEN_UPPER_BOUND))
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert finding["value_at_stake_is_floor"] is False
    assert not finding["value_band"].startswith(">= ")
    # And the dollars did not move: this is a claim change, not a value change.
    assert finding["value_at_stake_usd"] == 5_000.0


def test_case5_a_genuine_floor_under_the_same_gap_still_earns_it(fold):
    """The other arm, so the test above cannot pass by never granting a floor."""
    finding = _eoa_finding(fold, *_gapped_row(MAGNITUDE_STATE_PROVEN_FLOOR))
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert finding["value_at_stake_is_floor"] is True
    assert finding["value_band"].startswith(">= ")


def test_case5_holds_on_a_subsumed_row_too(fold):
    """Case 7's parity clause: three investigation passes have silently measured
    findings only."""
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
    # The parity is only tested if a subsumed row was actually produced.
    assert subsumed, "the case must exercise a subsumed row, not two findings"
    for row in list(document.findings) + subsumed:
        assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED, row["capability"]
        assert not row["value_band"].startswith(">= ")


# --- the two arms V0-R ruled on, each pinned so a rename cannot pass ---------


def _unbounded_row(state: str) -> tuple[FunctionSignal, P.ValuePlane]:
    """A magnitude in ``state`` charged against an entity whose priced sheet is
    NOT DETERMINED — the case the reference corpus does not contain, and the one
    the disclosing arm exists for. No priced rows for ``KEY_C`` at all, so
    ``total`` returns None, which is the not_determined sheet and NOT a zero."""
    return _charged(state), value_plane({}, contracts=(KEY_C,))


def test_an_upper_bound_over_an_unpriced_sheet_is_never_disclosed_as_a_floor(fold):
    """The direction-earned key, pinned. A floor and an attribution-derived upper
    bound charged against an entity with no priced sheet are the SAME arithmetic
    and OPPOSITE claims, and publishing the second under ``witnessed_floor_usd``
    moves no number — so nothing but this assertion can catch it."""
    finding = _eoa_finding(fold, *_unbounded_row(MAGNITUDE_STATE_PROVEN_UPPER_BOUND))
    disclosed = finding["unbounded_floor_magnitudes"]
    assert len(disclosed) == 1
    note = disclosed[0]
    assert note["witness_state"] == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    assert note["witnessed_upper_bound_usd"] == 5_000.0
    assert "witnessed_floor_usd" not in note
    assert "ABOVE" in note["reading"]
    assert "at least this much" not in note["reading"]
    # The figure itself is unchanged by which name discloses it.
    assert finding["value_at_stake_usd"] == 5_000.0


def test_a_floor_over_an_unpriced_sheet_keeps_its_own_name_verbatim(fold):
    """The twin, so the assertion above cannot pass by never using either key."""
    note = _eoa_finding(fold, *_unbounded_row(MAGNITUDE_STATE_PROVEN_FLOOR))["unbounded_floor_magnitudes"][0]
    assert note["witness_state"] == MAGNITUDE_STATE_PROVEN_FLOOR
    assert note["witnessed_floor_usd"] == 5_000.0
    assert "witnessed_upper_bound_usd" not in note
    assert "the call moves at least this much somewhere" in note["reading"]


def _two_key_row(state: str) -> tuple[FunctionSignal, P.ValuePlane]:
    """One call witnessed over TWO priced entities — the signal-525 shape
    (``0xf3fef3a3 withdraw``, $28.1M), the only live instance of this branch."""
    return _charged(state, 3_000.0, KEY_C, KEY_V), value_plane({KEY_C: {"usdc": 2_000.0}, KEY_V: {"usdc": 2_000.0}})


def test_an_upper_bound_is_refused_across_two_keys_rather_than_apportioned(fold):
    """An EXACT witness bounds the whole call, so its keys may consume it as a
    budget. An upper bound may not: split across two entities with no
    apportionment witness it would attribute up to the WHOLE bound at each.
    Letting it join the exact side moves no number on this corpus, so only this
    assertion stands between the ruling and a silent regression."""
    finding = _eoa_finding(fold, *_two_key_row(MAGNITUDE_STATE_PROVEN_UPPER_BOUND))
    # Refused: no dollars for either entity, and the refusal is typed per key.
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
    """The twin: the refusal above must be about the STATE, not the two-key shape."""
    finding = _eoa_finding(fold, *_two_key_row(MAGNITUDE_STATE_PROVEN_EXACT))
    assert finding["value_at_stake_usd"] == 3_000.0
    assert set(finding["value_by_entity"]) == {KEY_C, KEY_V}


def test_the_floor_arm_is_not_vacuously_true_on_an_empty_contribution_set():
    """A universal over contributions is TRUE on a row with none, and a row that
    lost every figure would then publish ">= $0". The arm is written as an earned
    positive so it does not depend on ``_row_value``'s early return."""
    empty = frozenset()
    assert FOLD._bound_direction(0.0, empty, empty, True, False, empty) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert FOLD._bound_direction(None, empty, empty, True, False, empty) == FOLD.BOUND_DIRECTION_NOT_DETERMINED


# --- the record reaches the composed entry ----------------------------------


def _composing_signals(execution_payload: dict[str, Any] | None) -> list[FunctionSignal]:
    """The shared composing case, with the destination's magnitude re-witnessed
    as attribution-derived and carrying ``execution_payload`` (or the typed
    not-persisted refusal every corpus row is in today)."""
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
    """The invariant, end to end: a published magnitude names the call that
    produced it, and the route it claims is compared against that call."""
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
    # v1 publishes the bytes and decodes nothing: a positional guess off a byte
    # slice is the laundering this record exists to stop.
    assert execution["arguments_decoded"] is None

    route = entry["route_comparison"]
    # The chain's last hop is C -> V under the composed selector, and the probe
    # called V directly from the EOA: the target agrees and the caller does not.
    assert route["target_matches"] is True
    assert route["caller_matches"] is False
    assert route["verdict"] == EX.ROUTE_MISMATCH


def test_a_composed_entry_with_no_record_publishes_the_typed_reason(fold):
    """The state every entry on the reference corpus is in today: the figure is
    still published — withholding it is the composition rule's decision — but the
    entry says the execution behind it is not_determined and where to look."""
    entry = _composed(fold, None)
    execution = entry["proving_execution"]
    assert execution["state"] == EX.EXECUTION_NOT_DETERMINED
    assert execution["reason"] == EX.REASON_NOT_PERSISTED
    assert execution["transcript_ptr"] == "job::art"
    assert "caller" not in execution
    assert entry["route_comparison"]["verdict"] == EX.ROUTE_NOT_DETERMINED
    # ``execution_record_not_persisted`` is NOT one of the transport faults, so
    # the composition rule still decides the arm on the deletability join.
    assert entry["arm_taken"] == FOLD.ARM_REPUBLISHED_DIRECT
    assert entry["arm_taken"] in FOLD.COMPOSITION_ARMS


def test_the_destination_magnitude_carries_the_execution_and_its_direction():
    """``_DestinationMagnitude`` is what the composition rule reads: it must hand
    on the execution and whether the figure bounds from above."""
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
