"""F6: the proving caller is persisted end to end.

F4: the attribution path is ``proven_upper_bound``, not ``proven_floor``. F5: a coverage gap doesn't earn a floor over
attribution-derived contributions.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

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
    VAULT,
    C,
    facts,
    flow_sig,
    fold,  # noqa: F401  — the fold fixture, reused rather than forked
    proven,
    reaches,
    value_plane,
)
from utils import execution_record as EX
from utils.scoring_status import (
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
)


def test_a_record_naming_no_call_is_not_a_record():
    assert EX.from_residue({"caller": "0xabc"}, transcript_ptr=None, effect_verdict_id=None).reason == (
        EX.REASON_NOT_PERSISTED
    )


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


def test_case4_the_genuine_floor_path_keeps_its_floor():
    """The predicate is the basis, not any observed_reach_* key."""
    reach = D._flow_reach(
        {"observed_reach_priced_usd": 900.0, "observed_reach_priced_holders": [VAULT]},
        cast(Any, D._ContractFacts(contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[])),
        KEY_C,
    )
    assert reach.magnitude.state == MAGNITUDE_STATE_PROVEN_FLOOR
    assert reach.basis == "observed_reach_priced_usd(>= floor)"


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
