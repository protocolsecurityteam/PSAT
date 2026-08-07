"""The execution record, end to end, and the two labels that depend on it.

Three things are pinned here, and each of them is a positive fact that was being
published without a witness before:

1. **F6 — the proving caller is persisted.** The call that proved a ``flow.out``
   magnitude existed only inside the transcript blob, so no consumer of the
   figure could name the caller, the target, the selector or whether the probe
   was seeded. The recipe now records it on ``ObservedEffect.concrete``, the
   claims bridge forwards it, the distiller reads it back onto the signal and the
   fold publishes it beside every composed magnitude.
2. **F4 — the attribution path is not exact.** ``proven_exact`` is unearnable in
   principle on a path where a constant-amount probe credits a holder's whole
   priced balance; the state is ``proven_upper_bound`` and it is emphatically not
   ``proven_floor`` either, whose prose means "at least this much".
3. **F5 — a coverage gap alone does not earn a floor.** A row whose contributions
   are attribution-derived is bounded from above, so summing them under a ">= "
   band publishes the opposite of what the evidence supports.

The fold cases here build their own planes rather than importing
``test_scoring_redteam``'s: this module and that one are edited by different
units, and a shared helper is a shared blast radius.
"""

from __future__ import annotations

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
from services.scoring.schema import (
    FunctionSignal,
    PrincipalRef,
    Tri,
    entity_key,
    not_determined_signal_defaults,
)
from tests.test_effects_harness import RecordingStore, transfer_log
from utils import execution_record as EX
from utils.scoring_status import (
    MAGNITUDE_STATE_PROVEN_EXACT,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    SEVERITY_STATE_PROVEN,
    VALUE_BOUND_FLOOR,
    VALUE_STATE_PROVEN_REACH,
)

# ---------------------------------------------------------------------------
# 1. the shape itself
# ---------------------------------------------------------------------------


def test_an_absent_record_is_not_determined_and_never_an_empty_execution():
    """Every verdict written before the record existed carries no key at all,
    and that absence must reach the consumer as its own state — with a reason,
    the pointers to go and look, and no caller."""
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
    """``target`` and ``calldata`` are required. A payload with neither describes
    no execution, and admitting it would publish a block that claims to name one."""
    assert EX.from_residue({"caller": "0xabc"}, transcript_ptr=None, effect_verdict_id=None).reason == (
        EX.REASON_NOT_PERSISTED
    )


def test_the_seeding_qualifiers_are_three_valued_and_absence_is_the_third():
    """An absent ``input_seeded`` conflates "not seeded" with "seeding was never
    a question here". Reading it as ``False`` publishes an unqualified verdict."""
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
    """A single sentence for all seven reasons would be a data-claim that is
    FALSE on most of them: "the execution exists in the transcript the pointer
    names" is untrue of a row that has no verdict and therefore no pointer. Each
    reason states what is true of every row that can carry it, and the transcript
    clause appears only where a transcript was actually pointed at."""
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


def test_an_undetermined_record_must_name_a_registered_reason():
    with pytest.raises(ValueError):
        EX.ProvingExecution(state=EX.EXECUTION_NOT_DETERMINED, reason="because")
    with pytest.raises(ValueError):
        EX.ProvingExecution(state="probably")


def test_an_uncertified_height_is_dropped_rather_than_published():
    """``new_transcript`` writes ``block_source`` only for a positive, named pin.
    Without one the height is a bystander, and publishing it as the observation's
    would be the same over-claim one field over."""
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
    mismatch. A missing conjunct never resolves to ``route_match``."""
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


# ---------------------------------------------------------------------------
# 2. the producer: services/effects
# ---------------------------------------------------------------------------

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
    """On a seeded retry the unseeded call reverted and proved nothing. Recording
    it would name an execution the verdict did not come from."""
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
    """The bridge is the only boundary the scorer reads across. A record that
    stops here is a record the fold can never publish."""
    payload = {"target": CONTRACT, "calldata": CALLDATA, "caller": PRINCIPAL}
    claim = claims_bridge.verdict_to_claim(cast(Any, _Verdict({EX.PROVING_EXECUTION_KEY: payload})))
    assert claim is not None
    assert claim["witness"]["observed"][EX.PROVING_EXECUTION_KEY] == payload
    # Absence stays absence, so the consumer's third state is reachable.
    bare = claims_bridge.verdict_to_claim(cast(Any, _Verdict({})))
    assert bare is not None
    assert EX.PROVING_EXECUTION_KEY not in (bare["witness"].get("observed") or {})


# ---------------------------------------------------------------------------
# 3. the consumer: distill and fold
# ---------------------------------------------------------------------------

C = "0x" + "a" * 40
VAULT = "0x" + "b" * 40
EOA = "0x" + "3" * 40
SAFE = "0x" + "2" * 40
KEY_C = entity_key("ethereum", C)
KEY_V = entity_key("ethereum", VAULT)
COMPOSED_SELECTOR = "0x18457e61"
CALLING_SELECTOR = "0x2ddd62ce"


class _Func:
    id = 1
    authority_roles = None


def _facts(verdicts) -> Any:
    facts = D._ContractFacts(
        contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[], verdicts={1: verdicts}
    )
    return facts


class _Row:
    def __init__(self, ptr):
        self.id = 5
        self.transcript_ptr = ptr
        self.verdict = VERDICT_PROVEN


class _Row6(_Row):
    def __init__(self, ptr):
        super().__init__(ptr)
        self.id = 6


def test_the_distiller_publishes_the_typed_reason_when_no_record_is_stored():
    """The negative branch keeps the reason AND the pointers. A gate that dropped
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
    have paired one verdict's dollars with another's caller — the failure
    _destination_magnitudes forbids one file over. Both now read
    _cited_verdict_entry, so they agree by construction rather than by two scans
    that happen to."""
    first = {"witness": {"effect_verdict_id": 5, "observed": {}}}
    second = {
        "witness": {
            "effect_verdict_id": 6,
            "observed": {EX.PROVING_EXECUTION_KEY: {"target": VAULT, "calldata": CALLDATA, "caller": C}},
        }
    }
    entries = [first, second]
    facts = _facts([_Row("job::art"), _Row6("job::art6")])

    chosen = D._cited_verdict_entry(entries)
    assert chosen is second
    gate = D._proving_execution_gate(facts, _Func(), entries)
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


def _sig(**over: Any) -> FunctionSignal:
    fields = not_determined_signal_defaults()
    fields["gate_inputs"] = {
        "exact_empty_credit": Tri.not_determined().to_json(),
        "latch_witness": Tri.not_determined().to_json(),
        "reach_magnitude_usd": Tri.not_determined().to_json(),
    }
    base: dict[str, Any] = dict(
        job_id=None,
        protocol_id=1,
        contract_id=1,
        chain="ethereum",
        deployment_address=C,
        function_name="f",
        claim_id="upgrade.implementation",
        selector="0xdeadbeef",
    )
    gates = over.pop("gates", None)
    base.update(fields)
    base.update(over)
    if gates:
        base["gate_inputs"] = {**base["gate_inputs"], **gates}
    return FunctionSignal(**base)


def _flow_sig(**over: Any) -> FunctionSignal:
    gates = {
        "token_identity": Tri.not_determined().to_json(),
        "asset_class": Tri.not_determined().to_json(),
        "input_seeded": Tri.not_determined().to_json(),
        "contract_balance_seeded": Tri.not_determined().to_json(),
        "amount_capped_by_balance": Tri.not_determined().to_json(),
        "asset_identity": Tri.not_determined().to_json(),
        **over.pop("gates", {}),
    }
    return _sig(claim_id="flow.out", gates=gates, **over)


def _reaches(*keys: str) -> dict[str, Any]:
    return {
        "value_state": VALUE_STATE_PROVEN_REACH,
        "value_bound": VALUE_BOUND_FLOOR,
        "value_entity_keys": tuple(keys),
        "value_basis": "test",
    }


def _proven(sev: float) -> dict[str, Any]:
    return {"severity": Tri.proven(SEVERITY_STATE_PROVEN, sev), "severity_basis": ("capability_class_base",)}


def _principal_facts(pid: int, address: str, kind: str, **over: Any) -> P.PrincipalFacts:
    return P.PrincipalFacts(
        function_principal_id=pid,
        chain="ethereum",
        address=address.lower(),
        resolved_type=kind,
        owners=frozenset(over.get("owners", ())),
        threshold=over.get("threshold"),
        delay_seconds=None,
        protection_credit_withheld=False,
        protection_basis="stub",
        resolver_bases=(),
        role_bindings=(),
    )


class _StubConferral(P.ConferralPlane):
    """A conferral plane that answers for signals carrying no ``function_id``.

    The stub signals here have no persisted function behind them, so the real
    per-function ``state_writes`` lookup would report every gate's rewrites as
    unextracted and no gate would confer anything. The grant is stipulated
    instead, and the stipulation is visible in the call rather than in a default.
    """

    def __init__(self, rewrites, role_functions):
        super().__init__(role_functions=dict(role_functions or {}))
        self._rewrites = frozenset(rewrites)

    def grant_for(self, capability, function_id, *, entity=None, selector=None):
        return P.GateGrant(capability, self._rewrites, True, "stub(test)", self)

    def capability_grant(self, capability):
        return self.grant_for(capability, None)


def _value_plane(per_asset, *, per_asset_state=None, contracts=()) -> P.ValuePlane:
    plane = P.ValuePlane()
    plane.per_asset = per_asset
    plane.per_asset_state = per_asset_state or {}
    plane.contract_entities = set(contracts) | set(per_asset) | set(plane.per_asset_state)
    plane.alias = {}
    plane.provenance = {"stub": True}
    return plane


@pytest.fixture()
def fold(monkeypatch):
    def _run(signals, *, value=None, closure=None, principals=None, conferral=None, act_as=None):
        empty_value = _value_plane({})
        monkeypatch.setattr(P, "discovery_relation_entities", lambda s, p: {})
        monkeypatch.setattr(P, "load_value_plane", lambda s, p: value or empty_value)
        monkeypatch.setattr(P, "load_control_closure", lambda s, p: closure or P.ControlClosure(edges=()))
        monkeypatch.setattr(P, "load_condition_plane", lambda s, p: P.ConditionPlane())
        monkeypatch.setattr(P, "load_conferral_plane", lambda s, p: conferral or P.ConferralPlane(role_functions={}))
        monkeypatch.setattr(P, "load_act_as_plane", lambda s, p: act_as or P.ActAsPlane())
        monkeypatch.setattr(P, "load_proven_eoa_entities", lambda s, p: set())
        monkeypatch.setattr(P, "load_role_holder_floors", lambda s, p: {})
        monkeypatch.setattr(P, "load_principal_plane", lambda s, refs: principals or {})
        monkeypatch.setattr(P, "perimeter_state", lambda s, p: ("settled", {"pending_jobs": 0}))
        monkeypatch.setattr(P, "plane_row_counts", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_upgrade_provenance", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "unconsumed_reach_relations", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_ledgers", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_audit_posture", lambda s, p, v: {"stub": True})
        return FOLD.compute_protocol_score(cast(Any, None), 1, signals=signals)

    return _run


def _gapped_row(state: str) -> tuple[FunctionSignal, P.ValuePlane]:
    """One priced entity holding an unpriced asset beside the priced one — a
    coverage gap by construction — charged by a magnitude in ``state``."""
    signal = _flow_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven(state, 5_000.0).to_json()},
        **_proven(1.0),
        **_reaches(KEY_C),
    )
    plane = _value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    return signal, plane


# --- regression case 4 ------------------------------------------------------


def test_case4_an_attribution_derived_magnitude_publishes_neither_exact_nor_floor(fold):
    """Regression case 4. The attribution path credits a holder's WHOLE priced
    balance off a constant-amount probe, so nothing witnesses that the call moves
    it. ``proven_exact`` is unearnable in principle there, and ``proven_floor``
    is worse than unearned — it claims the opposite direction."""
    reach = D._flow_reach(
        {
            "reach_determined": True,
            "observed_reach_value_usd": 1_234.0,
            "observed_reach_holders": [VAULT],
        },
        cast(Any, D._ContractFacts(contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[])),
        KEY_C,
    )
    assert reach.magnitude.state == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    assert reach.magnitude.state not in (MAGNITUDE_STATE_PROVEN_EXACT, MAGNITUDE_STATE_PROVEN_FLOOR)
    assert reach.basis == "observed_reach_value_usd(fork-proven)"
    # The ENTITY-SET bound is a different axis and is untouched: the holder list
    # is exact whatever the dollars claim.
    assert reach.bound == "exact"


def test_case4_the_genuine_floor_path_keeps_its_floor(fold):
    """The predicate is the BASIS, not "any observed_reach_* key". A partly
    priced reach is a real floor and must keep it — two composed ties on the
    reference corpus turn on a floor beating an upper bound."""
    reach = D._flow_reach(
        {"observed_reach_priced_usd": 900.0, "observed_reach_priced_holders": [VAULT]},
        cast(Any, D._ContractFacts(contract_id=1, protocol_id=1, chain="ethereum", address=C, functions=[])),
        KEY_C,
    )
    assert reach.magnitude.state == MAGNITUDE_STATE_PROVEN_FLOOR
    assert reach.basis == "observed_reach_priced_usd(>= floor)"


def test_case4_the_upper_bound_token_is_readable_by_the_fold(fold):
    """Registration, not cosmetics. A state outside ``GATE_PROVEN_TOKENS`` is
    MALFORMED — ``_malformed_gates`` withholds the row and ``_gate`` degrades it
    — so leaving the token unregistered would take every attribution-derived
    magnitude out at once and call it a relabel."""
    signal = _flow_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven(MAGNITUDE_STATE_PROVEN_UPPER_BOUND, 5_000.0).to_json()},
        **_proven(1.0),
        **_reaches(KEY_C),
    )
    assert FOLD._malformed_gates(signal) == []
    assert FOLD._gate(signal, "reach_magnitude_usd").state == MAGNITUDE_STATE_PROVEN_UPPER_BOUND
    document = fold(
        [signal],
        principals={1: _principal_facts(1, EOA, "eoa")},
        value=_value_plane({KEY_C: {"usdc": 5_000_000.0}}),
    )
    assert document.findings[0]["value_at_stake_usd"] == 5_000.0


# --- regression case 5 (and case 7's subsumed parity) -----------------------


def test_case5_a_coverage_gap_over_an_attribution_derived_figure_earns_no_floor(fold):
    """Regression case 5. The row's only contribution bounds the principal from
    ABOVE; a gap in coverage cannot turn that into an at-least, and the band must
    not carry the ">= " qualifier on coverage grounds alone."""
    signal, plane = _gapped_row(MAGNITUDE_STATE_PROVEN_UPPER_BOUND)
    finding = fold([signal], principals={1: _principal_facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert finding["value_at_stake_is_floor"] is False
    assert not finding["value_band"].startswith(">= ")
    # And the dollars did not move: this is a claim change, not a value change.
    assert finding["value_at_stake_usd"] == 5_000.0


def test_case5_a_genuine_floor_under_the_same_gap_still_earns_it(fold):
    """The other arm, so the test above cannot pass by never granting a floor."""
    signal, plane = _gapped_row(MAGNITUDE_STATE_PROVEN_FLOOR)
    finding = fold([signal], principals={1: _principal_facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert finding["value_at_stake_is_floor"] is True
    assert finding["value_band"].startswith(">= ")


def test_case5_holds_on_a_subsumed_row_too(fold):
    """Case 7's parity clause. A subsumed row is published under ``provenance``
    and three investigation passes have silently measured findings only."""
    weak = _sig(
        claim_id="upgrade.implementation",
        function_name="weak",
        selector="0x11111111",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates={"reach_magnitude_usd": Tri.proven(MAGNITUDE_STATE_PROVEN_UPPER_BOUND, 5_000.0).to_json()},
        **_proven(0.5),
        **_reaches(KEY_C),
    )
    strong = _flow_sig(
        function_name="strong",
        selector="0x22222222",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates={"reach_magnitude_usd": Tri.proven(MAGNITUDE_STATE_PROVEN_UPPER_BOUND, 5_000.0).to_json()},
        **_proven(1.0),
        **_reaches(KEY_C),
    )
    plane = _value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    document = fold([weak, strong], principals={1: _principal_facts(1, SAFE, "eoa")}, value=plane)
    subsumed = list(document.provenance.get("subsumed_rows") or [])
    # The parity is only tested if a subsumed row was actually produced.
    assert subsumed, "the case must exercise a subsumed row, not two findings"
    for row in list(document.findings) + subsumed:
        assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED, row["capability"]
        assert not row["value_band"].startswith(">= ")


# --- the two arms V0-R ruled on, each pinned so a rename cannot pass ---------


def _unbounded_row(state: str, *, usd: float = 5_000.0) -> tuple[FunctionSignal, P.ValuePlane]:
    """A magnitude in ``state`` charged against an entity whose priced sheet is
    NOT DETERMINED — the case the reference corpus does not contain, and the one
    the disclosing arm exists for."""
    signal = _flow_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven(state, usd).to_json()},
        **_proven(1.0),
        **_reaches(KEY_C),
    )
    # No priced rows for KEY_C at all: ``total`` returns None, which is the
    # not_determined sheet and NOT a zero.
    return signal, _value_plane({}, contracts=(KEY_C,))


def test_an_upper_bound_over_an_unpriced_sheet_is_never_disclosed_as_a_floor(fold):
    """The direction-earned key, pinned.

    A floor and an attribution-derived upper bound charged against an entity with
    no priced sheet are the SAME arithmetic and OPPOSITE claims. Publishing the
    second under ``witnessed_floor_usd`` republishes a ceiling as an at-least —
    and it moves no number, so nothing but this assertion can catch it."""
    signal, plane = _unbounded_row(MAGNITUDE_STATE_PROVEN_UPPER_BOUND)
    finding = fold([signal], principals={1: _principal_facts(1, EOA, "eoa")}, value=plane).findings[0]
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
    """The twin, so the assertion above cannot pass by never using either key.
    The floor path is byte-identical to what it published before the third
    magnitude state existed."""
    signal, plane = _unbounded_row(MAGNITUDE_STATE_PROVEN_FLOOR)
    finding = fold([signal], principals={1: _principal_facts(1, EOA, "eoa")}, value=plane).findings[0]
    note = finding["unbounded_floor_magnitudes"][0]
    assert note["witness_state"] == MAGNITUDE_STATE_PROVEN_FLOOR
    assert note["witnessed_floor_usd"] == 5_000.0
    assert "witnessed_upper_bound_usd" not in note
    assert "the call moves at least this much somewhere" in note["reading"]


def _two_key_row(state: str) -> tuple[FunctionSignal, P.ValuePlane]:
    """One call witnessed over TWO priced entities — the signal-525 shape
    (``0xf3fef3a3 withdraw``, two ``value_entity_keys``, $28.1M), which is the
    only live instance of this branch in the database."""
    signal = _flow_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven(state, 3_000.0).to_json()},
        **_proven(1.0),
        **_reaches(KEY_C, KEY_V),
    )
    plane = _value_plane({KEY_C: {"usdc": 2_000.0}, KEY_V: {"usdc": 2_000.0}})
    return signal, plane


def test_an_upper_bound_is_refused_across_two_keys_rather_than_apportioned(fold):
    """The apportionment refusal, pinned on the state that joined the vocabulary.

    An EXACT witness bounds the whole call, so its keys may consume it as a
    budget. An upper bound may not: split across two entities with no
    apportionment witness it would attribute up to the WHOLE bound at each, which
    is the balance-sheet-as-a-reach error with a ceiling in place of a sheet.
    Letting it join the exact side moves no number on this corpus — signal 525
    scores in no row — so only this assertion stands between the ruling and a
    silent regression."""
    signal, plane = _two_key_row(MAGNITUDE_STATE_PROVEN_UPPER_BOUND)
    finding = fold([signal], principals={1: _principal_facts(1, EOA, "eoa")}, value=plane).findings[0]
    # Refused: no dollars are published for either entity, and the refusal is
    # typed per key rather than left as an absence.
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
    """The twin. The refusal above must be about the STATE, not about the
    two-key shape — an exact witness bounds the whole call and its keys consume
    it as a budget, which is behaviour this change must leave alone."""
    signal, plane = _two_key_row(MAGNITUDE_STATE_PROVEN_EXACT)
    finding = fold([signal], principals={1: _principal_facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert finding["value_at_stake_usd"] == 3_000.0
    assert set(finding["value_by_entity"]) == {KEY_C, KEY_V}


def test_the_floor_arm_is_not_vacuously_true_on_an_empty_contribution_set():
    """A universal over contributions is TRUE on a row with none, and a row that
    lost every figure would then publish ">= $0". The arm is written as an
    earned positive — non-empty AND every member proven not attributed — so it
    does not depend on ``_row_value``'s early return to stay correct."""
    empty = frozenset()
    assert FOLD._bound_direction(0.0, empty, empty, True, False, empty) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert FOLD._bound_direction(None, empty, empty, True, False, empty) == FOLD.BOUND_DIRECTION_NOT_DETERMINED


# --- the record reaches the composed entry ----------------------------------


def _composing_case() -> dict[str, Any]:
    return {
        "closure": P.ControlClosure(
            edges=(
                P.ControlEdge(
                    principal=KEY_C,
                    anchor=KEY_V,
                    relation="role_principal",
                    scope=P.parse_edge_scope("roles 12", "role_principal"),
                    witness=P.EDGE_WITNESS_CONTROL_GRAPH,
                ),
            )
        ),
        "conferral": _StubConferral(("owner",), {(KEY_V, 12): (P.LicensedFunction(COMPOSED_SELECTOR, "exit"),)}),
        "act_as": P.ActAsPlane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)},
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
        ),
        "value": _value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C,)),
    }


def _composing_signals(execution_payload: dict[str, Any] | None) -> list[FunctionSignal]:
    gate = _sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **_proven(0.75),
        **_reaches(KEY_C),
    )
    record = (
        Tri.proven(EX.GATE_STATE_RECORDED, execution_payload)
        if execution_payload is not None
        else Tri.proven(
            EX.GATE_STATE_NOT_RECORDED,
            EX.not_determined(EX.REASON_NOT_PERSISTED, transcript_ptr="job::art", effect_verdict_id=9).as_json(),
        )
    )
    destination = _flow_sig(
        deployment_address=VAULT,
        contract_id=2,
        function_name="exit",
        selector=COMPOSED_SELECTOR,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        witness_tier="behavioral_observed",
        gates={
            "reach_magnitude_usd": Tri.proven(MAGNITUDE_STATE_PROVEN_UPPER_BOUND, 1_000_000.0).to_json(),
            EX.PROVING_EXECUTION_KEY: record.to_json(),
        },
        **_proven(0.9),
        **_reaches(KEY_V),
    )
    return [gate, destination]


def _principals() -> dict[int, P.PrincipalFacts]:
    return {
        1: _principal_facts(1, EOA, "eoa"),
        2: _principal_facts(2, SAFE, "safe", owners=tuple("0x" + c * 40 for c in "cdef"), threshold=3),
    }


def _entry(document) -> dict[str, Any]:
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
    entry = _entry(fold(_composing_signals(payload), principals=_principals(), **_composing_case()))

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
    """The state every entry on the reference corpus is in today. The figure is
    still published — withholding it is the composition rule's decision, not this
    unit's — but the entry says, in its own words, that the execution behind it is
    not_determined and where to go and look."""
    entry = _entry(fold(_composing_signals(None), principals=_principals(), **_composing_case()))
    execution = entry["proving_execution"]
    assert execution["state"] == EX.EXECUTION_NOT_DETERMINED
    assert execution["reason"] == EX.REASON_NOT_PERSISTED
    assert execution["transcript_ptr"] == "job::art"
    assert "caller" not in execution
    assert entry["route_comparison"]["verdict"] == EX.ROUTE_NOT_DETERMINED
    # No arm has been taken by this fold, and it says so rather than implying one
    # from the presence of a figure.
    assert entry["arm_taken"] == FOLD.ARM_NOT_DETERMINED
    assert entry["arm_taken"] in FOLD.COMPOSITION_ARMS


def test_the_destination_magnitude_carries_the_execution_and_its_direction(fold):
    """``_DestinationMagnitude`` is what the composition rule reads. It must hand
    on the execution and whether the figure bounds from above, or the rule has to
    re-derive both from strings."""
    signals = _composing_signals(None)
    magnitudes = FOLD._destination_magnitudes(signals)
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
