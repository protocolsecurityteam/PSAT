"""On the reference corpus the deletability join and the banned ``len(act_as_chain) == 1`` shortcut partition the 40
composed entries identically. Cases 3a (one hop, no row: withhold) and 3b (two hops, qualifying row: republish)
are constructed to tell them apart. Cases 4, 5 live in ``test_execution_record.py``.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from services.scoring import distill as D
from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef, Tri
from tests.support import composition_admission_fixtures as CA
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    EOA,
    HOP1_SELECTOR,
    KEY_C,
    KEY_T,
    KEY_V,
    SAFE,
    _composing_signals,
    _gate_row,
    _two_hop_case,
    facts,
    fold,  # noqa: F401  — the fold fixture, reused rather than forked
    proven,
    reaches,
    sig,
)
from utils import execution_record as EX

_AUTHORS_THE_AMOUNT_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param_derived", "unconstrained_proven"),)
_AUTHORS_THE_AMOUNT_AT_T = ((KEY_T, HOP1_SELECTOR, COMPOSED_SELECTOR, "param_derived", "unconstrained_proven"),)
_CONSTRAINS_THE_TARGET_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param", "constrained"),)
_FORWARDS_EVERYTHING_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param", "not_determined"),)

_DELETES_THE_VAULT_AUTHORITY = ((KEY_V, EOA, "setAuthority"),)

# Present, so a join returning no row is an earned negative.
_GATING_AUTHORITY = "0x" + "9" * 40
_VAULT_CONSULTS_AN_AUTHORITY = {("ethereum", KEY_V.partition("::")[2], COMPOSED_SELECTOR): (_GATING_AUTHORITY,)}


def _entries(row: dict[str, Any]) -> list[dict[str, Any]]:
    return list(row.get("reach_composed_magnitudes") or [])


def _withheld(row: dict[str, Any]) -> list[dict[str, Any]]:
    return list(row.get("reach_composed_magnitudes_withheld") or [])


def _refusing() -> P.DeletabilityPlane:
    return CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY)


def _licensing() -> P.DeletabilityPlane:
    return CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY)


def test_case3a_one_hop_with_no_deletability_row_does_not_republish(fold):
    """A hop-count implementation publishes $1,000,000 here."""
    row = _gate_row(CA.composed_document(fold, deletability=_refusing(), routes=_AUTHORS_THE_AMOUNT_AT_C))

    assert _entries(row) == []
    withheld = _withheld(row)
    assert len(withheld) == 1
    entry = withheld[0]
    assert entry["act_as_chain_length"] == 1

    assert entry["arm_taken"] == FOLD.ARM_GATE_ONLY
    assert entry["withheld_reason"] == P.ROUTE_AMOUNT_AUTHORED
    assert entry["route_classification"]["state"] == P.ROUTE_AMOUNT_AUTHORED
    assert entry["route_classification"]["amount_is_authored_by_the_intermediate"] is True

    assert entry["act_as_chain"][0]["caller"] == KEY_C
    assert entry["act_as_chain"][0]["destination"] == KEY_V
    assert entry["act_as_chain"][0]["witness_kind"]

    assert entry["proving_execution"]["state"] == EX.EXECUTION_NOT_DETERMINED
    assert entry["proving_execution"]["reason"] == EX.REASON_NOT_PERSISTED
    assert entry["route_comparison"]["verdict"] == EX.ROUTE_NOT_DETERMINED

    assert entry["published_usd"] is None
    assert "witnessed_usd" not in entry and "flow_out_witness" not in entry
    assert not any(isinstance(v, float) for v in entry.values())

    assert entry["authority_deletability"]["state"] == P.DELETABILITY_PROVEN_NOT_DELETABLE
    assert entry["authority_deletability"]["reason"] == P.DELETABILITY_NO_SETTER_ROW
    assert row["value_by_entity"] == {}
    assert row["entities_priced_from_a_composed_ceiling"] == []

    # Trap 16: the rule runs on the selected entries, so a withheld candidate isn't replaced by the next one.
    assert len(_entries(row)) + len(_withheld(row)) == 1
    assert {e["entity"] for e in _withheld(row)} == {KEY_V}


# The authority arm's own qualifying row: a setter on the RESOLVED authority the
# vault's ``exit`` is witnessed consulting, with NO host setter anywhere. The
# host arm is asked first, so this is the only way a composed entry publishes
# ``basis.arm == "gating_authority"`` — and without it the shape ships covered at
# the join and uncovered in the document.
_DELETES_THE_GATING_AUTHORITYS_ROLES = ((f"ethereum::{_GATING_AUTHORITY}", EOA, "setUserRole"),)


@pytest.mark.parametrize(
    "deletability,arm,setter_name",
    [
        (
            CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY),
            P.DELETABILITY_ARM_HOST,
            "setAuthority",
        ),
        (
            CA.deletability_plane(
                authority=_DELETES_THE_GATING_AUTHORITYS_ROLES,
                gating=_VAULT_CONSULTS_AN_AUTHORITY,
            ),
            P.DELETABILITY_ARM_GATING_AUTHORITY,
            "setUserRole",
        ),
    ],
    ids=["host", "gating_authority"],
)
def test_case3b_two_hops_with_a_qualifying_row_republishes_and_names_it(fold, deletability, arm, setter_name):
    """POSITIVE ARM, mandatory. Length 2 and the figure survives.

    The deletability join returns a row proving this principal can author the
    destination's calldata itself — via the HOST arm or the GATING AUTHORITY arm —
    so a route-only or hop-count rule would wrongly withhold.

    Parametrised over both arms to check the host witness: only the host arm reached a
    composed entry, so the published ``basis.arm == "gating_authority"`` had no carrier.
    """
    row = _gate_row(
        CA.composed_document(
            fold,
            deletability=deletability,
            routes=_AUTHORS_THE_AMOUNT_AT_T,
            case=_two_hop_case(),
        )
    )
    assert _withheld(row) == []
    entries = _entries(row)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["act_as_chain_length"] == 2

    assert entry["arm_taken"] == FOLD.ARM_REPUBLISHED_DIRECT
    assert entry["published_usd"] == 1_000_000.0
    assert row["value_by_entity"] == {KEY_V: 1_000_000.0}

    basis = entry["authority_deletability"]["basis"]
    assert basis["setter_function_name"] == setter_name
    # B2-R N4: a basis naming setUserRole beside setAuthority's selector can't be re-checked.
    assert basis["setter_selector"] == CA.SETTER_SELECTORS[setter_name]
    assert (basis["setter_selector"] == CA.SET_AUTHORITY_SELECTOR) == (arm == P.DELETABILITY_ARM_HOST)
    assert isinstance(basis["function_principal_id"], int)
    assert basis["principal_address"] == EOA.lower()
    assert basis["membership_quality"] == "exact"
    assert entry["authority_deletability"]["state"] == P.DELETABILITY_DELETABLE
    assert basis["arm"] == arm
    # A basis naming the destination under both arms would make the arm unfalsifiable.
    assert basis["setter_contract"] == (KEY_V if arm == P.DELETABILITY_ARM_HOST else f"ethereum::{_GATING_AUTHORITY}")
    witness = entry["authority_deletability"]["gating_authority_witness"]
    assert witness["selector_scoped"] == ([] if arm == P.DELETABILITY_ARM_HOST else [_GATING_AUTHORITY])

    assert entry["proving_execution"]["state"] == EX.EXECUTION_NOT_DETERMINED
    assert entry["proving_execution"]["reason"] == EX.REASON_NOT_PERSISTED
    assert entry["route_classification"]["state"] == P.ROUTE_AMOUNT_AUTHORED


def test_case2_a_withheld_entry_keeps_its_gate_claim_and_loses_only_the_figure(fold):
    document = CA.composed_document(
        fold, deletability=_refusing(), routes=_AUTHORS_THE_AMOUNT_AT_C, case=_two_hop_case()
    )
    entry = _withheld(_gate_row(document))[0]

    assert entry["act_as_chain_length"] == 2
    assert [step["caller"] for step in entry["act_as_chain"]] == [KEY_C, KEY_T]
    assert entry["act_as_chain"][0]["destination_acceptance"]["destination_function"] == "bulkWithdraw"
    assert entry["act_as_chain"][1]["receiver_variable"] == "vault"

    assert set(entry["route_comparison"]) >= {"verdict", "claimed_caller", "claimed_target", "selector_matches"}
    assert entry["route_comparison"]["claimed_target"] == KEY_V

    assert entry["published_usd"] is None
    assert "REFUSAL and not a zero" in entry["reading"]


def test_case6_a_withheld_entry_is_counted_by_state_and_reason_together(fold):
    """``DELETABILITY_REASONS`` mixes an earned negative with undetermined kinds."""
    row = _gate_row(CA.composed_document(fold, deletability=_refusing(), routes=_AUTHORS_THE_AMOUNT_AT_C))
    census = row["reach_composition_census"]
    assert census["composed"] == 0
    assert census["composed_withheld"] == 1
    key = f"{P.DELETABILITY_PROVEN_NOT_DELETABLE}/{P.DELETABILITY_NO_SETTER_ROW}"
    assert census["composed_withheld_by_deletability"] == {key: 1}
    assert census["composed_withheld_by_arm"] == {FOLD.ARM_GATE_ONLY: 1}
    assert census["composed_withheld_by_reason"] == {P.ROUTE_AMOUNT_AUTHORED: 1}
    assert key.startswith(P.DELETABILITY_PROVEN_NOT_DELETABLE + "/")


def test_case6_a_refusal_does_not_move_confidence(fold):
    """``refused`` feeds none of the four terms; pinned so nobody wires one in."""
    kept = CA.composed_document(fold, deletability=_licensing(), routes=_AUTHORS_THE_AMOUNT_AT_C)
    refused = CA.composed_document(fold, deletability=_refusing(), routes=_AUTHORS_THE_AMOUNT_AT_C)
    detail = kept.model_parameters["confidence_detail"]
    refused_detail = refused.model_parameters["confidence_detail"]
    assert refused.confidence_pct == min(
        refused_detail["reachability_answered_pct"],
        refused_detail["capability_scored_pct"],
        refused_detail["value_priced_pct"],
        refused_detail["reach_magnitude_witnessed_pct"],
    )
    assert refused_detail["reach_magnitude_witnessed_pct"] <= detail["reach_magnitude_witnessed_pct"]
    assert "refused" not in refused_detail


def _weaker_capability() -> Any:
    return sig(
        claim_id="ownership.transfer",
        function_name="transferOwnership",
        selector="0xf2fde38b",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.75),
        **reaches(KEY_C),
    )


def _composing_subsumed_rows(document) -> list[dict[str, Any]]:
    subsumed = list(document.provenance.get("subsumed_rows") or [])
    assert subsumed, "the case must exercise a subsumed row, not two findings"
    composing = [row for row in subsumed if _entries(row) or _withheld(row)]
    assert composing, "the subsumed row must have offered a composed candidate"
    return composing


@pytest.mark.parametrize(
    "deletability,expect_published",
    [(CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY), False), (_licensing(), True)],
    ids=["withheld", "republished"],
)
def test_case7_both_arms_hold_on_a_subsumed_row(fold, deletability, expect_published):
    """21 of 40 entries are subsumed, including a $11.36M keep-it row."""
    document = CA.composed_document(
        fold,
        signals=[*_composing_signals(), _weaker_capability()],
        deletability=deletability,
        routes=_AUTHORS_THE_AMOUNT_AT_C,
    )
    for row in _composing_subsumed_rows(document):
        if expect_published:
            assert [e["arm_taken"] for e in _entries(row)] == [FOLD.ARM_REPUBLISHED_DIRECT]
            assert _withheld(row) == []
        else:
            assert _entries(row) == []
            assert [e["arm_taken"] for e in _withheld(row)] == [FOLD.ARM_GATE_ONLY]
            assert [e["published_usd"] for e in _withheld(row)] == [None]


def test_an_unresolvable_gating_authority_is_disclosed_and_not_read_as_a_negative(fold):
    """Obscuring the gating authority LOWERS published dollars, so it
    pays unless the obscuring itself is published: the entry lands on
    ``not_determined`` under its own token and the census counts the two apart."""
    # No gating witness at all: the join cannot ask the authority arm.
    row = _gate_row(CA.composed_document(fold, routes=_AUTHORS_THE_AMOUNT_AT_C))
    entry = _withheld(row)[0]
    disclosure = entry["authority_deletability"]
    assert disclosure["state"] == P.DELETABILITY_NOT_DETERMINED
    assert disclosure["reason"] == P.DELETABILITY_AUTHORITY_UNRESOLVED
    assert disclosure["reason"] != P.DELETABILITY_NO_SETTER_ROW
    assert disclosure["destination"] == KEY_V
    assert disclosure["selector"] == COMPOSED_SELECTOR
    assert disclosure["principal_addresses"] == [EOA.lower()]
    assert disclosure["gating_authority_witness"]["selector_scoped"] == []

    census = row["reach_composition_census"]
    assert census["composed_withheld_by_deletability"] == {
        f"{P.DELETABILITY_NOT_DETERMINED}/{P.DELETABILITY_AUTHORITY_UNRESOLVED}": 1
    }
    assert row["entities_withheld_from_a_composed_ceiling"][0]["authority_deletability_state"] == (
        P.DELETABILITY_NOT_DETERMINED
    )


@pytest.mark.parametrize(
    "routes,state,reason",
    [
        (_AUTHORS_THE_AMOUNT_AT_C, P.ROUTE_AMOUNT_AUTHORED, None),
        (_CONSTRAINS_THE_TARGET_AT_C, P.ROUTE_TARGET_CONSTRAINED, None),
        (_FORWARDS_EVERYTHING_AT_C, P.ROUTE_NOT_DETERMINED, P.ROUTE_NEITHER_CONJUNCT),
        ((), P.ROUTE_NOT_DETERMINED, P.ROUTE_NO_FLOW_WITNESS),
    ],
    ids=["amount_authored", "target_constrained", "neither_conjunct", "no_flow_witness"],
)
def test_the_typed_reason_is_read_off_the_traversed_body(fold, routes, state, reason):
    """Only the stored value-flow witness differs, so a name-based rule gives one answer to all four."""
    entry = _withheld(_gate_row(CA.composed_document(fold, deletability=_refusing(), routes=routes)))[0]
    assert entry["route_classification"]["state"] == state
    assert entry["route_classification"]["reason"] == reason
    assert entry["withheld_reason"] == (state if reason is None else reason)
    # Ruling 8(b).
    assert entry["arm_taken"] == (FOLD.ARM_NOT_DETERMINED if reason else FOLD.ARM_GATE_ONLY)
    assert entry["published_usd"] is None


def test_an_unclassifiable_route_is_still_republished_where_the_join_licenses_it(fold):
    """12 of 28 surviving entries traverse a body whose flow witness classifies neither way."""
    entry = _entries(
        _gate_row(CA.composed_document(fold, deletability=_licensing(), routes=_FORWARDS_EVERYTHING_AT_C))
    )[0]
    assert entry["arm_taken"] == FOLD.ARM_REPUBLISHED_DIRECT
    assert entry["published_usd"] == 1_000_000.0
    assert entry["route_classification"]["state"] == P.ROUTE_NOT_DETERMINED
    assert entry["route_classification"]["reason"] == P.ROUTE_NEITHER_CONJUNCT


def _with_destination_gate(payload: Any) -> list[Any]:
    signals = _composing_signals()
    destination = signals[-1]
    signals[-1] = replace(destination, gate_inputs={**destination.gate_inputs, EX.PROVING_EXECUTION_KEY: payload})
    return signals


def test_an_unfetchable_transcript_withholds_even_where_the_join_licenses_it(fold):
    """The licence to issue a call doesn't substitute for knowing what it was."""
    faulted = _with_destination_gate(
        Tri.proven(
            EX.GATE_STATE_NOT_RECORDED,
            EX.not_determined(EX.REASON_FETCH_FAILED, transcript_ptr="job::art").as_json(),
        ).to_json()
    )
    row = _gate_row(
        CA.composed_document(fold, signals=faulted, deletability=_licensing(), routes=_AUTHORS_THE_AMOUNT_AT_C)
    )
    assert _entries(row) == []
    entry = _withheld(row)[0]
    assert entry["arm_taken"] == FOLD.ARM_WITHHELD
    assert entry["withheld_reason"] == EX.REASON_FETCH_FAILED
    assert entry["withheld_reason"] in EX.FAULT_REASONS
    assert entry["published_usd"] is None
    assert entry["authority_deletability"]["state"] == P.DELETABILITY_DELETABLE


def test_a_record_that_was_never_persisted_is_a_gap_and_does_not_withhold(fold):
    """Every reference-corpus verdict predates the record, so treating this as a fault withholds all forty, the
    already-refuted outcome.
    """
    assert EX.REASON_NOT_PERSISTED not in EX.FAULT_REASONS
    document = CA.composed_document(fold, deletability=_licensing(), routes=_AUTHORS_THE_AMOUNT_AT_C)
    entry = _entries(_gate_row(document))[0]
    assert entry["proving_execution"]["reason"] == EX.REASON_NOT_PERSISTED
    assert entry["published_usd"] == 1_000_000.0
    assert _gate_row(document)["value_at_stake_usd"] == 1_000_000.0


def test_a_row_that_loses_every_composed_figure_publishes_none_and_not_zero(fold):
    """An empty sum is ``0.0``, which would publish a floor earned by having nothing in it."""
    row = _gate_row(CA.composed_document(fold, deletability=_refusing(), routes=_AUTHORS_THE_AMOUNT_AT_C))
    assert row["value_at_stake_usd"] is None
    assert row["value_at_stake_usd"] != 0.0
    assert row["value_by_entity"] == {}
    assert row["value_state"] == "not_determined"
    assert row["value_band"] == "not_determined"
    assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert row["value_at_stake_is_floor"] is False
    assert not str(row["value_band"]).startswith(">=")

    assert row["entities_priced_from_a_composed_ceiling"] == []
    withheld = row["entities_withheld_from_a_composed_ceiling"]
    assert [w["entity"] for w in withheld] == [KEY_V]
    assert withheld[0]["withheld_reason"] == P.ROUTE_AMOUNT_AUTHORED
    assert withheld[0]["authority_deletability_state"] == P.DELETABILITY_PROVEN_NOT_DELETABLE
    assert withheld[0]["authority_deletability_reason"] == P.DELETABILITY_NO_SETTER_ROW


def test_a_row_that_never_composed_anything_publishes_neither_list(fold):
    lone = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(0.75),
        **reaches(KEY_C),
    )
    row = _gate_row(fold([lone], principals={1: facts(1, SAFE, "safe", threshold=2)}))
    assert row["entities_priced_from_a_composed_ceiling"] == []
    assert row["entities_withheld_from_a_composed_ceiling"] == []
    assert row["reach_composed_magnitudes"] == []
    assert row["reach_composed_magnitudes_withheld"] == []


def _transcript(**over: Any) -> dict[str, Any]:
    blob: dict[str, Any] = {
        "feature": "value_out",
        "tier": "tier1",
        "chain_id": 1,
        "block_number": 25_658_245,
        "block_source": "invocation_pin",
        "calls": [
            {"label": "value_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61aabb"},
            {"label": "sentinel_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61ccdd"},
        ],
        "results": [{"label": "value_probe", "success": True}, {"label": "sentinel_probe", "success": True}],
    }
    blob.update(over)
    return blob


def _seeded_transcript() -> dict[str, Any]:
    return _transcript(
        calls=[
            {"label": "value_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61aabb"},
            {"label": "seeded_probe", "to": "0xTOKEN", "data": "0x70a08231"},
            {"label": "seeded_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61eeff"},
            {"label": "sentinel_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61ccdd"},
        ],
        results=[
            {"label": "value_probe", "success": False},
            {"label": "seeded_probe", "success": True},
            {"label": "seeded_probe", "success": True},
            {"label": "sentinel_probe", "success": True},
        ],
        seed_attempts=[
            {"label": "seeded_probe_payable", "outcome": "skipped_no_viable_attempt"},
            {"label": "seeded_probe", "outcome": "executed"},
        ],
        input_seeded=True,
        contract_balance_seeded=False,
    )


def test_the_unseeded_probe_is_the_record_where_no_seeded_attempt_landed():
    record = EX.from_transcript(_transcript(), transcript_ptr="job::art", effect_verdict_id=7)
    assert record.is_recorded
    assert (record.caller, record.target, record.selector) == ("0xaaa", "0xbbb", "0x18457e61")
    assert record.calldata == "0x18457e61aabb"
    assert record.probe_label == "value_probe"
    assert record.succeeded is True
    assert record.input_seeded is False and record.contract_balance_seeded is False
    assert (record.block_number, record.block_source, record.chain_id, record.tier) == (
        25_658_245,
        "invocation_pin",
        1,
        "tier1",
    )
    assert "ccdd" not in record.calldata


def test_the_seeded_retry_that_landed_is_the_record_and_not_the_call_that_reverted():
    """The unseeded probe proved nothing."""
    record = EX.from_transcript(_seeded_transcript(), transcript_ptr="job::art", effect_verdict_id=7)
    assert record.probe_label == "seeded_probe"
    assert record.calldata == "0x18457e61eeff"
    assert record.succeeded is True
    assert record.input_seeded is True
    assert record.contract_balance_seeded is False
    assert record.target == "0xbbb"


@pytest.mark.parametrize(
    "blob,dropped,expected",
    [
        (_seeded_transcript, "contract_balance_seeded", {"contract_balance_seeded": EX.SEEDING_NOT_DETERMINED}),
        (_transcript, "block_source", {"block_number": None, "block_source": None}),
    ],
    ids=["seeding_qualifier", "certified_height"],
)
def test_a_field_the_transcript_does_not_state_falls_to_its_own_third_state(blob, dropped, expected):
    payload = blob()
    del payload[dropped]
    record = EX.from_transcript(payload, transcript_ptr="job::art", effect_verdict_id=7)
    for field, value in expected.items():
        assert getattr(record, field) == value
        assert getattr(record, field) is not False


def test_a_transcript_naming_no_proving_call_is_its_own_reason_and_not_a_fault():
    record = EX.from_transcript(
        _transcript(calls=[{"label": "sentinel_probe", "to": "0xBBB", "data": "0x1234"}], results=[]),
        transcript_ptr="job::art",
        effect_verdict_id=7,
    )
    assert record.state == EX.EXECUTION_NOT_DETERMINED
    assert record.reason == EX.REASON_NO_PROVING_CALL
    assert record.reason not in EX.FAULT_REASONS
    assert record.transcript_ptr == "job::art"


@pytest.mark.parametrize(
    "pointer,parts",
    [("job::art", ("job", "art")), ("job::a::b", ("job", "a::b")), ("job", None), ("::art", None), (None, None)],
)
def test_a_pointer_that_does_not_resolve_is_not_coerced_into_one(pointer, parts):
    assert EX.pointer_parts(pointer) == parts


class _FakeQuery:
    def __init__(self, outcome: Any) -> None:
        self._outcome = outcome

    def filter(self, *_a: Any) -> _FakeQuery:
        return self

    def one_or_none(self) -> Any:
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


class _FakeSession:
    def __init__(self, outcome: Any) -> None:
        self._outcome = outcome

    def query(self, *_a: Any) -> _FakeQuery:
        return _FakeQuery(self._outcome)


@pytest.mark.parametrize(
    "outcome,reason",
    [
        (None, EX.REASON_TRANSCRIPT_UNSTORED),
        (RuntimeError("boom"), EX.REASON_FETCH_FAILED),
    ],
    ids=["no_artifact_row", "transport_failure"],
)
def test_each_way_of_failing_to_reach_the_transcript_keeps_its_own_reason(outcome, reason):
    """All three are faults with different implications for retrying."""
    D.clear_transcript_cache()
    reader = D._TranscriptReader(cast(Any, _FakeSession(outcome)))
    record = reader.execution(transcript_ptr="job::art", effect_verdict_id=7)
    assert record.state == EX.EXECUTION_NOT_DETERMINED
    assert record.reason == reason
    assert record.reason in EX.FAULT_REASONS
    assert record.effect_verdict_id == 7
    D.clear_transcript_cache()


def test_an_unresolvable_pointer_never_reaches_object_storage():
    D.clear_transcript_cache()
    reader = D._TranscriptReader(cast(Any, None))  # a session use would raise
    record = reader.execution(transcript_ptr="not-a-pointer", effect_verdict_id=7)
    assert record.reason == EX.REASON_PTR_UNRESOLVABLE
    assert record.reason in EX.FAULT_REASONS


# The caller-match conjunct — "gate claims transfer ON CALLER MATCH"

# The address the last act-as step names as its caller, and one that is not it.
_CLAIMED_CALLER = KEY_C.partition("::")[2]
_OTHER_CALLER = "0x" + "9" * 40


def _signals_proved_by(caller: str) -> list[Any]:
    return _with_destination_gate(
        Tri.proven(
            EX.GATE_STATE_RECORDED,
            EX.residue_payload(
                caller=caller,
                target=KEY_V.partition("::")[2],
                calldata=COMPOSED_SELECTOR + "00" * 32,
                probe_label="value_probe",
                succeeded=True,
                block_number=25_658_245,
                block_source="invocation_pin",
                chain_id=1,
                tier="tier1",
                input_seeded=False,
                contract_balance_seeded=False,
            ),
        ).to_json()
    )


def _proved_by(fold, caller: str, deletability: P.DeletabilityPlane, **over: Any):
    return CA.composed_document(
        fold,
        signals=[*_signals_proved_by(caller), *over.pop("extra_signals", [])],
        deletability=deletability,
        routes=_AUTHORS_THE_AMOUNT_AT_C,
        **over,
    )


def test_a_gate_claim_the_proof_was_admitted_for_publishes_corroborated(fold):
    """The destination's check reads no argument, so the route is irrelevant."""
    entry = _entries(_gate_row(_proved_by(fold, _CLAIMED_CALLER, _licensing())))[0]
    claim = entry["gate_claim"]
    assert claim["state"] == EX.GATE_CLAIM_CORROBORATED
    assert claim["reason"] == EX.GATE_CLAIM_REASON_SAME_CALLER
    assert claim["proven_caller"] == _CLAIMED_CALLER
    assert claim["claimed_caller"] == KEY_C
    assert entry["route_comparison"]["caller_matches"] is True
    assert entry["route_comparison"]["verdict"] == EX.ROUTE_MISMATCH
    assert "UNCORROBORATED" not in claim["reading"]


def test_a_gate_claim_the_proof_used_another_caller_for_is_qualified_not_asserted(fold):
    """``isAuthorized(msg.sender, msg.sig)`` reads the sender exactly; the chain is qualified, never retracted."""
    row = _gate_row(_proved_by(fold, _OTHER_CALLER, _licensing()))
    entry = _entries(row)[0]
    claim = entry["gate_claim"]

    assert claim["state"] == EX.GATE_CLAIM_NOT_CORROBORATED
    assert claim["reason"] == EX.GATE_CLAIM_REASON_OTHER_CALLER
    assert claim["proven_caller"] == _OTHER_CALLER
    assert claim["claimed_caller"] == KEY_C
    assert _OTHER_CALLER in claim["reading"] and KEY_C in claim["reading"]
    assert "UNCORROBORATED" in claim["reading"]
    assert entry["act_as_chain"][0]["caller"] == KEY_C
    assert "act-as witness alone" in claim["reading"]
    assert entry["arm_taken"] == FOLD.ARM_REPUBLISHED_DIRECT
    assert entry["published_usd"] == 1_000_000.0

    assert row["reach_composition_census"]["gate_claim_by_state"] == {EX.GATE_CLAIM_NOT_CORROBORATED: 1}


def test_a_withheld_entry_carries_the_caller_conjunct_too(fold):
    row = _gate_row(_proved_by(fold, _OTHER_CALLER, _refusing()))
    entry = _withheld(row)[0]
    assert entry["arm_taken"] == FOLD.ARM_GATE_ONLY
    assert entry["gate_claim"]["state"] == EX.GATE_CLAIM_NOT_CORROBORATED
    assert entry["gate_claim"]["proven_caller"] == _OTHER_CALLER
    assert entry["published_usd"] is None
    assert row["reach_composition_census"]["gate_claim_by_state"] == {EX.GATE_CLAIM_NOT_CORROBORATED: 1}


def test_no_execution_to_compare_a_caller_against_is_its_own_state(fold):
    document = CA.composed_document(fold, deletability=_licensing(), routes=_AUTHORS_THE_AMOUNT_AT_C)
    claim = _entries(_gate_row(document))[0]["gate_claim"]
    assert claim["state"] == EX.GATE_CLAIM_NOT_DETERMINED
    assert claim["reason"] == EX.GATE_CLAIM_REASON_NOT_COMPARED
    assert claim["proven_caller"] is None
    assert claim["state"] not in (EX.GATE_CLAIM_CORROBORATED, EX.GATE_CLAIM_NOT_CORROBORATED)
    assert len(set(EX.GATE_CLAIM_STATES)) == 3


@pytest.mark.parametrize(
    "caller,state",
    [(_CLAIMED_CALLER, EX.GATE_CLAIM_CORROBORATED), (_OTHER_CALLER, EX.GATE_CLAIM_NOT_CORROBORATED)],
    ids=["corroborated", "not_corroborated"],
)
def test_the_caller_conjunct_holds_on_a_subsumed_row_too(fold, caller, state):
    """4 of the 10 caller mismatches are subsumed."""
    document = _proved_by(fold, caller, _licensing(), extra_signals=[_weaker_capability()])
    for row in _composing_subsumed_rows(document):
        for entry in _entries(row) + _withheld(row):
            assert entry["gate_claim"]["state"] == state
        assert row["reach_composition_census"]["gate_claim_by_state"] == {state: len(_entries(row) + _withheld(row))}
