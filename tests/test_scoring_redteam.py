"""Adversarial regression suite: every attack the red-team landed, pinned.

These drive the fold with hand-built hostile signals and stubbed planes, so they
need no database and no network. Each test names the shape it forbids: a witness
that was never read standing in for one that was, on the weakness axis, the value
axis, the gate envelopes or the published document.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from services.scoring import distill as D
from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.constants import (
    FREEZE_KEYSET_RECOVERABLE,
    FREEZE_SUSTAINABLE,
    WEAKNESS_SAFE_SINGLE_SIGNER,
    WEAKNESS_SAFE_SUPERMAJORITY,
    WEAKNESS_SAFE_UNCREDITED,
    WEAKNESS_TIMELOCK_UNDETERMINED,
    delay_discount,
)
from services.scoring.schema import (
    FunctionSignal,
    PrincipalRef,
    Tri,
    entity_key,
    not_determined_signal_defaults,
)
from utils.scoring_status import (
    SEVERITY_STATE_PROVEN,
    VALUE_BOUND_EXACT,
    VALUE_BOUND_FLOOR,
    VALUE_STATE_PROVEN_REACH,
)

C = "0x" + "a" * 40
VAULT = "0x" + "b" * 40
SAFE = "0x" + "2" * 40
SAFE2 = "0x" + "5" * 40
EOA = "0x" + "3" * 40
TIMELOCK = "0x" + "7" * 40
OWNERS = tuple("0x" + c * 40 for c in "cdef")
KEY_C = entity_key("ethereum", C)
KEY_V = entity_key("ethereum", VAULT)


def sig(**over: Any) -> FunctionSignal:
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


def flow_sig(**over: Any) -> FunctionSignal:
    """A ``flow.out`` signal carrying the gates the distiller always writes."""
    gates = {
        "token_identity": Tri.not_determined().to_json(),
        "asset_class": Tri.not_determined().to_json(),
        "input_seeded": Tri.not_determined().to_json(),
        "contract_balance_seeded": Tri.not_determined().to_json(),
        "amount_capped_by_balance": Tri.not_determined().to_json(),
        "asset_identity": Tri.not_determined().to_json(),
        **over.pop("gates", {}),
    }
    return sig(claim_id="flow.out", gates=gates, **over)


def pause_sig(**over: Any) -> FunctionSignal:
    gates = {
        "pause_effective": Tri.not_determined().to_json(),
        "freeze_recovery_principals": Tri.not_determined().to_json(),
        "freeze_coverage_fraction": Tri.not_determined().to_json(),
        **over.pop("gates", {}),
    }
    return sig(claim_id="pause.set", gates=gates, **over)


def proven(severity: float, basis: tuple[str, ...] = ("capability_class_base",)) -> dict[str, Any]:
    return {"severity": Tri.proven(SEVERITY_STATE_PROVEN, severity), "severity_basis": basis}


def reaches(*keys: str, bound: str = VALUE_BOUND_FLOOR) -> dict[str, Any]:
    return {
        "value_state": VALUE_STATE_PROVEN_REACH,
        "value_bound": bound,
        "value_entity_keys": tuple(sorted(keys)),
        "value_basis": "acting_entity",
    }


def facts(
    pid: int,
    address: str,
    resolved_type: str,
    *,
    chain: str = "ethereum",
    owners: tuple[str, ...] = (),
    threshold: int | None = None,
    delay: float | None = None,
    withheld: bool = False,
) -> P.PrincipalFacts:
    return P.PrincipalFacts(
        function_principal_id=pid,
        chain=chain,
        address=address.lower(),
        resolved_type=resolved_type,
        owners=frozenset(o.lower() for o in owners),
        threshold=threshold,
        delay_seconds=delay,
        protection_credit_withheld=withheld,
        protection_basis="safe_protection_absent(not_determined);credit_stands",
        resolver_bases=(),
        role_bindings=(),
    )


def value_plane(per_asset: dict[str, dict[str, float]] | None = None) -> P.ValuePlane:
    plane = P.ValuePlane()
    plane.per_asset = per_asset or {}
    plane.provenance = {"stub": True}
    return plane


@pytest.fixture()
def fold(monkeypatch):
    """Drive the fold with stubbed planes: no database, no network."""

    def _run(signals, *, value=None, closure=None, principals=None, role_floors=None):
        monkeypatch.setattr(P, "load_value_plane", lambda s, p: value or value_plane())
        monkeypatch.setattr(P, "load_control_closure", lambda s, p: closure or {})
        monkeypatch.setattr(P, "load_role_holder_floors", lambda s: role_floors or {})
        monkeypatch.setattr(P, "load_principal_plane", lambda s, refs: principals or {})
        monkeypatch.setattr(P, "perimeter_state", lambda s, p: ("settled", {"pending_jobs": 0}))
        monkeypatch.setattr(P, "plane_row_counts", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_upgrade_provenance", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "unconsumed_reach_relations", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_ledgers", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_audit_posture", lambda s, p: {"stub": True})
        # The planes are stubbed, so the fold never touches a session.
        return FOLD.compute_protocol_score(cast(Any, None), 1, signals=signals)

    return _run


# --------------------------------------------------------------------------
# Weakness axis
# --------------------------------------------------------------------------


def test_f3_unread_owner_set_is_not_a_k_of_k_safe(fold):
    """n backfilled from k publishes the strongest rung out of an absent witness."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", threshold=2)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["weakness"] == WEAKNESS_SAFE_UNCREDITED
    assert "2/2" not in finding["principal"] and "2/2" not in str(finding["weakest_gate"])
    assert any("safe_owner_set_not_determined" in note for note in finding["witness_notes"])


def test_f3_proven_owner_set_still_earns_its_rung(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    assert document.findings[0]["weakness"] == WEAKNESS_SAFE_SUPERMAJORITY
    assert document.findings[0]["weakest_gate"] == "Safe 3/4"


def test_f2_unread_pauser_key_set_cannot_buy_the_recoverable_credit(fold):
    recovery = [{"function_principal_id": 2, "chain": "ethereum", "address": SAFE2}]
    signal = pause_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates={"freeze_recovery_principals": Tri.proven("enumerated", recovery).to_json()},
        **proven(FREEZE_KEYSET_RECOVERABLE, ("freeze_capability_proven",)),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={
            1: facts(1, SAFE, "safe", threshold=1),  # owner set never resolved
            2: facts(2, SAFE2, "safe", owners=OWNERS, threshold=2),
        },
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}),
    )
    finding = document.findings[0]
    assert not any("keyset_independent" in note for note in finding["witness_notes"])
    assert finding["severity_proven"] == FREEZE_SUSTAINABLE
    # The single-signer cliff is not waived on the strength of a non-witness.
    assert finding["weakness"] == WEAKNESS_SAFE_UNCREDITED
    assert "freeze_recovery_independence_not_determined" in {w["kind"] for w in document.warnings}


def test_f2_an_eoa_pauser_is_its_own_key_set(fold):
    """The address fallback is admissible exactly where the principal IS a key."""
    recovery = [{"function_principal_id": 2, "chain": "ethereum", "address": SAFE2}]
    signal = pause_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"freeze_recovery_principals": Tri.proven("enumerated", recovery).to_json()},
        **proven(FREEZE_KEYSET_RECOVERABLE, ("freeze_capability_proven",)),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE2, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}),
    )
    finding = document.findings[0]
    assert any(note.startswith("keyset_independent") for note in finding["witness_notes"])
    assert finding["severity_proven"] == FREEZE_KEYSET_RECOVERABLE


def test_w3_a_proven_zero_delay_is_not_an_unread_one(fold):
    assert delay_discount(0) == 1.0
    assert delay_discount(None) is None
    assert delay_discount(-1) is None

    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", TIMELOCK),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    zero = fold(
        [signal],
        principals={1: facts(1, TIMELOCK, "timelock", delay=0.0)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    ).findings[0]
    unread = fold(
        [signal],
        principals={1: facts(1, TIMELOCK, "timelock")},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    ).findings[0]

    assert "0d" in str(zero["weakest_gate"])
    assert any("proven_zero" in note for note in zero["witness_notes"])
    assert "not_determined" in str(unread["weakest_gate"])
    assert unread["weakness"] == WEAKNESS_TIMELOCK_UNDETERMINED


def _timelock_population(include_execute: bool) -> list[FunctionSignal]:
    claims = ["timelock.schedule"] + (["timelock.execute"] if include_execute else [])
    population = [
        sig(
            claim_id=claim,
            function_name=claim.split(".")[1],
            deployment_address=TIMELOCK,
            contract_id=2,
            selector=f"0x0000000{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        )
        for index, claim in enumerate(claims)
    ]
    population.append(
        sig(
            function_name="upgradeToC",
            deployment_address=VAULT,
            contract_id=3,
            selector="0x3659cfe6",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", TIMELOCK),),
            **proven(1.0),
            **reaches(KEY_V),
        )
    )
    population.append(
        sig(
            function_name="upgradeToD",
            deployment_address=C,
            contract_id=4,
            selector="0x3659cfe7",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
            **proven(1.0),
            **reaches(KEY_C),
        )
    )
    return population


def test_f8_propose_only_does_not_collapse_a_timelock(fold):
    """The collapse asserts the Safe can ACT AS the timelock: both halves or none."""
    principals = {
        1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2),
        2: facts(2, TIMELOCK, "timelock", delay=172800.0),
    }
    plane = value_plane({KEY_V: {"usdc": 100_000_000.0}, KEY_C: {"usdc": 10_000_000.0}})

    propose_only = fold(_timelock_population(include_execute=False), principals=principals, value=plane)
    both = fold(_timelock_population(include_execute=True), principals=principals, value=plane)

    propose_units = {f["principal_unit"] for f in propose_only.findings}
    assert entity_key("ethereum", TIMELOCK) in propose_units
    timelock_row = next(f for f in propose_only.findings if f["principal_unit"] == entity_key("ethereum", TIMELOCK))
    assert timelock_row["weakness"] == WEAKNESS_TIMELOCK_UNDETERMINED

    # With both halves proven the collapse runs, and the delayed value is still
    # charged at the DISCOUNTED weakness rather than the Safe's direct one.
    collapsed = [
        f for f in both.findings + both.provenance["subsumed_rows"] if f["capability"] == "upgrade.implementation"
    ]
    assert {f["principal_unit"] for f in collapsed} == {entity_key("ethereum", SAFE)}
    weaknesses = sorted(f["weakness"] for f in collapsed)
    assert len(weaknesses) == 2 and weaknesses[0] < weaknesses[1]
    assert both.provenance["principal_units"]["timelock_collapses"]


def test_w4_an_unread_proposer_threshold_cannot_rank_as_the_strongest(fold):
    """inv.5 takes the WEAKEST path, and unread must not win by construction."""
    population = _timelock_population(include_execute=True)
    principals = {
        1: facts(1, SAFE, "safe", owners=OWNERS),  # threshold never read
        2: facts(2, TIMELOCK, "timelock", delay=172800.0),
    }
    document = fold(population, principals=principals, value=value_plane({KEY_V: {"usdc": 100_000_000.0}}))
    rows = document.findings + document.provenance["subsumed_rows"]
    timelock_rows = [f for f in rows if "timelock" in str(f["weakest_gate"])]
    assert timelock_rows, "the timelock row should still be published"
    assert "k not_determined" in str(timelock_rows[0]["weakest_gate"])
    # Uncredited quorum × the proven delay discount — never a fabricated n/n.
    assert timelock_rows[0]["weakness"] == round(WEAKNESS_SAFE_UNCREDITED * (delay_discount(172800) or 1.0), 4)


def test_w6_an_unreadable_module_set_leaves_the_kn_credit_standing():
    """§7.1: only a PROVEN module or guard withholds the demotion."""
    proven_empty = {
        "module_set": [],
        "module_set_basis": "storage_linked_list_terminated",
        "guard": "proven_zero",
        "protection_is_upper_bound": "not_determined",
    }
    unreadable = {"module_set_basis": "not_determined", "protection_is_upper_bound": "not_determined"}
    proven_module = {**proven_empty, "protection_is_upper_bound": True}
    enumerated = {"module_set": ["0x" + "9" * 40], "module_set_basis": "storage_linked_list_terminated"}
    guarded = {**proven_empty, "guard": "proven_address"}

    assert P._safe_protection_verdict({"safe_protection": proven_empty})[0] is False
    assert P._safe_protection_verdict({"safe_protection": unreadable})[0] is False
    assert P._safe_protection_verdict({})[0] is False
    assert P._safe_protection_verdict({"safe_protection": proven_module})[0] is True
    assert P._safe_protection_verdict({"safe_protection": enumerated})[0] is True
    assert P._safe_protection_verdict({"safe_protection": guarded})[0] is True


# --------------------------------------------------------------------------
# Value axis
# --------------------------------------------------------------------------


def test_f1_a_native_only_flow_is_still_bounded_by_its_witness(fold):
    """The fork proved the call moves $10; the entity's sheet is not the answer."""
    plane = value_plane({KEY_C: {"native": 1_000_000_000.0}})
    signal = flow_sig(
        function_name="sweepETH",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={
            "reach_magnitude_usd": Tri.proven("proven_exact", 10.0).to_json(),
            "asset_class": Tri.proven("proven", "native_only").to_json(),
        },
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_EXACT),
    )
    finding = fold([signal], value=plane).findings[0]
    assert finding["value_at_stake_usd"] == 10.0
    assert finding["value_band"] == "<$100k"


def test_f1_a_native_only_flow_with_no_native_row_is_not_determined(fold):
    signal = flow_sig(
        function_name="sweepETH",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"asset_class": Tri.proven("proven", "native_only").to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C),
    )
    finding = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}})).findings[0]
    assert finding["value_at_stake_usd"] is None
    assert finding["undetermined_instances"][0]["why"].startswith("native_only_flow")


def test_f4_an_unpriced_entity_is_never_exposure_zero(fold):
    priced = sig(
        function_name="upgradeToA",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    unpriced = sig(
        function_name="upgradeToB",
        deployment_address=VAULT,
        contract_id=2,
        selector="0xfeedface",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_V),
    )
    document = fold(
        [priced, unpriced],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    by_unit = {f["principal_unit"]: f for f in document.findings}
    assert by_unit[entity_key("ethereum", EOA)]["exposure_usd"] is not None
    assert by_unit[entity_key("ethereum", SAFE)]["exposure_usd"] is None
    assert document.provenance["exposure_gaps"]


def test_f11_a_withheld_grade_publishes_no_derived_figure(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=value_plane({}))
    served = document.document()

    assert served["grade_state"] == "not_determined"
    assert served["confidence_pct"] is None
    assert "pct" not in served["model_parameters"]["confidence_detail"]
    for finding in served["findings"]:
        assert "net_points_lambda" not in finding
        assert "exposure_usd" not in finding
    withheld = document.provenance["grade_withheld"]
    assert withheld["grade_lambda_computed"] is not None
    assert withheld["per_finding"]


def test_f10_the_transitive_branch_reads_the_signals_value_state(fold):
    """An unwitnessed reach charges no closure, however rich the neighbours."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
    )  # value_state stays not_determined
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        closure={KEY_C: {KEY_V}},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 900_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] is None
    assert finding["value_state"] == "not_determined"
    assert finding["undetermined_instances"]


def test_v3_the_transitive_branch_discloses_unpriced_closure_entities(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        closure={KEY_C: {KEY_V}},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_is_floor"] is True
    assert finding["value_band"].startswith(">= ")
    assert any(row["entity"] == KEY_V for row in finding["undetermined_instances"])


def test_v4_exposure_caps_on_the_entity_contribution_not_the_row_total(fold):
    """A row spread over N entities must not charge its total against each one."""
    signals = [
        flow_sig(
            function_name=f"withdraw{index}",
            deployment_address=address,
            contract_id=index + 1,
            selector=f"0x0000001{index}",
            authority_openness="open",
            principal_state="none_required",
            witness_tier="behavioral_observed",
            gates={"reach_magnitude_usd": Tri.proven("proven_exact", 100.0).to_json()},
            **proven(0.9, ("caller_arbitrary_proven",)),
            **reaches(entity_key("ethereum", address), bound=VALUE_BOUND_EXACT),
        )
        for index, address in enumerate((C, VAULT))
    ]
    document = fold(
        signals,
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 200.0
    assert finding["value_by_entity"] == {KEY_C: 100.0, KEY_V: 100.0}
    # Each entity contributes at most its own $100, never the row's $200.
    assert finding["exposure_usd"] <= 200.0


# --------------------------------------------------------------------------
# Gates and vocabulary
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# Name-as-witness, contradictions and published labels
# --------------------------------------------------------------------------


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


def test_f6_selectors_are_what_the_facts_are_built_from():
    class _Fn:
        def __init__(self, name, selector):
            self.function_name = name
            self.selector = selector

    homonym = _Fn("setUserRole", "0xdeadbeef")
    canonical = _Fn("whateverName", "0x67aff484")
    assert D._lower(homonym.selector) not in D._SOLMATE_MUTATOR_SELECTORS
    assert D._lower(canonical.selector) in D._SOLMATE_MUTATOR_SELECTORS


def test_f6_the_delay_credit_examines_the_scored_functions_own_gate():
    entries: list[dict[str, Any]] = [{"claim_id": "timelock.set_delay"}]
    ungated, _, notes = D._severity(
        _contract_facts(),
        None,
        claim_id="timelock.set_delay",
        entries=entries,
        destination=D._UNDETERMINED_DESTINATION,
        openness="restricted",
        deployment_address=C,
        self_gated=False,
    )
    gated, basis, _ = D._severity(
        _contract_facts(),
        None,
        claim_id="timelock.set_delay",
        entries=entries,
        destination=D._UNDETERMINED_DESTINATION,
        openness="restricted",
        deployment_address=C,
        self_gated=True,
    )
    assert ungated.value == 0.3
    assert "delay_change_gate_not_self_gated" in notes
    assert gated.value == 0.0
    assert "delay_change_path_self_gated" in basis


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
    """The named gate must be the argmax, not whichever row was folded last."""
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
    # No fabricated sentinel threshold reaches a published structure.
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


def test_f5_confidence_does_not_rise_when_analysis_is_lost(fold):
    answered = sig(
        function_name="upgradeTo",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    unanswered = [
        sig(
            claim_id="roles.grant",
            function_name=f"grantRole{index}",
            deployment_address="0x" + str(index) * 40,
            contract_id=10 + index,
            selector=f"0x0000000{index}",
            **proven(0.55),
            **reaches(entity_key("ethereum", "0x" + str(index) * 40)),
        )
        for index in (5, 6, 7)
    ]
    principals = {1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3)}
    plane = value_plane({KEY_C: {"usdc": 1_000_000_000.0}})

    more = fold([answered, *unanswered], principals=principals, value=plane)
    less = fold([answered], principals=principals, value=plane)
    assert less.confidence_pct is not None and more.confidence_pct is not None
    assert less.confidence_pct <= more.confidence_pct


def test_probe_n_functions_counts_distinct_functions(fold):
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
            1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3),
            2: facts(2, SAFE2, "safe", owners=OWNERS, threshold=3),
        },
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    assert all(f["n_functions"] == 1 for f in document.findings)


def test_r1_capability_principal_is_not_a_reach_relation():
    assert "capability_principal" not in P.CONTROL_RELATIONS
    assert "capability_principal" in P.UNCONSUMED_REACH_RELATIONS


def test_g2_the_destination_free_allow_list_is_disjoint_and_conservative():
    from utils.scoring_status import DESTINATION_BEARING_CLAIMS, DESTINATION_FREE_CLAIMS

    assert not set(DESTINATION_BEARING_CLAIMS) & set(DESTINATION_FREE_CLAIMS)
    for claim in ("value_router", "callee_pointer.rotate", "upgrade.implementation"):
        assert claim not in DESTINATION_FREE_CLAIMS


def test_d3_an_unanswerable_signal_outside_the_perimeter_does_not_move_confidence(fold):
    """The denominator is the value plane plus the closure — never the population.

    Injecting a signal that answers nothing, on an entity the value and control
    planes never mention, must leave the published confidence exactly where it
    was: a perimeter that grew with the analysis would let the figure be moved by
    the act of looking.
    """
    answered = sig(
        function_name="upgradeTo",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    injected = sig(
        claim_id="roles.grant",
        function_name="grantRole",
        deployment_address="0x" + "9" * 40,
        contract_id=99,
        selector="0x99999999",
        **proven(0.55),
        **reaches(entity_key("ethereum", "0x" + "9" * 40)),
    )
    principals = {1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3)}
    plane = value_plane({KEY_C: {"usdc": 1_000_000_000.0}})

    before = fold([answered], principals=principals, value=plane)
    after = fold([answered, injected], principals=principals, value=plane)
    assert after.confidence_pct == before.confidence_pct
    detail_before = before.model_parameters["confidence_detail"]
    detail_after = after.model_parameters["confidence_detail"]
    assert detail_after["perimeter_entities"] == detail_before["perimeter_entities"]
    assert detail_after["perimeter_value_weighted_denominator"] == detail_before["perimeter_value_weighted_denominator"]


def test_g5_an_undecidable_asset_identity_falls_to_the_unpriced_branch(fold):
    """Single-asset pricing is licensed by a decidable token identity, not by a sheet."""
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
    # And the gap is charged to confidence rather than being free.
    assert fold([undecidable], value=plane).model_parameters["confidence_detail"]["value_priced_pct"] is not None
