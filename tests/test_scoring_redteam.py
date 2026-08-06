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
    FREEZE_CAPABILITY_PROVEN,
    FREEZE_KEYSET_RECOVERABLE,
    FREEZE_SUSTAINABLE,
    WEAKNESS_SAFE_MAJORITY,
    WEAKNESS_SAFE_MINORITY,
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
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
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
PROXY = "0x" + "6" * 40
IMPL = "0x" + "9" * 40
OWNERS = tuple("0x" + c * 40 for c in "cdef")
KEY_C = entity_key("ethereum", C)
KEY_V = entity_key("ethereum", VAULT)
KEY_PROXY = entity_key("ethereum", PROXY)
KEY_IMPL = entity_key("ethereum", IMPL)


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


def magnitude(usd: float) -> dict[str, Any]:
    """A witnessed reach magnitude, so the reach-magnitude term is not the minimum.

    A perimeter test asserts on the perimeter; leaving the magnitude unwitnessed
    would make every one of them a test of the reach-magnitude term instead.
    """
    return {"reach_magnitude_usd": Tri.proven("proven_floor", usd).to_json()}


def bounded_by_sheet(usd: float) -> dict[str, Any]:
    """An EXACT magnitude witness, so the entity's sheet may bound the charge.

    A magnitude witness is the only thing that puts a dollar figure on a reach:
    the reached entity's balance sheet answers "how much is there", never "how
    much can this reach move", and the fold refuses to substitute one for the
    other. A test whose subject is the exposure budget, the tie disclosure or the
    floor flag needs a row that publishes dollars at all, so it carries the
    witness the real signal would have to carry — usually set to the sheet, which
    is the case where ``min(sheet, witness)`` leaves the sheet standing.
    """
    return {"reach_magnitude_usd": Tri.proven("proven_exact", usd).to_json()}


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


def value_plane(
    per_asset: dict[str, dict[str, float]] | None = None,
    contracts: tuple[str, ...] = (),
    alias: dict[str, str] | None = None,
    per_asset_state: dict[str, dict[str, str]] | None = None,
) -> P.ValuePlane:
    plane = P.ValuePlane()
    plane.per_asset = per_asset or {}
    plane.per_asset_state = per_asset_state or {}
    # The confidence perimeter's base population, as the DB would supply it.
    plane.contract_entities = set(contracts) | set(plane.per_asset) | set(plane.per_asset_state)
    plane.alias = alias or {}
    plane.provenance = {"stub": True}
    return plane


def closure_of(
    adjacency: dict[str, set[str]] | None,
    *,
    relation: str = "controller_value",
    label: str | None = "owner",
) -> P.ControlClosure:
    """A ``ControlClosure`` from bare ``{principal: {anchor}}`` adjacency.

    The relation and label are stub witness detail — these tests assert on reach
    membership, which is the whole of what the closure carried before it carried
    scope. A test that means to exercise a scope passes its own.
    """
    return P.ControlClosure(
        edges=tuple(
            P.ControlEdge(
                principal=principal,
                anchor=anchor,
                relation=relation,
                scope=P.parse_edge_scope(label, relation),
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
            )
            for principal, anchors in sorted((adjacency or {}).items())
            for anchor in sorted(anchors)
        )
    )


def condition_plane(
    *,
    licensed: dict[tuple[str, str], tuple[tuple[str, int, tuple[str, ...]], ...]] | None = None,
    by_entity: dict[str, tuple[tuple[str, int, tuple[str, ...]], ...]] | None = None,
) -> P.ConditionPlane:
    """A ``ConditionPlane`` from ``{key: ((name, id, conditions), ...)}``.

    Empty by default, which is the "no destination function was analysed" state:
    the walk consults nothing, no caller condition is witnessed, and every hop
    stands on its edge — the behaviour every test written before the plane
    existed asserts.
    """

    def rows(spec):
        return {
            key: tuple(P.DestinationFunction(fid, name, conds) for name, fid, conds in entries)
            for key, entries in (spec or {}).items()
        }

    plane = P.ConditionPlane()
    plane.by_entity = rows(by_entity)
    plane.licensed = rows(licensed)
    plane.provenance = {"stub": True}
    return plane


@pytest.fixture()
def fold(monkeypatch):
    """Drive the fold with stubbed planes: no database, no network."""

    def _run(
        signals,
        *,
        value=None,
        closure=None,
        principals=None,
        role_floors=None,
        eoas=None,
        discovery=None,
        conditions=None,
    ):
        """``signals=None`` drives the PERSISTED path, through the population read."""
        monkeypatch.setattr(P, "discovery_relation_entities", lambda s, p: discovery or {})
        monkeypatch.setattr(P, "load_value_plane", lambda s, p: value or value_plane())
        monkeypatch.setattr(P, "load_control_closure", lambda s, p: closure_of(closure))
        monkeypatch.setattr(P, "load_condition_plane", lambda s, p: conditions or condition_plane())
        monkeypatch.setattr(P, "load_proven_eoa_entities", lambda s, p: eoas or set())
        monkeypatch.setattr(P, "load_role_holder_floors", lambda s, p: role_floors or {})
        monkeypatch.setattr(P, "load_principal_plane", lambda s, refs: principals or {})
        monkeypatch.setattr(P, "perimeter_state", lambda s, p: ("settled", {"pending_jobs": 0}))
        monkeypatch.setattr(P, "plane_row_counts", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_upgrade_provenance", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "unconsumed_reach_relations", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_ledgers", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_audit_posture", lambda s, p, v: {"stub": True})
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


def _pause_document(fold, pauser: P.PrincipalFacts, recovery: P.PrincipalFacts | None):
    entries = [{"function_principal_id": 2, "chain": "ethereum", "address": recovery.address}] if recovery else None
    signal = pause_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", pauser.address),),
        gates=(
            {"freeze_recovery_principals": Tri.proven("enumerated", entries).to_json()} if entries is not None else {}
        ),
        **proven(FREEZE_CAPABILITY_PROVEN, ("freeze_capability_proven",)),
        **reaches(KEY_C),
    )
    principals = {1: pauser}
    if recovery is not None:
        principals[2] = recovery
    return fold([signal], principals=principals, value=value_plane({KEY_C: {"usdc": 5_000_000.0}}))


def test_f2_an_unread_pauser_key_set_moves_severity_in_neither_direction(fold):
    """The freezing key set was never read, so independence is uncomputable.

    Nothing may move on that: not the recoverable credit (which would need proven
    independence) and not the sustainable component (which would need proven
    dependence). The question is published instead.
    """
    document = _pause_document(
        fold,
        facts(1, SAFE, "safe", threshold=1),  # owner set never resolved
        facts(2, SAFE2, "safe", owners=OWNERS, threshold=2),
    )
    finding = document.findings[0]
    assert not any("keyset_independent" in note for note in finding["witness_notes"])
    assert finding["severity_proven"] == FREEZE_CAPABILITY_PROVEN
    # The single-signer cliff is not waived on the strength of a non-witness.
    assert finding["weakness"] == WEAKNESS_SAFE_UNCREDITED
    assert "freeze_recovery_independence_not_determined" in {w["kind"] for w in document.warnings}
    assert "freeze_recovery_independence_not_determined" in finding["severity_basis"]


def test_f2_every_undetermined_recovery_arm_lands_on_the_same_rung(fold):
    """No recovery claim, an unresolved recovery principal and an unread key set."""
    pauser = facts(1, SAFE, "safe", owners=OWNERS, threshold=2)
    arms = [
        _pause_document(fold, pauser, None),
        _pause_document(fold, pauser, facts(2, SAFE2, "contract")),
        _pause_document(fold, facts(1, SAFE, "safe", threshold=2), facts(2, SAFE2, "safe", owners=OWNERS, threshold=2)),
    ]
    assert {document.findings[0]["severity_proven"] for document in arms} == {FREEZE_CAPABILITY_PROVEN}


def test_f2_proven_dependence_adds_the_sustainable_component(fold):
    """The only witness that raises the freeze rung is a PROVEN dependent key set."""
    shared = ("0x" + "1" * 40, "0x" + "2" * 40, "0x" + "3" * 40)
    document = _pause_document(
        fold,
        facts(1, SAFE, "safe", owners=shared, threshold=1),
        facts(2, SAFE2, "safe", owners=shared, threshold=2),
    )
    finding = document.findings[0]
    assert finding["severity_proven"] == FREEZE_SUSTAINABLE
    # And the single-signer cliff stands, because independence was refuted.
    assert finding["weakness"] == WEAKNESS_SAFE_SINGLE_SIGNER
    assert "freeze_keyset_not_independent" in finding["severity_basis"]


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
        gates=bounded_by_sheet(50_000_000.0),
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
    """Every closure entity is NAMED, priced or not — and none is priced by its sheet.

    The transitive branch used to publish the closure's balance sheets as the
    row's value, so the entity that could not be priced was the only one that
    appeared as a gap. Under the magnitude discipline the sheet prices nothing:
    a reach with no magnitude witness is not_determined at BOTH entities, and
    both are named. Membership is untouched — the row still reaches them.
    """
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
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])
    assert finding["value_at_stake_usd"] is None
    assert finding["value_band"] == "not_determined"
    # The floor flag is about a priced total that under-covers; there is no
    # total here, so it is False rather than a floor over nothing.
    assert finding["value_at_stake_is_floor"] is False
    named = {row["entity"] for row in finding["undetermined_instances"]}
    assert named == {KEY_C, KEY_V}
    priced_gap = next(row for row in finding["undetermined_instances"] if row["entity"] == KEY_C)
    assert priced_gap["why"].startswith("reach_magnitude_not_witnessed")
    assert finding["magnitude_witness_census"]["magnitude_not_witnessed"] == 1


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


def test_p0_a_proxy_and_its_implementation_are_one_priced_entity(fold):
    """Reaching both keys of one proxy pair charges one balance, not two.

    The plane folds the implementation's balance onto its proxy, so both keys
    answer with the same dollars; keying the row's contributions on the raw keys
    published a value at stake and an exposure that were both exactly 2x real.
    """
    signal = sig(
        deployment_address=PROXY,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(100_000_000.0),
        **proven(1.0),
        **reaches(KEY_IMPL, KEY_PROXY),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_PROXY: {"usdc": 100_000_000.0}}, alias={KEY_IMPL: KEY_PROXY}),
    )
    finding = document.findings[0]
    assert finding["reach_entities"] == [KEY_PROXY]
    assert finding["value_by_entity"] == {KEY_PROXY: 100_000_000.0}
    assert finding["value_at_stake_usd"] == 100_000_000.0
    assert finding["exposure_entities_charged"] == [KEY_PROXY]
    fraction = finding["severity_proven"] * finding["weakness"]
    assert finding["exposure_usd"] == round(fraction * 100_000_000.0, 2)
    # The denominator holds that same single balance, so charging the pair twice
    # spent more than the protocol tracks and drove the grade negative.
    assert document.grade_exposure == round(100.0 * (1.0 - fraction), 3)


def test_host_entities_name_the_deployments_not_the_reach(fold):
    """The row publishes WHERE its instances live, apart from what they reach.

    A transitive row's reach set can omit the host entirely (the host may be
    unpriced), leaving a consumer no way to name the contract the function is
    actually on. host_entities carries the deployment keys verbatim.
    """
    signal = sig(
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_V),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_V: {"usdc": 1_000.0}}),
    )
    finding = document.findings[0]
    assert finding["host_entities"] == [KEY_C]
    assert finding["reach_entities"] == [KEY_V]
    assert finding["n_entities"] == 1


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


def test_b5_the_self_gated_delay_credit_is_retired():
    """ "Every resolved principal is the contract" is a lower bound, not closure.

    The enumeration it reads is documented as a proven LOWER BOUND on the caller
    set, so "no other caller resolved" cannot license driving a capability-class
    base to exactly zero. The observation is published; the severity does not
    move on it.
    """
    entries: list[dict[str, Any]] = [{"claim_id": "timelock.set_delay"}]
    self_gated, basis, notes = D._severity(
        _contract_facts(),
        None,
        claim_id="timelock.set_delay",
        entries=entries,
        destination=D._UNDETERMINED_DESTINATION,
        openness="restricted",
        deployment_address=C,
        self_gated=True,
    )
    assert self_gated.value == 0.3
    assert "delay_gate_self_gated_lower_bound" in notes
    assert "delay_change_path_self_gated" not in basis


def test_f6_the_delay_gate_observation_names_which_arm_it_took():
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
    assert gated.value == 0.3
    assert "capability_class_base" in basis


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
        gates=bounded_by_sheet(1_000_000_000.0),
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
    # Not walked, and the exclusion carries a stated reason rather than being a
    # relation the walk happens never to mention.
    assert "capability_principal" in P.UNCONSUMED_REACH_REASONS
    # The rationale the register published before 1.1.0 was refuted: the
    # materialization budget never bites, so it cannot be the reason.
    assert "WITHDRAWN" in P.UNCONSUMED_REACH_REASONS["capability_principal"]


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
    # And the gap is charged to confidence rather than being free.
    assert fold([undecidable], value=plane).model_parameters["confidence_detail"]["value_priced_pct"] is not None


# --------------------------------------------------------------------------
# Round 2: attacking the fixes
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# Confidence perimeter admission rules
# --------------------------------------------------------------------------


def test_perimeter_folds_an_implementation_onto_its_proxy(fold):
    """An impl row is the proxy's entity: admitting both hands the impl a second
    copy of the proxy's value band that no signal could ever answer."""
    signal = sig(
        deployment_address=PROXY,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=magnitude(1_000_000_000.0),
        **proven(1.0),
        **reaches(KEY_PROXY),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane(
            {KEY_PROXY: {"usdc": 1_000_000_000.0}},
            contracts=(KEY_PROXY, KEY_IMPL),
            alias={KEY_IMPL: KEY_PROXY},
        ),
    )
    detail = document.model_parameters["confidence_detail"]
    assert detail["implementation_entities_folded"] == 1
    assert detail["perimeter_entities"] == 1
    assert detail["reachability_answered_pct"] == 100.0
    assert detail["capability_scored_pct"] == 100.0
    assert detail["value_priced_pct"] == 100.0
    assert document.confidence_pct == 100.0


def test_zero_address_is_not_a_perimeter_entity(fold):
    """A renounced-ownership 0x0 in the closure is a burn sentinel, not an
    entity whose capabilities could ever be assessed."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=magnitude(50_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}, contracts=(KEY_C,)),
        closure={KEY_C: {entity_key("ethereum", "0x" + "0" * 40)}},
    )
    detail = document.model_parameters["confidence_detail"]
    assert detail["zero_address_entities_excluded"] == 1
    assert detail["perimeter_entities"] == 1
    assert document.confidence_pct == 100.0


def test_a_proven_codeless_eoa_answers_vacuously(fold):
    """With no code there are no functions: the capability question collapses
    into the closure's reach answer — but only on the earned getCode witness,
    and never for the pricing term."""
    key_eoa = entity_key("ethereum", EOA)
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=magnitude(50_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    kwargs: dict = dict(
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}, contracts=(KEY_C,)),
        closure={key_eoa: {KEY_C}},
    )

    unproven = fold([signal], **kwargs)
    witnessed = fold([signal], **kwargs, eoas={key_eoa})

    unproven_detail = unproven.model_parameters["confidence_detail"]
    assert unproven_detail["proven_codeless_answered"] == 0
    assert unproven_detail["capability_scored_pct"] < 100.0

    detail = witnessed.model_parameters["confidence_detail"]
    assert detail["proven_codeless_answered"] == 1
    assert detail["reachability_answered_pct"] == 100.0
    assert detail["capability_scored_pct"] == 100.0
    # Holding value is a question code-lessness does not answer: the unpriced
    # EOA still charges the pricing term, and the headline stays the minimum.
    assert detail["value_priced_pct"] < 100.0
    assert witnessed.confidence_pct == detail["value_priced_pct"]

    # With the EOA's holdings priced, pricing no longer binds, and the earned
    # witness is exactly what separates a full answer from a charged gap.
    priced_kwargs = dict(
        kwargs,
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}, key_eoa: {"usdc": 1_000.0}}, contracts=(KEY_C,)),
    )
    assert fold([signal], **priced_kwargs).confidence_pct < 100.0
    assert fold([signal], **priced_kwargs, eoas={key_eoa}).confidence_pct == 100.0


# --------------------------------------------------------------------------
# Closure edge scope
# --------------------------------------------------------------------------


def test_role_labels_parse_to_the_roles_they_name():
    """A multi-role label licenses every role it names, and the pair is the scope."""
    scope = P.parse_edge_scope("roles 14,16", "role_principal")
    assert (scope.kind, scope.roles) == (P.SCOPE_ROLES, (14, 16))
    assert scope.is_determined
    assert P.parse_edge_scope("roles 12", "role_principal").roles == (12,)


def test_a_label_restating_its_relation_is_not_determined_not_an_empty_scope():
    """A label that only restates its relation names no role.

    Naming no role is not the same fact as licensing none: an empty scope reads
    as "licenses nothing", and the edge has to survive to be published as the
    shortfall it is.
    """
    scope = P.parse_edge_scope("role principal", "role_principal")
    assert scope.kind == P.SCOPE_NOT_DETERMINED
    assert not scope.is_determined
    assert scope.roles == ()
    # The verbatim label is kept: the shortfall is citable, not silently dropped.
    assert scope.label == "role principal"
    assert P.parse_edge_scope(None).kind == P.SCOPE_NOT_DETERMINED


def test_a_getter_name_is_a_state_var_scope_and_never_a_role():
    """``controller_value`` labels name a state variable.

    Reading one as a role would mint a licence out of a getter name.
    """
    scope = P.parse_edge_scope("roleRegistry", "controller_value")
    assert (scope.kind, scope.state_var, scope.roles) == (P.SCOPE_STATE_VAR, "roleRegistry", ())
    assert P.parse_edge_scope("_roles", "mapping_member").state_var == "_roles"


def test_the_closure_answers_adjacency_from_the_edges_it_carries():
    """Scope rides along with reach; it does not replace it."""
    closure = closure_of({KEY_C: {KEY_V, KEY_PROXY}})
    assert closure.principals() == (KEY_C,)
    assert closure.controlled_by(KEY_C) == tuple(sorted((KEY_V, KEY_PROXY)))
    assert closure.controlled_by(KEY_V) == ()
    assert {e.relation for e in closure.edges_from(KEY_C)} == {"controller_value"}


# --------------------------------------------------------------------------
# Value plane: which observation is current, and what a $0.00 reading proves
# --------------------------------------------------------------------------


class _Row:
    """The columns ``_reduce_observations`` reads off a balance row."""

    def __init__(self, usd, *, block=None, fetched=None, rid=0, raw="1000000"):
        self.usd_value = usd
        self.block_number = block
        self.fetched_at = fetched
        self.id = rid
        self.raw_balance = raw


def _reduce(**buckets):
    return P._reduce_observations({("k", "asset"): {a: rows for a, rows in buckets.items()}})


def test_one_account_read_twice_publishes_the_LATER_read_not_the_larger():
    """MAX across two heights of one account is a high-water mark, not a holding.

    The shape that fired on the real corpus: a proxy's live row and its
    implementation's frozen row are the SAME on-chain account read at two
    heights, folded into one bucket by the alias map. Reducing by MAX republishes
    a balance that had already moved when it was written.
    """
    account = "0x" + "1" * 40
    values, states, reduction = _reduce(
        **{account: [_Row(26_404_230.63, block=25_658_048, rid=1), _Row(14_346_384.46, block=25_691_487, rid=2)]}
    )
    assert values["k"]["asset"] == 14_346_384.46
    assert states["k"]["asset"] == P.ASSET_PRICED
    # The drop is disclosed, not silently absorbed.
    assert reduction["stale_high_water_marks_dropped"] == 1
    assert reduction["stale_high_water_usd_dropped"] == round(26_404_230.63 - 14_346_384.46, 2)
    assert reduction["height_witnessed_accounts"] == 1


def test_two_DISTINCT_accounts_are_two_holdings_and_the_entity_holds_their_sum():
    """The account is the discriminator: same account = one holding, two = two.

    Unexercised on the corpus this shipped against (every competing pair observes
    one address), so it is pinned here rather than left to a future reader to
    infer from the code.
    """
    a, b = "0x" + "1" * 40, "0x" + "2" * 40
    values, _, reduction = _reduce(**{a: [_Row(1000.0, block=10, rid=1)], b: [_Row(400.0, block=10, rid=2)]})
    assert values["k"]["asset"] == 1400.0
    assert reduction["multi_account_buckets"] == 1
    assert reduction.get("unwitnessed_account_buckets", 0) == 0


def test_an_unwitnessed_account_identity_is_never_summed():
    """Summing readings that may be one account twice re-mints the double count.

    Where the identity is missing the reduction falls back to MAX and says so,
    rather than inventing a holding out of two readings of an unknown number of
    accounts.
    """
    values, _, reduction = _reduce(**{"": [_Row(1000.0, rid=1)], "0x" + "2" * 40: [_Row(400.0, rid=2)]})
    assert values["k"]["asset"] == 1000.0
    assert reduction["unwitnessed_account_buckets"] == 1


def test_a_read_height_nobody_recorded_falls_back_to_write_order_and_says_so():
    """ERC-20 rows are never height-pinned, so most orderings are write order.

    A fact about this database, not about the chain — counted so the fiat is
    stated rather than passed off as an as-of-block reading.
    """
    import datetime as _dt

    early = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    late = _dt.datetime(2026, 2, 1, tzinfo=_dt.timezone.utc)
    account = "0x" + "1" * 40
    values, _, reduction = _reduce(**{account: [_Row(900.0, fetched=late, rid=1), _Row(100.0, fetched=early, rid=2)]})
    assert values["k"]["asset"] == 900.0
    assert reduction["write_order_accounts"] == 1
    assert reduction.get("height_witnessed_accounts", 0) == 0


def test_a_rounding_floor_reading_is_not_a_proven_zero():
    """``usd_value`` is numeric(20,2): $0.0035 stores as 0.00.

    Publishing that as a determined 0.0 mints a proven-empty balance sheet out of
    a price lookup that answered "below half a cent".
    """
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(0.0, rid=1, raw="12345")]})
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_BELOW_RESOLUTION
    assert "asset" not in plane.per_asset.get("k", {})
    assert plane.sheet_state("k") == P.SHEET_BELOW_RESOLUTION
    assert plane.total("k") is None


def test_a_proven_zero_QUANTITY_is_the_only_witness_of_an_empty_sheet():
    """The quantity, not the price, is what proves a sheet empty.

    Zero of an asset is worth zero at any price, so this is the one reading under
    which 0.00 is a number. The arm is unexercised on the shipped corpus — no row
    anywhere carries a zero raw balance — so it is pinned here.
    """
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(0.0, rid=1, raw="0")]})
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_PROVEN_ZERO
    assert plane.sheet_state("k") == P.SHEET_PROVEN_EMPTY
    assert plane.total("k") == 0.0


def test_the_three_ways_of_having_no_total_stay_apart():
    """not_determined is not one state: dust, unpriced and no rows are three."""
    plane = value_plane(
        per_asset={},
        per_asset_state={
            "dust": {"a": P.ASSET_BELOW_RESOLUTION},
            "unpriced": {"a": P.ASSET_UNPRICED},
        },
    )
    assert plane.sheet_state("dust") == P.SHEET_BELOW_RESOLUTION
    assert plane.sheet_state("unpriced") == P.SHEET_UNPRICED
    assert plane.sheet_state("never-seen") == P.SHEET_NO_ROWS
    assert [plane.total(k) for k in ("dust", "unpriced", "never-seen")] == [None, None, None]


def test_a_positive_row_beside_dust_keeps_its_positive_floor():
    """Dust withholds a number only where it is the ONLY answer."""
    plane = value_plane(
        per_asset={"k": {"good": 1000.0}},
        per_asset_state={"k": {"good": P.ASSET_PRICED, "dust": P.ASSET_BELOW_RESOLUTION}},
    )
    assert plane.sheet_state("k") == P.SHEET_PRICED
    assert plane.total("k") == 1000.0


def test_an_all_dust_sheet_charges_no_finding_a_proven_zero_exposure(fold):
    """The published shape R6 forbids: exposure 0.0 beside a proven reach.

    ``value_at_stake 0.0 / proven_reach / exposure 0.0`` reads as "this capability
    is proven to reach nothing" — an earned negative minted by a price lookup that
    answered below its own resolution.
    """
    dust_key = entity_key("base", VAULT)
    plane = value_plane(
        per_asset={KEY_PROXY: {"token": 5_000_000.0}},
        per_asset_state={
            KEY_PROXY: {"token": P.ASSET_PRICED},
            dust_key: {"dust": P.ASSET_BELOW_RESOLUTION},
        },
        contracts=(KEY_C, dust_key, KEY_PROXY),
    )
    dust = sig(
        chain="base",
        deployment_address=VAULT,
        **proven(1.0),
        **reaches(dust_key),
        authority_openness="open",
    )
    priced = sig(
        deployment_address=PROXY,
        function_name="g",
        gates=bounded_by_sheet(5_000_000.0),
        **proven(1.0),
        **reaches(KEY_PROXY),
        authority_openness="open",
    )
    document = fold([dust, priced], value=plane).document()
    row = next(r for r in document["findings"] if r["principal_unit"].startswith("base::"))
    assert row["value_at_stake_usd"] is None
    assert row["exposure_usd"] is None
    assert row["value_band"] == "not_determined"
    # The priced row beside it still scores, so this is the dust entity's own
    # answer and not a withheld grade standing in for one.
    assert document["grade_exposure"] is not None


# --------------------------------------------------------------------------
# Closure admission: the zero address, and the authority it proves absent
# --------------------------------------------------------------------------


def test_a_closure_publishes_a_zero_count_for_a_rule_that_never_fired():
    """An admission rule reports where it did NOT fire, or it discloses nothing."""
    closure = closure_of({KEY_C: {KEY_V}})
    assert closure.refusal_counts() == {P.REFUSAL_ZERO_ANCHOR: 0, P.REFUSAL_ZERO_PRINCIPAL: 0}
    assert closure.renounced_counts() == {"edges": 0, "authority_slots": 0, "anchors": 0}


def test_a_refused_edge_and_a_renounced_authority_are_counted_apart():
    """Two different facts about the same row, and only one is evidence.

    "We declined to walk an edge to the burn address" says what this scorer did;
    "this authority is held by nobody" says what the protocol is. Collapsing them
    would lose the earned negative inside a housekeeping count.
    """
    zero = entity_key("ethereum", P.ZERO_ADDRESS)
    closure = P.ControlClosure(
        edges=(),
        refusals=(
            P.RefusedEdge(
                rule=P.REFUSAL_ZERO_PRINCIPAL,
                principal=zero,
                anchor=KEY_V,
                relation="controller_value",
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
                edge_id=1,
            ),
        ),
        renounced=(
            P.RenouncedAuthority(
                anchor=KEY_V,
                relation="controller_value",
                scope=P.parse_edge_scope("owner", "controller_value"),
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
                edge_id=1,
            ),
        ),
    )
    assert closure.refusal_counts()[P.REFUSAL_ZERO_PRINCIPAL] == 1
    assert closure.renounced_counts() == {"edges": 1, "authority_slots": 1, "anchors": 1}
    # The refused edge reaches nothing: it is not in the walked graph at all.
    assert closure.principals() == ()
    assert closure.controlled_by(zero) == ()


def test_a_single_token_label_restating_its_relation_names_no_state_variable():
    """ "controller_value" on a controller_value edge is not a variable name.

    The multi-word restatements measured today ("role principal", "safe owner")
    fail the identifier check anyway; this single-token case is the one the
    restatement branch actually decides, and without it the parser would publish
    a state variable no source declares.
    """
    scope = P.parse_edge_scope("controller_value", "controller_value")
    assert (scope.kind, scope.state_var) == (P.SCOPE_NOT_DETERMINED, None)
    assert scope.label == "controller_value"
    # A real getter name on the same relation still earns the state-var reading.
    assert P.parse_edge_scope("owner", "controller_value").kind == P.SCOPE_STATE_VAR


def test_an_unpriced_reading_superseding_a_priced_one_is_counted():
    """A determined value that disappears must not disappear silently.

    The current reading answers no price where an earlier one did: the honest
    total is not_determined, and the rule that withheld it publishes where it
    fired. Unexercised on the shipped corpus, so it is pinned here.
    """
    import datetime as _dt

    early = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    late = _dt.datetime(2026, 2, 1, tzinfo=_dt.timezone.utc)
    account = "0x" + "1" * 40
    values, states, reduction = _reduce(
        **{account: [_Row(900.0, fetched=early, rid=1), _Row(None, fetched=late, rid=2)]}
    )
    assert states["k"]["asset"] == P.ASSET_UNPRICED
    assert "asset" not in values.get("k", {})
    assert reduction["unpriced_supersession_accounts"] == 1


def test_every_reduction_counter_is_published_even_where_it_never_fired():
    """A rule that reports nothing where it never applied is unreadable.

    An absent counter and a zero counter say different things, and only one of
    them is a fact about the corpus.
    """
    _, _, reduction = _reduce(**{"0x" + "1" * 40: [_Row(1000.0, rid=1)]})
    for counter in (
        "multi_account_buckets",
        "unwitnessed_account_buckets",
        "unpriced_supersession_accounts",
        "write_order_decided_accounts",
        "write_order_disagreeing_accounts",
        "stale_high_water_marks_dropped",
        f"assets_{P.ASSET_PROVEN_ZERO}",
        f"assets_{P.ASSET_BELOW_RESOLUTION}",
    ):
        assert reduction[counter] == 0, counter
    assert reduction["write_order_selected_usd"] == 0.0
    assert reduction["write_order_spread_usd"] == 0.0


def test_the_write_order_fallback_sizes_itself_in_accounts_and_dollars():
    """The disclosure has to answer "how much rests on this?", not just "did it".

    An account whose competing readings AGREE was not decided by the ordering in
    any meaningful sense, and an account with one reading was not ordered at all.
    Only the disagreeing set sizes the fiat.
    """
    import datetime as _dt

    early = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    late = _dt.datetime(2026, 2, 1, tzinfo=_dt.timezone.utc)
    disagreeing = "0x" + "1" * 40
    agreeing = "0x" + "2" * 40
    reduction = P._reduce_observations(
        {
            ("k", "a"): {disagreeing: [_Row(100.0, fetched=early, rid=1), _Row(900.0, fetched=late, rid=2)]},
            ("k", "b"): {agreeing: [_Row(50.0, fetched=early, rid=3), _Row(50.0, fetched=late, rid=4)]},
            ("k", "c"): {agreeing: [_Row(7.0, fetched=late, rid=5)]},
        }
    )[2]
    assert reduction["single_reading_accounts"] == 1
    assert reduction["write_order_decided_accounts"] == 2
    assert reduction["write_order_disagreeing_accounts"] == 1
    # The dollars that rest on the ordering, and the range they were chosen from.
    assert reduction["write_order_selected_usd"] == 900.0
    assert reduction["write_order_spread_usd"] == 800.0


def test_a_renounced_slot_is_counted_as_slots_and_as_the_edges_that_witness_it():
    """One authority slot read four times is one renounced authority.

    ``control_graph_edges`` carries a row per witnessed read, so publishing the
    row count as a slot count multiplies the earned negative by how often the
    resolver looked.
    """
    scope = P.parse_edge_scope("owner", "controller_value")
    closure = P.ControlClosure(
        edges=(),
        renounced=tuple(
            P.RenouncedAuthority(
                anchor=anchor,
                relation="controller_value",
                scope=scope,
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
                edge_id=edge_id,
            )
            for anchor, edge_id in ((KEY_V, 1), (KEY_V, 2), (KEY_V, 3), (KEY_C, 4))
        ),
    )
    assert closure.renounced_counts() == {"edges": 4, "authority_slots": 2, "anchors": 2}


# --------------------------------------------------------------------------
# W2b: per-call magnitude, budget honesty, order disclosure, floor flag
# --------------------------------------------------------------------------


def _exact_flow(magnitude: float, *keys: str) -> FunctionSignal:
    """One openly-callable ``flow.out`` call with one exact magnitude witness."""
    return flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_exact", magnitude).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(*keys, bound=VALUE_BOUND_EXACT),
    )


def test_r4_one_exact_witness_is_a_per_call_bound_not_a_per_key_one(fold):
    """A magnitude proven for one call, charged once per reached key, is N x real.

    ``min(held, magnitude)`` per key bounds each key by the witness and then sums
    them, so two keys published twice the one number the witness proved. The
    published sum may never exceed the witness the call carries.
    """
    document = fold(
        [_exact_flow(100.0, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert sum(finding["value_by_entity"].values()) <= 100.0
    # The key left with no room is not_determined: an exhausted budget is not a
    # measurement that the entity holds nothing.
    assert 0.0 not in finding["value_by_entity"].values()
    assert any(row["entity"] == KEY_V for row in finding["undetermined_instances"])
    cap = finding["witnessed_magnitude_caps"][0]
    assert (cap["witnessed_usd"], cap["uncapped_sum_usd"], cap["published_sum_usd"]) == (100.0, 200.0, 100.0)
    assert cap["entities_left_not_determined"] == [KEY_V]
    # The exposure the grade charges is bounded by the same one witness.
    assert finding["exposure_usd"] <= 100.0


def test_r4_a_capped_split_between_keys_is_published_as_order_determined(fold):
    """The cap has to fall somewhere, and where it falls is not evidence."""
    document = fold(
        [_exact_flow(100.0, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 60.0}, KEY_V: {"usdc": 60.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert finding["value_by_entity"] == {KEY_C: 60.0, KEY_V: 40.0}
    cap = finding["witnessed_magnitude_caps"][0]
    assert cap["uncapped_sum_usd"] == 120.0
    assert "not by evidence" in cap["reading"]


def test_r4_a_sub_cent_residual_is_not_a_published_zero(fold):
    """A share that rounds to $0.00 IS a published zero, whatever it was.

    Testing the residual against exact zero let a $0.004 remainder through, and
    every published dollar is rounded to the cent — so the entity reached a
    consumer at $0.00 with a proven-looking figure behind it.
    """
    document = fold(
        [_exact_flow(100.004, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 100.0}, KEY_V: {"usdc": 100.0}}),
    )
    finding = document.findings[0]
    assert finding["value_by_entity"] == {KEY_C: 100.0}
    assert finding["value_at_stake_usd"] == 100.0
    cap = finding["witnessed_magnitude_caps"][0]
    assert cap["entities_left_not_determined"] == [KEY_V]
    assert any(
        row["entity"] == KEY_V and "consumed_by_earlier_keys" in row["why"] for row in finding["undetermined_instances"]
    )


def test_r4_reach_membership_survives_a_magnitude_the_fold_refuses(fold):
    """Reach is membership; the dollars are a separate question with its own answer.

    Reading ``reach_entities`` off the value map deleted a proven membership
    whenever its magnitude was undetermined — so refusing to publish an unproven
    number would have silently emptied the reach sets it is meant to preserve.
    """
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 100.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, KEY_V, bound=VALUE_BOUND_FLOOR),
    )
    document = fold(
        [signal],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    # No magnitude survived the refusal...
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    # ...and the membership did.
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])


def test_r4_a_floor_magnitude_over_two_keys_has_no_apportionment_witness(fold):
    """A floor proves how much moves, never how it divides between holders.

    Charging the floor once per key multiplies it; splitting it between them
    invents a share nobody witnessed. Both are refused, so the call's magnitude
    is not_determined until an apportionment witness exists.
    """
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 100.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, KEY_V, bound=VALUE_BOUND_FLOOR),
    )
    document = fold(
        [signal],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_state"] == "not_determined"
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    assert {row["entity"] for row in finding["undetermined_instances"]} == {KEY_C, KEY_V}
    cap = finding["witnessed_magnitude_caps"][0]
    assert (cap["witness_state"], cap["published_sum_usd"]) == ("proven_floor", None)


def test_r4_one_key_keeps_its_floor_witness_exactly(fold):
    """The N=1 case carries no ambiguity and must not be touched by the rule."""
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 100.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_FLOOR),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert finding["value_by_entity"] == {KEY_C: 100.0}
    assert finding["witnessed_magnitude_caps"] == []


def test_r7_an_exhausted_exposure_budget_is_not_a_measured_zero(fold):
    """Rows that spent an entity's budget leave the next one nothing to measure.

    ``priced_entities`` counted the entity before the budget test, so a row whose
    every entity was already claimed landed in the priced branch with ``mine ==
    0.0`` and published ``exposure_usd: 0.0`` beside a list of charged entities —
    a measured zero out of an accounting that never ran.
    """
    signals = [
        sig(
            claim_id="upgrade.implementation",
            function_name=f"upgradeTo{index}",
            contract_id=index + 1,
            selector=f"0x0000002{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", address),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
        for index, address in enumerate((EOA, SAFE, TIMELOCK))
    ]
    document = fold(
        signals,
        principals={
            1: facts(1, EOA, "eoa"),
            2: facts(2, SAFE, "eoa"),
            3: facts(3, TIMELOCK, "eoa"),
        },
        value=value_plane({KEY_C: {"usdc": 10_000_000.0}}),
    )
    starved = [f for f in document.findings if f["exposure_usd"] is None]
    assert starved, "the third row must find no budget left"
    finding = starved[0]
    assert finding["exposure_entities_charged"] == [KEY_C]
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if g["principal_unit"] == finding["principal_unit"] and g["capability"] == finding["capability"]
    )
    exhausted = gap["budget_exhausted_entities"]
    assert [row["entity"] for row in exhausted] == [KEY_C]
    # The rows that took the budget are NAMED, so the null is attributable.
    claimants = {row["principal_unit"] for row in exhausted[0]["claimed_by"]}
    assert claimants and finding["principal_unit"] not in claimants
    assert round(sum(row["fraction_taken"] for row in exhausted[0]["claimed_by"]), 6) == 1.0
    assert gap["budget_partially_exhausted_entities"] == []


def test_r7_a_partly_charged_row_says_its_figure_is_marginal(fold):
    """A row charged at less than its own fraction publishes an understatement.

    The second row wants its full fraction of the vault and gets whatever the
    first left. The figure is still published — it is real — but reading it as
    this row's exposure to that entity is reading a marginal share as a total,
    and the gap entry is where the difference is named.
    """
    signals = [
        sig(
            claim_id="upgrade.implementation",
            function_name=f"upgradeTo{index}",
            contract_id=index + 1,
            selector=f"0x0000004{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", address),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
        for index, address in enumerate((EOA, SAFE))
    ]
    document = fold(
        signals,
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 10_000_000.0}}),
    )
    later = document.findings[1]
    assert later["exposure_usd"] is not None and later["exposure_usd"] > 0
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if g["principal_unit"] == later["principal_unit"] and g["capability"] == later["capability"]
    )
    trimmed = gap["budget_partially_exhausted_entities"]
    assert [row["entity"] for row in trimmed] == [KEY_C]
    assert trimmed[0]["fraction_taken"] < trimmed[0]["fraction_wanted"]
    assert trimmed[0]["claimed_by"][0]["principal_unit"] == document.findings[0]["principal_unit"]
    # The reading may not describe a published figure as an unmeasured one.
    assert "MARGINAL" in gap["reading"]
    assert "where the exposure is null" not in gap["reading"]


def test_r8_rows_that_tie_publish_that_the_order_decided_the_split(fold):
    """Equal points and capability leave the address string holding the money.

    The tie is broken by ``principal_unit``, and that order is spent on the
    exposure budget: the first row takes the shared entity's fraction and the
    second gets the remainder. The order stays deterministic; what it decided is
    published rather than read as an attribution.
    """
    signals = [
        sig(
            claim_id="upgrade.implementation",
            function_name=f"upgradeTo{index}",
            contract_id=index + 1,
            selector=f"0x0000003{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", address),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
        for index, address in enumerate((EOA, TIMELOCK))
    ]
    document = fold(
        signals,
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, TIMELOCK, "eoa")},
        value=value_plane({KEY_C: {"usdc": 10_000_000.0}}),
    )
    first, second = document.findings[0], document.findings[1]
    assert first["raw_points"] == second["raw_points"]
    assert first["exposure_order_tie"]["tied_with"] == [second["principal_unit"]]
    assert second["exposure_order_tie"]["tied_with"] == [first["principal_unit"]]
    assert first["exposure_order_tie"]["shared_entities"] == [KEY_C]
    assert first["exposure_order_tie"]["position_in_tie"] == 0
    assert "not by evidence" in first["exposure_order_tie"]["reading"]
    # The disclosure is about the arbitrariness, not a reason to reorder.
    assert first["exposure_usd"] > second["exposure_usd"]


def test_s5_an_entity_holding_unpriced_assets_makes_the_value_a_floor(fold):
    """A partly-priced entity is a floor even when every instance answered.

    The flag read whole-instance undetermination only, so a row reaching an
    entity whose priced sheet covers part of what it holds published its total as
    the entity's value rather than as the floor it is.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(5_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane({KEY_C: {"usdc": 5_000_000.0}})
    plane.unpriced_positions = {KEY_C: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 3e19}]}
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert finding["undetermined_instances"] == []
    assert finding["value_at_stake_is_floor"] is True
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_band"].startswith(">= ")


def test_s5_one_priced_asset_beside_unanswered_ones_is_not_a_priced_entity(fold):
    """The sheet state ranks ``priced`` first; the per-asset map holds the truth.

    An entity with one answered price and a hundred unanswered rows reads as
    ``priced`` at sheet level, so consulting that state published its one
    answered asset as the entity's value. The dominant real shape — balance rows
    whose ``usd_value`` is NULL beside rows that priced — has to make the total a
    floor, and an asset priced at the storage floor is the same shortfall.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        # One call over two keys, so the EXACT witness is a budget across them:
        # set above their sum, it leaves both sheets standing and the subject of
        # this test — the floor flag — is what the assertions read.
        gates=bounded_by_sheet(7_000_000.0),
        **proven(1.0),
        **reaches(KEY_C, KEY_V),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}, KEY_V: {"usdc": 2_000_000.0}},
        per_asset_state={
            KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED},
            KEY_V: {"usdc": P.ASSET_PRICED, "weth": P.ASSET_BELOW_RESOLUTION},
        },
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert plane.sheet_state(KEY_C) == P.SHEET_PRICED
    assert finding["undetermined_instances"] == []
    assert finding["value_at_stake_is_floor"] is True
    # A reading at the storage floor is a holding the total does not carry, so
    # it is the same shortfall as one nobody priced.
    assert finding["entities_holding_unpriced_assets"] == sorted([KEY_C, KEY_V])
    assert finding["value_band"].startswith(">= ")


def test_s5_a_fully_priced_entity_earns_its_hard_band(fold):
    """The flag is an earned negative in the other direction and must stay off."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "weth": P.ASSET_PROVEN_ZERO}},
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert finding["value_at_stake_is_floor"] is False
    assert finding["entities_holding_unpriced_assets"] == []
    assert not finding["value_band"].startswith(">= ")


def test_r21_a_reach_key_outside_the_perimeter_is_disclosed(fold):
    """The perimeter disclosure checked deployment keys and never reach keys.

    A reach key absent from the perimeter is value charged into a finding by an
    entity whose unanswered weight is in no denominator — the exact thing the
    disclosure exists to name.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C, KEY_V),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}, contracts=(KEY_C,)),
    )
    detail = document.document()["model_parameters"]["confidence_detail"]
    assert detail["signal_entities_outside_perimeter"] == [KEY_V]


# --------------------------------------------------------------------------
# Merged-unit weakness, the burn sentinel, and confidence completeness (W2c)
# --------------------------------------------------------------------------

MERGE_SHARED = tuple("0x" + c * 40 for c in "1234")
SAFE_MINORITY = "0x" + "e" * 40
SAFE_MAJORITY = "0x" + "d" * 40
KEY_ZERO = entity_key("ethereum", "0x" + "0" * 40)
OUTSIDER = "0x" + "8" * 40
KEY_OUTSIDER = entity_key("ethereum", OUTSIDER)


def _merged_unit_signals(claim: str = "upgrade.implementation"):
    """Two upgrade witnesses on two entities, one per member of a merged Safe unit."""
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
    """Value only the 4/8 member reaches is not priced at the 3/7 member's rung.

    ``_row_for`` keeps the max weakness over the unit's members while the row
    folds the UNION of their reach. inv. 5's weakest path is the weakest path TO
    THAT ENTITY, and the published union — which no single member reaches — is
    priced at the coalition able to act as every contributing member.
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
    # The union is priced at the HARDEST rung among the contributing members —
    # no union is charged at a rung some contributing member never has to clear —
    # and the published principal is the member that sets that rung.
    assert finding["weakness"] == WEAKNESS_SAFE_MAJORITY
    assert finding["weakest_gate"] == "Safe 4/8"
    assert SAFE_MAJORITY in finding["principal"]
    # Exposure charges each entity at ITS rung, not the unit's weakest member.
    assert finding["exposure_usd"] == pytest.approx(
        WEAKNESS_SAFE_MINORITY * 1_000_000.0 + WEAKNESS_SAFE_MAJORITY * 5_000_000.0
    )


def test_r9_members_at_one_rung_leave_the_row_untouched(fold):
    """The re-attribution fires on a DISAGREEMENT, never as a blanket rewrite."""
    document = fold(
        _merged_unit_signals(),
        # Both members 4/8-equivalent: 4/8 and 3/7 disagree, 4/8 and 4/8 do not.
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


def test_r10_the_burn_sentinel_is_never_charged_a_sheet(fold):
    """A witness that names ``0x0`` has proved no reach, and routes none.

    Ownership renounced to the zero address makes it the single largest fan-out
    in the graph; a repoint witness naming it would otherwise hand one finding
    everything the sentinel "controls". The perimeter refuses it as an entity and
    the fold refuses it as a reach key, so nothing behind it is reachable.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(1_000.0),
        **proven(1.0),
        **reaches(KEY_C, KEY_ZERO),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        # The sentinel as a live control hub: refusing it must also refuse
        # everything only it reaches.
        closure={KEY_ZERO: {KEY_V}},
        value=value_plane(
            {
                KEY_C: {"usdc": 1_000.0},
                KEY_ZERO: {"usdc": 4_000_000_000.0},
                KEY_V: {"usdc": 900_000_000.0},
            }
        ),
    )
    finding = document.findings[0]
    assert finding["reach_entities"] == [KEY_C]
    assert KEY_ZERO not in finding["value_by_entity"] and KEY_V not in finding["value_by_entity"]
    assert finding["value_at_stake_usd"] == 1_000.0
    assert "zero_address_reach_key_refused" in finding["witness_notes"]
    detail = document.model_parameters["confidence_detail"]
    assert detail["zero_address_entities_excluded"] >= 1
    assert not any(key.endswith("::" + "0x" + "0" * 40) for key in detail["signal_entities_outside_perimeter"])


def _magnitude_document(fold, *, witnessed: bool):
    gates = (
        {"reach_magnitude_usd": Tri.proven("proven_exact", 250_000.0).to_json()}
        if witnessed
        else {"reach_magnitude_usd": Tri.not_determined().to_json()}
    )
    signal = sig(
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
    """The confidence axis grows the term the unknown magnitude belongs in.

    Without it a gate-control reach counts as fully answered, fully scored and
    priced, so "we could not prove how much this moves" had nowhere to land but
    the grade.
    """
    unwitnessed_doc = _magnitude_document(fold, witnessed=False)
    witnessed_doc = _magnitude_document(fold, witnessed=True)
    unwitnessed = unwitnessed_doc.model_parameters["confidence_detail"]
    witnessed = witnessed_doc.model_parameters["confidence_detail"]
    assert unwitnessed["reach_magnitude_witnessed_pct"] == 0.0
    assert witnessed["reach_magnitude_witnessed_pct"] == 100.0
    assert unwitnessed["reach_magnitude_signals"]["proven_reach_in_denominator"] == 1
    assert unwitnessed["reach_magnitude_signals"]["magnitude_witnessed"] == 0
    # Answering the magnitude may only RAISE the term (inv. 6).
    assert witnessed["reach_magnitude_witnessed_pct"] >= unwitnessed["reach_magnitude_witnessed_pct"]

    # The finding SURVIVES its missing magnitude, at the unpriced band's floor:
    # the reach is proven and only its SIZE is not, which inv. 7's floor rule
    # governs. It is the dollar figure that is not_determined, never the row.
    assert unwitnessed_doc.findings[0]["reach_entities"] == [KEY_C]
    assert unwitnessed_doc.findings[0]["value_band"] == "not_determined"
    assert unwitnessed_doc.findings[0]["value_at_stake_usd"] is None
    assert unwitnessed_doc.findings[0]["raw_points"] > 0

    # And the exposure ratio is WITHHELD rather than published as 100. No
    # finding measured a numerator, so the ratio is a quantity nobody computed —
    # publishing "0% of tracked value is exposed" out of it would be the same
    # unproven-number move one axis over. λ is computed and carried in the
    # withheld block; grade, exposure and confidence stand or fall together
    # (ck_protocol_scores_grade_pairing), so the whole triple is not_determined.
    assert unwitnessed_doc.grade_state == GRADE_STATE_NOT_DETERMINED
    withheld = unwitnessed_doc.provenance["grade_withheld"]
    assert 0.0 < withheld["grade_lambda_computed"] < 100.0
    assert witnessed_doc.grade_state == GRADE_STATE_COMPUTED
    assert witnessed["pct"] > 0.0


def test_r11_every_proven_reach_capability_is_in_the_denominator(fold):
    """No capability buys its way out of "how much does this move?".

    A per-capability exclusion list reads as relief for a reach with no magnitude
    concept, but its only live effect is on an entity carrying BOTH an excluded
    and an admitted signal: dropping the excluded one RAISES the term by
    discarding a real unanswered question. Here one witnessed ``flow.out`` and one
    unwitnessed ``timelock.set_delay`` share an entity — the honest answer is 50%,
    and an exclusion list would publish 100%.
    """
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
    # 50, not 100: the unwitnessed half is not excused by its capability name.
    assert detail["reach_magnitude_witnessed_pct"] == 50.0
    assert detail["reach_magnitude_witnessed_of_reaching_pct"] == 50.0
    assert detail["reach_magnitude_vacuous_credit_pct"] == 0.0


def _perimeter_signal():
    return sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(1_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )


def test_r12_consuming_a_relation_may_not_raise_confidence(fold):
    """Monotonicity: declining to walk a relation CHARGES confidence, never frees it.

    The perimeter was seeded from the relations the scorer consumed, so entities
    a declined relation proved are principals of gated functions never entered
    the denominator — and the published figure was HIGHER for walking less.
    """
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
    # The entity the declined relation names is in the denominator EITHER WAY.
    assert KEY_OUTSIDER not in declined["signal_entities_outside_perimeter"]
    assert declined["perimeter_entities"] == consumed["perimeter_entities"]
    assert declined["perimeter_value_weighted_denominator"] == consumed["perimeter_value_weighted_denominator"]
    assert consumed["pct"] <= declined["pct"]
    assert declined["discovery_relation_entities_admitted"]["capability_principal"] == 1


def test_r12_a_declined_relations_entities_lower_confidence(fold):
    """The charge is real: the same analysis over a wider proven graph scores lower."""
    shared = dict(
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    )
    blind = fold([_perimeter_signal()], **shared).model_parameters["confidence_detail"]
    seeing = fold(
        [_perimeter_signal()],
        discovery={"capability_principal": {KEY_OUTSIDER}},
        **shared,
    ).model_parameters["confidence_detail"]
    assert seeing["perimeter_entities"] == blind["perimeter_entities"] + 1
    assert seeing["reachability_answered_pct"] < blind["reachability_answered_pct"]


def test_r17_contradictory_owner_sets_are_disclosed_not_silently_arbitrated(fold):
    """Two ``exact`` owner witnesses for one Safe: the disagreement is published."""
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


def test_r9_a_capped_magnitude_does_not_move_per_member_reach(fold):
    """W2b's per-call cap scales what a member is charged, never what it reaches.

    ``_member_weakness`` re-folds each member's own instances to ask which
    entities that member is proven to reach. That re-fold runs through the same
    ``_row_value`` the cap lives in, so a cap that removed an entity from a
    member's reach would silently drop the member from that entity's rung and
    fall back to the unit-level weakness. Reach is read off witnessed membership
    for exactly this reason, and the invariant is pinned here.
    """
    signals = [
        sig(
            function_name="upgradeA",
            deployment_address=C,
            contract_id=1,
            selector="0x00000001",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE_MINORITY),),
            gates=bounded_by_sheet(1_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        ),
        sig(
            function_name="upgradeB",
            deployment_address=VAULT,
            contract_id=2,
            selector="0x00000002",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", SAFE_MAJORITY),),
            # One call, two keys, and a witness that bounds the CALL: the cap
            # fires and trims the published dollars.
            gates={"reach_magnitude_usd": Tri.proven("proven_exact", 5_000_000.0).to_json()},
            **proven(1.0),
            **reaches(KEY_V, KEY_PROXY),
        ),
    ]
    finding = fold(
        signals,
        principals=_merged_unit_principals(),
        value=value_plane(
            {
                KEY_C: {"usdc": 1_000_000.0},
                KEY_V: {"usdc": 5_000_000.0},
                KEY_PROXY: {"usdc": 3_000_000.0},
            }
        ),
    ).findings[0]

    # The cap really fired: the uncapped sum exceeded the one witnessed number.
    caps = finding["witnessed_magnitude_caps"]
    assert caps and caps[0]["uncapped_sum_usd"] > caps[0]["witnessed_usd"]
    # Membership is untouched by it — every reached entity survives the cap.
    assert set(finding["reach_entities"]) == {KEY_C, KEY_V, KEY_PROXY}
    # And the per-member attribution still resolves: the 4/8 member is found as
    # the holder of both of its capped entities, so the safe-fail never fires and
    # they are priced at ITS rung, not at the unit's weakest member's.
    assert finding["weakness_by_entity"] == {
        KEY_C: WEAKNESS_SAFE_MINORITY,
        KEY_PROXY: WEAKNESS_SAFE_MAJORITY,
        KEY_V: WEAKNESS_SAFE_MAJORITY,
    }
    assert finding["weakness"] == WEAKNESS_SAFE_MAJORITY


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
    ],
)
def test_w3_a_repoint_is_admitted_only_on_a_validated_value_witness(named, tier, why):
    """R2 — a repoint adds a foreign entity to a reach set, and must earn it.

    It did the same job as the backlink licence with none of that function's
    checks: no protocol, no chain, no existence, and no check that the witness
    naming the entity proved anything about value. The burn-sentinel arm in
    particular has never fired on any corpus, which is why it is pinned rather
    than observed.
    """
    keys, bases, refused = D._repointed_entities({"tier": tier, "witness": {"callee": named}}, _repoint_facts())
    assert (keys, bases) == ([], [])
    assert [row["why"] for row in refused] == [why]
    assert refused[0]["basis"] == "witness.callee"

    # The positive control: a value witness naming an entity of this protocol on
    # this chain is admitted, so the refusals above are decisions and not a
    # recogniser that never says yes.
    admitted = D._repointed_entities({"tier": "behavioral_observed", "witness": {"callee": VAULT}}, _repoint_facts())
    assert admitted == ([KEY_V], ["witness.callee"], [])


def test_w3_a_repoint_never_upgrades_an_unscored_capability():
    """The second half of R2: naming a callee is not proving a capability.

    Six ``flow.in`` rows were promoted from ``capability_not_scored`` to
    ``proven_reach`` purely because a witness named an address — an upgrade of
    the reach STATE out of a fact about call structure.
    """
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


# --------------------------------------------------------------------------
# W3: the gate/code split, condition-bounded reach, and the magnitude rule

# --------------------------------------------------------------------------


SOLVER = "0x" + "4" * 40

KEY_SOLVER = entity_key("ethereum", SOLVER)

INITIATOR_GUARD = "initiator != address(this)"


def _queue_signal(claim: str, **over: Any) -> FunctionSignal:
    """One principal over the queue: the shape of the AtomicQueue finding."""
    return sig(
        claim_id=claim,
        function_name="setAuthority",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.75),
        **reaches(KEY_C),
        **over,
    )


def test_w3_gate_control_will_not_walk_an_edge_whose_scope_names_nothing(fold):
    """The scope bound, and the class split that makes it apply to one side only.

    Holding a gate over A gives its holder A's existing functions; whether one of
    them exercises A's authority over B is a question an edge label that names no
    role and no state variable cannot answer. Controlling A's CODE does not ask
    it — the code exercises whatever the code is authorized to exercise.
    """
    unlabelled = P.ControlClosure(
        edges=(
            P.ControlEdge(
                principal=KEY_C,
                anchor=KEY_V,
                relation="role_principal",
                scope=P.parse_edge_scope("role principal", "role_principal"),
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
            ),
        )
    )
    assert not unlabelled.edges[0].scope.is_determined
    conditions = condition_plane()

    gate, gate_hops = FOLD._closure({KEY_C}, unlabelled, conditions, code_control=False)
    code, code_hops = FOLD._closure({KEY_C}, unlabelled, conditions, code_control=True)
    assert gate == {KEY_C} and code == {KEY_C, KEY_V}
    assert gate_hops[0]["reason"] == FOLD.HOP_REFUSED_SCOPE
    assert code_hops == []
    # A determined scope is walked by both at this stage: narrowing it to the
    # selectors a role actually confers is a later refinement, and it may only
    # shrink this set.
    labelled = P.ControlClosure(
        edges=(
            P.ControlEdge(
                principal=KEY_C,
                anchor=KEY_V,
                relation="role_principal",
                scope=P.parse_edge_scope("roles 77", "role_principal"),
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
            ),
        )
    )
    assert FOLD._closure({KEY_C}, labelled, conditions, code_control=False)[0] == {KEY_C, KEY_V}


def test_w3_case3_a_freeze_charges_no_sheet_and_keeps_its_finding(fold):
    """Regression case 3 — pause.set leaves the grade.

    ``pause_effective`` proves the latch takes effect. It proves no FRACTION: how
    much of a sheet a freeze immobilises is a quantity nothing in this pipeline
    measures. Charging the whole sheet for it put three quarters of a billion
    dollars of unwitnessed magnitude into the grade.
    """
    freeze = pause_sig(
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"pause_effective": Tri.proven("proven", True).to_json()},
        **proven(0.05),
        **reaches(KEY_C),
    )
    priced = _perimeter_signal()
    document = fold(
        [freeze, priced],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 745_000_000.0}}),
    )
    rows = [f for f in document.findings] + list(document.provenance["subsumed_rows"])
    frozen = next(r for r in rows if r["capability"] == "pause.set")
    assert frozen["value_at_stake_usd"] is None
    assert frozen["value_band"] == "not_determined"
    assert frozen.get("exposure_usd") is None
    # The finding survives: a freeze capability is still a finding.
    assert frozen["raw_points"] > 0
    assert frozen["reach_entities"] == [KEY_C]
    # And the unknown has a home: the reach-magnitude term counts it unanswered.
    detail = document.model_parameters["confidence_detail"]
    census = detail["reach_magnitude_signals"]["by_capability"]
    assert census["pause.set"] == [0, 1]


def test_w3_case4_a_corrected_backlink_licence_carries_no_magnitude(fold):
    """Regression case 4 — the R3 trap.

    Correcting the backlink join makes a licence that had never once fired admit
    a foreign entity into a row's reach. Landing that correction WITHOUT the
    magnitude bound converts a cite/gate object into a dollar figure — the
    measured shape was one row going from $0.00 to $1,411,758.83 off the
    destination's whole sheet. The licence proves REACHABILITY; it proves no
    magnitude, so it supplies none.
    """
    licensed = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        reach_gate_state="licensed",
        **proven(0.75),
        **reaches(KEY_C, KEY_V),
    )
    document = fold(
        [licensed],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000.0}, KEY_V: {"usdc": 1_411_758.83}}),
    )
    finding = document.findings[0]
    # The licence is REACH: the entity is admitted and published.
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])
    # And it is not a magnitude: the destination's sheet is charged nowhere.
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    assert {row["entity"] for row in finding["undetermined_instances"]} == {KEY_C, KEY_V}


def test_w3_a_reach_key_naming_the_burn_sentinel_is_counted_where_it_is_refused(fold):
    """The fold's own count and gap for a reach key that is the burn sentinel.

    Both are unexercised on every corpus measured, which is exactly why they are
    pinned: a rule nobody has seen fire is one nobody has seen report either.
    """
    signal = sig(
        claim_id="roles.grant",
        function_name="grantRole",
        contract_id=2,
        selector="0x22222222",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.55),
        **reaches(KEY_ZERO),
    )
    priced = _perimeter_signal()
    document = fold(
        [signal, priced],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_ZERO: {"usdc": 4_000_000_000.0}}),
    )
    rows = list(document.findings) + list(document.provenance["subsumed_rows"])
    refused = next(r for r in rows if r["zero_address_reach_keys_refused"])
    assert refused["zero_address_reach_keys_refused"] == 1
    assert any(
        row["why"].startswith("every_reach_key_was_the_zero_address") for row in refused["undetermined_instances"]
    )
    assert "zero_address_reach_key_refused" in refused["witness_notes"]
    assert refused["value_at_stake_usd"] is None


def _witnessed_elsewhere(principal_id: int = 2) -> FunctionSignal:
    """One magnitude-witnessed row, so the document has an exposure to publish.

    grade, exposure and confidence are determined together, so a population in
    which NOTHING carries a magnitude witness withholds all three — correctly,
    since the exposure ratio would have no numerator anyone measured. A test
    asserting on a per-finding exposure needs the document to be scored at all.
    """
    return sig(
        claim_id="upgrade.implementation",
        function_name="upgradeTo",
        deployment_address=PROXY,
        contract_id=9,
        selector="0x11111111",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(principal_id, "ethereum", SAFE),),
        gates=bounded_by_sheet(500.0),
        **proven(1.0),
        **reaches(KEY_PROXY),
    )


def test_w3_case1_a_destination_guard_disproves_the_hop_that_carried_the_money(fold):
    """Regression case 1 — AtomicQueue's blocked principal.

    The EOA owns AtomicQueue, AtomicQueue holds a role on AtomicSolverV3, and the
    solver's ``finishSolve`` — the only function the role licenses it — reverts
    unless the initiator is the solver itself. No authority relation makes the
    queue the solver, so the hop is not something this walk can establish, and
    the solver's balance sheet was never the queue owner's to be charged.

    The finding stays ALIVE at the floor: the capability over the queue is
    proven, and it is the SIZE of what it reaches that is not.
    """
    conditions = condition_plane(
        licensed={(KEY_SOLVER, KEY_C): (("finishSolve", 570, (INITIATOR_GUARD,)),)},
        by_entity={
            KEY_SOLVER: (
                ("finishSolve", 570, (INITIATOR_GUARD,)),
                ("p2pSolve", 571, ()),
            )
        },
    )
    plane = value_plane({KEY_C: {"usdc": 1_000.0}, KEY_SOLVER: {"usdc": 1_505_140.39}, KEY_PROXY: {"usdc": 500.0}})
    shared = dict(
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "eoa")},
        closure={KEY_C: {KEY_SOLVER}},
        value=plane,
    )
    population = [_queue_signal("authority.replace"), _witnessed_elsewhere()]

    def queue_row(document):
        return next(f for f in document.findings if f["principal_unit"] == entity_key("ethereum", EOA))

    blocked = queue_row(fold(population, conditions=conditions, **shared))
    unguarded = queue_row(fold(population, **shared))

    # The control graph is identical; only the destination's own conditions differ.
    assert KEY_SOLVER in unguarded["reach_entities"]
    assert blocked["reach_entities"] == [KEY_C]
    hop = blocked["reach_hops_not_determined"][0]
    assert (hop["caller"], hop["destination"]) == (KEY_C, KEY_SOLVER)
    assert hop["reason"] == FOLD.HOP_REFUSED_CONDITION
    assert hop["disproving_conditions"][0]["conditions"] == [INITIATOR_GUARD]
    # Never a proven negative: the principal enumeration behind the licensed
    # surface is a lower bound, so this is not_determined and says so.
    assert "not_determined" in hop["reason"] or hop["reason"] == FOLD.HOP_REFUSED_CONDITION

    # Not charged the solver's sheet — and not charged the queue's either,
    # because no witness proved how much the capability moves.
    assert blocked["value_at_stake_usd"] is None
    assert blocked["value_by_entity"] == {}
    assert blocked["exposure_usd"] is None
    # Alive at the floor: the row still scores.
    assert blocked["value_band"] == "not_determined"
    assert blocked["raw_points"] > 0


def test_w3_case2_both_sides_of_the_inversion_fall_to_not_determined(fold):
    """Regression case 2 — the inversion, at this stage.

    The principal that provably CAN reach the money was published at $0.00 while
    two that provably cannot were charged $1.5M and $0.7M. Composing a witnessed
    magnitude for the reachable one is a later change; what this stage must
    deliver is that the FAKE attribution is gone — neither side carries a dollar
    figure nobody witnessed, so the document no longer asserts the inversion.
    """
    conditions = condition_plane(
        licensed={(KEY_SOLVER, KEY_C): (("finishSolve", 570, (INITIATOR_GUARD,)),)},
    )
    plane = value_plane({KEY_C: {"usdc": 1_000.0}, KEY_SOLVER: {"usdc": 2_229_837.61}, KEY_PROXY: {"usdc": 500.0}})
    blocked = _queue_signal("authority.replace")
    reaching = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        deployment_address=SOLVER,
        contract_id=2,
        selector="0x7a9e5e4b",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", TIMELOCK),),
        **proven(0.75),
        **reaches(KEY_SOLVER),
    )
    document = fold(
        [blocked, reaching, _witnessed_elsewhere(principal_id=3)],
        principals={
            1: facts(1, EOA, "eoa"),
            2: facts(2, TIMELOCK, "timelock", delay=172800.0),
            3: facts(3, SAFE, "eoa"),
        },
        closure={KEY_C: {KEY_SOLVER}},
        value=plane,
        conditions=conditions,
    )
    by_unit = {f["principal_unit"]: f for f in document.findings}
    unreachable = by_unit[entity_key("ethereum", EOA)]
    reachable = by_unit[entity_key("ethereum", TIMELOCK)]

    # The fake attribution: gone. Neither side publishes an unwitnessed dollar.
    assert unreachable["value_at_stake_usd"] is None
    assert reachable["value_at_stake_usd"] is None
    assert unreachable["exposure_usd"] is None
    assert reachable["exposure_usd"] is None
    # And the membership still tells the honest story: only the timelock's row
    # reaches the entity that holds the money.
    assert KEY_SOLVER not in unreachable["reach_entities"]
    assert KEY_SOLVER in reachable["reach_entities"]
