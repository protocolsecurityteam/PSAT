
from __future__ import annotations

import pytest

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import FunctionSignal, PrincipalRef, Tri, entity_key
from tests.support.scoring_builders import (
    EOA,
    INITIATOR_GUARD,
    KEY_C,
    KEY_IMPL,
    KEY_PROXY,
    KEY_V,
    KEY_ZERO,
    PROXY,
    SAFE,
    TIMELOCK,
    C,
    _perimeter_signal,
    _queue_signal,
    _role_edge,
    _var_edge,
    bounded_by_sheet,
    condition_plane,
    conferral_plane,
    facts,
    fold,  # noqa: F401  (fold fixture, registered by import)
    pause_sig,
    proven,
    reaches,
    sig,
    value_plane,
)

SOLVER = "0x" + "4" * 40

KEY_SOLVER = entity_key("ethereum", SOLVER)


def test_w4a_gate_control_will_not_walk_an_edge_whose_scope_names_nothing(fold):
    """An edge label naming no role or variable can't say whether a gate over A exercises A's authority over B; code
    control doesn't ask.
    """
    unlabelled = P.ControlClosure(edges=(_role_edge("role principal"),))
    assert not unlabelled.edges[0].scope.is_determined
    conditions = condition_plane()
    grant = conferral_plane().grant_for("ownership.transfer", None)

    gate, gate_hops, licensed, _ = FOLD._closure({KEY_C}, unlabelled, conditions, grant=grant)
    code, code_hops, _, _ = FOLD._closure({KEY_C}, unlabelled, conditions, grant=None)
    assert gate == {KEY_C} and code == {KEY_C, KEY_V}
    assert gate_hops[0]["reason"] == FOLD.HOP_REFUSED_SCOPE
    assert gate_hops[0]["conferral"] == P.CONFERRAL_SCOPE_NOT_DETERMINED
    assert gate_hops[0]["edge_label"] == "role principal"
    assert licensed == {} and code_hops == []


def test_w4a_a_role_confers_only_where_the_join_names_a_function_there(fold):
    """Licensed function names travel with the reach, where compositional magnitude is later attributed."""
    closure = P.ControlClosure(edges=(_role_edge("roles 77"),))
    conditions = condition_plane()

    licensing = conferral_plane(role_functions={(KEY_V, 77): (P.LicensedFunction("0xdeadbeef", "exit"),)})
    seen, hops, licensed, _ = FOLD._closure(
        {KEY_C}, closure, conditions, grant=licensing.grant_for("roles.grant", None)
    )
    assert seen == {KEY_C, KEY_V}
    assert hops == []
    assert licensed == {KEY_V: {P.LicensedFunction("0xdeadbeef", "exit")}}

    silent = conferral_plane(role_functions={(KEY_V, 78): (P.LicensedFunction("0xdeadbeef", "exit"),)})
    seen, hops, licensed, _ = FOLD._closure({KEY_C}, closure, conditions, grant=silent.grant_for("roles.grant", None))
    assert seen == {KEY_C}
    assert licensed == {}
    assert hops[0]["reason"] == FOLD.HOP_REFUSED_CONFERRAL
    assert hops[0]["conferral"] == P.CONFERRAL_ROLE_NOT_LICENSED
    assert FOLD._closure({KEY_C}, closure, conditions, grant=None)[0] == {KEY_C, KEY_V}


def test_w4a_a_gate_does_not_confer_a_variable_it_is_not_witnessed_to_rewrite(fold):
    """From the capability's own ``state_writes``; a different kind of authority makes the hop not_determined, not
    disproved.
    """
    conditions = condition_plane()
    owns = conferral_plane(rewrites=("owner", "_owner")).grant_for("ownership.transfer", None)

    owner_hop = P.ControlClosure(edges=(_var_edge("owner"),))
    assert FOLD._closure({KEY_C}, owner_hop, conditions, grant=owns)[0] == {KEY_C, KEY_V}

    hook_hop = P.ControlClosure(edges=(_var_edge("hook"),))
    seen, hops, _, _ = FOLD._closure({KEY_C}, hook_hop, conditions, grant=owns)
    assert seen == {KEY_C}
    assert hops[0]["reason"] == FOLD.HOP_REFUSED_CONFERRAL
    assert hops[0]["conferral"] == P.CONFERRAL_VARIABLE_NOT_REWRITTEN
    assert hops[0]["capability"] == "ownership.transfer"
    assert FOLD._closure({KEY_C}, hook_hop, conditions, grant=None)[0] == {KEY_C, KEY_V}


def test_w4a_a_gate_whose_writes_were_never_extracted_confers_nothing():
    """Never-extracted differs from proven-to-write-nothing; both withhold, and the hop says which."""
    conditions = condition_plane()
    plane = P.ConferralPlane()
    grant = plane.grant_for("ownership.transfer", None)
    assert not grant.writes_extracted

    closure = P.ControlClosure(edges=(_var_edge("owner"),))
    seen, hops, _, _ = FOLD._closure({KEY_C}, closure, conditions, grant=grant)
    assert seen == {KEY_C}
    assert hops[0]["conferral"] == P.CONFERRAL_WRITES_NOT_EXTRACTED
    roles = P.ControlClosure(edges=(_role_edge("roles 4"),))
    licensing = P.ConferralPlane(role_functions={(KEY_V, 4): (P.LicensedFunction("0xaaaaaaaa", "pull"),)})
    assert FOLD._closure({KEY_C}, roles, conditions, grant=licensing.grant_for("roles.grant", None))[0] == {
        KEY_C,
        KEY_V,
    }


def test_w4a_conferral_may_only_shrink_a_walk_never_grow_it():
    """Conferral is a bound, so its walk is a subset of the label-presence walk."""
    conditions = condition_plane()
    closure = P.ControlClosure(
        edges=(
            _var_edge("owner", anchor=KEY_V),
            _var_edge("hook", anchor=KEY_PROXY),
            _role_edge("roles 3", anchor=KEY_IMPL),
            _role_edge("role principal", anchor=entity_key("ethereum", TIMELOCK)),
        )
    )
    unbounded = FOLD._closure({KEY_C}, closure, conditions, grant=None)[0]
    for rewrites in ((), ("owner",), ("hook",), ("owner", "hook"), ("authority",)):
        for roles in (
            {},
            {(KEY_IMPL, 3): (P.LicensedFunction("0xaaaaaaaa", "pull"),)},
            {(KEY_IMPL, 9): (P.LicensedFunction("0xbbbbbbbb", "push"),)},
        ):
            plane = conferral_plane(rewrites=rewrites, role_functions=roles)
            walked = FOLD._closure({KEY_C}, closure, conditions, grant=plane.grant_for("ownership.transfer", None))[0]
            assert walked <= unbounded, (rewrites, roles)


def test_w3_case3_a_freeze_charges_no_sheet_and_keeps_its_finding(fold):
    """``pause_effective`` proves the latch, not a fraction; charging the whole sheet put ~$750M of unwitnessed
    magnitude into the grade.
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
    assert frozen["raw_points"] > 0
    assert frozen["reach_entities"] == [KEY_C]
    detail = document.model_parameters["confidence_detail"]
    census = detail["reach_magnitude_signals"]["by_capability"]
    assert census["pause.set"] == [0, 1]


def test_w3_case4_a_corrected_backlink_licence_carries_no_magnitude(fold):
    """R3: the fixed backlink licence proves reachability only; without the bound one row jumped from $0.00 to
    $1,411,758.83.
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
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    assert {row["entity"] for row in finding["undetermined_instances"]} == {KEY_C, KEY_V}


def test_w3_a_reach_key_naming_the_burn_sentinel_is_counted_where_it_is_refused(fold):
    """Unexercised on every corpus measured."""
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
    """Grade, exposure and confidence are determined together, so something must carry a magnitude witness."""
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
    """The EOA owns AtomicQueue, which holds a role on AtomicSolverV3, but ``finishSolve`` reverts unless the solver
    initiates. The finding stays alive at the floor.
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

    assert KEY_SOLVER in unguarded["reach_entities"]
    assert blocked["reach_entities"] == [KEY_C]
    hop = blocked["reach_hops_not_determined"][0]
    assert (hop["caller"], hop["destination"]) == (KEY_C, KEY_SOLVER)
    assert hop["reason"] == FOLD.HOP_REFUSED_CONDITION
    assert hop["disproving_conditions"][0]["conditions"] == [INITIATOR_GUARD]
    # The licensed-surface enumeration is a lower bound.
    assert "not_determined" in hop["reason"] or hop["reason"] == FOLD.HOP_REFUSED_CONDITION

    assert blocked["value_at_stake_usd"] is None
    assert blocked["value_by_entity"] == {}
    assert blocked["exposure_usd"] is None
    assert blocked["value_band"] == "not_determined"
    assert blocked["raw_points"] > 0


def test_w3_case2_both_sides_of_the_inversion_fall_to_not_determined(fold):
    """The principal that could reach the money published $0.00 while two that couldn't were charged $1.5M and $0.7M."""
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

    assert unreachable["value_at_stake_usd"] is None
    assert reachable["value_at_stake_usd"] is None
    assert unreachable["exposure_usd"] is None
    assert reachable["exposure_usd"] is None
    assert KEY_SOLVER not in unreachable["reach_entities"]
    assert KEY_SOLVER in reachable["reach_entities"]


def test_w3_a_shared_implementation_folds_onto_no_proxy(fold):
    """R14: pinning either proxy would charge one's whole sheet to a row that reached the other.

    No measured corpus has this.
    """
    plane = value_plane({KEY_PROXY: {"usdc": 100_000_000.0}})
    plane.alias_ambiguous = {KEY_IMPL}
    signal = sig(
        deployment_address=PROXY,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(100_000_000.0),
        **proven(1.0),
        **reaches(KEY_IMPL),
    )
    finding = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert finding["value_by_entity"] == {}
    assert finding["value_at_stake_usd"] is None
    gap = finding["undetermined_instances"][0]
    assert gap["entity"] == KEY_IMPL
    assert gap["why"] == "shared_implementation_folds_onto_no_proxy(not_determined)"


def test_w3_an_alias_cycle_fails_loud(fold):
    """R15: picking a member would choose by iteration order and orphan the other's balances."""
    with pytest.raises(P.AliasCycleError):
        P._alias_fixed_point({KEY_PROXY: KEY_IMPL, KEY_IMPL: KEY_PROXY})
    third = entity_key("ethereum", "0x" + "d" * 40)
    assert P._alias_fixed_point({third: KEY_IMPL, KEY_IMPL: KEY_PROXY}) == {
        third: KEY_PROXY,
        KEY_IMPL: KEY_PROXY,
    }


def test_w3_a_beacon_is_a_code_control_edge_with_its_own_witness():
    """R16: consumers branch on the witness string, so the beacon gets its own column."""
    assert P.EDGE_WITNESS_BEACON_COLUMN != P.EDGE_WITNESS_ADMIN_COLUMN
    edge = P.ControlEdge(
        principal=KEY_C,
        anchor=KEY_PROXY,
        relation=None,
        scope=P.EdgeScope(P.SCOPE_NOT_DETERMINED),
        witness=P.EDGE_WITNESS_BEACON_COLUMN,
    )
    closure = P.ControlClosure(edges=(edge,))
    conditions = condition_plane()
    assert FOLD._closure({KEY_C}, closure, conditions, grant=None)[0] == {KEY_C, KEY_PROXY}
