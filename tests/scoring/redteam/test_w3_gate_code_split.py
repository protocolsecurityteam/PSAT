"""W3: the gate/code split, condition-bounded reach, and the magnitude rule.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

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
    """The scope bound, and the class split that makes it apply to one side only.

    Holding a gate over A gives its holder A's existing functions; whether one of
    them exercises A's authority over B is a question an edge label that names no
    role and no state variable cannot answer. Controlling A's CODE does not ask
    it — the code exercises whatever the code is authorized to exercise.
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
    # Withheld, never dropped: the label is cited verbatim on the published gap.
    assert gate_hops[0]["edge_label"] == "role principal"
    assert licensed == {} and code_hops == []


def test_w4a_a_role_confers_only_where_the_join_names_a_function_there(fold):
    """The role -> selector join, positive and negative on the same edge.

    A ``roles N`` edge is walked where the join names functions role N licenses
    AT THAT DESTINATION, and those names travel with the reach — they are the
    answer to "reach to do what", and what a compositional magnitude is later
    attributed to. Where the join names nothing the hop is not_determined: the
    label said "role 77" and no witness says what role 77 may do there.
    """
    closure = P.ControlClosure(edges=(_role_edge("roles 77"),))
    conditions = condition_plane()

    licensing = conferral_plane(role_functions={(KEY_V, 77): (P.LicensedFunction("0xdeadbeef", "exit"),)})
    seen, hops, licensed, _ = FOLD._closure(
        {KEY_C}, closure, conditions, grant=licensing.grant_for("roles.grant", None)
    )
    assert seen == {KEY_C, KEY_V}
    assert hops == []
    assert licensed == {KEY_V: {P.LicensedFunction("0xdeadbeef", "exit")}}

    # Same edge, same label, no witness of what the role licenses there.
    silent = conferral_plane(role_functions={(KEY_V, 78): (P.LicensedFunction("0xdeadbeef", "exit"),)})
    seen, hops, licensed, _ = FOLD._closure({KEY_C}, closure, conditions, grant=silent.grant_for("roles.grant", None))
    assert seen == {KEY_C}
    assert licensed == {}
    assert hops[0]["reason"] == FOLD.HOP_REFUSED_CONFERRAL
    assert hops[0]["conferral"] == P.CONFERRAL_ROLE_NOT_LICENSED
    # Code control does not ask the question at all.
    assert FOLD._closure({KEY_C}, closure, conditions, grant=None)[0] == {KEY_C, KEY_V}


def test_w4a_a_gate_does_not_confer_a_variable_it_is_not_witnessed_to_rewrite(fold):
    """ownership.transfer confers an ``owner`` hop and not a ``hook`` one.

    The evidence is the capability's own ``state_writes``: the gate seizes an
    authority of some kind, the hop runs on an authority of some kind, and the
    seizure composes down the chain when they are the same kind. Where they
    differ the hop is NOT disproved — it is not_determined, because whether the
    seized gate reaches the other authority depends on a function surface
    nothing witnesses.
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
    # not_determined, never a proven negative: the hop is published, and code
    # control still walks the same edge.
    assert FOLD._closure({KEY_C}, hook_hop, conditions, grant=None)[0] == {KEY_C, KEY_V}


def test_w4a_a_gate_whose_writes_were_never_extracted_confers_nothing():
    """A coverage gap is not an empty answer and is not a licence.

    A function whose ``state_writes`` never ran rewrites nothing anyone read,
    which is a different fact from a function proven to rewrite nothing. Both
    withhold, and the withheld hop says which one it was.
    """
    conditions = condition_plane()
    plane = P.ConferralPlane()
    grant = plane.grant_for("ownership.transfer", None)
    assert not grant.writes_extracted

    closure = P.ControlClosure(edges=(_var_edge("owner"),))
    seen, hops, _, _ = FOLD._closure({KEY_C}, closure, conditions, grant=grant)
    assert seen == {KEY_C}
    assert hops[0]["conferral"] == P.CONFERRAL_WRITES_NOT_EXTRACTED
    # A role hop asks the join, not state_writes, so it is unaffected by the gap.
    roles = P.ControlClosure(edges=(_role_edge("roles 4"),))
    licensing = P.ConferralPlane(role_functions={(KEY_V, 4): (P.LicensedFunction("0xaaaaaaaa", "pull"),)})
    assert FOLD._closure({KEY_C}, roles, conditions, grant=licensing.grant_for("roles.grant", None))[0] == {
        KEY_C,
        KEY_V,
    }


def test_w4a_conferral_may_only_shrink_a_walk_never_grow_it():
    """The monotone property, over every scope shape in one closure.

    Conferral is a bound and bounds do not add reach. Whatever a gate confers,
    its walk is a subset of the label-presence walk it replaced — which is the
    walk code control still performs, since code control asks no scope question.
    """
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


def test_w3_a_shared_implementation_folds_onto_no_proxy(fold):
    """R14: two proxies, one implementation, and no coin toss between them.

    Pinning either proxy charges a row that reached only the OTHER proxy's
    implementation with this one's whole sheet, publishes it as an entity nothing
    reached, and spends its exposure budget. Zero shared implementations exist on
    any corpus measured, so the rule is pinned here rather than observed.
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
    """R15: ``A -> B`` beside ``B -> A`` is a contradiction, not a fold.

    Resolving it by picking a member would publish a canonical entity chosen by
    iteration order, and orphan the other one's balances behind it.
    """
    with pytest.raises(P.AliasCycleError):
        P._alias_fixed_point({KEY_PROXY: KEY_IMPL, KEY_IMPL: KEY_PROXY})
    # And a chain resolves rather than stopping one hop short.
    third = entity_key("ethereum", "0x" + "d" * 40)
    assert P._alias_fixed_point({third: KEY_IMPL, KEY_IMPL: KEY_PROXY}) == {
        third: KEY_PROXY,
        KEY_IMPL: KEY_PROXY,
    }


def test_w3_a_beacon_is_a_code_control_edge_with_its_own_witness():
    """R16: whoever controls the beacon sets the implementation of every proxy.

    The broadest code-control link there is, and the closure carried no
    representation of it at all. It is named by its own column rather than
    borrowing the admin witness — consumers branch on the witness string, and
    ``relation is None`` is a property both columns share.
    """
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
