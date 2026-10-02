from __future__ import annotations

import pytest

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef, entity_key
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_IMPL,
    KEY_PROXY,
    KEY_V,
    KEY_ZERO,
    PROXY,
    TIMELOCK,
    _perimeter_signal,
    _role_edge,
    _var_edge,
    bounded_by_sheet,
    condition_plane,
    conferral_plane,
    facts,
    fold,  # noqa: F401  (fold fixture, registered by import)
    proven,
    reaches,
    sig,
    value_plane,
)


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
