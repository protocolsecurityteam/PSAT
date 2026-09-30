"""W2: 2-hop composition. ``bulkDeposit`` stands in for every hop the principal cannot drive."""

from __future__ import annotations

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    EOA,
    HOP1_ACCEPTED,
    HOP1_SELECTOR,
    INITIATOR_GUARD,
    KEY_C,
    KEY_PROXY,
    KEY_T,
    KEY_V,
    _composing_principals,
    _composing_signals,
    _gate_row,
    _role_edge,
    _two_hop_case,
    act_as_plane,
    condition_plane,
    conferral_plane,
    fold,  # noqa: F401  (fold fixture, registered by import)
    proven,
    reaches,
    sig,
    value_plane,
)
from utils.scoring_status import VALUE_STATE_PROVEN_REACH

REFUND_SELECTOR = "0x9d574420"


def test_w2_case1_the_two_hop_chain_composes_through_both_links(fold):
    """Remove any published link and the figure is not_determined."""
    document = fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert row["value_state"] == VALUE_STATE_PROVEN_REACH
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert entry["act_as_chain_length"] == 2
    first, second = entry["act_as_chain"]

    assert (first["caller"], first["destination"]) == (KEY_C, KEY_T)
    assert first["witness_kind"] == P.ACT_AS_WITNESS_DESTINATION_ACL
    assert first["calling_function"] == "finishSolve"
    assert first["destination_acceptance"] == {
        "source": "function_principals",
        "function_principal_id": 14279,
        "destination_function": "bulkWithdraw",
        "accepting_roles": [12],
        "membership_quality": "exact",
    }
    assert (second["caller"], second["destination"]) == (KEY_T, KEY_V)
    assert second["witness_kind"] == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert (second["calling_function"], second["receiver_variable"]) == ("bulkWithdraw", "vault")
    assert (second["receiver_observed_via"], second["receiver_block"]) == ("eth_call", 25_657_731)

    assert entry["flow_out_witness"] == {
        "state": "proven_exact",
        "usd": 1_000_000.0,
        "function": "exit",
        "entity": KEY_V,
    }
    assert entry["selector"] == COMPOSED_SELECTOR
    assert row["reach_composition_census"]["longest_composed_chain"] == 2
    # A chain that died at the router would recover nothing.
    assert KEY_T not in {e["entity"] for e in row["reach_composed_magnitudes"]}


def test_w2_case2_the_condition_disproved_hop_is_not_resurrected_by_composition(fold):
    """The condition plane's disproof is upstream of composition, and an ACL admission must not reach around it."""
    blocked = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            conditions=condition_plane(by_entity={KEY_T: (("finishSolve", 570, (INITIATOR_GUARD,)),)}),
        ),
    )
    row = _gate_row(blocked)
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    assert row["value_state"] == "not_determined"
    assert KEY_T not in row["reach_entities"]
    hop = next(h for h in row["reach_hops_not_determined"] if h["destination"] == KEY_T)
    assert hop["reason"] == FOLD.HOP_REFUSED_CONDITION
    assert hop["disproving_conditions"][0]["conditions"] == [INITIATOR_GUARD]


def test_w2_case3_composition_admits_a_magnitude_and_never_an_entity(fold):
    """Strip every act-as witness and the same entities are reached; only the dollars change."""
    with_witness = _gate_row(fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case()))
    without = _gate_row(
        fold(
            _composing_signals(),
            principals=_composing_principals(),
            **_two_hop_case(act_as=act_as_plane()),
        )
    )
    assert with_witness["reach_entities"] == without["reach_entities"]
    assert set(with_witness["reach_entities"]) >= {KEY_C, KEY_T, KEY_V}
    assert without["reach_composed_magnitudes"] == []
    assert without["value_at_stake_usd"] is None
    assert with_witness["value_at_stake_usd"] == 1_000_000.0


def test_w2_case4_a_parameter_bound_link_with_no_acl_row_stays_refused(fold):
    """The chain stops at hop 1 under its own typed reason."""
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
            )
        ),
    )
    row = _gate_row(document)
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    refused = row["reach_composition_census"]["act_as_refused"]
    assert refused[P.ACT_AS_NO_DESTINATION_ACL] == 1
    # Unreached is a different fact from a refusal at that hop.
    assert refused[FOLD.ACT_AS_CALLER_UNREACHED] == 1
    assert row["reach_composition_census"]["longest_composed_chain"] == 0


def test_w2_case5_no_composed_magnitude_exceeds_the_bound_over_two_hops(fold):
    """A longer chain makes the path harder to witness, never the number larger."""
    for sheet, expected in ((5_000_000.0, 1_000_000.0), (250_000.0, 250_000.0)):
        document = fold(
            _composing_signals(),
            principals=_composing_principals(),
            **_two_hop_case(value=value_plane({KEY_V: {"usdc": sheet}}, contracts=(KEY_C, KEY_T))),
        )
        entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
        assert entry["act_as_chain_length"] == 2
        assert entry["published_usd"] == expected
        assert entry["published_usd"] <= entry["flow_out_witness"]["usd"]
        assert entry["published_usd"] <= sheet
        assert _gate_row(document)["value_at_stake_usd"] == expected


def test_w2_case6_a_hop_from_a_function_the_previous_hop_did_not_admit_composes_nothing(fold):
    """The principal can only run the function the teller's list admitted; otherwise the chain would stand on sort
    order.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    (KEY_T, COMPOSED_SELECTOR): (("refundDeposit", "restricted", "vault", True, REFUND_SELECTOR),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
            )
        ),
    )
    row = _gate_row(document)
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    census = row["reach_composition_census"]
    assert census["act_as_refused"][P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION] == 1
    assert census["act_as_witnessed"] == 1
    assert KEY_V in row["reach_entities"]


def test_w2_an_overloaded_intermediate_name_does_not_stand_in_for_the_admitted_function(fold):
    """Names don't identify functions: 32 (entity, name) pairs in the reference corpus carry more than one selector."""
    overloaded = "0x9d574421"
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, overloaded),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
            )
        ),
    )
    row = _gate_row(document)
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    assert row["reach_composition_census"]["act_as_refused"][P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION] == 1


def test_w2_the_admitted_call_site_is_selected_and_never_vetoed_by_a_sibling(fold):
    """Vetoing "the" step would refuse a chain whose admitted step exists."""
    sites = (
        ("adminRefund", "restricted", "vault", True, REFUND_SELECTOR),
        ("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),
    )
    for ordering in (sites, tuple(reversed(sites))):
        document = fold(
            _composing_signals(),
            principals=_composing_principals(),
            **_two_hop_case(
                act_as=act_as_plane(
                    call_sites={
                        (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                        (KEY_T, COMPOSED_SELECTOR): ordering,
                    },
                    reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                    destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
                )
            ),
        )
        row = _gate_row(document)
        assert row["value_at_stake_usd"] == 1_000_000.0
        entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
        second = entry["act_as_chain"][1]
        assert (second["calling_function"], second["calling_selector"]) == ("bulkWithdraw", HOP1_SELECTOR)
        assert (
            P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION not in row["reach_composition_census"]["act_as_refused"]
        )


def test_w2_the_protocol_rollup_maxes_the_chain_length_and_sums_the_counts(fold):
    """Summed, two 2-hop rows would publish a 4-hop chain."""
    rows = [
        {
            "reach_composition_census": {"longest_composed_chain": 2, "licensed_selectors": 3},
            "reach_composed_magnitudes": [{"entity": KEY_V, "published_usd": 10.0}],
        },
        {
            "reach_composition_census": {"longest_composed_chain": 2, "licensed_selectors": 4},
            "reach_composed_magnitudes": [{"entity": KEY_PROXY, "published_usd": 5.0}],
        },
    ]
    rolled = FOLD._composition_totals(rows, [])["findings"]
    assert rolled["longest_composed_chain"] == 2, "summed, this would read 4"
    assert rolled["licensed_selectors"] == 7, "a genuine count still sums"
    assert rolled["entities_composed"] == 2

    document = fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case())
    census = document.provenance["reach_bounds"]["act_as_composition"]["census"]["findings"]
    assert census["longest_composed_chain"] == 2
    assert _gate_row(document)["reach_composition_census"]["longest_composed_chain"] == 2


def test_w2_a_seed_is_never_constrained_by_a_hop_into_it(fold):
    """Ruling 4 rule 2: every seed is hop 1 and needs no admitting."""
    hub_entry = "0x3e64ce99"
    document = fold(
        [
            sig(
                claim_id="authority.replace",
                function_name="setAuthority",
                authority_openness="restricted",
                principal_state="enumerated",
                principal_refs=(PrincipalRef(1, "ethereum", EOA),),
                **proven(0.75),
                **reaches(KEY_T, KEY_C),
            ),
            _composing_signals()[1],
        ],
        principals=_composing_principals(),
        closure=P.ControlClosure(
            edges=(
                _role_edge("roles 12", principal=KEY_T, anchor=KEY_C),
                _role_edge("roles 12", principal=KEY_C, anchor=KEY_V),
            )
        ),
        conferral=conferral_plane(
            role_functions={
                (KEY_C, 12): (P.LicensedFunction(hub_entry, "route"),),
                (KEY_V, 12): (P.LicensedFunction(COMPOSED_SELECTOR, "exit"),),
            }
        ),
        act_as=act_as_plane(
            call_sites={
                (KEY_T, hub_entry): (("relay", "restricted", "hub", True, REFUND_SELECTOR),),
                (KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),),
            },
            reads={(KEY_T, "hub"): (KEY_C, "eth_call", 1), (KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
        ),
        value=value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C, KEY_T)),
    )
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert entry["act_as_chain_length"] == 1
    assert entry["act_as_chain"][0]["caller"] == KEY_C
    assert P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION not in row["reach_composition_census"]["act_as_refused"]


def test_w2_a_node_entered_twice_publishes_the_chain_the_hop_was_issued_from(fold):
    """Ruling 4 rule 4: the chain must be the path the hop was issued from."""
    first_entry, second_entry = "0x11111111", HOP1_SELECTOR
    accepted = P.DestinationAcceptance((12,), "exact", "deposit", 991)
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            closure=P.ControlClosure(
                edges=(
                    _role_edge("roles 12", anchor=KEY_T),
                    _role_edge("roles 12", principal=KEY_T, anchor=KEY_V),
                )
            ),
            conferral=conferral_plane(
                role_functions={
                    (KEY_T, 12): (
                        P.LicensedFunction(first_entry, "deposit"),
                        P.LicensedFunction(second_entry, "bulkWithdraw"),
                    ),
                    (KEY_V, 12): (P.LicensedFunction(COMPOSED_SELECTOR, "exit"),),
                }
            ),
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, first_entry): (("depositSolve", "restricted", "", True, "0xaaaa0001"),),
                    (KEY_C, second_entry): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, second_entry),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={
                    (KEY_T, first_entry): {KEY_C: accepted},
                    (KEY_T, second_entry): {KEY_C: HOP1_ACCEPTED},
                },
            ),
        ),
    )
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    first, second = entry["act_as_chain"]
    assert (first["calling_function"], first["selector"]) == ("finishSolve", second_entry)
    assert second["calling_selector"] == second_entry
    assert first["selector"] == second["calling_selector"]
