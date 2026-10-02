"""W2: 2-hop composition. ``bulkDeposit`` stands in for every hop the principal cannot drive."""

from __future__ import annotations

from services.scoring import fold as FOLD
from services.scoring import planes as P
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
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
)

REFUND_SELECTOR = "0x9d574420"


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
