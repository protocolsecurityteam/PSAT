"""W2 — composition over a 2-hop chain: the ceiling, its disclosure, and the.

rule that no hop inherits its predecessor's authority
bulkDeposit at the teller: a function of the teller nothing on this chain
admits, used to stand in for every hop the principal cannot drive.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

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
    """Regression case 1. Both links witnessed, each by the shape it earns.

    The whole decomposition is published on the entry: the seized gate's row, a
    restricted authority-gated calling function of the seized node, the
    destination's ACL row with the role and the selector it admits, the
    intermediate's resolved pointer, and the destination's own flow.out witness.
    Remove any one and the figure is not_determined.
    """
    document = fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert row["value_state"] == VALUE_STATE_PROVEN_REACH
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert entry["act_as_chain_length"] == 2
    first, second = entry["act_as_chain"]

    # link 1: the seized node's restricted, authority-gated function, admitted
    # at the teller by the teller's OWN list, by role, on an exact membership.
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
    # link 2: the intermediate's own pointer, read on-chain holding the vault —
    # and it is issued from the very function link 1 admitted.
    assert (second["caller"], second["destination"]) == (KEY_T, KEY_V)
    assert second["witness_kind"] == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert (second["calling_function"], second["receiver_variable"]) == ("bulkWithdraw", "vault")
    assert (second["receiver_observed_via"], second["receiver_block"]) == ("eth_call", 25_657_731)

    # ...and the dollars at the far end are the DESTINATION's own witness.
    assert entry["flow_out_witness"] == {
        "state": "proven_exact",
        "usd": 1_000_000.0,
        "function": "exit",
        "entity": KEY_V,
    }
    assert entry["selector"] == COMPOSED_SELECTOR
    assert row["reach_composition_census"]["longest_composed_chain"] == 2
    # The router is on the path and carries no figure of its own: a chain that
    # died at it would recover nothing, which is why link 1 costs the chain.
    assert KEY_T not in {e["entity"] for e in row["reach_composed_magnitudes"]}


def test_w2_the_composed_figure_carries_no_authored_precondition_block(fold):
    """F3, cut. The block that hedged the figure was one constant string.

    ``caller_holding_precondition`` was 1,222 characters, identical on all forty
    entries of the reference corpus, and its central clause — that the last
    admitted call spends a quantity the caller must hold — is FALSE on the
    twelve whose destination is ``manage``. It is deleted rather than reworded,
    and with it ``principal_extraction_bound``, which named a direction the
    entry derived from nothing. What survives is what the entry can account for:
    the figure, the sheet that bounded it, and the execution that proved it.
    """
    document = fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case())
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert "caller_holding_precondition" not in entry
    assert "principal_extraction_bound" not in entry
    assert not hasattr(FOLD, "_CallerHoldingPrecondition")
    assert not hasattr(FOLD, "COMPOSED_BOUND_CALLER_ARGUMENTS")
    # The witness was READ from one function's row and measures the entity.
    assert entry["witness_granularity"] == "entity"
    # ...and deleting the hedge did not delete the figure or its account.
    assert entry["published_usd"] == 1_000_000.0
    assert entry["proving_execution"]["state"] in ("recorded", "not_determined")


def test_w2_case2_the_condition_disproved_hop_is_not_resurrected_by_composition(fold):
    """Regression case 2. The blocked EOA stays blocked.

    The intermediate's every consulted function pins its caller to the
    destination itself, which the condition plane reads as a disproof INSIDE the
    closure walk — upstream of composition. An admission built on the
    destination's ACL must not reach around it: the walk never offers the hop,
    so nothing composes and the magnitude stays not_determined.
    """
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
    """Regression case 3. No row reaches an entity composition put there.

    Reach is decided by the closure walk, which never consults the act-as plane.
    Strip every act-as witness and the same entities are still reached — only
    the dollars go to not_determined.
    """
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
    """Regression case 4. The destination-side witness is required, not assumed.

    Hop 1's call site takes its callee as a parameter, so no storage of the
    seized node can name the teller. With the teller's own list silent, nothing
    at either end names the address, and the chain stops at hop 1 under its own
    typed reason — the second hop is never even offered.
    """
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
    # The second link was witnessed and is never reached: its caller is not
    # reachable from the seized node, which is a different fact from a refusal
    # at that hop and is counted as one.
    assert refused[FOLD.ACT_AS_CALLER_UNREACHED] == 1
    assert row["reach_composition_census"]["longest_composed_chain"] == 0


def test_w2_case5_no_composed_magnitude_exceeds_the_bound_over_two_hops(fold):
    """Regression case 5. The anti-composition property, re-asserted at length 2.

    Two ceilings and the published figure clears neither: the destination's own
    witness, and the destination's determined sheet. A longer chain can only
    ever make the path harder to witness, never the number larger.
    """
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
    """Regression case 6. No hop inherits its predecessor's authority.

    The principal seized nothing on the teller. It arrives there as the caller
    the teller's list admitted, able to run exactly the function that list
    admitted — so a second hop issued from some OTHER function of the teller is
    a call nothing witnesses the principal can cause, however well-witnessed the
    teller's pointer to the vault is. Without the rule the chain would stand on
    which function name happened to sort first.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    # the teller reaches the vault from a function of its own
                    # that role 12 never licensed to this caller
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
    # Hop 1 is still witnessed — the chain is refused at the step that is
    # unwitnessed, not at the one before it.
    assert census["act_as_witnessed"] == 1
    # ...and the reach is untouched: membership never depended on the rule.
    assert KEY_V in row["reach_entities"]


def test_w2_an_overloaded_intermediate_name_does_not_stand_in_for_the_admitted_function(fold):
    """A function NAME does not identify a function, and the chain rule needs one.

    The teller reaches the vault from a function it also calls ``bulkWithdraw``
    — a real shape: 32 (entity, name) pairs on the reference corpus carry more
    than one selector, ``manage`` at the composed BoringVaults among them. Its
    selector is not the one hop 1 admitted, so the principal cannot drive it,
    and a rule that compared names would admit the hop and compose the vault.
    """
    overloaded = "0x9d574421"
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    # same NAME as the admitted function, different function
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
    """The chain rule SELECTS the admitted step; it does not judge an arbitrary one.

    The teller reaches the vault from two of its own functions, and the one the
    principal cannot drive sorts first. A rule that asked the plane for "the"
    step and then vetoed it would refuse the whole chain here — publishing a
    refusal that names a function the previous hop DID admit — so the walk asks
    the narrower question instead and the recovery survives the ordering.
    """
    sites = (
        # sorts before bulkWithdraw, and nothing on this chain admits it
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
    """Chain length is a per-row MAXIMUM; every other census key is a count.

    Summed instead, two rows each composing a 2-hop chain would publish a
    corpus with a 4-hop chain — an arithmetic artefact read as the deepest chain
    anyone proved. Asserted over the rollup directly, because one composing row
    cannot tell a max from a sum.
    """
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

    # ...and the key the rollup maxes is really the one the fold publishes.
    document = fold(_composing_signals(), principals=_composing_principals(), **_two_hop_case())
    census = document.provenance["reach_bounds"]["act_as_composition"]["census"]["findings"]
    assert census["longest_composed_chain"] == 2
    assert _gate_row(document)["reach_composition_census"]["longest_composed_chain"] == 2


def test_w2_a_seed_is_never_constrained_by_a_hop_into_it(fold):
    """Ruling 4 rule 2: the seized gate is spent at hop 1, and every seed IS hop 1.

    Two entities carry the finding's signal, so both are seeds, and one of them
    is also the far end of a witnessed hop from the other. That hop admits one
    of its functions — but a seed does not need admitting: the principal seized
    its gate directly, which is the whole reason it is a seed. Constraining it
    to the function some sibling hop happened to admit would refuse its own
    composable hop and publish a previous-hop reason for a node that has no
    previous hop.
    """
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
                # BOTH seeds: the signal was witnessed on each
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
                # the sibling seed really can call the other one...
                (KEY_T, hub_entry): (("relay", "restricted", "hub", True, REFUND_SELECTOR),),
                # ...and the constrained seed's own composing site is issued
                # from a different function of its own
                (KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),),
            },
            reads={(KEY_T, "hub"): (KEY_C, "eth_call", 1), (KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
        ),
        value=value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C, KEY_T)),
    )
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    # The seed spends its own gate: one step, from the seed, no inherited entry.
    assert entry["act_as_chain_length"] == 1
    assert entry["act_as_chain"][0]["caller"] == KEY_C
    assert P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION not in row["reach_composition_census"]["act_as_refused"]


def test_w2_a_node_entered_twice_publishes_the_chain_the_hop_was_issued_from(fold):
    """Ruling 4 rule 4: the published chain must BE the path, not a path.

    The intermediate is admitted under two of its own functions by two different
    functions of the seized node. Its hop to the vault is issued from the second
    of them, so the published chain must carry the step that admitted THAT one.
    Publishing whichever entry was witnessed first would name a path this step
    was not issued from, while the census says every step is the one before it
    admitted.
    """
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
                    # issued from the SECOND admitted function of the teller
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
    # ...the step that admitted bulkWithdraw, not the one that admitted deposit.
    assert (first["calling_function"], first["selector"]) == ("finishSolve", second_entry)
    assert second["calling_selector"] == second_entry
    # ...and the chain really is a chain: each step enters the function the next
    # step is issued from.
    assert first["selector"] == second["calling_selector"]
