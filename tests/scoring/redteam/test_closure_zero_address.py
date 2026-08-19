"""Closure admission: the zero address, and the authority it proves absent.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from services.scoring import planes as P
from services.scoring.schema import entity_key
from tests.support.scoring_builders import (
    KEY_C,
    KEY_V,
    _reduce,
    _Row,
    closure_of,
)


def test_a_closure_publishes_a_zero_count_for_a_rule_that_never_fired():
    """An admission rule reports where it did NOT fire, or it discloses nothing."""
    closure = closure_of({KEY_C: {KEY_V}})
    assert closure.refusal_counts() == {
        P.REFUSAL_MALFORMED_NODE_ID: 0,
        P.REFUSAL_SELF_EDGE: 0,
        P.REFUSAL_ZERO_ANCHOR: 0,
        P.REFUSAL_ZERO_PRINCIPAL: 0,
    }
    assert closure.renounced_counts() == {
        "edges": 0,
        "authority_slots": 0,
        "anchors": 0,
        "authority_slots_by_label": {},
    }


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
    assert closure.renounced_counts() == {
        "edges": 1,
        "authority_slots": 1,
        "anchors": 1,
        "authority_slots_by_label": {"owner": 1},
    }
    # The refused edge reaches nothing: it is not in the walked graph at all.
    assert closure.principals() == ()
    assert closure.controlled_by(zero) == ()


def test_a_relation_named_after_a_getter_may_not_suppress_that_getters_label():
    """The relation-restatement branch is gone, and this is why.

    It existed to stop a single-token label equal to its own relation from being
    read as a variable of that name. It decided nothing — DB-wide the only labels
    equal to their relation are the multi-word "role principal" and "safe owner",
    which fail the identifier check on their own — and it carried an inversion:
    the day a relation was named after a real getter, every genuine label of that
    name would have been suppressed silently, with no count anywhere. 100
    ``authority`` labels sit behind that hazard today. A rule that decides
    nothing and can invert is deleted, not documented.
    """
    scope = P.parse_edge_scope("authority", "authority")
    assert (scope.kind, scope.state_var) == (P.SCOPE_STATE_VAR, "authority")
    assert P.parse_edge_scope("controller_value", "controller_value").kind == P.SCOPE_STATE_VAR
    # The case the deleted branch was protecting is now decided structurally, by
    # the relation gate: on a role relation the only positive answer is a role.
    assert P.parse_edge_scope("owner", "controller_value").kind == P.SCOPE_STATE_VAR


def test_a_role_relation_never_fabricates_a_state_variable():
    """On ``role_principal`` the answer is a role set or ``not_determined``.

    The identifier reading applied to a role edge minted ``state_var="roles"``
    out of the literal label ``roles`` — a variable no source declares, on a
    relation that asserts a role holding and not a variable at all. No live edge
    carries that label; the fabrication is pinned here so it cannot return.
    """
    scope = P.parse_edge_scope("roles", "role_principal")
    assert (scope.kind, scope.state_var, scope.roles) == (P.SCOPE_NOT_DETERMINED, None, ())
    assert scope.label == "roles"
    assert P.parse_edge_scope("someGetter", "role_principal").kind == P.SCOPE_NOT_DETERMINED
    # A real role label on the same relation is unaffected.
    assert P.parse_edge_scope("roles 12", "role_principal").roles == (12,)


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
    assert closure.renounced_counts() == {
        "edges": 4,
        "authority_slots": 2,
        "anchors": 2,
        # One label over two anchors: the slot count is per (anchor, label),
        # and this breakdown is per label, so both anchors' ``owner`` slots
        # land on the one key.
        "authority_slots_by_label": {"owner": 2},
    }
