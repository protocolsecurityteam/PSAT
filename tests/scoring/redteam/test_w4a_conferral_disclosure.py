"""W4a — the disclosure items that ride with the conferral test.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from services.scoring import fold as FOLD
from services.scoring import planes as P
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_IMPL,
    KEY_PROXY,
    KEY_V,
    _queue_signal,
    _role_edge,
    _var_edge,
    conferral_plane,
    facts,
    fold,  # noqa: F401  (fold fixture, registered by import)
    value_plane,
)


def test_w4a_the_citation_cap_shows_evidence_before_prose_and_counts_what_it_hid():
    """The cap is a display bound; the order it evicts in must not be arbitrary.

    A prose ``reading`` restating how to read a field is not something a reader
    can check. Two transcript-bearing citations were evicted by one on a shipped
    row. Evidence first, prose last, and the total says how many were not shown.
    """
    prose = [{"field": "reach_gate_state", "reading": "how to read it", "value": i} for i in range(8)]
    evidence = [{"field": "claims[].witness", "transcript_ptr": "t", "verdict": "proven"}]
    plain = [{"field": "gated_contract_backlink", "value": ["k"]}]
    shown = FOLD._cited(prose[:4] + evidence + prose[4:] + plain)
    assert len(shown) == FOLD.CITATION_CAP
    assert shown[0] is evidence[0]
    assert shown[1] is plain[0]
    # Stable within a tier: the population order still decides among equals.
    assert [c["value"] for c in shown[2:]] == [0, 1, 2, 3, 4, 5]
    assert FOLD._cited(prose) == prose[: FOLD.CITATION_CAP]


def test_w4a_a_walked_hop_says_whether_the_surface_was_read_in_full():
    """ "No guard was found" over a surface read in part is not the same fact.

    The old census collapsed both into walked_on_analysed_conditions, so a hop
    resting on one extracted function out of twenty read as a checked hop.
    """
    fully = P.ConditionPlane()
    fully.by_entity = {KEY_V: (P.DestinationFunction(1, "a", (), True), P.DestinationFunction(2, "b", (), True))}
    assert fully.hop(KEY_C, KEY_V).coverage == P.WALKED_ON_ANALYSED_FULLY

    partly = P.ConditionPlane()
    partly.by_entity = {KEY_V: (P.DestinationFunction(1, "a", (), True), P.DestinationFunction(2, "b", (), False))}
    assert partly.hop(KEY_C, KEY_V).coverage == P.WALKED_ON_ANALYSED_PARTLY

    none = P.ConditionPlane()
    none.by_entity = {KEY_V: (P.DestinationFunction(1, "a", (), False),)}
    assert none.hop(KEY_C, KEY_V).coverage == P.WALKED_ON_UNANALYSED
    assert P.ConditionPlane().hop(KEY_C, KEY_V).coverage == P.WALKED_NO_FUNCTION
    assert set(P.WALKED_COVERAGE) == {
        P.WALKED_ON_ANALYSED_FULLY,
        P.WALKED_ON_ANALYSED_PARTLY,
        P.WALKED_ON_UNANALYSED,
        P.WALKED_NO_FUNCTION,
    }


def test_w4a_the_self_pin_recogniser_only_ever_withholds():
    """Its breadth is safe in exactly one direction, and this is that direction.

    Both comparators and every caller-named parameter are read as a pin, because
    the stored description carries no polarity and the name is the whole
    evidence. Every over-read moves a hop from walked to not_determined; nothing
    here can mint a proven-clear. The whole-word guard keeps ``spender`` out.
    """
    pinned = [
        "require(bool)(msg.sender != address(this))",
        "initiator != address(this)",
        "address(this) == _caller",
        "_sender == address(this)",
    ]
    for text in pinned:
        assert P._caller_self_pins([{"description": text}]) == (text,), text
    for text in ("spender != address(this)", "amount != address(this)", "msg.sender != owner"):
        assert P._caller_self_pins([{"description": text}]) == (), text

    plane = P.ConditionPlane()
    plane.by_entity = {KEY_V: (P.DestinationFunction(1, "solve", ("initiator != address(this)",), True),)}
    hop = plane.hop(KEY_C, KEY_V)
    # The strongest thing a pin can say is not_determined — never a proven no.
    assert hop.state == P.HOP_NOT_DETERMINED
    assert hop.state != "proven_no_reach"


def test_w4a_licensed_functions_are_keyed_on_the_entity_the_reach_set_uses(fold):
    """The join key a consumer joins on, not the raw anchor the walk speaks in.

    ``reach_entities`` is canonical — an implementation folded onto its proxy is
    one entity under two raw keys — while the walk names anchors. Publishing the
    licensed functions under the raw anchor would leave every folded destination
    unjoinable, silently, on the field the composition pass consumes.
    """
    closure = P.ControlClosure(edges=(_role_edge("roles 3", principal=KEY_C, anchor=KEY_IMPL),))
    plane = conferral_plane(role_functions={(KEY_IMPL, 3): (P.LicensedFunction("0xaaaaaaaa", "pull"),)})
    doc = fold(
        [_queue_signal("authority.replace")],
        value=value_plane(per_asset={KEY_PROXY: {"usdc": 100.0}}, alias={KEY_IMPL: KEY_PROXY}),
        closure=closure,
        conferral=plane,
        principals={1: facts(1, EOA, "eoa")},
    )
    row = doc.findings[0]
    licensed = row["reach_licensed_functions"]
    assert KEY_PROXY in row["reach_entities"], "the implementation folds onto its proxy"
    assert set(licensed) <= set(row["reach_entities"]), "every licensed key must be a reach key"
    # Structured at the source: the consumer joins on the selector rather than
    # splitting a string on a space a function name is allowed to contain.
    assert licensed == {KEY_PROXY: [{"selector": "0xaaaaaaaa", "name": "pull"}]}
    assert KEY_IMPL not in licensed


def test_w4a_a_withheld_frontier_hop_sizes_the_subtree_it_hides(fold):
    """One published hop can withhold a whole graph, and did.

    A row losing 22 entities behind 2 published hops named 2 destinations and
    said nothing about the other 20. The withheld population is sized against
    the widest walk this fold performs, and it is a size, never a claim.
    """
    a, b, c = KEY_V, KEY_PROXY, KEY_IMPL
    closure = P.ControlClosure(
        edges=(
            _var_edge("hook", principal=KEY_C, anchor=a),
            _var_edge("owner", principal=a, anchor=b),
            _var_edge("owner", principal=b, anchor=c),
        )
    )
    doc = fold(
        [_queue_signal("ownership.transfer")],
        closure=closure,
        conferral=conferral_plane(rewrites=("owner",)),
        principals={1: facts(1, EOA, "eoa")},
    )
    row = doc.findings[0]
    assert row["reach_entities"] == [KEY_C], "the frontier hop runs on an authority of another kind"
    assert len(row["reach_hops_not_determined"]) == 1, "one hop is published"
    behind = row["reach_withheld_behind_hops"]
    # …and it hides three entities, two of which the hop list never names.
    assert (behind["hops"], behind["entities"]) == (1, 3)
    assert behind["entity_keys"] == sorted([a, b, c])
    assert b not in {hop["destination"] for hop in row["reach_hops_not_determined"]}


def test_w4a_a_dangling_function_reference_recovers_on_deployment_and_selector():
    """A stale foreign key must not read as an extraction that never ran.

    ``function_score_signals.function_id`` is ON DELETE SET NULL and a
    re-analysis deletes and reinserts a contract's functions, so a signal that
    outlives one re-analysis points at nothing — and every state-variable hop it
    gates would degrade to writes-not-extracted, losing reach with a counted but
    causeless withhold. The signal's own (deployment, selector) survives that.
    """
    plane = P.ConferralPlane(
        writes_by_function={7: frozenset({"owner"})},
        writes_by_deployment_selector={(KEY_C, "0xabcdef12"): frozenset({"owner"})},
    )
    scope = P.parse_edge_scope("owner", "controller_value")

    live = plane.grant_for("ownership.transfer", 7, entity=KEY_C, selector="0xabcdef12")
    assert live.writes_extracted and "function 7" in live.basis

    recovered = plane.grant_for("ownership.transfer", None, entity=KEY_C, selector="0xABCDEF12")
    assert recovered.writes_extracted, "the selector is matched case-insensitively"
    assert recovered.confers(scope, KEY_V).conferred
    assert "recovered" in recovered.basis and "does not resolve" in recovered.basis

    # A key the recovery index does not carry stays unextracted rather than
    # guessing — the index only holds keys every function agrees under.
    lost = plane.grant_for("ownership.transfer", None, entity=KEY_V, selector="0xabcdef12")
    assert not lost.writes_extracted
    assert lost.confers(scope, KEY_V).outcome == P.CONFERRAL_WRITES_NOT_EXTRACTED
