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
    _var_edge,
    conferral_plane,
    facts,
    fold,  # noqa: F401  (fold fixture, registered by import)
)


def test_w4a_the_citation_cap_shows_evidence_before_prose_and_counts_what_it_hid():
    """A prose ``reading`` evicted two transcript-bearing citations on a shipped row."""
    prose = [{"field": "reach_gate_state", "reading": "how to read it", "value": i} for i in range(8)]
    evidence = [{"field": "claims[].witness", "transcript_ptr": "t", "verdict": "proven"}]
    plain = [{"field": "gated_contract_backlink", "value": ["k"]}]
    shown = FOLD._cited(prose[:4] + evidence + prose[4:] + plain)
    assert len(shown) == FOLD.CITATION_CAP
    assert shown[0] is evidence[0]
    assert shown[1] is plain[0]
    assert [c["value"] for c in shown[2:]] == [0, 1, 2, 3, 4, 5]
    assert FOLD._cited(prose) == prose[: FOLD.CITATION_CAP]


def test_w4a_a_walked_hop_says_whether_the_surface_was_read_in_full():
    """A hop resting on one extracted function of twenty read as fully checked."""
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
    """Stored descriptions carry no polarity, so over-reading is safe only because it moves hops to not_determined."""
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
    assert hop.state == P.HOP_NOT_DETERMINED
    assert hop.state != "proven_no_reach"


def test_w4a_a_withheld_frontier_hop_sizes_the_subtree_it_hides(fold):
    """A row lost 22 entities behind 2 published hops.

    The size is measured against the widest walk; it is never a claim.
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
    assert (behind["hops"], behind["entities"]) == (1, 3)
    assert behind["entity_keys"] == sorted([a, b, c])
    assert b not in {hop["destination"] for hop in row["reach_hops_not_determined"]}


def test_w4a_a_dangling_function_reference_recovers_on_deployment_and_selector():
    """``function_id`` is ON DELETE SET NULL and re-analysis reinserts functions; (deployment, selector) survives."""
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

    # The index only holds keys every function agrees under.
    lost = plane.grant_for("ownership.transfer", None, entity=KEY_V, selector="0xabcdef12")
    assert not lost.writes_extracted
    assert lost.confers(scope, KEY_V).outcome == P.CONFERRAL_WRITES_NOT_EXTRACTED
