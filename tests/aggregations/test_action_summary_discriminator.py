"""``action_summary`` is served unauthenticated with no first-party UI, so it is the quotable copy of the structured
planes.
"""

from __future__ import annotations

import pytest

from services.aggregations.action_summary import (
    ARBITRARY_SUMMARY,
    VACUOUS_SUMMARY,
    describe_action,
)


def test_vacuous_summary_is_labelled_as_restating_nothing():
    summary, kind, note = describe_action(VACUOUS_SUMMARY, [])
    assert summary == VACUOUS_SUMMARY
    assert kind == "vacuous"
    assert note and "restates no evidence" in note


def test_target_list_summary_discloses_the_write_conflation():
    """``effect_targets`` mixes state-write and external-call targets, so "Writes or calls into" cannot support
    "writes".
    """
    summary, kind, note = describe_action("Writes or calls into: accountantState.", [])
    assert summary == "Writes or calls into: accountantState."
    assert kind == "effect_target_list"
    assert note and "state-write" in note


def test_a_plain_label_summary_carries_no_note():
    """Negative control: the note is not a blanket hedge."""
    summary, kind, note = describe_action("Changes the contract pause state.", [{"claim_id": "pause.set"}])
    assert summary == "Changes the contract pause state."
    assert kind == "effect_label"
    assert note is None


def _exec_claim(constraint=None):
    witness = {} if constraint is None else {"destination_constraint": constraint}
    return {"claim_id": "exec.arbitrary", "tier": "standard_exact", "witness": witness}


def test_proven_unconstrained_destination_keeps_the_arbitrary_sentence():
    """Positive control: when the witness proves no mandatory gate pins the destination, "arbitrary" stays."""
    summary, kind, note = describe_action(ARBITRARY_SUMMARY, [_exec_claim({"state": "unconstrained_proven"})])
    assert summary == ARBITRARY_SUMMARY
    assert kind == "effect_label"
    assert note and "Confirmed" in note


def test_a_proven_gate_on_the_destination_narrows_the_sentence():
    summary, _kind, note = describe_action(
        ARBITRARY_SUMMARY,
        [_exec_claim({"state": "constrained", "guard": "mapping_allowlist"})],
    )
    assert summary is not None
    assert "arbitrary" not in summary
    assert "a mandatory gate constrains the destination (mapping_allowlist)" in summary
    assert note and "destination_constraint=constrained" in note


@pytest.mark.parametrize(
    "constraint,note_fragment",
    [
        # Persisted ``exec.arbitrary`` claims predate the ``destination_constraint`` key; an absent verdict is
        # unanswered, and "arbitrary" asserts an answer.
        pytest.param(None, "no destination_constraint verdict", id="absent_verdict"),
        pytest.param({"state": "not_determined"}, "not_determined", id="explicit_not_determined"),
    ],
)
def test_an_undetermined_destination_verdict_does_not_publish_arbitrary(constraint, note_fragment):
    summary, _kind, note = describe_action(ARBITRARY_SUMMARY, [_exec_claim(constraint)])
    assert summary is not None
    assert "arbitrary" not in summary
    assert "was not determined" in summary
    assert note and note_fragment in note


def test_a_missing_exec_claim_contradicts_the_sentence():
    """The claims plane ran and did not raise the claim (seen on ``LRTSquaredAdmin.rebalance``)."""
    summary, _kind, note = describe_action(ARBITRARY_SUMMARY, [], effect_labels=["arbitrary_external_call"])
    assert summary == "Executes external calldata from the contract."
    assert note and "records no exec.arbitrary claim" in note
    assert "label is still on the row" in note


def test_no_claim_list_at_all_is_not_treated_as_a_contradiction():
    """Negative control: no claims-plane output is not evidence against the sentence."""
    summary, _kind, note = describe_action(ARBITRARY_SUMMARY, None)
    assert summary == ARBITRARY_SUMMARY
    assert note and "no claim list" in note


def test_an_absent_sentence_is_its_own_state():
    summary, kind, note = describe_action(None, [])
    assert summary is None
    assert kind == "absent"
    assert note is None
