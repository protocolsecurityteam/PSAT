"""``action_summary`` ships on two unauthenticated endpoints and no first-party UI
renders it, so it is the quotable copy of the structured planes (W3-E item 3b, R3).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from services.aggregations.action_summary import (  # noqa: E402
    ARBITRARY_SUMMARY,
    VACUOUS_SUMMARY,
    describe_action,
)


def test_vacuous_summary_is_labelled_as_restating_nothing():
    """130 local rows. The sentence is indistinguishable from an evidence-derived
    one until it is labelled."""
    summary, kind, note = describe_action(VACUOUS_SUMMARY, [])
    assert summary == VACUOUS_SUMMARY
    assert kind == "vacuous"
    assert note and "restates no evidence" in note


def test_target_list_summary_discloses_the_write_conflation():
    """528 local rows. ``effect_targets`` does not separate state-write targets
    from external-call targets (D1: 501 of 1,642 populated rows carry zero
    state-write evidence), so "Writes or calls into" cannot support "writes"."""
    summary, kind, note = describe_action("Writes or calls into: accountantState.", [])
    assert summary == "Writes or calls into: accountantState."
    assert kind == "effect_target_list"
    assert note and "state-write" in note


def test_a_plain_label_summary_carries_no_note():
    """NEGATIVE CONTROL: the note is not a blanket hedge. A sentence a specific
    label produced, with nothing in the claims plane contradicting it, is clean."""
    summary, kind, note = describe_action("Changes the contract pause state.", [{"claim_id": "pause.set"}])
    assert summary == "Changes the contract pause state."
    assert kind == "effect_label"
    assert note is None


def _exec_claim(constraint=None):
    witness = {} if constraint is None else {"destination_constraint": constraint}
    return {"claim_id": "exec.arbitrary", "tier": "standard_exact", "witness": witness}


def test_proven_unconstrained_destination_keeps_the_arbitrary_sentence():
    """POSITIVE CONTROL for every narrowing below: when the witness PROVES no
    mandatory gate pins the destination, "arbitrary" is the right word and must
    survive."""
    summary, kind, note = describe_action(ARBITRARY_SUMMARY, [_exec_claim({"state": "unconstrained_proven"})])
    assert summary == ARBITRARY_SUMMARY
    assert kind == "effect_label"
    assert note and "Confirmed" in note


def test_a_proven_gate_on_the_destination_narrows_the_sentence():
    """A3 measured 7 of 20 ``exec.arbitrary`` destinations as pinned by a mandatory
    gate. The structured claim moved in Wave 1; the sentence did not."""
    summary, _kind, note = describe_action(
        ARBITRARY_SUMMARY,
        [_exec_claim({"state": "constrained", "guard": "mapping_allowlist"})],
    )
    assert "arbitrary" not in summary
    assert "a mandatory gate constrains the destination (mapping_allowlist)" in summary
    assert note and "destination_constraint=constrained" in note


def test_an_absent_destination_verdict_does_not_publish_arbitrary():
    """Every persisted ``exec.arbitrary`` claim (20/20 rows) carries NO
    ``destination_constraint`` key: the verdict predates A3. An absent verdict is
    the question being unanswered — the same reading ``claimsVocab.constraintText``
    takes — and "arbitrary" asserts an answer."""
    summary, _kind, note = describe_action(ARBITRARY_SUMMARY, [_exec_claim()])
    assert "arbitrary" not in summary
    assert "was not determined" in summary
    assert note and "no destination_constraint verdict" in note


def test_an_explicit_not_determined_verdict_also_hedges():
    summary, _kind, note = describe_action(ARBITRARY_SUMMARY, [_exec_claim({"state": "not_determined"})])
    assert "was not determined" in summary
    assert note and "not_determined" in note


def test_a_missing_exec_claim_contradicts_the_sentence():
    """The claims plane ran (it produced a list) and did not raise the claim. A3
    measured exactly this on ``LRTSquaredAdmin.rebalance`` — a pure false
    positive."""
    summary, _kind, note = describe_action(ARBITRARY_SUMMARY, [], effect_labels=["arbitrary_external_call"])
    assert summary == "Executes external calldata from the contract."
    assert note and "records no exec.arbitrary claim" in note
    assert "label is still on the row" in note


def test_no_claim_list_at_all_is_not_treated_as_a_contradiction():
    """NEGATIVE CONTROL for the test above: a row with no claims plane output is
    not evidence against the sentence, and hedging it would hedge every legacy
    payload on nothing."""
    summary, _kind, note = describe_action(ARBITRARY_SUMMARY, None)
    assert summary == ARBITRARY_SUMMARY
    assert note and "no claim list" in note


def test_an_absent_sentence_is_its_own_state():
    summary, kind, note = describe_action(None, [])
    assert summary is None
    assert kind == "absent"
    assert note is None
