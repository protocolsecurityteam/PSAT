"""What ``effective_functions.action_summary`` is allowed to say, at the two
public endpoints that publish it.

``action_summary`` is a one-sentence English restatement of ``effect_labels`` /
``effect_targets`` (``summaries._action_summary``). No first-party UI renders it,
but it ships on two unauthenticated endpoints — ``GET /api/analyses/{run_name}``
(``analysis_detail``) and ``GET /api/company/{name}/functions``
(``governance.principals._build_company_function_entry``) — so it is the quotable
copy of whatever the structured planes say: a narrowing in the structured claim
that leaves the sentence alone leaves the over-claim intact.

Measured on the local corpus (1,773 rows):

* **130** rows say *"Performs a contract action."* — the fall-through with no
  labels and no targets. It asserts nothing, and a consumer cannot tell it from a
  sentence that was derived from evidence.
* **528** rows say *"Writes or calls into: <targets>"*, read straight off
  ``effect_targets`` — a list that conflates writes with plain calls: 501 of
  1,642 populated rows carry zero state-write evidence, so "writes" is not
  something this sentence can support.
* **20** rows say *"Executes arbitrary external calldata from the contract."*
  The structured ``exec.arbitrary`` claim was narrowed while this sentence was
  not: the claim now carries a three-state ``destination_constraint``, 7 of 20
  destinations are pinned by a mandatory gate, and one row
  (``LRTSquaredAdmin.rebalance``) lost the claim entirely as a false positive.
  Every persisted claim still predates that narrowing, so on today's rows the
  honest reading is *not determined* — which is exactly what the frontend's own
  ``constraintText`` does with an absent verdict.

``summary_kind`` names which of the three shapes a sentence is, and
``summary_note`` carries the reconciliation when the structured plane disagrees
with the prose. Neither is ever omitted, so key-absence marks a pre-fix payload
rather than any particular state.
"""

from __future__ import annotations

from typing import Any

from utils.scoring_status import DESTINATION_STATE_UNCONSTRAINED_PROVEN, NOT_DETERMINED

# Exact producer constants (``summaries._action_summary``). Matched as strings
# because what has to be classified is the SENTENCE THAT SHIPS, not a
# re-derivation of the branch that made it; a reader comparing this module to the
# producer sees one coupling instead of a duplicated label ladder.
VACUOUS_SUMMARY = "Performs a contract action."
TARGET_LIST_PREFIX = "Writes or calls into:"
ARBITRARY_SUMMARY = "Executes arbitrary external calldata from the contract."


def _exec_arbitrary_claim(claims: Any) -> dict[str, Any] | None:
    if not isinstance(claims, list):
        return None
    for claim in claims:
        if isinstance(claim, dict) and claim.get("claim_id") == "exec.arbitrary":
            return claim
    return None


def describe_action(
    action_summary: str | None,
    claims: Any,
    effect_labels: Any = None,
) -> tuple[str | None, str, str | None]:
    """``(summary, summary_kind, summary_note)`` for one function row.

    ``summary_kind`` is one of:

    ``absent``
        No sentence at all.
    ``vacuous``
        The no-evidence fall-through. It restates nothing.
    ``effect_target_list``
        Read off ``effect_targets``, which does not separate state-write targets
        from external-call targets, so the sentence's "writes" is not evidence of
        a write.
    ``effect_label``
        Derived from a specific effect label.

    ``summary_note`` is ``None`` unless the structured claims plane says something
    the sentence does not. It is not a hedge added everywhere: the three routes
    below are the ones where the sentence and the claim can actually disagree.
    """
    if not action_summary:
        return action_summary, "absent", None

    if action_summary == VACUOUS_SUMMARY:
        return (
            action_summary,
            "vacuous",
            "No effect label and no effect target produced this sentence; it restates no evidence.",
        )

    if action_summary.startswith(TARGET_LIST_PREFIX):
        return (
            action_summary,
            "effect_target_list",
            (
                "Derived from effect_targets, which does not separate state-write targets from "
                "external-call targets; 'writes' is not established for the names listed."
            ),
        )

    if action_summary == ARBITRARY_SUMMARY:
        summary, note = _reconcile_arbitrary(claims, effect_labels)
        return summary, "effect_label", note

    return action_summary, "effect_label", None


def _reconcile_arbitrary(claims: Any, effect_labels: Any) -> tuple[str, str | None]:
    """The word "arbitrary" is a claim about the DESTINATION, and the structured
    plane now has a three-state verdict on it.

    Kept deliberately narrow. The sentence is only replaced when the claims plane
    has something to say — never on the strength of the claim list being missing,
    which would hedge every legacy payload on no evidence at all.
    """
    if not isinstance(claims, list):
        # The claims plane's output is not on this row, so there is nothing to
        # reconcile against. Say that rather than hedging the sentence.
        return ARBITRARY_SUMMARY, "Not reconciled against the claims plane: no claim list on this row."

    claim = _exec_arbitrary_claim(claims)
    if claim is None:
        labels = effect_labels if isinstance(effect_labels, list) else []
        detail = (
            "the arbitrary_external_call label is still on the row"
            if "arbitrary_external_call" in labels
            else "the label is also absent"
        )
        # The claims plane ran on this row (it produced a list) and did NOT raise
        # exec.arbitrary. One such row was measured as a pure false positive.
        return (
            "Executes external calldata from the contract.",
            f"The claims plane records no exec.arbitrary claim for this function ({detail}), "
            "so 'arbitrary' is not published as the summary.",
        )

    witness = claim.get("witness")
    verdict = witness.get("destination_constraint") if isinstance(witness, dict) else None
    state = verdict.get("state") if isinstance(verdict, dict) else None

    if state == DESTINATION_STATE_UNCONSTRAINED_PROVEN:
        return ARBITRARY_SUMMARY, "Confirmed: the exec.arbitrary witness proves no mandatory gate pins the destination."

    if isinstance(state, str) and state not in {NOT_DETERMINED}:
        guard = verdict.get("guard") if isinstance(verdict, dict) else None
        gate = f" ({guard})" if isinstance(guard, str) and guard else ""
        return (
            f"Executes external calldata from the contract; a mandatory gate constrains the destination{gate}.",
            f"Narrowed by the exec.arbitrary witness: destination_constraint={state}.",
        )

    # Absent verdict (every persisted claim predates the verdict) or an explicit
    # not_determined. Neither proves the destination is freely chosen, and
    # 'arbitrary' asserts that it is.
    return (
        "Executes external calldata from the contract; whether the destination is freely chosen was not determined.",
        (
            "The exec.arbitrary witness carries no destination_constraint verdict"
            if state is None
            else "The exec.arbitrary witness reports destination_constraint=not_determined"
        )
        + ", so 'arbitrary' is not published as the summary.",
    )
