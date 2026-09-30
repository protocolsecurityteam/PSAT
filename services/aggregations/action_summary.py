"""What ``effective_functions.action_summary`` may say on the two public endpoints that publish it
(``/api/analyses/{run_name}``, ``/api/company/{name}/functions``).

The sentence is the quotable copy of the structured planes, so narrowing a claim without the sentence leaves the
over-claim intact. Measured (1,773 rows): 130 say the vacuous ``Performs a contract action.``; 528 say ``Writes or calls
into`` though ``effect_targets`` conflates writes with calls; 20 say ``arbitrary`` calldata though ``exec.arbitrary``
now has a destination verdict.

``summary_kind`` and ``summary_note`` are never omitted, so key-absence marks a pre-fix payload.
"""

from __future__ import annotations

from typing import Any

from utils.scoring_status import DESTINATION_STATE_UNCONSTRAINED_PROVEN, NOT_DETERMINED

# Matched as strings: what's classified is the sentence that ships, not a re-derivation of the producer's branch.
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

    ``summary_kind``: ``absent``, ``vacuous`` (no-evidence fall-through), ``effect_target_list`` (its "writes" is not
    evidence of a write), ``effect_label``. ``summary_note`` is set only where the sentence and the claims plane can
    disagree.
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
    """ "Arbitrary" is a claim about the destination.

    Replaced only when the claims plane has something to say, never just because the claim list is missing.
    """
    if not isinstance(claims, list):
        return ARBITRARY_SUMMARY, "Not reconciled against the claims plane: no claim list on this row."

    claim = _exec_arbitrary_claim(claims)
    if claim is None:
        labels = effect_labels if isinstance(effect_labels, list) else []
        detail = (
            "the arbitrary_external_call label is still on the row"
            if "arbitrary_external_call" in labels
            else "the label is also absent"
        )
        # Claims plane ran and did not raise exec.arbitrary; one such row was a measured false positive.
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

    # Absent or not_determined verdict doesn't prove the destination is freely chosen, which 'arbitrary' asserts.
    return (
        "Executes external calldata from the contract; whether the destination is freely chosen was not determined.",
        (
            "The exec.arbitrary witness carries no destination_constraint verdict"
            if state is None
            else "The exec.arbitrary witness reports destination_constraint=not_determined"
        )
        + ", so 'arbitrary' is not published as the summary.",
    )
