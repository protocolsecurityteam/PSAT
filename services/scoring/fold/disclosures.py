"""Disclosures, warnings, and counterfactuals."""

from __future__ import annotations

from typing import Any

from services.scoring import constants as K
from services.scoring.fold.gates import ANYONE, _gate
from services.scoring.schema import NOT_DETERMINED, FunctionSignal, entity_key
from utils.scoring_status import (
    PRINCIPAL_STATE_NONE_REQUIRED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    SEVERITY_STATE_PROVEN,
    VALUE_STATE_PROVEN_NO_REACH,
)

# ---------------------------------------------------------------- disclosures


# The upgrade-authority disclosure and the same-function residual an uncharged
# row carries, in preference order — the first present on the row wins each slot.
# Both the self-service pair (SPEC §7 G7) and the msg_value siblings are here, so
# the earned negative reads the actual token the excluded row published rather
# than a hard-coded self-service one it may not carry.
_UNCHARGED_CONDITIONAL_TOKENS = (
    "self_service_bound_conditional_on_upgrade_authority",
    "fixed_destination_conditional_on_upgrade_authority",
)


_UNCHARGED_RESIDUAL_TOKENS = (
    "self_service_sibling_function_residual_not_proven",
    "msg_value_self_return_repetition_not_witnessed",
)


def _is_uncharged_product(signal: FunctionSignal) -> bool:
    """A proven-0.0 row whose severity_basis names an uncharged-product token.

    Gated on BOTH the token AND the value, never the float alone: a proven 0.0
    with no such token (``pause.set``'s build-up-from-zero) is a real charge that
    happens to start at zero, not a benign payout. A token beside a non-zero
    value is a disagreement handled by :func:`_uncharged_product`, not here."""
    if not (set(signal.severity_basis) & K.UNCHARGED_PRODUCT_BASES):
        return False
    return signal.severity.state == SEVERITY_STATE_PROVEN and signal.severity.value == 0.0


def _uncharged_product(signal: FunctionSignal, warnings: list[dict[str, Any]]) -> bool:
    """Whether the fold excludes this row as uncharged product surface.

    A severity_basis that names an uncharged-product token beside a severity that
    is not proven 0.0 is a bug, not a benign row: it is published as a warning and
    the row is NOT excluded (it keeps whatever charge its non-zero severity
    carries), so the disagreement can never buy a silent exclusion."""
    tokens = set(signal.severity_basis) & K.UNCHARGED_PRODUCT_BASES
    if not tokens:
        return False
    if not (signal.severity.state == SEVERITY_STATE_PROVEN and signal.severity.value == 0.0):
        warnings.append(
            _warning(
                "uncharged_product_basis_value_disagreement",
                signal,
                f"severity_basis names uncharged-product token(s) {sorted(tokens)} but severity is not proven 0.0",
            )
        )
        return False
    return True


def _collect_disclosures(
    signal: FunctionSignal,
    earned_negatives: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    warnings: list[dict[str, Any]],
) -> None:
    entity = entity_key(signal.chain, signal.deployment_address)
    credit = _gate(signal, "exact_empty_credit")
    if credit.is_determined:
        if signal.principal_state != PRINCIPAL_STATE_NOT_DETERMINED:
            # "No resolved caller can reach this" cannot be published beside ANY
            # determined caller state: ``enumerated`` names callers that reach it,
            # and ``none_required`` is a PROVEN PUBLIC PATH — the opposite pole,
            # and the worse contradiction of the two.
            warnings.append(
                _warning(
                    "exact_empty_credit_contradicted_by_principals",
                    signal,
                    (
                        "an earned empty caller set on a function with a proven public path"
                        if signal.principal_state == PRINCIPAL_STATE_NONE_REQUIRED
                        else "an earned empty caller set on a function whose principals resolved"
                    ),
                    principal_state=signal.principal_state,
                )
            )
        elif (entity, signal.function_name) not in seen:
            seen.add((entity, signal.function_name))
            payload = credit.value if isinstance(credit.value, dict) else {}
            earned_negatives.append(
                {
                    "entity": entity,
                    "function": signal.function_name,
                    "capability": signal.claim_id,
                    "fact": "no resolved caller can reach this function",
                    "state": "currently_unreachable",
                    "observed_at_block": payload.get("block"),
                    "empty_reason": payload.get("empty_reason"),
                    "counterfactual": "one ownership/authority write restores reachability",
                    "axiom": (
                        "msg.sender != 0x0, so an owner disjunct of {0x0} is a singleton rather than the empty set"
                    ),
                    "re_enablable_by": NOT_DETERMINED,
                }
            )
    if signal.value_state == VALUE_STATE_PROVEN_NO_REACH and (entity, signal.function_name + ":no_reach") not in seen:
        # An earned negative in its own right: reach was WITNESSED and reached
        # nothing. Publishing it beside the undetermined rows would lose the one
        # value fact on the page that was actually proven.
        seen.add((entity, signal.function_name + ":no_reach"))
        earned_negatives.append(
            {
                "entity": entity,
                "function": signal.function_name,
                "capability": signal.claim_id,
                "fact": "reach was witnessed and reached no value",
                "state": "proven_no_reach",
                "basis": signal.value_basis,
                "counterfactual": "funding the entity would give this capability something to reach",
                "re_enablable_by": NOT_DETERMINED,
            }
        )
    if _is_uncharged_product(signal) and (entity, signal.function_name + ":uncharged") not in seen:
        # An excluded row leaves NO finding, so its witness_notes reach no
        # document surface (``row.notes`` is the only path). The UUPS disclosure
        # and the same-function residual would vanish with it — so the earned
        # negative carries them here, read from the row's own notes rather than
        # hard-coded, because the excluded row may be a msg_value arm whose
        # disclosures are not the self-service pair.
        seen.add((entity, signal.function_name + ":uncharged"))
        notes = set(signal.witness_notes)
        conditional_on = next((t for t in _UNCHARGED_CONDITIONAL_TOKENS if t in notes), NOT_DETERMINED)
        residual = next((t for t in _UNCHARGED_RESIDUAL_TOKENS if t in notes), NOT_DETERMINED)
        earned_negatives.append(
            {
                "entity": entity,
                "function": signal.function_name,
                "capability": signal.claim_id,
                "fact": (
                    "the payout is bounded to the caller's own attached value or storage position and "
                    "moves no position the caller did not fund"
                ),
                "state": "uncharged_product_surface",
                "basis": list(signal.severity_basis),
                "conditional_on": conditional_on,
                "residual": residual,
                "counterfactual": "replacing the implementation removes the bound this verdict rests on",
                "re_enablable_by": NOT_DETERMINED,
            }
        )
    latch = _gate(signal, "latch_witness")
    if latch.is_determined:
        payload = latch.value if isinstance(latch.value, dict) else {}
        warnings.append(
            _warning(
                "one_shot_latch_is_reopenable",
                signal,
                "a consumed latch is a now-fact, re-openable by the upgrade authority of the probed proxy",
                latch_state=payload.get("latch_state"),
                probe_block=payload.get("probe_block"),
            )
        )
    for note in signal.witness_notes:
        if note in _NOTE_WARNINGS:
            warnings.append(_warning(note, signal, _NOTE_WARNINGS[note]))


_NOTE_WARNINGS = {
    "destination_not_determined_row_withheld": (
        "the destination was not proven, so no severity is assigned and the row does not "
        "enter the grade; absence of a resolved constraint is not proof the destination is open"
    ),
    "flow_severity_withheld_pending_amount_witness": (
        "the destination is proven caller-relative; what the payout is bounded BY has no witness, "
        "so no severity is assigned and the row does not enter the grade — absence of a bound is "
        "not proof the payout is unbounded"
    ),
    "msg_value_self_return_repetition_not_witnessed": (
        "the amount witness bounds each payment by the value attached to this call; nothing "
        "witnesses how many such payments one call makes"
    ),
    "destination_witnesses_contradict": (
        "two destination witnesses cannot both be true, so neither is adopted and the row is withheld"
    ),
    "caller_arbitrary_escalation_withheld": "caller_arbitrary carries no behavioural existence proof",
    "reach_floor_not_a_bound": "a 0.00 floor is 'no proven bound', not a proven zero",
    "reach_floor_absent": "reach_indeterminate with no floor key: nothing about the balance was witnessed",
    "reach_seeded_balance_only": "the contract's balance was overridden before the payout",
    "reach_partially_priced": "the reach is a proven floor; the unpriced remainder is a confidence gap",
    "freeze_effectiveness_not_determined": (
        "no fork proof that the latch takes effect, so no value membership is charged"
    ),
    "freeze_immobilised_fraction_not_determined": (
        "the value held at the frozen entity is measured; what fraction is immobilised has no witness"
    ),
    "product_claim_reachability_unproven": "treated as product on claim_id alone, but openness is not_determined",
    "claim_type_not_scored": "no severity model exists for this claim type; exclusion is not a benign verdict",
    "restricted_privileged_no_principal": "restricted privileged function with no resolved principal",
    "empty_caller_set_not_earned": (
        "an empty caller set that did not earn the served credit: neither reachable nor "
        "proven unreachable, so no earned negative is published"
    ),
    "registry_escalation_mutators_unverified": "an owner resolves but the role mutator selectors are not present",
    "delay_change_gate_not_self_gated": (
        "the delay-change path's own gate is not the contract itself, so no anti-decoy credit is taken"
    ),
    "destination_redirectable_by_unresolved_setter": "the destination's setter is named by no witness",
    "concrete_destination_existential_not_a_fixed_destination": (
        "an observed sink is existential and cannot prove a fixed destination"
    ),
    # The self-service arm's disclosures. An excluded row publishes no
    # witness_notes on any finding, so these must surface as warnings (inv. 6's
    # third channel) as well as ride the earned negative — otherwise a proven
    # benign payout's residuals would be legible on no document surface at all.
    "self_service_uncharged_product_surface": (
        "the payout is proven bounded to the caller's own position and the record is cleared before "
        "the external call, so the row is uncharged product surface and creates no finding"
    ),
    "self_service_bound_conditional_on_upgrade_authority": (
        "the self-service bound holds against the current implementation; the payout entity is a UUPS "
        "proxy, so whatever authority can replace the code can replace the bound"
    ),
    "self_service_sibling_function_residual_not_proven": (
        "the bound is proven for THIS function only; no witness names what sibling functions may do to the same record"
    ),
}


def _warning(kind: str, signal: FunctionSignal, note: str, **extra: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "entity": entity_key(signal.chain, signal.deployment_address),
        "function": signal.function_name,
        "capability": signal.claim_id,
        "note": note,
        **{k: v for k, v in sorted(extra.items()) if v is not None},
    }


def _summarise_warnings(warnings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        warnings,
        key=lambda w: (
            str(w.get("kind")),
            str(w.get("entity")),
            str(w.get("function")),
            str(w.get("capability")),
            str(w.get("note")),
        ),
    )


def _population_disposition(signals: list[FunctionSignal], findings: list[dict[str, Any]]) -> str:
    if not signals:
        return "no_population(no current signals for this protocol)"
    if not findings:
        return "population_scored_to_nothing(every signal failed closed)"
    return "scored"


def _counterfactual(kind: str) -> str:
    return {
        ANYONE: "gate this capability behind a multisig or timelock",
        "eoa": "move behind a strong multisig (>= 0.67 k/n) or a timelock",
        "safe": "raise the threshold ratio, diversify signers across units, and/or add a timelock in front",
        "timelock": "already timelock-gated; the residual is the proposer quorum and the delay length",
        "contract": "resolve the controlling principal of the gating contract",
    }.get(kind, "n/a")
