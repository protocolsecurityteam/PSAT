"""Destination resolution for out-flows."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from services.scoring import constants as K
from services.scoring.schema import (
    NOT_DETERMINED,
    Tri,
)
from utils.scoring_status import (
    DESTINATION_STATE_CONSTRAINED_PROVEN,
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_UNCONSTRAINED_PROVEN,
    OPENNESS_OPEN,
    OPENNESS_RESTRICTED,
    WITNESS_TIER_BEHAVIORAL_OBSERVED,
)

from .claims import _static_destination_shape, _tier

logger = logging.getLogger("services.scoring.distill")


@dataclass(frozen=True)
class _Destination:
    tri: Tri[str]
    severity: float | None
    basis: str
    notes: tuple[str, ...] = ()


_UNDETERMINED_DESTINATION = _Destination(tri=Tri[str].not_determined(), severity=None, basis=NOT_DETERMINED)


def _fork_caller_arbitrary_param(verdicts: Iterable[Any]) -> str | None:
    """The parameter a landed sentinel proved the caller chooses, or ``None``.

    A fork ``caller_arbitrary`` verdict proves only the parameter the sentinel was substituted into
    (``witness["sentinel_param"]``), which is often the payload rather than the call target. A verdict that doesn't name
    its parameter, or two naming different ones, yields nothing.
    """
    named: set[str] = set()
    for verdict in verdicts:
        witness = verdict.witness if isinstance(getattr(verdict, "witness", None), dict) else {}
        if verdict.verdict != "proven":
            continue
        if witness.get("destination_shape") != "caller_arbitrary" or witness.get("shape_proved_by") != "simulation":
            continue
        param = witness.get("sentinel_param")
        if isinstance(param, str) and param:
            named.add(param)
    return next(iter(named)) if len(named) == 1 else None


def _exec_destination(claim_id: str, witness: dict[str, Any], fork_param: str | None = None) -> _Destination:
    """The delegatecall/exec destination, and what it licenses.

    An indeterminate/unresolved destination is ``not_determined`` with no severity, never ``destination_unconstrained``.
    ``fork_param`` (:func:`_fork_caller_arbitrary_param`) is used only when it is the destination parameter.
    """
    destination = witness.get("destination") or {}
    target_kind = destination.get("target_kind") or witness.get("destination_kind")
    constraint = witness.get("destination_constraint") or {}
    state = constraint.get("state")

    if target_kind == "self":
        if state == DESTINATION_STATE_UNCONSTRAINED_PROVEN:
            # Contradictory witnesses (self-bound vs. unconstrained) prove neither; resolving to the benign arm would
            # let one forged half buy 0.0.
            return _Destination(
                tri=Tri[str].not_determined(),
                severity=None,
                basis="destination_witness_contradiction(self+unconstrained_proven)",
                notes=("destination_witnesses_contradict",),
            )
        # Keyed on target kind: ``constrained`` means a guard exists, not that the destination is this contract.
        severity = (
            K.DEST_SEVERITY_DELEGATECALL_SELF if claim_id == "delegatecall.execute" else K.DEST_SEVERITY_EXEC_SELF
        )
        # Only a literal self-binding corroborates; ``destination_operand`` is equally true of a foreign operand.
        corroborated = constraint.get("binding") in ("literal_self", "self") or constraint.get("guard") in (
            "literal_self",
            "self",
        )
        notes = ("destination_self_corroborated_by_literal",) if corroborated else ()
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, "self"),
            severity=severity,
            basis="destination_self_proven",
            notes=notes,
        )
    if target_kind == K.ADMIN_TARGET_KIND:
        return _Destination(
            tri=Tri[str].not_determined(),
            severity=None,
            basis="destination_storage_setter_deferred",
            notes=("destination_redirectable_by_unresolved_setter",),
        )
    if state == "constrained":
        guard = constraint.get("guard")
        if guard == "hash_commitment" and constraint.get("pins") is True:
            return _Destination(
                tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, "constrained:hash_commitment+pins"),
                severity=K.DEST_SEVERITY_HASH_COMMITMENT_PINS,
                basis="constrained:hash_commitment+pins",
            )
        if guard == "external_call_revert":
            return _Destination(
                tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, "constrained:external_call_revert"),
                severity=K.DEST_SEVERITY_EXTERNAL_CALL_REVERT,
                basis="constrained:external_call_revert",
                notes=("constraint_only_as_strong_as_external_contract",),
            )
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, f"constrained:{guard or 'unspecified'}"),
            severity=K.DEST_SEVERITY_CONSTRAINED_OTHER,
            basis=f"constrained:{guard or 'unspecified'}",
        )
    if state == DESTINATION_STATE_UNCONSTRAINED_PROVEN:
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_UNCONSTRAINED_PROVEN, "unconstrained_proven"),
            severity=K.DEST_SEVERITY_UNCONSTRAINED,
            basis="destination_unconstrained_proven",
        )
    # Join on the parameter, not the function: the fork proof applies only if ``sentinel_param`` is the parameter this
    # sink calls through (read from the witness, never the name). Any other shape stays not_determined.
    destination_param = witness.get("destination_param")
    if fork_param is not None and target_kind == "param" and isinstance(destination_param, str) and destination_param:
        if fork_param == destination_param:
            return _Destination(
                tri=Tri.proven(DESTINATION_STATE_UNCONSTRAINED_PROVEN, "caller_arbitrary"),
                severity=K.DEST_SEVERITY_UNCONSTRAINED,
                basis="fork:simulation+destination_param",
                notes=("destination_caller_arbitrary_proven_on_the_destination_parameter",),
            )
        return _Destination(
            tri=Tri[str].not_determined(),
            severity=None,
            basis="fork_caller_arbitrary_on_other_parameter(not_determined)",
            notes=("fork_caller_arbitrary_witness_is_about_another_parameter",),
        )
    return _UNDETERMINED_DESTINATION


def _caller_relative_destination(shape: str, basis: str, openness: str) -> _Destination:
    """A destination the static lattice proved caller-relative, and what the caller gate is worth against it.

    The lattice proof is universal, so it needs no existence witness, but the two kinds differ:

    ``msg_sender``: the payee is the caller. ``open`` makes the destination proven unconstrained, but the price is
    withheld (a drain and a redemption look the same); ``restricted`` gets the ordinary constrained convention.

    ``token_owner``: the payee is the current ``ownerOf`` a caller-passed id. Restricted keeps the constrained
    convention; open is withheld (open settlement to the rightful owner is the safe shape) pending an owner ruling.

    Unread openness withholds for either kind.
    """
    if openness == OPENNESS_OPEN:
        # Fail closed: only ``msg_sender`` escalates; new caller-relative kinds withhold until argued through.
        if shape != "msg_sender":
            return _Destination(
                tri=Tri[str].not_determined(),
                severity=None,
                basis=f"{basis}+open_caller_does_not_name_the_payee",
                notes=(f"destination_{shape}_open_gate_licenses_no_escalation",),
            )
        # The refusal note is added by ``_severity``, since ``_meet_destinations`` can move this destination onto a row
        # that ends up priced.
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_UNCONSTRAINED_PROVEN, "caller_arbitrary"),
            severity=None,
            basis=f"{basis}+open_caller+severity_pending_amount_witness",
            notes=(f"destination_{shape}_with_open_caller_gate",),
        )
    if openness == OPENNESS_RESTRICTED:
        held_by = (
            "constraint_only_as_strong_as_the_caller_gate"
            if shape == "msg_sender"
            else "destination_is_the_current_owner_of_a_caller_chosen_token_id"
        )
        # No fork basis to carry: the fork's shape vocabulary has no caller-relative kind. The constraint is in
        # ``notes``.
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, f"constrained:{shape}"),
            severity=K.DEST_SEVERITY_CONSTRAINED_OTHER,
            basis=f"constrained:{shape}+restricted_caller",
            notes=(held_by,),
        )
    return _Destination(
        tri=Tri[str].not_determined(),
        severity=None,
        basis=f"{basis}+caller_openness_not_determined",
        notes=(f"destination_{shape}_caller_gate_unread",),
    )


def _flow_destination(claim: dict[str, Any], all_claims: list[dict[str, Any]], openness: str) -> _Destination:
    witness = claim.get("witness") or {}
    observed = witness.get("observed") or {}
    proved_by = observed.get("shape_proved_by")
    shape = observed.get("destination_shape") if proved_by in ("simulation", "static") else None
    basis = f"fork:{proved_by}" if shape else ""
    if shape is None:
        static_shape, static_reason = _static_destination_shape(all_claims)
        shape = static_shape
        basis = f"static_lattice:{static_reason}"

    if shape == "caller_arbitrary":
        if _tier(claim) != WITNESS_TIER_BEHAVIORAL_OBSERVED:
            # An existential needs a behavioural existence proof.
            return _Destination(
                tri=Tri[str].not_determined(),
                severity=None,
                basis="caller_arbitrary_without_behavioural_proof",
                notes=("caller_arbitrary_escalation_withheld",),
            )
        constraint_state = None
        for flow in witness.get("flows") or []:
            if isinstance(flow, dict):
                constraint_state = (flow.get("target_constraint") or {}).get("state") or constraint_state
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_UNCONSTRAINED_PROVEN, "caller_arbitrary"),
            severity=K.FLOW_SEVERITY_CALLER_ARBITRARY,
            basis=(
                "caller_arbitrary+unconstrained_proven"
                if constraint_state == DESTINATION_STATE_UNCONSTRAINED_PROVEN
                else "caller_arbitrary_proven"
            ),
            notes=(f"target_constraint={constraint_state or 'absent'}",),
        )
    if shape == "immutable_fixed":
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, "immutable_fixed"),
            severity=K.FLOW_SEVERITY_FIXED_DESTINATION,
            basis=basis or "immutable_fixed_proven",
            notes=("fixed_destination_conditional_on_upgrade_authority",),
        )
    if shape == "storage_determined":
        return _Destination(
            tri=Tri[str].not_determined(),
            severity=None,
            basis="destination_storage_determined_deferred",
            notes=("destination_redirectable_by_unresolved_setter",),
        )
    if shape in K.CALLER_RELATIVE_TARGET_KINDS:
        return _caller_relative_destination(str(shape), basis, openness)
    return _Destination(tri=Tri[str].not_determined(), severity=None, basis=basis or NOT_DETERMINED)


_DESTINATION_MEET_RANK = {
    DESTINATION_STATE_UNCONSTRAINED_PROVEN: 0,
    DESTINATION_STATE_CONSTRAINED_PROVEN: 1,
    DESTINATION_STATE_NOT_APPLICABLE: 2,
}


def _meet_destinations(parts: list[_Destination]) -> _Destination:
    """The meet over every site: one unread destination makes the whole function unread. Never last-wins."""
    if not parts:
        return _UNDETERMINED_DESTINATION
    if any(not part.tri.is_determined for part in parts):
        undetermined = next(part for part in parts if not part.tri.is_determined)
        notes = tuple(sorted({n for part in parts for n in part.notes}))
        return _Destination(
            tri=Tri[str].not_determined(),
            severity=None,
            basis=undetermined.basis,
            notes=notes,
        )
    worst = min(parts, key=lambda p: (_DESTINATION_MEET_RANK[p.tri.state], -(p.severity or 0.0), p.basis))
    return _Destination(
        tri=worst.tri,
        severity=max((p.severity for p in parts if p.severity is not None), default=None),
        basis=worst.basis,
        notes=tuple(sorted({n for part in parts for n in part.notes})),
    )
