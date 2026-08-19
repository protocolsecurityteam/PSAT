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

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- destination


@dataclass(frozen=True)
class _Destination:
    tri: Tri[str]
    severity: float | None
    basis: str
    notes: tuple[str, ...] = ()


_UNDETERMINED_DESTINATION = _Destination(tri=Tri[str].not_determined(), severity=None, basis=NOT_DETERMINED)


def _fork_caller_arbitrary_param(verdicts: Iterable[Any]) -> str | None:
    """The parameter a landed sentinel proved the CALLER chooses, or ``None``.

    A fork ``caller_arbitrary`` verdict is a proof about exactly ONE parameter:
    the one the sentinel address was substituted into
    (``services.effects.calldata._value_probe_inputs``). It says nothing about
    the function's other address parameters, and on this corpus the two are
    routinely different — an executor-shaped function takes the sentinel in its
    PAYLOAD slot while its call target keeps the value the base probe passed.

    So the parameter identity is the join key, and the prober is the only thing
    that can state it: ``witness["sentinel_param"]``. A verdict that does not
    name its subject is not a weaker proof, it is a proof about an unnamed
    parameter — unusable here, and refused rather than assumed to be about the
    destination. Two verdicts naming different parameters likewise yield
    nothing rather than a picked winner.
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

    An ``indeterminate`` / ``unresolved_operand`` / ``not_determined``
    destination is NOT ``destination_unconstrained``. It fails to
    ``not_determined`` and yields no severity, so the row never enters the grade
    — absence of a resolved constraint is never proof the destination is open.

    ``fork_param`` is the parameter a landed sentinel proved caller-chosen on
    this function (:func:`_fork_caller_arbitrary_param`). It is consumed only on
    a proven identity with the destination parameter — see the arm below.
    """
    destination = witness.get("destination") or {}
    target_kind = destination.get("target_kind") or witness.get("destination_kind")
    constraint = witness.get("destination_constraint") or {}
    state = constraint.get("state")

    if target_kind == "self":
        if state == DESTINATION_STATE_UNCONSTRAINED_PROVEN:
            # Two witnesses that cannot both be true: a destination fixed at
            # ``address(this)`` and a destination proven unconstrained. A
            # contradiction is not evidence for either side, and resolving it to
            # the benign arm would let one forged half buy the 0.0 severity.
            return _Destination(
                tri=Tri[str].not_determined(),
                severity=None,
                basis="destination_witness_contradiction(self+unconstrained_proven)",
                notes=("destination_witnesses_contradict",),
            )
        # Keyed on the target kind, never on the constraint state alone: a
        # ``constrained`` state says a guard exists, not that the destination is
        # this contract.
        severity = (
            K.DEST_SEVERITY_DELEGATECALL_SELF if claim_id == "delegatecall.execute" else K.DEST_SEVERITY_EXEC_SELF
        )
        # Only a literal self-binding corroborates self-ness. ``destination_operand``
        # says the guard is bound to the operand, which is equally true of an
        # operand that is not this contract, so it corroborates nothing here.
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
    # The fork already answered this question for some functions and nobody
    # read the answer. Consuming it is a JOIN ON THE PARAMETER, never on the
    # function: the sentinel proved the caller picks whatever sits in
    # ``sentinel_param``, and only if that IS the parameter this sink calls
    # through does the proof say the destination is caller-chosen. The
    # destination parameter is read from the witness (``destination_param``
    # under a ``param`` kind), never from the function's name (inv. 1).
    #
    # Every other shape of the join refuses and the row stays not_determined:
    # a verdict about a different parameter licenses nothing here (it is the
    # ordinary shape of an arbitrary-call executor, whose sentinel rides the
    # payload while the call target is the prober's own choice), and a
    # destination that is not a whole parameter has no parameter to be joined on.
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
    """A destination the static lattice proved is caller-RELATIVE, and what the
    gate that decides who may call is worth against it.

    The lattice proof is a UNIVERSAL over every out-flow of the function, so it
    needs no behavioural existence witness the way the fork's ``caller_arbitrary``
    arm does (inv. 9). But the two kinds it proves make DIFFERENT claims, and one
    argument does not cover both:

    ``msg_sender`` — the payee IS the caller. The caller names the destination by
    choosing which address makes the call, so:

    * ``open`` — anyone can be ``msg.sender``, so the destination is proven
      unconstrained. The PRICE is a second question and this arm does not answer
      it: an open payout to the caller is the shape of a drain and the shape of a
      redemption alike, and what the amount is bounded BY has no witness here. So
      the destination is published and the severity is withheld — the basis says
      so, and ``_severity`` names the refusal on the row;
    * ``restricted`` — the recipient is inside the privileged caller set: the
      ordinary constrained-destination convention, and no stronger than the gate
      that produces it.

    ``token_owner`` — the payee is the CURRENT OWNER of a token id the caller
    passed (``ownerOf``, ``contract_analysis_pipeline.effects._TOKEN_OWNER_SELECTOR``).
    The caller chooses the id; the token's transfer history chooses the address.
    That is a real constraint and it is NOT the caller gate, so the restricted arm
    keeps the constrained convention but says what actually holds it. The OPEN
    arm is WITHHELD rather than escalated: "anyone may trigger the settlement,
    the funds go to the rightful owner" is the canonical safe shape of this
    pattern, so an open gate here is not evidence the destination is the
    attacker's to choose, and publishing ``unconstrained_proven`` off it would be
    a positive fact the producer's own witness refutes. Whether the open-caller
    ruling extends to this kind is the owner's to decide; until it does, the row
    is not_determined.

    Either kind with ``openness`` ``not_determined`` — the gate is UNREAD, which
    is neither open nor restricted. Both arms would price an unread witness, so
    the row stays not_determined and earns no severity.
    """
    if openness == OPENNESS_OPEN:
        # Named positively and failing closed: the escalation belongs to the one
        # kind whose payee the caller can name, and any kind added to
        # ``CALLER_RELATIVE_TARGET_KINDS`` later withholds until someone argues
        # it through rather than inheriting an escalation by default.
        if shape != "msg_sender":
            return _Destination(
                tri=Tri[str].not_determined(),
                severity=None,
                basis=f"{basis}+open_caller_does_not_name_the_payee",
                notes=(f"destination_{shape}_open_gate_licenses_no_escalation",),
            )
        # The refusal token is NOT stamped here: what a withheld price means is
        # ``_severity``'s to say, on the row it actually withheld. A destination
        # travels through ``_meet_destinations``, which borrows a sibling site's
        # severity, so a note fixed to this half could ride onto a row that ends
        # up priced and graded.
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
        # The incoming ``basis`` is not carried here, and its absence costs
        # nothing: neither kind can arrive from the fork (the simulation's shape
        # vocabulary has no caller-relative member), so the static provenance the
        # open and unread arms preserve would only restate the kind that is
        # already in this string. What the constraint IS, is in ``notes``.
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
    """The out-flow destination: fork shape first, static lattice second."""
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
            # An existential needs a behavioural existence proof; without one
            # the escalation is withheld rather than assumed.
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
    """The MEET over every site: one unread destination makes the fold unread.

    Never last-wins. A function whose second delegatecall site could not be
    resolved has an unread destination as a whole, and the proven first site
    cannot vouch for it.
    """
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
