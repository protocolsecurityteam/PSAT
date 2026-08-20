"""The gate envelope: closed gate vocabulary, malformed-gate detection, and the gate reads."""

from __future__ import annotations

import math
from typing import Any

from services.scoring.fold.types import _Row
from services.scoring.schema import NOT_DETERMINED, FunctionSignal, Tri
from utils import execution_record as EX
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.scoring_status import (
    MAGNITUDE_STATE_PROVEN_EXACT,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
)

ANYONE = "anyone"


# The closed vocabulary of every gate the fold reads: gate name → the proven
# state tokens that license its positive branch. ``gate_inputs`` is free-form
# JSONB with no CHECK behind it, so a reader that branches on "is not
# not_determined" treats a WITHHELD envelope (say ``not_earned``) as the earned
# one. Branching on the exact token is what makes the two different facts again.
GATE_PROVEN_TOKENS: dict[str, tuple[str, ...]] = {
    "exact_empty_credit": ("earned",),
    "latch_witness": ("witnessed",),
    # F4: ``proven_upper_bound`` is the ATTRIBUTION path's own state and MUST be
    # listed. ``_malformed_gates`` withholds any row whose gate state is neither
    # ``not_determined`` nor a member here, and ``_gate`` degrades it — so
    # omitting it would take every attribution-derived magnitude out at once,
    # which is a number movement dressed as a vocabulary omission.
    #
    # ``proven_ceiling`` (``scoring_status.MAGNITUDE_STATES_UPPER_BOUNDING``) is
    # ABSENT ON PURPOSE, and its absence takes no population out. This list
    # allow-lists states a DISTILLED signal may carry on its own
    # ``reach_magnitude_usd`` gate; a sheet ceiling is derived inside the fold
    # from the ``ValuePlane`` at the moment a code-control capability is priced
    # against the node it controls, so no signal ever presents it here and the
    # F4 hazard cannot apply to it. Should a distiller ever stamp the state onto
    # a gate, this is the line that must gain it — the omission is a scope
    # ruling, not an oversight.
    "reach_magnitude_usd": (
        MAGNITUDE_STATE_PROVEN_EXACT,
        MAGNITUDE_STATE_PROVEN_FLOOR,
        MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    ),
    # Both states are PROVEN: the distiller always performed the lookup, and the
    # earned negative carries the typed reason there is no record. The
    # execution's own three-state answer lives inside the payload — see
    # ``utils.execution_record``.
    PROVING_EXECUTION_KEY: EX.GATE_STATES,
    "token_identity": ("proven",),
    "asset_class": ("proven",),
    "input_seeded": ("proven",),
    "contract_balance_seeded": ("proven",),
    "amount_capped_by_balance": ("proven",),
    "asset_identity": ("resolved",),
    "pause_effective": ("proven",),
    "freeze_recovery_principals": ("enumerated",),
    "freeze_coverage_fraction": ("observed_blast_radius",),
    "destination_basis": ("basis",),
}


# Gates whose payload enters arithmetic. Validated as a real, finite number at
# READ as well as at construction: a string "1e12" compares and multiplies just
# fine in Python and would charge $1T off an untyped payload.
NUMERIC_GATES = frozenset({"reach_magnitude_usd"})


# Every gate's payload SHAPE, checked before any consumer walks it. ``gate_inputs``
# is free-form JSONB, so a list the fold iterates as dicts can arrive as a list of
# ints; without this the walk raises out of ``compute_protocol_score`` and one bad
# payload on one function silently costs the whole protocol its score.
GATE_PAYLOAD_SHAPES: dict[str, str] = {
    "exact_empty_credit": "object",
    "latch_witness": "object",
    "asset_identity": "object",
    "reach_magnitude_usd": "number",
    PROVING_EXECUTION_KEY: "object",
    "token_identity": "bool",
    "input_seeded": "bool",
    "contract_balance_seeded": "bool",
    "amount_capped_by_balance": "bool",
    "asset_class": "string",
    "destination_basis": "string",
    "pause_effective": "bool",
    "freeze_coverage_fraction": "string_list",
    "freeze_recovery_principals": "principal_ref_list",
}


# The gates the fold WILL read for a given claim. A signal missing one of them is
# a distiller bug, and it withholds its own row: reading a gate that was never
# written would put a default where a witness belongs, and raising would let one
# malformed row take the whole protocol's grade down with it.
REQUIRED_GATES = ("exact_empty_credit", "latch_witness", "reach_magnitude_usd")


REQUIRED_GATES_BY_CLAIM: dict[str, tuple[str, ...]] = {
    "flow.out": ("token_identity", "asset_class", "asset_identity"),
    "pause.set": ("freeze_recovery_principals",),
}


SINGLE_ASSET_CLASSES = frozenset({"erc20_only", "mixed"})


def _row_for(
    rows: dict[tuple[str, str, str], _Row],
    unit: str,
    capability: str,
    path: str,
    weakness: float,
    label: str,
    kind: str,
    address: str,
) -> _Row:
    """The row for one (unit, capability, ACCESS PATH), at its weakest gate.

    The path is part of the key because a unit can hold the same capability
    through paths that cost different things: a Safe that also proposes-and-
    executes on a timelock reaches the timelock's contracts only by paying the
    delay, and one max-weakness row would charge that delayed value at the
    Safe's undelayed rung. Within one path the weakest gate still wins (inv.5),
    which is what keeps two merged Safes one power rather than two.
    """
    key = (unit, capability, path)
    row = rows.get(key)
    if row is None:
        row = _Row(unit=unit, capability=capability, path=path)
        rows[key] = row
    if weakness > row.weakness or not row.weakest_label:
        row.weakness = weakness
        row.weakest_label = label
        row.principal_kind = kind
        row.weakest_address = address
    row.principal_addresses.add(address)
    # The member's OWN rung, kept beside the unit's weakest: a merged Safe unit
    # publishes one reach union, and pricing an entity only the 4/8 member
    # reaches at the 3/7 member's rung charges a coalition nobody proved.
    previous = row.member_gate.get(address)
    if previous is None or weakness > previous[0]:
        row.member_gate[address] = (weakness, label, kind)
    return row


# ---------------------------------------------------------------- gate reads


def _malformed_gates(signal: FunctionSignal) -> list[str]:
    """Gate envelopes this fold refuses to read, by name.

    A state outside the gate's closed vocabulary, or a numeric payload that is
    not a finite number, is a row this fold cannot score honestly.
    """
    bad: list[str] = []
    for name in REQUIRED_GATES + REQUIRED_GATES_BY_CLAIM.get(signal.claim_id, ()):
        if name not in signal.gate_inputs:
            bad.append(f"{name}(absent)")
    for name, raw in sorted(signal.gate_inputs.items()):
        expected = GATE_PROVEN_TOKENS.get(name)
        if expected is None:
            continue
        try:
            tri = Tri.from_json(raw)
        except ValueError:
            bad.append(name)
            continue
        if tri.state == NOT_DETERMINED:
            continue
        if tri.state not in expected:
            bad.append(name)
            continue
        if not _payload_has_shape(name, tri.value):
            bad.append(name)
    return bad


def _payload_has_shape(name: str, value: Any) -> bool:
    """Whether a proven gate payload is the shape its consumers walk."""
    shape = GATE_PAYLOAD_SHAPES.get(name)
    if shape is None:
        return True
    if shape == "number":
        return _is_number(value)
    if shape == "bool":
        return isinstance(value, bool)
    if shape == "string":
        return isinstance(value, str)
    if shape == "object":
        return isinstance(value, dict)
    if shape == "string_list":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if shape == "principal_ref_list":
        return isinstance(value, list) and all(_is_principal_ref(item) for item in value)
    return False


def _is_principal_ref(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    raw_id = entry.get("function_principal_id")
    if isinstance(raw_id, bool) or not isinstance(raw_id, int):
        return False
    for key in ("chain", "address"):
        if key in entry and entry[key] is not None and not isinstance(entry[key], str):
            return False
    return True


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def _gate(signal: FunctionSignal, name: str) -> Tri[Any]:
    """One gate, read on its EXACT proven token. Never "is not not_determined".

    A state the gate's vocabulary does not name is returned as
    ``not_determined``: an unrecognised token is a witness this fold cannot
    vouch for, and reading it as the positive branch is how a withheld arm
    publishes an earned one.
    """
    try:
        tri = signal.gate_input(name)
    except KeyError:
        # ``_malformed_gates`` has already withheld any row whose required gates
        # are missing; this arm keeps an incidental read from raising out of the
        # fold rather than inventing a value.
        return Tri.not_determined()
    expected = GATE_PROVEN_TOKENS.get(name, ())
    if tri.state == NOT_DETERMINED or tri.state in expected:
        if name in NUMERIC_GATES and tri.is_determined and not _is_number(tri.value):
            return Tri.not_determined()
        return tri
    return Tri.not_determined()


def _signal_identity(signal: FunctionSignal) -> tuple[Any, ...]:
    """What names one signal row across the fold and the confidence pass.

    ``contract_id`` is part of it because split-proxy secondary implementations
    share a ``deployment_address`` and are legitimately different contracts.
    """
    return (signal.contract_id, signal.chain, signal.deployment_address, signal.selector, signal.claim_id)


def _signal_execution(signal: FunctionSignal) -> EX.ProvingExecution:
    """The execution this signal's magnitude was proven by, or the typed reason
    there is none.

    A gate this fold cannot read is not an execution it may assume. ``_gate``
    already degrades an unrecognised token to ``not_determined``, and a
    ``not_determined`` envelope carries no payload — so both of those land on
    :data:`EX.REASON_NOT_PERSISTED`, the same state a row written before the
    record existed lands on. Absence never becomes a match, an empty caller, or
    an unseeded probe.
    """
    gate = _gate(signal, PROVING_EXECUTION_KEY)
    payload = gate.value if isinstance(gate.value, dict) else {}
    ptr = payload.get("transcript_ptr")
    verdict_id = payload.get("effect_verdict_id")
    # The two POINTERS survive the negative branch. They are the row's own
    # identity, not part of the record, and they are exactly what a reader needs
    # in order to go and look at the transcript the record is missing from —
    # dropping them would turn a traceable gap into an untraceable one.
    if gate.state != EX.GATE_STATE_RECORDED:
        reason = payload.get("reason")
        return EX.not_determined(
            reason if reason in EX.NOT_DETERMINED_REASONS else EX.REASON_NOT_PERSISTED,
            transcript_ptr=ptr if isinstance(ptr, str) else None,
            effect_verdict_id=verdict_id if isinstance(verdict_id, int) else None,
        )
    return EX.from_residue(
        payload,
        transcript_ptr=ptr if isinstance(ptr, str) else None,
        effect_verdict_id=verdict_id if isinstance(verdict_id, int) else None,
    )
