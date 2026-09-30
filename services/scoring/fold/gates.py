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


# Gate name to the proven tokens that license its positive branch. ``gate_inputs`` is unchecked JSONB, so match exact
# tokens, not "not not_determined".
GATE_PROVEN_TOKENS: dict[str, tuple[str, ...]] = {
    "exact_empty_credit": ("earned",),
    "latch_witness": ("witnessed",),
    # F4: ``proven_upper_bound`` must be listed or every attribution-derived row is withheld. ``proven_ceiling`` is
    # absent on purpose: it's derived inside the fold and never on a distilled gate.
    "reach_magnitude_usd": (
        MAGNITUDE_STATE_PROVEN_EXACT,
        MAGNITUDE_STATE_PROVEN_FLOOR,
        MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    ),
    # Both states are proven; the execution's own three-state answer is in the payload (``utils.execution_record``).
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


# Validated as finite numbers on read too: a string "1e12" still does arithmetic in Python.
NUMERIC_GATES = frozenset({"reach_magnitude_usd"})


# Payload shapes are checked before walking so one bad payload withholds its row instead of raising out of the whole
# score.
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


# A missing one is a distiller bug: withhold the row rather than default or raise.
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
    """The row for one (unit, capability, access path), at its weakest gate.

    The path is in the key because the same capability via a timelock costs the delay; one max-weakness row would charge
    it at the undelayed rung.
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
    # Keep the member's own rung so an entity only one member reaches isn't priced at another's.
    previous = row.member_gate.get(address)
    if previous is None or weakness > previous[0]:
        row.member_gate[address] = (weakness, label, kind)
    return row


def _malformed_gates(signal: FunctionSignal) -> list[str]:
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
    """One gate, read on its exact proven token. Unrecognised tokens read as ``not_determined``."""
    try:
        tri = signal.gate_input(name)
    except KeyError:
        # Missing required gates were already withheld; this keeps incidental reads from raising.
        return Tri.not_determined()
    expected = GATE_PROVEN_TOKENS.get(name, ())
    if tri.state == NOT_DETERMINED or tri.state in expected:
        if name in NUMERIC_GATES and tri.is_determined and not _is_number(tri.value):
            return Tri.not_determined()
        return tri
    return Tri.not_determined()


def _signal_identity(signal: FunctionSignal) -> tuple[Any, ...]:
    """The signal's identity.

    Includes ``contract_id`` because split-proxy implementations share a deployment address.
    """
    return (signal.contract_id, signal.chain, signal.deployment_address, signal.selector, signal.claim_id)


def _signal_execution(signal: FunctionSignal) -> EX.ProvingExecution:
    """The execution that proved this signal's magnitude, or the typed reason there is none.

    Unreadable or undetermined gates map to :data:`EX.REASON_NOT_PERSISTED`, never an assumed execution.
    """
    gate = _gate(signal, PROVING_EXECUTION_KEY)
    payload = gate.value if isinstance(gate.value, dict) else {}
    ptr = payload.get("transcript_ptr")
    verdict_id = payload.get("effect_verdict_id")
    # Keep the pointers so the gap stays traceable to its transcript.
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
