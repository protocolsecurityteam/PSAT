"""``delegatecall.execute``: foreign code runs in this contract's storage.

Deliberately separate from ``upgrade.implementation``, which asserts the EIP-1967/UUPS standard; a consumer wanting
"logic can be replaced" reads the union.

The destination is classified from the IR, not the recorded sink target string, which depends on the route (a storage
variable directly, the library's own parameter name via a library, a temporary via assembly). The walk descends into
internal/library callees like the sink producer, binding each formal to the caller's argument, to reach the subject's
own symbol.

States are earned: ``storage_setter`` and siblings from the resolved variable, ``param`` from the subject's formal,
``self`` from a literal ``address(this)`` (a proven fixed address, so ``constrained``). Anything unsettled (a mapping
element like ``userModule[msg.sender]``, a multiply-defined name, an unresolved forwarder) is ``indeterminate`` with
``not_determined``; the claim still fires.
"""

from __future__ import annotations

from typing import Any

from ...contract_analysis_pipeline.predicate_types import (
    TARGET_KIND_STORAGE_NO_SETTER,
    TARGET_KIND_STORAGE_SETTER,
)
from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts
from ._taint import UNDETERMINED, _definitions, _origin, _root_variable

# Operand 1 of ``delegatecall``/``callcode`` is the destination.
_ASM_DELEGATE_OPCODES = {"delegatecall": 1, "callcode": 1}
_LOW_LEVEL_DELEGATE = frozenset({"delegatecall", "callcode"})

# Deeper delegatecalls give ``indeterminate`` rather than a guess.
_MAX_DEPTH = 4


def _opcode(ir: Any) -> str:
    return str(getattr(getattr(ir, "function", None), "name", "") or "").split("(", 1)[0]


def _slot_origin(variable: Any, unit: Any) -> Any | None:
    """The state variable a slot expression folds to, or ``None``.

    A split proxy reads ``sload(CONSTANT_SLOT)``, so step through the ``sload`` result to its argument and fold to the
    constant; that is how a setter on the same slot is found.
    """
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import SolidityCall

    definitions = _definitions(unit)
    defining = definitions.get(id(_origin(variable)))
    if isinstance(defining, SolidityCall) and _opcode(defining) == "sload":
        arguments = list(getattr(defining, "arguments", None) or [])
        if not arguments:
            return None
        variable = arguments[0]
    root = _root_variable(variable, definitions)
    return root if isinstance(root, StateVariable) else None


def _assembly_slot_writers(ctx: ClaimContext, slot_variable: Any) -> list[str]:
    """Functions that ``sstore`` the same slot: separates a governor-settable split-proxy implementation from an
    unwritable one, on the assembly route where the state-write facts see nothing.
    """
    from slither.slithir.operations import SolidityCall

    writers: list[str] = []
    for signature in ctx.function_signatures():
        for fn in _facts.contract_functions(ctx, signature):
            found = False
            for node in getattr(fn, "nodes", None) or []:
                for ir in getattr(node, "irs", None) or []:
                    if not isinstance(ir, SolidityCall) or _opcode(ir) != "sstore":
                        continue
                    arguments = list(getattr(ir, "arguments", None) or [])
                    if arguments and _slot_origin(arguments[0], fn) is slot_variable:
                        found = True
            if found:
                writers.append(signature)
                break
    return sorted(set(writers))


def _classify_state_variable(ctx: ClaimContext, variable: Any) -> tuple[str, list[str]]:
    if getattr(variable, "is_constant", False):
        return "constant", []
    if getattr(variable, "is_immutable", False):
        return "immutable", []
    name = getattr(variable, "name", None)
    writers = sorted(
        signature
        for signature in ctx.function_signatures()
        if any(write.get("var") == name for write in _facts.state_writes(ctx, signature))
    )
    return (TARGET_KIND_STORAGE_SETTER if writers else TARGET_KIND_STORAGE_NO_SETTER), writers


def _destination_operand(ir: Any) -> Any | None:
    """The destination operand for the three routes that produce a delegatecall sink."""
    from slither.slithir.operations import LowLevelCall, SolidityCall

    if isinstance(ir, LowLevelCall):
        if str(getattr(ir, "function_name", "")) in _LOW_LEVEL_DELEGATE:
            return getattr(ir, "destination", None)
        return None
    if isinstance(ir, SolidityCall):
        index = _ASM_DELEGATE_OPCODES.get(_opcode(ir))
        arguments = list(getattr(ir, "arguments", None) or [])
        if index is not None and len(arguments) > index:
            return arguments[index]
    return None


def _resolve(ctx: ClaimContext, unit: Any, bindings: dict[int, Any], depth: int) -> list[dict[str, Any]]:
    """Every delegatecall destination reachable from ``unit``, resolved against the subject's symbols.

    ``bindings`` maps a formal's id to its caller-side root (carrying a library's ``target`` back to the subject's
    variable).
    """
    from slither.core.declarations import SolidityVariable
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import InternalCall, LibraryCall

    if depth > _MAX_DEPTH:
        return [{"target_kind": "indeterminate", "reason": "walk_depth"}]

    definitions = _definitions(unit)
    parameters = list(getattr(unit, "parameters", None) or [])
    out: list[dict[str, Any]] = []

    def resolve_operand(operand: Any) -> dict[str, Any]:
        from slither.slithir.variables import ReferenceVariable

        if isinstance(operand, ReferenceVariable):
            # An element: following ``points_to_origin`` to the base mapping would claim one unredirectable destination
            # where each caller sets their own.
            return {"target_kind": "indeterminate", "reason": "mapping_or_array_element"}
        root = _root_variable(operand, definitions)
        if root is UNDETERMINED or root is None:
            return {"target_kind": "indeterminate", "reason": "unresolved_operand"}
        bound = bindings.get(id(root))
        if bound is not None:
            root = bound
        if isinstance(root, SolidityVariable) and getattr(root, "name", None) == "this":
            # ``address(this)``: the address is pinned at compile time; whether its code can change is
            # ``upgrade.implementation``'s claim. Matched after binding so the OZ ``Multicall`` library route answers
            # the same.
            return {"target_kind": "self"}
        if isinstance(root, StateVariable):
            kind, writers = _classify_state_variable(ctx, root)
            record: dict[str, Any] = {"target_kind": kind, "variable": str(getattr(root, "name", "") or "")}
            if writers:
                record["writer_signatures"] = writers
            return record
        if any(root is parameter for parameter in parameters) and not bindings:
            # The caller names the code that runs in this contract's storage.
            return {"target_kind": "param", "variable": str(getattr(root, "name", "") or "")}
        return {"target_kind": "indeterminate", "reason": "unresolved_operand"}

    for node in getattr(unit, "nodes", None) or []:
        for ir in getattr(node, "irs", None) or []:
            operand = _destination_operand(ir)
            if operand is not None:
                record = resolve_operand(operand)
                if record["target_kind"] == "indeterminate" and _opcode(ir) in _ASM_DELEGATE_OPCODES:
                    slot = _slot_origin(operand, unit)
                    if slot is not None:
                        # A split-proxy dispatch: whoever passes the slot setter's gate owns this contract's storage.
                        writers = _assembly_slot_writers(ctx, slot)
                        record = {
                            "target_kind": TARGET_KIND_STORAGE_SETTER if writers else TARGET_KIND_STORAGE_NO_SETTER,
                            "storage_slot_variable": str(getattr(slot, "name", "") or ""),
                            **({"writer_signatures": writers} if writers else {}),
                        }
                out.append(record)
                continue
            if not isinstance(ir, (InternalCall, LibraryCall)):
                continue
            callee = getattr(ir, "function", None)
            if callee is None or not getattr(callee, "nodes", None):
                continue
            arguments = list(getattr(ir, "arguments", None) or [])
            formals = list(getattr(callee, "parameters", None) or [])
            child: dict[int, Any] = {}
            for index, formal in enumerate(formals):
                if index >= len(arguments):
                    continue
                root = _root_variable(arguments[index], definitions)
                if root is UNDETERMINED or root is None:
                    continue
                child[id(formal)] = bindings.get(id(root), root)
            out.extend(_resolve(ctx, callee, child, depth + 1))
    return out


def _fold(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse per-site destinations.

    Different kinds fold to ``indeterminate`` with members published. Agreeing kinds publish the union of evidence:
    ``writer_signatures`` answers who can replace the code, and one ungated writer among several makes it ungated.
    Agreeing values keep ``variable``; disagreeing ones move to ``variables``.
    """
    if not records:
        return {"target_kind": "indeterminate", "reason": "no_resolved_site"}
    if len(records) == 1:
        return dict(records[0])
    kinds = sorted({record["target_kind"] for record in records})
    if len(kinds) > 1:
        return {"target_kind": "indeterminate", "reason": "sites_disagree", "site_kinds": kinds}
    merged: dict[str, Any] = {"target_kind": kinds[0], "sites": len(records)}
    for field, plural in (
        ("variable", "variables"),
        ("storage_slot_variable", "storage_slot_variables"),
        ("reason", "reasons"),
    ):
        values = sorted({str(record[field]) for record in records if record.get(field)})
        if len(values) == 1:
            merged[field] = values[0]
        elif values:
            merged[plural] = values
    writers = sorted({writer for record in records for writer in record.get("writer_signatures") or []})
    if writers:
        merged["writer_signatures"] = writers
    return merged


def _explained_by_upgrade(ctx: ClaimContext, function: str) -> bool:
    """True when this entry is a standard upgrade whose delegatecall is the upgrade mechanism (UUPS
    ``upgradeToAndCall`` runs the initializer via delegatecall), mirroring the label suppression so it isn't
    counted twice. Read from the facts the upgrade matcher gates on, since matchers can't see each other's output.
    """
    from ._gates import UPGRADE_SELECTORS, is_upgrade_gate

    return ctx.canonical_selector(function) in UPGRADE_SELECTORS and is_upgrade_gate(ctx)


@claim_matcher(
    claim_id="delegatecall.execute",
    sentence="executes foreign code in this contract's storage context (delegatecall)",
    legacy_projection="delegatecall_execution",
    consumer_family="exec",
)
def delegatecall_execute(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    sink_ids = [
        str(sink["id"])
        for sink in _facts.body_sinks(ctx, function)
        if sink.get("kind") == "delegatecall" and sink.get("id")
    ]
    if not sink_ids or _explained_by_upgrade(ctx, function):
        return None
    unit = _facts.contract_function(ctx, function)
    destination: dict[str, Any] = (
        _fold(_resolve(ctx, unit, {}, 0)) if unit is not None else {"target_kind": "indeterminate", "reason": "no_ir"}
    )
    witness: dict[str, Any] = {
        "kind": "delegatecall_sink",
        "sink_ids": sorted(sink_ids),
        "destination": destination,
        "destination_constraint": _destination_constraint(ctx, function, unit, destination),
    }
    return ClaimEvidence(tier="idiom_structural", witness=witness)


def _destination_constraint(ctx: ClaimContext, function: str, unit: Any, destination: dict[str, Any]) -> dict[str, Any]:
    """Three-state verdict on whether the destination is pinned: ``self`` is ``constrained`` by the operand itself; a
    caller-named destination asks whether a mandatory gate pins it; anything else is ``not_determined``.
    """
    kind = destination.get("target_kind")
    if kind == "self":
        return {"state": "constrained", "guard": "literal_self", "pins": True, "binding": "destination_operand"}
    if kind == "param":
        return _facts.param_constraint(
            ctx, function, _parameter_index(unit, destination.get("variable")), mode="external_call"
        )
    return {"state": "not_determined"}


def _parameter_index(unit: Any, name: Any) -> int | None:
    if unit is None or not isinstance(name, str) or not name:
        return None
    for index, parameter in enumerate(getattr(unit, "parameters", None) or []):
        if getattr(parameter, "name", None) == name:
            return index
    return None
