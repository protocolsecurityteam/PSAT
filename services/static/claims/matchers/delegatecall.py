"""``delegatecall.execute`` — foreign code runs in this contract's storage.

The ``delegatecall_execution`` legacy label was the ONLY label in the whole
vocabulary that ever appeared without a claim, and it did so on exactly two rows
— so the claims plane covered the legacy semantic vocabulary completely except
here. Both rows are severity-relevant: one is an unauthenticated ``fallback``
that dispatches to a governor-settable slot, the other a governor-only deposit
whose target is a caller-keyed mapping element.

**Deliberately NOT ``upgrade.implementation``.** That claim asserts the
EIP-1967/UUPS contract and carries an established, well-characterised population
(the "24/27 timelock-gated" statistic). Admitting a non-standard split proxy into
it would corrupt that statistic to say the same severity-relevant thing. A
consumer that wants "logic can be replaced" reads the union of the two claims.

**The destination is classified from the IR, never from the recorded sink
target.** The sink target is a string, and which string it is depends on the
route the delegatecall took rather than on where the call goes: the direct route
records this contract's storage variable (``module``), the library route records
the LIBRARY's own parameter name (``target``) — a symbol that does not exist in
the subject contract at all — and the assembly route records a temporary
(``assembly_delegatecall:TMP_1821``). A classifier reading that string resolves
two of the three to nothing and publishes ``not_determined`` for a destination
that is provably a storage setter. Both production rows are assembly routes and
the corpus had none, so nothing could have caught it; W0-7 fixture 9 exists for
exactly this and this matcher must pass it.

So the walk descends into internal/library callees the way the sink producer
does (``effects.py`` recurses through ``InternalCall``/``LibraryCall``), binding
each callee formal to the caller's argument as it goes, and resolves the
destination operand to the subject's own symbol.

Three destination states, and none is defaulted into: ``storage_setter`` and its
siblings are earned from the resolved variable, and everything the walk did not
settle — a mapping element (``userModule[msg.sender]``: nothing static can name
the address, and answering ``userModule`` would assert ONE destination where
there is one per caller), a multiply-defined name, an unresolved forwarder —
lands on ``indeterminate`` with ``target_constraint`` ``not_determined``. The
claim still fires there: a delegatecall IS happening, which is a fact; the
severity modifier is what is unproven.
"""

from __future__ import annotations

from typing import Any

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts
from ._taint import UNDETERMINED, _definitions, _origin, _root_variable

# The assembly opcode layout: ``delegatecall(gas, addr, inOff, inLen, outOff,
# outLen)`` — operand 1 is the destination. ``callcode`` shares the shape.
_ASM_DELEGATE_OPCODES = {"delegatecall": 1, "callcode": 1}
_LOW_LEVEL_DELEGATE = frozenset({"delegatecall", "callcode"})

# How deep the callee walk goes. The sink producer recurses without a bound; a
# delegatecall further down than this yields ``indeterminate`` rather than a
# guess, which under-claims by construction.
_MAX_DEPTH = 4


def _opcode(ir: Any) -> str:
    return str(getattr(getattr(ir, "function", None), "name", "") or "").split("(", 1)[0]


def _slot_origin(variable: Any, unit: Any) -> Any | None:
    """The state variable a slot expression folds to, or ``None``.

    A split proxy reads its implementation with ``sload(ADMIN_IMPL_SLOT)`` where
    the slot is a ``bytes32 constant``. The operand reaching the delegatecall
    opcode is the ``sload``'s RESULT temporary, so the walk steps through that
    opcode to its argument and only then folds the assignment chain to the
    constant — which is the only thing that lets a setter on the same slot be
    found. Anything the fold does not settle answers ``None`` and the caller
    keeps ``indeterminate``."""
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
    """Full-names of the contract's functions whose bodies ``sstore`` the SAME
    slot variable. This is what separates a governor-settable split-proxy
    implementation from an unwritable one, on the assembly route where no
    ``StateVariable`` is ever written and the ordinary state-write facts see
    nothing."""
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
    """``(kind, writer signatures)`` for a resolved storage destination."""
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
    return ("storage_setter" if writers else "storage_no_setter"), writers


def _destination_operand(ir: Any) -> Any | None:
    """The operand carrying the delegatecall destination, for the three routes
    that produce a ``delegatecall`` sink."""
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
    """Every delegatecall destination reachable from ``unit``, resolved against
    the SUBJECT's symbols. ``bindings`` maps a formal parameter's id to the
    already-resolved caller-side root, which is what carries the library route's
    ``target`` back to this contract's ``module``."""
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
            # ``userModule[msg.sender]`` — an ELEMENT. Slither's
            # ``points_to_origin`` resolves it to the base mapping, and following
            # that would publish the mapping's mutability as the destination's:
            # one address, unredirectable, where in fact there is one per caller
            # and the caller sets their own. That is the worst over-claim
            # available on this field, so the element is where the walk stops.
            return {"target_kind": "indeterminate", "reason": "mapping_or_array_element"}
        root = _root_variable(operand, definitions)
        if root is UNDETERMINED or root is None:
            return {"target_kind": "indeterminate", "reason": "unresolved_operand"}
        bound = bindings.get(id(root))
        if bound is not None:
            root = bound
        if isinstance(root, StateVariable):
            kind, writers = _classify_state_variable(ctx, root)
            record: dict[str, Any] = {"target_kind": kind, "variable": str(getattr(root, "name", "") or "")}
            if writers:
                record["writer_signatures"] = writers
            return record
        if any(root is parameter for parameter in parameters) and not bindings:
            # A parameter of the SUBJECT's own entry point: the caller names the
            # code that runs in this contract's storage.
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
                        # A split-proxy dispatch: the destination is not a
                        # variable at all, it is whatever the slot holds, and
                        # whoever passes the setter's gate owns this contract's
                        # entire storage.
                        writers = _assembly_slot_writers(ctx, slot)
                        record = {
                            "target_kind": "storage_setter" if writers else "storage_no_setter",
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
    """Collapse the per-site destinations. Distinct resolved kinds fold to
    ``indeterminate`` with the members published — never to the most favourable
    one, and never to the first seen."""
    if not records:
        return {"target_kind": "indeterminate", "reason": "no_resolved_site"}
    kinds = sorted({record["target_kind"] for record in records})
    if len(kinds) == 1:
        return dict(records[0]) if len(records) == 1 else {**records[0], "sites": len(records)}
    return {"target_kind": "indeterminate", "reason": "sites_disagree", "site_kinds": kinds}


def _explained_by_upgrade(ctx: ClaimContext, function: str) -> bool:
    """True when this entry IS a standard upgrade, whose delegatecall sink is
    the upgrade mechanism rather than a separate capability.

    Mirrors the suppression ``project_effect_labels`` already applies to the
    ``delegatecall_execution`` LABEL: without it every UUPS ``upgradeToAndCall``
    — whose OZ implementation delegatecalls the new logic to run its initializer
    — would carry both claims and be counted twice by an exec consumer. The
    condition is read from the same facts the upgrade matcher gates on, because a
    matcher cannot see a sibling matcher's output."""
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
        # The A3/A4 verdict from day one: whether a mandatory revert gate pins a
        # caller-named destination is the same question here as on a value move.
        "destination_constraint": (
            _facts.param_constraint(
                ctx, function, _parameter_index(unit, destination.get("variable")), mode="external_call"
            )
            if destination.get("target_kind") == "param"
            else {"state": "not_determined"}
        ),
    }
    return ClaimEvidence(tier="idiom_structural", witness=witness)


def _parameter_index(unit: Any, name: Any) -> int | None:
    if unit is None or not isinstance(name, str) or not name:
        return None
    for index, parameter in enumerate(getattr(unit, "parameters", None) or []):
        if getattr(parameter, "name", None) == name:
            return index
    return None
