"""Controller tracking metadata for event-first, polling-backed monitoring: every state variable a predicate-tree
leaf references, with its writers from the effects artifact's state-write sinks.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Iterable, cast

from eth_utils.crypto import keccak

from schemas.contract_analysis import (
    AssociatedEvent,
    AssociatedEventInput,
    ControllerKind,
    ControllerProvenance,
    ControllerReadSpec,
    ControllerTrackingMode,
    ControllerTrackingTarget,
    ControllerTypeComponent,
    ControllerWriterFunction,
    EffectTags,
    Evidence,
    SemanticControlAnalysis,
)
from utils.scoring_status import OPENNESS_NOT_DETERMINED, OPENNESS_RESTRICTED

from .effects import _collect_reentrancy_guard_vars
from .mapping_events import member_witness_records
from .shared import (
    _contract_functions,
    _declaring_contract_name,
    _entry_points,
    _source_evidence,
    external_bool_leaf_is_gate_shape,
)
from .writer_openness import openness_of_write_paths, restricted_function_signatures


def _unit_key(unit) -> str:
    return (
        getattr(unit, "canonical_name", None)
        or getattr(unit, "full_name", None)
        or getattr(unit, "name", str(id(unit)))
    )


def _is_storage_layout_constant(name: str) -> bool:
    """True for ERC-7201/EIP-1967 slot-locator constants and ERC1967 ``__self``, which are never controllers: calling
    them reverts, and for OZ-v5 Ownable they shadowed the real owner. Real roles (``*_ROLE``) don't match.
    """
    if not name:
        return False
    if name == "__self":
        return True
    lowered = name.lower()
    return (
        lowered.endswith("storagelocation")
        or lowered.endswith("storageposition")
        or lowered.endswith("_slot")
        or lowered.endswith("_storage")
        or "initializable_storage" in lowered
    )


# OZ-v5 namespaced ownership roots, surfaced only through the slot constant (``<Name>StorageLocation``) and the internal
# accessor (``_get<Name>Storage()``), both of which revert; the canonical getter is ``owner()``. Only ownership roots:
# other namespaces aren't authorities, and the parametric AccessControl role-admin root is a per-role authority.
_OZ_V5_OWNERSHIP_SLOT_CONSTANTS = frozenset(
    {
        "OwnableStorageLocation",
        "AccessControlDefaultAdminRulesStorageLocation",
    }
)
_OZ_V5_OWNERSHIP_ACCESSORS = frozenset(
    {
        "_getOwnableStorage",
        "_getAccessControlDefaultAdminRulesStorage",
    }
)


def _oz_v5_ownership_getter_for_slot_constant(name: str | None) -> str | None:
    """``owner`` for an OZ-v5 ownership slot constant, else ``None``."""
    if isinstance(name, str) and name in _OZ_V5_OWNERSHIP_SLOT_CONSTANTS:
        return "owner"
    return None


def _oz_v5_ownership_getter_for_accessor(accessor: str | None) -> str | None:
    """``owner`` for an exact OZ-v5 ownership accessor name, else ``None``; other ``_get<X>Storage`` accessors are
    never rerouted.
    """
    if isinstance(accessor, str) and accessor in _OZ_V5_OWNERSHIP_ACCESSORS:
        return "owner"
    return None


def _abi_type(type_obj) -> str:
    """Canonical ABI type (see ``mapping_events._abi_type``).

    Feeds the event topic0 the watcher subscribes to, so every non-elementary type must collapse to its ABI head or the
    topic never fires.
    """
    if type_obj is None:
        return "unknown"
    from slither.core.declarations.contract import Contract
    from slither.core.declarations.enum import Enum
    from slither.core.declarations.structure import Structure
    from slither.core.solidity_types.array_type import ArrayType
    from slither.core.solidity_types.type_alias import TypeAlias
    from slither.core.solidity_types.user_defined_type import UserDefinedType

    if isinstance(type_obj, ArrayType):
        inner = _abi_type(getattr(type_obj, "type", None))
        length = getattr(type_obj, "length_value", None)
        if length is not None:
            return f"{inner}[{length}]"
        return f"{inner}[]"
    if isinstance(type_obj, TypeAlias):
        return _abi_type(getattr(type_obj, "underlying_type", None))
    if isinstance(type_obj, UserDefinedType):
        underlying = getattr(type_obj, "type", None)
        if isinstance(underlying, Contract):
            return "address"
        if isinstance(underlying, Enum):
            return "uint8"
        if isinstance(underlying, Structure):
            members = ",".join(
                _abi_type(getattr(elem, "type", None)) for elem in getattr(underlying, "elems_ordered", []) or []
            )
            return f"({members})"
    return str(type_obj)


def _type_kind(type_obj) -> str:
    if type_obj is None:
        return "unknown"

    type_name = type(type_obj).__name__
    if type_name == "ElementaryType":
        type_str = str(type_obj).lower()
        if type_str in {"address", "address payable"}:
            return "address"
        return "primitive"
    if type_name == "UserDefinedType":
        underlying = getattr(type_obj, "type", None)
        underlying_name = type(underlying).__name__
        if underlying_name == "Contract":
            return "contract"
        if underlying_name in {"Structure", "StructureContract"}:
            return "struct"
        if underlying_name in {"Enum", "EnumContract"}:
            return "enum"
        return "unknown"
    if type_name == "ArrayType":
        return "array"
    if type_name == "MappingType":
        return "mapping"
    return "unknown"


def _type_components(type_obj) -> list[ControllerTypeComponent]:
    if _type_kind(type_obj) != "struct":
        return []
    struct_decl = getattr(type_obj, "type", None)
    components: list[ControllerTypeComponent] = []
    for elem in getattr(struct_decl, "elems_ordered", []) or []:
        elem_type = getattr(elem, "type", None)
        components.append(
            {
                "name": getattr(elem, "name", "") or "",
                "type": str(elem_type) if elem_type is not None else "unknown",
                "abi_type": _abi_type(elem_type),
                "type_kind": _type_kind(elem_type),
            }
        )
    return components


def _event_signature(event_decl) -> str:
    arg_types = [_abi_type(getattr(elem, "type", None)) for elem in getattr(event_decl, "elems", [])]
    return f"{event_decl.name}({','.join(arg_types)})"


def _event_inputs(event_decl) -> list[AssociatedEventInput]:
    return [
        {
            "name": getattr(elem, "name", "") or "",
            "type": _abi_type(getattr(elem, "type", None)),
            "indexed": bool(getattr(elem, "indexed", False)),
        }
        for elem in getattr(event_decl, "elems", [])
    ]


def _event_reference(event_decl) -> AssociatedEvent:
    signature = _event_signature(event_decl)
    return {
        "name": event_decl.name,
        "signature": signature,
        "topic0": "0x" + keccak(text=signature).hex(),
        "inputs": _event_inputs(event_decl),
    }


def _event_index(contract) -> dict[str, list]:
    by_name: dict[str, list] = {}
    for current in [contract, *getattr(contract, "inheritance", [])]:
        events = getattr(current, "events", []) or getattr(current, "events_declared", [])
        for event_decl in events:
            by_name.setdefault(event_decl.name, []).append(event_decl)
    return by_name


def _ir_argument_types(arguments: Iterable) -> list[str]:
    return [_abi_type(getattr(argument, "type", None)) for argument in arguments]


def _resolve_event_refs(event_name: str, arguments: list, event_index: dict[str, list]) -> list[AssociatedEvent]:
    emitted_types = _ir_argument_types(arguments)
    matches = [
        event_decl
        for event_decl in event_index.get(event_name, [])
        if [_abi_type(getattr(elem, "type", None)) for elem in getattr(event_decl, "elems", [])] == emitted_types
    ]
    if not matches:
        matches = [
            event_decl
            for event_decl in event_index.get(event_name, [])
            if len(getattr(event_decl, "elems", []) or []) == len(arguments)
        ] or event_index.get(event_name, [])
    deduped: dict[str, AssociatedEvent] = {}
    for event_decl in matches:
        event_ref = _event_reference(event_decl)
        deduped[event_ref["signature"]] = event_ref
    return sorted(deduped.values(), key=lambda item: item["signature"])


def _collect_events(
    unit, project_dir: Path, event_index: dict[str, list], seen: set[str]
) -> list[tuple[AssociatedEvent, Evidence]]:
    key = _unit_key(unit)
    if key in seen:
        return []
    seen.add(key)

    events: list[tuple[AssociatedEvent, Evidence]] = []
    for node in getattr(unit, "nodes", []):
        for ir in getattr(node, "irs", []) or []:
            if type(ir).__name__ == "EventCall":
                event_name = getattr(ir, "name", None) or ""
                if event_name:
                    event_refs = _resolve_event_refs(event_name, list(getattr(ir, "arguments", []) or []), event_index)
                    evidence = _source_evidence(node, project_dir, detail=f"emit {event_name}")
                    events.extend((event_ref, evidence) for event_ref in event_refs)
            if type(ir).__name__ != "InternalCall":
                continue
            callee = getattr(ir, "function", None)
            if callee is None:
                continue
            events.extend(_collect_events(callee, project_dir, event_index, seen))
    return events


def _emitted_signatures(unit, event_index: dict[str, list], seen: set[str]) -> set[str]:
    """Event signatures ``unit`` can emit, following internal calls, without reading source like
    :func:`_collect_events`.
    """
    key = _unit_key(unit)
    if key in seen:
        return set()
    seen.add(key)
    signatures: set[str] = set()
    for node in getattr(unit, "nodes", []):
        for ir in getattr(node, "irs", []) or []:
            ir_kind = type(ir).__name__
            if ir_kind == "EventCall":
                # ``EventCall.name`` may be a ``Constant``.
                event_name = getattr(ir, "name", None)
                event_name = event_name if isinstance(event_name, str) else (str(event_name) if event_name else "")
                if event_name:
                    signatures.update(
                        ref["signature"]
                        for ref in _resolve_event_refs(
                            event_name, list(getattr(ir, "arguments", []) or []), event_index
                        )
                    )
            elif ir_kind == "InternalCall":
                callee = getattr(ir, "function", None)
                if callee is not None:
                    signatures |= _emitted_signatures(callee, event_index, seen)
    return signatures


def _entry_point_emitters(contract, event_index: dict[str, list]) -> dict[str, set[str]]:
    """Event signature -> entry points that can emit it: the restriction that matters is on the externally callable
    path.
    """
    out: dict[str, set[str]] = {}
    for function in _entry_points(contract):
        if getattr(function, "is_constructor", False):
            continue
        name = getattr(function, "full_name", getattr(function, "name", ""))
        if not name:
            continue
        for signature in _emitted_signatures(function, event_index, set()):
            out.setdefault(signature, set()).add(name)
    return out


class _EventQualification:
    """Precomputed per contract: an event may publish a mapping member change directly only when its args carry the
    written key (emit-write correspondence) and every emitter and every writer of the variable is proven
    caller-restricted. Otherwise occurrences are hints or activity.
    """

    def __init__(
        self,
        contract,
        event_index: dict[str, list],
        predicate_trees: Mapping[str, Any] | None,
        effects: Mapping[str, Any] | None,
    ) -> None:
        self._witness_by_pair = member_witness_records(contract)
        active = bool(self._witness_by_pair)
        self._emitters = _entry_point_emitters(contract, event_index) if active else {}
        self._restricted = restricted_function_signatures(predicate_trees) if active else frozenset()
        self._writers_by_var = _state_writers_from_effects(effects) if active else {}
        # Functions that write storage without attribution (assembly, delegatecall, library storage pointers) are
        # missing from the writer set, so if any survives subtracting the proven-restricted functions, qualification is
        # refused. Subtracting (rather than intersecting) keeps Solady's shape: its assembly writer is an internal
        # helper reached only from restricted entry points.
        opaque = (
            (
                _unattributable_write_functions(effects)
                | _library_storage_write_functions(contract)
                | _assembly_log_functions(contract)
            )
            if active
            else frozenset()
        )
        self._opaque_unrestricted = opaque - self._restricted

    def for_event(
        self,
        signature: str,
        target_vars: set[str],
        writers_by_signature: Mapping[str, set[str]],
    ) -> tuple[dict[str, Any] | None, str]:
        """``(member_witness, writer_openness)`` for one event.

        An emitter missing from *writers_by_signature* emits without writing, so openness is demoted.
        """
        witnesses = [
            record for var in sorted(target_vars) if (record := self._witness_by_pair.get((var, signature))) is not None
        ]
        if len(witnesses) != 1:
            # Zero witnesses: nothing proven. More than one: an occurrence doesn't say which mapping moved.
            return None, OPENNESS_NOT_DETERMINED
        witness = witnesses[0]
        emitters = self._emitters.get(signature) or set()
        if not emitters or any(not (writers_by_signature.get(fn) or set()) & target_vars for fn in emitters):
            return witness, OPENNESS_NOT_DETERMINED
        if self._opaque_unrestricted:
            # An open path can write storage unattributed, so no writer set is known complete.
            return witness, OPENNESS_NOT_DETERMINED
        mapping_var = witness["mapping_name"]
        writers = set(self._writers_by_var.get(mapping_var) or set())
        return witness, openness_of_write_paths(emitters, writers, self._restricted)


def _dedupe_event_refs(events: list[tuple[AssociatedEvent, Evidence]]) -> list[AssociatedEvent]:
    deduped: dict[str, AssociatedEvent] = {}
    for event_ref, _ in events:
        deduped[event_ref["signature"]] = event_ref
    return sorted(deduped.values(), key=lambda item: item["signature"])


def _functions_by_signature(contract) -> dict[str, object]:
    return {
        getattr(function, "full_name", getattr(function, "name", "")): function
        for function in _contract_functions(contract)
    }


def _walk_leaves(node: Any, callback) -> None:
    if not isinstance(node, dict):
        return
    if node.get("op") == "LEAF":
        leaf = node.get("leaf")
        if leaf is not None:
            callback(leaf)
        return
    for child in node.get("children") or []:
        _walk_leaves(child, callback)


def _collect_state_var_operands(predicate_trees: Mapping[str, Any] | None) -> set[str]:
    """Every state-variable operand any leaf surfaces (direct, set-descriptor storage var and keys, authority address
    source).
    """
    if not isinstance(predicate_trees, dict):
        return set()
    trees = predicate_trees.get("trees")
    if not isinstance(trees, dict):
        return set()

    state_vars: set[str] = set()

    def visit(leaf: dict[str, Any]) -> None:
        for operand in leaf.get("operands") or []:
            if isinstance(operand, dict) and operand.get("source") == "state_variable":
                name = operand.get("state_variable_name")
                if isinstance(name, str) and name:
                    state_vars.add(name)
        descriptor = leaf.get("set_descriptor") or {}
        if isinstance(descriptor, dict):
            storage_var = descriptor.get("storage_var")
            if isinstance(storage_var, str) and storage_var:
                state_vars.add(storage_var)
            authority = descriptor.get("authority_contract") or {}
            if isinstance(authority, dict):
                address_source = authority.get("address_source") or {}
                if isinstance(address_source, dict) and address_source.get("source") == "state_variable":
                    sv = address_source.get("state_variable_name")
                    if isinstance(sv, str) and sv:
                        state_vars.add(sv)
            for key_source in descriptor.get("key_sources") or []:
                if isinstance(key_source, dict) and key_source.get("source") == "state_variable":
                    sv = key_source.get("state_variable_name")
                    if isinstance(sv, str) and sv:
                        state_vars.add(sv)

    for tree in trees.values():
        _walk_leaves(tree, visit)
    return state_vars


# Roles that make an operand an access-control principal; otherwise business logic consults it.
_AUTHORITY_LEAF_ROLES = frozenset({"caller_authority", "delegated_authority"})


def _leaf_asserts_caller_gate(leaf: Mapping[str, Any]) -> bool:
    """An ``external_bool`` leaf contributes to ``caller_gate`` only for a gate-shaped callee.

    The classifier already enforces this; this guards drifted or hand-built trees (``vault.enter(msg.sender, ...)``).
    """
    if leaf.get("kind") != "external_bool":
        return True
    descriptor = leaf.get("set_descriptor")
    descriptor_signature = descriptor.get("callee_signature") if isinstance(descriptor, dict) else None
    return external_bool_leaf_is_gate_shape(
        leaf.get("callee_state_mutability"),
        leaf.get("gate_kind"),
        leaf.get("callee_signature") or descriptor_signature,
    )


def _collect_state_var_authority_roles(predicate_trees: Mapping[str, Any] | None) -> dict[str, set[str]]:
    """State-variable operand -> ``authority_role``s of leaves referencing it directly, to separate gated authorities
    from business reads.
    """
    if not isinstance(predicate_trees, dict):
        return {}
    trees = predicate_trees.get("trees")
    if not isinstance(trees, dict):
        return {}

    roles_by_var: dict[str, set[str]] = {}

    def visit(leaf: dict[str, Any]) -> None:
        role = leaf.get("authority_role")
        if not isinstance(role, str):
            return
        if role in _AUTHORITY_LEAF_ROLES and not _leaf_asserts_caller_gate(leaf):
            # A non-gate-shaped external call's operands aren't gated on (``vault.enter``'s wrapper token once made WETH
            # a controller).
            return
        for operand in leaf.get("operands") or []:
            if isinstance(operand, dict) and operand.get("source") == "state_variable":
                name = operand.get("state_variable_name")
                if isinstance(name, str) and name:
                    roles_by_var.setdefault(name, set()).add(role)

    for tree in trees.values():
        _walk_leaves(tree, visit)
    return roles_by_var


def _collect_state_var_member_operands(predicate_trees: Mapping[str, Any] | None) -> set[tuple[str, tuple[str, ...]]]:
    if not isinstance(predicate_trees, dict):
        return set()
    trees = predicate_trees.get("trees")
    if not isinstance(trees, dict):
        return set()

    refs: set[tuple[str, tuple[str, ...]]] = set()

    def visit(leaf: dict[str, Any]) -> None:
        for operand in leaf.get("operands") or []:
            if not isinstance(operand, dict) or operand.get("source") != "state_variable":
                continue
            name = operand.get("state_variable_name")
            member_path = operand.get("member_path")
            if isinstance(name, str) and name and isinstance(member_path, list) and member_path:
                path = tuple(part for part in member_path if isinstance(part, str) and part)
                if path:
                    refs.add((name, path))

    for tree in trees.values():
        _walk_leaves(tree, visit)
    return refs


def _collect_authority_state_vars(predicate_trees: Mapping[str, Any] | None) -> set[str]:
    """State variables named as a delegated authority's address source: external authority registries, promoted to
    ``external_contract``.
    """
    if not isinstance(predicate_trees, dict):
        return set()
    trees = predicate_trees.get("trees")
    if not isinstance(trees, dict):
        return set()

    authority_vars: set[str] = set()

    def visit(leaf: dict[str, Any]) -> None:
        # Only a leaf that proves an authority check may promote its descriptor's contract: the descriptor says where a
        # check would live, the role says one was proven.
        if leaf.get("authority_role") not in _AUTHORITY_LEAF_ROLES:
            return
        if not _leaf_asserts_caller_gate(leaf):
            return
        descriptor = leaf.get("set_descriptor") or {}
        if not isinstance(descriptor, dict):
            return
        authority = descriptor.get("authority_contract") or {}
        if not isinstance(authority, dict):
            return
        address_source = authority.get("address_source") or {}
        if isinstance(address_source, dict) and address_source.get("source") == "state_variable":
            sv = address_source.get("state_variable_name")
            if isinstance(sv, str) and sv:
                authority_vars.add(sv)

    for tree in trees.values():
        _walk_leaves(tree, visit)
    return authority_vars


# The caller is only observable through these (or helpers reading them), so a function reading neither can't gate on the
# caller.
_CALLER_IDENTITY_BUILTINS = frozenset({"msg.sender", "tx.origin"})


def _recursive_read(fn: Any, recursive_attr: str, direct_attr: str) -> set[str] | None:
    """Names read by ``fn``, its callees and modifiers (``onlyOwner`` lives in a Modifier), or ``None`` if the
    recursive accessor raised. The ``direct_attr`` fallback is only for objects without the accessor: substituting
    the narrower direct set after a failure would turn "couldn't read callees" into "callees read nothing" and
    mint ``call_target`` from a failure.
    """
    names: set[str] = set()
    for source in (fn, *(getattr(fn, "modifiers", None) or [])):
        accessor = getattr(source, recursive_attr, None)
        values: Any = None
        if callable(accessor):
            try:
                values = accessor()
            except Exception:
                return None
        if values is None:
            values = getattr(source, direct_attr, None)
        for variable in values or []:
            name = getattr(variable, "name", None)
            if isinstance(name, str) and name:
                names.add(name)
    return names


def _caller_gate_blind_spot_vars(contract: Any, predicate_trees: Mapping[str, Any] | None) -> set[str] | None:
    """State variables the caller-gate question was never answered for.

    ``call_target`` is minted from the absence of a lowered gate leaf, but a function whose gate couldn't be lowered has
    no tree. A blind-spot function is externally reachable, treeless and reads the caller; every state variable it reads
    is unanswered. Caller-blind functions are excluded on evidence.

    ``None`` when the surface couldn't be read (entry points not enumerable, or an accessor raised): an incomplete blind
    spot looks like a small one. Neither route occurs on real compiled contracts; tests construct both.
    """
    entry_points = getattr(contract, "functions_entry_points", None)
    if entry_points is None:
        return None
    trees = predicate_trees.get("trees") if isinstance(predicate_trees, dict) else None
    lowered = set(trees) if isinstance(trees, dict) else set()

    blind: set[str] = set()
    by_full_name: dict[str, Any] = {}
    for fn in entry_points:
        full_name = getattr(fn, "full_name", None)
        if isinstance(full_name, str):
            by_full_name.setdefault(full_name, fn)
        if getattr(fn, "visibility", None) not in ("external", "public"):
            continue
        if getattr(fn, "is_constructor", False) or (getattr(fn, "name", "") or "") == "constructor":
            continue
        if full_name in lowered:
            continue
        solidity_read = _recursive_read(fn, "all_solidity_variables_read", "solidity_variables_read")
        if solidity_read is None:
            # Unknown whether it observes the caller.
            return None
        if not (solidity_read & _CALLER_IDENTITY_BUILTINS):
            continue
        state_read = _recursive_read(fn, "all_state_variables_read", "state_variables_read")
        if state_read is None:
            return None
        blind |= state_read

    # Treeless and caller-reading by construction, so already covered; unioned to keep the dependency visible.
    uncertain = predicate_trees.get("guard_extraction_uncertain") if isinstance(predicate_trees, dict) else None
    for full_name in uncertain or []:
        fn = by_full_name.get(full_name) if isinstance(full_name, str) else None
        if fn is not None:
            state_read = _recursive_read(fn, "all_state_variables_read", "state_variables_read")
            if state_read is None:
                return None
            blind |= state_read
    return blind


def _collect_external_contract_state_vars_from_effects(
    effects: Mapping[str, Any] | None,
    state_var_names: set[str],
) -> set[str]:
    """State variables used as external-call destinations (``authority.check(...)``), from effects sinks whose target
    prefix is a real state var (so ``msg.sender.transfer`` doesn't match).
    """
    if not isinstance(effects, dict):
        return set()
    out: set[str] = set()
    for info in (effects.get("functions") or {}).values():
        if not isinstance(info, dict):
            continue
        for sink in info.get("sinks") or []:
            if not isinstance(sink, dict):
                continue
            if sink.get("kind") != "external_call":
                continue
            target = sink.get("target")
            if not isinstance(target, str) or "." not in target:
                continue
            prefix = target.split(".", 1)[0]
            if prefix in state_var_names:
                out.add(prefix)
    return out


def _effect_tags_for_signature(
    function_signature: str,
    effects: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """One emitter's sinks as ``{writes, delegates}``; the watcher unions these across an event's emitters."""
    out: dict[str, Any] = {"writes": set(), "delegates": False}
    if not isinstance(effects, dict):
        return out
    info = (effects.get("functions") or {}).get(function_signature)
    if not isinstance(info, dict):
        return out
    for sink in info.get("sinks") or []:
        if not isinstance(sink, dict):
            continue
        kind = sink.get("kind")
        if kind == "state_write":
            target = sink.get("target")
            if isinstance(target, str) and target:
                out["writes"].add(target)
        elif kind == "delegatecall":
            out["delegates"] = True
    return out


def _function_is_initializer(function: Any) -> bool:
    """OZ Initializable (``initializer``/``reinitializer`` modifier), used to tag ``Initialized`` so unexpected
    re-inits trigger reanalysis.
    """
    for modifier in getattr(function, "modifiers", []) or []:
        name = getattr(modifier, "name", "") or ""
        if name in ("initializer", "reinitializer", "onlyInitializing"):
            return True
    return False


def _unattributable_write_functions(effects: Mapping[str, Any] | None) -> frozenset[str]:
    """Functions whose storage writes attribution can't see: inline assembly reaching storage (recorded against a
    slot, never a name) and ``delegatecall``. They are missing from writer sets, so never intersect with them.
    """
    if not isinstance(effects, dict):
        return frozenset()
    out: set[str] = set()
    for fn_sig, info in (effects.get("functions") or {}).items():
        if not isinstance(fn_sig, str) or not isinstance(info, dict):
            continue
        if info.get("assembly_state_access"):
            out.add(fn_sig)
            continue
        if any(isinstance(sink, dict) and sink.get("kind") == "delegatecall" for sink in info.get("sinks") or []):
            out.add(fn_sig)
    return frozenset(out)


def _library_storage_write_functions(contract) -> frozenset[str]:
    """Entry points reaching a library function that takes a storage pointer (``MarkLib.put(libMap, user)``), which
    Slither attributes to no one. Libraries without storage parameters (``SafeERC20``, ``Math``) are unaffected.
    """
    out: set[str] = set()
    for function in _entry_points(contract):
        name = getattr(function, "full_name", getattr(function, "name", ""))
        if not name:
            continue
        accessor = getattr(function, "all_library_calls", None)
        if not callable(accessor):
            continue
        calls: list[Any] = []
        try:
            found: Any = accessor()
            calls = list(found) if found else []
        except Exception:
            # Unanswered isn't proof it writes nothing.
            out.add(name)
            continue
        for call in calls:
            callee = getattr(call, "function", None)
            if any(getattr(p, "location", None) == "storage" for p in getattr(callee, "parameters", None) or []):
                out.add(name)
                break
    return frozenset(out)


# An assembly LOG can forge any topic0 with no ``EventCall`` IR and no write, invisible to both openness quantifiers, so
# it is opaque on its own.
_ASSEMBLY_LOG_OPCODE = re.compile(r"\blog[0-4]\b")


def _assembly_reaches_log(unit, seen: set[str]) -> bool:
    """Whether ``unit`` or its callees can emit a log from assembly (unreadable assembly counts).

    Per opcode, not ``contains_assembly``: modern contracts use assembly constantly for storage and errors.
    """
    # Lazy, to keep the module importable without Slither side effects.
    from slither.core.cfg.node import NodeType

    key = _unit_key(unit)
    if key in seen:
        return False
    seen.add(key)
    for node in getattr(unit, "nodes", []) or []:
        if getattr(node, "type", None) == NodeType.ASSEMBLY or getattr(node, "inline_asm", None) is not None:
            source_mapping = getattr(node, "source_mapping", None)
            content = getattr(source_mapping, "content", None)
            if not isinstance(content, str) or not content:
                return True
            if _ASSEMBLY_LOG_OPCODE.search(content):
                return True
        for ir in getattr(node, "irs", []) or []:
            if type(ir).__name__ != "InternalCall":
                continue
            callee = getattr(ir, "function", None)
            if callee is not None and _assembly_reaches_log(callee, seen):
                return True
    return False


def _assembly_log_functions(contract) -> frozenset[str]:
    out: set[str] = set()
    for function in _entry_points(contract):
        name = getattr(function, "full_name", getattr(function, "name", ""))
        if not name:
            continue
        try:
            if _assembly_reaches_log(function, set()):
                out.add(name)
        except Exception:
            out.add(name)
    return frozenset(out)


def _state_writers_from_effects(
    effects: Mapping[str, Any] | None,
) -> dict[str, set[str]]:
    """State variable -> signatures writing it, from state-write sinks (constructors excluded)."""
    if not isinstance(effects, dict):
        return {}
    by_var: dict[str, set[str]] = {}
    for fn_sig, info in (effects.get("functions") or {}).items():
        if not isinstance(fn_sig, str) or fn_sig.startswith("constructor("):
            continue
        if not isinstance(info, dict):
            continue
        for sink in info.get("sinks") or []:
            if not isinstance(sink, dict):
                continue
            if sink.get("kind") != "state_write":
                continue
            target = sink.get("target")
            if isinstance(target, str) and target:
                by_var.setdefault(target, set()).add(fn_sig)
    return by_var


# A reentrancy latch every ``nonReentrant`` function writes and restores; donating its writers enrolled every event
# under a slot that never changes across a transaction.
_TRANSIENT_HYGIENE_CLASS = "reentrancy_guard"

# A write by a modifier; the set-and-restore proof is about the modifier.
_GUARD_WRITE_ORIGIN = "guard"


def _write_facts_by_signature(effects: Mapping[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    """Signature -> its ``state_writes`` facts. Absent signatures are not determined; callers keep those writers."""
    out: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(effects, dict):
        return out
    for fn_sig, info in (effects.get("functions") or {}).items():
        if not isinstance(fn_sig, str) or not isinstance(info, dict):
            continue
        facts = info.get("state_writes")
        if isinstance(facts, list):
            out[fn_sig] = [fact for fact in facts if isinstance(fact, dict)]
    return out


def _writer_survives_hygiene(
    facts: list[dict[str, Any]] | None,
    var: str,
    member_path: tuple[str, ...] | None,
    transient_vars: frozenset[str] = frozenset(),
) -> bool:
    """Whether this function writes *var* (at *member_path*) in a way worth watching. Exclusions need proof:

    * every write here is the transient-latch class, *var* is an IR-proven guard, and the write comes from the guard
    modifier (``origin == "guard"``). The class has a name fallback and is variable-granular, so without all three a
    body ``onlyOwner setStatus`` write would drop a real controller;
    * a member-scoped controller whose writes here all land on other members. Var-granular writes are kept.

    No facts keeps the writer.
    """
    if facts is None:
        return True
    for_var = [fact for fact in facts if fact.get("var") == var]
    if not for_var:
        return True
    if var in transient_vars and all(
        fact.get("hygiene_class") == _TRANSIENT_HYGIENE_CLASS and fact.get("origin") == _GUARD_WRITE_ORIGIN
        for fact in for_var
    ):
        return False
    if member_path:
        wanted = list(member_path)
        return any(not fact.get("member_path") or fact.get("member_path") == wanted for fact in for_var)
    return True


def _writer_records_from_effects(
    contract,
    project_dir: Path,
    target_state_vars: Iterable[str],
    event_lookup: dict[str, list],
    effects: Mapping[str, Any] | None,
    qualification: "_EventQualification | None" = None,
    member_path: tuple[str, ...] | None = None,
) -> tuple[list[ControllerWriterFunction], list[AssociatedEvent]]:
    """``ControllerWriterFunction`` records for targets from effects.

    *qualification* stamps member-witness/openness facts onto events (absent means not determined); *member_path*
    narrows to writers that can reach the member.
    """
    target_set = {var for var in target_state_vars if var}
    if not target_set:
        return [], []
    writers_by_var = _state_writers_from_effects(effects)
    facts_by_signature = _write_facts_by_signature(effects)
    # IR-proven guards, cached per contract.
    transient_vars = _collect_reentrancy_guard_vars(contract)
    writes_by_signature: dict[str, set[str]] = {}
    for var in target_set:
        for signature in writers_by_var.get(var, set()):
            if not _writer_survives_hygiene(facts_by_signature.get(signature), var, member_path, transient_vars):
                continue
            writes_by_signature.setdefault(signature, set()).add(var)

    functions_by_signature = _functions_by_signature(contract)
    writer_functions: list[ControllerWriterFunction] = []
    aggregated_events: dict[str, AssociatedEvent] = {}
    # Union of effects across an event's emitters; classification comes from this aggregate, not the name.
    tags_by_event_sig: dict[str, dict[str, Any]] = {}
    for signature in sorted(writes_by_signature):
        function = functions_by_signature.get(signature)
        if function is None:
            continue
        writes = sorted(writes_by_signature[signature])
        event_records = _collect_events(function, project_dir, event_lookup, set())
        event_refs = _dedupe_event_refs(event_records)
        fn_tags = _effect_tags_for_signature(signature, effects)
        fn_is_initializer = _function_is_initializer(function)
        for event_ref in event_refs:
            sig = event_ref["signature"]
            agg = tags_by_event_sig.setdefault(
                sig,
                {"writes": set(), "delegates": False, "is_initializer": False},
            )
            agg["writes"].update(fn_tags.get("writes") or set())
            if fn_tags.get("delegates"):
                agg["delegates"] = True
            if fn_is_initializer:
                agg["is_initializer"] = True
            aggregated_events[sig] = event_ref
        writer_functions.append(
            {
                "contract": _declaring_contract_name(function, contract.name),
                "function": signature,
                "visibility": getattr(function, "visibility", "unknown"),
                "writes": writes,
                "associated_events": event_refs,
                "evidence": [
                    _source_evidence(
                        function,
                        project_dir,
                        detail=f"writes tracked state {', '.join(writes)}",
                    )
                ],
            }
        )

    # Same tags on the flat event list and on each writer function.
    for sig, agg in tags_by_event_sig.items():
        tags: EffectTags = {}
        if agg["writes"]:
            tags["writes"] = sorted(agg["writes"])
        if agg["delegates"]:
            tags["delegates"] = True
        if agg["is_initializer"]:
            tags["is_initializer"] = True
        if not tags:
            continue
        target_event = aggregated_events.get(sig)
        if target_event is not None:
            target_event["effect_tags"] = tags
        for wf in writer_functions:
            for ev in wf["associated_events"]:
                if ev["signature"] == sig and "effect_tags" not in ev:
                    ev["effect_tags"] = tags

    if qualification is not None:
        for sig, event_ref in aggregated_events.items():
            member_witness, openness = qualification.for_event(sig, target_set, writes_by_signature)
            if member_witness is not None:
                event_ref["member_witness"] = member_witness
            # Only the proven value is written; absent is not determined.
            if openness == OPENNESS_RESTRICTED:
                event_ref["writer_openness"] = openness

    associated_events = sorted(aggregated_events.values(), key=lambda item: item["signature"])
    return writer_functions, associated_events


def _build_getter_index(contract) -> dict[str, str]:
    """Private state var -> its public getter (a view/pure function whose body is ``return <var>;``)."""
    out: dict[str, str] = {}
    for fn in getattr(contract, "functions", []) or []:
        visibility = getattr(fn, "visibility", None)
        if visibility not in ("public", "external"):
            continue
        if getattr(fn, "view", False) is False and getattr(fn, "pure", False) is False:
            continue
        if getattr(fn, "parameters", None):
            continue
        return_vars = list(getattr(fn, "returns", []) or [])
        if not return_vars:
            continue
        for node in getattr(fn, "nodes", []) or []:
            expr = getattr(node, "expression", None)
            text = str(expr) if expr is not None else ""
            if not text:
                continue
            for sv in getattr(contract, "state_variables_ordered", []) or []:
                if sv.name and text.strip() == sv.name:
                    out.setdefault(sv.name, fn.name)
                    break
    return out


def _component_for_member_path(
    components: list[ControllerTypeComponent],
    member_path: tuple[str, ...] | None,
) -> ControllerTypeComponent | None:
    if not member_path or len(member_path) != 1:
        return None
    return next((component for component in components if component["name"] == member_path[0]), None)


def _state_var_read_spec(
    name: str,
    state_vars_by_name: dict[str, Any],
    getter_by_var: dict[str, str],
    member_path: tuple[str, ...] | None = None,
) -> ControllerReadSpec:
    """Read spec for a state-var controller: a public var reads its auto-getter; a private var with a discovered
    getter reads that; one without is ``strategy=unknown`` (not readable by any call). The monitoring plane skips
    those; resolution still probes and records the revert. Type fields stay populated for shape guards.
    """
    sv = state_vars_by_name.get(name)
    type_obj = getattr(sv, "type", None) if sv is not None else None
    type_str = str(type_obj) if type_obj is not None else ""
    is_public = bool(getattr(sv, "visibility", None) == "public") if sv is not None else False
    getter_name = name if is_public else getter_by_var.get(name)
    components = _type_components(type_obj)
    projected_component = _component_for_member_path(components, member_path)
    spec: ControllerReadSpec = cast(
        ControllerReadSpec,
        {
            "strategy": "getter_call" if getter_name else "unknown",
            "target": getter_name or name,
            "kind": "state_variable",
            "state_variable_name": name,
            "type": projected_component["type"] if projected_component is not None else type_str,
            "type_kind": projected_component["type_kind"] if projected_component is not None else _type_kind(type_obj),
        },
    )
    if projected_component is not None:
        spec["parent_type"] = type_str
    if member_path:
        spec["member_path"] = list(member_path)
    if components:
        spec["components"] = components
    return spec


# OZ-v5 accessors make non-owner setters look like slot writers, so the owner controller's writers and events are
# narrowed to ``OwnershipTransferred`` emitters (like the v4 ``_owner`` controller).
_OWNERSHIP_TRANSFERRED_SIGNATURE = "OwnershipTransferred(address,address)"


def _emit_oz_v5_owner_target(
    tracking_targets: list[ControllerTrackingTarget],
    seen_ids: set[str],
    getter: str,
    slot_constant: str,
    contract,
    project_dir: Path,
    event_lookup: dict[str, list],
    effects: Mapping[str, Any] | None,
    qualification: "_EventQualification | None" = None,
) -> None:
    """Append one canonical OZ-v5 owner controller read through ``owner()``, keyed on the slot constant for writer
    discovery and narrowed to ``OwnershipTransferred`` emitters.
    """
    controller_id = f"state_variable:{getter}"
    if controller_id in seen_ids:
        return
    read_spec: ControllerReadSpec = cast(
        ControllerReadSpec,
        {
            "strategy": "getter_call",
            "target": getter,
            "kind": "state_variable",
            "state_variable_name": getter,
            "type": "address",
            "type_kind": "address",
        },
    )
    all_writers, all_events = _writer_records_from_effects(
        contract,
        project_dir,
        [slot_constant],
        event_lookup,
        effects,
        qualification,
    )
    writer_functions = [
        wf
        for wf in all_writers
        if any(ev.get("signature") == _OWNERSHIP_TRANSFERRED_SIGNATURE for ev in wf.get("associated_events") or [])
    ]
    associated_events = [ev for ev in all_events if ev.get("signature") == _OWNERSHIP_TRANSFERRED_SIGNATURE]
    if associated_events:
        tracking_mode = "event_plus_state"
        notes = [
            "Monitor associated events for low-latency detection and confirm "
            "the resulting controller state with RPC reads."
        ]
    else:
        tracking_mode = "state_only"
        notes = [
            "No deterministically associated post-deploy events were found "
            "for this controller state; rely on periodic RPC reads and "
            "reconciliation."
        ]
    tracking_targets.append(
        {
            "controller_id": controller_id,
            "label": getter,
            "source": getter,
            "kind": "state_variable",
            "read_spec": read_spec,
            "confidence": None,
            "tracking_mode": tracking_mode,
            "writer_functions": writer_functions,
            "associated_events": associated_events,
            "polling_sources": [getter],
            "notes": notes,
        }
    )
    seen_ids.add(controller_id)


def build_controller_tracking(
    contract,
    project_dir: Path,
    predicate_trees: Mapping[str, Any] | None,
    effects: Mapping[str, Any] | None,
    semantic_control: SemanticControlAnalysis | None = None,
) -> list[ControllerTrackingTarget]:
    """Event-first tracking metadata from predicate trees (every referenced state variable becomes a target), effects
    (writer functions per target) and ``semantic_control`` (role definitions).
    """
    event_lookup = _event_index(contract)
    qualification = _EventQualification(contract, event_lookup, predicate_trees, effects)
    state_vars_by_name = {sv.name: sv for sv in getattr(contract, "state_variables_ordered", [])}
    getter_by_var = _build_getter_index(contract)

    referenced_state_vars = _collect_state_var_operands(predicate_trees)
    referenced_member_paths = _collect_state_var_member_operands(predicate_trees)
    authority_roles_by_var = _collect_state_var_authority_roles(predicate_trees)
    external_contract_vars_from_effects = _collect_external_contract_state_vars_from_effects(
        effects,
        set(state_vars_by_name.keys()),
    )
    # "Holds another contract's address" (``kind``): delegated authority sources plus effects external-call targets. Not
    # an authority claim; any callee qualifies.
    delegated_authority_vars = _collect_authority_state_vars(predicate_trees)
    authority_state_vars = delegated_authority_vars | external_contract_vars_from_effects
    # "Gates the caller", kept separate so rows record provenance (``ControllerProvenance``).
    caller_gate_vars = delegated_authority_vars | {
        name for name, roles in authority_roles_by_var.items() if roles & _AUTHORITY_LEAF_ROLES
    }

    # ``caller_gate`` comes only from trees. With no trees (``core`` substitutes an error stub on builder failure, or a
    # successful build with no lowered leaf), neither question was answered, so every name is not determined rather than
    # a proven ``call_target``.
    predicate_trees_available = (
        isinstance(predicate_trees, dict)
        and isinstance(predicate_trees.get("trees"), dict)
        and bool(predicate_trees["trees"])
    )

    # Functions with no lowered tree hide their gates; see ``_caller_gate_blind_spot_vars``.
    gate_blind_spot_vars = (
        _caller_gate_blind_spot_vars(contract, predicate_trees) if predicate_trees_available else None
    )

    def _provenance_for(name: str) -> ControllerProvenance | None:
        if not predicate_trees_available:
            return None
        if name in caller_gate_vars:
            # Proven present; a blind spot elsewhere can't subtract evidence.
            return "caller_gate"
        if gate_blind_spot_vars is None or name in gate_blind_spot_vars:
            return None
        if name in external_contract_vars_from_effects:
            return "call_target"
        return None

    # So effects-only external contracts (``hook`` set by ``setHook`` and called ungated) still get a target.
    referenced_state_vars |= external_contract_vars_from_effects
    role_definitions = list(semantic_control.get("role_definitions", []) if semantic_control else [])

    tracking_targets: list[ControllerTrackingTarget] = []
    seen_ids: set[str] = set()

    # Pass 1: role identifiers from ``role_definitions``, skipping names that are also authority-registry state vars
    # (Pass 2 covers those with writers and events).
    for role_def in role_definitions:
        role_name = role_def.get("role")
        if not role_name:
            continue
        if role_name in authority_state_vars:
            continue
        # Slot-locator constants reach role definitions as bytes32 caller-authority operands but aren't roles (their
        # getter always reverts); same suppression as Pass 2.
        if _is_storage_layout_constant(role_name):
            # An OZ-v5 ownership slot backs a real owner: emit the canonical owner controller read through ``owner()``,
            # keyed on the slot for writers and events.
            getter = _oz_v5_ownership_getter_for_slot_constant(role_name)
            if getter is not None:
                _emit_oz_v5_owner_target(
                    tracking_targets,
                    seen_ids,
                    getter,
                    role_name,
                    contract,
                    project_dir,
                    event_lookup,
                    effects,
                    qualification,
                )
            continue
        controller_id = f"role_identifier:{role_name}"
        if controller_id in seen_ids:
            continue
        read_spec: ControllerReadSpec = {"strategy": "getter_call", "target": role_name}
        tracking_targets.append(
            {
                "controller_id": controller_id,
                "label": role_name,
                "source": role_name,
                "kind": "role_identifier",
                "read_spec": read_spec,
                "confidence": None,
                "tracking_mode": "state_only",
                "writer_functions": [],
                "associated_events": [],
                "polling_sources": [role_name],
                "notes": [
                    "Resolve the role identifier via eth_call and expand current "
                    "members through the authority adapter when supported."
                ],
            }
        )
        seen_ids.add(controller_id)

    role_def_names = {
        role_def.get("role")
        for role_def in role_definitions
        if role_def.get("role") and role_def.get("role") not in authority_state_vars
    }

    # Pass 2: every leaf-referenced state variable; registry vars become ``external_contract``, others
    # ``state_variable``, and referenced bytes32 constants become role identifiers.
    for name in sorted(referenced_state_vars):
        if name in role_def_names:
            continue
        if _is_storage_layout_constant(name):
            continue
        sv = state_vars_by_name.get(name)
        is_bytes32_constant = (
            sv is not None and str(getattr(sv, "type", "")) == "bytes32" and bool(getattr(sv, "is_constant", False))
        )
        is_role = is_bytes32_constant
        if is_role:
            controller_id = f"role_identifier:{name}"
            if controller_id in seen_ids:
                continue
            read_spec_role: ControllerReadSpec = {"strategy": "getter_call", "target": name}
            tracking_targets.append(
                {
                    "controller_id": controller_id,
                    "label": name,
                    "source": name,
                    "kind": "role_identifier",
                    "read_spec": read_spec_role,
                    "confidence": None,
                    "tracking_mode": "state_only",
                    "writer_functions": [],
                    "associated_events": [],
                    "polling_sources": [name],
                    "notes": [
                        "Resolve the role identifier via eth_call and expand current "
                        "members through the authority adapter when supported."
                    ],
                }
            )
            seen_ids.add(controller_id)
            continue

        kind: ControllerKind = "external_contract" if name in authority_state_vars else "state_variable"
        controller_id = f"{kind}:{name}"
        if controller_id in seen_ids:
            continue
        read_spec_var = _state_var_read_spec(name, state_vars_by_name, getter_by_var)

        # A whole struct has no single address value (member paths are projected separately).
        if kind == "state_variable" and read_spec_var.get("type_kind") == "struct":
            continue

        # A compile-time constant address only consulted by business logic is a sentinel, not an authority.
        if (
            kind == "state_variable"
            and read_spec_var.get("type_kind") in {"address", "contract"}
            and bool(getattr(sv, "is_constant", False))
            and not (authority_roles_by_var.get(name, set()) & _AUTHORITY_LEAF_ROLES)
        ):
            continue

        writer_functions, associated_events = _writer_records_from_effects(
            contract,
            project_dir,
            [name],
            event_lookup,
            effects,
            qualification,
        )
        if associated_events:
            tracking_mode: ControllerTrackingMode = "event_plus_state"
            notes = [
                "Monitor associated events for low-latency detection and confirm "
                "the resulting controller state with RPC reads."
            ]
        else:
            tracking_mode = "state_only"
            notes = [
                "No deterministically associated post-deploy events were found "
                "for this controller state; rely on periodic RPC reads and "
                "reconciliation."
            ]
            if not writer_functions:
                notes.append(
                    "No post-deploy writer functions were found from static "
                    "analysis; continue polling the current value and reanalyze "
                    "on implementation changes."
                )

        target: ControllerTrackingTarget = {
            "controller_id": controller_id,
            "label": name,
            "source": name,
            "kind": kind,
            "read_spec": read_spec_var,
            "confidence": None,
            "tracking_mode": tracking_mode,
            "writer_functions": writer_functions,
            "associated_events": associated_events,
            "polling_sources": [name],
            "notes": notes,
        }
        provenance = _provenance_for(name)
        # Absent (not None) when neither question was answered.
        if provenance is not None:
            target["authority_provenance"] = provenance
        tracking_targets.append(target)
        seen_ids.add(controller_id)

    for name, member_path in sorted(referenced_member_paths):
        if name in role_def_names:
            continue
        if _is_storage_layout_constant(name):
            continue
        label = f"{name}.{'.'.join(member_path)}"
        controller_id = f"state_variable:{label}"
        if controller_id in seen_ids:
            continue
        read_spec_member = _state_var_read_spec(name, state_vars_by_name, getter_by_var, member_path)
        if read_spec_member.get("type_kind") not in {"address", "contract"}:
            continue
        writer_functions, associated_events = _writer_records_from_effects(
            contract,
            project_dir,
            [name],
            event_lookup,
            effects,
            qualification,
            member_path,
        )
        tracking_mode = "event_plus_state" if associated_events else "state_only"
        notes = [
            "Read the projected struct field through its parent getter and "
            "treat only that address field as controller state."
        ]
        tracking_targets.append(
            {
                "controller_id": controller_id,
                "label": label,
                "source": label,
                "kind": "state_variable",
                "read_spec": read_spec_member,
                "confidence": None,
                "tracking_mode": tracking_mode,
                "writer_functions": writer_functions,
                "associated_events": associated_events,
                "polling_sources": [name],
                "notes": notes,
            }
        )
        seen_ids.add(controller_id)

    return sorted(tracking_targets, key=lambda item: item["label"])
