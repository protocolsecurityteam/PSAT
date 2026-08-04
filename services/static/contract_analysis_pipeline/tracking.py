"""Deterministic controller tracking metadata for event-first, polling-backed monitoring.

``build_controller_tracking`` sources inputs from semantic
``predicate_trees`` and ``effects`` artifacts. The walker enumerates every
state-variable operand referenced by any predicate-tree leaf, then pulls
writers from ``effects.functions`` state_write sinks.
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
    ControllerProvenance,
    ControllerReadSpec,
    ControllerTrackingTarget,
    ControllerTypeComponent,
    ControllerWriterFunction,
    EffectTags,
    Evidence,
    SemanticControlAnalysis,
)

from .effects import _collect_reentrancy_guard_vars
from .mapping_events import member_witness_records
from .shared import (
    _contract_functions,
    _declaring_contract_name,
    _entry_points,
    _source_evidence,
    external_bool_leaf_is_gate_shape,
)
from .writer_openness import (
    WRITER_OPENNESS_NOT_DETERMINED,
    WRITER_OPENNESS_RESTRICTED,
    openness_of_write_paths,
    restricted_function_signatures,
)


def _unit_key(unit) -> str:
    return (
        getattr(unit, "canonical_name", None)
        or getattr(unit, "full_name", None)
        or getattr(unit, "name", str(id(unit)))
    )


def _is_storage_layout_constant(name: str) -> bool:
    """True for ERC-7201 / EIP-1967 storage-layout pointer constants and the
    ERC1967 ``__self`` immutable — slot locators that are never controllers.

    Emitting them as ``role_identifier`` / ``state_variable`` targets produced
    dead ``eth_call_error`` rows (calling ``OwnableStorageLocation()`` etc.
    reverts) and, for OZ-v5 Ownable, shadowed the real owner. Standard-aware
    resolution reads the canonical getter (``owner()``) or role events instead.
    Real AccessControl roles (``*_ROLE``, ``DEFAULT_ADMIN_ROLE``) and ordinary
    address state vars do not match these suffixes.
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


# OZ-v5 ERC-7201 namespaced-storage OWNERSHIP roots. The owner lives in a
# namespaced struct rather than a plain ``_owner`` state var, so the compiler
# surfaces it only through two suppressed identifiers — the slot-locator constant
# (``<Name>StorageLocation``, a state_variable / role operand) and the internal
# storage accessor (``_get<Name>Storage()``, a view_call operand) — both of which
# revert when called directly. Each denotes the same root whose canonical public
# getter is ``owner()``. Scoped to the ownership roots only: Reentrancy / Pausable
# / OAppCore / EIP712 namespaces are not authorities, and the PARAMETRIC
# AccessControl role-admin root (``_getAccessControlStorage`` /
# ``getRoleAdmin(role)``) is a different, per-role authority — neither is the
# OZ-v5 owner and both stay out.
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
    """Canonical authority getter name for an OZ-v5 namespaced-storage ownership
    slot constant (``OwnableStorageLocation`` /
    ``AccessControlDefaultAdminRulesStorageLocation`` → ``owner``), or ``None``.

    The returned name is the live public getter, never the dead slot constant."""
    if isinstance(name, str) and name in _OZ_V5_OWNERSHIP_SLOT_CONSTANTS:
        return "owner"
    return None


def _oz_v5_ownership_getter_for_accessor(accessor: str | None) -> str | None:
    """Canonical authority getter name for an OZ-v5 namespaced-storage ownership
    internal accessor (``_getAccessControlDefaultAdminRulesStorage`` /
    ``_getOwnableStorage`` → ``owner``), matched by EXACT name, or ``None``.

    Anchored to the known ownership accessors so an arbitrary ``_get<X>Storage``
    (``_getL1BaseSyncPoolStorage``, the parametric ``_getAccessControlStorage``
    role-admin root) is never rerouted to ``owner()``."""
    if isinstance(accessor, str) and accessor in _OZ_V5_OWNERSHIP_ACCESSORS:
        return "owner"
    return None


def _abi_type(type_obj) -> str:
    """Canonical ABI type string (recursive); see ``mapping_events._abi_type``.

    Feeds both the ``inputs`` metadata and, via ``_event_signature``, the event
    ``topic0`` that the runtime watch plan subscribes to. Must collapse every
    non-elementary type to its canonical ABI head (contract/interface->address,
    enum->uint8, UDVT->underlying, array->canonical(elem)+suffix,
    struct->parenthesized member tuple) or the watcher subscribes to a topic0
    that never fires.
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
    """Event signatures *unit* can emit, following internal calls.

    The evidence-free twin of :func:`_collect_events`: it answers "which
    externally-callable paths reach this emit" without reading source lines for
    every function on the contract, which is the only reason it exists
    separately.
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
                # Slither types ``EventCall.name`` as ``str | Constant``; coerce
                # for the same reason ``mapping_events`` does.
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
    """Event signature → the ``full_name`` of every entry point that can emit it.

    Entry points, not all functions: an internal helper is only reachable
    through one, so the caller restriction that governs an emit is the one on
    the externally-callable path that leads there.
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
    """F3's two facts, precomputed once per contract.

    An event qualifies to publish a mapping member change directly when BOTH
    hold: its args carry the written entry's key (emit-write correspondence,
    from ``mapping_events``), and every path that can change the mapping — every
    emitter of the event AND every writer of the variable — is proven to
    restrict its caller. Either fact missing leaves the event unqualified, and
    the monitoring plane then treats an occurrence as a hint or as bare
    activity, never as a change claim.
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
        # Functions that can write storage this analysis cannot attribute to a
        # variable — inline assembly, delegatecall, a library call through a
        # storage pointer. Each is MISSING from the mapping's writer set, so the
        # quantifier over that set says nothing about them. What is left after
        # subtracting the proven-restricted functions is the open surface: if it
        # is non-empty, "every writer is restricted" was quantified over a
        # domain we know to be incomplete, and the qualification is refused.
        #
        # Subtracting ``_restricted`` rather than intersecting the writer set is
        # also what keeps the Solady shape working: there the assembly writer is
        # an internal helper reached only from ``onlyOwner`` / ``onlyRoles``
        # entry points, which ARE restricted, so nothing survives the
        # subtraction and the qualification stands.
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
        """``(member_witness, writer_openness)`` for one associated event.

        *writers_by_signature* maps a function's ``full_name`` to the tracked
        variables it writes; an emitter missing from it emits this event
        WITHOUT writing the variable, so on that path the event is not evidence
        of a write at all and the openness is demoted rather than proven.
        """
        witnesses = [
            record for var in sorted(target_vars) if (record := self._witness_by_pair.get((var, signature))) is not None
        ]
        if len(witnesses) != 1:
            # Zero: no correspondence was proven. More than one: the same event
            # is the witness for two different mappings, so an occurrence does
            # not say which entry moved.
            return None, WRITER_OPENNESS_NOT_DETERMINED
        witness = witnesses[0]
        emitters = self._emitters.get(signature) or set()
        if not emitters or any(not (writers_by_signature.get(fn) or set()) & target_vars for fn in emitters):
            return witness, WRITER_OPENNESS_NOT_DETERMINED
        if self._opaque_unrestricted:
            # An open path can write storage nothing attributed to a variable,
            # so no writer set on this contract is known to be complete.
            return witness, WRITER_OPENNESS_NOT_DETERMINED
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


# ---------------------------------------------------------------------------
# Semantic source extraction: walk predicate_trees / effects for raw signals.
# ---------------------------------------------------------------------------


def _walk_leaves(node: Any, callback) -> None:
    """Walk every LEAF descendant of ``node`` and invoke ``callback(leaf)``."""
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
    """Every state_variable operand surfaced by any leaf — direct
    operands AND set_descriptor.storage_var / key_sources AND
    authority_contract.address_source."""
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


# Authority roles that mark an operand as a real access-control principal (the
# caller is required to equal / be a member of the value). A var referenced only
# outside these roles is consulted by business logic, not gated on.
_AUTHORITY_LEAF_ROLES = frozenset({"caller_authority", "delegated_authority"})


def _leaf_asserts_caller_gate(leaf: Mapping[str, Any]) -> bool:
    """Belt-and-braces twin of the classifier's discriminator: an
    ``external_bool`` leaf may contribute a variable to ``caller_gate``
    provenance only when its callee is gate-shaped. The classifier no longer
    stamps ``delegated_authority`` on non-gate shapes, so on same-version
    trees this never fires; it exists so a drifted or hand-built tree cannot
    mint a control edge from a value-movement call
    (``vault.enter(msg.sender, …)``) through the harvest alone."""
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
    """Map each state-variable operand name to the set of ``authority_role``
    values of the leaves that reference it (direct operand reference only).

    Lets the admission loop tell a gated authority operand
    (``caller_authority`` / ``delegated_authority``) from one consulted purely
    by business logic, without re-deriving the predicate classification."""
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
            # An authority role on a non-gate-shaped external call must not
            # make its state-var operands read as gated-on: the operands of
            # ``vault.enter(msg.sender, ERC20(nativeWrapper), …)`` include
            # the wrapper token, and counting the leaf's role for them minted
            # WETH as a caller_gate controller of the Teller.
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
    """State-variable names appearing as
    ``set_descriptor.authority_contract.address_source.state_variable_name``.
    These are external authority registries;
    promote them from ``state_variable`` to ``external_contract`` kind so
    downstream resolution treats them as cross-contract delegates."""
    if not isinstance(predicate_trees, dict):
        return set()
    trees = predicate_trees.get("trees")
    if not isinstance(trees, dict):
        return set()

    authority_vars: set[str] = set()

    def visit(leaf: dict[str, Any]) -> None:
        # Only a leaf that itself asserts an authority check may promote its
        # descriptor's contract into the caller-gate set: the descriptor names
        # WHERE the check would live, the role says THAT a check was proven.
        # A business/pause/reentrancy leaf carrying a descriptor (or an
        # authority-role leaf whose callee is not gate-shaped) is not caller-
        # gate evidence.
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


# The caller is observable in the EVM only through these two builtins (and
# through helpers that themselves read one of them, which the recursive Slither
# accessors below follow). A function that reads neither cannot condition on who
# called it, so its missing tree is a determined "no caller gate here" rather
# than an unanswered question.
_CALLER_IDENTITY_BUILTINS = frozenset({"msg.sender", "tx.origin"})


def _recursive_read(fn: Any, recursive_attr: str, direct_attr: str) -> set[str] | None:
    """Names read by ``fn`` and everything it calls, including its modifiers.
    ``None`` when the recursive accessor failed — not determined.

    Modifiers are unioned explicitly: a guard written as ``onlyOwner`` lives in a
    ``Modifier`` object, and reading only the function body would classify the
    most common access-control shape in Solidity as caller-blind.

    The ``direct_attr`` fallback covers an object that never exposed the
    recursive accessor at all. It must NOT cover an accessor that exists and
    raised: the direct attribute is a strictly narrower set (this function's own
    body, not its callees), so substituting it turns "we could not read the
    callees" into "the callees read nothing" — a gate reached through an internal
    call disappears, its name drops out of the blind spot, and ``call_target``
    (a claim of proven absence) gets minted from a failure to determine. That is
    the one direction this whole function exists to prevent, so the failure is
    propagated as not-determined instead.
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
    """State-variable names the caller-gate question was never ANSWERED for.

    ``caller_gate`` is derived from the predicate leaves that were lowered.
    ``call_target`` is then minted for every remaining external-contract slot —
    i.e. from the *absence* of a lowered gate leaf, which is not the same fact as
    "no gate exists". The builder attempts the externally reachable surface
    (since G3 class R that includes ``fallback`` / ``receive``), but a function
    whose gate could not be lowered yields no tree, so a gate living in such a
    function is invisible and its address is published as a proven pure callee.

    A function is a blind spot when it is externally reachable, has no lowered
    tree, and observes the caller. Every state variable it reads is then a name
    this contract cannot answer the gate question for. Functions that read
    neither ``msg.sender`` nor ``tx.origin`` are excluded on evidence, not on
    convenience: with no caller in scope there is no caller gate to miss.

    Returns ``None`` when the surface could not be read at all — the same
    not-determined answer, applied to every name. Two routes reach it: the
    entry-point list could not be enumerated, or a recursive variable-read
    accessor raised (see ``_recursive_read``). Both mean the blind-spot set is
    incomplete, and an incomplete blind spot is indistinguishable from a small
    one, which is what makes ``call_target`` mintable from a failure.

    R2 status of that ``None`` arm, stated rather than implied: it has **zero
    realised rows** and is a lower bound, not a firing proof — for BOTH routes.
    The accessor route is reachable only when Slither's own
    ``all_state_variables_read`` / ``all_solidity_variables_read`` raise, which
    happens on no contract in the local corpus; it is covered by
    ``test_accessor_failure_answers_not_determined_instead_of_narrowing``, which
    makes the accessor raise by construction. Slither's
    ``Contract.functions_entry_points`` is a property returning a list
    comprehension, so it is never ``None`` for a real compiled contract; the arm
    is reachable only by construction (any other object passed in this position
    that cannot list its entry points) and is covered only by
    ``test_unenumerable_entry_points_answer_not_determined``, which builds that
    object by hand. It is kept because the alternative on an unreadable surface
    is to mint ``call_target`` from a second failure to determine — the exact
    defect this function exists to remove — not because it was observed firing.
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
            # Whether this function even observes the caller is unknown, so it
            # can neither be excluded on evidence nor have its names collected.
            return None
        if not (solidity_read & _CALLER_IDENTITY_BUILTINS):
            continue
        state_read = _recursive_read(fn, "all_state_variables_read", "state_variables_read")
        if state_read is None:
            return None
        blind |= state_read

    # ``guard_extraction_uncertain`` names entry points whose caller-authority
    # comparison the builder saw and could not lower. Those are treeless and
    # caller-reading by construction, so the sweep above already covers them;
    # unioning them explicitly keeps the dependency on that marker visible
    # rather than incidental.
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
    """State-variable names invoked as external-call destinations
    (``authority.check(...)``, ``hook.beforeTransfer(...)``). Sourced
    from ``effects.functions[*].sinks`` filtered to ``external_call``;
    we keep only sinks whose target's leading prefix matches an actual
    state-var name (so ``msg.sender.transfer`` etc. don't false-positive)."""
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
    """Project a single emitter function's sinks down to the small tag
    set the watcher needs to classify events without name matching.

    Returns a dict with ``writes`` (set of state-var names) and
    ``delegates`` (bool). The watcher unions these across all emitters
    of an event signature, so the final tags describe the event's
    full effect surface — not just one branch.
    """
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
    """Detect the OZ Initializable pattern — function modified by
    ``initializer`` or ``reinitializer``. Used to tag the Initialized
    event so reanalysis fires on unexpected re-inits without needing
    a hand-rolled Initialized topic in the global registry.
    """
    for modifier in getattr(function, "modifiers", []) or []:
        name = getattr(modifier, "name", "") or ""
        if name in ("initializer", "reinitializer", "onlyInitializing"):
            return True
    return False


def _unattributable_write_functions(effects: Mapping[str, Any] | None) -> frozenset[str]:
    """Functions whose storage effect the write-attribution cannot see.

    Two shapes, both demonstrated on compiled Solidity:

      * inline assembly reaching storage — the write is recorded against
        ``assembly_storage:<slot>``, never against a variable name, so such a
        function writes a tracked mapping WITHOUT appearing in that mapping's
        writer set; and
      * a ``delegatecall`` — the callee's writes land in this contract's
        storage and are not in this compilation unit at all.

    Note what this set is NOT for: intersecting it with a mapping's attributed
    writers. The whole point is that these functions are MISSING from that
    set, so an intersection is empty exactly when the shape is present.
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
    """Entry points reaching a library function that takes a STORAGE pointer.

    ``MarkLib.put(libMap, user)`` writes the caller's mapping through the
    pointer; Slither attributes the write to neither function, and
    ``all_state_variables_written()`` on the caller returns nothing for it — so
    such a caller is a writer of a tracked mapping that no writer set contains.

    The storage-parameter test is what keeps this from swallowing ordinary
    library use: ``SafeERC20.safeTransfer(token, to, amount)`` and
    ``Math.max(a, b)`` take no storage pointer and cannot write the caller's
    state, so a contract using them is untouched.
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
            # The question was not answered for this function; an unanswered
            # question is not proof that it writes nothing.
            out.add(name)
            continue
        for call in calls:
            callee = getattr(call, "function", None)
            if any(getattr(p, "location", None) == "storage" for p in getattr(callee, "parameters", None) or []):
                out.add(name)
                break
    return frozenset(out)


# An inline-assembly LOG opcode. A function reaching one can emit any topic0 it
# likes, including the topic0 of an event some other function's write earned a
# correspondence for — and it does so through a node carrying no ``EventCall``
# IR and, when it writes nothing, no state-write sink either. Such a function is
# invisible to BOTH openness quantifiers, so it is admitted to the opaque set on
# its own.
_ASSEMBLY_LOG_OPCODE = re.compile(r"\blog[0-4]\b")


def _assembly_reaches_log(unit, seen: set[str]) -> bool:
    """Can *unit* (or anything it calls internally) emit a log from assembly?

    Reads each assembly block's own source. Assembly whose source cannot be read
    counts as reaching a log: what the block does was not determined, and an
    undetermined block is not proof that it emits nothing.

    Detection is per-opcode rather than ``contains_assembly`` on purpose. Modern
    contracts use assembly constantly — ERC-7201 storage getters, Solady's
    slot arithmetic, custom-error reverts — and admitting every one of them
    would refuse qualification on nearly every real contract. Only the opcode
    that can forge an event is the threat.
    """
    # Imported lazily for the same reason the type handling above is: this
    # module stays importable without Slither side effects.
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
    """Entry points that can emit a log from inline assembly."""
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
    """Map state-variable name → set of function signatures that write it,
    sourced from ``effects.functions[*].sinks`` filtered to
    ``kind == "state_write"``. Excludes constructors."""
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


# ``StateWriteFact.hygiene_class`` for a variable a modifier sets before the
# placeholder and restores after it — the Solmate/OZ reentrancy latch. Every
# ``nonReentrant`` function writes it, so donating the whole writer set to it
# enrolls every event on the contract under a slot whose value is identical
# before and after each transaction (P1a: 2 of the 446 audited publications, and
# unbounded on a busy contract).
_TRANSIENT_HYGIENE_CLASS = "reentrancy_guard"

# ``StateWriteFact.origin`` for a write performed by a MODIFIER rather than by
# the function body. The write-and-restore proof is about the modifier, so this
# is the only origin the transient exclusion may subtract.
_GUARD_WRITE_ORIGIN = "guard"


def _write_facts_by_signature(effects: Mapping[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    """``function signature → its ``state_writes`` facts``, for the functions
    that carry them.

    A signature ABSENT from the result is the not-determined case — an effects
    artifact built before the facts existed, or a function whose writes the
    projection could not enrich. Callers keep such a writer rather than
    filtering it out, so a missing fact never silently narrows what is watched.
    """
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
    """Does this function write *var* (at *member_path*, when one is given) in a
    way worth watching?

    Two exclusions, both requiring the fact to be PROVEN before it subtracts:

      * every recorded write of *var* here is the transient-latch class, *var*
        is in *transient_vars* (the IR-proven guard set — written on both sides
        of a modifier's ``_;``), AND the write is carried by the modifier that
        holds that proof (``origin == "guard"``).

        All three are needed and each rules out a different way of deleting a
        real controller. ``hygiene_class`` carries a NAME fallback (``locked``,
        ``_status``, anything containing "reentran"), sound only as a suppressor
        of facts nobody admits — dropping a controller on it would make the name
        the witness. And the class is VARIABLE-granular, so once a var is a
        proven latch every write of it is stamped, including an ``onlyOwner
        setStatus`` in a function BODY: that write is a real, owner-controlled
        mutation and dropping it took the controller out of the plan entirely,
        with no watch and no poll. Only the modifier's own set-and-restore is
        the write the proof is about;
      * a member-scoped controller whose writes here are all proven to land on
        OTHER members. A ``var``-granularity write says which variable but not
        which member, so it is kept: not knowing which member moved is not
        knowing that this one did not.

    ``facts is None`` (nothing recorded) keeps the writer for the same reason.
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
    """Build ``ControllerWriterFunction`` records for the given state-variable
    targets, using ``effects`` as the writer-discovery source.

    *qualification* stamps F3's member-witness / writer-openness facts onto the
    aggregated events when it is supplied; without it the events carry neither,
    which the monitoring plane reads as the not-determined third state.

    *member_path* narrows a member-scoped controller to the writers that can
    reach that member (:func:`_writer_survives_hygiene`)."""
    target_set = {var for var in target_state_vars if var}
    if not target_set:
        return [], []
    writers_by_var = _state_writers_from_effects(effects)
    facts_by_signature = _write_facts_by_signature(effects)
    # IR-proven guards only (see ``_writer_survives_hygiene``); cached per
    # contract by the effects module, so this is a lookup after the first call.
    transient_vars = _collect_reentrancy_guard_vars(contract)
    # Invert: function-signature → set of vars it writes that we care about.
    writes_by_signature: dict[str, set[str]] = {}
    for var in target_set:
        for signature in writers_by_var.get(var, set()):
            if not _writer_survives_hygiene(facts_by_signature.get(signature), var, member_path, transient_vars):
                continue
            writes_by_signature.setdefault(signature, set()).add(var)

    functions_by_signature = _functions_by_signature(contract)
    writer_functions: list[ControllerWriterFunction] = []
    aggregated_events: dict[str, AssociatedEvent] = {}
    # Union of effects across every emitter of a given event signature. Each
    # event's downstream classification (ownership / admin / upgrade / etc.)
    # is decided from this aggregate, not from the event's name — see the
    # tag-driven dispatch in services/monitoring/event_topics.py.
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

    # Attach the aggregated tag dict to every event ref carrying that
    # signature — both in the controller's flat list and within each
    # writer_function so consumers reading either get the same view.
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
            # Only the proven value is written. Absent is the third state, the
            # same convention ``authority_provenance`` follows one level up, and
            # the monitoring plane normalizes it back to an explicit
            # ``not_determined`` on the spec the watcher reads.
            if openness == WRITER_OPENNESS_RESTRICTED:
                event_ref["writer_openness"] = openness

    associated_events = sorted(aggregated_events.values(), key=lambda item: item["signature"])
    return writer_functions, associated_events


# ---------------------------------------------------------------------------
# Helpers for read_spec resolution. Public state-vars get an auto-generated
# getter named after the var; private vars need an explicit one. We pick
# the getter via a small set of conventions the static pipeline can spot
# without RPC: a same-contract view function returning the var.
# ---------------------------------------------------------------------------


def _build_getter_index(contract) -> dict[str, str]:
    """Map private state-var name → its public getter function name.

    Walks the subject's view/pure functions whose body is
    ``return <state_var>;``."""
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
    """Build the read spec for a state-var controller. Three getter states:

    * public var — Solidity compiles an auto-getter named after the var:
      ``strategy=getter_call, target=<name>``.
    * private/internal var with a discovered same-contract getter
      (``_build_getter_index``) — ``strategy=getter_call, target=<getter>``.
    * private/internal var with NO getter — the var is not readable by
      any function call, so no getter target exists to claim:
      ``strategy=unknown`` (``target`` keeps the var name purely as an
      identifier). The monitoring plane's selector-minting consumer
      (``polling_plan._is_poll_decodable``) skips these. The RESOLUTION
      plane's ``_getter_target`` does NOT skip: it falls back to
      ``source`` (the same var name) and still probes the nonexistent
      getter — the revert path there records the honest third state
      (``value=None, observed_via="eth_call_error"`` + record_degraded),
      so no false value publishes, but the probe is wasted; tightening
      that consumer is a recorded follow-up, not this function's claim.
      The type fields stay populated so type-shape guards (struct skip,
      primitive-scalar snapshot skip) keep their inputs.
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


# Canonical OZ ownership-mutation event. Every function that touches an OZ-v5
# namespaced struct reads its slot via the same assembly accessor, so effects
# attributes a write of the slot constant to non-owner setters too; the
# ``OwnershipTransferred`` log is the precise ownership-change signal, so the
# owner controller's writer/event set is filtered to its emitters (matching the
# OZ-v4 ``_owner`` controller, whose only writers transfer/renounce ownership).
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
    """Append a canonical OZ-v5 ownership controller (read through ``owner()``)
    once, deduplicated by ``controller_id``.

    ``getter`` is the live public authority getter (``owner``); ``slot_constant``
    is the namespaced ``*StorageLocation`` constant the owner is written through.
    Writer/event discovery is keyed on the slot constant, then narrowed to the
    ``OwnershipTransferred`` emitters so the controller carries the same clean
    transfer/renounce writer set and ownership event as the OZ-v4 form."""
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
            "tracking_mode": tracking_mode,  # type: ignore[typeddict-item]
            "writer_functions": writer_functions,
            "associated_events": associated_events,
            "polling_sources": [getter],
            "notes": notes,
        }
    )
    seen_ids.add(controller_id)


# ---------------------------------------------------------------------------
# Top-level builders.
# ---------------------------------------------------------------------------


def build_controller_tracking(
    contract,
    project_dir: Path,
    predicate_trees: Mapping[str, Any] | None,
    effects: Mapping[str, Any] | None,
    semantic_control: SemanticControlAnalysis | None = None,
) -> list[ControllerTrackingTarget]:
    """Build event-first tracking metadata from the semantic predicate-tree +
    effects artifacts.

    Inputs:
      * ``predicate_trees`` — artifact from ``build_predicate_artifacts``.
        Walked for every state-variable operand referenced by a leaf
        (direct operand, set-descriptor storage_var/key_source, or
        authority_contract.address_source). Each unique name becomes a
        ``ControllerTrackingTarget``.
      * ``effects`` — artifact from ``build_effects``. Filtered to
        ``state_write`` sinks per externally-callable function; supplies
        the writer functions for each state-variable target.
      * ``semantic_control`` — supplies role definitions for
        ``role_identifier`` targets found from predicate-tree role keys.

    Predicate trees provide the structural controller reads; effects provide
    the writer side.
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
    # Union of two sources for "this state-var is an external contract":
    #   1. predicate_trees flagged it as authority_contract.address_source
    #   2. effects records an external_call from a function on it
    # This union answers ONLY "does this slot hold another contract's address",
    # which is what ``kind`` means. It is NOT an authority claim: (2) is
    # satisfied by any callee (``eETH``, ``lido``, ``liquidityPool``).
    delegated_authority_vars = _collect_authority_state_vars(predicate_trees)
    authority_state_vars = delegated_authority_vars | external_contract_vars_from_effects
    # "Gates the caller" — the separate question. A leaf either delegates its
    # authority check to the address (1) or names it directly in a
    # caller_authority / delegated_authority operand. Kept apart from the union
    # above so a persisted row can say which provenance it came from; see
    # ``ControllerProvenance``.
    caller_gate_vars = delegated_authority_vars | {
        name for name, roles in authority_roles_by_var.items() if roles & _AUTHORITY_LEAF_ROLES
    }

    # Both inputs to the split must be REAL for either answer to be evidence.
    # ``caller_gate`` is read out of ``predicate_trees`` alone, so when that
    # artifact carries no trees every name falls through to the
    # ``external_contract_vars_from_effects`` arm and a proven authority
    # registry is stamped ``call_target`` — a proven-absent gate synthesized
    # from a failure to determine, which downstream demotes its control edge.
    # That artifact is a real production state, not a hypothetical: ``core.py``
    # catches any predicate-builder exception and continues with
    # ``{"schema_version": "semantic", "error": ...}``, then passes exactly
    # that object here. With no trees NEITHER question was answered, so every
    # name is not-determined and keeps its control edge.
    #
    # Empty ``trees`` is treated the same as absent. A successful build over a
    # contract with no lowered guard leaf cannot distinguish "nothing gates
    # anything" from "no gate was lowered", and the safe reading of that
    # ambiguity is not-determined.
    predicate_trees_available = (
        isinstance(predicate_trees, dict)
        and isinstance(predicate_trees.get("trees"), dict)
        and bool(predicate_trees["trees"])
    )

    # Artifact-level availability is not enough: ``caller_gate`` is read out of
    # the trees that were LOWERED, so a gate living in a function with no tree
    # is invisible to it and the name falls through to ``call_target``. That is
    # the same "absence of a proven constraint" error one level down, and it is
    # realised on this corpus — see ``_caller_gate_blind_spot_vars``.
    gate_blind_spot_vars = (
        _caller_gate_blind_spot_vars(contract, predicate_trees) if predicate_trees_available else None
    )

    def _provenance_for(name: str) -> ControllerProvenance | None:
        if not predicate_trees_available:
            return None
        if name in caller_gate_vars:
            # Proven present. A lowered leaf gates on it; a blind spot
            # elsewhere cannot subtract from evidence already in hand.
            return "caller_gate"
        if gate_blind_spot_vars is None or name in gate_blind_spot_vars:
            # The gate question was never answered for this name.
            return None
        if name in external_contract_vars_from_effects:
            return "call_target"
        return None

    # Effects-discovered external-contract vars get added to the
    # referenced set so Pass 2 emits a tracking target for them even if
    # they don't appear as a leaf operand (e.g. ``hook`` written by
    # ``setHook(address)`` and called from the body, but not gated).
    referenced_state_vars |= external_contract_vars_from_effects
    role_definitions = list(semantic_control.get("role_definitions", []) if semantic_control else [])

    tracking_targets: list[ControllerTrackingTarget] = []
    seen_ids: set[str] = set()

    # Pass 1: role identifiers drawn from semantic_control.role_definitions.
    #
    # Skip role_definitions whose name is also an authority-registry state var.
    # The external_contract target gets writer/events through Pass 2; emitting
    # a state_only role_identifier for the same source would mask that row.
    for role_def in role_definitions:
        role_name = role_def.get("role")
        if not role_name:
            continue
        if role_name in authority_state_vars:
            continue
        # Storage-layout slot constants (Solady ``_OWNER_SLOT``, OZ-v5
        # ``OwnableStorageLocation``, ``*StorageLocation``) reach role_definitions
        # because they surface as bytes32-constant caller_authority operands, but
        # they are slot locators, not roles — ``role_identifier:<slot>`` produced
        # a dead ``getter_call <slot>()`` row that always reverts. Pass 2 already
        # filters these; mirror that guard here so the same suppression applies no
        # matter which pass first sees the name. The owner/governor they locate is
        # resolved from the canonical getter in predicate_evaluator instead.
        if _is_storage_layout_constant(role_name):
            # An OZ-v5 namespaced ownership slot is the one storage-layout
            # constant that backs a real authority: the owner lives in a
            # namespaced struct (no plain ``owner`` state var), so the slot
            # constant is the only operand the gate exposes. Emit a CANONICAL
            # owner controller read through ``owner()`` (never the dead slot
            # constant), keyed for writer/event tracking on the slot constant
            # itself (where ``transferOwnership`` / ``OwnershipTransferred`` write
            # and emit). Other slot constants stay suppressed.
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

    # Pass 2: every state-variable operand referenced by a leaf.
    # Authority-registry vars (authority_contract.address_source) get
    # promoted to ``external_contract`` kind; everything else is
    # ``state_variable``. Role-identifier-named vars not declared as
    # state vars (compile-time bytes32 constants referenced by name) get
    # role_identifier targets here too.
    for name in sorted(referenced_state_vars):
        if name in role_def_names:
            continue
        if _is_storage_layout_constant(name):
            continue
        sv = state_vars_by_name.get(name)
        # Role-identifier classification is structural: a referenced bytes32
        # constant can be read once and passed into semantic authority checks.
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

        kind: str = "external_contract" if name in authority_state_vars else "state_variable"
        controller_id = f"{kind}:{name}"
        if controller_id in seen_ids:
            continue
        read_spec_var = _state_var_read_spec(name, state_vars_by_name, getter_by_var)

        # A bare struct has no single storable address value; only the SEPARATE
        # member-path pass projects an individual address field out of it.
        # Emitting the whole struct as a controller forces a getter read of the
        # entire packed blob, which is never a principal. (Array/mapping
        # controllers are caller-keyed ACLs tracked through their associated
        # events, a separate concern handled downstream.)
        if kind == "state_variable" and read_spec_var.get("type_kind") == "struct":
            continue

        # A compile-time ``constant`` address/contract consulted only by business
        # logic (the caller is never required to equal or be a member of it) is a
        # sentinel identifier, not an authority. Immutable authorities
        # (``is_constant`` False) and constants the caller IS gated on
        # (``caller_authority`` / ``delegated_authority``) are kept.
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
            tracking_mode: str = "event_plus_state"
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
            "kind": kind,  # type: ignore[typeddict-item]
            "read_spec": read_spec_var,
            "confidence": None,
            "tracking_mode": tracking_mode,  # type: ignore[typeddict-item]
            "writer_functions": writer_functions,
            "associated_events": associated_events,
            "polling_sources": [name],
            "notes": notes,
        }
        provenance = _provenance_for(name)
        # Key omitted (not set to None) when neither question was answered:
        # absent is the not-determined state all the way to the DB column.
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
                "tracking_mode": tracking_mode,  # type: ignore[typeddict-item]
                "writer_functions": writer_functions,
                "associated_events": associated_events,
                "polling_sources": [name],
                "notes": notes,
            }
        )
        seen_ids.add(controller_id)

    return sorted(tracking_targets, key=lambda item: item["label"])
