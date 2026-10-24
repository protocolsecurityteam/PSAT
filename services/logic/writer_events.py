"""Writer events per writer function and field, and the lookups every write of which they log.

The static pipeline's ``mapping_events`` as the engine reads it: one spec per writer function (constructors included)
and struct field, and ``(mapping, key count, field path)`` relations whose every write has a matching mandatory event.
Kept here so the engine stands on committed code of its own; the unchanged helpers are the pipeline's.
"""

from __future__ import annotations

from typing import Any

from services.static.contract_analysis_pipeline.mapping_events import (
    WriterEventSpec,
    _abi_type,
    _converted_zero_constant,
    _direction_of_write,
    _event_metadata_index,
    _extract_event_emissions,
    _ir_name,
    _is_mapping_type,
    _match_event_to_keys,
    _match_event_value_position,
    _var_name,
)
from services.static.contract_analysis_pipeline.shared import _contract_functions


def _extract_index_writes(function: Any, fields: bool = False) -> list[tuple[str, list[Any], Any, Any]]:
    """``(mapping, keys, value, operation)`` per mapping write; ``value`` is None for ``delete``. ``fields`` adds writes
    to a field after the last key."""
    triples: list[tuple[str, list[Any], Any, Any]] = []
    for node in getattr(function, "nodes", []) or []:
        definitions: dict[str, Any] = {}
        conversions: dict[str, Any] = {}
        for ir in getattr(node, "irs", []) or []:
            kind = _ir_name(ir)
            if kind in {"Index", "Member"}:
                lvalue_name = _var_name(getattr(ir, "lvalue", None))
                if lvalue_name:
                    definitions[lvalue_name] = ir
            elif kind == "TypeConversion":
                lvalue_name = _var_name(getattr(ir, "lvalue", None))
                if lvalue_name:
                    conversions[lvalue_name] = getattr(ir, "variable", None)
            elif kind == "Assignment":
                lvalue_name = _var_name(getattr(ir, "lvalue", None))
                defining = definitions.get(lvalue_name)
                write = _mapping_write_from_index(
                    _field_base(defining, definitions) if fields else defining, definitions
                )
                if write is not None:
                    mapping_name, keys = write
                    rvalue = getattr(ir, "rvalue", None)
                    triples.append((mapping_name, keys, _converted_zero_constant(rvalue, conversions) or rvalue, ir))
            elif kind == "Delete":
                operand_name = _var_name(getattr(ir, "lvalue", None))
                defining = definitions.get(operand_name)
                write = _mapping_write_from_index(
                    _field_base(defining, definitions) if fields else defining, definitions
                )
                if write is not None:
                    mapping_name, keys = write
                    triples.append((mapping_name, keys, None, ir))
    return triples


def _field_base(defining: Any, definitions: dict[str, Any]) -> Any:
    """The Index under a trailing field access (``loans[who]`` in ``loans[who].isWhitelisted``), else ``defining``."""
    if _ir_name(defining) == "Member":
        base = definitions.get(_var_name(getattr(defining, "variable_left", None)))
        if _ir_name(base) == "Index":
            return base
    return defining


def _mapping_write_from_index(defining: Any, definitions: dict[str, Any]) -> tuple[str, list[Any]] | None:
    if _ir_name(defining) != "Index":
        return None
    base_name, keys = _index_base_mapping_name_and_keys(defining, definitions)
    if not base_name:
        return None
    return base_name, keys


def _index_base_mapping_name_and_keys(index_ir: Any, definitions: dict[str, Any]) -> tuple[str | None, list[Any]]:
    current = index_ir
    visited: set[str] = set()
    keys: list[Any] = []
    while _ir_name(current) == "Index":
        keys.insert(0, getattr(current, "variable_right", None))
        left = getattr(current, "variable_left", None)
        left_name = _var_name(left)
        if left_name in visited:
            return left_name or None, keys
        if left_name:
            visited.add(left_name)
        defining = definitions.get(left_name)
        # Through an ERC-7201 struct pointer (``$._roles[role][account]``), ``left`` is synthetic, so the field nearest
        # the Index is the logical mapping.
        member_field: str | None = None
        while _ir_name(defining) == "Member":
            if member_field is None:
                member_field = _var_name(getattr(defining, "variable_right", None)) or None
            base = getattr(defining, "variable_left", None)
            base_name = _var_name(base)
            if base_name in visited:
                return (member_field or left_name) or None, keys
            if base_name:
                visited.add(base_name)
            defining = definitions.get(base_name)
        if _ir_name(defining) != "Index":
            if member_field is None and defining is None and _pointer_mapping(left):
                # A mapping reached through a storage pointer a function returns (``_storageRoles()[role]``): named
                # by its type, as the engine names a slot-rooted lookup.
                return str(left.type), keys
            return (member_field or left_name) or None, keys
        current = defining
    return None, keys


def _pointer_mapping(value: Any) -> bool:
    """A mapping-typed local or temporary not drawn from a state variable: a pointer into storage some code computed
    (``_storageRoles()``'s result)."""
    from slither.core.variables.local_variable import LocalVariable
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.variables import TemporaryVariable

    return (
        _is_mapping_type(value)
        and isinstance(value, (LocalVariable, TemporaryVariable))
        and not isinstance(getattr(value, "points_to_origin", None), StateVariable)
    )


def writer_specs(contract: Any, *, per_writer: bool = False, fields: bool = False) -> list[WriterEventSpec]:
    """Writer-event specs, one per (mapping, event, direction, field); ``per_writer`` keeps one per writer function,
    constructors included, for the completeness check that matches each write against its own function's emits.
    ``fields`` adds ``field_write`` specs for struct fields after the last key.
    """
    from services.static.contract_analysis_pipeline.structural_evidence import evidence_for

    specs: list[WriterEventSpec] = []
    seen: set[tuple[str, ...]] = set()
    metadata_index = _event_metadata_index(contract)
    evidence = evidence_for(contract)
    for function in _contract_functions(contract):
        if getattr(function, "is_constructor", False) and not per_writer:
            continue
        # ``_extract_index_writes`` also sees namespaced-storage writes that ``_written_mappings`` misses.
        index_writes = _extract_index_writes(function, fields)
        if not index_writes:
            continue
        plain = {id(operation) for *_, operation in _extract_index_writes(function)} if fields else set()
        emissions = _extract_event_emissions(function, metadata_index)
        if not emissions:
            continue
        members = {id(write.operation): list(write.cell.members) for write in evidence.summary(function).writes}
        for mapping_name, key_vars, value_var, operation in index_writes:
            direction = _direction_of_write(value_var)
            if direction is None:
                continue
            match = _match_event_to_keys(emissions, key_vars)
            if match is None:
                continue
            event_signature, key_positions_by_index, indexed_positions = match
            event_name = event_signature.split("(", 1)[0]
            writer = getattr(function, "full_name", getattr(function, "name", ""))
            member_path = members.get(id(operation))
            key = (mapping_name, event_signature, direction, writer if per_writer else "", str(member_path))
            if key in seen:
                continue
            seen.add(key)
            key_position = key_positions_by_index.get(len(key_vars) - 1)
            if key_position is None:
                continue
            value_position = _match_event_value_position(emissions, value_var, event_signature, key_position)
            spec: WriterEventSpec = {
                "mapping_name": mapping_name,
                "event_signature": event_signature,
                "event_name": event_name,
                "key_position": key_position,
                "key_positions_by_index": key_positions_by_index,
                "indexed_positions": list(indexed_positions),
                "direction": direction,
                "writer_function": writer,
                "value_position": value_position,
            }
            if member_path is not None:
                spec["member_path"] = member_path
            if fields and id(operation) not in plain:
                spec["field_write"] = True
            specs.append(spec)
    return specs


def _library_call_may_write_storage(ir: Any) -> bool:
    """A library receives storage only through ``storage`` parameters; value parameters are copies."""
    params = list(getattr(ir.function, "parameters", None) or [])
    for i, arg in enumerate(ir.arguments):
        if not (_is_mapping_type(arg) or getattr(arg, "points_to_origin", None) is not None):
            continue
        if i >= len(params) or getattr(params[i], "location", None) in ("storage", None):
            return True
    return False


def _storage_root(arg: Any, fn: Any) -> str | None:
    """The state variable, or field of a namespaced struct, whose storage ``arg`` (a storage reference passed to a
    library) lies in: walked back through the ``Index``/``Member`` operations that made it. ``None`` when unknown."""
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import Index, Member

    defining = {}
    for node in getattr(fn, "nodes", []) or []:
        for ir in node.irs:
            if getattr(ir, "lvalue", None) is not None:
                defining.setdefault(ir.lvalue, ir)
    current, last_field = arg, None
    for _ in range(32):
        if isinstance(current, StateVariable):
            return current.name
        origin = getattr(current, "points_to_origin", None)
        if isinstance(origin, StateVariable):
            return origin.name
        ir = defining.get(current)
        if isinstance(ir, Index):
            current = ir.variable_left
        elif isinstance(ir, Member):
            last_field = str(ir.variable_right)
            current = ir.variable_left
        else:
            # A storage pointer (OpenZeppelin 5's ``$``): the field read off it names the storage; a mapping a
            # function returns (``_storageRoleMembers()``) is named by its type, as its writes are.
            if last_field and getattr(current, "location", None) == "storage":
                return last_field
            return str(current.type) if last_field is None and _pointer_mapping(current) else None
    return None


def _library_written_roots(ir: Any, fn: Any) -> set[str] | None:
    """What a library call may write: nothing for a view or pure function, else the storage of each ``storage``
    argument; ``None`` when that can't be named."""
    callee = ir.function
    if getattr(callee, "view", False) or getattr(callee, "pure", False):
        return set()
    params = list(getattr(callee, "parameters", None) or [])
    roots: set[str] = set()
    for i, arg in enumerate(ir.arguments):
        if not (_is_mapping_type(arg) or getattr(arg, "points_to_origin", None) is not None):
            continue
        if i >= len(params) or getattr(params[i], "location", None) in ("storage", None):
            root = _storage_root(arg, fn)
            if root is None:
                return None
            roots.add(root)
    return roots


def complete_relations(contract: Any, specs: list[WriterEventSpec]) -> set[tuple[str, int, tuple[str, ...]]]:
    """``(mapping, key count, field path)`` projections for which every write to the field has a matching mandatory
    event. A sibling field's writes don't change the field's cell; a whole-struct write does.

    Gates whether an event fold may claim an exact member set. ``specs`` should come from
    ``writer_specs(contract, per_writer=True)``. A matching event
    somewhere in a function is insufficient: its key and value must be the
    written values and every continuation of the write must reach that emit.
    Unknown assembly writes and unlogged initialization prevent a completeness claim.
    """
    from slither.slithir.operations import EventCall, InternalDynamicCall, LibraryCall, LowLevelCall, SolidityCall

    from services.static.contract_analysis_pipeline.structural_evidence import evidence_for
    from services.static.contract_analysis_pipeline.structural_ir import integer, operations, same

    functions = list(getattr(contract, "functions", []) or [])
    if any(
        (isinstance(ir, SolidityCall) and ir.function.name.startswith("sstore("))
        or (isinstance(ir, LowLevelCall) and str(ir.function_name) in {"delegatecall", "callcode"})
        or isinstance(ir, InternalDynamicCall)
        for fn in functions
        for _, ir in operations(fn)
    ):
        return set()
    # A library writes only the storage handed to it (``EnumerableSet.add(_roleMembers[role], who)`` touches
    # ``_roleMembers``, never ``_roles``): only those variables lose their claim.
    unlogged: set[str] = set()
    for fn in functions:
        for _, ir in operations(fn):
            if isinstance(ir, LibraryCall) and _library_call_may_write_storage(ir):
                roots = _library_written_roots(ir, fn)
                if roots is None:
                    return set()
                unlogged |= roots
    evidence = evidence_for(contract)
    groups: dict[tuple[str, int], list[Any]] = {}
    for fn in functions:
        for write in evidence.summary(fn).writes:
            if write.cell.keys:
                key = (write.cell.variable.name, len(write.cell.keys))
                groups.setdefault(key, []).append(write)

    def matched_event(write, ir, spec):
        if not isinstance(ir, EventCall) or str(ir.name) != spec["event_name"]:
            return False
        args = ir.arguments
        # Resolve overloads by actual ABI types, never by event name/arity alone.
        signature = f"{ir.name}({','.join(_abi_type(arg.type) for arg in args)})"
        if signature != spec["event_signature"]:
            return False
        positions = spec["key_positions_by_index"]
        if set(positions) != set(range(len(write.cell.keys))):
            return False
        if any(pos >= len(args) or not same(args[pos], write.cell.keys[i]) for i, pos in positions.items()):
            return False
        # A mutable temporary/parameter reused in an emit is not necessarily the
        # value written earlier. Without SSA equivalence, refuse such aliases.
        values = [*write.cell.keys, write.value]
        if any(
            getattr(op, "lvalue", None) is value
            for _, op in operations(write.function)
            for value in values
            if value is not None
        ):
            return False
        value = 0 if _ir_name(write.operation) == "Delete" else integer(write.value, write.function)
        if spec["direction"] in {"add", "remove"}:
            return value in (0, 1) and bool(value) == (spec["direction"] == "add")
        pos = spec.get("value_position")
        return pos is not None and pos < len(args) and same(args[pos], write.value)

    def same_field(spec, write):
        return "member_path" not in spec or tuple(spec["member_path"]) == write.cell.members

    def covered(write):
        candidates = [
            s
            for s in specs
            if s["mapping_name"] == write.cell.variable.name
            and s["writer_function"] == write.function.full_name
            and same_field(s, write)
        ]
        start_index = list(write.node.irs).index(write.operation) + 1
        # Per-node memo keeps the walk linear in CFG size; without it, sequential branches explode exponentially. Sound
        # because every node on the stack is emit-free, so a revisit means an emit-free cycle wherever it is reached.
        memo: dict[Any, bool] = {}

        def walk(node, index, seen):
            if node in seen:
                return False
            if index == 0 and node in memo:
                return memo[node]
            result = any(matched_event(write, ir, spec) for ir in node.irs[index:] for spec in candidates) or (
                bool(node.sons) and all(walk(child, 0, seen | {node}) for child in node.sons)
            )
            if index == 0:
                memo[node] = result
            return result

        return bool(candidates) and walk(write.node, start_index, set())

    def no_unbacked_emits(writes):
        relevant = [
            spec
            for spec in specs
            if spec["mapping_name"] == writes[0].cell.variable.name
            and len(spec["key_positions_by_index"]) == len(writes[0].cell.keys)
            and any(same_field(spec, w) for w in writes)
        ]
        names = {spec["event_name"] for spec in relevant}
        for fn in functions:
            for node, ir in operations(fn):
                if not isinstance(ir, EventCall) or str(ir.name) not in names:
                    continue
                if not any(
                    w.function is fn
                    and any(matched_event(w, ir, spec) for spec in relevant)
                    and (
                        w.node in node.dominators
                        if w.node is not node
                        else list(node.irs).index(w.operation) < list(node.irs).index(ir)
                    )
                    for w in writes
                ):
                    return False
        return True

    complete: set[tuple[str, int, tuple[str, ...]]] = set()
    for (name, arity), writes in groups.items():
        if name in unlogged:
            continue
        for field in {w.cell.members for w in writes}:
            relevant = [w for w in writes if field[: len(w.cell.members)] == w.cell.members]
            if (
                len({id(w.cell.variable) for w in relevant}) == 1
                and all(covered(w) for w in relevant)
                and no_unbacked_emits(relevant)
            ):
                complete.add((name, arity, field))
    return complete
