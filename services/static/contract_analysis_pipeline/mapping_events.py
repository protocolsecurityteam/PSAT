"""Discover mapping writes that can be replayed from emitted events."""

from __future__ import annotations

from typing import Any

from schemas.static_pipeline_schemas import EventMetadata as _EventMetadata
from schemas.static_pipeline_schemas import WriterEventDirection, WriterEventSpec

from .shared import _contract_functions


def _ir_name(ir: Any) -> str:
    return type(ir).__name__ if ir is not None else ""


def _var_name(item: Any) -> str:
    if item is None:
        return ""
    return getattr(item, "name", None) or str(item)


def _is_mapping_type(variable: Any) -> bool:
    type_str = str(getattr(variable, "type", "") or "")
    return type_str.startswith("mapping(")


def _written_mappings(function: Any) -> list[Any]:
    return [v for v in function.all_state_variables_written() if _is_mapping_type(v)]


def _extract_index_writes(function: Any) -> list[tuple[str, list[Any], Any]]:
    triples: list[tuple[str, list[Any], Any]] = []
    for node in getattr(function, "nodes", []) or []:
        definitions: dict[str, Any] = {}
        for ir in getattr(node, "irs", []) or []:
            kind = _ir_name(ir)
            if kind in {"Index", "Member"}:
                lvalue_name = _var_name(getattr(ir, "lvalue", None))
                if lvalue_name:
                    definitions[lvalue_name] = ir
            elif kind == "Assignment":
                lvalue_name = _var_name(getattr(ir, "lvalue", None))
                defining = definitions.get(lvalue_name)
                write = _mapping_write_from_index(defining, definitions)
                if write is not None:
                    mapping_name, keys = write
                    triples.append((mapping_name, keys, getattr(ir, "rvalue", None)))
            elif kind == "Delete":
                operand_name = _var_name(getattr(ir, "lvalue", None))
                defining = definitions.get(operand_name)
                write = _mapping_write_from_index(defining, definitions)
                if write is not None:
                    mapping_name, keys = write
                    triples.append((mapping_name, keys, None))
    return triples


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
        # A ``Member`` chain between Index levels either resolves to an inner
        # Index (nested mapping ``m[k].field[j]`` — keep walking) or bottoms out
        # at a struct base. When that base is a storage struct reached through a
        # pointer (OZ v5 / ERC-7201 namespaced storage,
        # ``$._roles[role][account]``), ``left`` is only a synthetic ref, so the
        # *field* name (``_roles``) is the logical mapping — capture the field
        # closest to the Index and prefer it when bottoming out.
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
            return (member_field or left_name) or None, keys
        current = defining
    return None, keys


def _direction_of_write(value_var: Any) -> WriterEventDirection | None:
    """Classify a mapping write by the assigned value.

    Returns ``"add"`` / ``"remove"`` for constant 1/0 (Maker
    ``wards[u] = 1`` shape) and ``"set"`` for variable assignments
    (``balances[u] = amount`` shape) where the value has to be
    decoded from the emitted event / trace at indexing time. PR D's
    backends consume the ``set`` direction; PR-A-era code paths
    only check for ``add``/``remove`` so the new value is invisible
    to them — exactly what we want.
    """
    if value_var is None:
        return "remove"
    value = getattr(value_var, "value", None)
    type_str = str(getattr(value_var, "type", "") or "")
    if value is None:
        return "set"
    if isinstance(value, bool):
        return "add" if value else "remove"
    try:
        numeric = int(value, 16) if isinstance(value, str) and str(value).startswith("0x") else int(value)
        return "add" if numeric != 0 else "remove"
    except (ValueError, TypeError):
        pass
    if type_str == "bool":
        if str(value).lower() in ("true", "1"):
            return "add"
        if str(value).lower() in ("false", "0"):
            return "remove"
    return "set"


def _abi_type(type_obj: Any) -> str:
    if type_obj is None:
        return "unknown"
    type_name = type(type_obj).__name__
    if type_name == "UserDefinedType":
        underlying = getattr(type_obj, "type", None)
        if type(underlying).__name__ == "Contract":
            return "address"
        if type(underlying).__name__ == "Enum":
            return "uint8"
    return str(type_obj)


def _event_declarations(contract: Any) -> list[Any]:
    declarations: list[Any] = []
    for current in [contract, *list(getattr(contract, "inheritance", []) or [])]:
        events = list(getattr(current, "events", []) or [])
        declared = list(getattr(current, "events_declared", []) or [])
        declarations.extend(events or declared)
    return declarations


def _event_metadata(event: Any) -> _EventMetadata | None:
    name = getattr(event, "name", "") or ""
    elems = list(getattr(event, "elems", []) or [])
    arg_types = [_abi_type(getattr(elem, "type", None)) for elem in elems]
    signature = getattr(event, "full_name", "") or ""
    if not signature and name:
        signature = f"{name}({','.join(arg_types)})"
    if not signature:
        return None
    return {
        "signature": signature,
        "arg_types": arg_types,
        "indexed_positions": [i for i, elem in enumerate(elems) if bool(getattr(elem, "indexed", False))],
    }


def _event_metadata_index(contract: Any) -> dict[str, list[_EventMetadata]]:
    index: dict[str, list[_EventMetadata]] = {}
    for event in _event_declarations(contract):
        metadata = _event_metadata(event)
        if metadata is None:
            continue
        name = getattr(event, "name", "") or metadata["signature"].split("(", 1)[0]
        for key in {name, metadata["signature"]}:
            if key:
                index.setdefault(key, []).append(metadata)
    return index


def _resolve_event_metadata(
    event_name: str,
    arguments: list[Any],
    metadata_index: dict[str, list[_EventMetadata]],
) -> _EventMetadata | None:
    candidates = metadata_index.get(event_name, [])
    if not candidates:
        return None
    arg_types = [_abi_type(getattr(arg, "type", None)) for arg in arguments]
    for candidate in candidates:
        if candidate["arg_types"] == arg_types:
            return candidate
    for candidate in candidates:
        if len(candidate["arg_types"]) == len(arguments):
            return candidate
    return candidates[0]


def _extract_event_emissions(
    function: Any,
    metadata_index: dict[str, list[_EventMetadata]],
) -> list[tuple[str, list[Any], list[int]]]:
    emissions: list[tuple[str, list[Any], list[int]]] = []
    for node in getattr(function, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if _ir_name(ir) != "EventCall":
                continue
            name = getattr(ir, "name", "") or ""
            # Slither types ``EventCall.name`` as ``str | Constant``; a Constant
            # slips through for events emitted via an aliased reference (seen on
            # Morpho). Coerce so the downstream signature handling never calls
            # ``.split('(')`` on a non-str.
            if not isinstance(name, str):
                name = str(name)
            arguments = list(getattr(ir, "arguments", []) or [])
            if not name:
                continue
            metadata = _resolve_event_metadata(name, arguments, metadata_index)
            if metadata is None:
                emissions.append((name, arguments, []))
                continue
            emissions.append((metadata["signature"], arguments, list(metadata["indexed_positions"])))
    return emissions


def _match_event_to_keys(
    emissions: list[tuple[str, list[Any], list[int]]],
    key_vars: list[Any],
) -> tuple[str, dict[int, int], list[int]] | None:
    key_names = [_var_name(key_var) for key_var in key_vars]
    if not key_names or any(not name for name in key_names):
        return None
    for signature, arguments, indexed_positions in emissions:
        positions: dict[int, int] = {}
        for key_idx, key_name in enumerate(key_names):
            for arg_idx, arg in enumerate(arguments):
                if _var_name(arg) == key_name:
                    positions[key_idx] = arg_idx
                    break
        if len(positions) == len(key_names):
            return signature, positions, indexed_positions
    return None


def discover_mapping_writer_events(contract: Any) -> list[WriterEventSpec]:
    specs: list[WriterEventSpec] = []
    seen: set[tuple[str, str, str]] = set()
    metadata_index = _event_metadata_index(contract)
    for function in _contract_functions(contract):
        if getattr(function, "is_constructor", False):
            continue
        # ``_extract_index_writes`` is the authoritative signal: it resolves
        # writes through struct-field / storage-pointer Member chains (OZ v5
        # namespaced storage) that ``_written_mappings`` — contract-level
        # mapping state variables only — does not see. Gate on it directly.
        index_writes = _extract_index_writes(function)
        if not index_writes:
            continue
        emissions = _extract_event_emissions(function, metadata_index)
        if not emissions:
            continue
        for mapping_name, key_vars, value_var in index_writes:
            direction = _direction_of_write(value_var)
            if direction is None:
                continue
            match = _match_event_to_keys(emissions, key_vars)
            if match is None:
                continue
            event_signature, key_positions_by_index, indexed_positions = match
            event_name = event_signature.split("(", 1)[0]
            key = (mapping_name, event_signature, direction)
            if key in seen:
                continue
            seen.add(key)
            key_position = key_positions_by_index.get(len(key_vars) - 1)
            if key_position is None:
                continue
            value_position = _match_event_value_position(emissions, value_var, event_signature, key_position)
            specs.append(
                {
                    "mapping_name": mapping_name,
                    "event_signature": event_signature,
                    "event_name": event_name,
                    "key_position": key_position,
                    "key_positions_by_index": key_positions_by_index,
                    "indexed_positions": list(indexed_positions),
                    "direction": direction,
                    "writer_function": getattr(function, "full_name", getattr(function, "name", "")),
                    "value_position": value_position,
                }
            )
    return specs


def _match_event_value_position(
    emissions: list[tuple[str, list[Any], list[int]]],
    value_var: Any,
    event_signature: str,
    key_position: int,
) -> int | None:
    """Locate the value argument's position in the matched event.

    Used by D.1+: when ``map[k] = v`` writes are mirrored by an event
    like ``OwnerSet(addr indexed, uint256)``, the value lives at a
    different arg position than the key. We match by identity against
    the value-var that drove the write; fall back to ``None`` so
    consumers (durable indexer, on-demand replay) skip value-aware
    decoding rather than guessing.
    """
    if value_var is None:
        return None
    target_name = getattr(value_var, "name", None)
    for sig, args, _indexed in emissions:
        if sig != event_signature:
            continue
        for idx, arg in enumerate(args):
            if idx == key_position:
                continue
            if arg is value_var:
                return idx
            if target_name is not None and getattr(arg, "name", None) == target_name:
                return idx
    return None
