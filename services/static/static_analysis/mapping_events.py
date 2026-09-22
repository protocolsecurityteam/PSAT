"""Discover mapping writes that can be replayed from emitted events."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from .shared import _contract_functions


class WriterEventSpec(TypedDict):
    mapping_name: str
    event_signature: str
    event_name: str
    key_position: int
    key_positions_by_index: dict[int, int]
    indexed_positions: list[int]
    direction: Literal["add", "remove", "set"]
    writer_function: str
    # Position of the assigned value in the event's args (D.1). For
    # ``add``/``remove`` semantics the assigned value is implicit so
    # this is ``None``; for ``set`` semantics it points at the topic
    # / data slot carrying the new value, e.g. ``OwnerSet(addr, val)``
    # would record ``key_position=0, value_position=1``.
    value_position: int | None


class _EventMetadata(TypedDict):
    signature: str
    arg_types: list[str]
    indexed_positions: list[int]


def _ir_name(ir: Any) -> str:
    return type(ir).__name__ if ir is not None else ""


def _var_name(item: Any) -> str:
    if item is None:
        return ""
    return getattr(item, "name", None) or str(item)


def _is_mapping_type(variable: Any) -> bool:
    type_str = str(getattr(variable, "type", "") or "")
    return type_str.startswith("mapping(")


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


def _direction_of_write(value_var: Any) -> Literal["add", "remove", "set"] | None:
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
    """Canonical ABI type string used to derive the event topic0.

    The topic0 keccak must hash the *canonical* ABI signature (the one solc
    emits), where every non-elementary type is collapsed to its ABI head:
    contract/interface -> ``address``, enum -> ``uint8``, user-defined value
    type -> its underlying elementary type, array -> ``canonical(elem)[N?]``,
    struct -> ``(canonical members...)``. Slither's ``str(type)`` and
    ``Event.full_name`` instead carry the *declared* names (``IGem``,
    ``Vat.Status``, ``IGem[]``), so they are non-canonical and must not reach
    the keccak. Recurse so nested shapes (``Foo[]``, ``Foo[][2]``, structs of
    interfaces) canonicalize fully.
    """
    if type_obj is None:
        return "unknown"
    # Imported lazily to keep this module importable without Slither side
    # effects, mirroring the rest of the static pipeline's type handling.
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
        # ``type Foo is uint256`` — collapse to the underlying elementary type.
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
    # Build the canonical signature from ``arg_types`` (Contract->address,
    # Enum->uint8, recursive arrays/structs/UDVT). ``Event.full_name`` carries
    # the *declared* type names (``IGem``, ``Vat.Status``, ``IGem[]``), so its
    # keccak never matches the on-chain topic0 whenever a parameter is a
    # non-elementary type. Derive from ``elems`` whenever the event has
    # parameters; only fall back to ``full_name`` when ``elems`` is unavailable
    # (no params, or a producer that could not introspect them).
    if name and elems:
        signature = f"{name}({','.join(arg_types)})"
    else:
        signature = (getattr(event, "full_name", "") or "") or (f"{name}()" if name else "")
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


def member_witness_record(spec: WriterEventSpec) -> dict[str, Any]:
    """JSON-clean correspondence record for the monitoring plane's F3
    qualification — the proof that an occurrence of this event names the entry
    that was written.

    Sibling of ``predicate_artifacts._value_writer_spec`` rather than a reuse of
    it: that one hard-codes ``direction: "set"`` and requires a non-null
    ``value_position``, which drops exactly the ``add``/``remove`` specs
    (``DenyFrom(address)``) whose whole payload is the key. Here the real
    direction rides and ``value_position`` may be ``None`` — an event that
    states no value states none, and the consumer publishes a key and a
    direction without inventing a value.

    ``key_positions_by_index`` is dropped for the same reason it is dropped
    there: its ``int`` keys do not survive a JSONB round-trip.
    """
    value_position = spec.get("value_position")
    return {
        "mapping_name": spec["mapping_name"],
        "event_signature": spec["event_signature"],
        "event_name": spec["event_name"],
        "key_position": int(spec["key_position"]),
        "indexed_positions": [int(pos) for pos in spec.get("indexed_positions") or []],
        "direction": spec["direction"],
        "writer_function": spec.get("writer_function") or "",
        "value_position": int(value_position) if value_position is not None else None,
    }


def multi_entry_writers(contract: Any) -> set[tuple[str, str]]:
    """``(mapping_name, writer_function)`` pairs where ONE call writes more than
    one entry of the mapping.

    ``discover_mapping_writer_events`` deduplicates on
    ``(mapping, event_signature, direction)``, so an ERC-20 ``transfer`` —
    ``balances[from]`` and ``balances[to]`` under a single ``Transfer`` — keeps
    only the first of the two writes and yields a record that names one entry.
    A consumer publishing that record's key would name the sender and say
    nothing about the recipient, while claiming to describe the event.
    """
    out: set[tuple[str, str]] = set()
    for function in _contract_functions(contract):
        if getattr(function, "is_constructor", False):
            continue
        keys_by_mapping: dict[str, set[str]] = {}
        for mapping_name, key_vars, _value in _extract_index_writes(function):
            if not mapping_name or not key_vars:
                continue
            keys_by_mapping.setdefault(mapping_name, set()).add(_var_name(key_vars[-1]))
        name = getattr(function, "full_name", getattr(function, "name", ""))
        for mapping_name, keys in keys_by_mapping.items():
            if len(keys) > 1:
                out.add((mapping_name, name))
    return out


def member_witness_records(contract: Any) -> dict[tuple[str, str], dict[str, Any]]:
    """``(mapping_name, event_signature)`` → the one correspondence record that
    pair proves.

    Two omissions, each because the event does not state a single entry change:

      * a pair matched by several specs that disagree on key/value position or
        direction — the event says an entry moved without saying which way; and
      * a pair whose writer changes SEVERAL entries of the mapping in one call
        (:func:`multi_entry_writers`) — the record names one of them, and a
        one-entry claim over a two-entry write is a false description of the
        event, not a partial one.
    """
    multi_entry = multi_entry_writers(contract)
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for spec in discover_mapping_writer_events(contract):
        mapping_name = spec.get("mapping_name")
        signature = spec.get("event_signature")
        if not mapping_name or not signature:
            continue
        if (mapping_name, spec.get("writer_function") or "") in multi_entry:
            continue
        by_pair.setdefault((mapping_name, signature), []).append(member_witness_record(spec))
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for pair, records in by_pair.items():
        distinct = {(r["key_position"], r["value_position"], r["direction"]) for r in records}
        if len(distinct) == 1:
            out[pair] = records[0]
    return out


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
