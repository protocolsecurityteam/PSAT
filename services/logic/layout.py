"""Storage locations and packing derived from compiler types."""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

_LOCATED = 100_000


def _size(type_: Any) -> int | None:
    """Bytes a value of ``type_`` occupies in a slot; ``None`` for types that take whole slots (structs, arrays,
    mappings)."""
    from slither.core.declarations import Contract, Enum
    from slither.core.solidity_types import ElementaryType, UserDefinedType

    if isinstance(type_, ElementaryType):
        name = type_.name
        if name in ("address", "address payable"):
            return 20
        if name == "bool":
            return 1
        for prefix in ("uint", "int"):
            if name.startswith(prefix):
                return int(name[len(prefix) :] or 256) // 8
        if name.startswith("bytes") and name != "bytes":
            return int(name[5:])
        return None
    if isinstance(type_, UserDefinedType):
        if isinstance(type_.type, Contract):
            return 20
        if isinstance(type_.type, Enum):
            return 1
    underlying = getattr(type_, "underlying_type", None)  # a user-defined value type (``type Duration is uint32``)
    if underlying is not None:
        return _size(underlying)
    return None


def _struct_fields(structure: Any) -> dict[str, tuple[int, int, Any]]:
    """Field -> (slot offset, byte offset, type), packed as the compiler packs; remembered on the structure."""
    cached = structure.__dict__.get("_psat_fields")
    if cached is None:
        cached = structure.__dict__["_psat_fields"] = _pack_fields(structure)
    return cached


def _pack_fields(structure: Any) -> dict[str, tuple[int, int, Any]]:
    out: dict[str, tuple[int, int, Any]] = {}
    slot, used = 0, 0
    for member in structure.elems_ordered:
        size = _size(member.type)
        if size is None:
            if used:
                slot, used = slot + 1, 0
            out[member.name] = (slot, 0, member.type)
            slot += _slots(member.type)
            continue
        if used + size > 32:
            slot, used = slot + 1, 0
        out[member.name] = (slot, used, member.type)
        used += size
    return out


def _slots(type_: Any) -> int:
    from slither.core.declarations import Structure
    from slither.core.solidity_types import ArrayType, UserDefinedType

    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
        fields = _struct_fields(type_.type)
        last = max(fields.values(), key=lambda f: f[0], default=(0, 0, None))
        return last[0] + (_slots(last[2]) if _size(last[2]) is None and last[2] is not None else 1)
    if isinstance(type_, ArrayType) and type_.length is not None:
        size = _size(type_.type)
        literal = getattr(type_, "length_value", None)  # ``bytes32[TREE_DEPTH]``: the constant, evaluated
        length = int(str(literal.value if literal is not None else type_.length), 0)
        if size is None:
            return length * _slots(type_.type)
        per = 32 // size
        return (length + per - 1) // per
    return 1


def _key_bytes(value: Any, type_: Any) -> bytes | None:
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        name = str(type_)
        if name.startswith("bytes") and name not in ("bytes", "bytes32"):
            return (value % 2 ** (8 * int(name[5:]))).to_bytes(int(name[5:]), "big").ljust(32, b"\0")
        return (value % 2**256).to_bytes(32, "big")
    if isinstance(value, str):
        return value.encode()
    return None


def locate(contract: Any, var_name: Any, path: tuple) -> tuple[int, int, Any] | None:
    """(slot, byte offset, type) of ``contract.var_name`` followed by concrete ``path`` steps; remembered per
    contract, since every guess at the arguments asks again."""
    memo = contract.__dict__.setdefault("_psat_located", {})
    key = (var_name, path)
    try:
        return memo[key]
    except KeyError:
        pass
    except TypeError:
        return _locate(contract, var_name, path)  # an unhashable step: computed every time
    if len(memo) >= _LOCATED:
        memo.clear()
    memo[key] = _locate(contract, var_name, path)
    return memo[key]


def _locate(contract: Any, var_name: Any, path: tuple) -> tuple[int, int, Any] | None:

    # ``state_variables`` leaves out a parent's private variables; the storage layout doesn't.
    if isinstance(var_name, tuple) and var_name[0] == "slot":
        # A pointer rooted at a raw slot (namespaced storage): ``var_name`` is ("slot", slot, struct name), already
        # evaluated to an int slot by the caller.
        slot, offset, type_ = var_name[1], 0, _named_type(contract, var_name[2])
        if not isinstance(slot, int) or type_ is None:
            return None
        return _walk(contract, slot, offset, type_, path)
    var = next((v for v in contract.state_variables_ordered if v.name == var_name), None)
    if var is None:
        return None
    try:
        slot, offset = contract.compilation_unit.storage_layout_of(contract, var)
    except KeyError:
        # Slither has no layout for this contract (several compilation units): packed here, as the compiler does.
        found = _layout(contract).get(id(var))
        if found is None:
            return None
        slot, offset = found
    return _walk(contract, slot, offset, var.type, path)


def _layout(contract: Any) -> dict[int, tuple[int, int]]:
    """id(variable) -> (slot, byte offset) of the contract's storage, in declaration order (bases first), packed."""
    cached = contract.__dict__.get("_psat_layout")
    if cached is None:
        try:
            cached = _pack_layout(contract)
        except ValueError:
            cached = {}  # a size the types don't give (an unevaluated array length): no layout, reads unknown
        contract.__dict__["_psat_layout"] = cached
    return cached


def _pack_layout(contract: Any) -> dict[int, tuple[int, int]]:
    out: dict[int, tuple[int, int]] = {}
    slot, used = 0, 0
    for var in contract.state_variables_ordered:
        if var.is_constant or var.is_immutable:
            continue
        size = _size(var.type)
        if size is None:
            if used:
                slot, used = slot + 1, 0
            out[id(var)] = (slot, 0)
            slot += _slots(var.type)
            continue
        if used + size > 32:
            slot, used = slot + 1, 0
        out[id(var)] = (slot, used)
        used += size
    return out


def _named_type(contract: Any, name: str) -> Any:
    from slither.core.declarations import Structure
    from slither.core.solidity_types import UserDefinedType

    unit = contract.compilation_unit
    for structure in [*unit.structures_top_level, *(s for c in unit.contracts for s in c.structures)]:
        if structure.canonical_name == name or structure.name == name:
            return UserDefinedType(structure) if isinstance(structure, Structure) else None
    # Any other type (``mapping(uint256 => Request)`` at an unstructured position): as some declaration spells it.
    declared = contract.__dict__.get("_psat_declared_types")
    if declared is None:
        declared = {}
        for c in unit.contracts:
            for v in [*c.state_variables, *(x for f in c.functions_and_modifiers for x in f.variables)]:
                declared.setdefault(str(v.type), v.type)
        contract.__dict__["_psat_declared_types"] = declared
    return declared.get(name)


def _walk(contract: Any, slot: int, offset: int, type_: Any, path: tuple) -> tuple[int, int, Any] | None:
    from slither.core.declarations import Structure
    from slither.core.solidity_types import ArrayType, MappingType, UserDefinedType

    for kind, step in path:
        if kind == "k" and isinstance(type_, MappingType):
            key = _key_bytes(step, type_.type_from)
            if key is None:
                return None
            slot = int.from_bytes(keccak(key + slot.to_bytes(32, "big")), "big")
            offset, type_ = 0, type_.type_to
        elif kind == "k" and isinstance(type_, ArrayType):
            if not isinstance(step, int):
                return None
            base = slot if type_.length is not None else int.from_bytes(keccak(slot.to_bytes(32, "big")), "big")
            size = _size(type_.type)
            if size is None:
                slot, offset = (base + step * _slots(type_.type)) % 2**256, 0
            else:
                per = 32 // size
                slot, offset = (base + step // per) % 2**256, (step % per) * size
            type_ = type_.type
        elif kind == "f" and step == "length" and isinstance(type_, ArrayType) and type_.length is None:
            return slot, 0, None
        elif kind == "f" and isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
            fields = _struct_fields(type_.type)
            if step not in fields:
                return None
            extra, offset, type_ = fields[step]
            slot = (slot + extra) % 2**256
        else:
            return None
    return slot, offset, type_


def _decode_word(word: int, offset: int, type_: Any) -> Any:
    size = _size(type_) if type_ is not None else 32
    if size is None:
        return word
    value = (word >> (8 * offset)) % 2 ** (8 * size)
    if str(type_) == "bool":
        return value != 0
    if str(type_).startswith("int"):
        bits = 8 * size
        return value - 2**bits if value >= 2 ** (bits - 1) else value
    return value
