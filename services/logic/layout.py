"""Storage locations and packing derived from compiler types."""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from .terms import _FOLD, Term, const, mk, mk_op

_LOCATED = 100_000


def _size(type_: Any) -> int | None:
    """Bytes a value of ``type_`` occupies in a slot; ``None`` for types that take whole slots (structs, arrays,
    mappings)."""
    from slither.core.declarations import Contract, Enum
    from slither.core.solidity_types import ElementaryType, FunctionType, UserDefinedType

    if isinstance(type_, FunctionType):
        return getattr(type_, "_psat_function_storage_width", None)

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
            return max(1, ((len(type_.type.values) - 1).bit_length() + 7) // 8)
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
    from slither.core.solidity_types import ArrayType, FunctionType, UserDefinedType

    if isinstance(type_, FunctionType) and _size(type_) is None:
        raise ValueError("unsupported:function_storage_visibility")

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
    from .abi_values import abi_name

    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        name = abi_name(type_)
        if name is None:
            return None
        if name.startswith("bytes") and name not in ("bytes", "bytes32"):
            return (value % 2 ** (8 * int(name[5:]))).to_bytes(int(name[5:]), "big").ljust(32, b"\0")
        return (value % 2**256).to_bytes(32, "big")
    if isinstance(value, (str, bytes)):
        raw = value.encode() if isinstance(value, str) else value
        name = abi_name(type_)
        if name is None:
            return None
        if name.startswith("bytes") and name != "bytes":
            return raw.ljust(32, b"\0") if len(raw) == int(name[5:]) else None
        return raw if name in ("bytes", "string") else None
    return None


def storage_name(contract: Any, variable: Any) -> str:
    """Keep distinct compiler declarations distinct even when old Solidity permits shadowing."""
    names = contract.__dict__.get("_psat_storage_names")
    if names is None:
        from collections import Counter

        counts = Counter(v.name for v in contract.state_variables_ordered)
        names = {
            id(v): f"{v.canonical_name}#{i}" if counts[v.name] > 1 else v.name
            for i, v in enumerate(contract.state_variables_ordered)
        }
        contract.__dict__["_psat_storage_names"] = names
    if id(variable) in names:
        return names[id(variable)]
    matches = [v for v in contract.state_variables_ordered if v.name == variable.name]
    if len(matches) > 1:
        matches = [
            v for v in matches if v.contract is variable.contract and v.source_mapping == variable.source_mapping
        ]
        if len(matches) != 1:
            raise ValueError("unsupported:ambiguous_storage_declaration")
        return names[id(matches[0])]
    return variable.name


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
    root = _root(contract, var_name)
    if root is None or not isinstance(root[0], int):
        return None
    return _walk(contract, *root, path)


def locate_symbolic(contract: Any, var_name: Any, path: tuple) -> tuple[Term, Term, Any] | None:
    """Compiler-derived slot/byte-offset expressions; key/index values remain symbolic.

    This locates cells, not execution reachability: array bounds and storage validity
    remain in the caller's formula. It uses the same layout walk as concrete reads.
    """
    root = _root(contract, var_name)
    if root is None:
        return None
    slot, offset, type_ = root
    return _walk(contract, mk("conv", "uint256", _term(slot)), _term(offset), type_, path)


def _root(contract: Any, var_name: Any) -> tuple[Any, int, Any] | None:
    _compiler_metadata(contract.compilation_unit)

    # ``state_variables`` leaves out a parent's private variables; the storage layout doesn't.
    if isinstance(var_name, tuple) and var_name[0] == "slot":
        # A pointer rooted at a raw slot (namespaced storage): ``var_name`` is ("slot", slot, struct name), already
        # evaluated to an int slot by the caller.
        slot, offset, type_ = var_name[1], 0, _named_type(contract, var_name[2])
        if not isinstance(slot, (int, Term)) or type_ is None:
            return None
        return slot % 2**256 if isinstance(slot, int) else slot, offset, type_
    var = next((v for v in contract.state_variables_ordered if storage_name(contract, v) == var_name), None)
    if var is None:
        return None
    found = _layout(contract).get(id(var))
    if found is None:
        return None
    slot, offset = found
    return slot, offset, var.type


def _layout(contract: Any) -> dict[int, tuple[int, int]]:
    """id(variable) -> (slot, byte offset) of the contract's storage, in declaration order (bases first), packed."""
    cached = contract.__dict__.get("_psat_layout")
    if cached is None:
        cached = _pack_layout(contract)
        contract.__dict__["_psat_layout"] = cached
    return cached


def _pack_layout(contract: Any) -> dict[int, tuple[int, int]]:
    out: dict[int, tuple[int, int]] = {}
    slot, used = contract.custom_storage_layout or 0, 0
    for var in contract.storage_variables_ordered:
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


def _compiler_metadata(unit: Any) -> None:
    """Cache compiler declaration, operand and assembly facts lost by the frontend.

    EVM storage uses 24 bytes for external pointers and 8 for internal pointers.
    Slither reports 24 for both. Binary common types likewise cannot be inferred
    from an assigned temporary's width. Facts are indexed by compiler source spans.
    """
    if getattr(unit, "_psat_compiler_metadata", False):
        return
    from slither.core.solidity_types import ArrayType, FunctionType, MappingType

    declarations, references, identifiers, externals, binary_types = {}, {}, {}, {}, {}
    for filename, source in unit.crytic_compile_compilation_unit.source_units.items():
        pending = [source.ast]
        while pending:
            node = pending.pop()
            if isinstance(node, list):
                pending.extend(node)
            elif isinstance(node, dict):
                if node.get("nodeType", node.get("name")) == "BinaryOperation" and "src" in node:
                    start, length, _ = node["src"].split(":")
                    common = node.get("commonType", node.get("attributes", {}).get("commonType"))
                    if isinstance(common, dict):
                        common = common.get("typeString")
                    if isinstance(common, str):
                        binary_types[(filename.absolute, int(start), int(length))] = common
                if node.get("nodeType", node.get("name")) == "VariableDeclaration" and "src" in node:
                    start, length, _ = node["src"].split(":")
                    declarations[(filename.absolute, int(start), int(length))] = node
                    identifiers[node.get("id")] = (filename.absolute, int(start), int(length))
                if "declaration" in node and "src" in node and ("isSlot" in node or "isOffset" in node):
                    start, length, _ = node["src"].split(":")
                    key = filename.absolute, int(start), int(length)
                    suffix = "slot" if node.get("isSlot") else "offset" if node.get("isOffset") else None
                    externals[key] = node["declaration"], suffix
                    if suffix is not None:
                        references[key] = suffix
                external = node.get("externalReferences", ())
                for reference in external.values() if isinstance(external, dict) else external:
                    if not isinstance(reference, dict) or reference.get("isSlot", False) == reference.get(
                        "isOffset", False
                    ):
                        continue
                    start, length, _ = reference["src"].split(":")
                    references[(filename.absolute, int(start), int(length))] = (
                        "slot" if reference.get("isSlot") else "offset"
                    )
                pending.extend(v for v in node.values() if isinstance(v, (dict, list)))

    def bind(type_, node):
        children = node.get("children", ())
        if isinstance(type_, FunctionType):
            visibility = node.get("visibility", node.get("attributes", {}).get("visibility"))
            width = {"external": 24, "internal": 8}.get(visibility)
            old = getattr(type_, "_psat_function_storage_width", width)
            setattr(type_, "_psat_function_storage_width", width if width == old else None)
        elif isinstance(type_, ArrayType):
            bind(type_.type, node.get("baseType", children[0] if children else {}))
        elif isinstance(type_, MappingType):
            bind(type_.type_from, node.get("keyType", children[0] if children else {}))
            bind(type_.type_to, node.get("valueType", children[1] if len(children) > 1 else {}))

    variables = [v for c in unit.contracts for v in c.state_variables_ordered]
    structures = [*unit.structures_top_level, *(s for c in unit.contracts for s in c.structures)]
    variables.extend(v for s in structures for v in s.elems_ordered)
    for variable in variables:
        span = variable.source_mapping
        node = declarations.get((span.filename.absolute, span.start, span.length), {})
        children = node.get("children", ())
        bind(variable.type, node.get("typeName", children[0] if children else {}))
    unit._psat_compiler_metadata = True
    unit._psat_binary_types = binary_types
    unit._psat_storage_references = references
    unit._psat_assembly_references = {
        key: (identifiers.get(declaration), suffix) for key, (declaration, suffix) in externals.items()
    }


def binary_operation_type(unit: Any, expression: Any) -> str | None:
    """The compiler's common operand type, before assignment widens the result."""
    _compiler_metadata(unit)
    span = getattr(expression, "source_mapping", None)
    if span is None:
        return None
    return unit._psat_binary_types.get((span.filename.absolute, span.start, span.length))


def assembly_bindings(contract: Any, function: Any, node: Any) -> dict:
    """Compiler-resolved external names for this exact legacy assembly block."""
    unit = contract.compilation_unit
    _compiler_metadata(unit)
    variables = [
        *function.parameters,
        *function.returns,
        *function.variables,
        *contract.state_variables,
        *getattr(unit, "variables_top_level", ()),
    ]
    variables.extend(v for c in unit.contracts for v in c.state_variables)
    declared, starts = {}, {}
    for variable in variables:
        span = variable.source_mapping
        declared.setdefault((span.filename.absolute, span.start, span.length), variable)
        choices = starts.setdefault((span.filename.absolute, span.start), {})
        choices[id(variable)] = variable
    span = node.source_mapping
    source = unit.core.source_code[span.filename.absolute].encode("utf-8")
    found = {}
    for (filename, start, length), (declaration, suffix) in unit._psat_assembly_references.items():
        if filename != span.filename.absolute or not span.start <= start < start + length <= span.start + span.length:
            continue
        name = source[start : start + length].decode("utf-8")
        variable = declared.get(declaration)
        if variable is None and declaration is not None:
            # Slither sometimes attaches the initializer statement's full span to a
            # local; its declaration still starts at this exact compiler offset.
            candidates = [
                v for v in starts.get(declaration[:2], {}).values() if v.source_mapping.length >= declaration[2]
            ]
            if len(candidates) == 1:
                variable = candidates[0]
        if variable is None:
            raise ValueError("unsupported:assembly_declaration")
        binding = variable, suffix
        if name in found and found[name] != binding:
            raise ValueError("unsupported:assembly_name_scope")
        found[name] = binding
    return found


def storage_reference(unit: Any, expression: Any) -> str | None:
    """The compiler's suffix for this exact assembly operand, not its flattened IR name."""
    _compiler_metadata(unit)
    span = getattr(expression, "source_mapping", None)
    if span is None:
        return None
    found = unit._psat_storage_references.get((span.filename.absolute, span.start, span.length))
    from slither.core.expressions import Identifier

    if (
        found is None
        and isinstance(expression, Identifier)
        and str(span.content).strip().endswith((".slot", ".offset"))
    ):
        return "unresolved"
    return found


def _named_type(contract: Any, name: str) -> Any:
    from slither.core.declarations import Structure
    from slither.core.solidity_types import UserDefinedType

    unit = contract.compilation_unit
    structures = {id(s): s for s in [*unit.structures_top_level, *(s for c in unit.contracts for s in c.structures)]}
    matches = [s for s in structures.values() if s.canonical_name == name]
    if not matches:
        matches = [s for s in structures.values() if s.name == name]
    if matches:
        return UserDefinedType(matches[0]) if len(matches) == 1 and isinstance(matches[0], Structure) else None
    # Any other type (``mapping(uint256 => Request)`` at an unstructured position): as some declaration spells it.
    declared = contract.__dict__.get("_psat_declared_types")
    if declared is None:
        declared = {}
        for c in unit.contracts:
            for v in [*c.state_variables, *(x for f in c.functions_and_modifiers for x in f.variables)]:
                key = str(v.type)
                if key in declared and declared[key] is not v.type and not _same_storage_type(declared[key], v.type):
                    declared[key] = None  # Identical names can refer to different imported declarations.
                else:
                    declared.setdefault(key, v.type)
        contract.__dict__["_psat_declared_types"] = declared
    return declared.get(name)


def _same_storage_type(a: Any, b: Any) -> bool:
    """Frontend equality omits function visibility, including inside containers."""
    from slither.core.solidity_types import ArrayType, FunctionType, MappingType

    if a != b:
        return False
    if isinstance(a, FunctionType):
        return _size(a) is not None and _size(a) == _size(b)
    if isinstance(a, ArrayType):
        return _same_storage_type(a.type, b.type)
    if isinstance(a, MappingType):
        return _same_storage_type(a.type_from, b.type_from) and _same_storage_type(a.type_to, b.type_to)
    return True


def _term(value: Any) -> Term:
    return value if isinstance(value, Term) else const(value)


def _slot_op(op: str, a: Any, b: Any) -> Any:
    # Concrete snapshot accounting can visit millions of cells. Do not intern a
    # formula node for every cell while doing plain integer address arithmetic.
    return mk_op(op, (_term(a), _term(b))) if isinstance(a, Term) or isinstance(b, Term) else _FOLD[op](a, b)


def _hashed_slot(slot: Any, key: Any = None, key_type: Any = None) -> Any:
    """Solidity's mapping/array slot hashing, retaining declared key encoding."""
    if not isinstance(slot, Term):
        prefix = b"" if key_type is None else _key_bytes(key, key_type)
        return None if prefix is None else int.from_bytes(keccak(prefix + slot.to_bytes(32, "big")), "big")
    from .abi_values import abi_name

    words = (mk("conv", "uint256", slot),)
    encoding = "abi.encode"
    if key_type is not None:
        name = abi_name(key_type)
        if name is None:
            return None
        key = key if isinstance(key, Term) else const(key, name)
        if name in ("bytes", "string"):
            # Dynamic mapping keys contribute their raw bytes, without length/offset words.
            encoding = "abi.encodePacked"
        else:
            key = mk("conv", name, key)
        words = (key, *words)
    return mk("hash", "keccak256", (mk("enc", encoding, words),))


def _walk(contract: Any, slot: Any, offset: Any, type_: Any, path: tuple) -> tuple[Any, Any, Any] | None:
    from slither.core.declarations import Structure
    from slither.core.solidity_types import ArrayType, MappingType, UserDefinedType

    for kind, step in path:
        if kind == "k" and isinstance(type_, MappingType):
            slot = _hashed_slot(slot, step, type_.type_from)
            if slot is None:
                return None
            offset, type_ = const(0) if isinstance(slot, Term) else 0, type_.type_to
        elif kind == "k" and isinstance(type_, ArrayType):
            if not isinstance(step, (int, Term)) or (isinstance(step, Term) and not isinstance(slot, Term)):
                return None
            base = slot if type_.length is not None else _hashed_slot(slot)
            if isinstance(slot, Term):
                step = mk("conv", "uint256", _term(step))
            size = _size(type_.type)
            if size is None:
                slot = _slot_op("add", base, _slot_op("mul", step, _slots(type_.type)))
                offset = const(0) if isinstance(slot, Term) else 0
            else:
                per = 32 // size
                slot = _slot_op("add", base, _slot_op("div", step, per))
                offset = _slot_op("mul", _slot_op("mod", step, per), size)
            type_ = type_.type
        elif kind == "f" and step == "length" and isinstance(type_, ArrayType) and type_.length is None:
            return slot, const(0) if isinstance(slot, Term) else 0, None
        elif kind == "f" and isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
            fields = _struct_fields(type_.type)
            if step not in fields:
                return None
            extra, offset, type_ = fields[step]
            slot = _slot_op("add", slot, extra)
            if isinstance(slot, Term):
                offset = const(offset)
        else:
            return None
    return slot, offset, type_


def _decode_word(word: int, offset: int, type_: Any) -> Any:
    from .abi_values import abi_name

    size = _size(type_) if type_ is not None else 32
    if size is None:
        return word
    value = (word >> (8 * offset)) % 2 ** (8 * size)
    name = abi_name(type_) if type_ is not None else "uint256"
    if name == "bool":
        return value != 0
    if name is not None and name.startswith("int"):
        bits = 8 * size
        return value - 2**bits if value >= 2 ** (bits - 1) else value
    return value
