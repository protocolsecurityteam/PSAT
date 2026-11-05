"""Typed ABI value transfer between source-level call frames.

Words are cleaned by the encoder, then validated/decoded by the receiver. Aggregate
fields transfer by position, not their source-language names. Unsupported layouts
produce unknown values AND conditions, never an invented empty/successful call.
"""

from __future__ import annotations

import re
from typing import Any, cast

from .terms import FALSE, TRUE, Term, const, mk, mk_and, mk_cmp, mk_ite, mk_not, mk_op, mk_or, unknown


def abi_name(type_: Any, seen=frozenset(), *, library=False) -> str | None:
    """Canonical ABI type. Repeated sibling types are not recursive types."""
    from slither.core.declarations import Contract, Enum, Structure
    from slither.core.solidity_types import ArrayType, FunctionType, MappingType, TypeAlias, UserDefinedType

    if id(type_) in seen:
        return None
    seen = seen | {id(type_)}
    if isinstance(type_, TypeAlias):
        return abi_name(type_.underlying_type, seen, library=library)
    if isinstance(type_, UserDefinedType):
        if library:
            return str(type_)
        inner = type_.type
        if isinstance(inner, Contract):
            return "address"
        if isinstance(inner, Enum):
            bits = max(8, ((len(inner.values) - 1).bit_length() + 7) // 8 * 8)
            return f"uint{bits}"
        if isinstance(inner, Structure):
            fields = [abi_name(f.type, seen) for f in inner.elems_ordered]
            return "(" + ",".join(cast(list[str], fields)) + ")" if all(f is not None for f in fields) else None
    if isinstance(type_, ArrayType):
        from .lower import _fixed_length

        inner = abi_name(type_.type, seen, library=library)
        length = _fixed_length(type_) if type_.is_fixed_array else ""
        return f"{inner}[{length}]" if inner is not None and length is not None else None
    if isinstance(type_, MappingType) and library:
        return str(type_)  # Library storage pointers retain the internal mapping type names.
    if isinstance(type_, FunctionType):
        return "function"
    name = from_name(str(type_))[1]
    return None if name == "unsupported" else name


def getter_shape(type_: Any) -> tuple[tuple, Any]:
    """Declared getter keys and terminal type, before ABI encoding of caller expressions."""
    from slither.core.solidity_types import ArrayType, ElementaryType, MappingType

    keys = []
    while isinstance(type_, (ArrayType, MappingType)):
        keys.append(type_.type_from if isinstance(type_, MappingType) else ElementaryType("uint256"))
        type_ = type_.type_to if isinstance(type_, MappingType) else type_.type
    return tuple(keys), type_


def abi_signature(declaration: Any) -> str:
    """Function identity from declared types; scalar getter declarations retain their signature."""
    parameters = getattr(declaration, "parameters", getattr(declaration, "elems", None))
    if parameters is None:
        types, _ = getter_shape(declaration.type)
        keys = [abi_name(t) for t in types]
        if any(k is None for k in keys):
            raise ValueError(f"unsupported getter key: {declaration.type}")
        return declaration.name + "(" + ",".join(cast(list[str], keys)) + ")"
    library = bool(getattr(getattr(declaration, "contract_declarer", None), "is_library", False))
    types = []
    for parameter in parameters:
        name = abi_name(parameter.type, library=library)
        if name is None:
            raise ValueError(f"unsupported ABI signature type: {parameter.type}")
        types.append(name + (" storage" if library and getattr(parameter, "location", None) == "storage" else ""))
    return declaration.name + "(" + ",".join(types) + ")"


def folded_selector(expression: Any, contract: Any, width: int) -> int | None:
    """Resolve ABI identifiers from typed declarations, not frontend-folded literals."""
    from eth_utils.crypto import keccak
    from slither.core.declarations import Contract, CustomError, Event, Function, SolidityVariable
    from slither.core.solidity_types import UserDefinedType

    if expression.member_name == "interfaceId":
        arguments = getattr(expression.expression, "arguments", ())
        interface = getattr(arguments[0], "value", None) if len(arguments) == 1 else None
        if interface is None or not getattr(interface, "is_interface", False):
            return None
        value = 0
        for declaration in interface.functions_declared:
            if declaration.visibility in ("public", "external") and not declaration.is_constructor:
                value ^= int.from_bytes(keccak(text=abi_signature(declaration))[:4], "big")
        return value
    reference = expression.expression
    name = getattr(reference, "member_name", None) or getattr(getattr(reference, "value", None), "name", None)
    direct = getattr(reference, "value", None)
    if isinstance(direct, (Function, CustomError, Event)):
        declarations = [direct]
    else:
        parent = getattr(reference, "expression", None)
        namespace = getattr(parent, "value", None)
        if isinstance(namespace, SolidityVariable) and namespace.name == "this":
            namespace = contract
        type_ = getattr(namespace, "type", getattr(parent, "type", None))
        if isinstance(type_, UserDefinedType):
            namespace = type_.type
        if not isinstance(namespace, Contract):
            return None
        declarations = [
            *namespace.functions,
            *namespace.custom_errors,
            *namespace.events,
            *(v for v in namespace.state_variables if v.visibility == "public"),
        ]
    matches = set()
    for declaration in declarations:
        if declaration.name != name:
            continue
        if isinstance(declaration, Function) and (
            declaration.visibility not in ("public", "external") or declaration.is_shadowed
        ):
            continue
        if isinstance(declaration, Event) != (width == 32):
            continue
        matches.add(int.from_bytes(keccak(text=abi_signature(declaration))[:width], "big"))
    return matches.pop() if len(matches) == 1 else None


def describe(type_: Any, seen=frozenset()) -> tuple:
    from slither.core.declarations import Contract, Enum, Structure
    from slither.core.solidity_types import ArrayType, UserDefinedType

    if id(type_) in seen:
        return ("abi_type", "unsupported")
    seen = seen | {id(type_)}
    if isinstance(type_, UserDefinedType):
        if isinstance(type_.type, Contract):
            return ("abi_type", "address")
        if isinstance(type_.type, Enum):
            return ("abi_type", "enum", len(type_.type.values))
        if isinstance(type_.type, Structure):
            return (
                "abi_type",
                "tuple",
                tuple(("abi_field", f.name, describe(f.type, seen)) for f in type_.type.elems_ordered),
            )
    if isinstance(type_, ArrayType):
        from .lower import _fixed_length

        return ("abi_type", "array", describe(type_.type, seen), _fixed_length(type_))
    return from_name(str(type_))


def from_name(name: str | None) -> tuple:
    if name is None:
        return ("abi_type", "unsupported")
    name = {"uint": "uint256", "int": "int256", "address payable": "address"}.get(name, name)
    if name in ("bool", "address", "bytes", "string") or re.fullmatch(r"u?int\d+|bytes\d+", name or ""):
        return ("abi_type", name)
    return ("abi_type", "unsupported")


def inferred(value: Term) -> tuple:
    if value[0] in ("caller", "origin", "this", "signer"):
        return from_name("address")
    if value[0] == "sig":
        return from_name("bytes4")
    if value[0] == "conv":
        return from_name(value[1])
    if value[0] in ("arg", "const"):
        return from_name(value[2])
    return from_name(None)


def _range(t):
    kind = t[1]
    if kind == "enum":
        return 0, t[2]
    if kind == "bool":
        return 0, 2
    if kind == "address":
        return 0, 2**160
    if re.fullmatch(r"uint\d+", kind):
        return 0, 2 ** int(kind[4:])
    if re.fullmatch(r"int\d+", kind):
        return -(2 ** (int(kind[3:]) - 1)), 2 ** (int(kind[3:]) - 1)
    return None


def compatible(src: tuple, dst: tuple) -> bool:
    """Every clean source encoding is a valid target encoding; no independence assumptions."""
    a, b = src[1], dst[1]
    if "unsupported" in (a, b):
        return False
    if a == b == "tuple":
        return len(src[2]) == len(dst[2]) and all(compatible(x[2], y[2]) for x, y in zip(src[2], dst[2]))
    if a == b == "array":
        return src[3] == dst[3] and compatible(src[2], dst[2])
    if a in ("bytes", "string") or b in ("bytes", "string"):
        return a in ("bytes", "string") and b in ("bytes", "string")
    if a == b == "enum":
        return src[2] <= dst[2]
    if a == b:
        return True
    if b in ("uint256", "int256", "bytes32") and _scalar(src):
        return True
    r1, r2 = _range(src), _range(dst)
    if r1 and r2:
        return r2[0] <= r1[0] and r1[1] <= r2[1]
    if re.fullmatch(r"bytes\d+", a) and re.fullmatch(r"bytes\d+", b):
        return int(a[5:]) <= int(b[5:])
    return False


def _scalar(t):
    return t[1] in ("enum", "bool", "address") or bool(re.fullmatch(r"u?int\d+|bytes\d+", t[1]))


def total_encoder(t):
    if t[1] == "tuple":
        return all(total_encoder(f[2]) for f in t[2])
    if t[1] == "array":
        return total_encoder(t[2])
    return _scalar(t) and t[1] != "enum"


def static_words(type_):
    """Number of ABI words in a static type; dynamic layout is not guessed."""
    if _scalar(type_):
        return 1
    if type_[1] == "tuple":
        sizes = [static_words(f[2]) for f in type_[2]]
        return sum(s for s in sizes if s is not None) if all(s is not None for s in sizes) else None
    if type_[1] == "array" and type_[3] is not None:
        inner = static_words(type_[2])
        return type_[3] * inner if inner is not None else None
    return None


def static_memory_size(type_):
    """Bytes allocated by a fully static aggregate ABI memory decoder."""
    if _scalar(type_):
        return 0
    if type_[1] == "tuple":
        sizes = [static_memory_size(f[2]) for f in type_[2]]
        return 32 * len(sizes) + sum(s for s in sizes if s is not None) if all(s is not None for s in sizes) else None
    if type_[1] == "array" and type_[3] is not None:
        inner = static_memory_size(type_[2])
        return type_[3] * (32 + inner) if inner is not None else None
    return None


def static_word(value, type_, index):
    """One encoded return word, including fields/arrays before later return values."""
    from .lower import element, project

    count = static_words(type_)
    if count is None or not 0 <= index < count:
        return None
    if _scalar(type_):
        return _word(value, type_)[0]
    if type_[1] == "tuple":
        for _, name, field_type in type_[2]:
            width = static_words(field_type)
            assert width is not None
            if index < width:
                return static_word(project(value, (("f", name),)), field_type, index)
            index -= width
    else:
        width = static_words(type_[2])
        assert width is not None and width > 0
        return static_word(element(value, const(index // width)), type_[2], index % width)
    return None


def decode_static(words, type_, strict: bool | None = True):
    """Decode a complete static ABI value from raw words, retaining validation conditions."""
    size = static_words(type_)
    bad = unknown("unsupported:static_abi_decode")
    if size is None or len(words) != size or strict is None:
        return bad, bad
    if _scalar(type_):
        return _decode(words[0], type_, strict)
    fields = type_[2] if type_[1] == "tuple" else tuple(("abi_field", str(i), type_[2]) for i in range(type_[3]))
    values, guards, offset = [], [], 0
    for _, _, child in fields:
        width = static_words(child)
        assert width is not None
        value, guard = decode_static(words[offset : offset + width], child, strict)
        values.append(value)
        guards.append(guard)
        offset += width
    value = (
        mk("struct", tuple(f[1] for f in fields), tuple(values))
        if type_[1] == "tuple"
        else mk("array", const(len(values)), tuple(values))
    )
    return value, mk_and(guards)


def decode_buffer(value, types, strict: bool | None = True, *, short_guard: Term = FALSE):
    """Decode caller-expected static returns or abi.decode inputs from actual bytes."""
    from .memory import buffer_memory, memory_word

    if not types:
        return (), TRUE
    bad = unknown("unsupported:abi.decode_layout")
    if value[0] == "ite":
        a, ga = decode_buffer(value[2], types, strict, short_guard=short_guard)
        b, gb = decode_buffer(value[3], types, strict, short_guard=short_guard)
        return tuple(mk_ite(value[1], x, y) for x, y in zip(a, b)), mk_ite(value[1], ga, gb)
    widths = [static_words(t) for t in types]
    layout = buffer_memory(value)
    if layout is None or any(w is None for w in widths):
        return (bad,) * len(types), bad
    if 32 * sum(w for w in widths if w is not None) > layout[0]:
        return (bad,) * len(types), short_guard
    values, guards, offset = [], [], 0
    for type_, width in zip(types, widths):
        assert width is not None
        words = tuple(memory_word(layout[1], offset + i * 32) for i in range(width))
        if any(w is None for w in words):
            return (bad,) * len(types), bad
        decoded, guard = decode_static(words, type_, strict)
        values.append(decoded)
        guards.append(guard)
        offset += 32 * width
    return tuple(values), mk_and(guards)


def encoded_region(value, limit=1024):
    """Known byte layout as (length, (offset, big-endian word, width) chunks)."""
    from eth_utils.crypto import keccak

    from .terms import packed_width

    if value[0] == "conv" and value[1] in ("bytes", "string"):
        return encoded_region(value[2], limit)
    if value[0] == "const" and isinstance(value[1], (bytes, str)):
        data = value[1].encode() if isinstance(value[1], str) else value[1]
        if len(data) > limit:
            return None
        return len(data), tuple(
            (i, const(int.from_bytes(data[i : i + 32].ljust(32, b"\0"), "big")), min(32, len(data) - i))
            for i in range(0, len(data), 32)
        )
    if value[0] != "enc":
        return None
    name, args = value[1:3]
    chunks, offset = [], 0
    if name == "abi.encodePacked":
        for arg in args:
            width = packed_width(arg)
            if width is None or width > 32 or offset + width > limit:
                return None
            word = (
                (arg if arg[:2] == ("conv", "uint256") else mk("conv", "uint256", arg))
                if width == 32
                else mk_op("shl", (arg, const(256 - 8 * width)))
            )
            chunks.append((offset, word, width))
            offset += width
        return offset, tuple(chunks)
    if name not in ("abi.encode", "abi.encodeWithSelector", "abi.encodeWithSignature"):
        return None
    if name != "abi.encode":
        if not args:
            return None
        head, args = args[0], args[1:]
        if name == "abi.encodeWithSignature":
            if head[0] != "const" or not isinstance(head[1], str):
                return None
            head = const(int.from_bytes(keccak(text=head[1])[:4], "big"), "bytes4")
        chunks.append((0, static_word(head, from_name("bytes4"), 0), 4))
        offset = 4
    types = value[3] if len(value) > 3 else tuple(inferred(v) for v in args)
    if len(args) != len(types):
        return None
    for arg, type_ in zip(args, types):
        size = static_words(type_)
        if size is None or offset + 32 * size > limit:
            return None
        for i in range(size):
            word = static_word(arg, type_, i)
            if word is None:
                return None
            chunks.append((offset, word, 32))
            offset += 32
    return offset, tuple(chunks)


def _word(value: Term, t: tuple) -> tuple[Term, Term]:
    kind = t[1]
    if kind == "enum":
        return mk("conv", "uint256", value), mk_and([mk_cmp("le", const(0), value), mk_cmp("lt", value, const(t[2]))])
    if kind == "bool":
        clean = value if value[:2] == ("conv", "bool") else mk("conv", "bool", value)
    elif kind == "address":
        clean = value if value[:2] == ("conv", "address") else mk("conv", "address", value)
    elif kind.startswith("bytes"):
        bits = 8 * int(kind[5:])
        clean = value if value[:2] == ("conv", f"uint{bits}") else mk("conv", f"uint{bits}", value)
        return mk_op("shl", (clean, const(256 - bits))), TRUE
    else:
        clean = value if value[:2] == ("conv", kind) else mk("conv", kind, value)
    return mk("conv", "uint256", clean), TRUE


def checked_return_size(contract: Any) -> bool | None:
    """Whether the caller's compiler checks actual returndata size before static decoding."""
    unit = getattr(contract, "compilation_unit", None)
    version = getattr(getattr(unit, "compiler_version", None), "version", None)
    match = re.match(r"(\d+)\.(\d+)", version or "")
    if match is None:
        return None
    evm = str((getattr(unit, "context", {}) or {}).get("psat_evm_version", "") or "").lower()
    # Solc 0.5+ uses actual return length only when RETURNDATASIZE is available.
    return (int(match[1]), int(match[2])) >= (0, 5) and evm not in {
        "homestead",
        "tangerinewhistle",
        "spuriousdragon",
    }


def strict_decoder(contract: Any, scope: Any = None) -> bool | None:
    """Whether ``contract``'s code decodes with ABI coder v2, which reverts on a word out of its type's range, rather
    than v1, which cleans it; ``None`` where its sources mix the two or don't say."""
    version = getattr(getattr(getattr(contract, "compilation_unit", None), "compiler_version", None), "version", None)
    match = re.match(r"(\d+)\.(\d+)", version or "")
    if contract is None or match is None:
        return None
    default = (int(match[1]), int(match[2])) >= (0, 8)
    coders = set()
    for scope in (
        [scope]
        if scope is not None
        else {id(c.file_scope): c.file_scope for c in (contract, *contract.inheritance)}.values()
    ):
        directives = [tuple(p.directive) for p in getattr(scope, "pragmas", ())]
        if any(d[:1] == ("abicoder",) for d in directives):
            coders.add(any(d == ("abicoder", "v2") for d in directives))
        else:
            coders.add(default or any(d == ("experimental", "ABIEncoderV2") for d in directives))
    return coders.pop() if len(coders) == 1 else None


def _decode(word: Term, t: tuple, strict: bool = True) -> tuple[Term, Term]:
    kind = t[1]
    if (
        kind != "enum"
        and not kind.startswith("bytes")
        and word[:2] == ("conv", "uint256")
        and word[2][:2] == ("conv", kind)
    ):
        return word[2], TRUE  # The encoder's cleanup already proves this word canonical.
    if kind.startswith("bytes") and word[:2] == ("op", "shl"):
        bits = 8 * int(kind[5:])
        clean, shift = word[2]
        if shift == const(256 - bits) and clean[:2] == ("conv", f"uint{bits}"):
            return clean, TRUE
    if not strict:
        # ABI coder v1 cleans a word to its type instead of rejecting it; how it reads an enum isn't modelled.
        if kind == "enum":
            return unknown("unsupported:abi_v1_enum"), unknown("unsupported:abi_v1_enum")
        if kind == "bool":
            return mk_not(mk_cmp("eq", word, const(0))), TRUE
        if kind.startswith("bytes"):
            return mk_op("shr", (word, const(256 - 8 * int(kind[5:])))), TRUE
        return mk("conv", kind, word), TRUE
    if kind == "enum":
        return word, mk_cmp("lt", word, const(t[2]))
    if kind == "bool":
        return mk_cmp("eq", word, const(1)), mk_or([mk_cmp("eq", word, const(0)), mk_cmp("eq", word, const(1))])
    if kind.startswith("bytes"):
        shift = 256 - 8 * int(kind[5:])
        clean = mk_op("shr", (word, const(shift)))
        return clean, mk_cmp("eq", word, mk_op("shl", (clean, const(shift))))
    clean = mk("conv", kind, word)
    return clean, mk_cmp("eq", word, mk("conv", "uint256", clean))


def transfer(value: Term, src: tuple, dst: tuple, depth=0, strict: bool | None = True) -> tuple[Term, Term]:
    """Logical value after encoding as src and decoding as dst (by ABI coder v2 if ``strict``, v1 if not, unknown
    if ``None``), plus validity condition."""
    from .lower import element, length_of, project

    if value[0] == "stackword":
        value = stack_value(value[1], value[2])[0]
    bad = unknown("unsupported:abi_boundary")
    if depth > 12 or strict is None:
        return bad, bad
    if value[0] == "ite":
        a, ga = transfer(value[2], src, dst, depth + 1, strict)
        b, gb = transfer(value[3], src, dst, depth + 1, strict)
        return mk_ite(value[1], a, b), mk_ite(value[1], ga, gb)
    if _scalar(src) and _scalar(dst):
        if value[0] == "const" and isinstance(value[1], (str, bytes)):
            raw = value[1]
            try:
                if src[1].startswith("bytes"):
                    raw = (
                        raw
                        if isinstance(raw, bytes)
                        else bytes.fromhex(raw[2:])
                        if raw.startswith("0x") and value[2] != "string"
                        else raw.encode()
                    )
                    width = int(src[1][5:])
                    if len(raw) > width:
                        return bad, bad
                    value = const(int.from_bytes(raw.ljust(width, b"\0"), "big"))
                else:
                    value = const(int(raw, 0))
            except (ValueError, TypeError):
                return bad, bad
        word, encoded = _word(value, src)
        out, decoded = _decode(word, dst, strict)
        return out, mk_and([encoded, decoded])
    if src[1] == dst[1] == "tuple" and compatible(src, dst):
        values = []
        guards = []
        for a, b in zip(src[2], dst[2]):
            val, guard = transfer(project(value, (("f", a[1]),)), a[2], b[2], depth + 1, strict)
            values.append(val)
            guards.append(guard)
        return mk("struct", tuple(f[1] for f in dst[2]), tuple(values)), mk_and(guards)
    if src[1] == dst[1] == "array" and compatible(src, dst):
        length = const(src[3]) if src[3] is not None else length_of(value)
        if length is not None and length[0] == "const" and isinstance(length[1], int) and 0 <= length[1] <= 64:
            pairs = [transfer(element(value, const(i)), src[2], dst[2], depth + 1, strict) for i in range(length[1])]
            return mk("array", length, tuple(p[0] for p in pairs)), mk_and(p[1] for p in pairs)
        if total_encoder(src[2]):
            return mk("abi_array", value, src[2], dst[2]), TRUE
    if src[1] in ("bytes", "string") and dst[1] in ("bytes", "string"):
        return value, mk("abi_bytes_valid", value)
    return bad, bad


def stack_value(raw: Term, type_: tuple) -> tuple[Term, Term]:
    """Logical view and canonical-word condition for a scalar held in an EVM register."""
    logical, _ = _decode(raw, type_, strict=False)
    _, valid = _decode(raw, type_, strict=True)
    kind = type_[1]
    if kind in ("uint256", "int256", "bytes32"):
        return logical, TRUE
    if raw[0] == "const" and isinstance(raw[1], (int, bool)):
        word = int(raw[1]) % 2**256
        if kind == "bool":
            return const(word != 0, "bool"), const(word in (0, 1), "bool")
        if kind.startswith("bytes"):
            bits = 8 * int(kind[5:])
            value = word >> (256 - bits)
            return const(value, kind), const(word == value << (256 - bits), "bool")
        bounds = _range(type_)
        if bounds is not None:
            bits = 160 if kind == "address" else int(kind.lstrip("uint"))
            value = word % 2**bits
            if kind.startswith("int") and value >= 2 ** (bits - 1):
                value -= 2**bits
            return const(value, kind), const(word == value % 2**256, "bool")
    word = raw[2] if raw[:2] == ("conv", "uint256") else raw
    if kind == "bool" and word[0] in ("cmp", "not", "and", "or", "ok", "caught", "delegate"):
        return word, TRUE
    return logical, valid
