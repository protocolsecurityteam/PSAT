"""Physical byte-range views of persistent storage, retaining logical read provenance."""

from .abi_values import abi_name
from .layout import _size, locate_symbolic
from .terms import FALSE, TRUE, _unmodelled, const, mk, mk_and, mk_cmp, mk_ite, mk_op


def word(value):
    if value[0] == "const" and isinstance(value[1], (int, bool)):
        return const(int(value[1]) % 2**256)
    if value[:2] == ("conv", "uint256"):
        return word(value[2])
    if value[0] == "hash" or value[:2] in (("op", "add"), ("op", "sub"), ("op", "mul")):
        return value
    return mk("conv", "uint256", value)


def annotate(contract, code, location):
    """A location's source context and physical coordinates are data, never IR objects."""
    if location[0] in ("raw", "transient", "heap", "act", "emit", "havoc"):
        return location
    try:
        where = locate_symbolic(contract, location[1], location[2])
    except ValueError:
        where = None  # The logical load retains the layout failure; aliases stay unplaced.
    slot, offset, type_ = where if where is not None else (None, None, None)
    size = (32 if type_ is None else _size(type_)) if where is not None else None
    type_name = "uint256" if type_ is None else abi_name(type_)
    # Function pointer values are stored bits; invoking them remains separate semantics.
    if type_name == "function" and size is not None:
        type_name = f"uint{size * 8}"
    return (*location[:3], ("cell", code, slot, offset, size, type_name))


def annotation(location):
    return location[3] if len(location) >= 4 and location[3][:1] == ("cell",) else None


def occurrence(location):
    tail = location[-1]
    return tail[1] if isinstance(tail, tuple) and tail[:1] == ("write_occurrence",) else None


def base_location(location):
    return location[:-1] if occurrence(location) is not None else location


def context(location):
    meta = annotation(location)
    return meta[1] if meta else None


def view(location):
    if location[0] == "raw":
        return location[1], word(location[2]), const(0), 32, "uint256"
    meta = annotation(location)
    if meta and meta[4] is not None and meta[5] is not None:
        return location[0], word(meta[2]), meta[3], meta[4], meta[5]
    return None


def child_load(load, steps):
    """Projection preserves source context but cannot reuse its parent's byte coordinates."""
    meta = load[4:]
    if meta:
        meta = (("cell", meta[0][1], None, None, None, None),)
    return mk("load", load[1], load[2], (*load[3], *steps), *meta)


def _encoding_words(value):
    if value[0] != "hash" or value[1] not in ("keccak256", "sha3") or len(value[2]) != 1:
        return None
    encoded = value[2][0]
    if encoded[0] != "enc" or encoded[1] != "abi.encode" or len(encoded) != 3:
        return None
    words = []
    for argument in encoded[2]:
        type_ = argument[1] if argument[0] == "conv" else argument[2] if argument[0] in ("arg", "const") else None
        if type_ is None or type_ in ("bytes", "string"):
            return None
        if type_.startswith("bytes") and type_[5:].isdigit():
            bits = 8 * int(type_[5:])
            words.append(mk_op("shl", (mk("conv", type_, argument), const(256 - bits))))
        elif type_ in ("address", "bool") or type_.startswith(("uint", "int")):
            words.append(word(mk("conv", type_, argument)))
        else:
            return None
    return words


def slot_equal(left, right):
    left, right = word(left), word(right)
    if left == right:
        return mk_cmp("eq", left, right)
    # Addition is modulo 2**256: cancelling an identical summand is exact.
    a = tuple(word(x) for x in left[2]) if left[:2] == ("op", "add") else (left, const(0))
    b = tuple(word(x) for x in right[2]) if right[:2] == ("op", "add") else (right, const(0))
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            if x == y and x != const(0) and not _unmodelled(x):
                return slot_equal(a[1 - i], b[1 - j])
    encoded_a, encoded_b = _encoding_words(left), _encoding_words(right)
    if encoded_a is not None and encoded_b is not None and len(encoded_a) == len(encoded_b):
        equal = mk_and(slot_equal(x, y) for x, y in zip(encoded_a, encoded_b))
        return mk("storage_key_equal", left, right, equal)
    return mk_cmp("eq", left, right)


def overlay(current, read, written, value):
    """Apply one typed/raw write to another field without changing neighboring bytes."""
    address, slot, offset, width, type_ = read
    other_address, other_slot, other_offset, other_width, other_type = written
    same = mk_and([mk_cmp("eq", address, other_address), slot_equal(slot, other_slot)])
    if same == FALSE:
        return current
    if offset[0] == other_offset[0] == "const" and (
        offset[1] + width <= other_offset[1] or other_offset[1] + other_width <= offset[1]
    ):
        return current
    if (width, type_) == (other_width, other_type) and mk_cmp("eq", offset, other_offset) == TRUE:
        return mk_ite(same, value, current)
    shift = mk_op("mul", (const(8), offset))
    other_shift = mk_op("mul", (const(8), other_offset))
    mask, other_mask = const(2 ** (8 * width) - 1), const(2 ** (8 * other_width) - 1)
    changed = mk_op("shr", (mk_op("shl", (other_mask, other_shift)), shift))
    bits = mk_op("shr", (mk_op("shl", (mk_op("and", (word(value), other_mask)), other_shift)), shift))
    retained = mk_op("and", (word(current), mk_op("bnot", (changed,))))
    raw = mk_op("and", (mk_op("or", (retained, bits)), mask))
    return mk_ite(same, mk("conv", type_, raw), current)
